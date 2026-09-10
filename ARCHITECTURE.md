# frza architecture

frza is a terminal-native agentic troubleshooting agent: a single static Go
binary, framework-free, with a hand-rolled agent loop. This document describes
how it is put together and why the main design choices were made.

## Design goals

1. **Runs anywhere a troubleshooter works** — one static binary, no runtime,
   no glibc dependency (`CGO_ENABLED=0`); kernel ≥ 3.2 or macOS 11+.
2. **Safe enough for production machines** — auditable and recoverable first,
   autonomous second. Every action passes classification, confirmation,
   backup, and journaling.
3. **Domain knowledge is content, not code** — troubleshooting playbooks
   (skills) are markdown directories that load without rebuilding the binary.
4. **No AI frameworks** — the agent loop, SSE protocol handling, and tool
   plumbing are standard-library Go. Every line is explainable in an interview
   or a code review.

## Component map

```
┌────────────────────────────────────────────────────────────────┐
│ REPL (readline)                                                │
│   slash commands │ !cmd / !!cmd │ Tab completion               │
├────────────────────────────────────────────────────────────────┤
│ sendMessage ── agent loop (≤ maxRounds, sequential tool calls) │
│   ├─ context trimmer (compress tool outputs → drop turn groups)│
│   ├─ confirmation gate (classify → auto / y·n·a / red warning) │
│   └─ journal writer (append-only JSONL, secret-redacted)       │
├──────────────────┬─────────────────────────────────────────────┤
│ provider layer   │ tools & skills                               │
│   callerFunc     │   bash (+exec alias) · read_file · search    │
│   → CallResult   │   write_file · use_skill                     │
│   anthropic      │   skill scanner: frontmatter → catalog       │
│   openai         │   two-level loading (catalog → full body)    │
│   gemini         │ safety model                                 │
│   openai_responses│  chain-aware classifier · backup-on-write   │
│   (tools + SSE)  │   undo (reverse WAL replay)                  │
├──────────────────┴─────────────────────────────────────────────┤
│ rendering (unchanged from chat heritage): markdown, tables,    │
│ code highlighting, thinking spinner, stream renderer           │
├────────────────────────────────────────────────────────────────┤
│ persistence: ~/.frza/  config.json · sessions/*.json ·         │
│   journal/*.jsonl (0600) · backups/<session>/ · skills/        │
└────────────────────────────────────────────────────────────────┘
```

## Provider layer

All providers share one signature:

```go
type callerFunc func(ctx, messages, system, model, apiKey, baseURL string,
    tools []Tool, onDelta, onReasoning func(string)) (CallResult, error)

type CallResult struct {
    Text      string
    ToolCalls []ToolCall
}
```

`Message` is the **canonical internal form**; each caller serializes it to its
own wire protocol. Only `openai_responses` carries tools today (provider
policy: Responses is the industry-converging protocol; the other three stay
chat-only), so tool-capable fields (`ToolCalls`, `ToolCallID`) map to
Responses `function_call` / `function_call_output` input items.

### Responses API streaming

`callOpenAIResponses` = HTTP concern (retry, headers) + `parseResponsesSSE`
(pure parser, replayable in tests):

- request: `input` items + `tools` + `tool_choice: auto`, SSE streaming
- events: `output_text.delta` → render; `reasoning_summary_text.delta` →
  spinner heartbeat; `output_item.added(function_call)` → register
  `item_id → (call_id, name)`; `function_call_arguments.delta` → accumulate;
  `response.completed` → return `CallResult`
- argument deltas key on `item_id` (`fc_…`) while the model-visible `call_id`
  (`bash_0`) arrives earlier — hence the map; calls keep `output_index` order
- transient failures (429 / 5xx / network) retry with 1s/4s/15s backoff;
  4xx auth fails fast

## Agent loop

`sendMessage` in agent mode (`--agent` or `/agent on`, Responses provider):

```
append user message
loop (≤ agentMaxRounds, default 15):
    trimContext()                       # before every API call
    res = callModel(history, tools)
    append assistant message (text + tool_calls)
    if no tool_calls → break            # final answer
    for each tool_call (sequential):    # order matters in diagnostics
        display ⚙ name: args-summary
        classify + confirm              # see safety model
        run tool (ctx-cancellable)      # failures feed back as results
        journal the operation
        append tool result message
    saveSession()                       # after every round
```

Key behaviors:

- **Ctrl-C** cancels the in-flight HTTP call *or* the running tool (shared
  context); a first-round failure drops the user message, later rounds keep
  history (tool results already recorded are valuable).
- **Declined commands are fed back** ("user refused; do not retry, propose an
  alternative") — the model adjusts instead of hammering the same command.
- **`/continue`** resumes after the round cap; **`!!cmd`** lets the user feed
  command output into the loop directly.

## Safety model

Four layers, each independently verifiable:

| Layer | Mechanism | Code |
|---|---|---|
| Classification | `classifyCommand`: strip harmless discards (`2>/dev/null`, `2>&1`) → reject-escalate on `$()`/backticks → dangerous regex set → split chain on `;` `&&` `\|\|` `|` (quote-aware) → every segment against the read-only whitelist (incl. subcommand rules for `systemctl`/`kubectl`/`git`/`tar`) → worst grade wins | table-driven tests |
| Confirmation | read-only → auto; reversible/unknown → `y/n/a`; destructive → red "not auto-reversible" warning + confirm; `a` approves the tool for the session | REPL `ask` via readline |
| Backup | before an approved destructive bash command, `backupTargetsFor` extracts `rm`/redirect targets and copies them; `write_file` overwrite always backs up; creations are journaled as undo-able | `~/.frza/backups/<session>/` |
| Journal & undo | every operation (incl. declined and user-typed `!cmd`) appended to `journal/<session>.jsonl` (0600, secrets redacted); `/undo` replays the journal backwards — restores the latest backup or deletes the latest agent-created file; undo actions themselves journaled | `undoLatest` (unit-tested replay) |

## Tools

| Tool | Contract highlights |
|---|---|
| `bash` (alias `exec`) | 120s default timeout; model may request `timeout_sec` (5s floor, 600s cap); output truncated head-200 + tail-50 lines, 8KB cap (truncation markers tell the model to switch strategies); cwd = launch dir |
| `read_file` | 1-based offset/limit (≤2000 lines), binary detection, reports `[lines a-b of N]` so the model can page |
| `search` | regex (literal fallback), dir walk skipping VCS/dep dirs and binaries, 100-match cap |
| `write_file` | full-file write only; confirm + backup on overwrite; create is `/undo`-able |
| `use_skill` | loads a playbook body, expands `{{SKILL_DIR}}` to an absolute path |

Tool descriptions are part of the safety/cost design (e.g. the bash
description steers large-file work to `search` and >10min jobs to
`nohup`-background + polling).

## Skills

A skill is a directory: `SKILL.md` (YAML-lite frontmatter + markdown playbook)
plus optional `scripts/`.

- **Sources**: `~/.frza/skills/` (primary), `<cwd>/skills/` (repo checkouts),
  and a `go:embed` starter pack released on first run when the user has none.
- **Two-level loading**: at startup only the catalog (name + description +
  `activate_when` triggers, ~1–2k tokens for dozens of skills) is appended to
  the system prompt; the full body loads on demand via `use_skill`.
- **Routing is semantic**, done by the model against the catalog — there is no
  keyword matcher in code (paraphrases match better than regexes ever will).
- **Three-layer system prompt**: user prompt (`/system`) + built-in agent
  operating rules (investigation discipline, missing-dependency protocol,
  archive-handling conventions) + skill catalog.
- Frontmatter parser accepts both `name` and legacy `skill_name`, multi-line
  descriptions, and `activate_when` lists — existing OpenClaw-format skills
  work unmodified.

## Context management

Budget-driven (`agent.context_max_tokens`, default 256k), applied before every
API round:

1. **Compress** oldest tool outputs to a placeholder (message structure and
   `tool_call_id` pairing preserved).
2. **Drop** oldest *turn groups* (a user message + its assistant/tool
   follow-ups) as a unit — never leaving an orphaned `function_call_output`
   that the API would reject; a marker note is prepended.

Token estimation is a stable upper-bound heuristic (ASCII ≈ 4 chars/token,
CJK ≈ 1.5 tokens/char) — cost control, not billing.

## Persistence layout

```
~/.frza/
  config.json            # providers (keys/models/urls per provider) + agent.* knobs
  sessions/<name>.json   # canonical Messages (omitempty keeps legacy files loadable)
  journal/<name>.jsonl   # append-only, 0600, secret-redacted
  backups/<session>/     # pre-change file copies, pruned by frza clean
  skills/<name>/SKILL.md # released from go:embed on first run when empty
```

## Why these choices

| Decision | Rationale |
|---|---|
| No SDK / no framework | the Responses protocol is ~200 lines of SSE handling; owning it removes a dependency surface and makes the behavior auditable |
| Single Go file (~3.7k lines) | everything navigable with grep; split planned only past ~4k lines (tools/agent are natural seams) |
| Sequential tool calls | diagnostic steps depend on each other; sequential keeps journal/undo semantics simple and correct |
| Semantic skill routing | paraphrase-tolerant; code-level keyword matching misses real phrasing |
| Journal as WAL (not a snapshotter) | filesystem snapshots are heavy; a journaled before-image of *identifiable* targets covers the realistic failure modes at ~1% of the complexity |
| Canonical Message + per-provider mapping | one internal model, protocol quirks isolated in callers; adding a provider never touches the loop |
| Responses-only tools | the industry is converging on the Responses shape; four partial tool integrations are worse than one excellent one |

## Testing architecture

Pure functions are extracted so the tricky parts are unit-testable without a
network:

- `parseResponsesSSE` — replayed against a **recorded Ark stream**
  (`testdata/ark_toolcall.sse`) plus synthetic multi-call/failure streams
- `classifyCommand` / `splitChain` — table-driven, including chain-bypass and
  `2>/dev/null` false-positive regressions
- `callOpenAIResponses` retry — `httptest` server mocking 429-then-success,
  401-fail-fast, retry-exhaustion
- `trimContext` — compression-before-drop, turn-group integrity, pairing
  invariants
- `undoLatest` — synthetic journal replay: delete-created, restore-backup,
  then empty
- `redactSecrets`, `truncateToolOutput`, `backupTargetsFor`, frontmatter
  parsing, `responsesInputItems` serialization

`go test ./...` is the CI gate for every release.
