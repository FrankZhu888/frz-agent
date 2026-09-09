# frza — terminal-native agentic troubleshooting agent

frza is an AI agent that troubleshoots real machines from your terminal. It
investigates with tools — shell commands, file reading, content search — follows
reusable **skill playbooks**, and operates under a production-grade **safety
model**: read-only commands run automatically, anything that changes the system
asks first, destructive operations warn and back up first, and every action is
journaled with `/undo` rollback.

Single static Go binary. No frameworks, no daemon, no Python required.
Function calling speaks the OpenAI **Responses API** (verified against
Volcengine Ark / kimi-k3); plain multi-provider chat (Anthropic / OpenAI /
Gemini) works as well.

## Quick start

```bash
# 1. get a binary from Releases (or: cd go && ./build.sh)

# 2. configure a Responses-API-compatible provider
frza config set --provider openai_responses --api-key YOUR_KEY \
  --base-url https://ark.cn-beijing.volces.com/api/v3

# 3. troubleshoot
frza --agent
```

Three starter skill playbooks (Linux system logs, Kubernetes, general app logs)
are embedded in the binary and released to `~/.frza/skills/` on first run.

## What it looks like

Analyzing a kubelet log for a node whose pods won't start:

```
> 节点上 Pod 起不来了，这是 kubelet.log，帮我分析下根因

⚙ use_skill: {"name":"k8s-analyzer"}              ← routes to the playbook
⚙ bash: ls -lh kubelet.log                        [auto] read-only command
⚙ bash: python3 ~/.frza/skills/k8s-analyzer/scripts/k8s_log_preprocess.py kubelet.log
⚙ search: "(?i)error|fail|fatal|back-off|timeout" in .
⚙ read_file: kubelet.log                          ← samples regions around hits

Root cause: disk pressure (>85%) → containerd image GC pressure →
container runtime down → node NotReady → pods cannot start.
Fix: 1) recover disk space … 2) restart containerd/kubelet …
     3) tune kubelet eviction thresholds to prevent recurrence …
```

## Safety model

Troubleshooting touches production machines, so the agent is built to be
auditable and recoverable, not just polite:

| Layer | Mechanism |
|---|---|
| Command classification | shell chains are split (`;`, `&&`, `\|`) and every segment graded: read-only whitelist / reversible / destructive / unknown. Worst segment wins |
| Confirmation | read-only commands auto-run; everything else asks `y/n/a` (always-for-session). Destructive ops (`rm`, `dd`, `systemctl restart`, `kubectl delete`, redirection overwrites…) warn in red |
| Backup | before an approved destructive command or file overwrite, identifiable target files are copied to `~/.frza/backups/` |
| Journal | every operation (including declined ones) is appended to `~/.frza/journal/<session>.jsonl` (mode 0600, secrets redacted) — a full audit trail of what the agent did |
| Undo | `/undo` rolls back the most recent file change — restores a backup or deletes an agent-created file; works after `/resume` |

Two command paths are kept separate: the model can propose commands (through
the gates above), and *you* can run commands directly with `!cmd` (display
only) or `!!cmd` (also feed the output to the model) — no confirmation needed
for your own input, still journaled.

## Skills: reusable troubleshooting playbooks

A skill is a directory: a `SKILL.md` playbook plus optional helper scripts.
Skills are how domain expertise becomes something the agent can execute —
yours, your team's, or the community's.

```
~/.frza/skills/
  k8s-analyzer/
    SKILL.md                        # triggers + step-by-step diagnostic workflow
    scripts/k8s_log_preprocess.py   # noise reduction for GB-scale logs
```

```markdown
---
name: k8s-analyzer
description: 定位 K8s 核心组件故障（kubelet/etcd/CNI/CoreDNS…），
             覆盖节点 NotReady、调度失败、网络不通等高频场景
---

## 前置检查
- `command -v python3`

## 流程
1. 用 scripts/k8s_log_preprocess.py 过滤噪声、匹配错误特征…
2. 按组件分支排查 …
```

- **Two-level loading**: the catalog (name + description + triggers) goes into
  the system prompt at startup; the model loads the full playbook on demand
  with `use_skill` — 100 playbooks wouldn't cost you context you don't use.
- **Semantic routing**: describe a symptom in your own words ("pods keep
  restarting") and the model picks the matching playbook; or name it
  explicitly: "用 k8s-analyzer 分析这个日志".
- **Scripts stay scripts**: the playbook tells the model *when* and *why* to
  run `scripts/*.py`; execution goes through the same gated bash tool, so the
  safety model applies uniformly.
- `/skills` lists what's loaded, `/reload-skills` rescans without restarting.

## Built-in tools

| Tool | Purpose | Notes |
|---|---|---|
| `bash` | shell commands | read-only auto-run, changes confirmed; 120s default timeout (model can request up to 600s); output truncated head-200 + tail-50 lines |
| `read_file` | read text files | offset/limit paging, binary detection |
| `search` | regex search over files/dirs | 100-match cap, skips VCS/dep dirs and binaries |
| `write_file` | create/overwrite files | confirms + auto-backup on overwrite; creations are `/undo`-able |
| `use_skill` | load a playbook | on demand, by exact name |

## Context & cost discipline

Long investigations stay affordable by design: tool outputs are truncated with
clear markers (the model learns to narrow with `search` instead of re-dumping),
and the conversation is kept within a configurable token budget — oldest tool
outputs are compressed first, then oldest turn groups dropped (tool-call
pairing preserved). Tunables live in `~/.frza/config.json`:

```bash
frza config set agent.max_rounds 30
frza config set agent.context_max_tokens 512000
frza config set agent.bash_timeout_sec 300
```

## Building

```bash
cd go
./build.sh            # static binaries for darwin/linux × amd64/arm64 + checksums
go test ./...         # classifier / SSE replay / retry / context / undo suites
```

`CGO_ENABLED=0` static builds: one file, no glibc dependency, runs anywhere
with Linux kernel ≥ 3.2 or macOS 11+.

## Deployment

Two patterns: run in-place on the affected machine, or (recommended) on a
dedicated analysis workstation that evidence is copied to — including driving a
Windows WinDbg box over SSH for memory.dmp analysis. See
[DEPLOYMENT.md](DEPLOYMENT.md) for the decision table, workstation dependency
checklist, and the on-call runbook.

## License

No license file yet — all rights reserved for now.
