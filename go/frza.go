// frza - a terminal-native agentic troubleshooting agent.
//
// The model investigates with tools (bash/read_file/search/write_file) in an
// agent loop, follows reusable skill playbooks (SKILL.md directories with
// companion scripts), and operates under a production-grade safety model —
// read-only commands auto-run, changes ask first, destructive ops warn in red
// and back up identifiable targets, and every operation is journaled with
// /undo rollback. Plain multi-provider chat still works out of the box.
//
// Features:
//   - Agent loop with function calling over the OpenAI Responses API
//     (SSE streaming; verified against Volcengine Ark / kimi-k3)
//   - Built-in tools: bash (120s default timeout, truncated output), read_file
//     (offset/limit, binary detection), search (regex, capped), write_file
//     (backup-on-overwrite), use_skill (on-demand playbook loading)
//   - Skills: directory playbooks (~/.frza/skills/, repo skills/), two-level
//     loading — catalog in system prompt, full body via use_skill
//   - Safety model: chain-aware command classifier (read-only whitelist /
//     reversible / destructive / unknown), y/n/a confirmation, append-only
//     operation journal with secret redaction, /undo + /journal
//   - REPL: !cmd runs shell directly, !!cmd feeds output to the model;
//     /agent /skills /reload-skills /undo /journal plus the frz chat commands
//   - Chat heritage (from frz): four provider protocols (Anthropic / OpenAI /
//     Gemini / OpenAI Responses — chat-only except Responses), terminal
//     Markdown rendering with CJK-aware tables and ASCII box realignment,
//     sessions in ~/.frza/sessions/*.json
package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/chzyer/readline"
	"github.com/rivo/uniseg"
	"golang.org/x/term"
)

// Version and author info. version/buildTime are injected at build time via
// -ldflags -X (see build.sh); a plain `go build` shows the default dev value.
var (
	version   = "dev"
	buildTime = ""
	author    = "Frank Zhu <flankeroot@gmail.com>"
)

func shortVersion() string { return "frza " + version }

// versionString is the full version line: version + build time + platform
// (handy for checking the architecture of distributed binaries) + author.
func versionString() string {
	s := shortVersion()
	if buildTime != "" {
		s += " (" + buildTime + ")"
	}
	return fmt.Sprintf("%s %s/%s  by %s", s, runtime.GOOS, runtime.GOARCH, author)
}

var (
	appDir     = filepath.Join(os.Getenv("HOME"), ".frza")
	sessDir    = filepath.Join(appDir, "sessions")
	exportDir  = filepath.Join(appDir, "exports")
	configFile = filepath.Join(appDir, "config.json")
)

var defaultModels = map[string]string{
	"anthropic":        "claude-sonnet-4-6",
	"openai":           "gpt-4o",
	"gemini":           "gemini-2.5-flash",
	"openai_responses": "kimi-k3",
}

var envKeyNames = map[string]string{
	"anthropic":        "ANTHROPIC_API_KEY",
	"openai":           "OPENAI_API_KEY",
	"gemini":           "GEMINI_API_KEY",
	"openai_responses": "ARK_API_KEY",
}

// Default API base URLs per provider. anthropic/openai/gemini URLs are hardcoded
// in their callers; the Responses protocol may front different vendors
// (Volcengine Ark, or the official OpenAI Responses API in the future),
// so it gets an overridable default here.
var defaultBaseURLs = map[string]string{
	"openai_responses": "https://ark.cn-beijing.volces.com/api/v3",
}

// Providers with true typewriter streaming (print as generated)
var streamingProviders = map[string]bool{"openai_responses": true}

// --------------------------------------------------------------------------
// Basic utilities
// --------------------------------------------------------------------------

func ensureDirs() { os.MkdirAll(sessDir, 0o755) }

// embeddedSkills ships the starter playbooks inside the binary so a bare
// frza works out of the box; they are released to ~/.frza/skills on first
// run (only when the user has no skills of their own yet).
//
//go:embed skills
var embeddedSkills embed.FS

func releaseEmbeddedSkills() {
	entries, err := os.ReadDir(skillsDir)
	if err == nil && len(entries) > 0 {
		return // user already has skills; never overwrite
	}
	os.MkdirAll(skillsDir, 0o755)
	fs.WalkDir(embeddedSkills, "skills", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel("skills", p)
		dst := filepath.Join(skillsDir, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		data, err := embeddedSkills.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	})
}

// loadConfig reads the config into a generic map (preserves all fields,
// including ones added in the future)
func loadConfig() map[string]interface{} {
	cfg := map[string]interface{}{}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return cfg
	}
	if json.Unmarshal(data, &cfg) != nil {
		return map[string]interface{}{}
	}
	return cfg
}

func saveConfig(cfg map[string]interface{}) {
	ensureDirs()
	if err := writeJSONFile(configFile, cfg, 0o600); err != nil {
		fmt.Println(stylize("[error] cannot write config: "+err.Error(), "red"))
	}
}

// checkConfigIntact guards `config set` against a corrupted config file:
// loadConfig treats unparseable JSON as empty, so a set would silently
// overwrite and destroy every existing key (audit C2). The corrupted file is
// preserved at config.json.bak for manual recovery before we refuse.
func checkConfigIntact() error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil // missing file: starting fresh is fine
	}
	var probe map[string]interface{}
	if json.Unmarshal(data, &probe) == nil {
		return nil
	}
	if berr := os.WriteFile(configFile+".bak", data, 0o600); berr == nil {
		return fmt.Errorf("%s is corrupted (backed up to %s.bak); fix or delete it before running config set", configFile, configFile)
	}
	return fmt.Errorf("%s is corrupted; fix or delete it before running config set", configFile)
}

// writeJSONFile writes JSON with indent=2 without escaping HTML/Unicode.
// The write is atomic — a temp file in the same directory is fsync'd and
// renamed over the target — so a crash mid-write never leaves a truncated
// session/config behind (audit C1). Files are created with the given mode;
// sessions and config hold unredacted conversation/credentials and must be
// 0600 like the journal (audit C3).
func writeJSONFile(path string, v interface{}, mode os.FileMode) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func cfgStr(cfg map[string]interface{}, key string) string {
	s, _ := cfg[key].(string)
	return s
}

func cfgMap(cfg map[string]interface{}, key string) map[string]interface{} {
	m, _ := cfg[key].(map[string]interface{})
	return m
}

// sessionPath keeps only letters, digits and -_. in the name
// (Unicode letters such as CJK are also allowed)
func sessionPath(name string) string {
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	safe := b.String()
	if safe == "" {
		safe = "session"
	}
	return filepath.Join(sessDir, safe+".json")
}

// Message is the canonical internal message form. Each caller serializes it
// into its provider's wire format (e.g. Responses API function_call items).
// New fields are omitempty so legacy session JSON still loads.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`   // assistant requesting tool executions
	ToolCallID string     `json:"tool_call_id,omitempty"` // tool result: which call this answers
	Name       string     `json:"name,omitempty"`         // tool result: tool name (for display/journal)
}

// ToolCall is one tool invocation requested by the model.
type ToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON string
}

// Tool is a capability offered to the model. Schema is a JSON Schema object
// describing the arguments. Run executes the tool with the raw arguments JSON.
type Tool struct {
	Name        string
	Description string
	Schema      map[string]interface{}
	Confirm     bool // ask the user before executing
	Run         func(ctx context.Context, argsJSON string) (string, error)
}

// CallResult is what a caller returns: assistant text (possibly streamed
// already) plus any tool calls the model asked for.
type CallResult struct {
	Text      string
	ToolCalls []ToolCall
}

type Session struct {
	Name         string    `json:"name"`
	Provider     string    `json:"provider"`
	Model        string    `json:"model"`
	BaseURL      string    `json:"base_url"`
	SystemPrompt string    `json:"system_prompt"`
	CreatedAt    string    `json:"created_at"`
	UpdatedAt    string    `json:"updated_at"`
	Messages     []Message `json:"messages"`
}

type sessionEntry struct {
	name string
	sess *Session
}

func listSessions() []sessionEntry {
	ensureDirs()
	files, _ := filepath.Glob(filepath.Join(sessDir, "*.json"))
	type fw struct {
		path string
		mod  time.Time
	}
	var fws []fw
	for _, f := range files {
		if st, err := os.Stat(f); err == nil {
			fws = append(fws, fw{f, st.ModTime()})
		}
	}
	sort.Slice(fws, func(i, j int) bool { return fws[i].mod.After(fws[j].mod) })
	var out []sessionEntry
	for _, f := range fws {
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		var s Session
		if json.Unmarshal(data, &s) != nil {
			continue
		}
		out = append(out, sessionEntry{strings.TrimSuffix(filepath.Base(f.path), ".json"), &s})
	}
	return out
}

// saveSession saves the session; empty sessions (0 messages) are skipped unless
// force is set. Returns (path, saved).
func saveSession(s *Session, force bool) (string, bool) {
	if !force && len(s.Messages) == 0 {
		return "", false
	}
	ensureDirs()
	s.UpdatedAt = time.Now().Format("2006-01-02T15:04:05")
	path := sessionPath(s.Name)
	if err := writeJSONFile(path, s, 0o600); err != nil {
		fmt.Println(stylize("[error] cannot save session: "+err.Error(), "red"))
		return "", false
	}
	lastAutoSave = time.Now() // any successful save resets the throttle (M15)
	return path, true
}

func nowISO() string { return time.Now().Format("2006-01-02T15:04:05") }

func defaultSessionName() string { return time.Now().Format("session-20060102-150405") }

func renameSessionFile(oldName, newName string) (bool, string) {
	oldPath, newPath := sessionPath(oldName), sessionPath(newName)
	if _, err := os.Stat(oldPath); err != nil {
		return false, fmt.Sprintf("session %q not found", oldName)
	}
	if newPath != oldPath {
		if _, err := os.Stat(newPath); err == nil {
			return false, fmt.Sprintf("session %q already exists, pick another name", newName)
		}
	}
	data, err := os.ReadFile(oldPath)
	if err != nil {
		return false, fmt.Sprintf("session %q not found", oldName)
	}
	var s map[string]interface{}
	if json.Unmarshal(data, &s) != nil {
		return false, fmt.Sprintf("session %q is corrupted", oldName)
	}
	s["name"] = newName
	s["updated_at"] = nowISO()
	// Never delete the original until the new file is durably in place —
	// otherwise a full disk turns a rename into data loss (audit C1).
	if err := writeJSONFile(newPath, s, 0o600); err != nil {
		return false, fmt.Sprintf("cannot write %q: %v (original session kept)", newName, err)
	}
	if newPath != oldPath {
		os.Remove(oldPath)
	}
	return true, newPath
}

// copySessionArtifacts duplicates the journal and backup directory to a new
// session name, leaving the source intact — the right semantics for
// `/save <new>` (a snapshot: the old session must keep its own undo chain;
// audit2 M4). Existing targets are never overwritten.
func copySessionArtifacts(oldName, newName string) {
	if oldName == "" || newName == "" || oldName == newName {
		return
	}
	oldJ, newJ := journalPath(oldName), journalPath(newName)
	if data, err := os.ReadFile(oldJ); err == nil {
		if _, err := os.Stat(newJ); os.IsNotExist(err) {
			if err := os.WriteFile(newJ, data, 0o600); err != nil {
				fmt.Println(stylize("[warn] could not copy journal: "+err.Error(), "yellow"))
			}
		}
	}
	oldB := filepath.Join(backupDir, oldName)
	if _, err := os.Stat(oldB); err != nil {
		return
	}
	filepath.WalkDir(oldB, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(oldB, p)
		dst := filepath.Join(backupDir, newName, rel)
		if d.IsDir() {
			os.MkdirAll(dst, 0o700)
			return nil
		}
		if _, err := os.Stat(dst); err == nil {
			return nil // never overwrite
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if err := os.WriteFile(dst, data, info.Mode().Perm()); err != nil {
			fmt.Println(stylize("[warn] could not copy backup "+rel+": "+err.Error(), "yellow"))
		}
		return nil
	})
}

// migrateSessionArtifacts moves the journal and backup directory over to a
// new session name so /undo keeps working across /rename and /save <new>
// (audit 3.5). Best-effort: a failed move is reported, never fatal.
func migrateSessionArtifacts(oldName, newName string) {
	if oldName == "" || newName == "" || oldName == newName {
		return
	}
	oldJ, newJ := journalPath(oldName), journalPath(newName)
	if _, err := os.Stat(oldJ); err == nil {
		if err := os.Rename(oldJ, newJ); err != nil {
			fmt.Println(stylize("[warn] could not migrate journal: "+err.Error(), "yellow"))
		}
	}
	oldB := filepath.Join(backupDir, oldName)
	if _, err := os.Stat(oldB); err == nil {
		if err := os.Rename(oldB, filepath.Join(backupDir, newName)); err != nil {
			fmt.Println(stylize("[warn] could not migrate backups: "+err.Error(), "yellow"))
		}
	}
}

func loadSession(name string) *Session {
	data, err := os.ReadFile(sessionPath(name))
	if err != nil {
		return nil
	}
	var s Session
	if json.Unmarshal(data, &s) != nil {
		return nil
	}
	// A session saved mid tool-batch (SIGTERM, crash, OOM kill) can carry an
	// assistant message whose tool_calls never got results; every subsequent
	// API round would then 400 on the unmatched function_call (audit2 §4.4).
	// Repair on load so an interrupted investigation stays resumable.
	s.Messages = repairToolCallPairing(s.Messages)
	return &s
}

// repairToolCallPairing appends a synthetic tool result for any assistant
// tool_call missing its result, preserving the function_call /
// function_call_output pairing the Responses API requires (audit2 §4.4).
func repairToolCallPairing(msgs []Message) []Message {
	for i := 0; i < len(msgs); i++ {
		m := msgs[i]
		if m.Role != "assistant" || len(m.ToolCalls) == 0 {
			continue
		}
		have := map[string]bool{}
		j := i + 1
		for ; j < len(msgs) && msgs[j].Role == "tool"; j++ {
			have[msgs[j].ToolCallID] = true
		}
		var missing []Message
		for _, tc := range m.ToolCalls {
			if !have[tc.ID] {
				missing = append(missing, Message{
					Role: "tool", ToolCallID: tc.ID, Name: tc.Name,
					Content: "[interrupted] tool result missing (session saved mid-batch)",
				})
			}
		}
		if len(missing) > 0 {
			tail := append(missing, msgs[j:]...)
			msgs = append(msgs[:j], tail...)
			i = j + len(missing) - 1 // continue after the repaired tool block
		}
	}
	return msgs
}

// sanitizeForDisplay escapes C0 control characters (including \r and ESC) so
// a hostile command string cannot redraw the line the user is reading or
// smuggle terminal sequences into the journal (audit2 §3.1). Tabs are kept
// (common and benign); newlines become visible \n.
func sanitizeForDisplay(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\033':
			b.WriteString(`\e`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func newSession(name, provider, model, systemPrompt, baseURL string) *Session {
	return &Session{
		Name: name, Provider: provider, Model: model, BaseURL: baseURL,
		SystemPrompt: systemPrompt, CreatedAt: nowISO(), UpdatedAt: nowISO(),
		Messages: []Message{},
	}
}

// exportSession exports the session to a Markdown file; returns (path, overwritten).
// Message contents are already Markdown, so they are dumped verbatim under role
// headings; metadata goes into a leading blockquote.
func exportSession(s *Session, dest string) (string, bool) {
	var b strings.Builder
	b.WriteString("# " + s.Name + "\n\n")
	fmt.Fprintf(&b, "> provider=%s  model=%s  created %s\n", s.Provider, s.Model, s.CreatedAt)
	if s.SystemPrompt != "" {
		fmt.Fprintf(&b, "> system: %s\n", s.SystemPrompt)
	}
	for _, m := range s.Messages {
		role := "Assistant"
		if m.Role == "user" {
			role = "User"
		}
		fmt.Fprintf(&b, "\n## %s\n\n%s\n", role, m.Content)
	}
	path := dest
	if path == "" {
		path = filepath.Join(exportDir, s.Name+".md")
	}
	if strings.HasPrefix(path, "~/") {
		path = filepath.Join(os.Getenv("HOME"), path[2:])
	}
	if filepath.Ext(path) == "" {
		path += ".md"
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	_, err := os.Stat(path)
	overwritten := err == nil
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		fmt.Println(stylize("[error] cannot export session: "+err.Error(), "red"))
		return "", false
	}
	return path, overwritten
}

// --------------------------------------------------------------------------
// API calls (unified as call(messages, system, model, apiKey) -> string)
// --------------------------------------------------------------------------

var errInterrupted = fmt.Errorf("interrupted")

// apiErrorHint maps common HTTP failures to a "how to fix" suggestion
// (audit A8): the startup key-missing error already guides the user, runtime
// API errors should too.
func apiErrorHint(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "HTTP 401") || strings.Contains(s, "HTTP 403"):
		return "authentication failed — check the api key: frza config show (set a fresh one with frza config set --provider <provider> --api-key KEY)"
	case strings.Contains(s, "HTTP 404"):
		return "not found — the model name may not exist on this provider (/model), or the base url is wrong (/baseurl)"
	case strings.Contains(s, "HTTP 429"):
		return "rate limited — frza retries automatically; if this persists, wait a bit or switch /model"
	}
	return ""
}

func httpPostJSON(ctx context.Context, url string, headers map[string]string, payload interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := doWithRetries(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return req, nil
	}, httpClientSync, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		// include status and a body peek: a 200 carrying an HTML error page
		// otherwise surfaces as an opaque "invalid character '<'" (M13)
		return nil, fmt.Errorf("failed to parse response (HTTP %d): %v: %.100s", resp.StatusCode, err, body)
	}
	return result, nil
}

// No overall timeout on streaming requests (long generations could exceed any
// fixed total deadline); cancellation is done via context, and the SSE parser
// has its own idle watchdog.
var httpClient = &http.Client{}

// httpClientSync serves the non-streaming chat calls (anthropic/openai/
// gemini): a server that accepts the connection but never answers must not
// hang the REPL forever (audit 3.7). Retries come from doWithRetries.
var httpClientSync = &http.Client{
	Timeout: 5 * time.Minute,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 60 * time.Second,
	},
}

// Caps on response bodies read into memory (audit 3.7: an uncapped ReadAll
// lets a misconfigured base-url OOM the process; error bodies likewise).
const (
	maxResponseBodyBytes = 10 << 20
	maxErrorBodyBytes    = 1 << 20
)

// retryBackoffs for transient API failures (429/5xx/network); a var so tests
// can shrink the waits.
var retryBackoffs = []time.Duration{time.Second, 4 * time.Second, 15 * time.Second}

// retryAfterDelay parses a Retry-After header (delta-seconds or HTTP-date).
func retryAfterDelay(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// doWithRetries issues an HTTP request, retrying network errors and 429/5xx
// (design §3.7: agent loops amplify call counts, so transient blips are the
// norm). A Retry-After header on 429 wins over the schedule when it asks for
// a longer wait (audit 3.7); other 4xx fail fast. makeReq must build a fresh
// request per attempt. The caller owns the returned body.
func doWithRetries(ctx context.Context, makeReq func() (*http.Request, error), client *http.Client, onRetry func(string)) (*http.Response, error) {
	backoffs := retryBackoffs
	for attempt := 0; ; attempt++ {
		req, err := makeReq()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		var failMsg string
		var delay time.Duration
		if err != nil {
			if ctx.Err() == context.Canceled {
				return nil, errInterrupted
			}
			// A client-side timeout is not a transient blip: with the sync
			// client's 5-minute timeout, 4 attempts would mean ~20 minutes
			// before the user sees an error. Fail fast instead (audit2 M3).
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil, fmt.Errorf("request timed out: %v", err)
			}
			failMsg = fmt.Sprintf("network error: %v", err)
		} else if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
			resp.Body.Close()
			failMsg = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncateStr(string(body), 200))
			if resp.StatusCode == 429 {
				delay = retryAfterDelay(resp.Header.Get("Retry-After"))
			}
		} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStr(string(body), 500))
		} else {
			return resp, nil
		}
		if attempt >= len(backoffs) {
			return nil, fmt.Errorf("%s (after %d attempts)", failMsg, attempt+1)
		}
		if d := backoffs[attempt]; d > delay {
			delay = d
		}
		if onRetry != nil {
			onRetry(fmt.Sprintf("retry %d/%d after: %s", attempt+1, len(backoffs), failMsg))
		}
		select {
		case <-ctx.Done():
			return nil, errInterrupted
		case <-time.After(delay):
		}
	}
}

func asMap(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	return m
}

func asSlice(v interface{}) []interface{} {
	s, _ := v.([]interface{})
	return s
}

func asString(v interface{}) string {
	s, _ := v.(string)
	return s
}

func callAnthropic(ctx context.Context, messages []Message, system, model, apiKey, baseURL string, tools []Tool, onDelta, onReasoning func(string)) (CallResult, error) {
	msgs := []map[string]string{}
	for _, m := range messages {
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}
	payload := map[string]interface{}{"model": model, "max_tokens": 8192, "messages": msgs}
	if system != "" {
		payload["system"] = system
	}
	// Respect a configured gateway/proxy like callOpenAI does (audit 3.7)
	url := "https://api.anthropic.com/v1/messages"
	if baseURL != "" {
		url = strings.TrimRight(baseURL, "/") + "/v1/messages"
	}
	result, err := httpPostJSON(ctx, url, map[string]string{
		"content-type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01",
	}, payload)
	if err != nil {
		return CallResult{}, err
	}
	var b strings.Builder
	for _, p := range asSlice(result["content"]) {
		if asString(asMap(p)["type"]) == "text" {
			b.WriteString(asString(asMap(p)["text"]))
		}
	}
	return CallResult{Text: b.String()}, nil
}

func callOpenAI(ctx context.Context, messages []Message, system, model, apiKey, baseURL string, tools []Tool, onDelta, onReasoning func(string)) (CallResult, error) {
	url := "https://api.openai.com/v1/chat/completions"
	if baseURL != "" {
		url = strings.TrimRight(baseURL, "/") + "/chat/completions"
	}
	msgs := []map[string]string{}
	if system != "" {
		msgs = append(msgs, map[string]string{"role": "system", "content": system})
	}
	for _, m := range messages {
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}
	// Newer models (o1/o3 etc.) only accept max_completion_tokens; the legacy
	// max_tokens parameter is rejected with 400
	payload := map[string]interface{}{"model": model, "messages": msgs, "max_completion_tokens": 8192}
	headers := map[string]string{
		"content-type": "application/json", "authorization": "Bearer " + apiKey,
	}
	result, err := httpPostJSON(ctx, url, headers, payload)
	if err != nil && strings.HasPrefix(err.Error(), "HTTP 400:") &&
		(strings.Contains(err.Error(), "max_completion_tokens") ||
			strings.Contains(err.Error(), "unrecognized") ||
			strings.Contains(err.Error(), "unsupported")) {
		// Many OpenAI-compatible gateways (vLLM, older proxies) only know the
		// legacy parameter; fall back once (audit 3.7).
		payload["max_tokens"] = payload["max_completion_tokens"]
		delete(payload, "max_completion_tokens")
		result, err = httpPostJSON(ctx, url, headers, payload)
	}
	if err != nil {
		return CallResult{}, err
	}
	choices := asSlice(result["choices"])
	if len(choices) == 0 {
		return CallResult{}, fmt.Errorf("failed to parse response: no choices")
	}
	return CallResult{Text: asString(asMap(asMap(choices[0])["message"])["content"])}, nil
}

// geminiEndpoint builds the generateContent URL and auth headers. The API key
// travels in the x-goog-api-key header, never the URL query: Go's *url.Error
// includes the full URL, so a query-string key would leak into error output
// and terminal scrollback (audit B1). A configured baseURL replaces the
// default API host, like callOpenAI (audit 3.7).
func geminiEndpoint(model, apiKey, baseURL string) (string, map[string]string) {
	base := "https://generativelanguage.googleapis.com/v1beta"
	if baseURL != "" {
		base = strings.TrimRight(baseURL, "/")
	}
	url := fmt.Sprintf("%s/models/%s:generateContent", base, model)
	return url, map[string]string{"content-type": "application/json", "x-goog-api-key": apiKey}
}

func callGemini(ctx context.Context, messages []Message, system, model, apiKey, baseURL string, tools []Tool, onDelta, onReasoning func(string)) (CallResult, error) {
	url, headers := geminiEndpoint(model, apiKey, baseURL)
	contents := []map[string]interface{}{}
	for _, m := range messages {
		role := "user"
		if m.Role == "assistant" {
			role = "model"
		}
		contents = append(contents, map[string]interface{}{
			"role": role, "parts": []map[string]string{{"text": m.Content}},
		})
	}
	payload := map[string]interface{}{
		"contents":         contents,
		"generationConfig": map[string]interface{}{"maxOutputTokens": 8192},
	}
	if system != "" {
		payload["systemInstruction"] = map[string]interface{}{"parts": []map[string]string{{"text": system}}}
	}
	result, err := httpPostJSON(ctx, url, headers, payload)
	if err != nil {
		return CallResult{}, err
	}
	candidates := asSlice(result["candidates"])
	if len(candidates) == 0 {
		return CallResult{Text: "(model returned no content, possibly blocked by safety filters)"}, nil
	}
	var b strings.Builder
	for _, p := range asSlice(asMap(asMap(candidates[0])["content"])["parts"]) {
		b.WriteString(asString(asMap(p)["text"]))
	}
	return CallResult{Text: b.String()}, nil
}

// responsesInputItems maps canonical Messages to Responses API input items
// (design §3.7): tool results become function_call_output items, assistant
// tool requests are replayed as function_call items, everything else becomes
// role+input_text messages.
func responsesInputItems(messages []Message) []map[string]interface{} {
	items := []map[string]interface{}{}
	for _, m := range messages {
		switch {
		case m.Role == "tool":
			items = append(items, map[string]interface{}{
				"type": "function_call_output", "call_id": m.ToolCallID, "output": m.Content,
			})
		case m.Role == "assistant" && len(m.ToolCalls) > 0:
			if m.Content != "" {
				items = append(items, map[string]interface{}{
					"role":    m.Role,
					"content": []map[string]string{{"type": "input_text", "text": m.Content}},
				})
			}
			for _, tc := range m.ToolCalls {
				items = append(items, map[string]interface{}{
					"type": "function_call", "call_id": tc.ID, "name": tc.Name, "arguments": tc.Arguments,
				})
			}
		default:
			items = append(items, map[string]interface{}{
				"role":    m.Role,
				"content": []map[string]string{{"type": "input_text", "text": m.Content}},
			})
		}
	}
	return items
}

// callOpenAIResponses speaks the OpenAI Responses API protocol
// (POST {baseURL}/responses) with SSE streaming. Many vendors (e.g. Volcengine
// Ark) expose OpenAI-compatible capability through this protocol.
func callOpenAIResponses(ctx context.Context, messages []Message, system, model, apiKey, baseURL string, tools []Tool, onDelta, onReasoning func(string)) (CallResult, error) {
	if baseURL == "" {
		return CallResult{}, fmt.Errorf("openai_responses provider requires base_url; pass --base-url.")
	}
	url := strings.TrimRight(baseURL, "/") + "/responses"
	items := responsesInputItems(messages)
	payload := map[string]interface{}{"model": model, "input": items, "stream": true}
	if system != "" {
		payload["instructions"] = system
	}
	if len(tools) > 0 {
		ts := []map[string]interface{}{}
		for _, t := range tools {
			ts = append(ts, map[string]interface{}{
				"type": "function", "name": t.Name, "description": t.Description, "parameters": t.Schema,
			})
		}
		payload["tools"] = ts
		payload["tool_choice"] = "auto"
	}
	data, _ := json.Marshal(payload)

	// Transient failures (429/5xx/network) retry with backoff; auth and other
	// 4xx fail fast. Retries heartbeat via onReasoning to keep the spinner
	// alive.
	resp, err := doWithRetries(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+apiKey)
		return req, nil
	}, httpClient, onReasoning)
	if err != nil {
		return CallResult{}, err
	}
	defer resp.Body.Close()

	// Watchdog against half-open connections: a stream that starts but then
	// goes silent without closing must not spin forever (audit 3.7).
	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()
	body := &idleTimeoutReader{body: resp.Body, timeout: streamIdleTimeout, cancel: streamCancel}
	return parseResponsesSSE(streamCtx, body, onDelta, onReasoning)
}

// streamIdleTimeout bounds how long the SSE parser waits for the next byte
// before declaring the stream stalled. A var so tests can shrink it.
var streamIdleTimeout = 120 * time.Second

var errStreamIdle = errors.New("stream idle timeout (no bytes received)")

// idleTimeoutReader fails the read with errStreamIdle when no bytes arrive
// within timeout — SSE streams produce something (text, reasoning, gateway
// keep-alives) every few seconds, so a long silence means a half-open
// connection (audit 3.7). cancel tears down the connection so the blocked
// underlying read returns.
type idleTimeoutReader struct {
	body    io.Reader
	timeout time.Duration
	cancel  context.CancelFunc
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := r.body.Read(p)
		ch <- result{n, err}
	}()
	select {
	case res := <-ch:
		return res.n, res.err
	case <-time.After(r.timeout):
		if r.cancel != nil {
			r.cancel()
		}
		return 0, errStreamIdle
	}
}

// parseResponsesSSE consumes the SSE stream of the Responses API and returns
// the accumulated assistant text plus any tool calls. Decoupled from HTTP so
// recorded streams can be replayed in tests.
//
// Event flow (verified against Ark kimi-k3, 2026-09-09): reasoning deltas and
// output_text deltas interleave with function_call items; argument deltas key
// on item_id (fc_...) while the model-visible call_id (bash_0) arrives in
// response.output_item.added, so we map one to the other and keep calls in
// output_index order.
func parseResponsesSSE(ctx context.Context, body io.Reader, onDelta, onReasoning func(string)) (CallResult, error) {
	var full strings.Builder
	var currentEvent string
	fcByItem := map[string]*ToolCall{}
	var fcOrder []string
	collectCalls := func() []ToolCall {
		if len(fcOrder) == 0 {
			return nil
		}
		calls := make([]ToolCall, 0, len(fcOrder))
		for _, id := range fcOrder {
			calls = append(calls, *fcByItem[id])
		}
		return calls
	}
	reader := bufio.NewReader(body)
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			if strings.HasPrefix(line, "event:") {
				currentEvent = strings.TrimSpace(line[len("event:"):])
			} else if strings.HasPrefix(line, "data:") {
				dataStr := strings.TrimSpace(line[len("data:"):])
				if dataStr != "" && dataStr != "[DONE]" {
					var evt map[string]interface{}
					if json.Unmarshal([]byte(dataStr), &evt) == nil {
						etype := currentEvent
						if etype == "" {
							etype = asString(evt["type"])
						}
						switch etype {
						case "response.output_text.delta":
							if d := asString(evt["delta"]); d != "" {
								full.WriteString(d)
								if onDelta != nil {
									onDelta(d)
								}
							}
						case "response.reasoning_summary_text.delta":
							// Reasoning deltas don't count as reply content; used
							// only as a "still thinking" heartbeat for the spinner
							if onReasoning != nil {
								onReasoning(asString(evt["delta"]))
							}
						case "response.output_item.added":
							if item := asMap(evt["item"]); asString(item["type"]) == "function_call" {
								itemID := asString(item["id"])
								fcByItem[itemID] = &ToolCall{ID: asString(item["call_id"]), Name: asString(item["name"])}
								fcOrder = append(fcOrder, itemID)
							}
						case "response.function_call_arguments.delta":
							if tc, ok := fcByItem[asString(evt["item_id"])]; ok {
								tc.Arguments += asString(evt["delta"])
							}
							// heartbeat so the spinner keeps moving while the
							// model composes tool arguments
							if onReasoning != nil {
								onReasoning("")
							}
						case "response.function_call_arguments.done":
							// deltas already accumulated; .done carries the full
							// arguments as a fallback
							if tc, ok := fcByItem[asString(evt["item_id"])]; ok && tc.Arguments == "" {
								tc.Arguments = asString(evt["arguments"])
							}
						case "response.failed":
							msg := asString(asMap(asMap(evt["response"])["error"])["message"])
							if msg == "" {
								msg = "unknown error"
							}
							return CallResult{}, fmt.Errorf("upstream error: %s", msg)
						case "response.completed":
							return CallResult{Text: full.String(), ToolCalls: collectCalls()}, nil
						}
					}
				}
			}
		}
		if err != nil {
			// Idle watchdog fired before any ctx cancellation — report the
			// stall, not a user interrupt (audit 3.7).
			if errors.Is(err, errStreamIdle) {
				return CallResult{}, fmt.Errorf("stream stalled (no data for %s): %w", streamIdleTimeout, err)
			}
			if ctx.Err() == context.Canceled {
				return CallResult{}, errInterrupted
			}
			// Stream ended without response.completed (connection reset, TLS
			// failure): returning partial output here would record a truncated
			// answer — or execute a tool with truncated JSON arguments — as if
			// the call had succeeded (review F4). Treat as an error instead.
			return CallResult{}, fmt.Errorf("stream ended prematurely (before response.completed): %v", err)
		}
	}
	// no return needed past the loop: every path out returns (response.completed,
	// cancellation, or premature-end error)
}

// callerFunc is the uniform provider call. tools is the set offered to the
// model this round (nil/empty for plain chat); providers without tool support
// ignore it. Callers that support tools surface requests in CallResult.ToolCalls.
type callerFunc func(ctx context.Context, messages []Message, system, model, apiKey, baseURL string, tools []Tool, onDelta, onReasoning func(string)) (CallResult, error)

var callers = map[string]callerFunc{
	"anthropic":        callAnthropic,
	"openai":           callOpenAI,
	"gemini":           callGemini,
	"openai_responses": callOpenAIResponses,
}

func callModel(ctx context.Context, provider string, messages []Message, system, model, apiKey, baseURL string, tools []Tool, onDelta, onReasoning func(string)) (CallResult, error) {
	fn, ok := callers[provider]
	if !ok {
		return CallResult{}, fmt.Errorf("unknown provider: %s", provider)
	}
	return fn(ctx, messages, system, model, apiKey, baseURL, tools, onDelta, onReasoning)
}

// --------------------------------------------------------------------------
// Agent tools & safety model
//   bash command classification (chain-aware), output truncation, operation
//   journal (append-only, secret-redacted), file backups for pre-undo state.
// --------------------------------------------------------------------------

// commandRisk classifies one shell command line (whole chain).
type commandRisk int

const (
	riskReadonly   commandRisk = iota // every chain segment is a whitelisted read-only command
	riskReversible                    // ordinary change; confirm, log
	riskDangerous                     // irreversible/destructive; red warning, backup targets when identifiable
	riskUnknown                       // unrecognized or contains command substitution; treat as reversible+confirm
)

// readonlyCmds: first-token whitelist. true = plainly read-only; false = needs
// no entry here (kept in readonlySubcmds or not read-only).
var readonlyCmds = map[string]bool{
	"ls": true, "cat": true, "grep": true, "egrep": true, "fgrep": true, "zgrep": true,
	"head": true, "tail": true, "more": true, "wc": true, "sort": true,
	"uniq": true, "cut": true, "tr": true, "diff": true,
	"find": true, "which": true, "whereis": true, "type": true, "file": true, "stat": true,
	"df": true, "du": true, "free": true, "top": true, "htop": true, "ps": true,
	"uptime": true, "uname": true, "whoami": true, "id": true, "w": true,
	"cal": true, "printenv": true, "echo": true, "printf": true,
	"pwd": true, "history": true, "alias": true, "jobs": true,
	"vmstat": true, "iostat": true, "mpstat": true, "pidstat": true,
	"ss": true, "netstat": true, "ip": true, "ifconfig": true, "ping": true, "dig": true,
	"nslookup": true, "host": true, "traceroute": true,
	"lsof": true, "lsblk": true, "lsmod": true, "lspci": true, "lsusb": true, "lscpu": true,
	"journalctl": true, "last": true, "lastlog": true, "crash": true,
	"zcat": true, "zipinfo": true, "jq": true, "strings": true,
	"nm": true, "objdump": true, "readelf": true, "pstack": true,
	// Deliberately NOT whitelisted (audit A2): xargs/env execute the command
	// they wrap (`ls | xargs mv`, `env mv a b`), and awk/sed scripts can run
	// commands (system(), `e` cmd) or write files (`w file`, -i) in ways field
	// matching cannot detect. They fall through to riskReversible (confirm).
	//
	// Also NOT whitelisted (audit2 §1.3): date (-s/positional sets the clock),
	// hostname (any operand sets it), dmesg (-C destroys the ring buffer,
	// i.e. incident evidence), less (-o writes a log file).
}

// readonlySubcmds: read-only only for specific subcommands (checked against the
// second token of the segment).
var readonlySubcmds = map[string][]string{
	"systemctl": {"status", "list-units", "list-unit-files", "is-active", "is-enabled", "show", "cat", "--version"},
	"kubectl":   {"get", "describe", "logs", "explain", "api-resources", "api-versions", "cluster-info", "top"},
	// branch/tag/remote deliberately excluded: their bare forms list, but
	// `git branch -D`, `git tag -d`, `git remote remove` delete (review F3)
	"git":    {"status", "log", "diff", "show", "blame", "ls-files", "rev-parse"},
	"tar":    {"-tf", "-tvf", "--list"},
	"sysctl": {"-a", "-n"},
	"mount":  {""}, // bare `mount` only
}

// dangerousFilePatterns: damage that is file-targeted and therefore undoable
// from a pre-execution backup (rm operands, > / >> overwrite targets).
var dangerousFilePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\brm\b`),
	regexp.MustCompile(`>\s*[^&\s]`), // > file / >> file redirection (overwrite)
}

// dangerousSystemPatterns: damage no file backup can undo (services, kernel,
// disks, processes). A dangerous command may only be downgraded to the
// reversible confirmation tier when NOTHING from this set matches —
// otherwise `rm -f /tmp/decoy && systemctl restart postgres` would ride the
// decoy's backup down to auto-approval (audit2 §2.1).
var dangerousSystemPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\brmdir\b`),
	regexp.MustCompile(`\bmkfs\b`),
	regexp.MustCompile(`\bdd\b`),
	regexp.MustCompile(`\bshred\b`),
	regexp.MustCompile(`\btruncate\b`),
	regexp.MustCompile(`\b(kill|pkill|killall)\b`),
	regexp.MustCompile(`\b(reboot|shutdown|halt|poweroff)\b`),
	regexp.MustCompile(`\bsystemctl\s+(stop|restart|disable|mask)\b`),
	regexp.MustCompile(`\bkubectl\s+(delete|drain|cordon|scale)\b`),
	regexp.MustCompile(`\b(chmod|chown|chgrp)\s+-R\b`),
	// word boundary alone would match the path in `cat /etc/passwd` (M6):
	// require a line start / whitespace / chain operator before the word
	regexp.MustCompile(`(?:^|[\s;|&])(useradd|userdel|passwd)\b`),
	regexp.MustCompile(`\b(iptables|nft)\b`),
	regexp.MustCompile(`\b(fdisk|parted|sgdisk)\b`),
	regexp.MustCompile(`\b(swapoff|swapon)\b`),
}

// dangerousPatterns matched against the raw (unsplit) command; any hit
// escalates the whole chain to riskDangerous.
var dangerousPatterns = append(append([]*regexp.Regexp{}, dangerousFilePatterns...), dangerousSystemPatterns...)

// dangerousOnlyFileTargeted reports whether cmd trips ONLY file-targeted
// dangerous patterns — the sole case where "all targets backed up" may
// downgrade the confirmation tier (audit2 §2.1). Preprocessed exactly like
// classifyCommand.
func dangerousOnlyFileTargeted(cmd string) bool {
	cmd = nullRedirect.ReplaceAllString(cmd, "")
	for _, re := range dangerousSystemPatterns {
		if re.MatchString(cmd) {
			return false
		}
	}
	return true
}

// splitChain splits a command line on shell chain operators ; && || | and on
// newlines — bash -c treats '\n' as a command separator, so a whitelisted
// first line must not "escort" arbitrary commands after it (audit2 §1.1).
// Single/double quotes are respected (a newline inside quotes stays put).
// Best-effort: unmatched quotes degrade to a single segment.
func splitChain(cmd string) []string {
	var segs []string
	var b strings.Builder
	var quote rune // 0, '\'', or '"'
	flush := func() {
		if s := strings.TrimSpace(b.String()); s != "" {
			segs = append(segs, s)
		}
		b.Reset()
	}
	runes := []rune(cmd)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if quote != 0 {
			b.WriteRune(r)
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
			b.WriteRune(r)
		case '\n', '\r':
			flush() // newline is a command separator to bash (audit2 §1.1)
		case ';', '|':
			flush()
			if r == '|' && i+1 < len(runes) && runes[i+1] == '|' {
				i++ // skip second |
			}
		case '&':
			flush()
			if i+1 < len(runes) && runes[i+1] == '&' {
				i++ // skip second &
			}
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return segs
}

// splitShellFields splits a command segment into fields while respecting
// single/double quotes — `rm "a b"` yields the single operand `a b`, unlike
// strings.Fields which would split it in two (audit 3.9). Quotes are stripped
// from the result. Best-effort, like splitChain.
func splitShellFields(seg string) []string {
	var fields []string
	var b strings.Builder
	var quote rune // 0, '\'', or '"'
	flush := func() {
		if b.Len() > 0 {
			fields = append(fields, b.String())
			b.Reset()
		}
	}
	for _, r := range seg {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return fields
}

func firstToken(seg string) string {
	fields := strings.Fields(seg)
	if len(fields) == 0 {
		return ""
	}
	name := fields[0]
	if !strings.ContainsRune(name, '/') {
		return name // bare name: resolved via PATH at exec time
	}
	// An explicit path is trusted only from a system bin dir — otherwise
	// /tmp/evil/ls inherits ls's read-only status and, combined with
	// write_file, becomes a persistent approval-free exec path (audit2 §1.4)
	switch filepath.Dir(name) {
	case "/bin", "/usr/bin", "/sbin", "/usr/sbin":
		return filepath.Base(name)
	}
	return ""
}

func nthToken(seg string, n int) string {
	fields := strings.Fields(seg)
	if len(fields) <= n {
		return ""
	}
	return fields[n]
}

// writeFlags: flags that turn an otherwise read-only command into a writer.
// A whitelisted command carrying any of these is NOT read-only — e.g.
// `sed -i`, `find -delete`, `sort -o`, `journalctl --vacuum-*`.
var writeFlags = map[string][]string{
	"find":       {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls", "-fprint", "-fprintf"},
	"sort":       {"-o", "--output"},
	"journalctl": {"--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush", "--sync", "--relinquish-var"},
	"ip":         {"add", "del", "delete", "set", "change", "replace", "flush", "save", "restore"},
	"ifconfig":   {"up", "down", "add", "delete", "mtu", "netmask", "broadcast", "promisc", "hw", "pointopoint", "dstaddr", "txqueuelen"},
	// audit2 §1.3: whitelisted commands with built-in write/exec forms
	"git":    {"--output"}, // git diff/log/show --output=F overwrites F
	"sysctl": {"-w", "--write"},
	"ss":     {"-K", "--kill"},                                 // destroys sockets in the kernel
	"tar":    {"-I", "--use-compress-program", "--to-command"}, // runs the program even in list mode
	"ping":   {"-f"},                                           // flood ping
}

// isReadonlySegment reports whether a single chain segment is a known
// read-only invocation (whitelist + subcommand/flag checks).
func isReadonlySegment(seg string) bool {
	// Redirects inside the segment (e.g. `cat x > y`) make it a write
	if strings.Contains(seg, ">") {
		return false
	}
	tok := firstToken(seg)
	if tok == "" {
		return false
	}
	if subs, ok := readonlySubcmds[tok]; ok {
		sub := nthToken(seg, 1)
		found := false
		for _, s := range subs {
			if s == sub {
				found = true
			}
		}
		if !found {
			return false
		}
		// a matching subcommand is read-only only if it also survives the
		// writeFlags check below — `git diff` lists, but `git diff
		// --output=F` overwrites F (audit2 §1.3)
	} else if !readonlyCmds[tok] {
		return false
	}
	// whitelisted command, but a write-capable flag/subcommand revokes it.
	// Short options match by prefix so attached values can't slip past
	// (`sort -oout.txt`; audit A3). Long options additionally match
	// unambiguous abbreviations — getopt_long and git accept
	// `journalctl --vacuum-ti=1d`, `git diff --outp=F` (audit2 §1.3).
	if bad, ok := writeFlags[tok]; ok {
		for _, field := range strings.Fields(seg)[1:] {
			f0 := field // option name without any =value
			if i := strings.IndexByte(f0, '='); i >= 0 {
				f0 = f0[:i]
			}
			for _, b := range bad {
				switch {
				case len(b) >= 2 && b[0] == '-' && b[1] != '-':
					if strings.HasPrefix(field, b) { // short option
						return false
					}
				case strings.HasPrefix(b, "--"):
					if f0 == b || (len(f0) >= 4 && strings.HasPrefix(b, f0)) {
						return false
					}
				case field == b: // subcommand word
					return false
				}
			}
		}
	}
	return true
}

// nullRedirect matches harmless output discards: 2>/dev/null, 2>&1,
// &>/dev/null, >/dev/null 2>&1 etc. These are idiomatic noise suppression,
// not writes — without stripping them, `du -sh . 2>/dev/null` would match the
// overwrite-redirect dangerous pattern. `&>` is stripped ONLY when its target
// is /dev/null: `cmd &> file` is a combined stdout+stderr overwrite and must
// stay visible to the dangerous-pattern scan (audit A1).
var nullRedirect = regexp.MustCompile(`\s+(&>+\s*/dev/null|\d*>&\d+|\d*>+\s*/dev/null|>+\s*/dev/null)(\s+2>&1)?`)

// classifyCommand implements the design doc §3.6: split the chain, grade every
// segment, take the worst. Dangerous raw patterns escalate FIRST — a
// destructive payload wrapped in $(...) must grade dangerous, not slip down
// to the laxer unknown tier (audit2 §1.2). Remaining command substitution
// $(...)/backticks and process substitution <(...)/>(...) cannot be
// statically graded -> riskUnknown (audit A4).
func classifyCommand(cmd string) commandRisk {
	cmd = nullRedirect.ReplaceAllString(cmd, "")
	for _, re := range dangerousPatterns {
		if re.MatchString(cmd) {
			return riskDangerous
		}
	}
	if strings.Contains(cmd, "$(") || strings.Contains(cmd, "`") ||
		strings.Contains(cmd, "<(") || strings.Contains(cmd, ">(") {
		return riskUnknown
	}
	segs := splitChain(cmd)
	if len(segs) == 0 {
		return riskUnknown
	}
	for _, seg := range segs {
		if !isReadonlySegment(seg) {
			// non-whitelisted but non-dangerous segment: presumably a
			// reversible change
			return riskReversible
		}
	}
	return riskReadonly
}

// --------------------------------------------------------------------------
// Context management (design §3.8): keep the conversation within a token
// budget. Stage 1 compresses the oldest tool outputs (structure preserved —
// tool_call pairing must survive); stage 2 drops the oldest whole turn groups
// (a user message plus its assistant/tool follow-ups) so no orphaned
// function_call_output ever reaches the API.
// --------------------------------------------------------------------------

// estimateTokens is a rough upper-bound heuristic: ASCII ~4 chars/token,
// CJK ~1.5 tokens/char. Stability over precision (cost control, not billing).
func estimateTokens(s string) int {
	score := 0
	for _, r := range s {
		if r < 128 {
			score++
		} else {
			score += 6
		}
	}
	return score / 4
}

func messagesTokens(msgs []Message) int {
	total := 0
	for _, m := range msgs {
		total += estimateTokens(m.Content) + 4
		for _, tc := range m.ToolCalls {
			total += estimateTokens(tc.Arguments) + 8
		}
	}
	return total
}

const compressedToolNote = "[earlier tool output omitted to fit the context budget]"

// trimContext brings msgs under budget. Returns the (possibly shortened) slice
// and the number of dropped turn groups; a marker user message is prepended
// when groups were dropped. The input slice is not mutated (compressed entries
// are copies).
func trimContext(msgs []Message, budget int) ([]Message, int) {
	if messagesTokens(msgs) <= budget {
		return msgs, 0
	}
	// Stage 1: compress tool outputs oldest-first until under budget
	out := make([]Message, len(msgs))
	copy(out, msgs)
	for i := range out {
		if messagesTokens(out) <= budget {
			return out, 0
		}
		if out[i].Role == "tool" && out[i].Content != compressedToolNote {
			out[i].Content = compressedToolNote + " (tool: " + out[i].Name + ")"
		}
	}
	if messagesTokens(out) <= budget {
		return out, 0
	}
	// Stage 2: drop oldest turn groups (a user message + following
	// assistant/tool messages up to the next user message)
	groups := [][]Message{}
	cur := -1
	for _, m := range out {
		if m.Role == "user" {
			groups = append(groups, nil)
			cur++
		}
		if cur < 0 { // leading non-user messages (shouldn't happen)
			groups = append(groups, nil)
			cur++
		}
		groups[cur] = append(groups[cur], m)
	}
	dropped := 0
	for len(groups) > 1 && messagesTokens(flattenGroups(groups)) > budget {
		groups = groups[1:]
		dropped++
	}
	trimmed := flattenGroups(groups)
	if dropped > 0 {
		marker := Message{Role: "user", Content: fmt.Sprintf(
			"[context note: the %d oldest conversation rounds and their tool outputs were omitted to fit the context budget]", dropped)}
		trimmed = append([]Message{marker}, trimmed...)
	}
	return trimmed, dropped
}

func flattenGroups(groups [][]Message) []Message {
	var out []Message
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// truncateToolOutput keeps the first headLines and last tailLines, and enforces
// a hard byte cap; the truncation marker carries the omitted line count so the
// model knows to switch to search/preprocess strategies (§3.4).
func truncateToolOutput(s string, headLines, tailLines, maxBytes int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > headLines+tailLines {
		kept := append([]string{}, lines[:headLines]...)
		omitted := len(lines) - headLines - tailLines
		kept = append(kept, fmt.Sprintf("[... truncated: %d of %d lines omitted ...]", omitted, len(lines)))
		kept = append(kept, lines[len(lines)-tailLines:]...)
		s = strings.Join(kept, "\n")
	}
	if len(s) > maxBytes {
		s = cutAtRuneBoundary(s, maxBytes) + fmt.Sprintf("\n[... truncated at %d bytes ...]", maxBytes)
	}
	return s
}

// cutAtRuneBoundary shortens s to at most n bytes without splitting a
// multibyte UTF-8 rune (byte slicing mid-rune produces invalid UTF-8, which
// renders as U+FFFD for the model and the user; audit 3.8). If the cut may
// have left an open ANSI escape sequence, a reset is appended so the style
// doesn't bleed into whatever follows.
func cutAtRuneBoundary(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n-- // UTF-8 continuation byte: back off to the rune start
	}
	s = s[:n]
	if strings.Contains(s, "\033[") {
		s += "\033[0m"
	}
	return s
}

// redactSecrets masks common credential shapes before anything hits the journal.
var (
	secretDashP    = regexp.MustCompile(`(?i)(-p)(\S+)`)
	secretSpacedP  = regexp.MustCompile(`(?i)(-p)\s+(\S+)`)
	mysqlContextRe = regexp.MustCompile(`(?i)\bmysql(dump)?\b`)
	secretBearer   = regexp.MustCompile(`(?i)(bearer\s+)(\S+)`)
	secretKeyword  = regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api[_-]?key|authorization)[\w-]*)(["'\s:=]+)(?:bearer\s+)?(\S+)`)
)

func redactSecrets(s string) string {
	// -p<password> only inside a mysql/mysqldump invocation (M7): applied
	// globally it mangles `ssh -p2222`, and `mysql -p secret` (space form) is
	// a real leak the old rule missed entirely.
	if mysqlContextRe.MatchString(s) {
		s = secretDashP.ReplaceAllString(s, "${1}***")
		s = secretSpacedP.ReplaceAllString(s, "${1} ***")
	}
	s = secretBearer.ReplaceAllString(s, "${1}***")
	s = secretKeyword.ReplaceAllString(s, "${1}${2}***")
	return s
}

// --------------------------------------------------------------------------
// Operation journal (§3.6): append-only JSONL per session, mode 0600.
// --------------------------------------------------------------------------

var journalDir = filepath.Join(appDir, "journal")

type journalEntry struct {
	Time     string `json:"time"`
	Session  string `json:"session"`
	Source   string `json:"source"` // "model" | "user"
	Tool     string `json:"tool"`
	Args     string `json:"args"`              // redacted
	Confirm  string `json:"confirm,omitempty"` // "auto" | "y" | "n" | "always" | "user-direct"
	Risk     string `json:"risk,omitempty"`
	Result   string `json:"result,omitempty"` // summary, redacted, truncated
	ExitCode int    `json:"exit_code,omitempty"`
	// Undo metadata (§3.6): a file backed up before a destructive op, or a
	// file created by a write op (undo = delete). Undone marks already-rolled-back.
	BackupOf string `json:"backup_of,omitempty"`
	BackupTo string `json:"backup_to,omitempty"`
	Created  string `json:"created,omitempty"`
	Undone   bool   `json:"undone,omitempty"`
}

var backupDir = filepath.Join(appDir, "backups")

// backupFile copies path into the session's backup dir; returns the backup
// path ("" on failure). Directories are not backed up (too heavy; the journal
// still records the operation for manual recovery).
func backupFile(sessionName, path string) string {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return ""
	}
	dir := filepath.Join(backupDir, sessionName)
	if os.MkdirAll(dir, 0o700) != nil {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*"))
	dst := filepath.Join(dir, fmt.Sprintf("%04d-%s", len(matches)+1, filepath.Base(path)))
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if os.WriteFile(dst, data, info.Mode()) != nil {
		return ""
	}
	return dst
}

// rmTargetRe finds file operands of rm (skipping flags and an optional
// sudo/doas prefix — `sudo rm -rf /data` deserves a backup just the same,
// audit 3.9); redirectTargetRe finds overwrite targets of > / >> (excluding
// fd merges and /dev/null).
var (
	rmTargetRe       = regexp.MustCompile(`(?:^|&&|\|\||;|\|)\s*(?:sudo\s+|doas\s+)?rm\s+((?:-\S+\s+)*)([^;&|]+)`)
	redirectTargetRe = regexp.MustCompile(`(?:^|[^0-9&>])>>?\s*([^&\s|;]+)`)
)

// backupTargetsFor extracts the files a dangerous command is about to destroy
// or clobber, best-effort (design §3.6: back up what we can identify).
func backupTargetsFor(cmd string) []string {
	var targets []string
	for _, m := range rmTargetRe.FindAllStringSubmatch(cmd, -1) {
		for _, f := range splitShellFields(m[2]) {
			if !strings.HasPrefix(f, "-") {
				targets = append(targets, f)
			}
		}
	}
	for _, m := range redirectTargetRe.FindAllStringSubmatch(cmd, -1) {
		t := strings.Trim(m[1], "\"'")
		if t != "/dev/null" && !strings.HasPrefix(t, "/dev/fd") {
			targets = append(targets, t)
		}
	}
	return targets
}

func journalPath(sessionName string) string {
	var b strings.Builder
	for _, r := range sessionName {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	safe := b.String()
	if safe == "" {
		safe = "session"
	}
	return filepath.Join(journalDir, safe+".jsonl")
}

func journalWrite(e journalEntry) {
	os.MkdirAll(journalDir, 0o700)
	e.Args = redactSecrets(truncateStr(e.Args, 500))
	e.Result = redactSecrets(truncateStr(e.Result, 500))
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	p := journalPath(e.Session)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		fmt.Println(stylize("[error] journal write failed: "+err.Error(), "red"))
	}
	os.Chmod(p, 0o600)
}

// undoLatest rolls back the most recent restorable operation in the session
// journal (design §3.6 reverse WAL replay): a backup is restored to its
// original path, or an agent-created file is deleted. The undo itself is
// journaled so repeated calls walk backwards through history. Returns a
// human-readable outcome.
func undoLatest(sessionName string) string {
	data, err := os.ReadFile(journalPath(sessionName))
	if err != nil {
		return "(no journal entries for this session)"
	}
	var entries []journalEntry
	for _, ln := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e journalEntry
		if json.Unmarshal([]byte(ln), &e) == nil {
			entries = append(entries, e)
		}
	}
	// paths already rolled back (recorded by previous undo entries)
	undone := map[string]bool{}
	for _, e := range entries {
		if e.Tool == "undo" {
			if e.BackupTo != "" {
				undone[e.BackupTo] = true
			}
			if e.Created != "" {
				undone[e.Created] = true
			}
		}
	}
	now := time.Now().Format("2006-01-02T15:04:05")
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.Tool == "undo" {
			continue
		}
		switch {
		case e.BackupTo != "" && !undone[e.BackupTo]:
			data, err := os.ReadFile(e.BackupTo)
			if err != nil {
				return fmt.Sprintf("backup %s missing: %v", e.BackupTo, err)
			}
			// Restore the original permission bits too — the backup file
			// itself carries them (see backupFile). A 0600 config must not
			// come back world-readable and a script must not lose its exec
			// bit (audit 3.6).
			mode := os.FileMode(0o644)
			if info, serr := os.Stat(e.BackupTo); serr == nil {
				mode = info.Mode().Perm()
			}
			if err := os.WriteFile(e.BackupOf, data, mode); err != nil {
				return fmt.Sprintf("restore failed: %v", err)
			}
			journalWrite(journalEntry{Time: now, Session: sessionName, Source: "user", Tool: "undo",
				Args: "restore " + e.BackupOf, BackupTo: e.BackupTo, Result: "ok"})
			return fmt.Sprintf("undone: restored %s (from %s)", e.BackupOf, e.BackupTo)
		case e.Created != "" && !undone[e.Created]:
			if err := os.Remove(e.Created); err != nil {
				return fmt.Sprintf("delete failed: %v", err)
			}
			journalWrite(journalEntry{Time: now, Session: sessionName, Source: "user", Tool: "undo",
				Args: "delete " + e.Created, Created: e.Created, Result: "ok"})
			return fmt.Sprintf("undone: deleted %s (was created by agent)", e.Created)
		}
	}
	return "(nothing to undo in this session)"
}

// --------------------------------------------------------------------------
// bash tool
// --------------------------------------------------------------------------

var bashWorkDir, _ = os.Getwd() // captured at process start

// bashTimeoutHardCap bounds the model-requested timeout_sec so a runaway
// value cannot hang the session; the config default agentBashTimeout applies
// when the model does not ask for more.
const bashTimeoutHardCap = 600 * time.Second

// boundedWriter bounds how much command output accumulates in memory: it
// keeps the first headCap and last tailCap bytes, and fires kill exactly once
// when the total crosses killCap. An infinite producer (`cat /dev/zero`,
// `yes`, `tail -f`) must not OOM the agent — especially painful on the
// production machines frza troubleshoots (audit2 §4.1). The token-facing
// truncation in runBash is a separate, smaller layer.
type boundedWriter struct {
	head    bytes.Buffer
	tail    []byte // ring holding the last tailCap bytes
	total   int64
	killCap int64
	kill    func()
	killed  bool
}

const (
	boundedHeadTail = 128 << 10
	boundedKillCap  = 4 << 20
)

func (w *boundedWriter) Write(p []byte) (int, error) {
	w.total += int64(len(p))
	if w.total > w.killCap && !w.killed {
		w.killed = true
		if w.kill != nil {
			w.kill()
		}
	}
	n := len(p)
	if w.head.Len() < boundedHeadTail {
		fill := boundedHeadTail - w.head.Len()
		if fill > len(p) {
			fill = len(p)
		}
		w.head.Write(p[:fill])
		p = p[fill:]
	}
	if len(p) > 0 { // head and tail stay disjoint
		w.tail = append(w.tail, p...)
		if len(w.tail) > boundedHeadTail {
			w.tail = append([]byte{}, w.tail[len(w.tail)-boundedHeadTail:]...)
		}
	}
	return n, nil
}

// String assembles the bounded output with a drop marker when content was
// omitted in the middle (or the process was killed for flooding).
func (w *boundedWriter) String() string {
	dropped := w.total - int64(w.head.Len()) - int64(len(w.tail))
	if dropped <= 0 {
		return w.head.String() + string(w.tail)
	}
	marker := fmt.Sprintf("\n[... %d bytes of output dropped", dropped)
	if w.killed {
		marker += fmt.Sprintf("; process killed after %d bytes ...]", w.killCap)
	} else {
		marker += " ...]"
	}
	return w.head.String() + marker + string(w.tail)
}

// execBash runs a command with a timeout and returns its combined output,
// plus whether the timeout fired. Output is memory-bounded (boundedWriter);
// token-facing truncation for the model happens in runBash, and a user-typed
// !cmd pages the (bounded) result (audit A7).
func execBash(ctx context.Context, command string, timeout time.Duration) (string, bool) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "bash", "-c", command)
	// Run bash in its own process group and kill the whole group on
	// timeout/Ctrl-C: the default kill only reaches bash itself, orphaning
	// grandchildren like `sleep 1000 | cat` on the target machine (audit 3.3).
	// frza ships darwin/linux only, so unix process-group calls are fine.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	// A daemonized grandchild keeps the inherited stdout pipe open after the
	// group dies; don't let Wait block on it forever (audit2 §4.5).
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = bashWorkDir
	out := &boundedWriter{killCap: boundedKillCap, kill: func() {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	output := out.String()
	if cctx.Err() == context.DeadlineExceeded {
		return output, true
	}
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return fmt.Sprintf("%s\n[exit code %d]", output, exit.ExitCode()), false
		}
		return output + "\n[error] " + err.Error(), false
	}
	return output, false
}

func runBash(ctx context.Context, argsJSON string) (string, error) {
	var args struct {
		Command    string `json:"command"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil || strings.TrimSpace(args.Command) == "" {
		return "", fmt.Errorf("invalid arguments: need {\"command\": \"...\"}")
	}
	timeout := agentBashTimeout
	if args.TimeoutSec > 0 {
		timeout = time.Duration(args.TimeoutSec) * time.Second
		if timeout > bashTimeoutHardCap {
			timeout = bashTimeoutHardCap
		}
		if timeout < 5*time.Second {
			timeout = 5 * time.Second
		}
	}
	output, timedOut := execBash(ctx, args.Command, timeout)
	output = truncateToolOutput(output, 200, 50, toolOutputMaxKB*1024)
	if timedOut {
		return output + fmt.Sprintf("\n[error] command timed out after %s", timeout), nil
	}
	if output == "" {
		return "(no output)", nil
	}
	return output, nil
}

// --------------------------------------------------------------------------
// read_file / search / write_file tools
// --------------------------------------------------------------------------

// toolMaxFileBytes caps how large a file read_file/search will slurp into
// memory (audit 3.9).
const toolMaxFileBytes = 64 << 20

func isBinaryData(data []byte) bool {
	n := len(data)
	if n > 512 {
		n = 512
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}

func runReadFile(ctx context.Context, argsJSON string) (string, error) {
	var args struct {
		Path   string `json:"path"`
		Offset int    `json:"offset"` // 1-based starting line
		Limit  int    `json:"limit"`  // max lines
	}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil || args.Path == "" {
		return "", fmt.Errorf("invalid arguments: need {\"path\": \"...\", \"offset\": N, \"limit\": M}")
	}
	if args.Offset <= 0 {
		args.Offset = 1
	}
	if args.Limit <= 0 {
		args.Limit = 200
	}
	if args.Limit > 2000 {
		args.Limit = 2000
	}
	// Only regular files may be slurped: devices, /proc entries and FIFOs
	// report Size()==0 (slipping past the size cap) and reading a FIFO blocks
	// forever (audit2 §4.1). Inspect those with bash tools instead.
	if info, err := os.Stat(args.Path); err == nil && !info.Mode().IsRegular() {
		return fmt.Sprintf("[not a regular file] %s (device/fifo/socket/proc) — inspect with bash tools (dd, head -c, strings) instead", args.Path), nil
	}
	// Guard against multi-GB logs: the whole file is read into memory, so a
	// stray read_file on a huge log would OOM the agent (audit 3.9). Point the
	// model at search/preprocessing instead.
	if info, err := os.Stat(args.Path); err == nil && info.Size() > toolMaxFileBytes {
		return fmt.Sprintf("[file too large] %s is %d MB (over the %d MB limit) — use search with a pattern, or bash (head/tail/grep) to preprocess", args.Path, info.Size()>>20, toolMaxFileBytes>>20), nil
	}
	data, err := os.ReadFile(args.Path)
	if err != nil {
		return "", err
	}
	if isBinaryData(data) {
		return fmt.Sprintf("[binary file] %s (%d bytes) — not displayable; use bash tools like strings/nm/objdump/crash to inspect", args.Path, len(data)), nil
	}
	lines := strings.Split(string(data), "\n")
	total := len(lines)
	if args.Offset > total {
		return fmt.Sprintf("[offset beyond end] %s has %d lines", args.Path, total), nil
	}
	end := args.Offset - 1 + args.Limit
	if end > total {
		end = total
	}
	out := strings.Join(lines[args.Offset-1:end], "\n")
	header := fmt.Sprintf("[lines %d-%d of %d]", args.Offset, end, total)
	if end < total {
		header += " — more available, use offset to continue"
	}
	return header + "\n" + truncateToolOutput(out, 2000, 0, 32768), nil
}

var searchSkipDirs = map[string]bool{
	".git": true, "node_modules": true, ".svn": true, "__pycache__": true,
	".idea": true, ".vscode": true, "vendor": true,
}

func runSearch(ctx context.Context, argsJSON string) (string, error) {
	var args struct {
		Pattern string `json:"pattern"`
		Path    string `json:"path"`
		Include string `json:"include"` // optional glob like *.log
	}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil || args.Pattern == "" {
		return "", fmt.Errorf("invalid arguments: need {\"pattern\": \"...\", \"path\": \"...\", \"include\": \"*.log\"}")
	}
	if args.Path == "" {
		args.Path = "."
	}
	re, err := regexp.Compile(args.Pattern)
	if err != nil {
		re = regexp.MustCompile(regexp.QuoteMeta(args.Pattern)) // fall back to literal
	}
	const maxResults = 100
	var results []string
	truncated := false
	skippedLarge := 0
	walkFn := func(p string, d os.DirEntry, err error) error {
		if err != nil || len(results) >= maxResults {
			return filepath.SkipAll
		}
		if ctx.Err() != nil { // Ctrl-C must stop the walk (audit2 §4.1)
			return ctx.Err()
		}
		if d.IsDir() {
			if searchSkipDirs[d.Name()] && p != args.Path {
				return filepath.SkipDir
			}
			return nil
		}
		if args.Include != "" {
			if ok, _ := filepath.Match(args.Include, d.Name()); !ok {
				return nil
			}
		}
		// Devices/proc entries/FIFOs report Size()==0 and can block forever
		// on read; only regular files are slurped (audit2 §4.1)
		info, ierr := d.Info()
		if ierr != nil || !info.Mode().IsRegular() {
			return nil
		}
		// Files beyond the size cap are slurped whole; skip them instead of
		// risking an OOM on a stray multi-GB log (audit 3.9)
		if info.Size() > toolMaxFileBytes {
			skippedLarge++
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil || isBinaryData(data) {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			if re.MatchString(line) {
				results = append(results, fmt.Sprintf("%s:%d: %s", p, i+1, truncateStr(strings.TrimSpace(line), 200)))
				if len(results) >= maxResults {
					truncated = true
					return filepath.SkipAll
				}
			}
		}
		return nil
	}
	info, statErr := os.Stat(args.Path)
	if statErr != nil {
		return "", statErr
	}
	if info.IsDir() {
		if werr := filepath.WalkDir(args.Path, walkFn); werr != nil && ctx.Err() != nil {
			return "", errInterrupted
		}
	} else if !info.Mode().IsRegular() {
		return fmt.Sprintf("[not a regular file] %s (device/fifo/socket/proc) — search a directory or use bash tools", args.Path), nil
	} else if info.Size() > toolMaxFileBytes {
		return fmt.Sprintf("[file too large] %s is %d MB (over the %d MB limit) — narrow the search with bash grep", args.Path, info.Size()>>20, toolMaxFileBytes>>20), nil
	} else {
		// single file: search it directly (skip binary). A read failure must
		// not masquerade as "no matches" — the model would conclude the
		// absence of evidence from missing evidence (M12)
		data, rerr := os.ReadFile(args.Path)
		if rerr != nil {
			return "", fmt.Errorf("cannot read %s: %w", args.Path, rerr)
		}
		if !isBinaryData(data) {
			for i, line := range strings.Split(string(data), "\n") {
				if re.MatchString(line) {
					results = append(results, fmt.Sprintf("%s:%d: %s", args.Path, i+1, truncateStr(strings.TrimSpace(line), 200)))
					if len(results) >= maxResults {
						truncated = true
						break
					}
				}
			}
		}
	}
	if len(results) == 0 {
		return fmt.Sprintf("(no matches for %q under %s)", args.Pattern, args.Path), nil
	}
	out := strings.Join(results, "\n")
	if skippedLarge > 0 {
		out += fmt.Sprintf("\n[note: skipped %d files over %d MB]", skippedLarge, toolMaxFileBytes>>20)
	}
	if truncated {
		out += fmt.Sprintf("\n[... truncated at %d matches; narrow the pattern or path ...]", maxResults)
	}
	return out, nil
}

func runWriteFile(ctx context.Context, argsJSON string) (string, error) {
	var args struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil || args.Path == "" {
		return "", fmt.Errorf("invalid arguments: need {\"path\": \"...\", \"content\": \"...\"}")
	}
	if dir := filepath.Dir(args.Path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	existed := false
	if _, err := os.Stat(args.Path); err == nil {
		existed = true
	}
	if err := os.WriteFile(args.Path, []byte(args.Content), 0o600); err != nil {
		return "", err
	}
	verb := "created"
	if existed {
		verb = "overwritten"
	}
	return fmt.Sprintf("ok: %s %s (%d bytes)", verb, args.Path, len(args.Content)), nil
}

func readFileToolDef() Tool {
	return Tool{
		Name: "read_file",
		Description: "Read a text file with line offset/limit (1-based). Binary files are detected and reported, not dumped. " +
			"For large files, read the first ~100 lines to identify the type, then use offset to sample specific regions.",
		Schema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":   map[string]interface{}{"type": "string", "description": "file path"},
				"offset": map[string]interface{}{"type": "integer", "description": "1-based starting line (default 1)"},
				"limit":  map[string]interface{}{"type": "integer", "description": "max lines to read (default 200, cap 2000)"},
			},
			"required": []string{"path"},
		},
		Confirm: false,
		Run:     runReadFile,
	}
}

func searchToolDef() Tool {
	return Tool{
		Name: "search",
		Description: "Search file contents under a directory (or a single file) for a regex pattern. " +
			"Returns path:line: match (max 100). Skips binary files and VCS/dependency dirs. " +
			"Use this to map the error landscape of a log BEFORE reading specific regions.",
		Schema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pattern": map[string]interface{}{"type": "string", "description": "regex (falls back to literal if invalid)"},
				"path":    map[string]interface{}{"type": "string", "description": "directory or file (default .)"},
				"include": map[string]interface{}{"type": "string", "description": "optional filename glob, e.g. *.log"},
			},
			"required": []string{"pattern"},
		},
		Confirm: false,
		Run:     runSearch,
	}
}

func writeFileToolDef() Tool {
	return Tool{
		Name: "write_file",
		Description: "Write (create or fully overwrite) a text file. Overwriting an existing file asks the user first, " +
			"and the original is backed up automatically (recoverable via /undo). Use for reports and fix scripts.",
		Schema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":    map[string]interface{}{"type": "string", "description": "target file path"},
				"content": map[string]interface{}{"type": "string", "description": "full file content"},
			},
			"required": []string{"path", "content"},
		},
		Confirm: true,
		Run:     runWriteFile,
	}
}

// --------------------------------------------------------------------------
// Skills (design §3.5): directory-based playbooks. Two-level loading —
// frontmatter summaries go into the system prompt at startup; the model loads
// the full body on demand via the use_skill tool.
// --------------------------------------------------------------------------

type skillInfo struct {
	Name        string
	Description string
	Activate    []string // activate_when triggers
	Dir         string
}

var (
	skillsDir    = filepath.Join(appDir, "skills")
	skillsCache  []skillInfo
	skillsLoaded bool
)

// skillSearchDirs returns skill roots in priority order: user dir first,
// then a skills/ dir next to the current working directory (repo checkout).
func skillSearchDirs() []string {
	dirs := []string{skillsDir}
	if cwd, err := os.Getwd(); err == nil {
		alt := filepath.Join(cwd, "skills")
		if alt != skillsDir {
			dirs = append(dirs, alt)
		}
	}
	return dirs
}

// parseSkillFrontmatter reads the --- ... --- block. Tolerates both `name` and
// `skill_name` (OpenClaw legacy), multi-line values, and activate_when lists.
func parseSkillFrontmatter(content string) (name, desc string, activate []string) {
	if !strings.HasPrefix(content, "---") {
		return "", "", nil
	}
	lines := strings.Split(content, "\n")
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return "", "", nil
	}
	key := ""
	inActivate := false
	for _, ln := range lines[1:end] {
		trimmed := strings.TrimSpace(ln)
		if inActivate && strings.HasPrefix(trimmed, "- ") {
			activate = append(activate, strings.TrimSpace(trimmed[2:]))
			continue
		}
		inActivate = false
		if idx := strings.Index(ln, ":"); idx > 0 && !strings.HasPrefix(ln, " ") && !strings.HasPrefix(ln, "\t") && !strings.HasPrefix(trimmed, "-") {
			key = strings.TrimSpace(ln[:idx])
			val := strings.TrimSpace(ln[idx+1:])
			switch key {
			case "name", "skill_name":
				name = val
			case "description":
				desc = val
			case "activate_when":
				inActivate = true
			default:
				key = ""
			}
			continue
		}
		// continuation of a multi-line description
		if key == "description" && trimmed != "" {
			desc += " " + trimmed
		}
	}
	return name, desc, activate
}

// scanSkills (re)builds the skill cache. Later dirs do not override earlier
// ones for the same skill name (user dir wins).
func scanSkills() []skillInfo {
	seen := map[string]bool{}
	var out []skillInfo
	for _, root := range skillSearchDirs() {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(root, e.Name(), "SKILL.md")
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			name, desc, activate := parseSkillFrontmatter(string(data))
			if name == "" {
				name = e.Name()
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, skillInfo{Name: name, Description: desc, Activate: activate, Dir: filepath.Join(root, e.Name())})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	skillsCache = out
	skillsLoaded = true
	return out
}

func getSkills() []skillInfo {
	if !skillsLoaded {
		return scanSkills()
	}
	return skillsCache
}

// agentSystemBlock is the built-in operating-rules layer of the agent system
// prompt (design §3.7, layer 2 of 3).
// defaultSystemPrompt is baked into newly created sessions when --system is
// not given (chat mode's layer-1; agent mode appends its own blocks on top).
// It lives in the session, not hidden in code: /system shows it, edits it,
// and `/system off` clears it.
const defaultSystemPrompt = `You are frza, a troubleshooting copilot for engineers running Linux and cloud infrastructure. Answer in the user's language. Be concrete: real commands, paths, and evidence over generic advice. Keep answers structured and tight.`

const agentSystemBlock = `You are a troubleshooting agent running on the user's machine with tool access.

Operating rules:
- Investigate with tools before concluding: prefer read_file/search over dumping files via bash; use bash for system state (df/ps/dmesg/ss) and for running skill scripts.
- Large files: never cat them whole. First map with search (error keywords), then read_file the regions around hits. Skill preprocess scripts are preferred for big logs.
- Extract archives to /tmp/frza-<case>/ (list with tar -tf first; never extract into the user's working directory).
- Destructive or system-changing commands will be shown to the user for confirmation; propose them when needed, but expect refusal and have a read-only fallback.
- Missing dependencies: check before running (command -v, python3 -c "import x"). When something is missing, explain what is needed and propose the exact install command — but NEVER install silently; installs are system changes and go through user confirmation like everything else. If the user declines, continue with a workaround that uses what is available.
- When done, report: root cause, evidence chain, and concrete fix steps.`

// skillsSystemBlock renders layer 3 (the skill catalog).
func skillsSystemBlock() string {
	skills := getSkills()
	if len(skills) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\nAvailable skill playbooks (call use_skill with the exact name to load the full playbook when the task matches):")
	for _, s := range skills {
		b.WriteString("\n- " + s.Name + ": " + truncateStr(s.Description, 300))
		if len(s.Activate) > 0 {
			b.WriteString(" (trigger: " + truncateStr(strings.Join(s.Activate, "; "), 150) + ")")
		}
	}
	return b.String()
}

func composeAgentSystem(userSystem string) string {
	return userSystem + agentSystemBlock + skillsSystemBlock()
}

func useSkillToolDef() Tool {
	return Tool{
		Name:        "use_skill",
		Description: "Load the full playbook of a named skill (from the catalog in the system prompt) into context. Use when the user's task matches a skill's description or triggers.",
		Schema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "exact skill name from the catalog"},
			},
			"required": []string{"name"},
		},
		Confirm: false,
		Run: func(ctx context.Context, argsJSON string) (string, error) {
			var args struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal([]byte(argsJSON), &args); err != nil || args.Name == "" {
				return "", fmt.Errorf("invalid arguments: need {\"name\": \"...\"}")
			}
			for _, s := range getSkills() {
				if s.Name == args.Name {
					data, err := os.ReadFile(filepath.Join(s.Dir, "SKILL.md"))
					if err != nil {
						return "", err
					}
					body := strings.ReplaceAll(string(data), "{{SKILL_DIR}}", s.Dir)
					return fmt.Sprintf("[skill %s loaded from %s]\n%s", s.Name, s.Dir, truncateToolOutput(body, 1500, 50, 32768)), nil
				}
			}
			names := []string{}
			for _, s := range getSkills() {
				names = append(names, s.Name)
			}
			return fmt.Sprintf("[error] skill %q not found; available: %s", args.Name, strings.Join(names, ", ")), nil
		},
	}
}

// bashToolDef is registered under both "bash" and "exec" (legacy skills written
// for OpenClaw call it exec; §3.5 compatibility).
func bashToolDef(name string) Tool {
	return Tool{
		Name: name,
		Description: "Run a bash shell command on this machine and return its output. " +
			"Use for diagnostics: reading logs, checking system state, running read-only inspection commands. " +
			"Output is truncated (first 200 + last 50 lines, 8KB cap) — for large files prefer grep/sed to narrow first. " +
			"Default timeout 120s; pass timeout_sec for heavy commands (crash on vmcore, big-log preprocess, large du/find — up to 600s). " +
			"For very long jobs (>10min), run them in background (nohup ... > /tmp/out 2>&1 &) and poll with tail on later turns.",
		Schema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"command":     map[string]interface{}{"type": "string", "description": "the bash command line to execute"},
				"timeout_sec": map[string]interface{}{"type": "integer", "description": "optional per-command timeout in seconds (default 120, max 600)"},
			},
			"required": []string{"command"},
		},
		Confirm: true, // auto-approved only when classifyCommand says riskReadonly
		Run:     runBash,
	}
}

// --------------------------------------------------------------------------
// Terminal Markdown rendering
//   Headings/bold/italic/inline code/lists/quotes/hr/code blocks; chroma syntax
//   highlighting. Falls back to plain text when piped, TERM=dumb, or NO_COLOR.
// --------------------------------------------------------------------------

func detectColorSupport() bool {
	if os.Getenv("FRZA_FORCE_COLOR") != "" {
		return true
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if t := os.Getenv("TERM"); t == "" || t == "dumb" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

var useColor = detectColorSupport()

// supportsTrueColor reports whether the terminal can render 24-bit color.
// Only COLORTERM=truecolor/24bit is trusted; when unset we assume NO — a
// 256-color approximation looks nearly identical, but a raw RGB sequence on a
// terminal that cannot parse it renders invisible (user report 2026-09-11).
func supportsTrueColor() bool {
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	return ct == "truecolor" || ct == "24bit"
}

var trueColor = supportsTrueColor()

func init() {
	if !trueColor {
		// 256-color approximations of the truecolor accents
		ansiCodes["inline_code"] = "\033[38;5;189m"
		shimmerBase = "\033[38;5;153m"
		shimmerHot = "\033[38;5;189m"
	}
}

var ansiCodes = map[string]string{
	"reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "italic": "\033[3m",
	"red": "\033[31m", "green": "\033[32m",
	// cyan/yellow are referenced by tool-call banners and context-trim /
	// round-limit notices; missing keys used to silently render unstyled
	// (audit 3.4)
	"cyan": "\033[36m", "yellow": "\033[33m",
	// 256-color mid-gray: ANSI 90 (bright black) is near-invisible on many
	// dark terminal themes, especially over SSH on Linux (user report
	// 2026-09-11). 245 stays de-emphasized but readable on both dark and
	// light backgrounds.
	"gray": "\033[38;5;245m",
	// Inline code: blue-violet rgb(177,185,249), Claude Code's suggestion color
	"inline_code": "\033[38;2;177;185;249m",
}

func stylize(text string, styles ...string) string {
	if !useColor || text == "" {
		return text
	}
	var b strings.Builder
	for _, s := range styles {
		b.WriteString(ansiCodes[s])
	}
	b.WriteString(text)
	b.WriteString(ansiCodes["reset"])
	return b.String()
}

// Inline elements: code > bold > italic. Go's RE2 has no lookaround, so the
// word-boundary guards for the underscore forms (protecting snake_case) are
// written into the pattern as (?:^|[^\w]) boundary character groups — otherwise
// an underscore inside a word like TIME_WAIT would match a "giant italic" span
// across half the line and swallow any **bold** in between. Boundary characters
// are consumed by the match but written back verbatim, matching the semantics
// of Python's (?<!\w)…(?!\w).
var inlineRe = regexp.MustCompile(
	"(\x60[^\x60\n]+\x60)" +
		"|(\\*\\*[^\\s*](?:[^\n*]*[^\\s*])?\\*\\*)" +
		"|((?:^|[^\\w])(__[^_\n]+?__)(?:[^\\w]|$))" +
		"|(\\*[^\\s*](?:[^\n*]*[^\\s*])?\\*)" +
		"|((?:^|[^\\w])(_[^_\n]+?_)(?:[^\\w]|$))")

func renderInline(line string) string {
	if !useColor {
		return line
	}
	var b strings.Builder
	last := 0
	for _, m := range inlineRe.FindAllStringSubmatchIndex(line, -1) {
		b.WriteString(line[last:m[0]])
		switch {
		case m[2] >= 0: // `code`
			b.WriteString(stylize(line[m[2]+1:m[3]-1], "inline_code"))
		case m[4] >= 0: // **bold**
			b.WriteString(stylize(line[m[4]+2:m[5]-2], "bold"))
		case m[6] >= 0: // boundary+__bold__+boundary (m[6:8] whole, m[8:10] the __..__ body)
			b.WriteString(line[m[6]:m[8]])
			b.WriteString(stylize(line[m[8]+2:m[9]-2], "bold"))
			b.WriteString(line[m[9]:m[7]])
		case m[10] >= 0: // *it*
			b.WriteString(stylize(line[m[10]+1:m[11]-1], "italic"))
		case m[12] >= 0: // boundary+_it_+boundary
			b.WriteString(line[m[12]:m[14]])
			b.WriteString(stylize(line[m[14]+1:m[15]-1], "italic"))
			b.WriteString(line[m[15]:m[13]])
		}
		last = m[1]
	}
	b.WriteString(line[last:])
	return b.String()
}

var (
	headingRe  = regexp.MustCompile(`^\s{0,3}#{1,6}\s+(.*)$`)
	hrRe       = regexp.MustCompile(`^\s{0,3}(-{3,}|\*{3,}|_{3,})\s*$`)
	ulRe       = regexp.MustCompile(`^(\s*)[-*+]\s+(.*)$`)
	olRe       = regexp.MustCompile(`^(\s*)(\d{1,3})[.)]\s+(.*)$`)
	fenceRe    = regexp.MustCompile("^\\s{0,3}\x60{3}([^\x60]*)\\s*$")
	tableSepRe = regexp.MustCompile(`^\s*\|?\s*:?-{2,}:?\s*(?:\|\s*:?-{2,}:?\s*)+\|?\s*$`)
	ansiStrip  = regexp.MustCompile("\\x1b\\[[0-9;]*m")
)

func renderLine(line string) string {
	if m := headingRe.FindStringSubmatch(line); m != nil {
		return stylize(m[1], "bold") // heading keeps default foreground, bold only
	}
	if hrRe.MatchString(line) {
		return stylize(strings.Repeat("─", 40), "gray")
	}
	stripped := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(stripped, ">") {
		indent := line[:len(line)-len(stripped)]
		return indent + stylize("▎", "gray") + " " + renderInline(strings.TrimLeft(stripped[1:], " \t"))
	}
	if m := ulRe.FindStringSubmatch(line); m != nil {
		return m[1] + "• " + renderInline(m[2])
	}
	if m := olRe.FindStringSubmatch(line); m != nil {
		return m[1] + m[2] + ". " + renderInline(m[3])
	}
	return renderInline(line)
}

func isTableRow(line string) bool {
	s := strings.TrimSpace(line)
	return strings.HasPrefix(s, "|") && strings.Count(s, "|") >= 2
}

func splitTableRow(line string) []string {
	s := strings.TrimSpace(line)
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimSuffix(s, "|")
	parts := strings.Split(s, "|")
	for i, c := range parts {
		// Expand tabs to a fixed 4 spaces: tabs jump to multiples of 8 in the
		// terminal, making width unpredictable
		parts[i] = strings.ReplaceAll(strings.TrimSpace(c), "\t", "    ")
	}
	return parts
}

func colAlign(cell string) string {
	cell = strings.TrimSpace(cell)
	left, right := strings.HasPrefix(cell, ":"), strings.HasSuffix(cell, ":")
	if left && right {
		return "center"
	}
	if right {
		return "right"
	}
	return "left"
}

// dispWidth returns the display width: ANSI escapes stripped, then terminal
// columns counted by grapheme cluster (uniseg handles ZWJ/VS16/combining marks)
func dispWidth(s string) int {
	return uniseg.StringWidth(ansiStrip.ReplaceAllString(s, ""))
}

func padCell(s string, width int, align string) string {
	gap := width - dispWidth(s)
	if gap <= 0 {
		return s
	}
	switch align {
	case "right":
		return strings.Repeat(" ", gap) + s
	case "center":
		left := gap / 2
		return strings.Repeat(" ", left) + s + strings.Repeat(" ", gap-left)
	}
	return s + strings.Repeat(" ", gap)
}

// pickStyle picks a chroma style from COLORFGBG (only when set), defaulting
// to monokai — troubleshooting servers are dark-background far more often
// than not, and a light theme on a dark terminal renders code invisible
// (user report 2026-09-11).
func pickStyle() string {
	if cfb := os.Getenv("COLORFGBG"); cfb != "" {
		if i := strings.LastIndex(cfb, ";"); i >= 0 {
			switch cfb[i+1:] {
			case "7", "15":
				return "github"
			}
		}
	}
	return "monokai"
}

var (
	bgStrip1 = regexp.MustCompile(`;48;5;\d+`)
	bgStrip2 = regexp.MustCompile(`;48;2;\d+;\d+;\d+`)
	bgStrip3 = regexp.MustCompile("\\x1b\\[48;[25];[\\d;]*m")
)

// stripChromaBG strips the style's own background colors, keeping only
// foreground colors (so the terminal background shows through)
func stripChromaBG(text string) string {
	text = bgStrip1.ReplaceAllString(text, "")
	text = bgStrip2.ReplaceAllString(text, "")
	return bgStrip3.ReplaceAllString(text, "")
}

func isNumberToken(t chroma.TokenType) bool {
	return t >= chroma.LiteralNumber && t < chroma.LiteralNumber+100
}

var (
	numPlainRe   = regexp.MustCompile(`^\d+(\.\d+)?$`)
	numAccRe     = regexp.MustCompile(`^[0-9a-fA-FtT./:-]+$`)
	numCompundRe = regexp.MustCompile(`^[0-9a-fA-FtT]+([./:-][0-9a-fA-FtT]+){2,}$`)
	numBareRe    = regexp.MustCompile(`^\d+$`)
)

// demoteLine demotes pseudo-number tokens inside "number+separator+number"
// compound fragments (IP/date/time/MAC/version) within a single line
func demoteLine(tokens []chroma.Token) ([]chroma.Token, bool) {
	out := []chroma.Token{}
	demoted := false
	i, n := 0, len(tokens)
	for i < n {
		t := tokens[i]
		if isNumberToken(t.Type) && numPlainRe.MatchString(t.Value) {
			j := i + 1
			acc := t.Value
			for j < n && numAccRe.MatchString(tokens[j].Value) {
				acc += tokens[j].Value
				j++
			}
			if numCompundRe.MatchString(acc) {
				for k := i; k < j; k++ {
					out = append(out, chroma.Token{Type: chroma.Text, Value: tokens[k].Value})
				}
				demoted = true
				i = j
				continue
			}
		}
		out = append(out, t)
		i++
	}
	return out, demoted
}

// demoteCompoundNumberTokens runs compound-number demotion per line; once a
// fragment is demoted on a line, stray bare numbers on that line are demoted
// too (avoiding a half-colored timestamp line)
func demoteCompoundNumberTokens(tokens []chroma.Token) []chroma.Token {
	var lines [][]chroma.Token
	var cur []chroma.Token
	for _, t := range tokens {
		cur = append(cur, t)
		if strings.Contains(t.Value, "\n") {
			lines = append(lines, cur)
			cur = nil
		}
	}
	if len(cur) > 0 {
		lines = append(lines, cur)
	}
	out := []chroma.Token{}
	for _, line := range lines {
		processed, demoted := demoteLine(line)
		if demoted {
			for i, t := range processed {
				if isNumberToken(t.Type) && numBareRe.MatchString(t.Value) {
					processed[i] = chroma.Token{Type: chroma.Text, Value: t.Value}
				}
			}
		}
		out = append(out, processed...)
	}
	return out
}

// Prompt prefix of shell session blocks ([user@host ~]# / user@host:~$);
// the bash lexer doesn't understand prompts, so they are handled separately
var shellSessionLangs = map[string]bool{
	"bash": true, "sh": true, "shell": true, "zsh": true,
	"console": true, "shell-session": true, "": true,
}
var promptRe = regexp.MustCompile(`^(\s*(?:\[[\w.\-]+@[\w.\-]+[^\]]*\]|[\w.\-]+@[\w.\-]+:[^\n]*?)[#$]\s*)(.*)$`)

func lexFragment(lexer chroma.Lexer, s string) []chroma.Token {
	var toks []chroma.Token
	it, err := lexer.Tokenise(nil, s)
	if err != nil {
		return []chroma.Token{{Type: chroma.Text, Value: s}}
	}
	for t := it(); t != chroma.EOF; t = it() {
		toks = append(toks, t)
	}
	return toks
}

// lexShellSession handles shell session blocks per line: the prompt prefix
// stays plain text, the command after #/$ still gets bash highlighting
func lexShellSession(code string, lexer chroma.Lexer) []chroma.Token {
	out := []chroma.Token{}
	for _, line := range strings.Split(code, "\n") {
		if m := promptRe.FindStringSubmatch(line); m != nil {
			out = append(out, chroma.Token{Type: chroma.Text, Value: m[1]})
			if m[2] != "" {
				out = append(out, lexFragment(lexer, m[2])...)
			}
		} else if line != "" {
			out = append(out, lexFragment(lexer, line)...)
		}
		out = append(out, chroma.Token{Type: chroma.Text, Value: "\n"})
	}
	return out
}

func highlightCode(code, lang string) string {
	var lexer chroma.Lexer
	if lang != "" {
		lexer = lexers.Get(lang)
	}
	if lexer == nil {
		lexer = lexers.Fallback
	}
	var toks []chroma.Token
	hasPrompt := false
	for _, l := range strings.Split(code, "\n") {
		if promptRe.MatchString(l) {
			hasPrompt = true
			break
		}
	}
	if shellSessionLangs[strings.ToLower(lang)] && hasPrompt {
		toks = lexShellSession(code, lexer)
	} else {
		toks = lexFragment(lexer, code)
	}
	toks = demoteCompoundNumberTokens(toks)
	// terminal16m emits exact RGB (more faithful) but only when the terminal
	// can render it; otherwise approximate to the 256-color palette
	formatterName := "terminal256"
	if trueColor {
		formatterName = "terminal16m"
	}
	formatter := formatters.Get(formatterName)
	var buf bytes.Buffer
	if err := formatter.Format(&buf, styles.Get(pickStyle()), chroma.Literator(toks...)); err != nil {
		return code
	}
	return stripChromaBG(buf.String())
}

// --------------------------------------------------------------------------
// ASCII box-art realignment in code blocks
//   Models draw ┌─┐│└─┘ diagrams by "mentally" counting CJK widths and are
//   often off by 1-2 columns, leaving ragged right edges. This realigns box
//   lines in untagged/text code blocks by padding every vertical edge rightward
//   to the group's widest column. Insert-only, never deletes content.
// --------------------------------------------------------------------------

// Box-drawing chars with "vertical edge" semantics; ─ ┬ ┴ ┼ are horizontal/crossing
var boxVBars = map[rune]bool{'│': true, '┌': true, '┐': true, '└': true, '┘': true, '├': true, '┤': true}

// Only realign blocks with these language tags, avoiding box chars inside
// e.g. python string literals
var boxArtLangs = map[string]bool{"": true, "text": true, "txt": true, "plain": true}

// Max column spread allowed for edges at the same level: beyond that the boxes
// are intentionally different widths, or an anomalous line sneaked in
const boxEdgeTolerance = 4

type boxEdge struct {
	byteIdx int
	col     int
}

// boxEdges returns (byte_index, display_col) of all vertical-edge chars in the
// line; lines containing tabs return nil (column math unpredictable)
func boxEdges(line string) []boxEdge {
	if strings.Contains(line, "\t") {
		return nil
	}
	var edges []boxEdge
	col := 0
	g := uniseg.NewGraphemes(line)
	for g.Next() {
		cl := g.Str()
		from, _ := g.Positions()
		if r, ok := singleRune(cl); ok && boxVBars[r] {
			edges = append(edges, boxEdge{from, col})
		}
		col += uniseg.StringWidth(cl)
	}
	return edges
}

func singleRune(s string) (rune, bool) {
	rs := []rune(s)
	if len(rs) == 1 {
		return rs[0], true
	}
	return 0, false
}

// alignBoxEdge aligns each line's (-level)-th vertical edge from the right to
// one display column (level=-1 is the outermost right edge). Only pushes edges
// rightward (insert spaces before an edge; insert ─ for horizontal borders).
func alignBoxEdge(group []string, level int) []string {
	type entry struct {
		idx int
		e   boxEdge
	}
	var particip []entry
	for idx, line := range group {
		edges := boxEdges(line)
		// level=-1 needs at least two edges; level=-2 needs at least three
		// (with two, the 2nd-from-right is the left border and must not move)
		if edges != nil && len(edges) >= 1-level {
			particip = append(particip, entry{idx, edges[len(edges)+level]})
		}
	}
	if len(particip) < 2 {
		return group
	}
	minC, maxC := particip[0].e.col, particip[0].e.col
	for _, p := range particip[1:] {
		if p.e.col < minC {
			minC = p.e.col
		}
		if p.e.col > maxC {
			maxC = p.e.col
		}
	}
	if maxC-minC > boxEdgeTolerance {
		return group
	}
	out := append([]string(nil), group...)
	for _, p := range particip {
		gap := maxC - p.e.col
		if gap <= 0 {
			continue
		}
		line := out[p.idx]
		// Horizontal borders (┌──┐/└──┘) get ─ to stay continuous; content lines get spaces
		fill := " "
		if p.e.byteIdx > 0 && lastRuneIs(line[:p.e.byteIdx], '─') {
			fill = "─"
		}
		out[p.idx] = line[:p.e.byteIdx] + strings.Repeat(fill, gap) + line[p.e.byteIdx:]
	}
	return out
}

func lastRuneIs(s string, r rune) bool {
	rs := []rune(s)
	return len(rs) > 0 && rs[len(rs)-1] == r
}

// realignGroup: fully uniform structure (same edge count on every line, e.g.
// several identical side-by-side boxes) aligns every edge level from innermost
// to outermost; mixed structure (nested boxes / annotations) aligns only the
// two outermost right-edge levels — deeper levels risk mismapping and are left
// to the spread guard.
func realignGroup(group []string) []string {
	counts := map[int]bool{}
	for _, l := range group {
		counts[len(boxEdges(l))] = true
	}
	if len(counts) == 1 {
		var nEdges int
		for n := range counts {
			nEdges = n
		}
		for level := -(nEdges - 1); level < 0; level++ {
			group = alignBoxEdge(group, level)
		}
	} else {
		group = alignBoxEdge(group, -2)
		group = alignBoxEdge(group, -1)
	}
	return group
}

// realignBoxArt realigns hand-drawn box diagrams in a code block; a run of
// consecutive box lines (>= 3 lines) forms one box group
func realignBoxArt(code string) string {
	raw := strings.Split(code, "\n")
	lines := make([]string, len(raw))
	for i, l := range raw {
		lines[i] = strings.TrimRight(l, " \t")
	}
	out := []string{}
	i, n := 0, len(lines)
	for i < n {
		if boxEdges(lines[i]) != nil {
			j := i
			for j < n && boxEdges(lines[j]) != nil {
				j++
			}
			group := lines[i:j]
			if len(group) >= 3 {
				group = realignGroup(group)
			}
			out = append(out, group...)
			i = j
		} else {
			out = append(out, lines[i])
			i++
		}
	}
	return strings.Join(out, "\n")
}

// --------------------------------------------------------------------------
// Markdown renderer (line-fed; code blocks and tables accumulate before
// one-shot formatting)
// --------------------------------------------------------------------------

type markdownRenderer struct {
	inCode       bool
	codeLang     string
	codeLines    []string
	tablePending *string
	inTable      bool
	tableRows    []string
	tableAligns  []string
}

func (r *markdownRenderer) feedLine(line string) (string, bool) {
	out := []string{}

	// Table state machine (| inside code blocks doesn't trigger tables)
	if !r.inCode {
		if r.tablePending != nil {
			if tableSepRe.MatchString(line) {
				r.inTable = true
				r.tableRows = []string{*r.tablePending}
				for _, c := range splitTableRow(line) {
					r.tableAligns = append(r.tableAligns, colAlign(c))
				}
				r.tablePending = nil
				return "", false
			}
			out = append(out, renderLine(*r.tablePending))
			r.tablePending = nil
		}
		if r.inTable {
			if isTableRow(line) {
				r.tableRows = append(r.tableRows, line)
				return "", false
			}
			out = append(out, r.renderTable())
			r.inTable = false
			r.tableRows = nil
		}
	}

	// Code block fence
	if m := fenceRe.FindStringSubmatch(line); m != nil {
		if r.inCode {
			r.inCode = false
			out = append(out, r.renderCode())
			r.codeLines = nil
		} else {
			r.inCode = true
			r.codeLang = strings.TrimSpace(m[1])
			r.codeLines = nil
		}
		return strings.Join(out, "\n"), len(out) > 0
	}
	if r.inCode {
		r.codeLines = append(r.codeLines, line)
		return strings.Join(out, "\n"), len(out) > 0
	}

	// Candidate table header: hold pending, check if next line is a separator
	if isTableRow(line) {
		r.tablePending = &line
		return strings.Join(out, "\n"), len(out) > 0
	}

	out = append(out, renderLine(line))
	return strings.Join(out, "\n"), true
}

// flush is called at end of input: renders any pending table or unclosed code block
func (r *markdownRenderer) flush() (string, bool) {
	out := []string{}
	if r.tablePending != nil {
		out = append(out, renderLine(*r.tablePending))
		r.tablePending = nil
	}
	if r.inTable {
		out = append(out, r.renderTable())
		r.inTable = false
		r.tableRows = nil
	}
	if r.inCode {
		r.inCode = false
		if len(r.codeLines) > 0 {
			out = append(out, r.renderCode())
		}
	}
	return strings.Join(out, "\n"), len(out) > 0
}

func (r *markdownRenderer) renderTable() string {
	rows := [][]string{}
	ncols := 0
	for _, row := range r.tableRows {
		cells := splitTableRow(row)
		if len(cells) > ncols {
			ncols = len(cells)
		}
		rows = append(rows, cells)
	}
	for i, row := range rows {
		for len(row) < ncols {
			row = append(row, "")
		}
		rows[i] = row
	}
	aligns := append([]string(nil), r.tableAligns...)
	for len(aligns) < ncols {
		aligns = append(aligns, "left")
	}
	aligns = aligns[:ncols]
	rendered := make([][]string, len(rows))
	for i, row := range rows {
		rc := make([]string, ncols)
		for j, c := range row {
			rc[j] = renderInline(c)
		}
		rendered[i] = rc
	}
	widths := make([]int, ncols)
	for j := 0; j < ncols; j++ {
		for _, row := range rendered {
			if w := dispWidth(row[j]); w > widths[j] {
				widths[j] = w
			}
		}
	}
	segs := make([]string, ncols)
	for j, w := range widths {
		segs[j] = strings.Repeat("─", w+2) // +2 for the space padding on both sides
	}
	border := func(left, mid, right string) string {
		return stylize(left+strings.Join(segs, mid)+right, "gray")
	}
	makeRow := func(cells []string, cellStyle string) string {
		parts := make([]string, ncols)
		for i := 0; i < ncols; i++ {
			c := cells[i]
			if cellStyle != "" {
				c = stylize(c, cellStyle)
			}
			parts[i] = padCell(c, widths[i], aligns[i])
		}
		bar := stylize("│", "gray")
		return bar + " " + strings.Join(parts, " "+bar+" ") + " " + bar
	}
	// Fully enclosed box: top/bottom borders + separators between header and rows
	lines := []string{border("┌", "┬", "┐")}
	lines = append(lines, makeRow(rendered[0], "bold"))
	lines = append(lines, border("├", "┼", "┤"))
	for i, row := range rendered[1:] {
		if i > 0 {
			lines = append(lines, border("├", "┼", "┤"))
		}
		lines = append(lines, makeRow(row, ""))
	}
	lines = append(lines, border("└", "┴", "┘"))
	return strings.Join(lines, "\n")
}

func (r *markdownRenderer) renderCode() string {
	code := strings.Join(r.codeLines, "\n")
	if boxArtLangs[strings.ToLower(r.codeLang)] {
		// Hand-drawn diagrams are often ragged from CJK width miscounts; realign first
		code = realignBoxArt(code)
	}
	bar := stylize("▎", "gray")
	if useColor {
		rendered := strings.TrimRight(highlightCode(code, r.codeLang), "\n")
		lines := strings.Split(rendered, "\n")
		for i, l := range lines {
			lines[i] = bar + " " + l
		}
		return strings.Join(lines, "\n")
	}
	if code == "" {
		return ""
	}
	lines := strings.Split(code, "\n")
	for i, l := range lines {
		lines[i] = bar + " " + l
	}
	return strings.Join(lines, "\n")
}

func renderMarkdown(text string) string {
	r := &markdownRenderer{}
	out := []string{}
	for _, line := range strings.Split(text, "\n") {
		if rendered, ok := r.feedLine(line); ok {
			out = append(out, rendered)
		}
	}
	if tail, ok := r.flush(); ok {
		out = append(out, tail)
	}
	return strings.Join(out, "\n")
}

// streamRenderer is a line-buffered renderer for streaming output: renders only
// complete lines (Markdown syntax closes per line)
type streamRenderer struct {
	r   *markdownRenderer
	buf string
}

func newStreamRenderer() *streamRenderer {
	return &streamRenderer{r: &markdownRenderer{}}
}

func (s *streamRenderer) feed(text string) {
	s.buf += text
	for strings.Contains(s.buf, "\n") {
		i := strings.Index(s.buf, "\n")
		line := s.buf[:i]
		s.buf = s.buf[i+1:]
		s.emit(line)
	}
}

func (s *streamRenderer) finish() {
	if s.buf != "" {
		s.emit(s.buf)
		s.buf = ""
	}
	if tail, ok := s.r.flush(); ok {
		fmt.Println(tail)
	}
}

func (s *streamRenderer) emit(line string) {
	if rendered, ok := s.r.feedLine(line); ok {
		fmt.Println(rendered)
	}
}

// --------------------------------------------------------------------------
// ThinkingIndicator: animated indicator while waiting for the model (refreshed
// from a goroutine). Style replicates Claude Code's spinner: ✻ + random verb +
// shimmer sweep.
// --------------------------------------------------------------------------

// Troubleshooting-flavored spinner verbs: the tool is used during incidents,
// so the vocabulary stays professional (the inherited Claude-Code-style list
// had Brewing/Weaving/Wandering — off-tone for an on-call screen).
var thinkingVerbs = []string{"Thinking", "Analyzing", "Investigating", "Diagnosing",
	"Checking", "Researching", "Reasoning", "Correlating", "Inspecting", "Tracing"}

const shimmerW = 4

// shimmer colors are vars: init() swaps in 256-color approximations when the
// terminal lacks truecolor (see supportsTrueColor)
var (
	shimmerBase = "\033[38;2;147;165;255m" // claudeBlue_FOR_SYSTEM_SPINNER
	shimmerHot  = "\033[38;2;177;195;255m" // claudeBlueShimmer
)

type thinkingIndicator struct {
	stopCh  chan struct{}
	doneCh  chan struct{}
	mu      sync.Mutex
	state   string
	t0      time.Time
	started bool
	rng     *rand2
}

type rand2 struct{ mu sync.Mutex }

func (r *rand2) pick() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return thinkingVerbs[int(time.Now().UnixNano()%int64(len(thinkingVerbs)))]
}

func newThinkingIndicator() *thinkingIndicator {
	return &thinkingIndicator{state: "Waiting", rng: &rand2{}}
}

func (ti *thinkingIndicator) start() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	ti.t0 = time.Now()
	ti.stopCh = make(chan struct{})
	ti.doneCh = make(chan struct{})
	ti.started = true
	go ti.run()
}

func (ti *thinkingIndicator) setState(state string) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	if ti.state == "Waiting" {
		ti.state = state
	}
}

func (ti *thinkingIndicator) shimmerText(text string, frame int) string {
	if !useColor {
		return text
	}
	runes := []rune(text)
	n := len(runes)
	cycle := n + shimmerW
	pos := frame % cycle
	var b strings.Builder
	for i, ch := range runes {
		if pos <= i && i < pos+shimmerW {
			b.WriteString(shimmerHot)
		} else {
			b.WriteString(shimmerBase)
		}
		b.WriteRune(ch)
	}
	b.WriteString("\033[0m")
	return b.String()
}

func (ti *thinkingIndicator) run() {
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		select {
		case <-ti.stopCh:
			close(ti.doneCh)
			return
		case <-ticker.C:
			ti.mu.Lock()
			state := ti.state
			ti.mu.Unlock()
			elapsed := int(time.Since(ti.t0).Seconds())
			ts := fmt.Sprintf("%ds", elapsed)
			if elapsed >= 60 {
				ts = fmt.Sprintf("%dm %ds", elapsed/60, elapsed%60)
			}
			text := fmt.Sprintf("✻ %s %s", state, ts)
			fmt.Fprintf(os.Stdout, "\r%s\033[K", ti.shimmerText(text, frame))
			frame++
		}
	}
}

func (ti *thinkingIndicator) stop() {
	if !ti.started {
		return
	}
	close(ti.stopCh)
	<-ti.doneCh
	ti.started = false
	fmt.Fprint(os.Stdout, "\r\033[K") // erase the indicator line
}

func (ti *thinkingIndicator) randomVerb() { ti.setState(ti.rng.pick()) }

// --------------------------------------------------------------------------
// REPL
// --------------------------------------------------------------------------

func formatHistory(messages []Message) string {
	out := []string{}
	for _, m := range messages {
		out = append(out, "")
		if m.Role == "user" {
			for _, line := range strings.Split(m.Content, "\n") {
				out = append(out, stylize("> ", "green")+line)
			}
		} else {
			out = append(out, renderMarkdown(m.Content))
		}
	}
	return strings.Join(out, "\n")
}

// pageText views long text through a pager ($PAGER, default less -R -F -X);
// falls back to plain print when not a tty or no pager is available
func pageText(text string) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Println(text)
		return
	}
	pager := os.Getenv("PAGER")
	if pager == "" {
		pager = "less"
	}
	parts := strings.Fields(pager)
	if len(parts) == 0 { // whitespace-only PAGER (review F5)
		parts = []string{"less"}
	}
	if filepath.Base(parts[0]) == "less" {
		parts = append(parts, "-R", "-F", "-X")
	}
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdin = strings.NewReader(text)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println(text)
	}
}

// Slash commands offered for Tab completion
var replCommands = []string{
	"/agent", "/baseurl", "/clear", "/continue", "/edit", "/exit", "/export", "/help", "/history",
	"/journal", "/list", "/model", "/new", "/quit", "/reload-skills", "/rename", "/resume", "/save", "/skills", "/system", "/undo",
}

// suggestCommand finds the closest slash command for an "unknown command"
// hint (audit A5): an unambiguous prefix wins, otherwise the nearest by
// edit distance within two typos.
func suggestCommand(cmd string) string {
	if len(cmd) >= 3 {
		for _, c := range replCommands {
			if strings.HasPrefix(c, cmd) {
				return c
			}
		}
	}
	best, bestDist := "", 3
	for _, c := range replCommands {
		if d := editDistance(cmd, c); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

// editDistance is the classic Levenshtein distance over runes (command names
// are short, so the DP table is tiny).
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 0
			if ra[i-1] != rb[j-1] {
				cost = 1
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

type frzCompleter struct{}

// Do implements readline.AutoCompleter: session names after /resume, /save
// and /new (the latter two surface existing names so collisions are visible);
// command names at line start.
func (frzCompleter) Do(line []rune, pos int) ([][]rune, int) {
	s := string(line[:pos])
	for _, c := range []string{"/resume", "/save", "/new"} {
		if strings.HasPrefix(s, c+" ") || strings.HasPrefix(s, c+"\t") {
			idx := strings.LastIndexAny(s, " \t")
			prefix := s[idx+1:]
			var out [][]rune
			for _, e := range listSessions() {
				if strings.HasPrefix(e.name, prefix) {
					out = append(out, []rune(e.name[len(prefix):]))
				}
			}
			return out, len([]rune(prefix))
		}
	}
	if strings.HasPrefix(s, "/") && !strings.ContainsAny(s, " \t") {
		var out [][]rune
		for _, c := range replCommands {
			if strings.HasPrefix(c, s) {
				out = append(out, []rune(c[len(s):]))
			}
		}
		return out, len([]rune(s))
	}
	return nil, 0
}

const helpText = `Available commands:
  Sessions
    /save [name]         Save current session (uses current name if omitted)
    /rename <name>       Rename current session
    /resume [name]       Switch to another session (latest session if omitted)
    /list                List all saved sessions
    /new [name]          Start a new session
    /export [file]       Export current session to Markdown
                         (default ~/.frza/exports/<session>.md)

  Session settings
    /system [prompt|off]  View, set, or clear the system prompt
                         (new sessions start with a built-in troubleshooting default)
    /model [name]        View or switch model
    /baseurl [url]       View or set custom API base url (required by
                         openai_responses and similar providers)

  Agent
    /agent [on|off]      View or toggle agent mode (model can run tools such as
                         bash; read-only commands auto-run, changes ask first)
    /journal             Show the operation journal of this session (last 20)
    /undo                Roll back the most recent file change made by the agent
    /skills              List available skill playbooks
    /reload-skills       Rescan skill directories (after adding/editing skills)
    /continue            Keep investigating after the agent round limit is hit

  Other
    !cmd                 Run a shell command directly (output shown only)
    !!cmd                Run a shell command and feed its output to the model
    /edit                Compose a multi-line message in your editor (great for
                         pasting long logs/questions); sent on save & exit
    /history [N]         Show conversation history (N = last N rounds only;
                         long output is paged automatically)
    /clear               Clear current session history (keeps system prompt)
    /help                Show this help
    /exit or /quit       Save and exit
`

const editHint = `# Type your message below (multi-line OK). It is sent when you
# save and exit the editor. These two lines are removed automatically;
# empty content cancels.
`

// editInEditor opens $VISUAL/$EDITOR (default vi) to compose a multi-line
// message; returns "" when cancelled/empty. Goes through a temp file rather
// than terminal line buffering, so there is no 1024-byte canonical-mode limit.
func editInEditor() string {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	// whitespace-only VISUAL/EDITOR would make the temp file the "program"
	// (same class of bug as blank PAGER, review F5) — fall back to vi (M14)
	if strings.TrimSpace(editor) == "" {
		editor = "vi"
	}
	f, err := os.CreateTemp("", "frza-edit-*.md")
	if err != nil {
		fmt.Println(stylize("[error] cannot create temp file: "+err.Error(), "red"))
		return ""
	}
	path := f.Name()
	f.WriteString(editHint)
	f.Close()
	defer os.Remove(path)

	parts := append(strings.Fields(editor), path)
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.Error); ok {
			fmt.Println(stylize(fmt.Sprintf("[error] editor not found: %s (set it via export EDITOR=vim)", editor), "red"))
		} else {
			fmt.Println("(editor exited abnormally, cancelled)")
		}
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	text := string(data)
	// Only strip the hint lines if they are exactly as written: a blanket
	// "ignore lines starting with #" rule would eat log content such as
	// root prompts (# iptables -L)
	if strings.HasPrefix(text, editHint) {
		text = text[len(editHint):]
	}
	return strings.TrimSpace(text)
}

// confirmFunc asks the user a question and returns their answer ("y"/"n"/"a").
type confirmFunc func(prompt string) string

// agentRegistry maps every accepted tool name to its definition. "bash" and
// "exec" are the same tool (exec = legacy OpenClaw skill name, §3.5).
var agentRegistry = map[string]Tool{
	"bash":       bashToolDef("bash"),
	"exec":       bashToolDef("exec"),
	"read_file":  readFileToolDef(),
	"search":     searchToolDef(),
	"write_file": writeFileToolDef(),
	"use_skill":  useSkillToolDef(),
}

// agentToolsOffered lists the tools sent to the model (one entry per unique
// definition; aliases stay lookup-only to save tokens).
func agentToolsOffered() []Tool {
	return []Tool{
		agentRegistry["bash"], agentRegistry["read_file"], agentRegistry["search"],
		agentRegistry["write_file"], agentRegistry["use_skill"],
	}
}

// alwaysApproved remembers "a" answers for the current session (cleared on
// /new; audit 3.9). It covers dangerous commands ONLY when their targets
// were all backed up pre-confirmation (effectively reversible); genuinely
// irreversible dangerous commands use alwaysApprovedCmd instead (see
// prepareDangerousBackups).
var alwaysApproved = map[string]bool{}

// alwaysCovers reports whether a remembered "always" answer auto-approves
// this call at the given risk level. Dangerous is handled by the tiered
// gate; unknown (ungradeable: command substitution, opaque syntax) must
// never be auto-approved at all (audit2 §1.2/§2.2).
func alwaysCovers(toolName string, risk commandRisk) bool {
	return alwaysApproved[toolName] && risk != riskDangerous && risk != riskUnknown
}

// alwaysApprovedCmd remembers "a" answers for exact irreversible commands
// (dangerous with no backupable target: dd, kill, systemctl, reboot...).
// Only the identical command string is covered — any variation asks again.
// Cleared on /new together with alwaysApproved.
var alwaysApprovedCmd = map[string]bool{}

func resetAlwaysApproved() {
	for k := range alwaysApproved {
		delete(alwaysApproved, k)
	}
	for k := range alwaysApprovedCmd {
		delete(alwaysApprovedCmd, k)
	}
}

// prepareDangerousBackups backs up every identifiable target of a dangerous
// command BEFORE confirmation (a backup is a read-only copy, so doing it
// early is side-effect-free). allBackedUp is false when there is nothing to
// back up or any target fails — such commands are genuinely irreversible
// and keep the strict confirmation tier.
func prepareDangerousBackups(sessionName, fullCmd string) (backups []string, allBackedUp bool) {
	targets := backupTargetsFor(fullCmd)
	if len(targets) == 0 {
		return nil, false
	}
	all := true
	for _, target := range targets {
		if dst := backupFile(sessionName, target); dst != "" {
			backups = append(backups, target+" -> "+dst)
		} else {
			all = false
		}
	}
	return backups, all
}

// Agent tunables; defaults here, overridable via config.json "agent" section
// (frza config set agent.max_rounds 30). See design §3.7.
var (
	agentMaxRounds     = 15
	agentBashTimeout   = 120 * time.Second // default; model may request more via timeout_sec (cap 600s)
	toolOutputMaxKB    = 8
	contextMaxTokens   = 256000
	backupKeepSessions = 10
)

// applyAgentConfig applies the config.json "agent" section onto the tunables.
func applyAgentConfig(cfg map[string]interface{}) {
	m := cfgMap(cfg, "agent")
	if m == nil {
		return
	}
	num := func(key string, dst *int) {
		if v, ok := m[key].(float64); ok && v > 0 {
			*dst = int(v)
		}
	}
	num("max_rounds", &agentMaxRounds)
	num("tool_output_max_kb", &toolOutputMaxKB)
	num("context_max_tokens", &contextMaxTokens)
	num("backup_keep_sessions", &backupKeepSessions)
	if v, ok := m["bash_timeout_sec"].(float64); ok && v > 0 {
		agentBashTimeout = time.Duration(int(v)) * time.Second
	}
}

// bashCommandOf extracts the full, untruncated command from a bash/exec tool
// call for SAFETY decisions (classification, backup extraction). Falls back to
// the raw arguments when unparseable — never truncated.
func bashCommandOf(tc ToolCall) string {
	var args struct {
		Command string `json:"command"`
	}
	if json.Unmarshal([]byte(tc.Arguments), &args) == nil && args.Command != "" {
		return args.Command
	}
	return tc.Arguments
}

// describeCall renders a one-line summary of a tool call for the terminal.
func describeCall(tc ToolCall) string {
	var args struct {
		Command string `json:"command"`
		Path    string `json:"path"`
		Pattern string `json:"pattern"`
		Name    string `json:"name"`
	}
	if json.Unmarshal([]byte(tc.Arguments), &args) == nil {
		switch {
		case args.Command != "":
			return truncateStr(args.Command, 200)
		case args.Pattern != "" && args.Path != "":
			return truncateStr(fmt.Sprintf("%q in %s", args.Pattern, args.Path), 200)
		case args.Path != "":
			return truncateStr(args.Path, 200)
		case args.Name != "":
			return args.Name
		}
	}
	return truncateStr(tc.Arguments, 200)
}

// sendMessage sends one user message to the model and renders the reply. In
// agent mode it runs the tool-calling loop: model -> tool calls -> results ->
// model, until a plain answer or the round cap. On failure/interruption of the
// FIRST round the user message is dropped (legacy behavior); later rounds keep
// history (tool results already recorded are valuable context).
func sendMessage(session *Session, userInput, provider, apiKey string, ask confirmFunc) {
	session.Messages = append(session.Messages, Message{Role: "user", Content: userInput})
	isStreaming := streamingProviders[provider]

	// Ctrl-C cancels the in-flight HTTP call or tool execution
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	var interrupted atomic.Bool
	go func() {
		select {
		case sig := <-sigCh:
			if sig == syscall.SIGTERM {
				// SIGTERM means the system wants the process gone (shutdown,
				// systemd stop, CI timeout) — save and exit rather than just
				// cancelling the in-flight request and returning to the REPL
				// (audit 3.1).
				saveSession(session, false)
				os.Exit(143)
			}
			interrupted.Store(true)
			cancel()
		case <-ctx.Done():
		}
	}()

	agent := agentMode && toolProviders[provider]
	var tools []Tool
	systemPrompt := session.SystemPrompt
	if agent {
		tools = agentToolsOffered()
		systemPrompt = composeAgentSystem(session.SystemPrompt)
	}

	// apiMessages is the API-bound copy of the conversation: context trimming
	// applies ONLY to it, never to session.Messages — the session keeps full
	// history so /history, /export and the audit trail never lose original
	// tool outputs (audit2 M1).
	var apiMessages []Message

	callRound := func() (CallResult, error) {
		indicator := newThinkingIndicator()
		indicator.start()
		var res CallResult
		var err error
		if isStreaming {
			fmt.Println()
			stream := newStreamRenderer()
			onDelta := func(text string) {
				indicator.stop()
				stream.feed(text)
			}
			onReasoning := func(string) { indicator.randomVerb() }
			res, err = callModel(ctx, provider, apiMessages, systemPrompt,
				session.Model, apiKey, session.BaseURL, tools, onDelta, onReasoning)
			indicator.stop()
			stream.finish()
			fmt.Println()
		} else {
			res, err = callModel(ctx, provider, apiMessages, systemPrompt,
				session.Model, apiKey, session.BaseURL, tools, nil, nil)
			indicator.stop()
		}
		return res, err
	}

	for round := 0; ; round++ {
		// Keep the API-bound copy within budget before each round (§3.8):
		// compress old tool outputs first, drop oldest turn groups if needed
		apiMessages = append([]Message(nil), session.Messages...)
		if trimmed, dropped := trimContext(apiMessages, contextMaxTokens); dropped > 0 {
			apiMessages = trimmed
			fmt.Println(stylize(fmt.Sprintf("[context] omitted %d oldest rounds from the model's view (full history kept locally) to fit the %d-token budget", dropped, contextMaxTokens), "yellow"))
		} else {
			apiMessages = trimmed
		}
		res, err := callRound()

		if interrupted.Load() || err == errInterrupted {
			fmt.Println(stylize("\n[cancelled] request interrupted", "gray"))
			if round == 0 {
				session.Messages = session.Messages[:len(session.Messages)-1]
			}
			return
		}
		if err != nil {
			fmt.Println(stylize(fmt.Sprintf("\n[error] %v", err), "red"))
			if hint := apiErrorHint(err); hint != "" {
				fmt.Println(stylize("  hint: "+hint, "gray"))
			}
			if round == 0 {
				session.Messages = session.Messages[:len(session.Messages)-1] // failed message is not recorded
			}
			return
		}

		// Record the assistant turn (text and/or tool requests)
		session.Messages = append(session.Messages, Message{Role: "assistant", Content: res.Text, ToolCalls: res.ToolCalls})
		if !isStreaming && res.Text != "" {
			fmt.Println()
			fmt.Println(renderMarkdown(res.Text))
			fmt.Println()
		}

		if len(res.ToolCalls) == 0 || !agent {
			break // plain final answer
		}

		// Execute tool calls sequentially (design §3.7: ordered, dependencies)
		for _, tc := range res.ToolCalls {
			if interrupted.Load() {
				// Ctrl-C landed mid-batch: skip the remaining calls instead of
				// executing them (audit 3.2 — read_file/search/write_file don't
				// watch ctx and would otherwise still run, write_file included).
				// Still record a tool message per call so the tool_call/tool
				// pairing survives for the next API round.
				session.Messages = append(session.Messages, Message{
					Role: "tool", ToolCallID: tc.ID, Name: tc.Name,
					Content: "[interrupted by user] tool call skipped",
				})
				continue
			}
			tool, known := agentRegistry[tc.Name]
			if !known {
				session.Messages = append(session.Messages, Message{
					Role: "tool", ToolCallID: tc.ID, Name: tc.Name,
					Content: fmt.Sprintf("[error] unknown tool %q", tc.Name),
				})
				continue
			}
			summary := describeCall(tc)
			fmt.Println(stylize(fmt.Sprintf("⚙ %s: %s", tc.Name, summary), "cyan"))

			fullCmd := ""
			if tc.Name == "bash" || tc.Name == "exec" {
				fullCmd = bashCommandOf(tc)
			}
			// The summary is only the first 200 chars — fine for display, but
			// the human approver must see what the classifier sees (review F1
			// fixed this for the machine; audit2 §3.1 for the human). Print
			// the complete, control-char-cleaned command when it exceeds the
			// summary.
			if fullCmd != "" && len(fullCmd) > 200 {
				fmt.Println(stylize(fmt.Sprintf("  full command (%d bytes): %s",
					len(fullCmd), sanitizeForDisplay(fullCmd)), "cyan"))
			}

			// The journal is the audit trail: record the full command (cleaned,
			// secrets redacted by journalWrite), never the 200-char display
			// summary — otherwise /journal can never reconstruct what actually
			// ran (audit2 §3.1)
			journalArgs := summary
			if fullCmd != "" {
				journalArgs = sanitizeForDisplay(fullCmd)
			}

			// ---- confirmation gate (§3.6) ----
			// Safety decisions (classification, backup extraction) MUST run on
			// the full untruncated command; summary is display-only (review F1:
			// a payload padded past describeCall's 200 chars would otherwise
			// evade the dangerous-pattern scan entirely).
			risk := riskUnknown
			confirmMode := "auto"
			approved := true
			var backups []string // pre-confirmation backups of dangerous targets
			dangerousBackedUp := false
			if tool.Confirm {
				if fullCmd != "" {
					risk = classifyCommand(fullCmd)
				} else if tc.Name == "write_file" {
					// write_file is undoable by design (backup on overwrite,
					// delete-on-create): grade it reversible so "a" can cover
					// it — riskUnknown must never be auto-approved (§1.2)
					risk = riskReversible
				}
				// Tiered dangerous handling: a dangerous command whose damage
				// is purely file-targeted (rm / redirection) with every target
				// safely backed up is effectively reversible, so "a" covers it
				// like any reversible call. Commands touching anything else
				// (dd/kill/systemctl/reboot — audit2 §2.1: a decoy rm must not
				// downgrade a chained systemctl) fall back to per-exact-command
				// memory.
				if risk == riskDangerous && fullCmd != "" {
					backups, dangerousBackedUp = prepareDangerousBackups(session.Name, fullCmd)
					if dangerousBackedUp && !dangerousOnlyFileTargeted(fullCmd) {
						dangerousBackedUp = false
					}
					for _, b := range backups {
						fmt.Println(stylize(fmt.Sprintf("  [backup] %s", b), "gray"))
					}
				}
				autoRisk := risk
				if dangerousBackedUp {
					autoRisk = riskReversible
				}
				switch {
				case risk == riskReadonly:
					fmt.Println(stylize("  [auto] read-only command", "gray"))
				case alwaysCovers(tc.Name, autoRisk):
					confirmMode = "always"
					fmt.Println(stylize("  [auto] pre-approved this session", "gray"))
				case risk == riskDangerous && !dangerousBackedUp && alwaysApprovedCmd[fullCmd]:
					confirmMode = "always"
					fmt.Println(stylize("  [auto] pre-approved this exact command", "gray"))
				default:
					if risk == riskDangerous {
						if dangerousBackedUp {
							fmt.Println(stylize("  ⚠ destructive — targets backed up above, /undo can restore", "yellow"))
						} else {
							fmt.Println(stylize("  ⚠ DESTRUCTIVE / NOT auto-reversible — no automatic undo possible", "red"))
						}
					}
					prompt := "  execute? [y]es/[n]o/[a]lways: "
					if risk == riskDangerous && !dangerousBackedUp {
						prompt = "  execute? [y]es/[n]o/[a]lways this exact command: "
					}
					ans := "y"
					if ask != nil {
						ans = ask(prompt)
					}
					confirmMode = ans
					if ans == "a" {
						if risk == riskDangerous && !dangerousBackedUp {
							alwaysApprovedCmd[fullCmd] = true
						} else {
							alwaysApproved[tc.Name] = true
						}
					} else if ans != "y" {
						approved = false
					}
				}
			}

			var result string
			if !approved {
				result = "[declined by user] the user refused to run this command; do NOT retry the same command, ask or propose an alternative"
				fmt.Println(stylize("  declined", "gray"))
				journalWrite(journalEntry{
					Time: time.Now().Format("2006-01-02T15:04:05"), Session: session.Name,
					Source: "model", Tool: tc.Name, Args: journalArgs, Confirm: confirmMode,
					Risk: riskName(risk), Result: "declined by user",
				})
			} else {
				// Dangerous bash targets were already backed up at the
				// confirmation gate (before the user answered). write_file
				// backs up here (overwrite) or marks creation for undo.
				var writeNewPath string // write_file creating a new file (undo = delete)
				if tc.Name == "write_file" {
					// Overwriting: back up the original; creating: undo = delete
					var wargs struct {
						Path string `json:"path"`
					}
					if json.Unmarshal([]byte(tc.Arguments), &wargs) == nil && wargs.Path != "" {
						if _, err := os.Stat(wargs.Path); err == nil {
							if dst := backupFile(session.Name, wargs.Path); dst != "" {
								backups = append(backups, wargs.Path+" -> "+dst)
								fmt.Println(stylize(fmt.Sprintf("  [backup] %s -> %s", wargs.Path, dst), "gray"))
							}
						} else {
							writeNewPath = wargs.Path
						}
					}
				}
				tStart := time.Now()
				// Heartbeat while the tool runs: bash can legitimately take
				// minutes (600s cap), and a silent terminal reads as a hang
				// (audit A2). No-op on non-tty.
				toolSpin := newThinkingIndicator()
				toolSpin.setState("Running " + tc.Name)
				toolSpin.start()
				out, rerr := tool.Run(ctx, tc.Arguments)
				toolSpin.stop()
				if rerr != nil {
					out = "[error] " + rerr.Error()
				}
				if interrupted.Load() {
					result = out + "\n[interrupted by user]"
				} else {
					result = out
				}
				fmt.Println(stylize(fmt.Sprintf("  → %s", truncateStr(firstLine(result), 160)), "gray"))
				je := journalEntry{
					Time: tStart.Format("2006-01-02T15:04:05"), Session: session.Name,
					Source: "model", Tool: tc.Name, Args: journalArgs, Confirm: confirmMode,
					Risk: riskName(risk), Result: truncateStr(result, 300),
				}
				if len(backups) > 0 {
					// one backup record per file for undo replay; the command
					// entry carries the first mapping for quick reading
					first := backups[0]
					if i := strings.Index(first, " -> "); i >= 0 {
						je.BackupOf, je.BackupTo = first[:i], first[i+4:]
					}
				}
				if writeNewPath != "" && rerr == nil && !strings.HasPrefix(out, "[error]") {
					je.Created = writeNewPath
				}
				journalWrite(je)
				for _, b := range backups {
					if b == backups[0] {
						continue // already recorded in je above
					}
					if i := strings.Index(b, " -> "); i >= 0 {
						journalWrite(journalEntry{
							Time: tStart.Format("2006-01-02T15:04:05"), Session: session.Name,
							Source: "model", Tool: "backup", Args: tc.Name + ": " + journalArgs,
							BackupOf: b[:i], BackupTo: b[i+4:], Result: "backup",
						})
					}
				}
			}
			session.Messages = append(session.Messages, Message{
				Role: "tool", ToolCallID: tc.ID, Name: tc.Name, Content: result,
			})
		}
		// Auto-save every round so an unexpected exit loses nothing
		// (throttled — a full rewrite+fsync every round is wasteful on long
		// investigations, audit2 M15; the window it opens is ≤2s of history)
		autoSaveSession(session)

		if interrupted.Load() {
			fmt.Println(stylize("\n[cancelled] tool execution interrupted", "gray"))
			return
		}
		if round+1 >= agentMaxRounds {
			fmt.Println(stylize(fmt.Sprintf("\n[agent] round limit (%d) reached; type /continue or send any message to keep going", agentMaxRounds), "yellow"))
			break
		}
	}
	// Final save at the end of the turn: never throttled
	saveSession(session, false)
}

// lastAutoSave records the last successful auto-save for throttling (M15).
var lastAutoSave time.Time

// autoSaveSession saves unless the previous save (any kind) happened within
// the last 2 seconds — rapid tool rounds would otherwise rewrite and fsync
// the whole session file every round.
func autoSaveSession(session *Session) {
	if time.Since(lastAutoSave) < 2*time.Second {
		return
	}
	saveSession(session, false)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func riskName(r commandRisk) string {
	switch r {
	case riskReadonly:
		return "readonly"
	case riskReversible:
		return "reversible"
	case riskDangerous:
		return "dangerous"
	}
	return "unknown"
}

func repl(session *Session, apiKey string) {
	provider := session.Provider
	fmt.Printf("%s  session %q  provider=%s  model=%s\n", shortVersion(), session.Name, provider, session.Model)
	if agentMode {
		fmt.Print("agent mode ON — the model can run tools (read-only auto-runs, changes ask first).\n")
	} else {
		// Say it out loud when tools are OFF: a resumed session without
		// --agent silently degrades to plain chat otherwise (audit A3)
		fmt.Print(stylize("agent mode OFF — chat only; enable with /agent on or --agent\n", "gray"))
	}
	fmt.Print("Type /help for commands, /exit to save and quit.\n\n")

	// Persist readline history across restarts so the up-arrow finds previous
	// sessions' commands (audit A1). 0600 like the journal: inputs may contain
	// hostnames, paths, pasted snippets.
	historyFile := filepath.Join(appDir, "input_history")
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "> ",
		AutoComplete:    frzCompleter{},
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		HistoryFile:     historyFile,
	})
	if err != nil {
		fmt.Println(stylize("[error] cannot initialize line editing: "+err.Error(), "red"))
		return
	}
	defer os.Chmod(historyFile, 0o600) // runs after rl.Close writes the file
	defer rl.Close()

	// ask is the confirmation gate for tool execution (y/n/a)
	ask := func(prompt string) string {
		rl.SetPrompt(prompt)
		line, err := rl.Readline()
		rl.SetPrompt("> ")
		if err != nil {
			fmt.Println()
			return "n"
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return "y"
		case "a", "always":
			return "a"
		}
		return "n"
	}

	for {
		userInput, err := rl.Readline()
		if err != nil { // Ctrl-C (ErrInterrupt) or Ctrl-D (io.EOF): save and quit
			fmt.Print("\n(interrupted, saving session...)\n")
			saveSession(session, false)
			break
		}
		userInput = strings.TrimSpace(userInput)
		if userInput == "" {
			continue
		}

		// `!cmd` runs a shell command directly (display only);
		// `!!cmd` also feeds the output to the model (design §3.1)
		if strings.HasPrefix(userInput, "!") {
			feed := strings.HasPrefix(userInput, "!!")
			cmdline := strings.TrimSpace(strings.TrimLeft(userInput, "!"))
			if cmdline == "" {
				continue
			}
			fmt.Println(stylize("$ "+cmdline, "cyan"))
			// User-typed commands show full output (paged when long); the
			// model-facing truncation only applies when feeding back via !!
			// (audit A7)
			out, timedOut := execBash(context.Background(), cmdline, agentBashTimeout)
			if timedOut {
				out += fmt.Sprintf("\n[error] command timed out after %s", agentBashTimeout)
			}
			pageText(out)
			journalWrite(journalEntry{
				Time: time.Now().Format("2006-01-02T15:04:05"), Session: session.Name,
				Source: "user", Tool: "bash", Args: cmdline, Confirm: "user-direct",
				Risk: riskName(classifyCommand(cmdline)), Result: truncateStr(out, 300),
			})
			if feed {
				outForModel := truncateToolOutput(out, 200, 50, toolOutputMaxKB*1024)
				sendMessage(session, fmt.Sprintf("$ %s\n%s", cmdline, outForModel), provider, apiKey, ask)
			}
			continue
		}

		if strings.HasPrefix(userInput, "/") {
			cmd := userInput
			arg := ""
			if i := strings.IndexAny(userInput, " \t"); i >= 0 {
				cmd, arg = userInput[:i], strings.TrimSpace(userInput[i+1:])
			}
			cmd = strings.ToLower(cmd)

			switch cmd {
			case "/exit", "/quit":
				if path, ok := saveSession(session, false); ok {
					fmt.Printf("session saved to %s\n", path)
				} else {
					fmt.Println("(empty session, not saved)")
				}
				return

			case "/help":
				fmt.Print(helpText)

			case "/save":
				if arg != "" && arg != session.Name {
					if _, err := os.Stat(sessionPath(arg)); err == nil {
						fmt.Printf("session %q already exists, pick another name (to avoid overwriting it)\n", arg)
						continue
					}
				}
				oldName := session.Name
				if arg != "" {
					session.Name = arg
				}
				if path, ok := saveSession(session, true); ok {
					fmt.Printf("saved to %s\n", path)
					// /save snapshots under a new name: copy artifacts so the
					// old session keeps its own undo chain (audit2 M4)
					copySessionArtifacts(oldName, session.Name)
				} else {
					session.Name = oldName // save failed: keep the old identity
				}

			case "/rename":
				if arg == "" {
					fmt.Println("usage: /rename <new-name>")
					continue
				}
				oldName := session.Name
				saveSession(session, false) // persist latest content first, then rename as a whole
				if ok, result := renameSessionFile(oldName, arg); ok {
					session.Name = arg
					migrateSessionArtifacts(oldName, arg)
					fmt.Printf("renamed session %q to %q\n", oldName, arg)
				} else {
					fmt.Println(result)
				}

			case "/resume":
				target := arg
				if target == "" {
					// No name given: resume the most recently updated session
					// (excluding the current one)
					for _, e := range listSessions() {
						if e.name != session.Name {
							target = e.name
							break
						}
					}
					if target == "" {
						fmt.Println("no session to resume.")
						continue
					}
				}
				saveSession(session, false)
				loaded := loadSession(target)
				if loaded == nil {
					fmt.Printf("session %q not found; type /list to see saved sessions.\n", target)
					continue
				}
				session = loaded
				provider = session.Provider
				// The resumed session may belong to another provider; re-resolve
				// the key against the session's own provider to avoid a 401
				if resumedKey := resolveAPIKey(provider, "", loadConfig()); resumedKey != "" {
					apiKey = resumedKey
				} else {
					envName := envKeyNames[provider]
					if envName == "" {
						envName = "corresponding env var"
					}
					fmt.Println(stylize(fmt.Sprintf("[note] no API key found for %s (%s); calls in this session will fail", provider, envName), "red"))
				}
				fmt.Printf("switched to session %q provider=%s model=%s\n", session.Name, provider, session.Model)

			case "/list":
				sessions := listSessions()
				if len(sessions) == 0 {
					fmt.Println("(no saved sessions yet)")
				}
				for _, e := range sessions {
					fmt.Printf("  - %s  [%s/%s]  %d messages  updated %s\n",
						e.name, e.sess.Provider, e.sess.Model, len(e.sess.Messages), e.sess.UpdatedAt)
				}

			case "/new":
				saveSession(session, false)
				newName := arg
				if newName == "" {
					newName = defaultSessionName()
				}
				// "always" approvals are per-session: don't let them leak into
				// the fresh session (audit 3.9)
				resetAlwaysApproved()
				// Carry base_url over: openai_responses and similar providers
				// cannot make calls without it
				session = newSession(newName, provider, session.Model, session.SystemPrompt, session.BaseURL)
				fmt.Printf("started new session %q\n", newName)

			case "/export":
				if len(session.Messages) == 0 {
					fmt.Println("(no conversation yet, nothing to export)")
					continue
				}
				path, overwritten := exportSession(session, arg)
				if path == "" {
					continue // error already reported by exportSession
				}
				msg := fmt.Sprintf("exported to %s", path)
				if overwritten {
					msg += " (overwrote existing file)"
				}
				fmt.Println(msg)

			case "/edit":
				text := editInEditor()
				if text != "" {
					if kb := len(text) / 1024; kb > 100 {
						fmt.Printf("(editor content is %d KB, sending as a whole)\n", kb)
					}
					sendMessage(session, text, provider, apiKey, ask)
				} else {
					fmt.Println("(empty content, cancelled)")
				}

			case "/system":
				switch {
				case arg == "":
					if session.SystemPrompt != "" {
						fmt.Printf("current system prompt: %s\n", session.SystemPrompt)
					} else {
						fmt.Println("current system prompt: (not set)")
					}
				case strings.EqualFold(arg, "off") || strings.EqualFold(arg, "clear") || strings.EqualFold(arg, "none"):
					session.SystemPrompt = ""
					fmt.Println("system prompt cleared.")
				default:
					session.SystemPrompt = arg
					fmt.Println("system prompt updated.")
				}

			case "/model":
				if arg != "" {
					session.Model = arg
					fmt.Printf("model switched to: %s\n", arg)
					fmt.Println(stylize("note: applies to this session only; persist with frza config set --model "+arg, "gray"))
				} else {
					fmt.Printf("current model: %s\n", session.Model)
				}

			case "/baseurl":
				if arg != "" {
					session.BaseURL = arg
					fmt.Printf("base url set to: %s\n", arg)
				} else if session.BaseURL != "" {
					fmt.Printf("current base url: %s\n", session.BaseURL)
				} else {
					fmt.Println("current base url: (not set, provider default)")
				}

			case "/history":
				msgs := session.Messages
				if len(msgs) == 0 {
					fmt.Println("(no conversation yet in this session)")
					continue
				}
				if arg != "" {
					var n int
					if _, err := fmt.Sscanf(arg, "%d", &n); err != nil || n <= 0 {
						fmt.Println("usage: /history [last N rounds]")
						continue
					}
					if 2*n < len(msgs) {
						msgs = msgs[len(msgs)-2*n:]
					}
					// Align to a user-message boundary so display doesn't start mid-round
					for len(msgs) > 0 && msgs[0].Role != "user" {
						msgs = msgs[1:]
					}
					if len(msgs) < len(session.Messages) {
						fmt.Printf("(showing last %d rounds only; full history has %d messages, /history shows all)\n",
							n, len(session.Messages))
					}
				}
				pageText(formatHistory(msgs))

			case "/clear":
				// One slip wipes the whole investigation context; confirm
				// first, consistent with the undo/journal safety model (A4)
				if len(session.Messages) > 0 {
					if ans := ask(fmt.Sprintf("  clear %d messages? [y/n]: ", len(session.Messages))); ans == "n" {
						fmt.Println("kept.")
						continue
					}
				}
				session.Messages = nil
				fmt.Println("session history cleared.")

			case "/agent":
				switch strings.ToLower(arg) {
				case "on":
					agentMode = true
				case "off":
					agentMode = false
				case "":
				default:
					fmt.Println("usage: /agent [on|off]")
					continue
				}
				state := "off"
				if agentMode {
					state = "on"
				}
				note := ""
				if agentMode && !toolProviders[session.Provider] {
					note = " (warning: provider " + session.Provider + " has no tool support; chat-only)"
				}
				fmt.Printf("agent mode: %s%s\n", state, note)

			case "/continue":
				if len(session.Messages) == 0 {
					fmt.Println("(nothing to continue)")
					continue
				}
				sendMessage(session, "Please continue the investigation from where you stopped.", provider, apiKey, ask)

			case "/skills":
				skills := getSkills()
				if len(skills) == 0 {
					fmt.Println("(no skills found; drop skill dirs containing SKILL.md into ~/.frza/skills/)")
					continue
				}
				fmt.Printf("%d skills:\n", len(skills))
				for _, s := range skills {
					fmt.Printf("  %-32s %s\n", s.Name, truncateStr(s.Description, 80))
				}

			case "/reload-skills":
				skills := scanSkills()
				fmt.Printf("reloaded: %d skills\n", len(skills))

			case "/undo":
				fmt.Println(undoLatest(session.Name))

			case "/journal":
				data, err := os.ReadFile(journalPath(session.Name))
				if err != nil {
					fmt.Println("(no journal entries for this session)")
					continue
				}
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				const maxShow = 20
				start := 0
				if len(lines) > maxShow {
					start = len(lines) - maxShow
					fmt.Printf("(showing last %d of %d entries; full log: %s)\n", maxShow, len(lines), journalPath(session.Name))
				}
				for _, ln := range lines[start:] {
					var e journalEntry
					if json.Unmarshal([]byte(ln), &e) != nil {
						continue
					}
					mark := " "
					if e.Risk == "dangerous" {
						mark = stylize("!", "red")
					}
					// full date+time for audit: cross-midnight incidents and
					// resumed days-old sessions are meaningless with time only
					ts := strings.Replace(e.Time, "T", " ", 1)
					fmt.Printf("%s %s [%s/%s] %s: %s\n", mark, ts, e.Source, e.Confirm, e.Tool, truncateStr(e.Args, 80))
				}

			default:
				if sug := suggestCommand(cmd); sug != "" {
					fmt.Printf("unknown command: %s; did you mean %s? (type /help for all commands)\n", cmd, sug)
				} else {
					fmt.Printf("unknown command: %s; type /help for available commands.\n", cmd)
				}
			}
			continue
		}

		// Normal user message -> call the model
		sendMessage(session, userInput, provider, apiKey, ask)
	}
}

// --------------------------------------------------------------------------
// CLI entry
// --------------------------------------------------------------------------

func resolveModel(provider, cliModel string, cfg map[string]interface{}) string {
	if cliModel != "" {
		return cliModel
	}
	if m := cfgMap(cfg, "models"); m != nil {
		if s, ok := m[provider].(string); ok && s != "" {
			return s
		}
	}
	// The legacy global "model" config field only applies to the default
	// provider in config — otherwise switching providers would call the API
	// with the previous provider's model name (404)
	if provider == cfgStr(cfg, "provider") {
		if m := cfgStr(cfg, "model"); m != "" {
			return m
		}
	}
	return defaultModels[provider]
}

func resolveBaseURL(provider, cliURL string, cfg map[string]interface{}) string {
	if cliURL != "" {
		return cliURL
	}
	if urls := cfgMap(cfg, "base_urls"); urls != nil {
		if s, ok := urls[provider].(string); ok && s != "" {
			return s
		}
	}
	return defaultBaseURLs[provider]
}

func resolveAPIKey(provider, cliKey string, cfg map[string]interface{}) string {
	if cliKey != "" {
		return cliKey
	}
	if envName := envKeyNames[provider]; envName != "" {
		if k := os.Getenv(envName); k != "" {
			return k
		}
	}
	if keys := cfgMap(cfg, "api_keys"); keys != nil {
		if s, ok := keys[provider].(string); ok {
			return s
		}
	}
	return ""
}

const helpUsage = `usage: frza [-h] [--provider PROVIDER] [--model MODEL] [--api-key KEY]
           [--base-url URL] [--system PROMPT] [--resume [NAME]]
           [--session-name NAME] [--list-sessions] [--agent] [--version]
           {config,rename,clean} ...

options:
  -h, --help           show this help message and exit
  --provider PROVIDER  model backend: openai_responses / anthropic / openai / gemini (default openai_responses)
  --model MODEL        model name, e.g. claude-sonnet-4-6 / gpt-4o / gemini-2.5-flash / kimi-k3
  --api-key KEY        API key (can also come from env var or config, see below)
  --base-url URL       custom API base url (required by openai_responses and similar providers)
  --system PROMPT      system prompt
  --resume [NAME]      resume a session (most recently updated one if NAME omitted)
  --session-name NAME  name for the new session (auto-generated if omitted)
  --list-sessions      list saved sessions and exit
  --agent              start in agent mode (the main event): the model investigates
                       with tools — bash/read_file/search/write_file/use_skill —
                       and follows skill playbooks from ~/.frza/skills/.
                       read-only commands auto-run, changes ask first (y/n/a),
                       destructive ops warn and back up first; see /journal /undo
  --version            show version info and exit

subcommands:
  config    view or set default config
  rename    rename a saved session
  clean     delete all empty sessions

Examples:
  frza --agent                               start the troubleshooting agent
  frza --agent --resume my-session           resume an investigation
  frza                                       plain chat with the default config
  frza --provider openai --model gpt-4o      pick a provider / model
  frza --list-sessions                       list all saved sessions and exit
  frza config set --provider openai_responses --api-key xxx --base-url URL
                                            persist defaults to ~/.frza/config.json
  frza rename old new                        rename a saved session
  frza clean                                 delete all empty sessions

API key precedence: --api-key > environment variable > config file
  anthropic=ANTHROPIC_API_KEY  openai=OPENAI_API_KEY
  gemini=GEMINI_API_KEY        openai_responses=ARK_API_KEY

Models and base urls are stored per provider and never leak across providers.

Once inside a session, type /help for slash commands (/agent /skills /undo
/journal /save /resume /export /edit /history etc.); !cmd runs a shell command
directly, !!cmd also feeds its output to the model; Tab completes commands and
session names after /resume, /save and /new.
`

// parseFlags parses "--flag value", "--flag=value" and "--boolflag" forms
func parseFlags(args []string, names map[string]bool, boolNames map[string]bool) (map[string]string, []string, error) {
	flags := map[string]string{}
	var rest []string
	i := 0
	for i < len(args) {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			kv := strings.SplitN(a[2:], "=", 2)
			name := kv[0]
			if boolNames[name] {
				flags[name] = "true"
				i++
				continue
			}
			if !names[name] {
				return nil, nil, fmt.Errorf("unknown option: --%s", name)
			}
			if len(kv) == 2 {
				flags[name] = kv[1]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[name] = args[i+1]
				i++
			} else {
				// next token is another flag (or missing): don't swallow it as
				// the value — `frza --model --agent` must not set model to
				// "--agent" (audit 3.9)
				return nil, nil, fmt.Errorf("option --%s requires a value", name)
			}
		} else {
			rest = append(rest, a)
		}
		i++
	}
	return flags, rest, nil
}

var mainFlagNames = map[string]bool{
	"provider": true, "model": true, "api-key": true, "base-url": true,
	"system": true, "resume": true, "session-name": true,
}

var mainBoolFlags = map[string]bool{"list-sessions": true, "version": true, "agent": true, "resume-latest": true}

// agentMode enables the tool-calling agent loop (--agent, /agent on|off).
var agentMode bool

// toolProviders: providers that support function calling (§1 provider policy).
var toolProviders = map[string]bool{"openai_responses": true}

func main() {
	ensureDirs()
	releaseEmbeddedSkills()
	args := os.Args[1:]

	// Subcommands
	if len(args) > 0 {
		switch args[0] {
		case "config":
			cmdConfig(args[1:])
			return
		case "rename":
			cmdRename(args[1:])
			return
		case "clean":
			cmdClean()
			return
		case "render": // hidden subcommand: render Markdown from stdin (for golden tests)
			data, _ := io.ReadAll(os.Stdin)
			fmt.Println(renderMarkdown(string(data)))
			return
		case "tooltest": // hidden subcommand: verify tool-calling against the live provider
			cmdToolTest(args[1:])
			return
		}
	}

	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Printf("%s — a terminal-native agentic troubleshooting agent\n", shortVersion())
			fmt.Print("the model investigates with tools (bash/read_file/search/write_file),\n" +
				"follows skill playbooks, and asks before changing anything (--agent).\n" +
				"Plain multi-provider chat works too (Anthropic / OpenAI / Gemini / Responses).\n")
			fmt.Printf("author: %s\n\n", author)
			fmt.Print(helpUsage)
			return
		}
	}

	// Bare `--resume` (no name) means "the most recently updated session",
	// mirroring the REPL's /resume-without-arg (audit A6). Rewrite it to a
	// bool flag before parsing so parseFlags doesn't demand a value.
	for i, a := range args {
		if a == "--resume" && (i+1 == len(args) || strings.HasPrefix(args[i+1], "--")) {
			args[i] = "--resume-latest"
		}
	}

	flags, _, err := parseFlags(args, mainFlagNames, mainBoolFlags)
	if err != nil {
		fmt.Println(err)
		fmt.Print("usage: frza [-h] [--provider PROVIDER] [--model MODEL] [--api-key KEY]\n" +
			"           [--base-url URL] [--system PROMPT] [--resume [NAME]]\n" +
			"           [--session-name NAME] [--list-sessions] [--agent] [--version]\n" +
			"           {config,rename,clean} ...\n")
		os.Exit(1)
	}
	if flags["version"] == "true" {
		fmt.Println(versionString())
		return
	}
	listOnly := flags["list-sessions"] == "true"
	agentMode = flags["agent"] == "true"
	cfg := loadConfig()
	applyAgentConfig(cfg)

	if listOnly {
		sessions := listSessions()
		if len(sessions) == 0 {
			fmt.Println("(no saved sessions yet)")
		}
		for _, e := range sessions {
			fmt.Printf("  - %s  [%s/%s]  %d messages  updated %s\n",
				e.name, e.sess.Provider, e.sess.Model, len(e.sess.Messages), e.sess.UpdatedAt)
		}
		return
	}

	provider := flags["provider"]
	if provider == "" {
		provider = cfgStr(cfg, "provider")
	}
	if provider == "" {
		provider = "openai_responses"
	}
	if _, ok := callers[provider]; !ok {
		fmt.Printf("[error] unknown provider: %s (choose from: openai_responses / anthropic / openai / gemini)\n", provider)
		os.Exit(1)
	}

	var session *Session
	resumeName := flags["resume"]
	if flags["resume-latest"] == "true" {
		for _, e := range listSessions() { // sorted by mtime, newest first
			resumeName = e.name
			break
		}
		if resumeName == "" {
			fmt.Println("[error] no session to resume; start a fresh one instead.")
			os.Exit(1)
		}
	}
	if resumeName != "" {
		session = loadSession(resumeName)
		if session == nil {
			fmt.Printf("[error] session %q not found; see --list-sessions.\n", resumeName)
			os.Exit(1)
		}
		// The REPL always calls the model with the session's own provider, so the
		// provider/key are re-resolved against it
		provider = session.Provider
	}

	model := resolveModel(provider, flags["model"], cfg)
	baseURL := resolveBaseURL(provider, flags["base-url"], cfg)
	apiKey := resolveAPIKey(provider, flags["api-key"], cfg)

	if apiKey == "" {
		envName := envKeyNames[provider]
		if envName == "" {
			envName = "corresponding env var"
		}
		fmt.Printf("[error] no API key found for %s. Provide it via:\n", provider)
		fmt.Println("  1) --api-key YOUR_KEY")
		fmt.Printf("  2) export %s=YOUR_KEY\n", envName)
		fmt.Printf("  3) frza config set --provider %s --api-key YOUR_KEY\n", provider)
		os.Exit(1)
	}

	if _, need := defaultBaseURLs[provider]; need && baseURL == "" {
		fmt.Printf("[error] provider=%s requires a base url; pass --base-url, "+
			"or frza config set --provider %s --base-url URL\n", provider, provider)
		os.Exit(1)
	}

	if session != nil {
		// --resume: apply command-line overrides
		if v := flags["system"]; v != "" {
			session.SystemPrompt = v
		}
		if v := flags["model"]; v != "" {
			session.Model = v
		}
		if v := flags["base-url"]; v != "" {
			session.BaseURL = v
		} else if session.BaseURL == "" {
			session.BaseURL = baseURL
		}
	} else {
		name := flags["session-name"]
		if name == "" {
			name = defaultSessionName()
		}
		sys := flags["system"]
		if sys == "" {
			sys = defaultSystemPrompt // baked into the session; /system shows/edits/clears it
		}
		session = newSession(name, provider, model, sys, baseURL)
	}

	repl(session, apiKey)
}

func cmdConfig(args []string) {
	if len(args) > 0 && args[0] == "set" {
		if err := checkConfigIntact(); err != nil {
			fmt.Println(stylize("[error] "+err.Error(), "red"))
			os.Exit(1)
		}
	}
	cfg := loadConfig()
	if len(args) == 0 || args[0] == "show" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		enc.Encode(cfg)
		fmt.Print(buf.String())
		return
	}
	if args[0] != "set" {
		fmt.Println("usage: frza config {set,show} ...")
		os.Exit(1)
	}
	for _, a := range args[1:] {
		if a == "-h" || a == "--help" {
			fmt.Print("usage: frza config set [-h] [--provider PROVIDER] [--model MODEL]\n" +
				"                     [--api-key KEY] [--base-url URL]\n\n" +
				"set default provider/model/api-key (API keys, base urls and models are stored per provider)\n")
			return
		}
	}
	flags, positional, err := parseFlags(args[1:], map[string]bool{
		"provider": true, "model": true, "api-key": true, "base-url": true,
	}, nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Positional form: frza config set agent.<key> <number> (design §3.7 knobs)
	if len(positional) > 0 {
		if len(positional) != 2 || !strings.HasPrefix(positional[0], "agent.") {
			fmt.Println("usage: frza config set agent.{max_rounds|bash_timeout_sec|tool_output_max_kb|backup_keep_sessions|context_max_tokens} N")
			os.Exit(1)
		}
		key := strings.TrimPrefix(positional[0], "agent.")
		allowed := map[string]bool{"max_rounds": true, "bash_timeout_sec": true, "tool_output_max_kb": true, "backup_keep_sessions": true, "context_max_tokens": true}
		if !allowed[key] {
			fmt.Printf("[error] unknown agent config key %q\n", key)
			os.Exit(1)
		}
		var num int
		if _, err := fmt.Sscanf(positional[1], "%d", &num); err != nil || num <= 0 {
			fmt.Printf("[error] value must be a positive integer: %q\n", positional[1])
			os.Exit(1)
		}
		m := cfgMap(cfg, "agent")
		if m == nil {
			m = map[string]interface{}{}
			cfg["agent"] = m
		}
		m[key] = num
		saveConfig(cfg)
		fmt.Printf("agent.%s = %d (takes effect on next start)\n", key, num)
		return
	}
	defaultProvider := flags["provider"]
	if defaultProvider == "" {
		defaultProvider = cfgStr(cfg, "provider")
	}
	if defaultProvider == "" {
		defaultProvider = "openai_responses"
	}
	if v := flags["provider"]; v != "" {
		cfg["provider"] = v
	}
	if v := flags["model"]; v != "" {
		m := cfgMap(cfg, "models")
		if m == nil {
			m = map[string]interface{}{}
			cfg["models"] = m
		}
		m[defaultProvider] = v
	}
	if v := flags["api-key"]; v != "" {
		m := cfgMap(cfg, "api_keys")
		if m == nil {
			m = map[string]interface{}{}
			cfg["api_keys"] = m
		}
		m[defaultProvider] = v
	}
	if v := flags["base-url"]; v != "" {
		m := cfgMap(cfg, "base_urls")
		if m == nil {
			m = map[string]interface{}{}
			cfg["base_urls"] = m
		}
		m[defaultProvider] = v
	}
	saveConfig(cfg)
	fmt.Printf("config saved to %s\n", configFile)
}

func cmdRename(args []string) {
	if len(args) != 2 {
		fmt.Println("usage: frza rename <old-name> <new-name>")
		os.Exit(1)
	}
	if ok, result := renameSessionFile(args[0], args[1]); ok {
		fmt.Printf("renamed session %q to %q (%s)\n", args[0], args[1], result)
	} else {
		fmt.Printf("[error] %s\n", result)
		os.Exit(1)
	}
}

func cmdClean() {
	removed := []string{}
	for _, e := range listSessions() {
		if len(e.sess.Messages) == 0 {
			os.Remove(sessionPath(e.name))
			removed = append(removed, e.name)
			fmt.Printf("deleted empty session: %s\n", e.name)
		}
	}
	if len(removed) == 0 {
		fmt.Println("(no empty sessions)")
	}
	// Prune old backup dirs, keeping the most recent backupKeepSessions (§3.6)
	entries, err := os.ReadDir(backupDir)
	if err == nil {
		type bd struct {
			name string
			mod  time.Time
		}
		var dirs []bd
		for _, e := range entries {
			if info, err := e.Info(); err == nil && e.IsDir() {
				dirs = append(dirs, bd{e.Name(), info.ModTime()})
			}
		}
		// guard on len(dirs), not len(entries): stray files/stat errors can
		// shrink dirs below backupKeepSessions (review F6)
		if len(dirs) > backupKeepSessions {
			sort.Slice(dirs, func(i, j int) bool { return dirs[i].mod.After(dirs[j].mod) })
			for _, d := range dirs[backupKeepSessions:] {
				os.RemoveAll(filepath.Join(backupDir, d.name))
				fmt.Printf("pruned old backups: %s\n", d.name)
			}
		}
	}
}

// cmdToolTest is a hidden developer subcommand: it offers a fake "bash" tool to
// the live provider and prints the parsed tool calls, then feeds a canned
// result back to verify the function_call_output round-trip. Usage:
//
//	frza tooltest [--provider openai_responses] [--model M] [--base-url URL]
func cmdToolTest(args []string) {
	flags, _, err := parseFlags(args, mainFlagNames, mainBoolFlags)
	if err != nil {
		fmt.Println(err)
		return
	}
	cfg := loadConfig()
	provider := flags["provider"]
	if provider == "" {
		provider = cfgStr(cfg, "provider")
	}
	if provider == "" {
		provider = "openai_responses"
	}
	model := resolveModel(provider, flags["model"], cfg)
	baseURL := resolveBaseURL(provider, flags["base-url"], cfg)
	apiKey := resolveAPIKey(provider, flags["api-key"], cfg)
	if apiKey == "" {
		fmt.Println("no API key; run: frza config set --provider " + provider + " --api-key YOUR_KEY")
		return
	}
	fmt.Printf("provider=%s model=%s base=%s\n", provider, model, baseURL)

	bashTool := Tool{
		Name:        "bash",
		Description: "Run a shell command",
		Schema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"command": map[string]interface{}{"type": "string", "description": "the shell command to run"}},
			"required":   []string{"command"},
		},
	}
	msgs := []Message{{Role: "user", Content: "What is the disk usage of / on this machine? Use the bash tool to find out."}}

	ctx := context.Background()
	res, err := callModel(ctx, provider, msgs, "", model, apiKey, baseURL, []Tool{bashTool}, nil, nil)
	if err != nil {
		fmt.Println("[round1 error]", err)
		return
	}
	fmt.Printf("[round1] text=%q tool_calls=%d\n", truncateStr(res.Text, 80), len(res.ToolCalls))
	for _, tc := range res.ToolCalls {
		fmt.Printf("  call id=%q name=%q args=%s\n", tc.ID, tc.Name, tc.Arguments)
	}
	if len(res.ToolCalls) == 0 {
		fmt.Println("FAIL: model did not request a tool call")
		return
	}

	// Round 2: replay the call + a canned result, expect a final text answer
	msgs = append(msgs,
		Message{Role: "assistant", ToolCalls: res.ToolCalls},
		Message{Role: "tool", ToolCallID: res.ToolCalls[0].ID, Name: res.ToolCalls[0].Name,
			Content: "Filesystem      Size  Used Avail Use% Mounted on\n/dev/disk3s1   460G  380G   60G  87% /"},
	)
	res2, err := callModel(ctx, provider, msgs, "", model, apiKey, baseURL, []Tool{bashTool}, nil, nil)
	if err != nil {
		fmt.Println("[round2 error]", err)
		return
	}
	fmt.Printf("[round2] text=%q tool_calls=%d\n", truncateStr(res2.Text, 200), len(res2.ToolCalls))
	if res2.Text == "" {
		fmt.Println("FAIL: no final answer after tool result")
		return
	}
	fmt.Println("PASS: tool-calling round-trip works")
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return cutAtRuneBoundary(s, n) + "..."
}
