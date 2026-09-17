package main

// Regression tests for the medium-severity audit batch (AUDIT.md §3).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestRunBashKillsProcessGroup (audit 3.3): a timeout must kill the whole
// process group, not just bash — grandchildren must not be orphaned.
func TestRunBashKillsProcessGroup(t *testing.T) {
	tmp := t.TempDir()
	pidFile := filepath.Join(tmp, "child.pid")
	out, err := runBash(context.Background(),
		fmt.Sprintf(`{"command":"sleep 300 & echo $! > %s; wait","timeout_sec":1}`, pidFile))
	if err != nil {
		t.Fatalf("runBash: %v", err)
	}
	if !strings.Contains(out, "timed out") {
		t.Fatalf("expected timeout, got %q", out)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("child pid not recorded: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("bad pid file: %q", data)
	}
	// SIGKILL delivery is immediate, but give the kernel a moment to reap
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return // process gone: success
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("grandchild process %d still alive after group kill", pid)
}

// TestUndoPreservesMode (audit 3.6): undo must restore the original
// permission bits, not force 0644.
func TestUndoPreservesMode(t *testing.T) {
	tmp := t.TempDir()
	oldJournal, oldBackup := journalDir, backupDir
	journalDir = filepath.Join(tmp, "journal")
	backupDir = filepath.Join(tmp, "backups")
	t.Cleanup(func() { journalDir, backupDir = oldJournal, oldBackup })

	target := filepath.Join(tmp, "script.sh")
	if err := os.WriteFile(target, []byte("#!/bin/sh\necho v1\n"), 0o750); err != nil {
		t.Fatal(err)
	}
	dst := backupFile("undo-mode", target)
	if dst == "" {
		t.Fatalf("backup failed")
	}
	// the tool-call path journals one entry per backup; mirror that here
	journalWrite(journalEntry{
		Time: nowISO(), Session: "undo-mode", Source: "model", Tool: "write_file",
		Args: target, BackupOf: target, BackupTo: dst, Result: "ok",
	})
	// agent "breaks" the file: new content, tighter mode
	os.WriteFile(target, []byte("garbage"), 0o600)

	if msg := undoLatest("undo-mode"); !strings.Contains(msg, "restored") {
		t.Fatalf("undo failed: %s", msg)
	}
	data, _ := os.ReadFile(target)
	if !strings.Contains(string(data), "echo v1") {
		t.Errorf("content not restored: %q", data)
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o750 {
		t.Errorf("mode = %o, want 750 (exec bit lost)", info.Mode().Perm())
	}
}

// TestMigrateSessionArtifacts (audit 3.5): renaming a session must move its
// journal and backups so /undo keeps working.
func TestMigrateSessionArtifacts(t *testing.T) {
	tmp := t.TempDir()
	oldJournal, oldBackup := journalDir, backupDir
	journalDir = filepath.Join(tmp, "journal")
	backupDir = filepath.Join(tmp, "backups")
	t.Cleanup(func() { journalDir, backupDir = oldJournal, oldBackup })

	os.MkdirAll(journalDir, 0o700)
	os.WriteFile(journalPath("old-name"), []byte("{}\n"), 0o600)
	os.MkdirAll(filepath.Join(backupDir, "old-name"), 0o700)
	os.WriteFile(filepath.Join(backupDir, "old-name", "0001-x"), []byte("bak"), 0o600)

	migrateSessionArtifacts("old-name", "new-name")

	if _, err := os.Stat(journalPath("new-name")); err != nil {
		t.Errorf("journal not migrated: %v", err)
	}
	if _, err := os.Stat(journalPath("old-name")); !os.IsNotExist(err) {
		t.Errorf("old journal still present")
	}
	if _, err := os.Stat(filepath.Join(backupDir, "new-name", "0001-x")); err != nil {
		t.Errorf("backups not migrated: %v", err)
	}
	// same-name and empty-name calls are no-ops
	migrateSessionArtifacts("new-name", "new-name")
	migrateSessionArtifacts("", "x")
}

// TestAlwaysCovers (audit 3.9): "always" never covers dangerous commands and
// is cleared between sessions.
func TestAlwaysCovers(t *testing.T) {
	resetAlwaysApproved()
	t.Cleanup(resetAlwaysApproved)

	alwaysApproved["bash"] = true
	if !alwaysCovers("bash", riskReversible) || !alwaysCovers("bash", riskReadonly) {
		t.Errorf("always should cover reversible/read-only")
	}
	if alwaysCovers("bash", riskDangerous) {
		t.Errorf("always must NOT cover dangerous commands")
	}
	if alwaysCovers("bash", riskUnknown) {
		t.Errorf("always must NOT cover unknown-risk commands (audit2 §1.2)")
	}
	resetAlwaysApproved()
	if alwaysCovers("bash", riskReversible) {
		t.Errorf("resetAlwaysApproved did not clear approvals")
	}

	// exact-command memory is cleared too
	alwaysApprovedCmd["rm -rf /x"] = true
	resetAlwaysApproved()
	if alwaysApprovedCmd["rm -rf /x"] {
		t.Errorf("resetAlwaysApproved did not clear exact-command approvals")
	}
}

// TestPrepareDangerousBackups: the tier decision — a dangerous command with
// all targets backed up is effectively reversible; one with no backupable
// target (or a failed backup) is not.
func TestPrepareDangerousBackups(t *testing.T) {
	tmp := t.TempDir()
	oldBackup := backupDir
	backupDir = filepath.Join(tmp, "backups")
	t.Cleanup(func() { backupDir = oldBackup })

	existing := filepath.Join(tmp, "data.log")
	os.WriteFile(existing, []byte("important"), 0o600)

	// no backupable target: genuinely irreversible
	if _, ok := prepareDangerousBackups("s", "systemctl restart nginx"); ok {
		t.Errorf("systemctl restart should NOT count as backed up")
	}
	if _, ok := prepareDangerousBackups("s", "dd if=/dev/zero of=/dev/sda"); ok {
		t.Errorf("dd should NOT count as backed up")
	}
	// all targets backed up: effectively reversible
	backups, ok := prepareDangerousBackups("s", "rm "+existing)
	if !ok || len(backups) != 1 {
		t.Errorf("rm of existing file should be fully backed up: %v %v", backups, ok)
	}
	// any failed target (missing file) demotes the command back to irreversible
	if _, ok := prepareDangerousBackups("s", "rm "+existing+" "+filepath.Join(tmp, "ghost")); ok {
		t.Errorf("rm with a missing target should NOT count as fully backed up")
	}
}

// TestParseFlagsNoSwallow (audit 3.9): `--model --agent` must not set the
// model to "--agent".
func TestParseFlagsNoSwallow(t *testing.T) {
	if _, _, err := parseFlags([]string{"--model", "--agent"}, mainFlagNames, mainBoolFlags); err == nil {
		t.Errorf("expected 'requires a value' error")
	}
	flags, _, err := parseFlags([]string{"--model", "k3", "--agent"}, mainFlagNames, mainBoolFlags)
	if err != nil || flags["model"] != "k3" || flags["agent"] != "true" {
		t.Errorf("normal parsing broke: %v %v", flags, err)
	}
}

// TestCutAtRuneBoundary (audit 3.8): truncation never splits a multibyte
// rune and closes dangling ANSI styles.
func TestCutAtRuneBoundary(t *testing.T) {
	// 中 is 3 bytes; a 5-byte budget must keep only the first rune
	got := truncateStr("中文中文", 5)
	if got != "中..." {
		t.Errorf("truncateStr mid-rune: %q", got)
	}
	got = truncateStr("\033[31mred text here\033[0m", 9)
	if !strings.Contains(got, "\033[0m") {
		t.Errorf("dangling ANSI not reset: %q", got)
	}
	// byte-cap path of truncateToolOutput
	big := strings.Repeat("中", 100) // 300 bytes
	out := truncateToolOutput(big, 200, 50, 100)
	marker := strings.Index(out, "[... truncated at")
	if marker < 0 {
		t.Fatalf("truncation marker missing: %q", out)
	}
	if !strings.Contains(out[:marker], "中") || !utf8Valid(out[:marker]) {
		t.Errorf("invalid UTF-8 after truncation: %q", out[:marker])
	}
}

func utf8Valid(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			size := 0
			switch {
			case s[i]&0xE0 == 0xC0:
				size = 2
			case s[i]&0xF0 == 0xE0:
				size = 3
			case s[i]&0xF8 == 0xF0:
				size = 4
			default:
				return false
			}
			if i+size > len(s) {
				return false
			}
			i += size - 1
		}
	}
	return true
}

// TestBackupTargetsSudoAndQuotes (audit 3.9): sudo-prefixed rm and quoted
// operands must still yield backup targets.
func TestBackupTargetsSudoAndQuotes(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"sudo rm -rf /data", []string{"/data"}},
		{"doas rm x.log", []string{"x.log"}},
		{`rm "a b"`, []string{"a b"}},
		{"rm -f plain.txt", []string{"plain.txt"}},
	}
	for _, c := range cases {
		got := backupTargetsFor(c.cmd)
		if len(got) != len(c.want) || (len(got) > 0 && got[0] != c.want[0]) {
			t.Errorf("backupTargetsFor(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestRetryAfterHeader (audit 3.7): a 429 with Retry-After must wait at
// least that long even when the backoff schedule is shorter.
func TestRetryAfterHeader(t *testing.T) {
	withFastRetries(t) // backoffs shrink to 1ms; Retry-After must dominate
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			fmt.Fprint(w, `{"error":"slow down"}`)
			return
		}
		fmt.Fprint(w, `{"content":[{"type":"text","text":"ok"}]}`)
	}))
	defer srv.Close()

	start := time.Now()
	res, err := callAnthropic(context.Background(),
		[]Message{{Role: "user", Content: "hi"}}, "", "m", "key", srv.URL, nil, nil, nil)
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	if res.Text != "ok" {
		t.Errorf("text = %q", res.Text)
	}
	if d := time.Since(start); d < 900*time.Millisecond {
		t.Errorf("Retry-After not honored: waited only %s", d)
	}
}

// TestAnthropicRetriesAndBaseURL (audit 3.7): non-streaming callers retry
// 429/5xx and honor a custom base-url.
func TestAnthropicRetriesAndBaseURL(t *testing.T) {
	withFastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %s, want /v1/messages", r.URL.Path)
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(500)
			return
		}
		fmt.Fprint(w, `{"content":[{"type":"text","text":"hi"}]}`)
	}))
	defer srv.Close()

	res, err := callAnthropic(context.Background(),
		[]Message{{Role: "user", Content: "hi"}}, "", "m", "key", srv.URL, nil, nil, nil)
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	if res.Text != "hi" || calls.Load() != 2 {
		t.Errorf("text=%q calls=%d, want hi/2", res.Text, calls.Load())
	}
}

// TestOpenAIMaxTokensFallback (audit 3.7): a gateway that rejects
// max_completion_tokens gets one automatic retry with max_tokens.
func TestOpenAIMaxTokensFallback(t *testing.T) {
	withFastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		if strings.Contains(string(body), "max_completion_tokens") {
			calls.Add(1)
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":{"message":"unsupported parameter max_completion_tokens"}}`)
			return
		}
		if !strings.Contains(string(body), "max_tokens") {
			t.Errorf("fallback request missing max_tokens: %s", body)
		}
		calls.Add(1)
		fmt.Fprint(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer srv.Close()

	res, err := callOpenAI(context.Background(),
		[]Message{{Role: "user", Content: "hi"}}, "", "m", "key", srv.URL, nil, nil, nil)
	if err != nil {
		t.Fatalf("expected fallback success, got %v", err)
	}
	if res.Text != "ok" || calls.Load() != 2 {
		t.Errorf("text=%q calls=%d, want ok/2", res.Text, calls.Load())
	}
}

// TestGeminiBaseURL (audit 3.7): gemini honors a custom base-url.
func TestGeminiBaseURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models/gemini-x:generateContent" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("x-goog-api-key") != "key" {
			t.Errorf("api key header missing")
		}
		fmt.Fprint(w, `{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`)
	}))
	defer srv.Close()

	res, err := callGemini(context.Background(),
		[]Message{{Role: "user", Content: "hi"}}, "", "gemini-x", "key", srv.URL, nil, nil, nil)
	if err != nil || res.Text != "ok" {
		t.Errorf("res=%q err=%v", res.Text, err)
	}
}

// TestSSEIdleTimeout (audit 3.7): a stream that goes silent mid-response is
// reported as stalled, not spun on forever.
func TestSSEIdleTimeout(t *testing.T) {
	old := streamIdleTimeout
	streamIdleTimeout = 100 * time.Millisecond
	t.Cleanup(func() { streamIdleTimeout = old })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done() // hang: never send response.completed
	}))
	defer srv.Close()

	_, err := callOpenAIResponses(context.Background(),
		[]Message{{Role: "user", Content: "hi"}}, "", "m", "key", srv.URL, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "stream stalled") {
		t.Errorf("expected stream-stalled error, got %v", err)
	}
}

// TestBoundedWriter (audit2 §4.1): output is memory-bounded and the producer
// is killed once it floods.
func TestBoundedWriter(t *testing.T) {
	killed := 0
	w := &boundedWriter{killCap: boundedKillCap, kill: func() { killed++ }}
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = 'x'
	}
	for i := 0; i < 5; i++ { // 5 MB total, cap is 4 MB
		n, err := w.Write(chunk)
		if n != len(chunk) || err != nil {
			t.Fatalf("Write must consume everything: n=%d err=%v", n, err)
		}
	}
	if killed != 1 {
		t.Errorf("kill fired %d times, want exactly 1", killed)
	}
	if w.head.Len() != boundedHeadTail || len(w.tail) != boundedHeadTail {
		t.Errorf("head=%d tail=%d, want %d each", w.head.Len(), len(w.tail), boundedHeadTail)
	}
	out := w.String()
	if !strings.Contains(out, "process killed") {
		t.Errorf("kill marker missing: %.120s", out)
	}

	// small output: exact passthrough, no marker
	w2 := &boundedWriter{killCap: boundedKillCap}
	w2.Write([]byte("hello"))
	if got := w2.String(); got != "hello" {
		t.Errorf("small write mangled: %q", got)
	}
}

// TestExecBashBoundedOutput (audit2 §4.1): cat /dev/zero no longer OOMs —
// the producer is killed at the cap and execBash returns promptly.
func TestExecBashBoundedOutput(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero")
	}
	start := time.Now()
	out, timedOut := execBash(context.Background(), "cat /dev/zero", 60*time.Second)
	if timedOut {
		t.Errorf("should be killed by the output cap, not the timeout")
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("took too long: %s", d)
	}
	if !strings.Contains(out, "process killed") {
		t.Errorf("kill marker missing: %.120s", out)
	}
	if len(out) > 2*boundedHeadTail+4096 {
		t.Errorf("output not bounded: %d bytes", len(out))
	}
}

// TestExecBashWaitDelayOrphan (audit2 §4.5): a background child that outlives
// bash keeps the inherited stdout pipe open; without WaitDelay, cmd.Wait
// would block until the orphan exits on its own.
func TestExecBashWaitDelayOrphan(t *testing.T) {
	start := time.Now()
	out, timedOut := execBash(context.Background(), "sleep 30 & echo started", 30*time.Second)
	if timedOut {
		t.Errorf("bash exits immediately here; the timeout must not fire")
	}
	// bash has already exited; the orphan sleep holds the pipe for 30s, and
	// WaitDelay (2s) is all that unsticks Wait before then
	if d := time.Since(start); d > 8*time.Second {
		t.Errorf("WaitDelay not honored: took %s", d)
	}
	if !strings.Contains(out, "started") {
		t.Errorf("output lost: %q", out)
	}
}

// TestReadFileNotRegular (audit2 §4.1): devices/FIFOs are refused.
func TestReadFileNotRegular(t *testing.T) {
	out, err := runReadFile(context.Background(), `{"path":"/dev/null"}`)
	if err != nil {
		t.Fatalf("runReadFile: %v", err)
	}
	if !strings.Contains(out, "not a regular file") {
		t.Errorf("expected not-a-regular-file guard, got %.80s", out)
	}
}

// TestRunSearchSkipsFIFO (audit2 §4.1): search must not block on FIFOs.
func TestRunSearchSkipsFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello world\n"), 0o644)
	done := make(chan string, 1)
	go func() {
		out, _ := runSearch(context.Background(),
			fmt.Sprintf(`{"pattern":"hello","path":%q}`, dir))
		done <- out
	}()
	select {
	case out := <-done:
		if !strings.Contains(out, "a.txt:1") {
			t.Errorf("expected match in a.txt: %q", out)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("search hung (likely on the FIFO)")
	}
}

// TestSyncClientTimeoutFailsFast (audit2 M3): a client-side timeout must not
// be retried like a transient blip.
func TestSyncClientTimeoutFailsFast(t *testing.T) {
	old := httpClientSync
	httpClientSync = &http.Client{Timeout: 50 * time.Millisecond}
	t.Cleanup(func() { httpClientSync = old })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := callAnthropic(context.Background(),
		[]Message{{Role: "user", Content: "hi"}}, "", "m", "key", srv.URL, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout error, got %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("timeout was retried: calls = %d", calls.Load())
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("not fail-fast: %s", d)
	}
}

// TestCopySessionArtifacts (audit2 M4): /save snapshots copy the artifacts;
// the old session keeps its own undo chain.
func TestCopySessionArtifacts(t *testing.T) {
	tmp := t.TempDir()
	oldJournal, oldBackup := journalDir, backupDir
	journalDir = filepath.Join(tmp, "journal")
	backupDir = filepath.Join(tmp, "backups")
	t.Cleanup(func() { journalDir, backupDir = oldJournal, oldBackup })

	os.MkdirAll(journalDir, 0o700)
	os.WriteFile(journalPath("old-name"), []byte("{}\n"), 0o600)
	os.MkdirAll(filepath.Join(backupDir, "old-name"), 0o700)
	os.WriteFile(filepath.Join(backupDir, "old-name", "0001-x"), []byte("bak"), 0o640)

	copySessionArtifacts("old-name", "new-name")

	// old intact, new present with same content and mode
	if _, err := os.Stat(journalPath("old-name")); err != nil {
		t.Errorf("old journal lost: %v", err)
	}
	data, err := os.ReadFile(journalPath("new-name"))
	if err != nil || string(data) != "{}\n" {
		t.Errorf("journal copy wrong: %q %v", data, err)
	}
	info, err := os.Stat(filepath.Join(backupDir, "new-name", "0001-x"))
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("backup copy wrong: %v", err)
	}

	// never overwrite an existing target
	os.WriteFile(journalPath("new-name"), []byte("changed\n"), 0o600)
	copySessionArtifacts("old-name", "new-name")
	data, _ = os.ReadFile(journalPath("new-name"))
	if string(data) != "changed\n" {
		t.Errorf("existing journal overwritten: %q", data)
	}
}

// TestSuggestCommand (audit A5): typos and prefixes get a "did you mean" hint.
func TestSuggestCommand(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/jurnal", "/journal"}, // transposition typo
		{"/hist", "/history"},   // unambiguous prefix
		{"/reloa-skills", "/reload-skills"},
		{"/mode", "/model"},
		{"/xyz", ""}, // nothing close enough
	}
	for _, c := range cases {
		if got := suggestCommand(c.in); got != c.want {
			t.Errorf("suggestCommand(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAPIErrorHint (audit A8): common HTTP failures map to a fix suggestion.
func TestAPIErrorHint(t *testing.T) {
	cases := []struct {
		err  string
		want string // substring expected in the hint; "" means no hint
	}{
		{"HTTP 401: unauthorized", "api key"},
		{"HTTP 403: forbidden", "api key"},
		{"HTTP 404: model not found", "/model"},
		{"HTTP 429: slow down (after 4 attempts)", "rate limited"},
		{"HTTP 500: boom", ""},
		{"network error: dial tcp: refused", ""},
	}
	for _, c := range cases {
		got := apiErrorHint(fmt.Errorf("%s", c.err))
		if c.want == "" && got != "" {
			t.Errorf("apiErrorHint(%q) = %q, want none", c.err, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("apiErrorHint(%q) = %q, want substring %q", c.err, got, c.want)
		}
	}
}

// TestDangerousOnlyFileTargeted (audit2 §2.1): the downgrade gate — a decoy
// rm must not make a chained systemctl/dd/iptables "reversible".
func TestDangerousOnlyFileTargeted(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{"rm -f /tmp/x", true},
		{"echo hi > /tmp/x", true},
		{"rm -f /tmp/decoy && systemctl restart postgres", false},
		{"rm -f /tmp/decoy; dd if=/dev/zero of=/dev/sdb bs=1M", false},
		{"rm -f /tmp/decoy; iptables -F", false},
		{"dd if=/dev/zero of=/dev/sdb", false},
		{"cat /etc/hosts", true},                    // vacuous: no system pattern (not dangerous anyway)
		{"echo x &> /dev/null; rm -f /tmp/y", true}, // null-redirect stripped first
	}
	for _, c := range cases {
		if got := dangerousOnlyFileTargeted(c.cmd); got != c.want {
			t.Errorf("dangerousOnlyFileTargeted(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestSanitizeForDisplay (audit2 §3.1): control characters must not reach
// the terminal or the journal raw.
func TestSanitizeForDisplay(t *testing.T) {
	cases := []struct{ in, want string }{
		{"echo ok", "echo ok"},
		{"a\rb", `a\rb`},
		{"\x1b[2Kclear", `\e[2Kclear`},
		{"line1\nline2", `line1\nline2`},
		{"\x01\x7f", `\x01\x7f`},
		{"tab\there", "tab\there"}, // tabs are kept
	}
	for _, c := range cases {
		if got := sanitizeForDisplay(c.in); got != c.want {
			t.Errorf("sanitizeForDisplay(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRepairToolCallPairing (audit2 §4.4): a session saved mid tool-batch
// gets synthetic results so the next API round doesn't 400.
func TestRepairToolCallPairing(t *testing.T) {
	broken := []Message{
		{Role: "user", Content: "q"},
		{Role: "assistant", ToolCalls: []ToolCall{{ID: "c1", Name: "bash"}, {ID: "c2", Name: "bash"}}},
		{Role: "tool", ToolCallID: "c1", Name: "bash", Content: "ok"},
		{Role: "user", Content: "next"},
	}
	got := repairToolCallPairing(broken)
	// expect: user, assistant, tool(c1), tool(c2 synthetic), user
	if len(got) != 5 {
		t.Fatalf("repaired length = %d, want 5: %#v", len(got), got)
	}
	if got[3].ToolCallID != "c2" || got[3].Role != "tool" {
		t.Errorf("missing synthetic result for c2: %#v", got[3])
	}
	if got[4].Role != "user" {
		t.Errorf("tail shifted wrongly: %#v", got[4])
	}

	// intact sessions are untouched
	intact := []Message{
		{Role: "user", Content: "q"},
		{Role: "assistant", ToolCalls: []ToolCall{{ID: "c1", Name: "bash"}}},
		{Role: "tool", ToolCallID: "c1", Name: "bash", Content: "ok"},
	}
	if got := repairToolCallPairing(intact); len(got) != 3 {
		t.Errorf("intact session modified: %#v", got)
	}
}

// TestReadFileTooLarge (audit 3.9): read_file refuses to slurp a huge file.
func TestReadFileTooLarge(t *testing.T) {
	tmp := t.TempDir()
	big := filepath.Join(tmp, "big.log")
	f, _ := os.Create(big)
	f.Truncate(toolMaxFileBytes + 1) // sparse: instant
	f.Close()

	out, err := runReadFile(context.Background(), fmt.Sprintf(`{"path":%q}`, big))
	if err != nil {
		t.Fatalf("runReadFile: %v", err)
	}
	if !strings.Contains(out, "file too large") {
		t.Errorf("expected size guard, got %.80s", out)
	}
}
