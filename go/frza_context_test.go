package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bigString(n int) string { return strings.Repeat("x", n) }

// TestTrimContextCompressFirst: tool outputs are compressed BEFORE any turn
// group is dropped, and the tool message structure (ToolCallID) survives.
func TestTrimContextCompressFirst(t *testing.T) {
	msgs := []Message{
		{Role: "user", Content: "check the log"},
		{Role: "assistant", ToolCalls: []ToolCall{{ID: "c1", Name: "bash", Arguments: `{"command":"cat big.log"}`}}},
		{Role: "tool", ToolCallID: "c1", Name: "bash", Content: bigString(40000)},
		{Role: "assistant", Content: "analysis result"},
	}
	full := messagesTokens(msgs)
	budget := full - estimateTokens(bigString(40000)) + 500 // only compression fits
	out, dropped := trimContext(msgs, budget)
	if dropped != 0 {
		t.Fatalf("compression should suffice, dropped %d groups", dropped)
	}
	if messagesTokens(out) > budget {
		t.Errorf("still over budget: %d > %d", messagesTokens(out), budget)
	}
	if out[2].Role != "tool" || out[2].ToolCallID != "c1" {
		t.Errorf("tool message structure broken: %+v", out[2])
	}
	if !strings.Contains(out[2].Content, "omitted") {
		t.Errorf("tool output not compressed: %q", out[2].Content[:60])
	}
	// original slice untouched
	if msgs[2].Content != bigString(40000) {
		t.Errorf("input slice was mutated")
	}
}

// TestTrimContextDropsWholeGroups: under a tight budget the oldest turn groups
// go as a unit — never leaving an orphaned tool result or an assistant message
// whose tool results were dropped.
func TestTrimContextDropsWholeGroups(t *testing.T) {
	var msgs []Message
	for i := 0; i < 6; i++ {
		msgs = append(msgs,
			Message{Role: "user", Content: "round " + string(rune('a'+i)) + " " + bigString(2000)},
			Message{Role: "assistant", ToolCalls: []ToolCall{{ID: "c" + string(rune('0'+i)), Name: "bash", Arguments: `{"command":"x"}`}}},
			Message{Role: "tool", ToolCallID: "c" + string(rune('0'+i)), Name: "bash", Content: bigString(2000)},
			Message{Role: "assistant", Content: "answer " + bigString(500)},
		)
	}
	out, dropped := trimContext(msgs, 3000)
	if dropped == 0 {
		t.Fatalf("expected group drops")
	}
	if messagesTokens(out) > 4000 { // budget + marker slack
		t.Errorf("way over budget after trim: %d", messagesTokens(out))
	}
	// no orphan: first message after optional marker must not be a bare tool msg
	start := 0
	if strings.HasPrefix(out[0].Content, "[context note:") {
		start = 1
	}
	if out[start].Role == "tool" {
		t.Errorf("orphaned tool message at start of trimmed context")
	}
	// tool_call pairing: every assistant ToolCalls must have its result following
	for i, m := range out {
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			if i+1 >= len(out) || out[i+1].Role != "tool" || out[i+1].ToolCallID != m.ToolCalls[0].ID {
				t.Errorf("broken tool_call pairing at index %d", i)
			}
		}
	}
	// the newest round always survives
	last := out[len(out)-1]
	if !strings.Contains(last.Content, "answer") {
		t.Errorf("newest round was dropped")
	}
}

// TestParseSkillFrontmatter covers both modern and OpenClaw-legacy formats.
func TestParseSkillFrontmatter(t *testing.T) {
	modern := `---
name: k8s-analyzer
description: Kubernetes 集群故障分析，覆盖 kubelet、etcd、CNI
  以及调度失败等高频场景
activate_when:
  - 节点 NotReady
  - Pod 启动失败
version: 1.0
---
# body`
	name, desc, act := parseSkillFrontmatter(modern)
	if name != "k8s-analyzer" {
		t.Errorf("name = %q", name)
	}
	if !strings.Contains(desc, "etcd") || !strings.Contains(desc, "高频场景") {
		t.Errorf("multi-line description broken: %q", desc)
	}
	if len(act) != 2 || act[0] != "节点 NotReady" {
		t.Errorf("activate_when = %v", act)
	}

	legacy := `---
skill_name: Linux内核崩溃（kdump）分析
description: 自动化分析 vmcore
author: someone
version: 5.0.0
---
# body`
	name, desc, _ = parseSkillFrontmatter(legacy)
	if name != "Linux内核崩溃（kdump）分析" {
		t.Errorf("legacy skill_name not honored: %q", name)
	}
	if desc != "自动化分析 vmcore" {
		t.Errorf("legacy description: %q", desc)
	}

	// no frontmatter at all
	name, desc, _ = parseSkillFrontmatter("# just markdown")
	if name != "" || desc != "" {
		t.Errorf("expected empty parse for frontmatter-less content")
	}
}

// TestResponsesInputItems verifies the canonical->wire mapping, especially
// tool_call pairing serialization.
func TestResponsesInputItems(t *testing.T) {
	msgs := []Message{
		{Role: "user", Content: "hi"},
		{Role: "assistant", Content: "let me check", ToolCalls: []ToolCall{{ID: "bash_0", Name: "bash", Arguments: `{"command":"df"}`}}},
		{Role: "tool", ToolCallID: "bash_0", Name: "bash", Content: "9% used"},
		{Role: "assistant", Content: "all good"},
	}
	items := responsesInputItems(msgs)
	if len(items) != 5 {
		t.Fatalf("expected 5 items, got %d", len(items))
	}
	if items[0]["role"] != "user" {
		t.Errorf("item0 = %+v", items[0])
	}
	if items[1]["role"] != "assistant" {
		t.Errorf("item1 = %+v", items[1])
	}
	fc := items[2]
	if fc["type"] != "function_call" || fc["call_id"] != "bash_0" || fc["name"] != "bash" {
		t.Errorf("function_call item wrong: %+v", fc)
	}
	out := items[3]
	if out["type"] != "function_call_output" || out["call_id"] != "bash_0" || out["output"] != "9% used" {
		t.Errorf("function_call_output item wrong: %+v", out)
	}
	// assistant with empty content but tool calls -> no empty text item
	msgs2 := []Message{
		{Role: "assistant", ToolCalls: []ToolCall{{ID: "x", Name: "bash", Arguments: "{}"}}},
	}
	items2 := responsesInputItems(msgs2)
	if len(items2) != 1 || items2[0]["type"] != "function_call" {
		t.Errorf("empty-content assistant with tool calls should emit only function_call: %+v", items2)
	}
}

// TestUndoLatest replays a synthetic journal: created-file deletion, then
// backup restoration, then nothing left.
func TestUndoLatest(t *testing.T) {
	// sandbox the journal/backup dirs
	tmp := t.TempDir()
	oldJournal, oldBackup := journalDir, backupDir
	journalDir = filepath.Join(tmp, "journal")
	backupDir = filepath.Join(tmp, "backups")
	t.Cleanup(func() { journalDir, backupDir = oldJournal, oldBackup })

	sess := "test-sess"
	created := filepath.Join(tmp, "agent-made.txt")
	orig := filepath.Join(tmp, "original.txt")
	backup := filepath.Join(tmp, "backups", sess, "0001-original.txt")
	os.MkdirAll(filepath.Dir(backup), 0o755)
	os.WriteFile(created, []byte("agent content"), 0o644)
	os.WriteFile(backup, []byte("original content"), 0o644)

	journalWrite(journalEntry{Time: "t1", Session: sess, Source: "model", Tool: "write_file",
		Args: orig, BackupOf: orig, BackupTo: backup, Result: "ok"})
	journalWrite(journalEntry{Time: "t2", Session: sess, Source: "model", Tool: "write_file",
		Args: created, Created: created, Result: "ok"})

	// 1st undo: newest first -> deletes the created file
	msg := undoLatest(sess)
	if !strings.Contains(msg, "deleted") {
		t.Fatalf("undo1 = %q", msg)
	}
	if _, err := os.Stat(created); !os.IsNotExist(err) {
		t.Errorf("created file still exists after undo")
	}

	// 2nd undo: restores the backup
	msg = undoLatest(sess)
	if !strings.Contains(msg, "restored") {
		t.Fatalf("undo2 = %q", msg)
	}
	data, _ := os.ReadFile(orig)
	if string(data) != "original content" {
		t.Errorf("restored content = %q", string(data))
	}

	// 3rd undo: nothing left
	msg = undoLatest(sess)
	if !strings.Contains(msg, "nothing to undo") {
		t.Errorf("undo3 = %q", msg)
	}
}
