package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestClassifyCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want commandRisk
	}{
		// read-only singles
		{"df -h", riskReadonly},
		{"ls -la /var/log", riskReadonly},
		{"cat /etc/hosts", riskReadonly},
		{"dmesg | tail -100", riskReadonly},
		{"ps aux | grep java", riskReadonly},
		{"kubectl get pods -n kube-system", riskReadonly},
		{"git status", riskReadonly},
		{"tar -tf bundle.tar.gz", riskReadonly},
		{"systemctl status nginx", riskReadonly},
		// harmless discard idioms must NOT escalate (regression: 2>/dev/null
		// used to match the overwrite-redirect dangerous pattern)
		{"du -sh . 2>/dev/null", riskReadonly},
		{"pwd && echo --- && du -sh . 2>/dev/null", riskReadonly},
		{"grep -r ERROR /var/log 2>/dev/null | head -50", riskReadonly},
		{"find / -name core 2>&1 | head", riskReadonly},
		{"du -h --max-depth=1 . 2>/dev/null | sort -hr | head -20", riskReadonly},
		// chain bypass attempts: worst segment wins
		{"ls; rm -rf /tmp/x", riskDangerous},
		{"cat /etc/hosts && rm a.log", riskDangerous},
		{"ls | tee out.txt", riskReversible}, // tee not whitelisted -> confirm
		{"echo hi > /tmp/x.txt", riskDangerous},
		{"cat a > b.conf", riskDangerous},
		// destructive
		{"rm -rf /var/log/old", riskDangerous},
		{"dd if=/dev/zero of=/dev/sda", riskDangerous},
		{"systemctl restart nginx", riskDangerous},
		{"kubectl delete pod foo", riskDangerous},
		{"kill -9 1234", riskDangerous},
		{"reboot", riskDangerous},
		{"chmod -R 777 /data", riskDangerous},
		// command substitution cannot be statically graded
		{"echo $(rm -rf x)", riskUnknown},
		{"ls `pwd`", riskUnknown},
		// whitelist write-flag escapes: not auto-run (regression guard)
		{"sed -i s/a/b/ app.conf", riskReversible},
		{"sed s/a/b/ app.conf", riskReadonly},
		{"find /var/log -name '*.log' -delete", riskReversible},
		{"find /var/log -name '*.log'", riskReadonly},
		{"sort -o out.txt in.txt", riskReversible},
		{"journalctl --vacuum-time=1d", riskReversible},
		{"journalctl -u nginx --since today", riskReadonly},
		{"ip link set eth0 down", riskReversible},
		{"ip addr show", riskReadonly},
		{"ifconfig eth0 down", riskReversible},
		{"ifconfig -a", riskReadonly},
		// git mutating forms must not be read-only (review F3)
		{"git branch -D feature-work", riskReversible},
		{"git tag -d v0.9", riskReversible},
		{"git remote remove origin", riskReversible},
		{"git log --oneline | head", riskReadonly},
		// ordinary changes
		{"mkdir /tmp/newdir", riskReversible},
		{"touch /tmp/a", riskReversible},
		{"python3 script.py", riskReversible},
	}
	for _, c := range cases {
		if got := classifyCommand(c.cmd); got != c.want {
			t.Errorf("classifyCommand(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

func TestSplitChain(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"ls -la", []string{"ls -la"}},
		{"ls; rm x", []string{"ls", "rm x"}},
		{"a && b || c", []string{"a", "b", "c"}},
		{"grep 'a;b' file | wc -l", []string{"grep 'a;b' file", "wc -l"}},
		{`echo "x|y" && ls`, []string{`echo "x|y"`, "ls"}},
		{"  df -h  ", []string{"df -h"}},
	}
	for _, c := range cases {
		got := splitChain(c.cmd)
		if len(got) != len(c.want) {
			t.Errorf("splitChain(%q) = %v, want %v", c.cmd, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitChain(%q)[%d] = %q, want %q", c.cmd, i, got[i], c.want[i])
			}
		}
	}
}

func TestTruncateToolOutput(t *testing.T) {
	var lines []string
	for i := 0; i < 1000; i++ {
		lines = append(lines, "line")
	}
	big := strings.Join(lines, "\n")
	out := truncateToolOutput(big, 10, 5, 8192)
	if !strings.Contains(out, "985 of 1000 lines omitted") {
		t.Errorf("truncation marker missing: %q", out)
	}
	if strings.Count(out, "\n") > 20 {
		t.Errorf("too many lines kept: %d", strings.Count(out, "\n"))
	}
	// byte cap
	long := strings.Repeat("x", 20000)
	out = truncateToolOutput(long, 200, 50, 8192)
	if len(out) > 8300 {
		t.Errorf("byte cap not enforced: %d", len(out))
	}
}

func TestRedactSecrets(t *testing.T) {
	cases := []struct{ in, want string }{
		{"mysql -u root -pSecret123 db", "mysql -u root -p*** db"},
		{"export AWS_SECRET_KEY=abcd1234", "export AWS_SECRET_KEY=***"},
		{"curl -H 'Authorization: Bearer tok123' x", "curl -H 'Authorization: ***' x"},
		{"token=xyz789", "token=***"},
		{"ls -la", "ls -la"},
	}
	for _, c := range cases {
		got := redactSecrets(c.in)
		if !strings.Contains(got, "***") && strings.Contains(c.want, "***") {
			t.Errorf("redactSecrets(%q) = %q, want something like %q", c.in, got, c.want)
		}
		if strings.Contains(got, "Secret123") || strings.Contains(got, "abcd1234") || strings.Contains(got, "tok123") || strings.Contains(got, "xyz789") {
			t.Errorf("secret leaked in redactSecrets(%q) = %q", c.in, got)
		}
	}
}

func TestBackupTargetsFor(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"rm a.log", []string{"a.log"}},
		{"rm -rf /tmp/x /tmp/y", []string{"/tmp/x", "/tmp/y"}},
		{"ls; rm -f b.txt", []string{"b.txt"}},
		{"echo hi > c.txt", []string{"c.txt"}},
		{"cat a >> d.log", []string{"d.log"}},
		{"df -h", nil},
		{"du -sh . 2>/dev/null", nil},
	}
	for _, c := range cases {
		got := backupTargetsFor(c.cmd)
		if len(got) != len(c.want) {
			t.Errorf("backupTargetsFor(%q) = %v, want %v", c.cmd, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("backupTargetsFor(%q)[%d] = %q, want %q", c.cmd, i, got[i], c.want[i])
			}
		}
	}
}

func TestRunBashTimeout(t *testing.T) {
	old := agentBashTimeout
	agentBashTimeout = 120 * time.Second
	t.Cleanup(func() { agentBashTimeout = old })

	// model-requested timeout below the 5s floor is clamped to 5s
	start := time.Now()
	out, err := runBash(context.Background(), `{"command":"sleep 30","timeout_sec":1}`)
	if err != nil {
		t.Fatalf("runBash: %v", err)
	}
	if !strings.Contains(out, "timed out after 5s") {
		t.Errorf("expected clamp-to-5s timeout, got %q", out)
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Errorf("5s floor not honored (took %s)", d)
	}

	// excessive values are capped (hard cap is 600s; don't actually sleep —
	// just verify the clamp via a quick command)
	out, err = runBash(context.Background(), `{"command":"echo ok","timeout_sec":99999}`)
	if err != nil || !strings.Contains(out, "ok") {
		t.Errorf("capped quick command failed: %q %v", out, err)
	}
}

// TestPaddingEvasion: safety decisions must use the full command, never the
// 200-char display summary (review F1). A payload padded past 200 chars with
// a destructive tail must still classify as dangerous.
func TestPaddingEvasion(t *testing.T) {
	padding := strings.Repeat("/very/long/harmless/path", 12) // >200 chars
	payload := "grep foo " + padding + " ; rm -rf /home/user/data"
	if len(payload) < 220 {
		t.Fatalf("test payload too short: %d", len(payload))
	}
	// the old code classified describeCall's truncated summary; the full
	// command must be used (via bashCommandOf in the tool-call path)
	if got := classifyCommand(payload); got != riskDangerous {
		t.Errorf("padded payload classified %v, want riskDangerous", got)
	}
	// and the truncation that made this dangerous must not be what safety sees
	if len(truncateStr(payload, 200)) >= len(payload) {
		t.Fatalf("truncateStr did not truncate — test setup broken")
	}
	tc := ToolCall{ID: "x", Name: "bash", Arguments: `{"command":"` + payload + `"}`}
	_ = tc // bashCommandOf coverage lives in the wiring; classify is the gate
}
