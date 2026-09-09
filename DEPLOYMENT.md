# Deployment patterns

frza is a single static binary, so "deployment" is mostly about *where* it runs
and what it can reach — the LLM API on one side, your evidence (logs, dumps,
pcaps) on the other. Two patterns cover most real environments.

## Pattern A — in-place, on the affected machine

Run `frza --agent` directly on the machine being troubleshooted.

**Prerequisite**: the machine must reach your LLM API endpoint. Many production
networks can't; check first (`curl -sS <base_url>/models -H "Authorization:
Bearer $KEY"` or just try a one-line chat).

When it fits, the safety model is built for exactly this:

- read-only diagnostics (`df`, `ps`, `ss`, `dmesg`, `journalctl`, `crash`
  analysis) run automatically — zero friction during an incident
- anything that changes the system asks first; destructive commands warn and
  back up first
- the session journal (`~/.frza/journal/`) doubles as the incident timeline:
  what was inspected, what was run, what was declined — useful raw material
  for the postmortem

Keep heavy analysis (full vmcore walks, GB-scale log preprocessing) off
production machines — that's Pattern B's job.

## Pattern B — dedicated analysis workstation ⭐ (recommended default)

Copy the evidence *out* of production to a fixed Linux box that has frza, the
tool dependencies, and your skill library installed once:

```
production hosts                     analysis workstation
┌──────────────┐   scp / rsync /    ┌──────────────────────────────┐
│ vmcore       │   shared storage   │ frza --agent                 │
│ log bundles  │ ─────────────────► │ + crash & kernel debuginfo   │
│ perf.data    │                    │ + python3, sysstat, tshark   │
│ pcaps        │                    │ + your full skill library    │
└──────────────┘                    └──────────────┬───────────────┘
                                                   │ LLM API
                                                   ▼
```

Why this is the better default:

1. **Network reality**: the workstation sits where the API is reachable;
   evidence flows one way (out of production), commands never flow in.
2. **Dependencies installed once**: every skill's preflight check is green by
   construction.
3. **Load isolation**: crash walks and log preprocessing don't touch
   production CPU/IO.
4. **Team sharing**: one box, one skill library, everyone troubleshoots the
   same way. Distributing "workstation + frza" to a team is copying one
   binary plus `~/.frza/skills/`.

### Workstation dependency checklist

Debian/Ubuntu:

```bash
sudo apt install -y crash linux-crashdump python3 sysstat gdb lsof \
                    strace tcpdump tshark jq unzip
# kernel debuginfo for crash: distro-specific, see
# https://documentation.ubuntu.com/ubuntu-server-how-to/debugging/debuginfod/
```

RHEL/CentOS/Rocky:

```bash
sudo dnf install -y crash kernel-debuginfo python3 sysstat gdb lsof \
                    strace tcpdump wireshark-cli jq unzip
```

Optional, per your skills: `kubectl`, `perf`, `pcp`, `nvme-cli`, `smartmontools`.

## Analyzing Windows dumps from a Linux workstation

Windows `memory.dmp` / minidump analysis requires WinDbg (`cdb.exe`), which
only exists on Windows. The proven pattern is a small Windows analysis box
(VM is fine) with WinDbg and OpenSSH server installed, and let frza drive it
over SSH:

```
frza (Linux) --ssh-->  windows-dump-box: cdb -z memory.dmp -c "!analyze -v; q"
```

- The `windows-dump-analyzer` skill is written for exactly this flow; point it
  at your host via an environment variable, e.g. `export FRZA_WINDBG_HOST=windbg@10.x.y.z`
- SSH commands are not in the read-only whitelist (frza cannot back up what
  happens on a remote machine), so the agent will ask for confirmation —
  answer `a` once per session to approve the channel, the journal still
  records every remote command
- Verify the channel non-interactively first:
  `ssh -o BatchMode=yes $FRZA_WINDBG_HOST "cdb -version"`

The analysis itself is read-only (cdb reads the dump file), which is the
comfort zone of the safety model.

## On-call runbook (incident-time usage)

1. `frza --agent` on the workstation (Pattern B) or the host (Pattern A)
2. State symptoms in plain words; name a skill if you know it
   ("用 k8s-analyzer 分析这个日志")
3. Let read-only investigation run; review confirmation prompts carefully —
   during an incident, prefer declining and asking for the read-only
   alternative
4. `/journal` anytime for the action timeline; `/undo` if the agent changed a
   file it shouldn't have
5. After mitigation: `/export` the session to Markdown as postmortem material;
   journal + session together are the evidence trail

## Network & data checklist

| Requirement | Pattern A | Pattern B |
|---|---|---|
| Host can reach LLM API | required | only workstation needs it |
| Evidence leaves production | no | yes (scp/share) |
| Tool deps on the spot | per host | once, centrally |
| Heavy analysis off prod | no | yes |
| Team-shared skill library | no | yes |
