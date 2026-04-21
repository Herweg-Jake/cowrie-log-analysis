# Annotation Codebook

Reference for human annotators grading Cowrie honeypot sessions against the
MITRE ATT&CK framework. One page for the scheme, one page for the ambiguous
cases. Read both before starting.

## What You're Doing

You will look at raw session data — commands run, downloads attempted, auth
log, timing — and record your judgment of:

1. **Primary MITRE tactic** (one of the enum values below, or "No Action" / "Unknown")
2. **Threat level** (1=High, 2=Medium, 3=Low)
3. **Your confidence** (1=guessing, 5=certain)
4. **False-negative risk** (checkbox: would missing this session be dangerous?)
5. **Free-form notes** (especially for ambiguous cases — explain your reasoning)

You will NOT see either pipeline's labels. This is intentional. The goal is
independent ground truth.

## The "Primary Tactic" Rule

If a session spans multiple tactics (recon → download → execute), pick the
**most advanced/severe** tactic in the kill chain. A session that does
Discovery → C2 → Execution gets labeled **Execution** as primary.

Rough ordering from least to most severe:

> No Action / Unknown → Initial Access → Discovery → Credential Access →
> Command and Control → Execution → Persistence → Privilege Escalation →
> Lateral Movement → Collection → Exfiltration → Impact / Resource Hijacking

## Tactic Definitions (honeypot-specific)

| Tactic | What it looks like in Cowrie | Typical commands |
|---|---|---|
| **Initial Access** | Authenticated successfully but took no further action. The "attack" was just getting in. | (session_type = `success_no_commands`) |
| **Discovery** | Commands to learn about the system. Did NOT act beyond looking. | `uname`, `cat /etc/passwd`, `cat /proc/cpuinfo`, `ls`, `ifconfig`, `whoami`, `id`, `lscpu`, `free`, `df` |
| **Credential Access** | Tried to read credential stores, SSH keys, shadow file. | `cat /etc/shadow`, `cat ~/.ssh/*`, `grep password` |
| **Command and Control** | Downloaded tools/payloads from external infrastructure. | `wget http://...`, `curl -O ...`, `tftp -g ...`, `ftpget ...` |
| **Execution** | Ran downloaded payloads or commands meant to *do* something. Distinguished from Discovery by *intent to act*. | `./malware`, `sh script.sh`, `python -c ...`, `chmod +x x && ./x`, `perl -e ...` |
| **Persistence** | Modified system to maintain access. | `crontab -e`, `echo ... >> ~/.ssh/authorized_keys`, `adduser`, `/etc/rc.local`, systemd unit writes |
| **Privilege Escalation** | Attempted to elevate privileges. | `sudo -i`, `su -`, SUID exploitation, known-CVE kernel exploits |
| **Defense Evasion** | Cleared logs, disabled services, hid files. | `history -c`, `rm ~/.bash_history`, `iptables -F`, `kill` security daemons, `chattr` |
| **Collection** | Gathered data before exfil. | `tar czf ...`, reading browser/app data |
| **Exfiltration** | Moved data out. | `scp`, `curl -T`, `nc` uploads |
| **Lateral Movement** | Pivoted to other hosts. | `ssh other.host`, `rsync user@other:` |
| **Impact** | Destructive actions. | `rm -rf /`, mass `kill`, `reboot`, `dd if=/dev/zero of=/dev/...`, disk wiping |
| **Resource Hijacking** | Cryptomining or resource abuse. | xmrig, minerd, any miner config, stratum+tcp URLs |
| **No Action** | Auth failed or session otherwise did nothing observable (no commands, no downloads). | (session_type = `failed_auth_only`) |
| **Unknown** | You genuinely cannot tell. Use sparingly — if you're leaning toward a tactic but unsure, pick it and mark confidence=1 or 2 instead. | — |

## Threat Level Definitions

| Level | Name | Definition | Examples |
|---|---|---|---|
| **1** | High | Could damage the system or achieve attacker objectives. | Execution of payloads, Impact, C2 with successful payload delivery, Resource Hijacking |
| **2** | Medium | Establishes persistence or escalates privileges without immediate damage. | Persistence, Privilege Escalation, Credential Access, successful lateral recon |
| **3** | Low | Reconnaissance only, or no meaningful action taken. | Discovery, Initial Access with no follow-up, No Action, failed auth |

A level-1 session isn't automatically tactic=Impact; level is about *severity*,
tactic is about *what kind of activity*. A session that downloads malware AND
executes it is Execution + level 1. A session that only runs `uname -a` is
Discovery + level 3.

## Ambiguity Cheatsheet

**"They downloaded something but never executed it"** → Command and Control,
level 2. The download itself is the action; execution intent is present but
unfulfilled.

**"They tried to download but the download failed"** (wget returned an error) →
Still Command and Control, level 3. Intent matters; outcome doesn't let the
attacker off the hook for grading.

**"They ran a shell script that only does `uname -a` and `cat /etc/passwd`"**
→ Discovery, level 3. Don't count "ran a script" as Execution unless the
script does something beyond discovery.

**"Auth succeeded but they typed only garbage / nonsense / nothing"** →
Initial Access, level 3. They got in, that's it.

**"Session has 200 commands but they're all obvious bot pattern"** (the same
`enable\nshell\nsh\n...` setup every bot does) → Grade by what the bot
*actually did* afterward. The boilerplate doesn't upgrade the tactic.

**"They ran `sudo su` and it failed"** → Credential Access, level 2. The
attempt itself establishes the tactic.

**"Everything they did is already a built-in Cowrie fake response"** →
Doesn't matter — grade as if the commands had succeeded. We're grading
*intent*, not whether Cowrie fooled them.

**"They ran a miner binary"** → Resource Hijacking, level 1. Don't mistake
this for generic Execution.

**"Session looks completely empty but auth_success=true"** → Initial Access,
level 3. See the `success_no_commands` category.

## The False-Negative Flag

Check `is_false_negative_risk = true` when this session represents real
attacker activity that a security team should **not** miss. Rough heuristic:

- **Check it** for: any level-1 session, any Persistence/Impact/C2 session,
  novel-looking commands, signs of targeting (non-generic credentials,
  custom payloads), anything that made you go "huh, that's unusual."
- **Leave it unchecked** for: routine Discovery-only sessions, failed-auth
  brute-force attempts, generic IoT-botnet patterns that occur at massive
  volume.

This flag feeds into a separate "did the pipeline miss anything dangerous?"
metric. It's orthogonal to the level — a level-2 persistence attempt can
still be high false-negative risk.

## Confidence Scale

| Value | Meaning |
|---|---|
| 5 | Certain. The commands clearly match one tactic; no ambiguity. |
| 4 | Confident. One interpretation is clearly more likely than alternatives. |
| 3 | Reasonable guess. Multiple interpretations plausible; I picked the best one. |
| 2 | Weak guess. Could easily be wrong; data is thin. |
| 1 | Effectively guessing. Logged commands are too sparse or ambiguous. |

If you find yourself recording 1s and 2s a lot, that's a useful signal — note
it in the free-form field. It may indicate either codebook gaps or genuinely
hard sessions.

## Annotation Output Format

One JSON record per session:

```json
{
  "annotation_id": 42,
  "annotator": "jake",
  "primary_tactic": "Command and Control",
  "threat_level": 2,
  "confidence": 4,
  "is_false_negative_risk": true,
  "notes": "Downloaded a .sh from an IP we've seen before. No execution in-session."
}
```

Save all annotations to `annotation_results.jsonl` (one JSON per line). If
multiple annotators, each writes their own `annotation_results_<name>.jsonl`
and `compute_ground_truth_metrics.py` will merge them.

## Inter-Annotator Calibration

If two or more annotators are working on this, do the first 50 sessions
together (sitting at one screen), then split up for the rest. Around
session 150, pick 50 sessions you've both done independently and compute
Cohen's kappa. If kappa < 0.6, stop, discuss the disagreements, refine this
codebook, and re-annotate those 50.

## Quick Tactic Picker (decision tree)

1. Did auth fail? → **No Action**, level 3.
2. Auth succeeded, no commands? → **Initial Access**, level 3.
3. Did they run any destructive command (rm -rf, dd, wipe)? → **Impact**, level 1.
4. Is there a miner binary / stratum URL? → **Resource Hijacking**, level 1.
5. Did they execute a downloaded payload (./x, sh x.sh, python -c on a non-recon script)? → **Execution**, level 1.
6. Did they modify crontab, authorized_keys, rc.local, or add a user? → **Persistence**, level 2.
7. Did they attempt `sudo`, `su`, read shadow, or use a kernel exploit? → **Privilege Escalation** or **Credential Access**, level 2.
8. Did they download from an external server (wget/curl/tftp)? → **Command and Control**, level 2.
9. Did they only run discovery commands (uname, cat /etc/passwd, ls, id)? → **Discovery**, level 3.
10. None of the above, but something is there? → **Unknown**, confidence=1-2, notes required.
