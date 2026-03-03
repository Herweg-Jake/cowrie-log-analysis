"""
MITRE ATT&CK-based session labeling.

This module labels sessions with:
  1. Threat level (1=high, 2=medium, 3=low) based on command severity
  2. Primary MITRE tactic (the most severe one detected)
  3. All tactics detected in the session

The labeling is rule-based for now (matching command patterns to tactics).
Later, we can train ML models to do this more accurately, but rules give
us a starting point and ground truth for that training.

The three levels from the paper:
  - Level 1 (High): Actions that could damage the system - execution of
    malicious files, killing processes, deleting files, downloading malware
  - Level 2 (Medium): Persistence and privilege escalation - changing
    permissions, adding users, modifying crontab
  - Level 3 (Low): Reconnaissance and discovery - uname, cat /etc/passwd,
    checking system resources

v2 upgrades (making algo path competitive with agent):
  - Kill chain detection: boost severity when recon -> persist -> impact combo detected
  - Base64 decoding: attackers love to hide commands in base64, decode before scanning
  - Behavioral tagging: machine-gun script vs slow human typing
  - Unknown tiers: not all unknowns are equal, split by complexity

Reference: MITRE ATT&CK Enterprise Tactics
https://attack.mitre.org/tactics/enterprise/
"""

import base64
import re
from dataclasses import dataclass, field
from typing import Any
from ..aggregators.session_aggregator import Session


@dataclass
class SessionLabel:
    """
    Labels assigned to a session.

    Contains threat level, tactics, and behavioral tags.
    """
    level: int  # 1=high/critical, 2=medium, 3=low
    primary_tactic: str  # most severe tactic detected
    all_tactics: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)  # for debugging

    # v2: behavioral tagging
    behavior_tag: str = "UNKNOWN_SPEED"  # MACHINE_SPEED, HUMAN_SPEED, or UNKNOWN_SPEED
    kill_chain_detected: bool = False  # true if multi-stage attack pattern found
    obfuscation_detected: bool = False  # true if we decoded base64/hex

    # v3: additional fields for pipeline comparison and Kibana filtering
    sophistication_score: int = 1  # 1-5 score based on observable complexity
    tactic_count: int = 0  # number of distinct MITRE tactics observed
    has_download: bool = False  # promoted from features.F46_has_files
    has_upload: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "primary_tactic": self.primary_tactic,
            "all_tactics": self.all_tactics,
            "matched_patterns": self.matched_patterns[:20],  # cap for storage
            "behavior_tag": self.behavior_tag,
            "kill_chain_detected": self.kill_chain_detected,
            "obfuscation_detected": self.obfuscation_detected,
            "sophistication_score": self.sophistication_score,
            "tactic_count": self.tactic_count,
            "has_download": self.has_download,
            "has_upload": self.has_upload,
        }


# Pattern definitions for each tactic
# Each tactic has a list of (pattern_name, regex) tuples
# Order matters within levels - earlier tactics are considered "more severe"

LEVEL_1_PATTERNS = {
    # These are the most dangerous - could cause real damage
    
    "Impact": [
        ("rm_rf", re.compile(r'\brm\s+(-[rf]+\s+)*/', re.IGNORECASE)),
        ("rm_star", re.compile(r'\brm\s+(-[rf]+\s+)*\*', re.IGNORECASE)),
        ("kill_process", re.compile(r'\bkill\s+-9\s+', re.IGNORECASE)),
        ("dd_if", re.compile(r'\bdd\s+if=', re.IGNORECASE)),
        ("mkfs", re.compile(r'\bmkfs\b', re.IGNORECASE)),
        ("shutdown", re.compile(r'\b(shutdown|reboot|halt|poweroff)\b', re.IGNORECASE)),
        ("init_0_6", re.compile(r'\binit\s+[06]\b', re.IGNORECASE)),
    ],
    
    "Execution": [
        ("direct_execute", re.compile(r'\./\S+', re.IGNORECASE)),
        ("bash_c", re.compile(r'\bbash\s+-c\s', re.IGNORECASE)),
        ("sh_c", re.compile(r'\bsh\s+-c\s', re.IGNORECASE)),
        ("perl_e", re.compile(r'\bperl\s+-e\s', re.IGNORECASE)),
        ("python_c", re.compile(r'\bpython[23]?\s+-c\s', re.IGNORECASE)),
        ("source_script", re.compile(r'\bsource\s+\S+|^\.\s+\S+', re.IGNORECASE)),
        ("nohup", re.compile(r'\bnohup\s+', re.IGNORECASE)),
        ("eval", re.compile(r'\beval\s+', re.IGNORECASE)),
        ("dropper", re.compile(r'chmod.*&&.*\./', re.IGNORECASE)),
    ],
    
    "Command and Control": [
        ("wget_execute", re.compile(r'\bwget\s+.*\|\s*(ba)?sh', re.IGNORECASE)),
        ("curl_execute", re.compile(r'\bcurl\s+.*\|\s*(ba)?sh', re.IGNORECASE)),
        ("nc_shell", re.compile(r'\b(nc|netcat|ncat)\s+.*-e\s', re.IGNORECASE)),
        ("bash_revshell", re.compile(r'/dev/tcp/', re.IGNORECASE)),
        ("python_revshell", re.compile(r'socket.*connect.*dup2', re.IGNORECASE)),
        ("perl_revshell", re.compile(r'perl.*socket.*connect', re.IGNORECASE)),
        ("tftp_get", re.compile(r'\btftp\s+', re.IGNORECASE)),
        ("wget_o", re.compile(r'\bwget\s+.*-O\s', re.IGNORECASE)),
        ("curl_o", re.compile(r'\bcurl\s+.*-o\s', re.IGNORECASE)),
        ("base64_decode", re.compile(r'\bbase64\s+(-d|--decode)', re.IGNORECASE)),
    ],

    "Resource Hijacking": [
        ("xmrig", re.compile(r'\bxmrig\b', re.IGNORECASE)),
        ("stratum_proto", re.compile(r'stratum\+tcp://', re.IGNORECASE)),
        ("minerd", re.compile(r'\bminerd\b', re.IGNORECASE)),
        ("cpuminer", re.compile(r'\bcpuminer\b', re.IGNORECASE)),
        ("donate_level", re.compile(r'--donate-level', re.IGNORECASE)),
        ("nicehash", re.compile(r'\bnicehash\b', re.IGNORECASE)),
        ("cryptonight", re.compile(r'\bcryptonight\b', re.IGNORECASE)),
    ],
    
    "Defense Evasion": [
        ("history_clear", re.compile(r'\bhistory\s+-[cdw]', re.IGNORECASE)),
        ("unset_hist", re.compile(r'\bunset\s+HIST', re.IGNORECASE)),
        ("histsize_0", re.compile(r'HISTSIZE=0|HISTFILESIZE=0', re.IGNORECASE)),
        ("rm_logs", re.compile(r'\brm\s+.*(/var/log/|\.bash_history|\.history)', re.IGNORECASE)),
        ("truncate_logs", re.compile(r'>\s*/var/log/|echo\s*>\s*/var/log/', re.IGNORECASE)),
        ("dev_null_redirect", re.compile(r'2>/dev/null.*&>/dev/null', re.IGNORECASE)),
        ("systemctl_stop", re.compile(r'\bsystemctl\s+stop\b', re.IGNORECASE)),
        ("service_stop", re.compile(r'\bservice\s+\S+\s+stop\b', re.IGNORECASE)),
        ("ufw_disable", re.compile(r'\bufw\s+disable\b', re.IGNORECASE)),
        ("selinux_disable", re.compile(r'\bsetenforce\s+0\b', re.IGNORECASE)),
        ("iptables_flush", re.compile(r'\biptables\s+-F\b', re.IGNORECASE)),
    ],
}

LEVEL_2_PATTERNS = {
    # Medium severity - establishing persistence, escalating privileges
    
    "Persistence": [
        ("crontab_edit", re.compile(r'\bcrontab\s+-[el]', re.IGNORECASE)),
        ("etc_cron", re.compile(r'/etc/cron', re.IGNORECASE)),
        ("rc_local", re.compile(r'/etc/rc\.local', re.IGNORECASE)),
        ("init_d", re.compile(r'/etc/init\.d/', re.IGNORECASE)),
        ("systemd_enable", re.compile(r'\bsystemctl\s+enable', re.IGNORECASE)),
        ("bashrc_edit", re.compile(r'>>?\s*~?/?(\.bashrc|\.bash_profile|\.profile)', re.IGNORECASE)),
        ("authorized_keys", re.compile(r'authorized_keys', re.IGNORECASE)),
    ],
    
    "Privilege Escalation": [
        ("sudo_command", re.compile(r'\bsudo\s+', re.IGNORECASE)),
        ("su_command", re.compile(r'\bsu\s+-?\s*$|\bsu\s+-?\s+\w+', re.IGNORECASE)),
        ("chmod_x", re.compile(r'\bchmod\s+\+?[0-7]*x|\bchmod\s+7', re.IGNORECASE)),
        ("chmod_777", re.compile(r'\bchmod\s+777', re.IGNORECASE)),
        ("chown", re.compile(r'\bchown\s+', re.IGNORECASE)),
        ("setuid", re.compile(r'\bchmod\s+[24]', re.IGNORECASE)),  # setuid/setgid bits
    ],
    
    "Credential Access": [
        ("etc_shadow", re.compile(r'/etc/shadow', re.IGNORECASE)),
        ("etc_passwd_write", re.compile(r'>>\s*/etc/passwd', re.IGNORECASE)),
        ("passwd_command", re.compile(r'\bpasswd\s+\w+', re.IGNORECASE)),
        ("useradd", re.compile(r'\buseradd\b', re.IGNORECASE)),
        ("adduser", re.compile(r'\badduser\b', re.IGNORECASE)),
        ("usermod", re.compile(r'\busermod\b', re.IGNORECASE)),
    ],
}

LEVEL_3_PATTERNS = {
    # Low severity - reconnaissance, information gathering
    
    "Discovery": [
        ("uname", re.compile(r'\buname\b', re.IGNORECASE)),
        ("cat_etc_passwd", re.compile(r'\bcat\s+/etc/passwd', re.IGNORECASE)),
        ("cat_etc", re.compile(r'\bcat\s+/etc/', re.IGNORECASE)),
        ("whoami", re.compile(r'\bwhoami\b', re.IGNORECASE)),
        ("id_command", re.compile(r'\bid\b', re.IGNORECASE)),
        ("hostname", re.compile(r'\bhostname\b', re.IGNORECASE)),
        ("ifconfig", re.compile(r'\bifconfig\b', re.IGNORECASE)),
        ("ip_addr", re.compile(r'\bip\s+(addr|a)\b', re.IGNORECASE)),
        ("netstat", re.compile(r'\bnetstat\b', re.IGNORECASE)),
        ("ss_command", re.compile(r'\bss\s+-', re.IGNORECASE)),
        ("ps_aux", re.compile(r'\bps\s+(aux|ef)', re.IGNORECASE)),
        ("w_command", re.compile(r'(?:^|\s|;)w(?:\s|$|;)', re.IGNORECASE)),
        ("who_command", re.compile(r'\bwho\b', re.IGNORECASE)),
        ("last_command", re.compile(r'\blast\b', re.IGNORECASE)),
        ("df_command", re.compile(r'\bdf\b', re.IGNORECASE)),
        ("free_command", re.compile(r'\bfree\b', re.IGNORECASE)),
        ("lscpu", re.compile(r'\blscpu\b', re.IGNORECASE)),
        ("nproc", re.compile(r'\bnproc\b', re.IGNORECASE)),
        ("uptime", re.compile(r'\buptime\b', re.IGNORECASE)),
        ("ls_la", re.compile(r'\bls\s+-la', re.IGNORECASE)),
        ("find_command", re.compile(r'\bfind\s+/', re.IGNORECASE)),
        ("env_command", re.compile(r'\benv\b|\bprintenv\b', re.IGNORECASE)),
        ("dmesg", re.compile(r'\bdmesg\b', re.IGNORECASE)),
        ("cat_cpuinfo", re.compile(r'\bcat\s+/proc/cpuinfo', re.IGNORECASE)),
        ("dmidecode", re.compile(r'\bdmidecode\b', re.IGNORECASE)),
        ("virt_detect", re.compile(r'\b(virt-what|systemd-detect-virt)\b', re.IGNORECASE)),
        ("docker_check", re.compile(r'\.dockerenv|/proc/1/cgroup', re.IGNORECASE)),
    ],
}


class MitreLabeler:
    """
    Labels sessions with MITRE ATT&CK tactics and threat levels.

    v2: now includes stateful analysis (kill chains), base64 decoding,
    and behavioral tagging. Not just dumb regex anymore.

    Usage:
        labeler = MitreLabeler()
        label = labeler.label(session)
        print(f"Level: {label.level}, Tactic: {label.primary_tactic}")
    """

    # Patterns for explicit obfuscation contexts (not just raw base64-ish strings)
    # We look for actual decode pipelines, not random 8-char substrings
    _BASE64_DECODE_PIPE = re.compile(
        r'(?:echo\s+["\']?[A-Za-z0-9+/=]+["\']?\s*\|.*\bbase64\s+(?:-d|--decode))'
        r'|(?:\bbase64\s+(?:-d|--decode)\s+<<<)',
        re.IGNORECASE,
    )
    _HEX_ESCAPE_PIPE = re.compile(
        r"echo\s+-[ne]+\s+['\"].*\\x[0-9a-fA-F]{2}.*['\"].*\|\s*(ba)?sh",
        re.IGNORECASE,
    )
    # Standalone base64 -d (already caught in L1 patterns but useful for the
    # obfuscation flag independently)
    _BASE64_DECODE_CMD = re.compile(r'\bbase64\s+(-d|--decode)', re.IGNORECASE)
    _HEX_ESCAPE_PATTERN = re.compile(r'\\x[0-9a-fA-F]{2}', re.IGNORECASE)

    def __init__(self):
        # compile all patterns once at init
        # structure: [(level, tactic, pattern_name, compiled_regex), ...]
        self._patterns = []

        for level, pattern_dict in [
            (1, LEVEL_1_PATTERNS),
            (2, LEVEL_2_PATTERNS),
            (3, LEVEL_3_PATTERNS),
        ]:
            for tactic, patterns in pattern_dict.items():
                for pattern_name, regex in patterns:
                    self._patterns.append((level, tactic, pattern_name, regex))

    def _try_decode_base64(self, s: str) -> str | None:
        """
        Attempt to decode a string as base64.
        Returns decoded string if it looks like valid ascii text, None otherwise.
        """
        try:
            decoded = base64.b64decode(s).decode('utf-8', errors='strict')
            # sanity check: should be mostly printable ascii
            # if it's binary garbage, skip it
            printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
            if printable_ratio > 0.8:
                return decoded
        except Exception:
            pass
        return None

    def _normalize_commands(self, commands: list[str]) -> tuple[list[str], bool]:
        """
        Pre-process commands to decode obfuscated payloads.
        Returns (normalized_commands, found_obfuscation).

        Instead of scanning every 8-char substring as potential base64 (too noisy),
        we only decode when there's an explicit decode context:
        - echo XXX | base64 -d
        - echo -e '\\xNN...' | sh
        - base64 -d <<< XXX
        - hex escape sequences (\\x patterns)
        """
        normalized = list(commands)  # start with originals
        found_obfuscation = False

        for cmd in commands:
            # check for base64 decode pipelines
            if self._BASE64_DECODE_PIPE.search(cmd):
                found_obfuscation = True
                # try to extract and decode the base64 blob
                b64_blob = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')
                for match in b64_blob.finditer(cmd):
                    decoded = self._try_decode_base64(match.group())
                    if decoded and decoded not in normalized:
                        normalized.append(decoded)

            # check for standalone base64 -d (might be in a pipe from a file)
            elif self._BASE64_DECODE_CMD.search(cmd):
                found_obfuscation = True

            # check for hex escape sequences piped to sh/bash
            if self._HEX_ESCAPE_PIPE.search(cmd):
                found_obfuscation = True

            # hex escapes in echo commands are suspicious even without a pipe
            if self._HEX_ESCAPE_PATTERN.search(cmd):
                # only flag if there are multiple hex escapes (not just one stray \x00)
                hex_count = len(self._HEX_ESCAPE_PATTERN.findall(cmd))
                if hex_count >= 3:
                    found_obfuscation = True

        return normalized, found_obfuscation

    def _detect_kill_chain(self, tactics: set[str]) -> bool:
        """
        Check for multi-stage attack patterns (kill chain).

        If an attacker does recon, then persists, then executes or impacts...
        that's a complete attack chain and worse than any single tactic.
        """
        # these combos indicate a real attack, not just drive-by noise
        dangerous_combos = [
            # classic: scout the system, drop persistence, run payload
            {"Discovery", "Persistence", "Execution"},
            {"Discovery", "Persistence", "Impact"},
            # recon + immediate impact (aggressive attacker)
            {"Discovery", "Execution", "Impact"},
            # privesc chain: recon, escalate, persist
            {"Discovery", "Privilege Escalation", "Persistence"},
            # C2 + execution (download + execute is the most common bot pattern)
            {"Command and Control", "Execution"},
            {"Command and Control", "Impact"},
            # credential theft + persistence: steal creds, add own keys
            {"Credential Access", "Persistence"},
            # cryptomining chains
            {"Command and Control", "Resource Hijacking"},
            {"Execution", "Resource Hijacking"},
        ]

        for combo in dangerous_combos:
            if combo.issubset(tactics):
                return True
        return False

    def _get_min_inter_command_gap(self, session: Session) -> float | None:
        """
        Get the minimum time gap between any two consecutive commands.

        A gap under 0.05s almost certainly means pasted/scripted input.
        Returns None if there aren't enough commands with timestamps.
        """
        timestamps = []
        for cmd in session.commands:
            ts = cmd.get("timestamp")
            if ts is not None:
                timestamps.append(ts)

        if len(timestamps) < 2:
            return None

        timestamps.sort()
        min_gap = float('inf')
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
            if delta < min_gap:
                min_gap = delta

        return min_gap

    def _get_behavior_tag(self, session: Session, cmd_count: int) -> str:
        """
        Tag session as machine or human based on command timing.

        Uses two signals:
        1. Overall command rate (cmds/sec)
        2. Minimum inter-command gap (catches pasted command blocks)

        Bots paste commands faster than any human can type.
        """
        duration = session.get_computed_duration()

        if duration <= 0 or cmd_count == 0:
            return "UNKNOWN_SPEED"

        # check for pasted commands first - if any two commands arrived
        # within 0.05s of each other, that's definitely not a human
        min_gap = self._get_min_inter_command_gap(session)
        if min_gap is not None and min_gap < 0.05:
            return "MACHINE_SPEED"

        cmds_per_sec = cmd_count / duration

        # lowered from 5.0 — in honeypots, Cowrie's execution simulation
        # slows down even automated sessions, so 2 cmd/sec is plenty fast
        if cmds_per_sec > 2.0:
            return "MACHINE_SPEED"
        elif cmds_per_sec < 0.3:
            return "HUMAN_SPEED"
        else:
            return "UNKNOWN_SPEED"

    # common Linux commands for fuzzy matching against unknown inputs
    # if someone types "unme" instead of "uname" we want to recognize that
    _COMMON_LINUX_CMDS = {
        "ls", "cd", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "touch",
        "echo", "grep", "find", "sort", "head", "tail", "less", "more",
        "chmod", "chown", "chgrp", "sudo", "su", "passwd", "whoami",
        "uname", "hostname", "ifconfig", "ping", "curl", "wget", "ssh",
        "scp", "tar", "gzip", "gunzip", "zip", "unzip", "ps", "kill",
        "top", "htop", "df", "du", "free", "mount", "umount", "fdisk",
        "apt", "yum", "dnf", "pip", "npm", "git", "docker", "systemctl",
        "service", "crontab", "iptables", "netstat", "ss", "nmap",
        "vi", "vim", "nano", "sed", "awk", "python", "perl", "bash",
        "export", "source", "alias", "history", "man", "which", "locate",
    }

    def _looks_like_typo(self, cmd: str) -> bool:
        """
        Check if an unknown command looks like a typo of a known binary.

        Uses simple edit distance — if it's within 2 chars of a common
        command, it's probably a typo rather than something novel.
        """
        # grab the first word (the binary name)
        first_word = cmd.split()[0].strip("./") if cmd.strip() else ""
        if not first_word or len(first_word) > 20:
            return False

        first_lower = first_word.lower()

        # exact match means it's known, not a typo
        if first_lower in self._COMMON_LINUX_CMDS:
            return False

        # simple edit distance check (max distance 2)
        for known in self._COMMON_LINUX_CMDS:
            if abs(len(first_lower) - len(known)) > 2:
                continue
            dist = self._edit_distance(first_lower, known)
            if dist <= 2:
                return True

        return False

    @staticmethod
    def _edit_distance(a: str, b: str) -> int:
        """Levenshtein distance between two strings. Capped at 3 for speed."""
        if abs(len(a) - len(b)) > 2:
            return 3
        # standard DP but bail early
        m, n = len(a), len(b)
        prev = list(range(n + 1))
        for i in range(1, m + 1):
            curr = [i] + [0] * n
            for j in range(1, n + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            prev = curr
        return prev[n]

    def _classify_unknown(self, commands: list[str]) -> str:
        """
        Not all "unknown" sessions are equal.
        Split into tiers based on command complexity and count.

        Unknown-High: long commands, pipes, special chars, many unknowns = likely novel attack
        Unknown-Low: short simple strings, typos, or few commands
        """
        suspicious_chars = {'|', '>', '<', ';', '&', '$', '`'}
        unknown_count = 0
        typo_count = 0

        for cmd in commands:
            # long command or special chars = suspicious
            if len(cmd) > 50:
                return "Unknown Activity (High)"
            if any(c in cmd for c in suspicious_chars):
                return "Unknown Activity (High)"

            if self._looks_like_typo(cmd):
                typo_count += 1
            else:
                unknown_count += 1

        # many truly unknown commands = suspicious even if individually simple
        if unknown_count >= 5:
            return "Unknown Activity (High)"

        return "Unknown Activity (Low)"
    
    def _compute_sophistication_score(
        self,
        level: int,
        tactic_count: int,
        kill_chain: bool,
        obfuscation: bool,
        matched_count: int,
        commands: list[str],
    ) -> int:
        """
        Score session sophistication from 1-5 based on observable indicators.

        1 = single failed command or empty session
        2 = basic recon only (uname, whoami)
        3 = downloads or persistence attempts
        4 = multi-stage with evasion or obfuscation
        5 = novel techniques, anti-forensics, environment-aware behavior
        """
        # start with level as a rough baseline (inverted: level 1 = more severe)
        if matched_count == 0:
            return 1

        score = 1

        # level 3 (recon) = at least 2
        if level <= 3 and matched_count > 0:
            score = 2

        # level 2 (persistence/privesc) or downloads = at least 3
        if level <= 2:
            score = 3

        # multi-tactic or kill chain or obfuscation = at least 4
        if tactic_count >= 3 or kill_chain or obfuscation:
            score = 4

        # environment-aware + evasion + multi-stage = 5
        if kill_chain and obfuscation and tactic_count >= 4:
            score = 5

        return min(score, 5)

    def label(self, session: Session) -> SessionLabel:
        """
        Assign labels to a session based on its commands.

        v2: normalization, kill chain detection, behavioral tagging.
        v3: sophistication scoring, tactic count, download/upload flags.
        """
        # get raw command inputs
        raw_commands = [c["input"] for c in session.commands if c.get("input")]

        # track download/upload presence at the label level
        has_download = len(session.downloads) > 0
        has_upload = len(session.uploads) > 0

        # no commands = either failed auth or idle session
        if not raw_commands:
            if not session.auth_success:
                return SessionLabel(
                    level=3,
                    primary_tactic="Initial Access (Failed)",
                    all_tactics=["Initial Access (Failed)"],
                    matched_patterns=[],
                    sophistication_score=1,
                    tactic_count=1,
                    has_download=has_download,
                    has_upload=has_upload,
                )
            else:
                return SessionLabel(
                    level=3,
                    primary_tactic="No Action",
                    all_tactics=["No Action"],
                    matched_patterns=[],
                    sophistication_score=1,
                    tactic_count=1,
                    has_download=has_download,
                    has_upload=has_upload,
                )

        # v2: normalize commands (decode obfuscation)
        commands, obfuscation_detected = self._normalize_commands(raw_commands)

        # v2: get behavioral tag early
        behavior_tag = self._get_behavior_tag(session, len(raw_commands))

        # scan all commands (including decoded ones) for pattern matches
        matches = []  # [(level, tactic, pattern_name), ...]

        for cmd in commands:
            for level, tactic, pattern_name, regex in self._patterns:
                if regex.search(cmd):
                    matches.append((level, tactic, pattern_name))

        # no patterns matched = unknown activity
        if not matches:
            # v2: split unknowns into high/low complexity
            unknown_tactic = self._classify_unknown(raw_commands)
            return SessionLabel(
                level=3,
                primary_tactic=unknown_tactic,
                all_tactics=[unknown_tactic],
                matched_patterns=[],
                behavior_tag=behavior_tag,
                obfuscation_detected=obfuscation_detected,
                sophistication_score=2 if obfuscation_detected else 1,
                tactic_count=1,
                has_download=has_download,
                has_upload=has_upload,
            )

        # find most severe level
        min_level = min(m[0] for m in matches)

        # collect all tactics detected
        all_tactics_set = set(m[1] for m in matches)
        all_tactics = list(all_tactics_set)
        tactic_count = len(all_tactics_set)

        # v2: kill chain detection - if we see a multi-stage attack, boost to level 1
        kill_chain_detected = self._detect_kill_chain(all_tactics_set)
        if kill_chain_detected and min_level > 1:
            min_level = 1  # upgrade severity

        # primary tactic = first one at the most severe level (respects priority ordering)
        level_1_tactics = ["Impact", "Execution", "Command and Control", "Resource Hijacking", "Defense Evasion"]
        level_2_tactics = ["Persistence", "Privilege Escalation", "Credential Access"]
        level_3_tactics = ["Discovery"]

        if min_level == 1:
            priority_order = level_1_tactics
        elif min_level == 2:
            priority_order = level_2_tactics
        else:
            priority_order = level_3_tactics

        primary_tactic = "Unknown"
        for tactic in priority_order:
            if tactic in all_tactics:
                primary_tactic = tactic
                break

        # if kill chain bumped us to level 1, primary tactic should reflect that
        if kill_chain_detected and primary_tactic not in level_1_tactics:
            primary_tactic = "Kill Chain Detected"

        # collect matched pattern names (useful for debugging)
        matched_patterns = list(set(m[2] for m in matches))
        if kill_chain_detected:
            matched_patterns.append("kill_chain")
        if obfuscation_detected:
            matched_patterns.append("obfuscation_decoded")

        # v3: compute sophistication score
        sophistication = self._compute_sophistication_score(
            level=min_level,
            tactic_count=tactic_count,
            kill_chain=kill_chain_detected,
            obfuscation=obfuscation_detected,
            matched_count=len(matched_patterns),
            commands=raw_commands,
        )

        return SessionLabel(
            level=min_level,
            primary_tactic=primary_tactic,
            all_tactics=sorted(all_tactics),
            matched_patterns=sorted(matched_patterns),
            behavior_tag=behavior_tag,
            kill_chain_detected=kill_chain_detected,
            obfuscation_detected=obfuscation_detected,
            sophistication_score=sophistication,
            tactic_count=tactic_count,
            has_download=has_download,
            has_upload=has_upload,
        )


# Convenience function for one-off labeling
_default_labeler = None

def label_session(session: Session) -> SessionLabel:
    """
    Label a session using the default labeler.
    
    This is a convenience function that creates a shared labeler instance.
    For batch processing, create your own MitreLabeler to avoid any
    potential issues.
    """
    global _default_labeler
    if _default_labeler is None:
        _default_labeler = MitreLabeler()
    return _default_labeler.label(session)
