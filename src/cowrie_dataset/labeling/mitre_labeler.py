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

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "primary_tactic": self.primary_tactic,
            "all_tactics": self.all_tactics,
            "matched_patterns": self.matched_patterns[:20],  # cap for storage
            "behavior_tag": self.behavior_tag,
            "kill_chain_detected": self.kill_chain_detected,
            "obfuscation_detected": self.obfuscation_detected,
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
    ],
    
    "Command and Control": [
        ("wget_execute", re.compile(r'\bwget\s+.*\|\s*(ba)?sh', re.IGNORECASE)),
        ("curl_execute", re.compile(r'\bcurl\s+.*\|\s*(ba)?sh', re.IGNORECASE)),
        ("nc_shell", re.compile(r'\b(nc|netcat|ncat)\s+.*-e\s', re.IGNORECASE)),
        ("tftp_get", re.compile(r'\btftp\s+', re.IGNORECASE)),
        ("wget_o", re.compile(r'\bwget\s+.*-O\s', re.IGNORECASE)),
        ("curl_o", re.compile(r'\bcurl\s+.*-o\s', re.IGNORECASE)),
        ("base64_decode", re.compile(r'\bbase64\s+(-d|--decode)', re.IGNORECASE)),
    ],
    
    "Defense Evasion": [
        ("history_clear", re.compile(r'\bhistory\s+-[cdw]', re.IGNORECASE)),
        ("unset_hist", re.compile(r'\bunset\s+HIST', re.IGNORECASE)),
        ("histsize_0", re.compile(r'HISTSIZE=0|HISTFILESIZE=0', re.IGNORECASE)),
        ("rm_logs", re.compile(r'\brm\s+.*(/var/log/|\.bash_history|\.history)', re.IGNORECASE)),
        ("truncate_logs", re.compile(r'>\s*/var/log/|echo\s*>\s*/var/log/', re.IGNORECASE)),
        ("dev_null_redirect", re.compile(r'2>/dev/null.*&>/dev/null', re.IGNORECASE)),
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

    # regex to find base64-ish strings (at least 8 chars to catch short payloads)
    # real base64 strings are usually longer but attackers do use short ones
    _BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')

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
        Pre-process commands to decode any base64 obfuscation.
        Returns (normalized_commands, found_obfuscation).

        Attackers love stuff like: echo "cm0gLXJmIC8="|base64 -d|sh
        We want to catch that 'rm -rf /' hiding in there.
        """
        normalized = list(commands)  # start with originals
        found_obfuscation = False

        for cmd in commands:
            # look for base64-ish blobs in the command
            for match in self._BASE64_PATTERN.finditer(cmd):
                candidate = match.group()
                decoded = self._try_decode_base64(candidate)
                if decoded and decoded not in normalized:
                    # found something real, add it to scan list
                    normalized.append(decoded)
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
            # C2 + execution = bad news
            {"Command and Control", "Execution"},
            {"Command and Control", "Impact"},
        ]

        for combo in dangerous_combos:
            if combo.issubset(tactics):
                return True
        return False

    def _get_behavior_tag(self, session: Session, cmd_count: int) -> str:
        """
        Tag session as machine or human based on command rate.

        Bots paste 50 commands in a second. Humans type slowly.
        This isn't foolproof but it's a useful signal.
        """
        duration = session.get_computed_duration()

        if duration <= 0 or cmd_count == 0:
            return "UNKNOWN_SPEED"

        cmds_per_sec = cmd_count / duration

        # thresholds tuned based on what feels right
        # >5 cmd/sec is definitely automated
        # <0.3 cmd/sec is probably a human exploring
        if cmds_per_sec > 5.0:
            return "MACHINE_SPEED"
        elif cmds_per_sec < 0.3:
            return "HUMAN_SPEED"
        else:
            return "UNKNOWN_SPEED"

    def _classify_unknown(self, commands: list[str]) -> str:
        """
        Not all "unknown" sessions are equal.
        Split into tiers based on command complexity.

        Unknown-High: long commands, pipes, special chars = likely novel attack
        Unknown-Low: short simple strings = probably typos or aliases
        """
        suspicious_chars = {'|', '>', '<', ';', '&', '$', '`'}

        for cmd in commands:
            # long command or special chars = suspicious
            if len(cmd) > 50:
                return "Unknown Activity (High)"
            if any(c in cmd for c in suspicious_chars):
                return "Unknown Activity (High)"

        return "Unknown Activity (Low)"
    
    def label(self, session: Session) -> SessionLabel:
        """
        Assign labels to a session based on its commands.

        v2: now includes normalization, kill chain detection, and behavioral tagging.
        """
        # get raw command inputs
        raw_commands = [c["input"] for c in session.commands if c.get("input")]

        # no commands = either failed auth or idle session
        if not raw_commands:
            if not session.auth_success:
                return SessionLabel(
                    level=3,
                    primary_tactic="Initial Access (Failed)",
                    all_tactics=["Initial Access (Failed)"],
                    matched_patterns=[],
                )
            else:
                return SessionLabel(
                    level=3,
                    primary_tactic="No Action",
                    all_tactics=["No Action"],
                    matched_patterns=[],
                )

        # v2: normalize commands (decode base64 obfuscation)
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
            )

        # find most severe level
        min_level = min(m[0] for m in matches)

        # collect all tactics detected
        all_tactics_set = set(m[1] for m in matches)
        all_tactics = list(all_tactics_set)

        # v2: kill chain detection - if we see a multi-stage attack, boost to level 1
        kill_chain_detected = self._detect_kill_chain(all_tactics_set)
        if kill_chain_detected and min_level > 1:
            min_level = 1  # upgrade severity

        # primary tactic = first one at the most severe level (respects priority ordering)
        level_1_tactics = ["Impact", "Execution", "Command and Control", "Defense Evasion"]
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
            matched_patterns.append("base64_decoded")

        return SessionLabel(
            level=min_level,
            primary_tactic=primary_tactic,
            all_tactics=sorted(all_tactics),
            matched_patterns=sorted(matched_patterns),
            behavior_tag=behavior_tag,
            kill_chain_detected=kill_chain_detected,
            obfuscation_detected=obfuscation_detected,
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
