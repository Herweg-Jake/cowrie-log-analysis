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

Reference: MITRE ATT&CK Enterprise Tactics
https://attack.mitre.org/tactics/enterprise/
"""

import re
from dataclasses import dataclass, field
from typing import Any
from ..aggregators.session_aggregator import Session


@dataclass
class SessionLabel:
    """
    Labels assigned to a session.
    
    Contains the threat level, primary tactic, and all detected tactics.
    """
    level: int  # 1=high, 2=medium, 3=low
    primary_tactic: str  # The most severe tactic detected
    all_tactics: list[str] = field(default_factory=list)  # All tactics detected
    matched_patterns: list[str] = field(default_factory=list)  # Which patterns matched (for debugging)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "primary_tactic": self.primary_tactic,
            "all_tactics": self.all_tactics,
            "matched_patterns": self.matched_patterns[:20],  # cap for storage
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
    
    Usage:
        labeler = MitreLabeler()
        label = labeler.label(session)
        print(f"Level: {label.level}, Tactic: {label.primary_tactic}")
    """
    
    def __init__(self):
        # Compile all patterns once at init time
        # Structure: [(level, tactic, pattern_name, compiled_regex), ...]
        self._patterns = []
        
        for level, pattern_dict in [
            (1, LEVEL_1_PATTERNS),
            (2, LEVEL_2_PATTERNS),
            (3, LEVEL_3_PATTERNS),
        ]:
            for tactic, patterns in pattern_dict.items():
                for pattern_name, regex in patterns:
                    self._patterns.append((level, tactic, pattern_name, regex))
    
    def label(self, session: Session) -> SessionLabel:
        """
        Assign labels to a session based on its commands.
        
        Scans all commands and returns the most severe level found,
        along with all detected tactics.
        """
        # Get all command inputs
        commands = [c["input"] for c in session.commands if c.get("input")]
        
        # If no commands, it's either failed auth or login with no action
        if not commands:
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
        
        # Scan all commands for pattern matches
        matches = []  # [(level, tactic, pattern_name), ...]
        
        for cmd in commands:
            for level, tactic, pattern_name, regex in self._patterns:
                if regex.search(cmd):
                    matches.append((level, tactic, pattern_name))
        
        # If no patterns matched, it's unknown activity (still somewhat suspicious)
        if not matches:
            return SessionLabel(
                level=3,
                primary_tactic="Unknown Activity",
                all_tactics=["Unknown Activity"],
                matched_patterns=[],
            )
        
        # Find the most severe level
        min_level = min(m[0] for m in matches)
        
        # Get all tactics detected
        all_tactics = list(set(m[1] for m in matches))
        
        # Primary tactic is the first one at the minimum (most severe) level
        # This respects the ordering we defined in the pattern dicts
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
        
        # Collect matched pattern names (useful for debugging and analysis)
        matched_patterns = list(set(m[2] for m in matches))
        
        return SessionLabel(
            level=min_level,
            primary_tactic=primary_tactic,
            all_tactics=sorted(all_tactics),
            matched_patterns=sorted(matched_patterns),
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
