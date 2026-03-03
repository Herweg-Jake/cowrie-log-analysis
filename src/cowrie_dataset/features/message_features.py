"""
Message-based feature extraction (F1-F38).

These features analyze the commands that attackers entered during their
session. We're looking for patterns like:
  - Reconnaissance commands (uname, cat /etc/passwd, etc.)
  - Privilege escalation (sudo, chmod, etc.)
  - File operations (wget, curl, rm, etc.)
  - Obfuscation (base64 encoding, hex strings)
  - Attack characteristics (message length, typing speed)

The paper describes 38 message-based features. We implement all of them
here, with some slight modifications where the paper's description was
unclear or where we found additional useful patterns.
"""

import re
from typing import Any
from ..aggregators.session_aggregator import Session


# Regex patterns for various command categories
# These are pre-compiled for performance since we'll run them a lot

# F1-F4: Invalid/basic commands
PATTERN_BASH = re.compile(r'\bbash\b', re.IGNORECASE)
PATTERN_SHELL = re.compile(r'\bsh(?:ell)?\b', re.IGNORECASE)
PATTERN_EXIT = re.compile(r'\bexit\b', re.IGNORECASE)
PATTERN_HELP = re.compile(r'\bhelp\b', re.IGNORECASE)

# F5-F7: Account operations
PATTERN_PASSWD = re.compile(r'\bpasswd\s+\w+', re.IGNORECASE)
PATTERN_CHPASSWD = re.compile(r'\bchpasswd\b', re.IGNORECASE)
PATTERN_USERADD = re.compile(r'\buseradd\b', re.IGNORECASE)

# F8-F13: File execution
PATTERN_DOT_FILE = re.compile(r'^\.\s+\S+|;\s*\.\s+\S+', re.IGNORECASE)  # ". file" (source)
PATTERN_SH_FILE = re.compile(r'\bsh\s+\S+\.sh|\bsh\s+-c', re.IGNORECASE)
PATTERN_SLASH_FILE = re.compile(r'(?:^|;|\||&&)\s*\./\S+', re.IGNORECASE)  # ./something
PATTERN_PERL = re.compile(r'\bperl\s+\S+', re.IGNORECASE)
PATTERN_PYTHON = re.compile(r'\bpython[23]?\s+\S+', re.IGNORECASE)
PATTERN_BIN = re.compile(r'/bin/\S+', re.IGNORECASE)

# F14-F15: Permission escalation
PATTERN_CHMOD = re.compile(r'\bchmod\b', re.IGNORECASE)
PATTERN_SUDO_SU = re.compile(r'\bsudo\s+su\b|\bsudo\s+-i\b|\bsudo\s+bash\b', re.IGNORECASE)

# F16-F17: History deletion / covering tracks
PATTERN_RM = re.compile(r'\brm\s+', re.IGNORECASE)
PATTERN_HISTORY = re.compile(r'\bhistory\s*-[cdw]|\bunset\s+HISTFILE|HISTSIZE=0', re.IGNORECASE)

# F18-F27: System reconnaissance
PATTERN_CAT_ETC = re.compile(r'\bcat\s+/etc/', re.IGNORECASE)
PATTERN_UNAME = re.compile(r'\buname\b', re.IGNORECASE)
PATTERN_WC = re.compile(r'\bwc\b', re.IGNORECASE)
PATTERN_CRONTAB = re.compile(r'\bcrontab\b', re.IGNORECASE)
PATTERN_W = re.compile(r'(?:^|\s|;)w(?:\s|$|;)', re.IGNORECASE)  # the 'w' command (tricky!)
PATTERN_PS = re.compile(r'\bps\b', re.IGNORECASE)
PATTERN_FREE = re.compile(r'\bfree\b', re.IGNORECASE)
PATTERN_LSCPU = re.compile(r'\blscpu\b', re.IGNORECASE)
PATTERN_NPROC = re.compile(r'\bnproc\b', re.IGNORECASE)
PATTERN_UPTIME = re.compile(r'\buptime\b', re.IGNORECASE)

# F28-F31: Network/download commands
PATTERN_WGET = re.compile(r'\bwget\b', re.IGNORECASE)
PATTERN_TFTP = re.compile(r'\btftp\b', re.IGNORECASE)
PATTERN_SCP = re.compile(r'\bscp\b', re.IGNORECASE)
PATTERN_PING = re.compile(r'\bping\b', re.IGNORECASE)

# Additional network commands not in the paper but commonly seen
PATTERN_CURL = re.compile(r'\bcurl\b', re.IGNORECASE)
PATTERN_NC = re.compile(r'\b(?:nc|netcat|ncat)\b', re.IGNORECASE)

# F32-F33: Shutdown/impact commands
PATTERN_KILL = re.compile(r'\bkill\b', re.IGNORECASE)
PATTERN_REBOOT = re.compile(r'\breboot\b|\bshutdown\b|\binit\s+[06]\b', re.IGNORECASE)

# F34-F35: Obfuscation
PATTERN_BASE64 = re.compile(r'\bbase64\b', re.IGNORECASE)
PATTERN_HEX = re.compile(r'\\x[0-9a-fA-F]{2}|0x[0-9a-fA-F]+', re.IGNORECASE)

# F36: URLs in messages
PATTERN_URL = re.compile(r'https?://\S+|ftp://\S+', re.IGNORECASE)


def count_pattern(commands: list[str], pattern: re.Pattern) -> int:
    """Count how many commands match a pattern."""
    return sum(1 for cmd in commands if pattern.search(cmd))


def count_all_matches(commands: list[str], pattern: re.Pattern) -> int:
    """Count total matches across all commands (a command can match multiple times)."""
    return sum(len(pattern.findall(cmd)) for cmd in commands)


def extract_message_features(session: Session) -> dict[str, Any]:
    """
    Extract all 38 message-based features from a session.
    
    Returns a dict with keys F1-F38 plus some additional features we
    found useful. All values are numeric (int or float) for ML compatibility.
    """
    # Get all command inputs as a list of strings
    commands = [c["input"] for c in session.commands if c.get("input")]
    
    # If no commands, return zeros for everything
    if not commands:
        return _empty_message_features()
    
    # Combine all commands into one big string for some analyses
    all_text = " ".join(commands)
    total_length = len(all_text)
    
    # Calculate timing features
    duration = session.get_computed_duration()
    num_commands = len(commands)
    
    # F38: Messages per second (typing speed indicator)
    # High values suggest automated/scripted attacks
    if duration > 0:
        messages_per_sec = num_commands / duration
        chars_per_sec = total_length / duration
    else:
        messages_per_sec = num_commands  # instant = very fast
        chars_per_sec = total_length
    
    features = {
        # F1-F4: Invalid/basic commands
        "F1_keyword_bash": count_pattern(commands, PATTERN_BASH),
        "F2_keyword_shell": count_pattern(commands, PATTERN_SHELL),
        "F3_keyword_exit": count_pattern(commands, PATTERN_EXIT),
        "F4_keyword_help": count_pattern(commands, PATTERN_HELP),
        
        # F5-F7: Account operations
        "F5_keyword_passwd": count_pattern(commands, PATTERN_PASSWD),
        "F6_keyword_chpasswd": count_pattern(commands, PATTERN_CHPASSWD),
        "F7_keyword_useradd": count_pattern(commands, PATTERN_USERADD),
        
        # F8-F13: File execution
        "F8_keyword_dot_file": count_pattern(commands, PATTERN_DOT_FILE),
        "F9_keyword_sh_file": count_pattern(commands, PATTERN_SH_FILE),
        "F10_keyword_slash_file": count_pattern(commands, PATTERN_SLASH_FILE),
        "F11_keyword_perl": count_pattern(commands, PATTERN_PERL),
        "F12_keyword_python": count_pattern(commands, PATTERN_PYTHON),
        "F13_keyword_bin": count_pattern(commands, PATTERN_BIN),
        
        # F14-F15: Permission escalation
        "F14_keyword_chmod": count_pattern(commands, PATTERN_CHMOD),
        "F15_keyword_sudo_su": count_pattern(commands, PATTERN_SUDO_SU),
        
        # F16-F17: History deletion
        "F16_keyword_rm": count_pattern(commands, PATTERN_RM),
        "F17_keyword_history": count_pattern(commands, PATTERN_HISTORY),
        
        # F18-F27: System reconnaissance
        "F18_keyword_cat_etc": count_pattern(commands, PATTERN_CAT_ETC),
        "F19_keyword_uname": count_pattern(commands, PATTERN_UNAME),
        "F20_keyword_wc": count_pattern(commands, PATTERN_WC),
        "F21_keyword_crontab": count_pattern(commands, PATTERN_CRONTAB),
        "F22_keyword_w": count_pattern(commands, PATTERN_W),
        "F23_keyword_ps": count_pattern(commands, PATTERN_PS),
        "F24_keyword_free": count_pattern(commands, PATTERN_FREE),
        "F25_keyword_lscpu": count_pattern(commands, PATTERN_LSCPU),
        "F26_keyword_nproc": count_pattern(commands, PATTERN_NPROC),
        "F27_keyword_uptime": count_pattern(commands, PATTERN_UPTIME),
        
        # F28-F31: Network/download commands
        "F28_keyword_wget": count_pattern(commands, PATTERN_WGET),
        "F29_keyword_tftp": count_pattern(commands, PATTERN_TFTP),
        "F30_keyword_scp": count_pattern(commands, PATTERN_SCP),
        "F31_keyword_ping": count_pattern(commands, PATTERN_PING),
        
        # F32-F33: Shutdown/impact
        "F32_keyword_kill": count_pattern(commands, PATTERN_KILL),
        "F33_keyword_reboot": count_pattern(commands, PATTERN_REBOOT),
        
        # F34-F35: Obfuscation
        "F34_count_base64": count_pattern(commands, PATTERN_BASE64),
        "F35_count_hex": count_all_matches(commands, PATTERN_HEX),
        
        # F36-F38: Content analysis
        "F36_count_url": count_all_matches(commands, PATTERN_URL),
        "F37_message_length": total_length,
        "F38_messages_per_sec": round(messages_per_sec, 4),
        
        # Bonus features not in the paper but useful
        "extra_chars_per_sec": round(chars_per_sec, 4),
        "extra_num_commands": num_commands,
        "extra_avg_cmd_length": round(total_length / num_commands, 2) if num_commands > 0 else 0,
        "extra_unique_commands": len(set(commands)),
        "extra_keyword_curl": count_pattern(commands, PATTERN_CURL),
        "extra_keyword_nc": count_pattern(commands, PATTERN_NC),

        # v3: timing, length, diversity, and shell operator features
        "extra_min_inter_command_gap": _compute_min_inter_command_gap(session),
        "extra_max_cmd_length": max(len(cmd) for cmd in commands),
        "extra_command_diversity_ratio": round(len(set(commands)) / num_commands, 4),
        "extra_has_pipe": sum(1 for cmd in commands if '|' in cmd),
        "extra_has_redirect": sum(1 for cmd in commands if '>' in cmd),
    }

    return features


def _compute_min_inter_command_gap(session: Session) -> float:
    """
    Minimum time between any two consecutive commands.

    Best single feature for distinguishing pasted/scripted input from
    interactive typing. A value under 0.05s is almost certainly automated.
    Returns -1.0 if there aren't enough timestamped commands.
    """
    timestamps = []
    for cmd in session.commands:
        ts = cmd.get("timestamp")
        if ts is not None:
            timestamps.append(ts)

    if len(timestamps) < 2:
        return -1.0

    timestamps.sort()
    min_gap = float('inf')
    for i in range(1, len(timestamps)):
        delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
        if delta < min_gap:
            min_gap = delta

    return round(min_gap, 6)


def _empty_message_features() -> dict[str, Any]:
    """Return zeroed features for sessions with no commands."""
    return {
        "F1_keyword_bash": 0,
        "F2_keyword_shell": 0,
        "F3_keyword_exit": 0,
        "F4_keyword_help": 0,
        "F5_keyword_passwd": 0,
        "F6_keyword_chpasswd": 0,
        "F7_keyword_useradd": 0,
        "F8_keyword_dot_file": 0,
        "F9_keyword_sh_file": 0,
        "F10_keyword_slash_file": 0,
        "F11_keyword_perl": 0,
        "F12_keyword_python": 0,
        "F13_keyword_bin": 0,
        "F14_keyword_chmod": 0,
        "F15_keyword_sudo_su": 0,
        "F16_keyword_rm": 0,
        "F17_keyword_history": 0,
        "F18_keyword_cat_etc": 0,
        "F19_keyword_uname": 0,
        "F20_keyword_wc": 0,
        "F21_keyword_crontab": 0,
        "F22_keyword_w": 0,
        "F23_keyword_ps": 0,
        "F24_keyword_free": 0,
        "F25_keyword_lscpu": 0,
        "F26_keyword_nproc": 0,
        "F27_keyword_uptime": 0,
        "F28_keyword_wget": 0,
        "F29_keyword_tftp": 0,
        "F30_keyword_scp": 0,
        "F31_keyword_ping": 0,
        "F32_keyword_kill": 0,
        "F33_keyword_reboot": 0,
        "F34_count_base64": 0,
        "F35_count_hex": 0,
        "F36_count_url": 0,
        "F37_message_length": 0,
        "F38_messages_per_sec": 0.0,
        "extra_chars_per_sec": 0.0,
        "extra_num_commands": 0,
        "extra_avg_cmd_length": 0.0,
        "extra_unique_commands": 0,
        "extra_keyword_curl": 0,
        "extra_keyword_nc": 0,
        "extra_min_inter_command_gap": -1.0,
        "extra_max_cmd_length": 0,
        "extra_command_diversity_ratio": 0.0,
        "extra_has_pipe": 0,
        "extra_has_redirect": 0,
    }
