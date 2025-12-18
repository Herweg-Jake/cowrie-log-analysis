"""
Host-based feature extraction (F39-F46).

These features capture information about the connection itself rather
than the commands entered. Things like:
  - Protocol (SSH vs Telnet)
  - Source port
  - SSH client version
  - Authentication info
  - Session duration
  - Response sizes

Some of these need special handling for ML - strings like SSH version
need to be encoded numerically. For the MVP, we'll store both the raw
values and some basic encodings.
"""

from typing import Any
from ..aggregators.session_aggregator import Session


# Known SSH client "families" - we'll use these for rough categorization
# These are patterns we expect to see in the version string
SSH_CLIENT_FAMILIES = {
    "openssh": "openssh",
    "putty": "putty",
    "libssh": "libssh",
    "dropbear": "dropbear",
    "paramiko": "paramiko",
    "asyncssh": "asyncssh",
    "go": "golang",
    "ruby": "ruby",
    "nmap": "nmap",  # scanning
    "masscan": "masscan",  # scanning
}


def categorize_ssh_client(version: str | None) -> str:
    """
    Categorize an SSH version string into a known family.
    
    The raw version strings are too varied to use directly, but we can
    group them into families like "openssh", "putty", "libssh", etc.
    
    Returns "unknown" if we can't categorize it.
    """
    if not version:
        return "unknown"
    
    version_lower = version.lower()
    
    for pattern, family in SSH_CLIENT_FAMILIES.items():
        if pattern in version_lower:
            return family
    
    return "other"


def extract_host_features(session: Session) -> dict[str, Any]:
    """
    Extract host-based features (F39-F46) from a session.
    
    Returns both raw values (for storage/forensics) and encoded values
    (for ML). The encoded values have "_encoded" suffix.
    """
    # Get command count for received size calculation
    num_commands = len(session.commands)
    
    # F45: Received_Size (AVG)
    # The paper describes this as the average response size per command.
    # We don't have response sizes in Cowrie logs directly, but we can
    # estimate based on command complexity. For MVP, we'll use a proxy.
    # TODO: If Cowrie logs include response info, use that instead.
    
    # For now, we'll compute average command length as a proxy
    # (longer commands often get longer responses)
    if num_commands > 0:
        total_input_len = sum(len(c.get("input", "")) for c in session.commands)
        avg_input_size = total_input_len / num_commands
    else:
        avg_input_size = 0.0
    
    # F46: File - boolean for whether files were downloaded/uploaded
    has_files = len(session.downloads) > 0 or len(session.uploads) > 0
    
    # SSH client categorization
    ssh_family = categorize_ssh_client(session.ssh_version)
    
    features = {
        # F39: Protocol (0=telnet, 1=ssh)
        "F39_protocol": session.protocol,
        
        # F40: Source port
        # High ports (>49152) are typical ephemeral ports
        # Low ports might indicate specific tools or misconfigurations
        "F40_src_port": session.src_port,
        "F40_src_port_high": 1 if session.src_port > 49152 else 0,
        
        # F41: SSH Client Version (raw + encoded)
        "F41_ssh_version": session.ssh_version or "",
        "F41_ssh_family": ssh_family,
        "F41_ssh_family_encoded": _encode_ssh_family(ssh_family),
        
        # F42: Username (raw + some encodings)
        "F42_username": session.final_username or "",
        "F42_username_is_root": 1 if session.final_username == "root" else 0,
        "F42_username_length": len(session.final_username or ""),
        
        # F43: Password (raw + some analysis)
        # Note: storing passwords is useful for research but be careful with this data!
        "F43_password": session.final_password or "",
        "F43_password_length": len(session.final_password or ""),
        "F43_password_is_common": 1 if _is_common_password(session.final_password) else 0,
        
        # F44: Duration in seconds
        "F44_duration": round(session.get_computed_duration(), 2),
        
        # F45: Received Size (AVG) - using input size as proxy for now
        "F45_received_size_avg": round(avg_input_size, 2),
        
        # F46: File (boolean)
        "F46_has_files": 1 if has_files else 0,
        "F46_download_count": len(session.downloads),
        "F46_upload_count": len(session.uploads),
        
        # Extra host features not in the paper
        "extra_hassh": session.hassh or "",
        "extra_login_attempts": len(session.login_attempts),
        "extra_auth_success": 1 if session.auth_success else 0,
        "extra_tcpip_forwards": len(session.tcpip_requests),
        "extra_dst_port": session.dst_port,
    }
    
    return features


def _encode_ssh_family(family: str) -> int:
    """
    Encode SSH family as an integer for ML.
    
    This is a simple ordinal encoding. For better ML performance,
    you might want to use one-hot encoding at training time.
    """
    encoding = {
        "unknown": 0,
        "other": 1,
        "openssh": 2,
        "putty": 3,
        "libssh": 4,
        "dropbear": 5,
        "paramiko": 6,
        "asyncssh": 7,
        "golang": 8,
        "ruby": 9,
        "nmap": 10,
        "masscan": 11,
    }
    return encoding.get(family, 1)  # default to "other"


# Common passwords seen in honeypot attacks
# This is a small sample - in production you'd load from a file
COMMON_PASSWORDS = {
    "admin", "password", "123456", "12345678", "root", "toor",
    "admin123", "password123", "letmein", "welcome", "monkey",
    "dragon", "master", "qwerty", "login", "pass", "test",
    "guest", "administrator", "changeme", "1234", "12345",
    "123456789", "1234567890", "abc123", "111111", "123123",
    "ubuntu", "debian", "centos", "raspberry", "pi", "default",
    "support", "user", "backup", "oracle", "mysql", "postgres",
    "ftpuser", "ftp", "www", "web", "apache", "nginx",
}


def _is_common_password(password: str | None) -> bool:
    """Check if a password is in our list of commonly-used passwords."""
    if not password:
        return False
    return password.lower() in COMMON_PASSWORDS
