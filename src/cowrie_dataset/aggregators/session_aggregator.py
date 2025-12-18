"""
Session aggregator for Cowrie events.

This is where the magic happens - we take a stream of raw events and
group them into complete attack sessions. A session is everything that
happens from when an attacker connects to when they disconnect (or get
disconnected).

The tricky part is that sessions can span multiple log files. If an
attacker connects at 11:58 PM and disconnects at 12:03 AM, those events
are in different daily files. We handle this by keeping sessions in
memory and only "completing" them when we see the session.closed event
or when we're done processing all files.

For the MVP, we keep everything in memory. For production scale, we'd
want to use a disk-backed store (SQLite, LevelDB, etc.) but let's not
over-engineer until we need to.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Iterator
import logging

from ..parsers.cowrie_parser import CowrieEvent

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """
    A complete (or in-progress) attack session.
    
    This holds all the raw data we've collected about a session. Feature
    extraction happens later - here we just collect the facts.
    """
    
    session_id: str
    location: str  # which honeypot sensor (ssh-amsterdam, etc.)
    
    # Connection info - populated from session.connect
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 22
    protocol: int = 1  # 0=telnet, 1=ssh
    
    # Timing
    start_ts: Optional[datetime] = None
    end_ts: Optional[datetime] = None
    duration: Optional[float] = None  # from session.closed event, if available
    
    # Client info
    ssh_version: Optional[str] = None
    hassh: Optional[str] = None
    hassh_algorithms: Optional[str] = None
    
    # Authentication tracking
    login_attempts: list = field(default_factory=list)  # list of (username, password, success) tuples
    auth_success: bool = False
    final_username: Optional[str] = None
    final_password: Optional[str] = None
    
    # Commands - we store all of them for feature extraction
    commands: list = field(default_factory=list)  # list of (timestamp, input, success) tuples
    
    # Downloads/uploads
    downloads: list = field(default_factory=list)  # list of {url, shasum, outfile} dicts
    uploads: list = field(default_factory=list)
    
    # TCP forwarding requests (tunneling attempts)
    tcpip_requests: list = field(default_factory=list)
    
    # Source files this session came from (for debugging)
    source_files: set = field(default_factory=set)
    
    # Event count (useful for sanity checks)
    event_count: int = 0
    
    # Is this session complete (did we see session.closed)?
    is_closed: bool = False
    
    def add_event(self, event: CowrieEvent):
        """
        Add an event to this session.
        
        This is the main entry point - we dispatch to specific handlers
        based on the event type.
        """
        self.event_count += 1
        
        if event.source_file:
            self.source_files.add(event.source_file)
        
        # Update timestamps
        if self.start_ts is None or event.timestamp < self.start_ts:
            self.start_ts = event.timestamp
        if self.end_ts is None or event.timestamp > self.end_ts:
            self.end_ts = event.timestamp
        
        # Dispatch to handler based on event type
        event_type = event.event_id
        
        if event_type == "cowrie.session.connect":
            self._handle_connect(event)
        elif event_type == "cowrie.client.version":
            self._handle_client_version(event)
        elif event_type == "cowrie.client.kex":
            self._handle_client_kex(event)
        elif event_type == "cowrie.login.success":
            self._handle_login_success(event)
        elif event_type == "cowrie.login.failed":
            self._handle_login_failed(event)
        elif event_type == "cowrie.command.input":
            self._handle_command(event, success=True)
        elif event_type == "cowrie.command.failed":
            self._handle_command(event, success=False)
        elif event_type == "cowrie.session.file_download":
            self._handle_download(event)
        elif event_type == "cowrie.session.file_upload":
            self._handle_upload(event)
        elif event_type == "cowrie.session.closed":
            self._handle_closed(event)
        elif event_type == "cowrie.direct-tcpip.request":
            self._handle_tcpip_request(event)
        # There are other event types we're ignoring for now (client.size, etc.)
        # They're not useful for our feature set
    
    def _handle_connect(self, event: CowrieEvent):
        """Session connection - grab the network info."""
        self.src_ip = event.src_ip
        self.src_port = event.src_port or 0
        self.dst_ip = event.dst_ip or ""
        self.dst_port = event.dst_port or 22
        self.protocol = event.protocol if event.protocol is not None else 1
    
    def _handle_client_version(self, event: CowrieEvent):
        """SSH client version string."""
        self.ssh_version = event.ssh_version
    
    def _handle_client_kex(self, event: CowrieEvent):
        """SSH key exchange info (hassh fingerprint)."""
        self.hassh = event.hassh
        self.hassh_algorithms = event.hassh_algorithms
    
    def _handle_login_success(self, event: CowrieEvent):
        """Successful authentication."""
        self.login_attempts.append((event.username, event.password, True))
        self.auth_success = True
        self.final_username = event.username
        self.final_password = event.password
    
    def _handle_login_failed(self, event: CowrieEvent):
        """Failed authentication attempt."""
        self.login_attempts.append((event.username, event.password, False))
    
    def _handle_command(self, event: CowrieEvent, success: bool):
        """
        Command execution (or attempt).
        
        success=True means the command was recognized by cowrie
        success=False means it was an invalid/unknown command
        """
        if event.input:  # sometimes input is None or empty
            self.commands.append({
                "timestamp": event.timestamp,
                "input": event.input,
                "success": success,
            })
    
    def _handle_download(self, event: CowrieEvent):
        """File download attempt."""
        self.downloads.append({
            "url": event.url,
            "shasum": event.shasum,
            "outfile": event.outfile,
        })
    
    def _handle_upload(self, event: CowrieEvent):
        """File upload."""
        self.uploads.append({
            "shasum": event.shasum,
            "destfile": event.destfile,
        })
    
    def _handle_closed(self, event: CowrieEvent):
        """Session closed - we now have the complete picture."""
        self.is_closed = True
        if event.duration is not None:
            self.duration = event.duration
    
    def _handle_tcpip_request(self, event: CowrieEvent):
        """TCP/IP forwarding request (tunneling attempt)."""
        self.tcpip_requests.append({
            "dst_ip": event.raw.get("dst_ip"),
            "dst_port": event.raw.get("dst_port"),
        })
    
    def get_computed_duration(self) -> float:
        """
        Get session duration in seconds.
        
        Prefers the duration from session.closed event if available,
        otherwise computes from start/end timestamps.
        """
        if self.duration is not None:
            return self.duration
        
        if self.start_ts and self.end_ts:
            delta = self.end_ts - self.start_ts
            return delta.total_seconds()
        
        return 0.0
    
    def get_session_type(self) -> str:
        """
        Classify this session by what the attacker did.
        
        Returns one of:
        - "failed_auth_only": Never successfully logged in
        - "success_no_commands": Logged in but didn't run any commands
        - "success_with_commands": Logged in and ran commands
        """
        if not self.auth_success:
            return "failed_auth_only"
        
        if not self.commands:
            return "success_no_commands"
        
        return "success_with_commands"
    
    def to_dict(self) -> dict:
        """
        Convert to a dictionary suitable for JSON/ES indexing.
        
        This is the raw session data - feature extraction happens
        separately and gets merged in later.
        """
        return {
            "session_id": self.session_id,
            "location": self.location,
            
            "connection": {
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "dst_ip": self.dst_ip,
                "dst_port": self.dst_port,
                "protocol": self.protocol,
            },
            
            "timing": {
                "start_ts": self.start_ts.isoformat() if self.start_ts else None,
                "end_ts": self.end_ts.isoformat() if self.end_ts else None,
                "duration_s": self.get_computed_duration(),
            },
            
            "client": {
                "ssh_version": self.ssh_version,
                "hassh": self.hassh,
                "hassh_algorithms": self.hassh_algorithms,
            },
            
            "authentication": {
                "attempts": len(self.login_attempts),
                "success": self.auth_success,
                "failed_count": sum(1 for _, _, s in self.login_attempts if not s),
                "success_count": sum(1 for _, _, s in self.login_attempts if s),
                "usernames_tried": list(set(u for u, _, _ in self.login_attempts if u)),
                "final_username": self.final_username,
                "final_password": self.final_password,
            },
            
            "commands": {
                "total_count": len(self.commands),
                "success_count": sum(1 for c in self.commands if c["success"]),
                "failed_count": sum(1 for c in self.commands if not c["success"]),
                # Store up to 100 commands for forensics, but we compute features on all
                "inputs": [c["input"] for c in self.commands[:100]],
                "unique_commands": len(set(c["input"] for c in self.commands)),
            },
            
            "downloads": {
                "count": len(self.downloads),
                "urls": [d["url"] for d in self.downloads[:20] if d.get("url")],
                "shasums": [d["shasum"] for d in self.downloads[:20] if d.get("shasum")],
            },
            
            "uploads": {
                "count": len(self.uploads),
            },
            
            "tcpip_forwards": {
                "count": len(self.tcpip_requests),
            },
            
            "meta": {
                "event_count": self.event_count,
                "source_files": list(self.source_files),
                "is_closed": self.is_closed,
                "session_type": self.get_session_type(),
            },
        }


class SessionAggregator:
    """
    Aggregates Cowrie events into complete sessions.
    
    Feed it events via add_event(), then call get_completed_sessions()
    to retrieve sessions that are done. When you're finished processing
    all events, call flush() to get any remaining sessions that never
    got a proper close event.
    
    Usage:
        aggregator = SessionAggregator(location="ssh-amsterdam")
        
        for event in parser.parse_directory(path):
            completed = aggregator.add_event(event)
            for session in completed:
                process_completed_session(session)
        
        # Don't forget to flush at the end!
        for session in aggregator.flush():
            process_completed_session(session)
    """
    
    def __init__(self, location: str):
        """
        Args:
            location: The honeypot location name (e.g., "ssh-amsterdam")
        """
        self.location = location
        
        # In-memory session store: session_id -> Session
        self._sessions: dict[str, Session] = {}
        
        # Stats
        self.sessions_created = 0
        self.sessions_completed = 0
    
    def add_event(self, event: CowrieEvent) -> list[Session]:
        """
        Add an event and return any sessions that completed as a result.
        
        Most of the time this returns an empty list. When we see a
        session.closed event, we return the now-complete session.
        """
        session_id = event.session
        
        # Get or create the session
        if session_id not in self._sessions:
            self._sessions[session_id] = Session(
                session_id=session_id,
                location=self.location,
            )
            self.sessions_created += 1
        
        session = self._sessions[session_id]
        session.add_event(event)
        
        # If this event closed the session, remove it from our store and return it
        if event.event_id == "cowrie.session.closed":
            del self._sessions[session_id]
            self.sessions_completed += 1
            return [session]
        
        return []
    
    def flush(self) -> Iterator[Session]:
        """
        Flush all remaining sessions.
        
        Call this after processing all events. Any sessions still in
        memory never got a close event (maybe the connection dropped,
        or the close event was in a file we didn't process).
        
        These sessions are marked as not closed, which downstream code
        might want to handle differently.
        """
        for session in self._sessions.values():
            self.sessions_completed += 1
            yield session
        
        self._sessions.clear()
    
    def get_active_session_count(self) -> int:
        """How many sessions are currently in progress?"""
        return len(self._sessions)
    
    def get_stats(self) -> dict:
        """Return aggregation statistics."""
        return {
            "location": self.location,
            "sessions_created": self.sessions_created,
            "sessions_completed": self.sessions_completed,
            "active_sessions": len(self._sessions),
        }
