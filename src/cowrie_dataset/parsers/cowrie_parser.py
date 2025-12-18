"""
Cowrie honeypot log parser.

Cowrie logs are stored as gzipped JSON-lines files, one event per line.
This parser handles:
  - Reading .gz files without fully decompressing to disk
  - Parsing each JSON line into a structured event
  - Yielding events as a stream (memory efficient for large files)
  - Handling malformed lines gracefully (log and skip)

The parser is intentionally dumb - it just reads and parses. All the
smart session aggregation and feature extraction happens downstream.
"""

import gzip
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class CowrieEvent:
    """
    A single event from a Cowrie log file.
    
    We parse the raw JSON into this structured class so downstream code
    doesn't have to deal with missing keys, type conversions, etc.
    
    Not all fields are present in all event types - that's fine, we just
    leave them as None. The event_id tells you what type of event it is
    and therefore which fields are relevant.
    """
    
    # Core fields (present in every event)
    event_id: str                    # e.g., "cowrie.session.connect", "cowrie.command.input"
    timestamp: datetime              # When this event occurred (UTC)
    session: str                     # Session ID - this is how we group events
    src_ip: str                      # Attacker's IP
    
    # Connection info (from cowrie.session.connect)
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None   # 0 = telnet, 1 = ssh (I think?)
    
    # Client info (from cowrie.client.version, cowrie.client.kex)
    ssh_version: Optional[str] = None
    hassh: Optional[str] = None
    hassh_algorithms: Optional[str] = None
    
    # Auth info (from cowrie.login.*)
    username: Optional[str] = None
    password: Optional[str] = None
    
    # Command info (from cowrie.command.*)
    input: Optional[str] = None      # The actual command text
    
    # Download/upload info (from cowrie.session.file_*)
    url: Optional[str] = None
    shasum: Optional[str] = None
    outfile: Optional[str] = None
    destfile: Optional[str] = None
    
    # Session close info (from cowrie.session.closed)
    duration: Optional[float] = None
    
    # Misc - sometimes there's a message field with extra context
    message: Optional[str] = None
    
    # The raw dict, in case we need something we didn't explicitly extract
    raw: dict = field(default_factory=dict, repr=False)
    
    # Metadata about where this event came from (useful for debugging)
    source_file: Optional[str] = None
    line_number: Optional[int] = None


def parse_timestamp(ts_str: str) -> datetime:
    """
    Parse Cowrie's timestamp format into a datetime.
    
    Cowrie uses ISO8601 with 'Z' suffix for UTC, like:
    "2021-01-09T00:00:01.916929Z"
    
    Python's fromisoformat() is picky about the 'Z', so we handle it.
    """
    # Replace Z with +00:00 for Python's parser
    if ts_str.endswith('Z'):
        ts_str = ts_str[:-1] + '+00:00'
    
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        # If that fails, try a more lenient parse
        # Sometimes the microseconds are truncated or missing
        for fmt in [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ]:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        
        # Give up and raise
        raise ValueError(f"Cannot parse timestamp: {ts_str}")


def parse_event(raw: dict, source_file: str = None, line_number: int = None) -> CowrieEvent:
    """
    Parse a raw JSON dict into a CowrieEvent.
    
    This handles all the field extraction and type conversion in one place.
    Missing fields just become None - we don't fail on incomplete events.
    """
    
    # These fields should always be present, but let's be defensive
    event_id = raw.get("eventid", "unknown")
    session = raw.get("session", "unknown")
    src_ip = raw.get("src_ip", "0.0.0.0")
    
    # Timestamp is critical - if it's missing or broken, that's a problem
    ts_str = raw.get("timestamp", "")
    try:
        timestamp = parse_timestamp(ts_str) if ts_str else datetime.now()
    except ValueError as e:
        logger.warning(f"Bad timestamp in {source_file}:{line_number}: {ts_str}")
        timestamp = datetime.now()  # fallback, not great but better than crashing
    
    return CowrieEvent(
        event_id=event_id,
        timestamp=timestamp,
        session=session,
        src_ip=src_ip,
        
        # Connection fields
        src_port=raw.get("src_port"),
        dst_ip=raw.get("dst_ip"),
        dst_port=raw.get("dst_port"),
        protocol=raw.get("protocol"),
        
        # Client fields
        ssh_version=raw.get("version"),  # note: field is called "version" in the JSON
        hassh=raw.get("hassh"),
        hassh_algorithms=raw.get("hasshAlgorithms"),
        
        # Auth fields
        username=raw.get("username"),
        password=raw.get("password"),
        
        # Command fields
        input=raw.get("input"),
        
        # Download fields
        url=raw.get("url"),
        shasum=raw.get("shasum"),
        outfile=raw.get("outfile"),
        destfile=raw.get("destfile"),
        
        # Session close
        duration=raw.get("duration"),
        
        # Message
        message=raw.get("message"),
        
        # Keep the raw dict around
        raw=raw,
        source_file=source_file,
        line_number=line_number,
    )


class CowrieParser:
    """
    Parser for Cowrie honeypot log files.
    
    Usage:
        parser = CowrieParser()
        
        # Parse a single file
        for event in parser.parse_file("/path/to/cowrie.json.2021_1_9.gz"):
            print(event.event_id, event.session)
        
        # Parse all files in a directory
        for event in parser.parse_directory("/opt/honeypot/ssh-amsterdam"):
            process(event)
    
    The parser yields events as a stream, so you can process huge amounts
    of data without loading everything into memory.
    """
    
    def __init__(self):
        self.files_parsed = 0
        self.events_parsed = 0
        self.errors = 0
    
    def parse_file(self, filepath: Path | str) -> Iterator[CowrieEvent]:
        """
        Parse a single Cowrie log file (gzipped or plain).
        
        Yields CowrieEvent objects one at a time. Malformed lines are
        logged and skipped, not raised as exceptions.
        """
        filepath = Path(filepath)
        filename = filepath.name
        
        logger.debug(f"Parsing {filepath}")
        
        # Figure out how to open this file
        if filepath.suffix == '.gz':
            opener = gzip.open
            mode = 'rt'  # text mode for gzip
        else:
            opener = open
            mode = 'r'
        
        try:
            with opener(filepath, mode, encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue  # skip empty lines
                    
                    try:
                        raw = json.loads(line)
                        event = parse_event(raw, source_file=filename, line_number=line_num)
                        self.events_parsed += 1
                        yield event
                        
                    except json.JSONDecodeError as e:
                        # Malformed JSON - log it and move on
                        logger.warning(f"JSON parse error in {filename}:{line_num}: {e}")
                        self.errors += 1
                        continue
                    except Exception as e:
                        # Something else went wrong
                        logger.warning(f"Error parsing {filename}:{line_num}: {e}")
                        self.errors += 1
                        continue
            
            self.files_parsed += 1
            
        except Exception as e:
            logger.error(f"Failed to open/read {filepath}: {e}")
            raise
    
    def parse_directory(
        self, 
        dirpath: Path | str,
        pattern: str = "cowrie*.gz",
        limit: Optional[int] = None,
        sort_by_date: bool = True
    ) -> Iterator[CowrieEvent]:
        """
        Parse all matching files in a directory.
        
        Args:
            dirpath: Directory containing Cowrie log files
            pattern: Glob pattern to match files (default: cowrie*.gz)
            limit: Max number of files to process (for testing)
            sort_by_date: If True, process files in chronological order
                         This helps with session merging across files
        
        Yields CowrieEvent objects from all files.
        """
        dirpath = Path(dirpath)
        
        if not dirpath.exists():
            logger.error(f"Directory does not exist: {dirpath}")
            return
        
        # Find all matching files
        files = list(dirpath.glob(pattern))
        
        if not files:
            logger.warning(f"No files matching '{pattern}' in {dirpath}")
            return
        
        if sort_by_date:
            # Sort by the date in the filename
            # Filename format: cowrie.json.YYYY_M_D.gz or cowrie_json.YYYY_M_D.gz
            files = sorted(files, key=self._extract_date_from_filename)
        
        if limit:
            files = files[:limit]
        
        logger.info(f"Processing {len(files)} files from {dirpath}")
        
        for filepath in files:
            yield from self.parse_file(filepath)
    
    def _extract_date_from_filename(self, filepath: Path) -> tuple:
        """
        Extract a sortable date tuple from a Cowrie filename.
        
        Handles formats like:
        - cowrie.json.2021_1_9.gz  -> (2021, 1, 9)
        - cowrie_json.2020_10_15.gz -> (2020, 10, 15)
        
        Returns (9999, 99, 99) if we can't parse it, so those files sort last.
        """
        name = filepath.stem  # removes .gz
        if name.endswith('.json'):
            name = name[:-5]  # remove .json too if present
        
        # Try to find the date part (YYYY_M_D or YYYY_MM_DD)
        parts = name.split('.')
        for part in parts:
            if '_' in part:
                date_parts = part.split('_')
                if len(date_parts) == 3:
                    try:
                        year, month, day = int(date_parts[0]), int(date_parts[1]), int(date_parts[2])
                        return (year, month, day)
                    except ValueError:
                        continue
        
        # Couldn't parse, return a high value so it sorts last
        return (9999, 99, 99)
    
    def get_stats(self) -> dict:
        """Return parsing statistics."""
        return {
            "files_parsed": self.files_parsed,
            "events_parsed": self.events_parsed,
            "errors": self.errors,
        }
