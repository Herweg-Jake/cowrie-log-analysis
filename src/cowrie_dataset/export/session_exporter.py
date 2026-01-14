"""
Session Exporter - standardizes session data for both pipelines.

This is the "single source of truth" that feeds both the rule-based
baseline (Pipeline A) and the agentic analysis (Pipeline B). By having
one export format, we ensure fair comparison between the two approaches.

The exported format flattens the nested Session structure into something
that's easier to work with in ML pipelines and Elasticsearch.
"""

import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Iterator, Optional

from ..aggregators import Session
from ..features import extract_message_features, extract_host_features, extract_geo_features
from ..labeling import label_session


@dataclass
class ExportedSession:
    """
    Flat, standardized session format for analysis.

    This combines raw session data, computed features, and rule-based labels
    into a single structure. The agentic pipeline will add its own labels
    to this later.
    """

    # identifiers
    session_id: str
    location: str

    # timing
    start_ts: Optional[str]
    end_ts: Optional[str]
    duration_s: float

    # network stuff
    src_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "ssh" or "telnet"

    # auth info
    auth_success: bool
    login_attempts: list[dict]
    final_username: Optional[str]
    final_password: Optional[str]

    # what the attacker did
    commands: list[dict]
    downloads: list[dict]
    uploads: list[dict]

    # ssh fingerprinting
    ssh_version: Optional[str]
    hassh: Optional[str]

    # pre-computed features (the F1-F52 stuff)
    features: dict

    # rule-based labels (Pipeline A output)
    labels_rule_based: dict

    # geo data (might be empty if no maxmind db)
    geo: dict

    # metadata
    session_type: str
    event_count: int

    def to_dict(self) -> dict:
        """Convert to plain dict - useful for JSON/ES."""
        return asdict(self)

    def to_json(self, compact: bool = False) -> str:
        """
        JSON string representation.

        compact=True gives single-line output for JSONL files.
        compact=False gives pretty-printed output for debugging.
        """
        if compact:
            return json.dumps(self.to_dict(), default=str)
        return json.dumps(self.to_dict(), default=str, indent=2)


def export_session(session: Session, geo_enricher=None) -> ExportedSession:
    """
    Transform a raw Session into the standardized export format.

    This merges:
    - Raw session data (IPs, commands, downloads, etc.)
    - Computed features (F1-F52)
    - Rule-based MITRE labels
    - Optional geo enrichment

    The result can be fed to either pipeline for analysis.
    """
    # grab all the features
    msg_features = extract_message_features(session)
    host_features = extract_host_features(session)
    geo_features = extract_geo_features(session, geo_enricher) if geo_enricher else {}

    # merge feature dicts - host features override message features if there's overlap
    all_features = {**msg_features, **host_features}

    # get rule-based labels (this is our baseline)
    label = label_session(session)

    # figure out protocol from port
    protocol = "telnet" if session.dst_port == 23 else "ssh"

    # format login attempts consistently
    login_attempts = [
        {"username": u, "password": p, "success": s}
        for u, p, s in session.login_attempts
    ]

    return ExportedSession(
        session_id=session.session_id,
        location=session.location,
        start_ts=session.start_ts.isoformat() if session.start_ts else None,
        end_ts=session.end_ts.isoformat() if session.end_ts else None,
        duration_s=session.get_computed_duration(),
        src_ip=session.src_ip,
        src_port=session.src_port or 0,
        dst_port=session.dst_port or 22,
        protocol=protocol,
        auth_success=session.auth_success,
        login_attempts=login_attempts,
        final_username=session.final_username,
        final_password=session.final_password,
        commands=session.commands,
        downloads=session.downloads,
        uploads=session.uploads,
        ssh_version=session.ssh_version,
        hassh=session.hassh,
        features=all_features,
        labels_rule_based=label.to_dict(),
        geo=geo_features,
        session_type=session.get_session_type(),
        event_count=session.event_count,
    )


def export_sessions_to_jsonl(
    sessions: Iterator[Session],
    output_path: Path,
    geo_enricher=None,
    progress_callback=None,
) -> int:
    """
    Bulk export sessions to a JSONL file (one JSON object per line).

    JSONL is nice because:
    - Easy to process line-by-line (memory efficient)
    - Easy to parallelize
    - Easy to append to
    - Works well with unix tools (grep, head, tail, wc -l)

    Args:
        sessions: Iterator of Session objects
        output_path: Where to write the JSONL file
        geo_enricher: Optional GeoEnricher for IP->location mapping
        progress_callback: Optional fn(count) called every 1000 sessions

    Returns:
        Number of sessions exported
    """
    count = 0
    output_path = Path(output_path)

    with open(output_path, 'w') as f:
        for session in sessions:
            exported = export_session(session, geo_enricher)
            # compact JSON - one line per session
            f.write(exported.to_json(compact=True) + '\n')
            count += 1

            if progress_callback and count % 1000 == 0:
                progress_callback(count)

    return count


def load_sessions_from_jsonl(input_path: Path) -> Iterator[dict]:
    """
    Load sessions from a JSONL file.

    Yields dicts (not ExportedSession objects) since that's what
    downstream code usually wants anyway.
    """
    with open(input_path) as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)
