#!/usr/bin/env python3
"""
MVP Test Script - Quick way to test the pipeline on a few files.

This script is standalone - you can run it directly without installing
the package. It's useful for initial testing and debugging.

Usage:
    # Test with a single file
    python scripts/run_mvp_test.py /path/to/cowrie.json.2021_1_9.gz

    # Test with a directory (processes first 10 files)
    python scripts/run_mvp_test.py /opt/honeypot/ssh-amsterdam --limit 10

    # Test with dry run (no ES needed)
    python scripts/run_mvp_test.py /path/to/data --dry-run --print
"""

import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime

# Add the src directory to the path so we can import our modules
script_dir = Path(__file__).parent
project_root = script_dir.parent
sys.path.insert(0, str(project_root / "src"))

from cowrie_dataset.parsers import CowrieParser
from cowrie_dataset.aggregators import SessionAggregator
from cowrie_dataset.features import extract_message_features, extract_host_features
from cowrie_dataset.labeling import MitreLabeler


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def process_file(filepath: Path) -> list:
    """Process a single file and return sessions."""
    logger = logging.getLogger(__name__)
    logger.info(f"Processing file: {filepath}")
    
    parser = CowrieParser()
    aggregator = SessionAggregator(location="test")
    
    sessions = []
    
    for event in parser.parse_file(filepath):
        completed = aggregator.add_event(event)
        sessions.extend(completed)
    
    # Flush remaining
    sessions.extend(aggregator.flush())
    
    logger.info(f"Parser stats: {parser.get_stats()}")
    logger.info(f"Aggregator stats: {aggregator.get_stats()}")
    
    return sessions


def process_directory(dirpath: Path, limit: int = 10) -> list:
    """Process files from a directory and return sessions."""
    logger = logging.getLogger(__name__)
    logger.info(f"Processing directory: {dirpath} (limit: {limit})")
    
    parser = CowrieParser()
    aggregator = SessionAggregator(location=dirpath.name)
    
    sessions = []
    
    for event in parser.parse_directory(dirpath, limit=limit, sort_by_date=True):
        completed = aggregator.add_event(event)
        sessions.extend(completed)
    
    sessions.extend(aggregator.flush())
    
    logger.info(f"Parser stats: {parser.get_stats()}")
    logger.info(f"Aggregator stats: {aggregator.get_stats()}")
    
    return sessions


def analyze_sessions(sessions: list, print_samples: bool = False, num_samples: int = 3):
    """Analyze sessions and print statistics."""
    logger = logging.getLogger(__name__)
    labeler = MitreLabeler()
    
    if not sessions:
        logger.warning("No sessions to analyze!")
        return
    
    # Compute features and labels for all sessions
    results = []
    for session in sessions:
        msg_features = extract_message_features(session)
        host_features = extract_host_features(session)
        label = labeler.label(session)
        
        results.append({
            "session": session,
            "msg_features": msg_features,
            "host_features": host_features,
            "label": label,
        })
    
    # Print overall stats
    print("\n" + "="*60)
    print("SESSION ANALYSIS RESULTS")
    print("="*60)
    
    print(f"\nTotal sessions: {len(sessions)}")
    
    # Session type breakdown
    session_types = {}
    for r in results:
        st = r["session"].get_session_type()
        session_types[st] = session_types.get(st, 0) + 1
    
    print("\nSession types:")
    for st, count in sorted(session_types.items()):
        print(f"  {st}: {count}")
    
    # Level breakdown
    levels = {}
    for r in results:
        lvl = r["label"].level
        levels[lvl] = levels.get(lvl, 0) + 1
    
    print("\nThreat levels:")
    for lvl in [1, 2, 3]:
        count = levels.get(lvl, 0)
        pct = (count / len(results)) * 100 if results else 0
        print(f"  Level {lvl}: {count} ({pct:.1f}%)")
    
    # Tactic breakdown
    tactics = {}
    for r in results:
        for t in r["label"].all_tactics:
            tactics[t] = tactics.get(t, 0) + 1
    
    print("\nTactics detected:")
    for tactic, count in sorted(tactics.items(), key=lambda x: -x[1]):
        print(f"  {tactic}: {count}")
    
    # Feature stats for sessions with commands
    sessions_with_cmds = [r for r in results if r["session"].commands]
    if sessions_with_cmds:
        print("\nFeature stats (sessions with commands):")
        
        # Average command count
        avg_cmds = sum(len(r["session"].commands) for r in sessions_with_cmds) / len(sessions_with_cmds)
        print(f"  Avg commands per session: {avg_cmds:.1f}")
        
        # Average message length
        avg_len = sum(r["msg_features"]["F37_message_length"] for r in sessions_with_cmds) / len(sessions_with_cmds)
        print(f"  Avg message length: {avg_len:.1f}")
        
        # Sessions with downloads
        with_downloads = sum(1 for r in sessions_with_cmds if r["session"].downloads)
        print(f"  Sessions with downloads: {with_downloads}")
    
    # Print sample sessions
    if print_samples:
        print("\n" + "="*60)
        print(f"SAMPLE SESSIONS (first {num_samples})")
        print("="*60)
        
        for i, r in enumerate(results[:num_samples]):
            session = r["session"]
            label = r["label"]
            
            print(f"\n--- Session {i+1}: {session.session_id} ---")
            print(f"Type: {session.get_session_type()}")
            print(f"Source IP: {session.src_ip}")
            print(f"Duration: {session.get_computed_duration():.1f}s")
            print(f"Auth success: {session.auth_success}")
            print(f"Username: {session.final_username}")
            print(f"Commands: {len(session.commands)}")
            print(f"Downloads: {len(session.downloads)}")
            print(f"Label: Level {label.level} - {label.primary_tactic}")
            print(f"All tactics: {label.all_tactics}")
            
            if session.commands:
                print("Sample commands:")
                for cmd in session.commands[:5]:
                    cmd_text = cmd["input"][:80] + "..." if len(cmd["input"]) > 80 else cmd["input"]
                    print(f"  > {cmd_text}")
    
    # Export a sample document
    print("\n" + "="*60)
    print("SAMPLE DOCUMENT (JSON)")
    print("="*60)
    
    if results:
        sample = results[0]
        doc = sample["session"].to_dict()
        doc["features"] = {**sample["msg_features"], **sample["host_features"]}
        doc["labels"] = sample["label"].to_dict()
        
        print(json.dumps(doc, indent=2, default=str))


def main():
    parser = argparse.ArgumentParser(description="MVP test script for Cowrie pipeline")
    parser.add_argument("path", help="Path to a .gz file or directory")
    parser.add_argument("--limit", "-n", type=int, default=10, help="Max files to process")
    parser.add_argument("--print", "-p", action="store_true", help="Print sample sessions")
    parser.add_argument("--samples", type=int, default=3, help="Number of samples to print")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    setup_logging(args.verbose)
    
    path = Path(args.path)
    
    if not path.exists():
        print(f"Error: Path does not exist: {path}")
        sys.exit(1)
    
    start_time = datetime.now()
    
    if path.is_file():
        sessions = process_file(path)
    else:
        sessions = process_directory(path, limit=args.limit)
    
    elapsed = datetime.now() - start_time
    print(f"\nProcessing time: {elapsed}")
    
    analyze_sessions(sessions, print_samples=args.print, num_samples=args.samples)


if __name__ == "__main__":
    main()
