#!/usr/bin/env python3
"""
Run the agent pipeline on exported sessions.

Usage:
    # Process all sessions
    python scripts/run_agent_pipeline.py --input sessions.jsonl --output labeled.jsonl

    # With trained anomaly detector
    python scripts/run_agent_pipeline.py --input sessions.jsonl --output labeled.jsonl \
        --anomaly-stats anomaly_stats.json

    # Dry run (no API calls)
    python scripts/run_agent_pipeline.py --input sessions.jsonl --output labeled.jsonl --dry-run

    # Crank up concurrency (default 50, max bounded by your RPM limit)
    python scripts/run_agent_pipeline.py --input sessions.jsonl --output labeled.jsonl --concurrency 80
"""

import argparse
import os
from pathlib import Path


def _load_env():
    """Load .env file from project root if it exists."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Don't override existing env vars
            if key not in os.environ:
                os.environ[key] = value


_load_env()
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:
    # Fallback if tqdm not installed
    def tqdm(iterable, **kwargs):
        total = kwargs.get('total', 0)
        for i, item in enumerate(iterable):
            if i % 100 == 0:
                print(f"Progress: {i}/{total}")
            yield item

from cowrie_dataset.anomaly.statistical_detector import (
    StatisticalAnomalyDetector,
    add_anomaly_flag,
)
from cowrie_dataset.agents import AgentConfig, AgentRunner


def process_session(runner, session):
    """Process a single session through the pipeline. Runs in a worker thread."""
    result = runner.process(session)
    session["labels_agentic"] = result.to_dict()
    return session, result


def main():
    parser = argparse.ArgumentParser(description="Run agent pipeline")
    parser.add_argument("--input", "-i", required=True, help="Input JSONL file")
    parser.add_argument("--output", "-o", required=True, help="Output JSONL file")
    parser.add_argument("--anomaly-stats", help="Pre-trained anomaly detector stats")
    parser.add_argument("--z-threshold", type=float, default=3.0)
    parser.add_argument("--model", default=None, help="Override model (defaults to AgentConfig default)")
    parser.add_argument("--dry-run", action="store_true", help="Skip API calls")
    parser.add_argument("--limit", type=int, help="Limit number of sessions")
    parser.add_argument("--concurrency", type=int, default=50,
                        help="Number of concurrent API requests (default 50)")
    parser.add_argument("--skip-non-anomalous", action="store_true", default=True,
                        help="Only process sessions flagged as statistical anomalies")
    args = parser.parse_args()

    # Load or create anomaly detector
    if args.anomaly_stats:
        print(f"Loading anomaly detector from {args.anomaly_stats}...")
        detector = StatisticalAnomalyDetector.load(Path(args.anomaly_stats))
    else:
        print("No anomaly stats provided, will flag all sessions as anomalous")
        detector = None

    # Setup agent runner
    if args.dry_run:
        print("DRY RUN - no API calls will be made")
        runner = None
    else:
        config = AgentConfig(**({"model": args.model} if args.model else {}))
        runner = AgentRunner(config=config, skip_non_anomalous=args.skip_non_anomalous)
        print(f"Using {config.model} with {config.requests_per_minute} RPM limit, "
              f"{args.concurrency} concurrent workers")

    # Count input lines
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        return 1

    line_count = sum(1 for _ in open(input_path))
    if args.limit:
        line_count = min(line_count, args.limit)

    print(f"Processing {line_count} sessions...")

    # Process sessions
    output_path = Path(args.output)
    processed = 0
    anomalous_count = 0
    relevant_count = 0
    write_lock = threading.Lock()

    with open(input_path) as f_in, open(output_path, 'w') as f_out:
        pbar = tqdm(total=line_count)

        if not runner:
            # Dry run - no concurrency needed
            for i, line in enumerate(f_in):
                if args.limit and i >= args.limit:
                    break

                session = json.loads(line)

                if detector:
                    session = add_anomaly_flag(session, detector)
                else:
                    session["statistical_anomaly"] = {
                        "is_anomaly": True,
                        "score": 0.0,
                        "reasons": ["No detector - flagging all"],
                        "z_scores": {},
                    }

                if session.get("statistical_anomaly", {}).get("is_anomaly", False):
                    anomalous_count += 1

                session["labels_agentic"] = {
                    "dry_run": True,
                    "was_anomaly": session.get("statistical_anomaly", {}).get("is_anomaly", False),
                }

                f_out.write(json.dumps(session) + '\n')
                processed += 1
                pbar.update(1)
        else:
            # Concurrent processing - fire off API calls in parallel
            pending = set()

            def handle_result(future):
                """Write result and update counters when a future completes."""
                nonlocal processed, relevant_count
                try:
                    session_out, result = future.result()
                    with write_lock:
                        f_out.write(json.dumps(session_out) + '\n')
                    if result.hunter_verdict == "RELEVANT":
                        relevant_count += 1
                    processed += 1
                except Exception as e:
                    processed += 1
                    print(f"\nError processing session: {e}")
                pbar.update(1)

            with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                for i, line in enumerate(f_in):
                    if args.limit and i >= args.limit:
                        break

                    session = json.loads(line)

                    if detector:
                        session = add_anomaly_flag(session, detector)
                    else:
                        session["statistical_anomaly"] = {
                            "is_anomaly": True,
                            "score": 0.0,
                            "reasons": ["No detector - flagging all"],
                            "z_scores": {},
                        }

                    if session.get("statistical_anomaly", {}).get("is_anomaly", False):
                        anomalous_count += 1

                    future = executor.submit(process_session, runner, session)
                    pending.add(future)

                    # drain completed futures to keep memory bounded
                    if len(pending) >= args.concurrency * 2:
                        done = {f for f in pending if f.done()}
                        for f in done:
                            handle_result(f)
                        pending -= done

                # flush remaining futures
                for f in as_completed(pending):
                    handle_result(f)

        pbar.close()

    print(f"\n{'='*60}")
    print(f"Processed {processed} sessions")
    print(f"Anomalous sessions: {anomalous_count}")

    if args.dry_run:
        print("\nDRY RUN complete - no API calls were made")
        print(f"Output written to: {output_path}")
    elif runner:
        stats = runner.get_stats()
        print("\nPipeline Statistics:")
        print(f"  Anomaly rate: {stats['anomaly_rate']:.1%}")
        print(f"  Hunter filter rate: {stats['hunter_filter_rate']:.1%}")
        print(f"  Sessions marked RELEVANT: {relevant_count}")
        print(f"  Fully analyzed by Analyst: {stats['sessions_fully_analyzed']}")
        print(f"  Total cost: ${stats['total_cost_usd']:.4f}")
        print(f"  Avg latency: {stats['avg_latency_per_session_ms']:.0f}ms")
        print(f"  Errors: {stats['errors']}")

    print(f"\nOutput written to: {output_path}")
    print(f"{'='*60}")

    return 0


if __name__ == "__main__":
    exit(main())
