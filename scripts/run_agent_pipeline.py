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
"""

import argparse
import json
import os
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


def main():
    parser = argparse.ArgumentParser(description="Run agent pipeline")
    parser.add_argument("--input", "-i", required=True, help="Input JSONL file")
    parser.add_argument("--output", "-o", required=True, help="Output JSONL file")
    parser.add_argument("--anomaly-stats", help="Pre-trained anomaly detector stats")
    parser.add_argument("--z-threshold", type=float, default=3.0)
    parser.add_argument("--model", default="claude-sonnet-4-20250514")
    parser.add_argument("--dry-run", action="store_true", help="Skip API calls")
    parser.add_argument("--limit", type=int, help="Limit number of sessions")
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
        config = AgentConfig(model=args.model)
        runner = AgentRunner(config=config, skip_non_anomalous=args.skip_non_anomalous)

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

    with open(input_path) as f_in, open(output_path, 'w') as f_out:
        for i, line in enumerate(tqdm(f_in, total=line_count)):
            if args.limit and i >= args.limit:
                break

            session = json.loads(line)

            # Add anomaly flag if detector available
            if detector:
                session = add_anomaly_flag(session, detector)
            else:
                # Flag everything as anomalous for testing
                session["statistical_anomaly"] = {
                    "is_anomaly": True,
                    "score": 0.0,
                    "reasons": ["No detector - flagging all"],
                    "z_scores": {},
                }

            # Track anomalies
            if session.get("statistical_anomaly", {}).get("is_anomaly", False):
                anomalous_count += 1

            # Run agent pipeline
            if runner:
                result = runner.process(session)
                session["labels_agentic"] = result.to_dict()
                
                # Track relevant sessions
                if result.hunter_verdict == "RELEVANT":
                    relevant_count += 1
            else:
                # Dry run - add placeholder
                session["labels_agentic"] = {
                    "dry_run": True,
                    "was_anomaly": session.get("statistical_anomaly", {}).get("is_anomaly", False),
                }

            # Write output
            f_out.write(json.dumps(session) + '\n')
            processed += 1

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
