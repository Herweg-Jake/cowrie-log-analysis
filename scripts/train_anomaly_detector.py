#!/usr/bin/env python3
"""
Train the statistical anomaly detector on historical sessions.

This builds a baseline of "what normal looks like" so we can flag the
weird sessions for expensive LLM analysis. Run this on a big chunk of
your historical data before deploying the agent pipeline.

Usage:
    python scripts/train_anomaly_detector.py -i sessions.jsonl -o stats.json

    # with custom thresholds
    python scripts/train_anomaly_detector.py -i sessions.jsonl -o stats.json \
        --z-threshold 2.5 --min-samples 50
"""

import argparse
import json
import sys
from pathlib import Path

# add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cowrie_dataset.anomaly import StatisticalAnomalyDetector


def main():
    parser = argparse.ArgumentParser(
        description="Train anomaly detector on historical sessions"
    )
    parser.add_argument(
        "--input", "-i",
        type=Path,
        required=True,
        help="Input JSONL file with exported sessions",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        required=True,
        help="Output JSON file for trained stats",
    )
    parser.add_argument(
        "--z-threshold",
        type=float,
        default=3.0,
        help="Z-score threshold for anomaly (default: 3.0 = 99.7%% coverage)",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=100,
        help="Min samples before trusting stats (default: 100)",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: input file not found: {args.input}")
        sys.exit(1)

    detector = StatisticalAnomalyDetector(
        z_threshold=args.z_threshold,
        min_samples=args.min_samples,
    )

    # count lines first for progress
    print(f"Counting sessions in {args.input}...")
    line_count = sum(1 for _ in open(args.input))
    print(f"Found {line_count:,} sessions")

    # train
    print("Training...")
    processed = 0
    with open(args.input) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            session = json.loads(line)
            features = session.get("features", {})
            detector.train(features)
            processed += 1

            # progress every 10k
            if processed % 10000 == 0:
                pct = processed / line_count * 100
                print(f"  {processed:,} / {line_count:,} ({pct:.0f}%)")

    # save
    detector.save(args.output)

    # summary
    print(f"\nDone! Processed {processed:,} sessions")
    print(f"Trained: {detector.is_trained}")
    print(f"Saved to: {args.output}")
    print(f"\n{detector.summary()}")


if __name__ == "__main__":
    main()
