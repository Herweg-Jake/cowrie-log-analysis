#!/usr/bin/env python3
"""Quick parse-rate check for a local Ollama model.

Phase 4 acceptance: structured JSON output on >=90% of sessions, otherwise
the model can't handle the prompt and we pick a different one. Run this
on a 10-session subsample before committing to a full B-Local run.

Usage:
    python scripts/local_llm_smoke.py --model qwen2.5:7b-instruct \\
        --input annotation_sample_blind.jsonl --n 10
"""

import argparse
import json
import sys
from pathlib import Path

# Make 'src' importable when run from the repo root without an install.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cowrie_dataset.agents import AgentConfig, AgentRunner


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="Ollama model tag, e.g. qwen2.5:7b-instruct")
    ap.add_argument("--input", required=True, help="Sessions JSONL")
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--base-url", default=None,
                    help="Override OLLAMA_BASE_URL for this run")
    args = ap.parse_args()

    if args.base_url:
        import os
        os.environ["OLLAMA_BASE_URL"] = args.base_url

    config = AgentConfig(provider="ollama", model=args.model,
                         requests_per_minute=600,  # local is rate-limited by GPU not API
                         retry_attempts=2, retry_delay=1.0)
    runner = AgentRunner(config=config, skip_non_anomalous=False)

    sessions = []
    with open(args.input) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            sessions.append(json.loads(line))
            if len(sessions) >= args.n:
                break

    if not sessions:
        sys.exit("no sessions loaded")

    parsed_ok = 0
    errors = []
    for s in sessions:
        # Force the runner to call the agents regardless of anomaly flag.
        s.setdefault("statistical_anomaly", {"is_anomaly": True, "score": 1.0})
        result = runner.process(s)
        analyst = (result.labels_agentic or {}).get("analyst_verdict")
        if analyst and analyst.get("primary_tactic"):
            parsed_ok += 1
        else:
            errors.append(result.labels_agentic.get("error") or "no analyst verdict")

    rate = parsed_ok / len(sessions)
    print(f"parse rate: {parsed_ok}/{len(sessions)} = {rate:.0%}")
    if errors:
        print("first few errors:")
        for e in errors[:3]:
            print(f"  - {e}")
    print(f"verdict: {'OK (>= 90%)' if rate >= 0.9 else 'FAIL - pick a different model'}")
    return 0 if rate >= 0.9 else 1


if __name__ == "__main__":
    sys.exit(main())
