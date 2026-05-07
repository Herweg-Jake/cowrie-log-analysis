"""Pipeline E - majority vote across LLM variants.

Bonus pipeline: average is often better than any single model. Ties on
tactic break by highest mean confidence among voters; level uses the
median (rounded) of voters that agreed on the tactic.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path

from . import metrics as M


def majority_vote(label_paths_with_names, output_path, ensemble_name="ensemble"):
    """label_paths_with_names: list of (jsonl_path, pipeline_name)."""
    loaded = []
    all_ids = set()
    for path, name in label_paths_with_names:
        d = M.load_pipeline_labels(path, pipeline_name=name)
        loaded.append(d)
        all_ids |= set(d)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    n_written = 0
    with open(output_path, "w") as out:
        for sid in sorted(all_ids):
            voters = [d[sid] for d in loaded if sid in d]
            if not voters:
                continue
            tactic_counts: Counter = Counter()
            tactic_conf: dict[str, list[float]] = {}
            for v in voters:
                tactic_counts[v.tactic] += 1
                tactic_conf.setdefault(v.tactic, []).append(v.confidence or 0.0)
            top_count = max(tactic_counts.values())
            top = [t for t, c in tactic_counts.items() if c == top_count]
            if len(top) == 1:
                tactic = top[0]
            else:
                # tie-break: highest mean confidence among the tied tactics
                tactic = max(top, key=lambda t: statistics.fmean(tactic_conf[t]))
            agreeing = [v for v in voters if v.tactic == tactic]
            levels = [v.level for v in agreeing if v.level is not None]
            level = int(round(statistics.median(levels))) if levels else None
            confidence = statistics.fmean([v.confidence for v in agreeing if v.confidence is not None]) \
                if any(v.confidence is not None for v in agreeing) else None

            out.write(json.dumps({
                "session_id": sid,
                f"label_{ensemble_name}": {
                    "primary_tactic": tactic,
                    "threat_level": level,
                    "confidence": confidence,
                    "n_voters": len(voters),
                    "n_agreeing": len(agreeing),
                },
            }) + "\n")
            n_written += 1
    return n_written


def cli(argv=None):
    ap = argparse.ArgumentParser(prog="cowrie_dataset.cli ensemble")
    ap.add_argument("--inputs", nargs="+", required=True,
                    help="One or more <path>:<pipeline_name> entries")
    ap.add_argument("--output", required=True)
    ap.add_argument("--name", default="ensemble")
    args = ap.parse_args(argv)
    pairs = []
    for entry in args.inputs:
        if ":" not in entry:
            raise SystemExit(f"--inputs entries must look like path:pipeline_name (got {entry!r})")
        path, name = entry.rsplit(":", 1)
        pairs.append((path, name))
    n = majority_vote(pairs, args.output, ensemble_name=args.name)
    print(f"wrote {n} ensemble predictions -> {args.output}")


if __name__ == "__main__":
    cli()
