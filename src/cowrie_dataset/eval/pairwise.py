"""Pairwise McNemar matrix + bootstrap F1 deltas across pipelines.

Outputs a triangular CSV. Symmetric entries are blank so the file
collapses cleanly when opened in a spreadsheet.
"""

from __future__ import annotations

import argparse
import csv
import json
from itertools import combinations
from pathlib import Path

from . import metrics as M


def _correctness(truth, preds, axis):
    common = sorted(set(truth) & set(preds))
    return common, [
        M._value(truth[s], axis) == M._value(preds[s], axis)
        for s in common
    ]


def pairwise_mcnemar(spec_path, truth_path, out_csv, axis="tactic"):
    spec = json.loads(Path(spec_path).read_text())
    truth = M.load_annotations(truth_path)
    pipelines = []
    for entry in spec:
        preds = M.load_pipeline_labels(entry["predictions"], pipeline_name=entry.get("pipeline_name"))
        ids, correct = _correctness(truth, preds, axis)
        pipelines.append({"name": entry["name"], "ids": ids, "correct": dict(zip(ids, correct))})

    names = [p["name"] for p in pipelines]
    rows = [["pipeline"] + names]
    for i, a in enumerate(pipelines):
        row = [a["name"]]
        for j, b in enumerate(pipelines):
            if j <= i:
                row.append("")
                continue
            common = sorted(set(a["ids"]) & set(b["ids"]))
            ac = [a["correct"][s] for s in common]
            bc = [b["correct"][s] for s in common]
            res = M.mcnemar(ac, bc)
            row.append(f"p={res['p_value']:.4f}; b={res['b']}, c={res['c']}")
        rows.append(row)

    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        csv.writer(f).writerows(rows)


def cli(argv=None):
    ap = argparse.ArgumentParser(prog="cowrie_dataset.cli pairwise_mcnemar")
    ap.add_argument("--spec", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--axis", default="tactic", choices=["tactic", "level"])
    args = ap.parse_args(argv)
    pairwise_mcnemar(args.spec, args.truth, args.output, axis=args.axis)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    cli()
