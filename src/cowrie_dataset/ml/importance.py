"""Top-feature importances for the tactic head.

Saves the result as a CSV that the paper's analysis directory expects.
SHAP would be nicer than gain/split, but it pulls in extra deps; gain
importance from LightGBM is good enough for the "is the model degenerate"
check the plan calls out.
"""

from __future__ import annotations

import csv
import pickle
from pathlib import Path


def export_importance(model_path: str, out_csv: str, top_n: int = 20):
    with open(model_path, "rb") as f:
        payload = pickle.load(f)
    feats = payload["feature_order"]
    booster = payload["tactic"]["model"].booster_
    gains = booster.feature_importance(importance_type="gain")
    splits = booster.feature_importance(importance_type="split")
    rows = sorted(zip(feats, gains, splits), key=lambda r: r[1], reverse=True)[:top_n]

    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["feature", "gain", "split"])
        for feat, g, s in rows:
            w.writerow([feat, f"{g:.4f}", int(s)])


def cli(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="cowrie_dataset.cli ml_importance")
    ap.add_argument("--model", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--top", type=int, default=20)
    args = ap.parse_args(argv)
    export_importance(args.model, args.output, args.top)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    cli()
