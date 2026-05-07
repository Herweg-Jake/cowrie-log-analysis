"""Build the eight-pipeline headline table.

The table is the single most-cited artifact in the paper, so the code
here is short and the numbers come from one source of truth - the
metrics module. Don't ad-hoc additional calculations in the notebook.
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

import pandas as pd

from . import metrics as M


def _level_mae(truth, preds):
    common = sorted(set(truth) & set(preds))
    diffs = [abs(truth[s].level - preds[s].level)
             for s in common
             if truth[s].level is not None and preds[s].level is not None]
    return statistics.fmean(diffs) if diffs else None


def _cost_summary(cost_log_path):
    """Per-session $/sess + median latency, from a Phase 3 cost log."""
    if not cost_log_path or not Path(cost_log_path).exists():
        return {"cost_per_session": None, "median_latency_ms": None, "n_calls": 0}
    by_session = {}
    for line in Path(cost_log_path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        s = by_session.setdefault(r["session_id"], {"cost": 0.0, "lat": 0})
        s["cost"] += r.get("cost_usd", 0.0) or 0.0
        s["lat"] += r.get("latency_ms", 0) or 0
    if not by_session:
        return {"cost_per_session": None, "median_latency_ms": None, "n_calls": 0}
    costs = [v["cost"] for v in by_session.values()]
    lats = [v["lat"] for v in by_session.values()]
    return {
        "cost_per_session": statistics.fmean(costs),
        "median_latency_ms": statistics.median(lats),
        "n_calls": len(by_session),
    }


def evaluate_pipeline(name, truth, preds, cost_log_path=None):
    n = len(set(truth) & set(preds))
    tactic_pc = M.per_class_metrics(truth, preds, axis="tactic")
    _, t_lvl, p_lvl = M._align(truth, preds, "level")
    cost = _cost_summary(cost_log_path)
    return {
        "pipeline": name,
        "n_aligned": n,
        "tactic_accuracy": M.accuracy(truth, preds, "tactic"),
        "tactic_macro_f1": float(tactic_pc["f1"].mean()) if len(tactic_pc) else 0.0,
        "level_mae": _level_mae(truth, preds),
        "level_weighted_kappa": M.cohens_kappa(t_lvl, p_lvl, weights="linear"),
        "false_negative_rate": M.false_negative_rate(truth, preds, M.default_fn_definition),
        "cost_per_1k_sessions": (cost["cost_per_session"] * 1000 if cost["cost_per_session"] is not None else None),
        "median_latency_ms": cost["median_latency_ms"],
    }


def build_table(spec_path, truth_path, out_md, out_csv=None):
    """spec_path is JSON: a list of {name, predictions, pipeline_name, cost_log?}."""
    spec = json.loads(Path(spec_path).read_text())
    truth = M.load_annotations(truth_path)
    rows = []
    for entry in spec:
        preds = M.load_pipeline_labels(entry["predictions"], pipeline_name=entry.get("pipeline_name"))
        rows.append(evaluate_pipeline(entry["name"], truth, preds, entry.get("cost_log")))
    df = pd.DataFrame(rows)

    Path(out_md).parent.mkdir(parents=True, exist_ok=True)
    md = ["# Headline pipeline comparison",
          "",
          f"Truth: `{truth_path}` ({len(truth)} annotations)",
          ""]
    fmt = df.copy()
    for col in ("tactic_accuracy", "false_negative_rate"):
        fmt[col] = fmt[col].apply(lambda x: f"{x:.1%}" if x is not None else "n/a")
    for col in ("tactic_macro_f1", "level_weighted_kappa", "level_mae"):
        fmt[col] = fmt[col].apply(lambda x: f"{x:.3f}" if isinstance(x, (int, float)) else "n/a")
    for col in ("cost_per_1k_sessions",):
        fmt[col] = fmt[col].apply(lambda x: f"${x:.4f}" if isinstance(x, (int, float)) else "n/a")
    fmt["median_latency_ms"] = fmt["median_latency_ms"].apply(
        lambda x: f"{int(x)}" if isinstance(x, (int, float)) else "n/a")
    md.append(fmt.to_markdown(index=False))
    Path(out_md).write_text("\n".join(md) + "\n")

    if out_csv:
        Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(out_csv, index=False)


def cli(argv=None):
    ap = argparse.ArgumentParser(prog="cowrie_dataset.cli headline")
    ap.add_argument("--spec", required=True,
                    help="JSON list of pipelines: [{name, predictions, pipeline_name, cost_log}]")
    ap.add_argument("--truth", required=True)
    ap.add_argument("--out-md", required=True)
    ap.add_argument("--out-csv", default=None)
    args = ap.parse_args(argv)
    build_table(args.spec, args.truth, args.out_md, args.out_csv)
    print(f"wrote {args.out_md}")


if __name__ == "__main__":
    cli()
