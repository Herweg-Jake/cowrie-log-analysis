"""Pareto and calibration figures.

Matplotlib only. Seaborn would prettier but it's an extra dep and these
plots are simple enough not to need it. Each function takes a row-shaped
DataFrame so the caller can pre-filter or re-order without touching us.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # headless boxes; figures get saved, not shown
import matplotlib.pyplot as plt
import pandas as pd

from . import metrics as M


def _is_dominated(row, df):
    """Strict domination: another point is >= on F1 AND <= on cost, with at least one strict."""
    for _, other in df.iterrows():
        if other.name == row.name:
            continue
        if (other["tactic_macro_f1"] >= row["tactic_macro_f1"]
                and other["cost_per_1k_sessions"] <= row["cost_per_1k_sessions"]
                and (other["tactic_macro_f1"] > row["tactic_macro_f1"]
                     or other["cost_per_1k_sessions"] < row["cost_per_1k_sessions"])):
            return True
    return False


def pareto_plot(headline_csv, out_path):
    """Cost vs macro-F1, log-x. Pareto frontier highlighted."""
    df = pd.read_csv(headline_csv)
    df = df.dropna(subset=["tactic_macro_f1", "cost_per_1k_sessions"]).copy()
    if df.empty:
        raise SystemExit("no rows with both cost and F1; cannot draw Pareto plot")

    df["dominated"] = df.apply(lambda r: _is_dominated(r, df), axis=1)

    fig, ax = plt.subplots(figsize=(7, 5))
    nondom = df[~df["dominated"]].sort_values("cost_per_1k_sessions")
    dom = df[df["dominated"]]

    if not nondom.empty:
        ax.plot(nondom["cost_per_1k_sessions"], nondom["tactic_macro_f1"],
                "-", color="#444", linewidth=1, label="Pareto frontier")
        ax.scatter(nondom["cost_per_1k_sessions"], nondom["tactic_macro_f1"],
                   s=80, c="#1f77b4", zorder=3, label="non-dominated")
    if not dom.empty:
        ax.scatter(dom["cost_per_1k_sessions"], dom["tactic_macro_f1"],
                   s=60, c="#bbb", marker="x", label="dominated")

    for _, r in df.iterrows():
        ax.annotate(r["pipeline"], (r["cost_per_1k_sessions"], r["tactic_macro_f1"]),
                    xytext=(5, 5), textcoords="offset points", fontsize=9)

    ax.set_xscale("log")
    ax.set_xlabel("$ per 1k sessions (log scale)")
    ax.set_ylabel("Tactic macro F1")
    ax.set_title("Cost-quality Pareto")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    pdf_path = Path(out_path).with_suffix(".pdf")
    fig.savefig(pdf_path)
    plt.close(fig)


def calibration_plot(truth_path, predictions_path, pipeline_name, out_path,
                     n_bins=10, axis="tactic"):
    truth = M.load_annotations(truth_path)
    preds = M.load_pipeline_labels(predictions_path, pipeline_name=pipeline_name)
    rel = M.calibration_curve(truth, preds, axis=axis, n_bins=n_bins)
    if rel.empty:
        raise SystemExit("no confidence values in predictions; cannot calibrate")

    ece = M.expected_calibration_error(rel)
    fig, ax = plt.subplots(figsize=(5.5, 5.5))
    ax.plot([0, 1], [0, 1], "--", color="#aaa", label="perfect")
    ax.plot(rel["mean_confidence"], rel["accuracy"], "o-",
            color="#d62728", label=f"{pipeline_name}")
    for _, r in rel.iterrows():
        if r["n"] > 0:
            ax.annotate(f"n={int(r['n'])}",
                        (r["mean_confidence"], r["accuracy"]),
                        xytext=(4, -10), textcoords="offset points", fontsize=8)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.set_xlabel("predicted confidence")
    ax.set_ylabel("empirical accuracy")
    ax.set_title(f"Reliability: {pipeline_name}  (ECE = {ece:.3f})")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return {"pipeline": pipeline_name, "ece": ece, "n_bins": int((rel["n"] > 0).sum())}


def cli(argv=None):
    ap = argparse.ArgumentParser(prog="cowrie_dataset.cli figures")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pareto")
    p.add_argument("--headline-csv", required=True)
    p.add_argument("--output", required=True)

    c = sub.add_parser("calibration")
    c.add_argument("--truth", required=True)
    c.add_argument("--predictions", required=True)
    c.add_argument("--pipeline-name", required=True)
    c.add_argument("--output", required=True)
    c.add_argument("--axis", default="tactic", choices=["tactic", "level"])
    c.add_argument("--bins", type=int, default=10)

    args = ap.parse_args(argv)
    if args.cmd == "pareto":
        pareto_plot(args.headline_csv, args.output)
        print(f"wrote {args.output}")
    else:
        out = calibration_plot(args.truth, args.predictions, args.pipeline_name,
                               args.output, n_bins=args.bins, axis=args.axis)
        print(f"wrote {args.output}  (ECE = {out['ece']:.3f})")


if __name__ == "__main__":
    cli()
