"""``python -m cowrie_dataset.cli evaluate ...``

Writes one machine-readable JSON, one human Markdown summary, and a CSV
confusion per axis. Output paths are derived from --output (which is
treated as a directory if it exists or ends with a slash, else as the
JSON file path and siblings get sensible names).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import metrics as M


def _resolve_outputs(out: str, pipeline: str):
    p = Path(out)
    if p.is_dir() or out.endswith("/"):
        p.mkdir(parents=True, exist_ok=True)
        base = p / f"metrics_{pipeline}"
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        base = p.with_suffix("")
    return {
        "json": base.with_suffix(".json"),
        "md": base.with_suffix(".md"),
        "conf_tactic": base.parent / f"confusion_{pipeline}_tactic.csv",
        "conf_level": base.parent / f"confusion_{pipeline}_level.csv",
    }


def _summary_md(pipeline, n, tactic_acc, tactic_macro, level_acc, level_kappa,
                level_mae, fn_rate, per_class_tactic, per_class_level):
    lines = [
        f"# Metrics: {pipeline}",
        "",
        f"- aligned sessions: **{n}**",
        f"- tactic accuracy: **{tactic_acc:.1%}**",
        f"- tactic macro F1: **{tactic_macro:.3f}**",
        f"- level accuracy: **{level_acc:.1%}**",
        f"- level weighted kappa: **{_fmt(level_kappa)}**",
        f"- level MAE: **{_fmt(level_mae)}**",
        f"- false-negative rate (silent miss): **{fn_rate:.1%}**",
        "",
        "## Per-tactic",
        "",
        per_class_tactic.round(3).to_markdown(),
        "",
        "## Per-level",
        "",
        per_class_level.round(3).to_markdown(),
    ]
    return "\n".join(lines) + "\n"


def _fmt(x):
    return f"{x:.3f}" if isinstance(x, (int, float)) else "n/a"


def _level_mae(truth, preds):
    common = sorted(set(truth) & set(preds))
    diffs = [abs(truth[s].level - preds[s].level)
             for s in common
             if truth[s].level is not None and preds[s].level is not None]
    return sum(diffs) / len(diffs) if diffs else None


def run(argv=None):
    ap = argparse.ArgumentParser(prog="cowrie_dataset.cli evaluate")
    ap.add_argument("--truth", required=True, help="Annotation JSONL (human or LLM)")
    ap.add_argument("--pred", required=True, help="Pipeline label JSONL")
    ap.add_argument("--pipeline-name", required=True,
                    help="Used to pick the right label_<name> block and to name outputs")
    ap.add_argument("--output", required=True,
                    help="Output directory or base file path")
    args = ap.parse_args(argv)

    truth = M.load_annotations(args.truth)
    preds = M.load_pipeline_labels(args.pred, pipeline_name=args.pipeline_name)
    if not (set(truth) & set(preds)):
        raise SystemExit("No overlapping session_ids between --truth and --pred")

    paths = _resolve_outputs(args.output, args.pipeline_name)

    tactic_pc = M.per_class_metrics(truth, preds, axis="tactic")
    level_pc = M.per_class_metrics(truth, preds, axis="level")
    tactic_conf = M.confusion_matrix(truth, preds, axis="tactic")
    level_conf = M.confusion_matrix(truth, preds, axis="level")

    # Truth and pred values for ordinal kappa
    _, t_lvl, p_lvl = M._align(truth, preds, "level")
    level_kappa = M.cohens_kappa(t_lvl, p_lvl, weights="linear")

    fn_rate = M.false_negative_rate(truth, preds, M.default_fn_definition)
    tactic_acc = M.accuracy(truth, preds, "tactic")
    level_acc = M.accuracy(truth, preds, "level")
    tactic_macro = float(tactic_pc["f1"].mean()) if len(tactic_pc) else 0.0
    level_mae = _level_mae(truth, preds)
    n = len(set(truth) & set(preds))

    payload = {
        "pipeline": args.pipeline_name,
        "n_aligned": n,
        "tactic": {
            "accuracy": tactic_acc,
            "macro_f1": tactic_macro,
            "per_class": tactic_pc.reset_index().to_dict(orient="records"),
        },
        "level": {
            "accuracy": level_acc,
            "weighted_kappa": level_kappa,
            "mae": level_mae,
            "per_class": level_pc.reset_index().to_dict(orient="records"),
        },
        "false_negative_rate": fn_rate,
    }

    paths["json"].write_text(json.dumps(payload, indent=2, default=str))
    paths["md"].write_text(_summary_md(
        args.pipeline_name, n, tactic_acc, tactic_macro, level_acc,
        level_kappa, level_mae, fn_rate, tactic_pc, level_pc,
    ))
    tactic_conf.to_csv(paths["conf_tactic"])
    level_conf.to_csv(paths["conf_level"])

    print(f"wrote {paths['json']}")
    print(f"wrote {paths['md']}")
    print(f"wrote {paths['conf_tactic']}")
    print(f"wrote {paths['conf_level']}")


if __name__ == "__main__":
    run()
