"""Run a trained Pipeline C model over a sessions JSONL.

Emits one ``label_ml`` block per session compatible with the metrics
framework's loader. Sessions missing all features still get a row, with
an explicit ``label_ml.note`` flagging that the input was empty.
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np

from .features import FEATURE_ORDER, extract_features


def _load_model(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def _predict_one(payload, x_filled):
    tac = payload["tactic"]
    pred_int = int(tac["model"].predict(x_filled.reshape(1, -1))[0])
    tactic = tac["classes"][pred_int]
    proba = tac["model"].predict_proba(x_filled.reshape(1, -1))[0]
    confidence = float(np.max(proba))

    lvl_raw = float(payload["level"]["model"].predict(x_filled.reshape(1, -1))[0])
    level = int(np.clip(round(lvl_raw), 1, 3))
    return tactic, level, confidence, lvl_raw


def predict(model_path: str, sessions_path: str, output_path: str, pipeline_name: str = "ml") -> int:
    payload = _load_model(model_path)
    medians = np.array(payload["medians"], dtype=np.float64)

    if payload["feature_order"] != FEATURE_ORDER:
        # Loud failure: a feature added or reordered upstream invalidates the model.
        raise SystemExit(
            "Feature order mismatch. The trained model expects a different set/order. "
            "Retrain or pin the older feature_schema.json."
        )

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n_written = 0
    with open(sessions_path) as f, open(out_path, "w") as out:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            x = extract_features(r)
            mask = np.isnan(x)
            if mask.all():
                out.write(json.dumps({
                    "session_id": r.get("session_id"),
                    f"label_{pipeline_name}": {
                        "primary_tactic": "Unknown Activity",
                        "threat_level": 3,
                        "confidence": 0.0,
                        "note": "no features available",
                    },
                }) + "\n")
                n_written += 1
                continue
            x_filled = np.where(mask, medians, x)
            tactic, level, conf, lvl_raw = _predict_one(payload, x_filled)
            out.write(json.dumps({
                "session_id": r.get("session_id"),
                f"label_{pipeline_name}": {
                    "primary_tactic": tactic,
                    "threat_level": level,
                    "confidence": conf,
                    "level_raw": round(lvl_raw, 3),
                },
            }) + "\n")
            n_written += 1
    return n_written


def cli(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="cowrie_dataset.cli predict_ml")
    ap.add_argument("--model", required=True)
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--pipeline-name", default="ml",
                    help="Used in the emitted label_<name> key")
    args = ap.parse_args(argv)
    n = predict(args.model, args.input, args.output, args.pipeline_name)
    print(f"wrote {n} predictions -> {args.output}")


if __name__ == "__main__":
    cli()
