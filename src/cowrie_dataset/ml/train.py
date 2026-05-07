"""Train Pipeline C.

One classifier for tactic, one regressor for level (regression-then-round
keeps the ordinal nature without bringing in a special-purpose lib).
Cross-validation is stratified by tactic AND by sensor - skipping the
sensor stratification leaks the geographic signal.

Run via the CLI: ``python -m cowrie_dataset.cli train_ml --help``.
"""

from __future__ import annotations

import json
import pickle
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .features import FEATURE_ORDER, extract_features, write_schema


@dataclass
class TrainConfig:
    sessions_path: str
    labels_path: str
    model_out: str
    cv_folds: int = 5
    seed: int = 42
    skip_agreement_subset: bool = True


def _load_sessions(path):
    by_id = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            sid = r.get("session_id")
            if sid:
                by_id[sid] = r
    return by_id


def _load_labels(path):
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            sid = r.get("session_id") or r.get("annotation_id")
            if sid is None:
                continue
            tactic = (r.get("primary_tactic") or "").strip()
            level = r.get("threat_level")
            if level is None:
                level = r.get("level")
            if tactic and level is not None:
                out[sid] = (tactic, int(level))
    return out


def _agreement_session_ids(sessions):
    """IDs where pipeline A and pipeline B agree on tactic AND level.

    Training on this subset would just teach the model the easy cases.
    The plan calls this out explicitly - skip them.
    """
    out = set()
    for sid, s in sessions.items():
        a = s.get("label_rule") or s.get("rule_based_label") or {}
        b = s.get("label_agent") or s.get("agent_label") or {}
        if not a or not b:
            continue
        a_t = (a.get("primary_tactic") or "").strip()
        b_t = (b.get("primary_tactic") or "").strip()
        a_l = a.get("threat_level") if a.get("threat_level") is not None else a.get("level")
        b_l = b.get("threat_level") if b.get("threat_level") is not None else b.get("level")
        if a_t and a_t == b_t and a_l == b_l:
            out.add(sid)
    return out


def _stratified_groups(tactics, sensors, n_folds, seed):
    """Stratified-by-tactic-and-sensor fold assignment.

    Plain GroupKFold doesn't stratify; sklearn's StratifiedGroupKFold does
    but we don't want to require sklearn just for this. Implement the
    simple version by hand: round-robin within each (tactic, sensor)
    bucket.
    """
    rng = np.random.default_rng(seed)
    folds = np.full(len(tactics), -1, dtype=int)
    buckets: dict[tuple, list[int]] = {}
    for i, (t, s) in enumerate(zip(tactics, sensors)):
        buckets.setdefault((t, s), []).append(i)
    for idxs in buckets.values():
        rng.shuffle(idxs)
        for j, i in enumerate(idxs):
            folds[i] = j % n_folds
    return folds


def _try_lightgbm():
    try:
        import lightgbm as lgb
        return lgb
    except ImportError:
        return None


def _train_classifier(X, y, lgb):
    classes = sorted(set(y))
    y_int = np.array([classes.index(v) for v in y], dtype=np.int32)
    model = lgb.LGBMClassifier(
        n_estimators=300, learning_rate=0.05, num_leaves=31,
        min_child_samples=10, n_jobs=-1, verbosity=-1,
    )
    model.fit(X, y_int)
    return {"model": model, "classes": classes}


def _train_regressor(X, y, lgb):
    model = lgb.LGBMRegressor(
        n_estimators=300, learning_rate=0.05, num_leaves=31,
        min_child_samples=10, n_jobs=-1, verbosity=-1,
    )
    model.fit(X, np.array(y, dtype=np.float64))
    return {"model": model}


def _cv_score(X, y_t, y_l, sensors, n_folds, seed, lgb):
    folds = _stratified_groups(y_t, sensors, n_folds, seed)
    fold_metrics = []
    for k in range(n_folds):
        train_idx = np.where(folds != k)[0]
        test_idx = np.where(folds == k)[0]
        if len(train_idx) == 0 or len(test_idx) == 0:
            continue
        # Tactic
        tac = _train_classifier(X[train_idx], [y_t[i] for i in train_idx], lgb)
        pred_int = tac["model"].predict(X[test_idx])
        pred_tac = [tac["classes"][int(p)] for p in pred_int]
        true_tac = [y_t[i] for i in test_idx]
        tactic_acc = sum(1 for a, b in zip(pred_tac, true_tac) if a == b) / len(true_tac)
        # Level
        reg = _train_regressor(X[train_idx], [y_l[i] for i in train_idx], lgb)
        pred_lvl_raw = reg["model"].predict(X[test_idx])
        pred_lvl = np.clip(np.round(pred_lvl_raw), 1, 3).astype(int)
        true_lvl = np.array([y_l[i] for i in test_idx], dtype=int)
        level_mae = float(np.mean(np.abs(pred_lvl - true_lvl)))
        fold_metrics.append({
            "fold": k,
            "n_train": int(len(train_idx)),
            "n_test": int(len(test_idx)),
            "tactic_accuracy": tactic_acc,
            "level_mae": level_mae,
        })
    return fold_metrics


def _impute_medians(X):
    """Median imputation. Return (filled, medians, imputation_rate)."""
    medians = np.nanmedian(X, axis=0)
    medians = np.where(np.isnan(medians), 0.0, medians)
    mask = np.isnan(X)
    rate = float(mask.mean())
    filled = np.where(mask, medians, X)
    return filled, medians, rate


def train(cfg: TrainConfig) -> dict:
    lgb = _try_lightgbm()
    if lgb is None:
        raise RuntimeError(
            "lightgbm not installed. Install with: pip install lightgbm"
        )

    sessions = _load_sessions(cfg.sessions_path)
    labels = _load_labels(cfg.labels_path)
    common = sorted(set(sessions) & set(labels))

    if cfg.skip_agreement_subset:
        agree = _agreement_session_ids(sessions)
        common = [s for s in common if s not in agree]

    if not common:
        raise SystemExit("No training sessions left after filtering. Check inputs.")

    rows = [extract_features(sessions[s]) for s in common]
    X_raw = np.vstack(rows)
    X, medians, imputation_rate = _impute_medians(X_raw)

    y_t = [labels[s][0] for s in common]
    y_l = [labels[s][1] for s in common]
    sensors = [sessions[s].get("sensor", "unknown") for s in common]

    cv_metrics = _cv_score(X, y_t, y_l, sensors, cfg.cv_folds, cfg.seed, lgb)

    tactic_head = _train_classifier(X, y_t, lgb)
    level_head = _train_regressor(X, y_l, lgb)

    out_path = Path(cfg.model_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "feature_order": FEATURE_ORDER,
        "medians": medians.tolist(),
        "tactic": tactic_head,
        "level": level_head,
        "n_train": len(common),
        "skipped_agreement_subset": cfg.skip_agreement_subset,
    }
    with open(out_path, "wb") as f:
        pickle.dump(payload, f)
    write_schema(out_path.parent / "feature_schema.json")

    cv_summary = {
        "n_train": len(common),
        "n_features": len(FEATURE_ORDER),
        "imputation_rate": imputation_rate,
        "tactic_distribution": dict(Counter(y_t)),
        "level_distribution": dict(Counter(y_l)),
        "fold_metrics": cv_metrics,
        "tactic_accuracy_mean": float(np.mean([m["tactic_accuracy"] for m in cv_metrics])) if cv_metrics else None,
        "level_mae_mean": float(np.mean([m["level_mae"] for m in cv_metrics])) if cv_metrics else None,
    }
    return cv_summary


def cli(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="cowrie_dataset.cli train_ml")
    ap.add_argument("--train-data", required=True, help="labeled_sessions.jsonl")
    ap.add_argument("--labels", required=True, help="annotations file with primary_tactic + level")
    ap.add_argument("--model-out", required=True)
    ap.add_argument("--cv-folds", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--keep-agreement-subset", action="store_true",
                    help="Train on the easy subset too (default: skip)")
    ap.add_argument("--cv-out", default=None,
                    help="Write CV results JSON here (default: alongside model)")
    args = ap.parse_args(argv)

    cfg = TrainConfig(
        sessions_path=args.train_data,
        labels_path=args.labels,
        model_out=args.model_out,
        cv_folds=args.cv_folds,
        seed=args.seed,
        skip_agreement_subset=not args.keep_agreement_subset,
    )
    summary = train(cfg)
    cv_out = args.cv_out or str(Path(args.model_out).with_suffix(".cv.json"))
    Path(cv_out).parent.mkdir(parents=True, exist_ok=True)
    Path(cv_out).write_text(json.dumps(summary, indent=2, default=str))
    print(f"trained on {summary['n_train']} sessions; CV summary -> {cv_out}")


if __name__ == "__main__":
    cli()
