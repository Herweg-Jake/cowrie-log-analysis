"""Smoke tests for Phase 2-6 modules.

Heavier flows (real LLM calls, real Cowrie data) are out of scope - this
just checks that the module wiring holds, IO works, and the obvious
edge cases don't crash.
"""

import json
import os
import tempfile
from pathlib import Path

import numpy as np
import pytest

from cowrie_dataset.eval import ensemble, headline, pairwise, taxonomy
from cowrie_dataset.eval import metrics as M
from cowrie_dataset.ml import features as F
from cowrie_dataset.ml import predict as P
from cowrie_dataset.ml import train as T


# ---- ML round-trip ------------------------------------------------------

def _synth_dataset(tmp, n=90):
    rng = np.random.default_rng(0)
    sessions_path = tmp / "sessions.jsonl"
    labels_path = tmp / "labels.jsonl"
    sensors = ["amsterdam", "london", "toronto"]
    with open(sessions_path, "w") as fs, open(labels_path, "w") as fl:
        for i in range(n):
            tactic = ["Discovery", "Execution", "Persistence"][i % 3]
            level = {"Discovery": 3, "Execution": 1, "Persistence": 2}[tactic]
            feats = {k: float(rng.integers(0, 5)) for k in F.FEATURE_ORDER}
            # Inject strong signal so the model can actually learn
            feats["F1_keyword_bash"] = 5.0 if tactic == "Execution" else 0.0
            feats["F19_keyword_uname"] = 5.0 if tactic == "Discovery" else 0.0
            sid = f"s{i:03d}"
            fs.write(json.dumps({
                "session_id": sid,
                "sensor": sensors[i % 3],
                "features": feats,
            }) + "\n")
            fl.write(json.dumps({
                "session_id": sid,
                "primary_tactic": tactic,
                "threat_level": level,
            }) + "\n")
    return sessions_path, labels_path


def test_ml_train_predict_roundtrip(tmp_path):
    pytest.importorskip("lightgbm")
    sessions_path, labels_path = _synth_dataset(tmp_path)
    model_path = tmp_path / "m.pkl"
    cfg = T.TrainConfig(
        sessions_path=str(sessions_path),
        labels_path=str(labels_path),
        model_out=str(model_path),
        cv_folds=3,
        seed=0,
        skip_agreement_subset=False,
    )
    summary = T.train(cfg)
    # Strong signal -> should beat random easily on a 3-class task.
    assert summary["tactic_accuracy_mean"] > 0.6

    pred_path = tmp_path / "preds.jsonl"
    n = P.predict(str(model_path), str(sessions_path), str(pred_path), "ml")
    assert n == 90

    # And the metrics framework picks the file up cleanly.
    preds = M.load_pipeline_labels(str(pred_path), pipeline_name="ml")
    assert "s000" in preds
    assert preds["s000"].confidence is not None


# ---- ensemble ------------------------------------------------------------

def test_ensemble_majority_vote(tmp_path):
    paths = []
    for name, tactic, conf, level in [
        ("b1", "Discovery", 0.6, 2),
        ("b2", "Discovery", 0.7, 3),
        ("b3", "Execution", 0.9, 1),
    ]:
        p = tmp_path / f"{name}.jsonl"
        p.write_text(json.dumps({
            "session_id": "s1",
            "label_agent": {"primary_tactic": tactic, "threat_level": level, "confidence": conf},
        }) + "\n")
        paths.append((str(p), "agent"))
    out = tmp_path / "ens.jsonl"
    ensemble.majority_vote(paths, str(out), ensemble_name="E")
    rec = json.loads(out.read_text())
    assert rec["label_E"]["primary_tactic"] == "Discovery"
    # Median level among the agreeing voters (Discovery -> [2,3]) -> 2 or 3
    assert rec["label_E"]["threat_level"] in {2, 3}
    assert rec["label_E"]["n_agreeing"] == 2


def test_ensemble_tie_break_by_confidence(tmp_path):
    paths = []
    for name, tactic, conf in [
        ("b1", "Discovery", 0.5),
        ("b2", "Execution", 0.95),
    ]:
        p = tmp_path / f"{name}.jsonl"
        p.write_text(json.dumps({
            "session_id": "s1",
            "label_agent": {"primary_tactic": tactic, "threat_level": 2, "confidence": conf},
        }) + "\n")
        paths.append((str(p), "agent"))
    out = tmp_path / "ens.jsonl"
    ensemble.majority_vote(paths, str(out), ensemble_name="E")
    rec = json.loads(out.read_text())
    # Tied 1-1, higher confidence wins.
    assert rec["label_E"]["primary_tactic"] == "Execution"


# ---- headline ------------------------------------------------------------

def test_headline_table_writes_md_and_csv(tmp_path):
    truth = tmp_path / "truth.jsonl"
    truth.write_text("\n".join(json.dumps({
        "session_id": f"s{i}", "primary_tactic": "Discovery", "threat_level": 3,
    }) for i in range(5)) + "\n")
    preds_path = tmp_path / "preds.jsonl"
    preds_path.write_text("\n".join(json.dumps({
        "session_id": f"s{i}",
        "label_rule": {"primary_tactic": "Discovery" if i < 4 else "No Action",
                       "threat_level": 3, "confidence": "high"},
    }) for i in range(5)) + "\n")
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps([
        {"name": "A", "predictions": str(preds_path), "pipeline_name": "rule"},
    ]))
    out_md = tmp_path / "headline.md"
    out_csv = tmp_path / "headline.csv"
    headline.build_table(str(spec_path), str(truth), str(out_md), str(out_csv))
    assert "A" in out_md.read_text()
    assert out_csv.exists()


# ---- pairwise McNemar ---------------------------------------------------

def test_pairwise_mcnemar_writes_triangular(tmp_path):
    truth = tmp_path / "truth.jsonl"
    truth.write_text("\n".join(json.dumps({
        "session_id": f"s{i}", "primary_tactic": "Discovery", "threat_level": 3,
    }) for i in range(8)) + "\n")
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    a.write_text("\n".join(json.dumps({
        "session_id": f"s{i}",
        "label_rule": {"primary_tactic": "Discovery", "threat_level": 3},
    }) for i in range(8)) + "\n")
    b.write_text("\n".join(json.dumps({
        "session_id": f"s{i}",
        "label_agent": {"primary_tactic": "Discovery" if i < 4 else "Execution",
                        "threat_level": 3},
    }) for i in range(8)) + "\n")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps([
        {"name": "A", "predictions": str(a), "pipeline_name": "rule"},
        {"name": "B", "predictions": str(b), "pipeline_name": "agent"},
    ]))
    out = tmp_path / "mc.csv"
    pairwise.pairwise_mcnemar(str(spec), str(truth), str(out))
    txt = out.read_text()
    assert "p=" in txt and "A" in txt and "B" in txt
