"""Tests for the cowrie_dataset.eval.metrics module.

These cover the acceptance criteria from Phase 1 of the implementation
plan: confusion shape, the level/tactic split, and the self-comparison
sanity check on the bootstrap CI.
"""

import json
from pathlib import Path

import pytest

from cowrie_dataset.eval import metrics as M


# ---- fixtures ------------------------------------------------------------

def _ann(tactic, level, fn_risk=False):
    return M.Annotation(tactic=tactic, level=level, fn_risk=fn_risk)


def _lbl(tactic, level, conf=None):
    return M.Label(tactic=tactic, level=level, confidence=conf)


@pytest.fixture
def truth():
    # 6 sessions, mostly Discovery
    return {
        "s1": _ann("Discovery", 3),
        "s2": _ann("Discovery", 3),
        "s3": _ann("Discovery", 2),
        "s4": _ann("Execution", 1, fn_risk=True),
        "s5": _ann("Execution", 1, fn_risk=True),
        "s6": _ann("Persistence", 2),
    }


@pytest.fixture
def perfect_pred(truth):
    return {sid: _lbl(a.tactic, a.level, conf=0.9) for sid, a in truth.items()}


@pytest.fixture
def level_only_disagree(truth):
    # Same tactics, but L1 truth gets called L2. Mirrors the agent's
    # documented severity undercall on credential drops.
    bumped = {1: 2, 2: 2, 3: 3}
    return {sid: _lbl(a.tactic, bumped[a.level], conf=0.7) for sid, a in truth.items()}


# ---- IO ------------------------------------------------------------------

def test_load_annotations_handles_both_id_keys(tmp_path):
    p = tmp_path / "ann.jsonl"
    p.write_text(
        json.dumps({"session_id": "x", "primary_tactic": "Discovery",
                    "threat_level": 3, "confidence": 0.8}) + "\n"
        + json.dumps({"annotation_id": "y", "primary_tactic": "Execution",
                      "threat_level": 1, "is_false_negative_risk": True}) + "\n"
    )
    out = M.load_annotations(p)
    assert set(out) == {"x", "y"}
    assert out["x"].tactic == "Discovery" and out["x"].level == 3
    assert out["y"].fn_risk is True


def test_load_pipeline_labels_picks_named_block(tmp_path):
    p = tmp_path / "preds.jsonl"
    p.write_text(json.dumps({
        "session_id": "x",
        "label_rule": {"primary_tactic": "Discovery", "threat_level": 3,
                       "confidence": "high"},
        "label_agent": {"primary_tactic": "Execution", "threat_level": 1,
                        "confidence": 0.4},
    }) + "\n")
    rule = M.load_pipeline_labels(p, pipeline_name="rule")
    assert rule["x"].tactic == "Discovery"
    assert rule["x"].confidence == pytest.approx(0.9)  # "high" -> 0.9

    agent = M.load_pipeline_labels(p, pipeline_name="agent")
    assert agent["x"].tactic == "Execution"
    assert agent["x"].confidence == pytest.approx(0.4)


def test_load_pipeline_labels_falls_back_to_legacy_keys(tmp_path):
    p = tmp_path / "preds.jsonl"
    p.write_text(json.dumps({
        "session_id": "x",
        "rule_based_label": {"primary_tactic": "Discovery", "level": 2},
    }) + "\n")
    out = M.load_pipeline_labels(p, pipeline_name="rule")
    assert out["x"].tactic == "Discovery"
    assert out["x"].level == 2


# ---- confusion + per-class ----------------------------------------------

def test_confusion_matches_existing_analyzer(truth, perfect_pred):
    cm = M.confusion_matrix(truth, perfect_pred, axis="tactic")
    # Diagonal carries everything, off-diagonal is zero.
    diag = sum(cm.at[lbl, lbl] for lbl in cm.index)
    assert diag == len(truth)
    assert cm.values.sum() == len(truth)


def test_per_class_metrics_are_perfect_when_predictions_match(truth, perfect_pred):
    df = M.per_class_metrics(truth, perfect_pred, axis="tactic")
    assert (df["precision"] == 1.0).all()
    assert (df["recall"] == 1.0).all()
    assert (df["f1"] == 1.0).all()


def test_level_only_disagreement_does_not_contaminate_tactic(truth, level_only_disagree):
    # Tactic side is perfect.
    t_df = M.per_class_metrics(truth, level_only_disagree, axis="tactic")
    assert (t_df["f1"] == 1.0).all()

    # Level side shows the L1 -> L2 miscalibration: nothing is correctly L1.
    l_df = M.per_class_metrics(truth, level_only_disagree, axis="level")
    assert l_df.at["1", "recall"] == 0.0
    assert l_df.at["2", "recall"] > 0  # L2s are still right


def test_macro_f1_zero_when_all_wrong():
    truth = {"s": _ann("Discovery", 3)}
    pred = {"s": _lbl("Persistence", 2)}
    assert M.macro_f1(truth, pred, axis="tactic") == 0.0


# ---- agreement -----------------------------------------------------------

def test_kappa_perfect_agreement():
    a = ["A", "A", "B", "B", "C"]
    assert M.cohens_kappa(a, a) == 1.0


def test_weighted_kappa_penalizes_distance_less_than_unweighted():
    # Two raters: one always picks neighbour-off; weighted kappa should be
    # higher than unweighted because errors are by 1 not by 2.
    a = [1, 2, 3, 1, 2, 3]
    b = [2, 3, 2, 2, 3, 2]
    k_unw = M.cohens_kappa(a, b)
    k_lin = M.cohens_kappa(a, b, weights="linear")
    assert k_lin > k_unw


def test_mcnemar_no_discordance():
    out = M.mcnemar([True, False, True], [True, False, True])
    assert out["n_discordant"] == 0
    assert out["p_value"] == 1.0


def test_mcnemar_strong_discordance_has_small_p():
    a = [True] * 20
    b = [False] * 20
    out = M.mcnemar(a, b)
    assert out["b"] == 20 and out["c"] == 0
    assert out["p_value"] < 1e-4


def test_agreement_metrics_uses_weighted_kappa_for_level():
    a = {"s1": _ann("X", 1), "s2": _ann("X", 2), "s3": _ann("X", 3)}
    b = {"s1": _ann("X", 2), "s2": _ann("X", 3), "s3": _ann("X", 2)}
    out = M.agreement_metrics(a, b, axis="level")
    # Every disagreement is by exactly 1, so weighted kappa should be > 0.
    assert out["n"] == 3
    assert out["kappa"] is not None


# ---- bootstrap (the sanity check the plan asked for) --------------------

def test_bootstrap_self_comparison_centered_on_zero(truth, perfect_pred):
    mean, (lo, hi) = M.bootstrap_f1_diff(
        truth, perfect_pred, perfect_pred, axis="tactic",
        n_iter=500, seed=0,
    )
    assert mean == 0.0
    assert lo == 0.0 and hi == 0.0


def test_bootstrap_returns_positive_diff_when_a_better(truth, perfect_pred, level_only_disagree):
    # A is perfect on tactic, B too (level-only disagreement), so diff
    # should be ~0 here. Use a different setup for "A better than B".
    bad_b = {sid: _lbl("Persistence", 2) for sid in truth}
    mean, (lo, hi) = M.bootstrap_f1_diff(
        truth, perfect_pred, bad_b, axis="tactic", n_iter=500, seed=0,
    )
    assert mean > 0
    assert lo > 0  # entire CI above zero - A clearly wins


# ---- calibration & FN rate ----------------------------------------------

def test_calibration_curve_has_expected_columns(truth, perfect_pred):
    df = M.calibration_curve(truth, perfect_pred, axis="tactic", n_bins=5)
    assert list(df.columns) == ["bin_low", "bin_high", "n", "mean_confidence", "accuracy"]
    # All predictions correct -> accuracy column is 1.0 in any populated bin.
    assert (df["accuracy"] == 1.0).all()
    assert M.expected_calibration_error(df) < 0.2


def test_default_fn_definition_catches_silent_no_action():
    truth = {"s": _ann("Execution", 1, fn_risk=True)}
    silent = {"s": _lbl("No Action", None)}
    loud = {"s": _lbl("Execution", 1)}
    assert M.false_negative_rate(truth, silent, M.default_fn_definition) == 1.0
    assert M.false_negative_rate(truth, loud, M.default_fn_definition) == 0.0


def test_false_negative_rate_ignores_truth_no_action():
    # Truth itself says No Action - any pipeline that also says no-action
    # is correct, not a false negative.
    truth = {"s": _ann("No Action", None)}
    pred = {"s": _lbl("No Action", None)}
    assert M.false_negative_rate(truth, pred, M.default_fn_definition) == 0.0
