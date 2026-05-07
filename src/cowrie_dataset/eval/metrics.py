"""Pipeline-agnostic evaluation metrics.

Tactic and level are scored separately on purpose. The headline finding
(rule-based pipeline silently dropping real attacks vs. the agent
under-calling severity) lives in those two axes, and conflating them
the way the original analyzer did made the L3->L2 miscalibration
invisible.

All public functions take ``dict[session_id -> Annotation|Label]`` and
align by id internally. Callers don't need to keep parallel lists in
sync, and pipelines that emit different subsets of the data still
compose cleanly.
"""

from __future__ import annotations

import json
import math
import random
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Literal

import pandas as pd


# Tactic strings that mean "no classification was produced". Treated as a
# real class for confusion / F1 - the silent-failure analysis only works
# if these stay distinct from "missing from the file".
NULL_TACTICS = frozenset({"", "no action", "unknown activity", "unknown"})

Axis = Literal["tactic", "level", "joint"]


@dataclass(frozen=True)
class Annotation:
    """A truth label, from a human or LLM annotator."""
    tactic: str
    level: int | None
    fn_risk: bool = False
    confidence: float | None = None


@dataclass(frozen=True)
class Label:
    """A pipeline prediction."""
    tactic: str
    level: int | None
    confidence: float | None = None


# ---------------------------------------------------------------------------
# IO

# Pipeline label blocks have shown up under at least four names across the
# project's history. List the ones we know about; load_pipeline_labels picks
# whichever shows up first.
_LABEL_KEYS = ("label_rule", "label_agent", "rule_based_label", "agent_label")

# Categorical confidence -> rough numeric. Only used for Pipeline A, which
# is the only thing that emits strings here. The exact midpoints don't
# matter for ranking; calibration plots will bin them anyway.
_CONF_WORDS = {"high": 0.9, "medium": 0.6, "low": 0.3}


def _norm_tactic(t):
    return (t or "").strip()


def _to_float(v):
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    return _CONF_WORDS.get(str(v).strip().lower())


def _level_of(d):
    # Pipeline A historically used "level"; new schema uses "threat_level".
    if d is None:
        return None
    v = d.get("threat_level")
    return v if v is not None else d.get("level")


def _read_jsonl(path):
    with Path(path).open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def load_annotations(path: str | Path) -> dict[str, Annotation]:
    """Read an annotation_results*.jsonl file.

    Records are keyed by ``session_id`` if present, otherwise by
    ``annotation_id`` (the blind sampler uses that one).
    """
    out: dict[str, Annotation] = {}
    for r in _read_jsonl(path):
        sid = r.get("session_id") or r.get("annotation_id")
        if sid is None:
            continue
        out[sid] = Annotation(
            tactic=_norm_tactic(r.get("primary_tactic")),
            level=_level_of(r),
            fn_risk=bool(r.get("is_false_negative_risk")),
            confidence=_to_float(r.get("confidence")),
        )
    return out


def load_pipeline_labels(
    path: str | Path,
    pipeline_name: str | None = None,
) -> dict[str, Label]:
    """Read a pipeline label JSONL into ``{session_id: Label}``.

    The label can live at the top level of the record or nested under
    ``label_<name>``. ``pipeline_name`` is consulted first; legacy keys
    (``rule_based_label`` / ``agent_label``) are tried after that.
    """
    keys = []
    if pipeline_name:
        keys.append(f"label_{pipeline_name}")
    keys.extend(k for k in _LABEL_KEYS if k not in keys)

    out: dict[str, Label] = {}
    for r in _read_jsonl(path):
        sid = r.get("session_id") or r.get("annotation_id")
        if sid is None:
            continue
        block = None
        for k in keys:
            v = r.get(k)
            if isinstance(v, dict):
                block = v
                break
        if block is None:
            # top-level record, e.g. when the file only carries one pipeline
            if "primary_tactic" not in r:
                continue
            block = r
        out[sid] = Label(
            tactic=_norm_tactic(block.get("primary_tactic")),
            level=_level_of(block),
            confidence=_to_float(block.get("confidence")),
        )
    return out


# ---------------------------------------------------------------------------
# Alignment

def _value(obj, axis: Axis):
    if axis == "tactic":
        return obj.tactic
    if axis == "level":
        return obj.level
    return (obj.tactic, obj.level)


def _align(truth, predictions, axis: Axis):
    ids = sorted(set(truth) & set(predictions))
    t = [_value(truth[i], axis) for i in ids]
    p = [_value(predictions[i], axis) for i in ids]
    return ids, t, p


def _stringify(xs):
    return ["" if x is None else str(x) for x in xs]


# ---------------------------------------------------------------------------
# Confusion + per-class

def confusion_matrix(
    truth: dict[str, Annotation],
    predictions: dict[str, Label],
    axis: Axis = "tactic",
) -> pd.DataFrame:
    """Rows are truth labels, columns are predictions."""
    _, t, p = _align(truth, predictions, axis)
    t = _stringify(t)
    p = _stringify(p)
    labels = sorted(set(t) | set(p))
    df = pd.DataFrame(0, index=labels, columns=labels, dtype=int)
    df.index.name = "truth"
    df.columns.name = "pred"
    for ti, pi in zip(t, p):
        df.at[ti, pi] += 1
    return df


def _prf(t_list, p_list):
    labels = sorted(set(t_list) | set(p_list))
    rows = []
    for lbl in labels:
        tp = sum(1 for x, y in zip(p_list, t_list) if x == lbl and y == lbl)
        fp = sum(1 for x, y in zip(p_list, t_list) if x == lbl and y != lbl)
        fn = sum(1 for x, y in zip(p_list, t_list) if x != lbl and y == lbl)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        rows.append((lbl, prec, rec, f1, tp + fn))
    df = pd.DataFrame(rows, columns=["class", "precision", "recall", "f1", "support"])
    return df.set_index("class")


def per_class_metrics(
    truth: dict[str, Annotation],
    predictions: dict[str, Label],
    axis: Axis = "tactic",
) -> pd.DataFrame:
    _, t, p = _align(truth, predictions, axis)
    return _prf(_stringify(t), _stringify(p))


def macro_f1(truth, predictions, axis: Axis = "tactic") -> float:
    df = per_class_metrics(truth, predictions, axis)
    return float(df["f1"].mean()) if len(df) else 0.0


def accuracy(truth, predictions, axis: Axis = "tactic") -> float:
    _, t, p = _align(truth, predictions, axis)
    if not t:
        return 0.0
    return sum(1 for a, b in zip(t, p) if a == b) / len(t)


# ---------------------------------------------------------------------------
# Agreement

def cohens_kappa(a, b, weights: str = "unweighted") -> float | None:
    """``weights='linear'`` is appropriate for ordinal labels (the levels)."""
    paired = [(x, y) for x, y in zip(a, b) if x is not None and y is not None]
    if not paired:
        return None
    labels = sorted({v for pair in paired for v in pair}, key=str)
    idx = {v: i for i, v in enumerate(labels)}
    k = len(labels)
    o = [[0] * k for _ in range(k)]
    for x, y in paired:
        o[idx[x]][idx[y]] += 1
    n = len(paired)
    row = [sum(o[i]) for i in range(k)]
    col = [sum(o[i][j] for i in range(k)) for j in range(k)]
    if weights == "linear":
        m = max(1, k - 1)
        w = [[1 - abs(i - j) / m for j in range(k)] for i in range(k)]
    else:
        w = [[1 if i == j else 0 for j in range(k)] for i in range(k)]
    po = sum(o[i][j] * w[i][j] for i in range(k) for j in range(k)) / n
    pe = sum((row[i] * col[j] / n) * w[i][j] for i in range(k) for j in range(k)) / n
    if pe >= 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


def mcnemar(a_correct: list[bool], b_correct: list[bool]) -> dict:
    """Exact two-sided binomial McNemar on paired correctness."""
    b = sum(1 for x, y in zip(a_correct, b_correct) if x and not y)
    c = sum(1 for x, y in zip(a_correct, b_correct) if y and not x)
    n = b + c
    if n == 0:
        return {"b": 0, "c": 0, "n_discordant": 0, "p_value": 1.0}
    ps = [math.comb(n, k) * 0.5 ** n for k in range(n + 1)]
    pb = ps[b]
    return {
        "b": b,
        "c": c,
        "n_discordant": n,
        "p_value": min(1.0, sum(x for x in ps if x <= pb + 1e-12)),
    }


def agreement_metrics(
    annot1: dict[str, Annotation],
    annot2: dict[str, Annotation],
    axis: Axis = "tactic",
) -> dict:
    """Inter-annotator agreement for a single axis.

    Uses weighted kappa for ``level`` (ordinal), unweighted for tactic.
    """
    _, a, b = _align(annot1, annot2, axis)
    if not a:
        return {"n": 0, "raw_agreement": None, "kappa": None}
    weights = "linear" if axis == "level" else "unweighted"
    return {
        "n": len(a),
        "raw_agreement": sum(1 for x, y in zip(a, b) if x == y) / len(a),
        "kappa": cohens_kappa(a, b, weights=weights),
    }


# ---------------------------------------------------------------------------
# Bootstrap

def _macro_f1_lists(t, p):
    df = _prf(t, p)
    return float(df["f1"].mean()) if len(df) else 0.0


def bootstrap_f1_diff(
    truth: dict[str, Annotation],
    pred_a: dict[str, Label],
    pred_b: dict[str, Label],
    axis: Axis = "tactic",
    n_iter: int = 10_000,
    seed: int = 42,
) -> tuple[float, tuple[float, float]]:
    """Paired bootstrap on macro-F1(A) - macro-F1(B). 95% percentile CI."""
    common = sorted(set(truth) & set(pred_a) & set(pred_b))
    n = len(common)
    if n == 0:
        return 0.0, (0.0, 0.0)
    t_all = _stringify([_value(truth[i], axis) for i in common])
    a_all = _stringify([_value(pred_a[i], axis) for i in common])
    b_all = _stringify([_value(pred_b[i], axis) for i in common])

    rng = random.Random(seed)
    diffs = []
    for _ in range(n_iter):
        idx = [rng.randrange(n) for _ in range(n)]
        t = [t_all[i] for i in idx]
        a = [a_all[i] for i in idx]
        b = [b_all[i] for i in idx]
        diffs.append(_macro_f1_lists(t, a) - _macro_f1_lists(t, b))
    diffs.sort()
    mean = sum(diffs) / len(diffs)
    lo = diffs[int(0.025 * n_iter)]
    hi = diffs[min(n_iter - 1, int(0.975 * n_iter))]
    return mean, (lo, hi)


# ---------------------------------------------------------------------------
# Calibration

def calibration_curve(
    truth: dict[str, Annotation],
    predictions: dict[str, Label],
    axis: Axis = "tactic",
    n_bins: int = 10,
) -> pd.DataFrame:
    """Reliability bins. Skips predictions with no confidence value."""
    common = sorted(set(truth) & set(predictions))
    rows = []
    for sid in common:
        c = predictions[sid].confidence
        if c is None:
            continue
        ok = _value(truth[sid], axis) == _value(predictions[sid], axis)
        rows.append((float(c), int(ok)))
    if not rows:
        return pd.DataFrame(columns=["bin_low", "bin_high", "n", "mean_confidence", "accuracy"])
    df = pd.DataFrame(rows, columns=["confidence", "correct"])
    edges = [i / n_bins for i in range(n_bins + 1)]
    df["bin"] = pd.cut(df["confidence"], bins=edges, include_lowest=True)
    g = df.groupby("bin", observed=True)
    out = pd.DataFrame({
        "n": g.size(),
        "mean_confidence": g["confidence"].mean(),
        "accuracy": g["correct"].mean(),
    }).reset_index()
    out["bin_low"] = out["bin"].apply(lambda x: float(x.left))
    out["bin_high"] = out["bin"].apply(lambda x: float(x.right))
    return out[["bin_low", "bin_high", "n", "mean_confidence", "accuracy"]]


def expected_calibration_error(reliability: pd.DataFrame) -> float:
    if len(reliability) == 0:
        return 0.0
    n_total = reliability["n"].sum()
    if n_total == 0:
        return 0.0
    gap = (reliability["mean_confidence"] - reliability["accuracy"]).abs()
    return float((gap * reliability["n"] / n_total).sum())


# ---------------------------------------------------------------------------
# False-negative rate

def false_negative_rate(
    truth: dict[str, Annotation],
    predictions: dict[str, Label],
    fn_definition: Callable[[Annotation, Label], bool],
) -> float:
    """Fraction of aligned sessions where ``fn_definition`` returns True."""
    common = sorted(set(truth) & set(predictions))
    if not common:
        return 0.0
    return sum(1 for sid in common if fn_definition(truth[sid], predictions[sid])) / len(common)


def default_fn_definition(t: Annotation, p: Label) -> bool:
    """Project default: real attack in truth, but pipeline output is no-action.

    Encodes the silent-failure mode that motivated the whole comparison.
    """
    if _norm_tactic(t.tactic).lower() in NULL_TACTICS:
        return False
    pred = _norm_tactic(p.tactic).lower()
    return pred in NULL_TACTICS or p.level is None
