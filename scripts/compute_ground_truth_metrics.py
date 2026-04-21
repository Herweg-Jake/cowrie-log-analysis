#!/usr/bin/env python3
"""
Phase 4 of the Human Annotation Plan: score both pipelines against human
ground truth.

Inputs:
  --annotations    one or more annotation_results*.jsonl files (from the web
                   viewer or spreadsheet export). If more than one annotator,
                   inter-annotator agreement is computed and final labels are
                   resolved via majority vote (ties broken by highest mean
                   confidence).
  --sample-full    annotation_sample_full.jsonl (has both pipeline labels)

Outputs (stdout + optional --output JSON):
  - Per-pipeline tactic confusion matrix vs. human ground truth
  - Per-pipeline level confusion matrix vs. human ground truth
  - Per-tactic precision, recall, F1 for each pipeline
  - Overall accuracy, macro F1, weighted F1 for each pipeline
  - Level MAE per pipeline
  - False-negative rates (of sessions humans flagged as FN-risk, what fraction
    did each pipeline assign level-3 or "No Action")
  - McNemar's test (paired binary correctness) for pipeline comparison
  - Bootstrap 95% CI for F1 difference (B - A)
  - Cohen's kappa between annotators (tactic; weighted for level)
  - Novel-detection validation (Phase 5): of bucket C samples, what fraction
    did humans agree with the agent?

Usage:
    python scripts/compute_ground_truth_metrics.py \\
        --annotations annotation_results_jake.jsonl annotation_results_partner.jsonl \\
        --sample-full annotation_out/annotation_sample_full.jsonl \\
        --output ground_truth_metrics.json

Statistical notes:
  - McNemar's test uses the exact binomial test on discordant pairs, which is
    appropriate for our sample size (~400 and the discordant count will be
    smaller).
  - Bootstrap uses the percentile method with 10,000 resamples by default.
  - Cohen's weighted kappa uses linear weights for ordinal level comparison.
  - All tests operate on the matched-by-session_id pairs of (A, B, H) labels.

No heavy ML deps. Uses only stdlib + no numpy required.
"""

import argparse
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------

def load_annotations(paths):
    """
    Returns dict: annotation_id -> list[annotation_dict] (one per annotator).
    """
    by_id = defaultdict(list)
    for p in paths:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                aid = rec.get("annotation_id")
                if aid is None:
                    continue
                by_id[aid].append(rec)
    return by_id


def load_sample_full(path):
    """Returns dict: annotation_id -> full record with pipeline labels."""
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            out[rec["annotation_id"]] = rec
    return out


# ---------------------------------------------------------------------------
# Label resolution
# ---------------------------------------------------------------------------

def _majority(items, key_fn, confidence_fn):
    """Majority vote with ties broken by average confidence."""
    buckets = defaultdict(list)
    for it in items:
        buckets[key_fn(it)].append(it)
    best = None
    for k, group in buckets.items():
        avg_conf = sum(confidence_fn(g) or 0 for g in group) / len(group)
        score = (len(group), avg_conf)
        if best is None or score > best[0]:
            best = (score, k)
    return best[1] if best else None


def resolve_ground_truth(annotations_by_id):
    """
    For each annotation_id, produce a single ground-truth label.
    Returns dict: annotation_id -> {tactic, level, fn_risk, n_annotators, agreement}
    """
    out = {}
    for aid, recs in annotations_by_id.items():
        tactic = _majority(
            recs,
            key_fn=lambda r: r.get("primary_tactic") or "",
            confidence_fn=lambda r: r.get("confidence"),
        )
        level = _majority(
            recs,
            key_fn=lambda r: r.get("threat_level"),
            confidence_fn=lambda r: r.get("confidence"),
        )
        # FN risk: any annotator flagging it counts (err on the side of caution).
        fn_risk = any(bool(r.get("is_false_negative_risk")) for r in recs)
        tactic_agree = sum(1 for r in recs if (r.get("primary_tactic") or "") == tactic)
        level_agree = sum(1 for r in recs if r.get("threat_level") == level)
        out[aid] = {
            "tactic": tactic,
            "level": level,
            "fn_risk": fn_risk,
            "n_annotators": len(recs),
            "tactic_agreement_rate": tactic_agree / len(recs),
            "level_agreement_rate": level_agree / len(recs),
        }
    return out


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

def _norm(t):
    return (t or "").strip()


def confusion_matrix(pred, truth):
    """Returns {pred_label: {truth_label: count}}."""
    m = defaultdict(lambda: Counter())
    for p, t in zip(pred, truth):
        m[_norm(p)][_norm(t)] += 1
    return {k: dict(v) for k, v in m.items()}


def classification_report(pred, truth):
    """
    Returns per-class precision/recall/F1 + overall accuracy, macro-F1, weighted-F1.
    """
    labels = sorted(set(_norm(x) for x in (pred + truth) if _norm(x)))
    per_class = {}
    total = 0
    correct = 0
    support_total = Counter()
    macro_f1 = 0.0
    weighted_f1 = 0.0
    macro_count = 0

    for lbl in labels:
        tp = sum(1 for p, t in zip(pred, truth) if _norm(p) == lbl and _norm(t) == lbl)
        fp = sum(1 for p, t in zip(pred, truth) if _norm(p) == lbl and _norm(t) != lbl)
        fn = sum(1 for p, t in zip(pred, truth) if _norm(p) != lbl and _norm(t) == lbl)
        support = tp + fn
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        per_class[lbl] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
        }
        support_total[lbl] = support
        macro_f1 += f1
        macro_count += 1
        weighted_f1 += f1 * support

    for p, t in zip(pred, truth):
        if not _norm(p) and not _norm(t):
            continue
        total += 1
        if _norm(p) == _norm(t):
            correct += 1

    overall_support = sum(support_total.values())
    return {
        "per_class": per_class,
        "accuracy": (correct / total) if total else 0.0,
        "macro_f1": (macro_f1 / macro_count) if macro_count else 0.0,
        "weighted_f1": (weighted_f1 / overall_support) if overall_support else 0.0,
        "n": total,
    }


def mean_absolute_error(pred, truth):
    paired = [(p, t) for p, t in zip(pred, truth) if p is not None and t is not None]
    if not paired:
        return None
    return sum(abs(p - t) for p, t in paired) / len(paired)


# ---------------------------------------------------------------------------
# McNemar's test (exact binomial on discordant pairs)
# ---------------------------------------------------------------------------

def mcnemar(a_correct, b_correct):
    """
    a_correct, b_correct: lists of booleans (one per session). Returns dict
    with b (A right, B wrong), c (A wrong, B right), and two-sided exact p.
    """
    b = sum(1 for ac, bc in zip(a_correct, b_correct) if ac and not bc)
    c = sum(1 for ac, bc in zip(a_correct, b_correct) if not ac and bc)
    n = b + c
    if n == 0:
        return {"b": 0, "c": 0, "n_discordant": 0, "p_value": 1.0,
                "note": "no discordant pairs"}
    # Two-sided exact binomial: sum P(X=k) for all k with P(X=k) <= P(X=b) under p=0.5.
    ps = []
    for k in range(n + 1):
        ps.append(math.comb(n, k) * (0.5 ** n))
    pb = ps[b]
    p_value = sum(p for p in ps if p <= pb + 1e-12)
    return {
        "b_A_right_B_wrong": b,
        "c_A_wrong_B_right": c,
        "n_discordant": n,
        "p_value": min(1.0, p_value),
    }


# ---------------------------------------------------------------------------
# Bootstrap CI for F1 difference (B - A)
# ---------------------------------------------------------------------------

def bootstrap_f1_diff(a_pred, b_pred, truth, n_boot=10000, seed=42, metric="macro_f1"):
    rng = random.Random(seed)
    n = len(truth)
    diffs = []
    for _ in range(n_boot):
        idx = [rng.randint(0, n - 1) for _ in range(n)]
        a_s = [a_pred[i] for i in idx]
        b_s = [b_pred[i] for i in idx]
        t_s = [truth[i] for i in idx]
        a_rep = classification_report(a_s, t_s)
        b_rep = classification_report(b_s, t_s)
        diffs.append(b_rep[metric] - a_rep[metric])
    diffs.sort()
    lo = diffs[int(0.025 * n_boot)]
    hi = diffs[int(0.975 * n_boot)]
    mean = sum(diffs) / len(diffs)
    return {"metric": metric, "mean_diff": mean, "ci95_low": lo, "ci95_high": hi, "n_boot": n_boot}


# ---------------------------------------------------------------------------
# Cohen's kappa (unweighted + linear-weighted for ordinal)
# ---------------------------------------------------------------------------

def cohens_kappa(a, b, weights="unweighted"):
    """
    weights: 'unweighted' or 'linear'. 'linear' only makes sense for ordinal
    integer labels.
    """
    paired = [(ai, bi) for ai, bi in zip(a, b) if ai is not None and bi is not None]
    if not paired:
        return None
    labels = sorted(set([x for p in paired for x in p]))
    idx = {l: i for i, l in enumerate(labels)}
    k = len(labels)
    o = [[0] * k for _ in range(k)]
    for ai, bi in paired:
        o[idx[ai]][idx[bi]] += 1
    n = len(paired)
    row = [sum(o[i]) for i in range(k)]
    col = [sum(o[i][j] for i in range(k)) for j in range(k)]

    if weights == "linear":
        max_d = max(1, k - 1)
        w = [[1 - abs(i - j) / max_d for j in range(k)] for i in range(k)]
    else:
        w = [[1 if i == j else 0 for j in range(k)] for i in range(k)]

    po = sum(o[i][j] * w[i][j] for i in range(k) for j in range(k)) / n
    pe = sum((row[i] * col[j] / n) * w[i][j] for i in range(k) for j in range(k)) / n
    if pe >= 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


# ---------------------------------------------------------------------------
# Non-inferiority helper
# ---------------------------------------------------------------------------

def non_inferiority_verdict(ci_low, ci_high, delta=0.05):
    """
    Given a 95% CI on (F1_B - F1_A), decide superiority/non-inferiority.
    delta is the pre-specified non-inferiority margin.
    """
    if ci_low > 0:
        return f"B superior (95% CI entirely above 0, [{ci_low:.3f}, {ci_high:.3f}])"
    if ci_high < 0:
        return f"A superior (95% CI entirely below 0, [{ci_low:.3f}, {ci_high:.3f}])"
    if ci_low > -delta:
        return f"B non-inferior within delta={delta} (CI low={ci_low:.3f})"
    return f"inconclusive within delta={delta} (CI low={ci_low:.3f})"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _fn_detected(tactic, level):
    """A pipeline 'detects' a session when it's not assigned to no-action or level 3."""
    t = _norm(tactic).lower()
    if t in ("", "no action"):
        return False
    if level is None:
        return False
    return level <= 2


def main():
    parser = argparse.ArgumentParser(description="Compute ground-truth metrics")
    parser.add_argument("--annotations", nargs="+", required=True,
                        help="One or more annotation_results*.jsonl files")
    parser.add_argument("--sample-full", required=True,
                        help="annotation_sample_full.jsonl with both pipeline labels")
    parser.add_argument("--output", "-o", help="Save full results to JSON")
    parser.add_argument("--bootstrap", type=int, default=10000)
    parser.add_argument("--non-inferiority-margin", type=float, default=0.05,
                        help="Delta for non-inferiority test on F1 difference")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    annotations = load_annotations(args.annotations)
    sample_full = load_sample_full(args.sample_full)
    ground_truth = resolve_ground_truth(annotations)

    # Match annotation_ids across annotations + sample_full
    common_ids = sorted(set(ground_truth) & set(sample_full))
    if not common_ids:
        print("No overlap between annotations and sample-full.")
        return 1

    # Build aligned arrays
    a_tactic, b_tactic, h_tactic = [], [], []
    a_level,  b_level,  h_level  = [], [], []
    fn_risk = []
    buckets = []
    for aid in common_ids:
        rec = sample_full[aid]
        gt = ground_truth[aid]
        a_tactic.append(_norm((rec.get("rule_based_label") or {}).get("primary_tactic", "")))
        b_tactic.append(_norm((rec.get("agent_label") or {}).get("primary_tactic", "")))
        h_tactic.append(_norm(gt["tactic"]))
        a_level.append((rec.get("rule_based_label") or {}).get("level"))
        b_level.append((rec.get("agent_label") or {}).get("level"))
        h_level.append(gt["level"])
        fn_risk.append(bool(gt["fn_risk"]))
        buckets.append(rec.get("bucket"))

    # Reports
    a_tactic_report = classification_report(a_tactic, h_tactic)
    b_tactic_report = classification_report(b_tactic, h_tactic)

    # Level: stringify for the classification report, but also keep numeric for MAE
    a_level_s = [str(x) if x is not None else "" for x in a_level]
    b_level_s = [str(x) if x is not None else "" for x in b_level]
    h_level_s = [str(x) if x is not None else "" for x in h_level]
    a_level_report = classification_report(a_level_s, h_level_s)
    b_level_report = classification_report(b_level_s, h_level_s)

    a_level_mae = mean_absolute_error(a_level, h_level)
    b_level_mae = mean_absolute_error(b_level, h_level)

    # False-negative rates: fraction of FN-risk-flagged sessions the pipeline
    # failed to detect (tactic=No Action or level=3).
    fn_risk_ids = [i for i, fr in enumerate(fn_risk) if fr]
    a_fn_rate = (sum(1 for i in fn_risk_ids if not _fn_detected(a_tactic[i], a_level[i]))
                 / len(fn_risk_ids)) if fn_risk_ids else None
    b_fn_rate = (sum(1 for i in fn_risk_ids if not _fn_detected(b_tactic[i], b_level[i]))
                 / len(fn_risk_ids)) if fn_risk_ids else None

    # McNemar: correctness of tactic label
    a_correct = [a_tactic[i] == h_tactic[i] for i in range(len(common_ids))]
    b_correct = [b_tactic[i] == h_tactic[i] for i in range(len(common_ids))]
    mcnemar_res = mcnemar(a_correct, b_correct)

    # Bootstrap F1 diff (macro + weighted)
    boot_macro = bootstrap_f1_diff(a_tactic, b_tactic, h_tactic,
                                   n_boot=args.bootstrap, seed=args.seed, metric="macro_f1")
    boot_weighted = bootstrap_f1_diff(a_tactic, b_tactic, h_tactic,
                                      n_boot=args.bootstrap, seed=args.seed, metric="weighted_f1")

    boot_macro["verdict"] = non_inferiority_verdict(
        boot_macro["ci95_low"], boot_macro["ci95_high"], args.non_inferiority_margin)
    boot_weighted["verdict"] = non_inferiority_verdict(
        boot_weighted["ci95_low"], boot_weighted["ci95_high"], args.non_inferiority_margin)

    # Inter-annotator agreement (only on sessions annotated by >1 person)
    iaa = None
    multi = {aid: recs for aid, recs in annotations.items() if len(recs) >= 2}
    if multi:
        # Pairwise across all pairs of annotators; simple case: compute kappa
        # between the first two annotators per id.
        pairs_tactic_a, pairs_tactic_b = [], []
        pairs_level_a, pairs_level_b = [], []
        for aid, recs in multi.items():
            pairs_tactic_a.append(recs[0].get("primary_tactic"))
            pairs_tactic_b.append(recs[1].get("primary_tactic"))
            pairs_level_a.append(recs[0].get("threat_level"))
            pairs_level_b.append(recs[1].get("threat_level"))
        iaa = {
            "n_overlap": len(multi),
            "tactic_kappa": cohens_kappa(pairs_tactic_a, pairs_tactic_b),
            "level_weighted_kappa": cohens_kappa(pairs_level_a, pairs_level_b, weights="linear"),
            "tactic_percent_agreement":
                sum(1 for a, b in zip(pairs_tactic_a, pairs_tactic_b) if a == b) / len(multi),
            "level_percent_agreement":
                sum(1 for a, b in zip(pairs_level_a, pairs_level_b) if a == b) / len(multi),
        }

    # Novel-detection validation (Phase 5): for bucket='novel' samples, did
    # humans agree that agent_label's tactic was correct?
    novel_ids = [i for i, b in enumerate(buckets) if b == "novel"]
    novel_validation = None
    if novel_ids:
        agreed = sum(1 for i in novel_ids if b_tactic[i] == h_tactic[i])
        # "real threat" = human labeled something other than No Action / Unknown
        real_threat = sum(1 for i in novel_ids
                          if h_tactic[i].lower() not in ("", "no action", "unknown"))
        novel_validation = {
            "n_novel_in_sample": len(novel_ids),
            "agent_tactic_matches_human": agreed,
            "agent_precision": agreed / len(novel_ids),
            "human_saw_real_threat": real_threat,
            "human_real_threat_rate": real_threat / len(novel_ids),
            "tactic_distribution_human": dict(Counter(h_tactic[i] for i in novel_ids)),
        }

    results = {
        "n_scored": len(common_ids),
        "pipeline_A_rule_based": {
            "tactic": {
                "confusion_matrix": confusion_matrix(a_tactic, h_tactic),
                "report": a_tactic_report,
            },
            "level": {
                "confusion_matrix": confusion_matrix(a_level_s, h_level_s),
                "report": a_level_report,
                "mae": a_level_mae,
            },
            "false_negative_rate": a_fn_rate,
        },
        "pipeline_B_agent": {
            "tactic": {
                "confusion_matrix": confusion_matrix(b_tactic, h_tactic),
                "report": b_tactic_report,
            },
            "level": {
                "confusion_matrix": confusion_matrix(b_level_s, h_level_s),
                "report": b_level_report,
                "mae": b_level_mae,
            },
            "false_negative_rate": b_fn_rate,
        },
        "comparison": {
            "mcnemar_tactic": mcnemar_res,
            "bootstrap_macro_f1_diff": boot_macro,
            "bootstrap_weighted_f1_diff": boot_weighted,
            "non_inferiority_margin": args.non_inferiority_margin,
        },
        "inter_annotator_agreement": iaa,
        "novel_detection_validation": novel_validation,
        "ground_truth_annotator_counts": {
            "n_with_1_annotator": sum(1 for _, recs in annotations.items() if len(recs) == 1),
            "n_with_2+_annotators": sum(1 for _, recs in annotations.items() if len(recs) >= 2),
        },
    }

    # ---------- print summary ----------
    print("=" * 70)
    print("GROUND-TRUTH METRICS")
    print("=" * 70)
    print(f"\nScored {len(common_ids)} sessions (matched by annotation_id).")

    print("\n## Pipeline A (rule-based) vs human")
    print(f"  Tactic accuracy       : {a_tactic_report['accuracy']:.1%}")
    print(f"  Tactic macro F1       : {a_tactic_report['macro_f1']:.3f}")
    print(f"  Tactic weighted F1    : {a_tactic_report['weighted_f1']:.3f}")
    print(f"  Level accuracy        : {a_level_report['accuracy']:.1%}")
    print(f"  Level MAE             : {a_level_mae:.3f}" if a_level_mae is not None else "  Level MAE             : n/a")
    print(f"  FN rate (high-risk)   : {a_fn_rate:.1%}" if a_fn_rate is not None else "  FN rate               : n/a")

    print("\n## Pipeline B (agent) vs human")
    print(f"  Tactic accuracy       : {b_tactic_report['accuracy']:.1%}")
    print(f"  Tactic macro F1       : {b_tactic_report['macro_f1']:.3f}")
    print(f"  Tactic weighted F1    : {b_tactic_report['weighted_f1']:.3f}")
    print(f"  Level accuracy        : {b_level_report['accuracy']:.1%}")
    print(f"  Level MAE             : {b_level_mae:.3f}" if b_level_mae is not None else "  Level MAE             : n/a")
    print(f"  FN rate (high-risk)   : {b_fn_rate:.1%}" if b_fn_rate is not None else "  FN rate               : n/a")

    print("\n## Comparison")
    print(f"  McNemar (tactic)      : b={mcnemar_res.get('b_A_right_B_wrong')}, "
          f"c={mcnemar_res.get('c_A_wrong_B_right')}, p={mcnemar_res.get('p_value'):.4f}")
    print(f"  Bootstrap macro F1    : delta={boot_macro['mean_diff']:+.3f}, "
          f"95% CI [{boot_macro['ci95_low']:+.3f}, {boot_macro['ci95_high']:+.3f}]")
    print(f"    verdict             : {boot_macro['verdict']}")
    print(f"  Bootstrap weighted F1 : delta={boot_weighted['mean_diff']:+.3f}, "
          f"95% CI [{boot_weighted['ci95_low']:+.3f}, {boot_weighted['ci95_high']:+.3f}]")
    print(f"    verdict             : {boot_weighted['verdict']}")

    if iaa:
        print("\n## Inter-annotator agreement")
        print(f"  Overlap sessions      : {iaa['n_overlap']}")
        print(f"  Tactic kappa          : {iaa['tactic_kappa']:.3f}" if iaa['tactic_kappa'] is not None else "  Tactic kappa          : n/a")
        print(f"  Level weighted kappa  : {iaa['level_weighted_kappa']:.3f}" if iaa['level_weighted_kappa'] is not None else "  Level weighted kappa  : n/a")
        print(f"  Tactic % agreement    : {iaa['tactic_percent_agreement']:.1%}")
        print(f"  Level % agreement     : {iaa['level_percent_agreement']:.1%}")

    if novel_validation:
        print("\n## Novel-detection validation (Phase 5)")
        print(f"  Novel samples         : {novel_validation['n_novel_in_sample']}")
        print(f"  Agent matches human   : {novel_validation['agent_precision']:.1%}")
        print(f"  Human-confirmed threat: {novel_validation['human_real_threat_rate']:.1%}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nSaved full results to {args.output}")
    return 0


if __name__ == "__main__":
    exit(main())
