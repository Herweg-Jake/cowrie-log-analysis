"""Evaluation framework: metrics, agreement, bootstrap CIs.

Every later phase's pipeline output gets scored through here, so the public
surface in ``metrics`` is the only thing callers should depend on.
"""

from .metrics import (
    Annotation,
    Label,
    agreement_metrics,
    bootstrap_f1_diff,
    calibration_curve,
    cohens_kappa,
    confusion_matrix,
    false_negative_rate,
    load_annotations,
    load_pipeline_labels,
    macro_f1,
    mcnemar,
    per_class_metrics,
)

__all__ = [
    "Annotation",
    "Label",
    "agreement_metrics",
    "bootstrap_f1_diff",
    "calibration_curve",
    "cohens_kappa",
    "confusion_matrix",
    "false_negative_rate",
    "load_annotations",
    "load_pipeline_labels",
    "macro_f1",
    "mcnemar",
    "per_class_metrics",
]
