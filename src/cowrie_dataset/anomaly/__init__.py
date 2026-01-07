"""
Statistical anomaly detection for pre-filtering sessions.

Flags sessions that deviate from "normal" so we only send weird ones
to the expensive LLM agents.
"""

from .statistical_detector import (
    FeatureStats,
    AnomalyResult,
    StatisticalAnomalyDetector,
    add_anomaly_flag,
    ANOMALY_FEATURES,
)

__all__ = [
    "FeatureStats",
    "AnomalyResult",
    "StatisticalAnomalyDetector",
    "add_anomaly_flag",
    "ANOMALY_FEATURES",
]
