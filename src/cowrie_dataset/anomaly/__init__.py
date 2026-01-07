"""
Statistical Anomaly Detection Module.

Uses Z-scores to identify sessions that deviate significantly from the norm.
This pre-filters sessions before sending to expensive LLM agents.
"""

from .statistical_detector import (
    AnomalyStats,
    AnomalyResult,
    StatisticalAnomalyDetector,
    add_anomaly_flag,
    ANOMALY_FEATURES,
)

__all__ = [
    "AnomalyStats",
    "AnomalyResult",
    "StatisticalAnomalyDetector",
    "add_anomaly_flag",
    "ANOMALY_FEATURES",
]
