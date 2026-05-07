"""Pipeline C: classical ML on engineered features.

Two heads, deliberately not joint-trained:
  - tactic classifier (multi-class, LightGBM)
  - level ordinal regressor (regression-then-round, LightGBM)

This mirrors the tactic-vs-level split that the metrics framework uses,
so the comparison line up cleanly in the headline table.
"""

from .features import FEATURE_ORDER, extract_features

__all__ = ["FEATURE_ORDER", "extract_features"]
