"""
Statistical anomaly detection using Z-scores.

The idea is simple: most honeypot sessions are boring bot scans. We only want
to send the weird ones to expensive LLM agents. This module learns what
"normal" looks like from historical data, then flags sessions that deviate
significantly.

Uses Welford's online algorithm for computing running mean/variance, which
is numerically stable and memory-efficient (no need to store all samples).
"""

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class FeatureStats:
    """Running statistics for a single numeric feature."""

    name: str
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0  # sum of squared deviations (for variance)

    @property
    def variance(self) -> float:
        # need at least 2 samples for meaningful variance
        return self.m2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)

    def update(self, value: float) -> None:
        """
        Add a new sample using Welford's algorithm.

        This is the "proper" way to compute running variance without
        accumulating floating point errors. See Knuth TAOCP vol 2.
        """
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    def z_score(self, value: float) -> float:
        """How many std devs is this value from the mean?"""
        if self.std_dev < 0.0001:  # avoid div by zero for constant features
            return 0.0
        return (value - self.mean) / self.std_dev


@dataclass
class AnomalyResult:
    """What the detector found about a session."""

    is_anomaly: bool
    score: float  # max |z-score| across all features
    reasons: list[str]  # which features triggered the anomaly
    z_scores: dict[str, float]  # all z-scores for debugging


# Features we actually care about for anomaly detection.
# These are the ones that tend to vary meaningfully between boring scans
# and interesting attacks. Picked from the F1-F52 feature set.
ANOMALY_FEATURES = [
    # timing - fast or slow sessions stand out
    "F44_duration",
    "F38_messages_per_sec",
    "extra_chars_per_sec",

    # command volume
    "extra_num_commands",
    "extra_unique_commands",
    "extra_avg_cmd_length",

    # specific attack indicators
    "F28_keyword_wget",
    "F29_keyword_tftp",
    "F14_keyword_chmod",
    "F16_keyword_rm",
    "F17_keyword_history",
    "extra_keyword_curl",

    # file transfer is always interesting
    "F46_download_count",
]


class StatisticalAnomalyDetector:
    """
    Learns what "normal" sessions look like, then flags outliers.

    Training phase:
        detector = StatisticalAnomalyDetector()
        for session in historical_data:
            detector.train(session["features"])
        detector.save("stats.json")

    Detection phase:
        detector = StatisticalAnomalyDetector.load("stats.json")
        result = detector.check(new_session["features"])
        if result.is_anomaly:
            # send to expensive LLM analysis
    """

    def __init__(self, z_threshold: float = 3.0, min_samples: int = 100):
        """
        Args:
            z_threshold: How many std devs to consider anomalous (3.0 = 99.7%)
            min_samples: Need this many samples before we trust the stats
        """
        self.z_threshold = z_threshold
        self.min_samples = min_samples
        self.stats: dict[str, FeatureStats] = {
            name: FeatureStats(name=name) for name in ANOMALY_FEATURES
        }
        self._trained = False

    def train(self, features: dict) -> None:
        """Feed a session's features to update our running stats."""
        for name, stat in self.stats.items():
            if name not in features:
                continue
            val = features[name]
            # skip non-numeric or nan values
            if isinstance(val, (int, float)) and not math.isnan(val):
                stat.update(float(val))

        # check if we have enough samples now
        sample_counts = [s.count for s in self.stats.values()]
        if sample_counts and min(sample_counts) >= self.min_samples:
            self._trained = True

    def check(self, features: dict) -> AnomalyResult:
        """
        Check if a session is anomalous.

        Returns an AnomalyResult with details about what made it weird.
        """
        if not self._trained:
            # before training, be conservative - flag everything
            return AnomalyResult(
                is_anomaly=True,
                score=0.0,
                reasons=["detector not trained yet"],
                z_scores={},
            )

        z_scores = {}
        reasons = []
        max_z = 0.0

        for name, stat in self.stats.items():
            if name not in features or stat.count < self.min_samples:
                continue

            val = features[name]
            if not isinstance(val, (int, float)) or math.isnan(val):
                continue

            z = stat.z_score(float(val))
            z_scores[name] = round(z, 3)

            # check if this feature alone makes it an outlier
            if abs(z) > self.z_threshold:
                direction = "high" if z > 0 else "low"
                reasons.append(f"{name}={val} ({direction}, z={z:.1f})")

            if abs(z) > abs(max_z):
                max_z = z

        return AnomalyResult(
            is_anomaly=len(reasons) > 0,
            score=round(abs(max_z), 3),
            reasons=reasons,
            z_scores=z_scores,
        )

    def save(self, path: Path | str) -> None:
        """Dump learned stats to JSON for later use."""
        data = {
            "z_threshold": self.z_threshold,
            "min_samples": self.min_samples,
            "trained": self._trained,
            "features": {
                name: {
                    "count": stat.count,
                    "mean": stat.mean,
                    "m2": stat.m2,
                    "std_dev": stat.std_dev,
                }
                for name, stat in self.stats.items()
            },
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: Path | str) -> "StatisticalAnomalyDetector":
        """Load pre-trained stats from JSON."""
        with open(path) as f:
            data = json.load(f)

        detector = cls(
            z_threshold=data["z_threshold"],
            min_samples=data["min_samples"],
        )
        detector._trained = data["trained"]

        for name, fdata in data["features"].items():
            if name in detector.stats:
                detector.stats[name].count = fdata["count"]
                detector.stats[name].mean = fdata["mean"]
                detector.stats[name].m2 = fdata["m2"]

        return detector

    @property
    def is_trained(self) -> bool:
        return self._trained

    def summary(self) -> str:
        """Quick summary of what we learned."""
        lines = [f"StatisticalAnomalyDetector (trained={self._trained})"]
        lines.append(f"  z_threshold={self.z_threshold}, min_samples={self.min_samples}")
        for name, stat in self.stats.items():
            if stat.count > 0:
                lines.append(f"  {name}: n={stat.count}, mean={stat.mean:.2f}, std={stat.std_dev:.2f}")
        return "\n".join(lines)


def add_anomaly_flag(session: dict, detector: StatisticalAnomalyDetector) -> dict:
    """
    Convenience function to add anomaly detection results to a session dict.

    Modifies the dict in-place and returns it.
    """
    features = session.get("features", {})
    result = detector.check(features)

    session["statistical_anomaly"] = {
        "is_anomaly": result.is_anomaly,
        "score": result.score,
        "reasons": result.reasons,
        "z_scores": result.z_scores,
    }
    return session
