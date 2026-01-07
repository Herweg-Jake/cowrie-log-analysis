# Comparative Research Implementation Plan
## Rule-Based vs Agentic Honeypot Log Labeling

**Project:** Cowrie Honeypot Log Analysis
**Research Goal:** Quantify the value-add of AI agents in cybersecurity threat classification
**Status:** Implementation Ready

---

## Executive Summary

This plan implements two parallel pipelines for labeling Cowrie honeypot sessions:

| Pipeline | Approach | Speed | Cost | Status |
|----------|----------|-------|------|--------|
| **A (Baseline)** | Deterministic regex + static thresholds | ~10,000 sessions/sec | Free | ✅ Built |
| **B (Agentic)** | LLM-based anomaly detection + reasoning | ~0.5 sessions/sec | ~$0.01/session | 🔨 To Build |

Both pipelines output to the same Elasticsearch index with side-by-side labels, enabling direct comparison in Kibana.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Raw Cowrie Logs (.gz)                            │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    SessionAggregator (Existing)                         │
│                    Produces: Session Objects                            │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
┌───────────────────────────────┐   ┌───────────────────────────────────┐
│    PIPELINE A (Baseline)      │   │    PIPELINE B (Agentic)           │
├───────────────────────────────┤   ├───────────────────────────────────┤
│                               │   │                                   │
│  ┌─────────────────────────┐  │   │  ┌─────────────────────────────┐  │
│  │  Feature Extraction     │  │   │  │  Statistical Anomaly Filter │  │
│  │  (F1-F52 - Existing)    │  │   │  │  (Z-Score Pre-processing)   │  │
│  └───────────┬─────────────┘  │   │  └───────────┬─────────────────┘  │
│              │                │   │              │                    │
│              ▼                │   │              ▼                    │
│  ┌─────────────────────────┐  │   │  ┌─────────────────────────────┐  │
│  │  MITRE Labeler          │  │   │  │  Agent 1: Hunter (Triage)   │  │
│  │  (Regex Rules)          │  │   │  │  Filter: RELEVANT / NOISE   │  │
│  └───────────┬─────────────┘  │   │  └───────────┬─────────────────┘  │
│              │                │   │              │ (if RELEVANT)      │
│              │                │   │              ▼                    │
│              │                │   │  ┌─────────────────────────────┐  │
│              │                │   │  │  Agent 2: Analyst (Labeler) │  │
│              │                │   │  │  MITRE + Reasoning + Score  │  │
│              │                │   │  └───────────┬─────────────────┘  │
│              │                │   │              │                    │
└──────────────┼────────────────┘   └──────────────┼────────────────────┘
               │                                   │
               └─────────────┬─────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Elasticsearch Index                                │
│                  (Dual Labels Side-by-Side)                             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Baseline Refinements

### 1.1 Freeze Session Structure

**Status:** ✅ Already Complete

Your `Session.to_dict()` method produces clean JSON. No changes needed.

**Verification Task:**
```python
# scripts/verify_session_schema.py
from cowrie_dataset.aggregators import Session

# Ensure these fields exist in every session dict
REQUIRED_FIELDS = [
    'session_id', 'location', 'src_ip', 'commands',
    'authentication', 'timing', 'downloads'
]

def verify_session(session: Session) -> bool:
    doc = session.to_dict()
    return all(field in doc for field in REQUIRED_FIELDS)
```

### 1.2 Freeze MITRE Labeler Rules

**Status:** ✅ Already Complete

**Important:** Do not modify `src/cowrie_dataset/labeling/mitre_labeler.py` once experiments begin. This is your control group.

**Document the frozen state:**
```bash
# Create a snapshot of the rules
git tag baseline-rules-v1.0 -m "Frozen MITRE labeling rules for research"
```

### 1.3 Create Baseline Export Utility

**File:** `src/cowrie_dataset/export/session_exporter.py`

```python
"""
Session Exporter - Creates standardized JSON for both pipelines.

This module ensures Pipeline A and Pipeline B receive IDENTICAL input data.
"""

import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Iterator, Optional
from datetime import datetime

from cowrie_dataset.aggregators import Session
from cowrie_dataset.features import (
    extract_message_features,
    extract_host_features,
    extract_geo_features,
)
from cowrie_dataset.labeling import label_session


@dataclass
class ExportedSession:
    """Standardized session format for both pipelines."""

    # Core identifiers
    session_id: str
    location: str

    # Timing
    start_ts: str
    end_ts: Optional[str]
    duration_s: float

    # Network
    src_ip: str
    src_port: int
    dst_port: int
    protocol: str

    # Authentication
    auth_success: bool
    login_attempts: list[dict]
    final_username: Optional[str]
    final_password: Optional[str]

    # Attack data
    commands: list[dict]  # [{timestamp, input, success}]
    downloads: list[dict]
    uploads: list[dict]

    # Client fingerprint
    ssh_version: Optional[str]
    hassh: Optional[str]

    # Pre-computed features (F1-F52)
    features: dict

    # Pipeline A labels (rule-based)
    labels_rule_based: dict

    # Geo data
    geo: dict

    # Metadata
    session_type: str
    event_count: int

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, indent=2)


def export_session(
    session: Session,
    geo_enricher=None,
) -> ExportedSession:
    """
    Convert a Session to standardized export format.

    This is the SINGLE SOURCE OF TRUTH for both pipelines.
    """
    # Extract all features
    msg_features = extract_message_features(session)
    host_features = extract_host_features(session)
    geo_features = extract_geo_features(session, geo_enricher) if geo_enricher else {}

    # Merge features
    all_features = {**msg_features, **host_features}

    # Get rule-based labels
    label = label_session(session)

    return ExportedSession(
        session_id=session.session_id,
        location=session.location,
        start_ts=session.start_ts.isoformat() if session.start_ts else None,
        end_ts=session.end_ts.isoformat() if session.end_ts else None,
        duration_s=session.get_computed_duration(),
        src_ip=session.src_ip,
        src_port=session.src_port or 0,
        dst_port=session.dst_port or 22,
        protocol="ssh" if (session.dst_port or 22) == 22 else "telnet",
        auth_success=session.auth_success,
        login_attempts=[
            {"username": u, "password": p, "success": s}
            for u, p, s in session.login_attempts
        ],
        final_username=session.final_username,
        final_password=session.final_password,
        commands=session.commands,
        downloads=session.downloads,
        uploads=session.uploads,
        ssh_version=session.ssh_version,
        hassh=session.hassh,
        features=all_features,
        labels_rule_based={
            "level": label.level,
            "primary_tactic": label.primary_tactic,
            "all_tactics": label.all_tactics,
            "matched_patterns": label.matched_patterns,
        },
        geo=geo_features,
        session_type=session.get_session_type(),
        event_count=session.event_count,
    )


def export_sessions_to_jsonl(
    sessions: Iterator[Session],
    output_path: Path,
    geo_enricher=None,
) -> int:
    """Export sessions to JSON Lines format for agent processing."""
    count = 0
    with open(output_path, 'w') as f:
        for session in sessions:
            exported = export_session(session, geo_enricher)
            f.write(exported.to_json().replace('\n', ' ') + '\n')
            count += 1
    return count
```

---

## Phase 2: Statistical Anomaly Detector

### 2.1 Module Design

**File:** `src/cowrie_dataset/anomaly/statistical_detector.py`

```python
"""
Statistical Anomaly Detector - Pre-filter for Agent Pipeline.

Uses Z-scores to identify sessions that deviate significantly from the norm.
This reduces the number of sessions sent to expensive LLM agents.
"""

import json
import math
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
import statistics


@dataclass
class AnomalyStats:
    """Running statistics for a single feature."""
    name: str
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0  # Sum of squared differences from mean

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)

    def update(self, value: float) -> None:
        """Update running statistics using Welford's algorithm."""
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    def z_score(self, value: float) -> float:
        """Calculate Z-score for a value."""
        if self.std_dev == 0:
            return 0.0
        return (value - self.mean) / self.std_dev


@dataclass
class AnomalyResult:
    """Result of anomaly detection for a session."""
    is_anomaly: bool
    anomaly_score: float  # Max absolute Z-score
    anomaly_reasons: list[str]  # Features that triggered anomaly
    feature_z_scores: dict[str, float]  # All Z-scores


# Features to use for anomaly detection (subset of F1-F52)
ANOMALY_FEATURES = [
    # Timing features
    "F44_session_duration",
    "F36_messages_per_sec",
    "extra_chars_per_sec",

    # Command features
    "extra_num_commands",
    "extra_unique_commands",
    "extra_avg_cmd_length",

    # Attack indicators
    "F28_wget",
    "F29_tftp",
    "F14_chmod",
    "F16_rm",
    "F17_history",

    # Network features
    "F37_url_count",
    "F46_file_transfer",
]


class StatisticalAnomalyDetector:
    """
    Detects anomalous sessions using statistical Z-score analysis.

    Usage:
        # Training phase - process historical sessions
        detector = StatisticalAnomalyDetector()
        for session_features in historical_sessions:
            detector.update_stats(session_features)
        detector.save_stats("anomaly_stats.json")

        # Detection phase
        detector = StatisticalAnomalyDetector.load("anomaly_stats.json")
        result = detector.detect(new_session_features)
        if result.is_anomaly:
            # Send to Agent 1 for triage
            pass
    """

    def __init__(
        self,
        z_threshold: float = 3.0,
        min_samples: int = 100,
    ):
        """
        Initialize detector.

        Args:
            z_threshold: Z-score threshold for anomaly detection (default: 3.0 = 99.7%)
            min_samples: Minimum samples before detection is reliable
        """
        self.z_threshold = z_threshold
        self.min_samples = min_samples
        self.stats: dict[str, AnomalyStats] = {
            name: AnomalyStats(name=name) for name in ANOMALY_FEATURES
        }
        self._is_trained = False

    def update_stats(self, features: dict) -> None:
        """Update running statistics with a new session's features."""
        for name, stat in self.stats.items():
            if name in features:
                value = features[name]
                if isinstance(value, (int, float)) and not math.isnan(value):
                    stat.update(float(value))

        # Check if we have enough samples
        sample_counts = [s.count for s in self.stats.values()]
        if sample_counts and min(sample_counts) >= self.min_samples:
            self._is_trained = True

    def detect(self, features: dict) -> AnomalyResult:
        """
        Detect if a session is anomalous.

        Args:
            features: Session features dict (output of feature extraction)

        Returns:
            AnomalyResult with detection details
        """
        if not self._is_trained:
            # Before training, mark everything as potentially anomalous
            return AnomalyResult(
                is_anomaly=True,
                anomaly_score=0.0,
                anomaly_reasons=["Detector not yet trained"],
                feature_z_scores={},
            )

        z_scores = {}
        anomaly_reasons = []
        max_z = 0.0

        for name, stat in self.stats.items():
            if name in features and stat.count >= self.min_samples:
                value = features[name]
                if isinstance(value, (int, float)) and not math.isnan(value):
                    z = stat.z_score(float(value))
                    z_scores[name] = round(z, 3)

                    if abs(z) > self.z_threshold:
                        direction = "high" if z > 0 else "low"
                        anomaly_reasons.append(
                            f"{name}: {value} ({direction}, z={z:.2f})"
                        )

                    if abs(z) > abs(max_z):
                        max_z = z

        return AnomalyResult(
            is_anomaly=len(anomaly_reasons) > 0,
            anomaly_score=round(abs(max_z), 3),
            anomaly_reasons=anomaly_reasons,
            feature_z_scores=z_scores,
        )

    def save_stats(self, path: Path) -> None:
        """Save learned statistics to JSON."""
        data = {
            "z_threshold": self.z_threshold,
            "min_samples": self.min_samples,
            "is_trained": self._is_trained,
            "stats": {
                name: {
                    "count": stat.count,
                    "mean": stat.mean,
                    "m2": stat.m2,
                    "std_dev": stat.std_dev,
                }
                for name, stat in self.stats.items()
            }
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: Path) -> "StatisticalAnomalyDetector":
        """Load statistics from JSON."""
        with open(path) as f:
            data = json.load(f)

        detector = cls(
            z_threshold=data["z_threshold"],
            min_samples=data["min_samples"],
        )
        detector._is_trained = data["is_trained"]

        for name, stat_data in data["stats"].items():
            if name in detector.stats:
                detector.stats[name].count = stat_data["count"]
                detector.stats[name].mean = stat_data["mean"]
                detector.stats[name].m2 = stat_data["m2"]

        return detector


def add_anomaly_flag(
    session_dict: dict,
    detector: StatisticalAnomalyDetector,
) -> dict:
    """
    Add anomaly detection results to a session dict.

    Args:
        session_dict: Session dict with 'features' key
        detector: Trained anomaly detector

    Returns:
        Session dict with 'statistical_anomaly' added
    """
    features = session_dict.get("features", {})
    result = detector.detect(features)

    session_dict["statistical_anomaly"] = {
        "is_anomaly": result.is_anomaly,
        "score": result.anomaly_score,
        "reasons": result.anomaly_reasons,
        "z_scores": result.feature_z_scores,
    }

    return session_dict
```

### 2.2 Training Script

**File:** `scripts/train_anomaly_detector.py`

```python
#!/usr/bin/env python3
"""
Train the statistical anomaly detector on historical sessions.

Usage:
    python scripts/train_anomaly_detector.py --input sessions.jsonl --output anomaly_stats.json
"""

import argparse
import json
from pathlib import Path
from tqdm import tqdm

from cowrie_dataset.anomaly.statistical_detector import StatisticalAnomalyDetector


def main():
    parser = argparse.ArgumentParser(description="Train anomaly detector")
    parser.add_argument("--input", "-i", required=True, help="Input JSONL file")
    parser.add_argument("--output", "-o", required=True, help="Output stats file")
    parser.add_argument("--z-threshold", type=float, default=3.0)
    parser.add_argument("--min-samples", type=int, default=100)
    args = parser.parse_args()

    detector = StatisticalAnomalyDetector(
        z_threshold=args.z_threshold,
        min_samples=args.min_samples,
    )

    input_path = Path(args.input)
    line_count = sum(1 for _ in open(input_path))

    print(f"Training on {line_count} sessions...")

    with open(input_path) as f:
        for line in tqdm(f, total=line_count):
            session = json.loads(line)
            detector.update_stats(session.get("features", {}))

    detector.save_stats(Path(args.output))

    print(f"\nTraining complete!")
    print(f"  Trained: {detector._is_trained}")
    print(f"  Z-threshold: {detector.z_threshold}")
    print(f"\nFeature statistics:")
    for name, stat in detector.stats.items():
        if stat.count > 0:
            print(f"  {name}:")
            print(f"    count={stat.count}, mean={stat.mean:.3f}, std={stat.std_dev:.3f}")


if __name__ == "__main__":
    main()
```

---

## Phase 3: Agent Infrastructure

### 3.1 Agent Base Module

**File:** `src/cowrie_dataset/agents/__init__.py`

```python
"""
Agentic Pipeline for Honeypot Session Analysis.

This module provides LLM-based analysis using a two-agent workflow:
1. Hunter Agent: Triage - filters noise from statistical anomalies
2. Analyst Agent: Deep MITRE mapping with reasoning
"""

from .base import AgentConfig, AgentResponse
from .hunter import HunterAgent
from .analyst import AnalystAgent
from .runner import AgentRunner

__all__ = [
    "AgentConfig",
    "AgentResponse",
    "HunterAgent",
    "AnalystAgent",
    "AgentRunner",
]
```

**File:** `src/cowrie_dataset/agents/base.py`

```python
"""Base classes for agent infrastructure."""

import os
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime


@dataclass
class AgentConfig:
    """Configuration for LLM agents."""

    # API Configuration
    provider: str = "anthropic"  # "anthropic" or "openai"
    model: str = "claude-sonnet-4-20250514"
    api_key: Optional[str] = None

    # Request settings
    max_tokens: int = 1024
    temperature: float = 0.1  # Low for consistent analysis

    # Rate limiting
    requests_per_minute: int = 50
    retry_attempts: int = 3
    retry_delay: float = 1.0

    # Cost tracking
    input_cost_per_1k: float = 0.003  # Claude Sonnet input
    output_cost_per_1k: float = 0.015  # Claude Sonnet output

    def __post_init__(self):
        if self.api_key is None:
            if self.provider == "anthropic":
                self.api_key = os.environ.get("ANTHROPIC_API_KEY")
            elif self.provider == "openai":
                self.api_key = os.environ.get("OPENAI_API_KEY")


@dataclass
class AgentResponse:
    """Standardized response from an agent."""

    success: bool
    result: dict
    reasoning: Optional[str] = None

    # Metadata
    model: str = ""
    latency_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    # Cost tracking
    estimated_cost: float = 0.0

    # Error handling
    error: Optional[str] = None
    retries: int = 0


class BaseAgent(ABC):
    """Abstract base class for LLM agents."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self._client = None
        self._request_times: list[float] = []

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """Return the system prompt for this agent."""
        pass

    @abstractmethod
    def format_input(self, session: dict) -> str:
        """Format session data for the agent's user prompt."""
        pass

    @abstractmethod
    def parse_output(self, response_text: str) -> dict:
        """Parse the agent's response into structured data."""
        pass

    def _get_client(self):
        """Lazy-load the API client."""
        if self._client is None:
            if self.config.provider == "anthropic":
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.config.api_key)
            elif self.config.provider == "openai":
                import openai
                self._client = openai.OpenAI(api_key=self.config.api_key)
        return self._client

    def _rate_limit(self) -> None:
        """Enforce rate limiting."""
        now = time.time()
        # Remove requests older than 1 minute
        self._request_times = [t for t in self._request_times if now - t < 60]

        if len(self._request_times) >= self.config.requests_per_minute:
            sleep_time = 60 - (now - self._request_times[0])
            if sleep_time > 0:
                time.sleep(sleep_time)

        self._request_times.append(time.time())

    def _call_api(self, user_prompt: str) -> tuple[str, int, int]:
        """Make API call and return (response_text, input_tokens, output_tokens)."""
        client = self._get_client()

        if self.config.provider == "anthropic":
            response = client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                system=self.system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return (
                response.content[0].text,
                response.usage.input_tokens,
                response.usage.output_tokens,
            )
        elif self.config.provider == "openai":
            response = client.chat.completions.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return (
                response.choices[0].message.content,
                response.usage.prompt_tokens,
                response.usage.completion_tokens,
            )

    def analyze(self, session: dict) -> AgentResponse:
        """
        Analyze a session and return structured response.

        Args:
            session: Session dict (from ExportedSession.to_dict())

        Returns:
            AgentResponse with analysis results
        """
        user_prompt = self.format_input(session)

        for attempt in range(self.config.retry_attempts):
            try:
                self._rate_limit()

                start_time = time.time()
                response_text, input_tokens, output_tokens = self._call_api(user_prompt)
                latency_ms = int((time.time() - start_time) * 1000)

                result = self.parse_output(response_text)

                # Calculate cost
                input_cost = (input_tokens / 1000) * self.config.input_cost_per_1k
                output_cost = (output_tokens / 1000) * self.config.output_cost_per_1k

                return AgentResponse(
                    success=True,
                    result=result,
                    reasoning=result.get("reasoning"),
                    model=self.config.model,
                    latency_ms=latency_ms,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    estimated_cost=input_cost + output_cost,
                    retries=attempt,
                )

            except Exception as e:
                if attempt < self.config.retry_attempts - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))
                else:
                    return AgentResponse(
                        success=False,
                        result={},
                        error=str(e),
                        retries=attempt,
                    )
```

### 3.2 Hunter Agent (Triage)

**File:** `src/cowrie_dataset/agents/hunter.py`

```python
"""
Hunter Agent - Triage Agent for filtering noise from statistical anomalies.

Role: Determine if a statistically anomalous session is truly interesting
or just a broken bot script / scanner noise.
"""

import json
import re
from .base import BaseAgent, AgentConfig


class HunterAgent(BaseAgent):
    """
    Agent 1: The Hunter - Triage and noise filtering.

    Input: Session JSON + statistical anomaly flag
    Output: RELEVANT or NOISE with brief reasoning
    """

    @property
    def system_prompt(self) -> str:
        return """You are a Cyber Threat Hunter analyzing honeypot sessions.

Your job is to quickly triage sessions that were flagged as statistical anomalies.
Determine if the session represents a RELEVANT attack worth deeper analysis,
or just NOISE (broken scripts, scanners, random probing).

## Classification Guidelines

### Mark as RELEVANT if:
- Attacker shows clear intent (reconnaissance → exploitation → persistence)
- Commands demonstrate awareness of the system (checking OS, architecture)
- Evidence of payload download or lateral movement attempts
- Unusual but coherent command sequences
- Signs of manual operation (typos corrected, adaptive behavior)
- Anti-forensics or evasion techniques
- Attempts to establish persistence (cron, rc.local, authorized_keys)

### Mark as NOISE if:
- Only random/broken commands with no coherent goal
- Pure brute-force without post-auth activity
- Scanner fingerprinting only (just version checks)
- Bot stuck in a loop repeating the same failed command
- Empty sessions or immediate disconnects
- Only single discovery command with no follow-up

## Response Format

You MUST respond with valid JSON in this exact format:
```json
{
  "verdict": "RELEVANT" or "NOISE",
  "confidence": 0.0 to 1.0,
  "reasoning": "One sentence explanation"
}
```

Be concise. Do not explain the JSON format. Just output the JSON."""

    def format_input(self, session: dict) -> str:
        """Format session for hunter analysis."""

        # Extract key information
        commands = session.get("commands", [])
        command_inputs = [c.get("input", "") for c in commands[:50]]  # Limit

        anomaly = session.get("statistical_anomaly", {})
        rule_labels = session.get("labels_rule_based", {})

        prompt = f"""## Session Summary

**Session ID:** {session.get('session_id', 'unknown')}
**Duration:** {session.get('duration_s', 0):.1f} seconds
**Auth Success:** {session.get('auth_success', False)}
**Session Type:** {session.get('session_type', 'unknown')}

## Statistical Anomaly Flags

This session was flagged because:
{json.dumps(anomaly.get('reasons', []), indent=2)}

Anomaly Score: {anomaly.get('score', 0)}

## Rule-Based Classification (Baseline)

Level: {rule_labels.get('level', 'N/A')}
Primary Tactic: {rule_labels.get('primary_tactic', 'N/A')}
Matched Patterns: {', '.join(rule_labels.get('matched_patterns', []))}

## Commands Executed ({len(commands)} total)

```
{chr(10).join(command_inputs) if command_inputs else '(no commands)'}
```

## Your Task

Is this session RELEVANT for deeper analysis, or NOISE?
Respond with JSON only."""

        return prompt

    def parse_output(self, response_text: str) -> dict:
        """Parse hunter response."""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{[^{}]*\}', response_text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return {
                    "verdict": data.get("verdict", "NOISE").upper(),
                    "confidence": float(data.get("confidence", 0.5)),
                    "reasoning": data.get("reasoning", ""),
                }
        except (json.JSONDecodeError, ValueError):
            pass

        # Fallback: look for keywords
        text_upper = response_text.upper()
        if "RELEVANT" in text_upper:
            return {"verdict": "RELEVANT", "confidence": 0.5, "reasoning": "Parsed from text"}
        return {"verdict": "NOISE", "confidence": 0.5, "reasoning": "Parse failed, defaulting to NOISE"}
```

### 3.3 Analyst Agent (Deep Labeling)

**File:** `src/cowrie_dataset/agents/analyst.py`

```python
"""
Analyst Agent - Deep MITRE ATT&CK mapping with reasoning.

Role: Provide detailed threat analysis for sessions marked RELEVANT by the Hunter.
"""

import json
import re
from .base import BaseAgent, AgentConfig


# MITRE ATT&CK tactics relevant to honeypot attacks
MITRE_TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


class AnalystAgent(BaseAgent):
    """
    Agent 2: The Analyst - Deep MITRE mapping and reasoning.

    Input: Session JSON (RELEVANT sessions only)
    Output: Detailed threat analysis with MITRE mapping
    """

    @property
    def system_prompt(self) -> str:
        return """You are a Senior Security Analyst specializing in honeypot data analysis.

Your job is to provide detailed threat analysis of attacker sessions, including:
1. Intent identification
2. MITRE ATT&CK mapping
3. Sophistication assessment
4. Reasoning for your conclusions

## MITRE ATT&CK Tactics (choose from these)

- Initial Access: Gaining entry (T1078 Valid Accounts, T1190 Exploit Public-Facing)
- Execution: Running malicious code (T1059 Command/Script Interpreter)
- Persistence: Maintaining access (T1053 Scheduled Task, T1098 Account Manipulation)
- Privilege Escalation: Gaining higher privileges (T1548 Abuse Elevation)
- Defense Evasion: Avoiding detection (T1070 Indicator Removal, T1027 Obfuscation)
- Credential Access: Stealing credentials (T1003 Credential Dumping)
- Discovery: Learning about the system (T1082 System Info, T1083 File Discovery)
- Lateral Movement: Moving through network (T1021 Remote Services)
- Collection: Gathering data (T1005 Data from Local System)
- Command and Control: Communicating with attacker (T1071 Application Layer)
- Exfiltration: Stealing data (T1041 Exfiltration Over C2)
- Impact: Damaging systems (T1485 Data Destruction, T1486 Data Encrypted)

## Sophistication Levels

- SCRIPT_KIDDIE: Copy-pasted commands, no adaptation, common tools only
- INTERMEDIATE: Some customization, basic evasion, multiple attack phases
- ADVANCED: Custom tooling, sophisticated evasion, clear operational security
- APT: Highly targeted, novel techniques, extensive reconnaissance

## Response Format

Respond with valid JSON only:
```json
{
  "threat_level": 1-3 (1=High, 2=Medium, 3=Low),
  "primary_tactic": "One of the MITRE tactics",
  "all_tactics": ["List", "of", "tactics"],
  "technique_ids": ["T1059.004", "T1053.003"],
  "sophistication": "SCRIPT_KIDDIE|INTERMEDIATE|ADVANCED|APT",
  "intent": "Brief description of attacker's goal",
  "reasoning": "2-3 sentences explaining your analysis",
  "confidence": 0.0 to 1.0,
  "iocs": ["List of indicators of compromise found"]
}
```"""

    def format_input(self, session: dict) -> str:
        """Format session for analyst deep-dive."""

        commands = session.get("commands", [])
        downloads = session.get("downloads", [])

        # Format commands with timestamps
        command_lines = []
        for cmd in commands[:100]:  # Limit to 100 commands
            ts = cmd.get("timestamp", "")
            inp = cmd.get("input", "")
            success = "✓" if cmd.get("success") else "✗"
            command_lines.append(f"[{ts}] {success} {inp}")

        prompt = f"""## Session Analysis Request

### Session Metadata

- **Session ID:** {session.get('session_id')}
- **Location:** {session.get('location')}
- **Source IP:** {session.get('src_ip')}
- **Duration:** {session.get('duration_s', 0):.1f} seconds
- **Protocol:** {session.get('protocol', 'ssh')}

### Authentication

- **Success:** {session.get('auth_success')}
- **Username:** {session.get('final_username', 'N/A')}
- **Password:** {session.get('final_password', 'N/A')}
- **SSH Version:** {session.get('ssh_version', 'N/A')}
- **HASSH:** {session.get('hassh', 'N/A')}

### Geographic Info

{json.dumps(session.get('geo', {}), indent=2)}

### Commands Executed ({len(commands)} total)

```
{chr(10).join(command_lines) if command_lines else '(no commands)'}
```

### Downloads ({len(downloads)} files)

{json.dumps(downloads, indent=2) if downloads else '(none)'}

### Rule-Based Analysis (Baseline for comparison)

{json.dumps(session.get('labels_rule_based', {}), indent=2)}

### Statistical Anomaly Info

{json.dumps(session.get('statistical_anomaly', {}), indent=2)}

---

Analyze this session and provide your assessment as JSON."""

        return prompt

    def parse_output(self, response_text: str) -> dict:
        """Parse analyst response."""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{[^{}]*"threat_level"[^{}]*\}', response_text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return {
                    "threat_level": int(data.get("threat_level", 2)),
                    "primary_tactic": data.get("primary_tactic", "Unknown"),
                    "all_tactics": data.get("all_tactics", []),
                    "technique_ids": data.get("technique_ids", []),
                    "sophistication": data.get("sophistication", "SCRIPT_KIDDIE"),
                    "intent": data.get("intent", ""),
                    "reasoning": data.get("reasoning", ""),
                    "confidence": float(data.get("confidence", 0.5)),
                    "iocs": data.get("iocs", []),
                }
        except (json.JSONDecodeError, ValueError) as e:
            pass

        # Fallback
        return {
            "threat_level": 2,
            "primary_tactic": "Unknown",
            "all_tactics": [],
            "technique_ids": [],
            "sophistication": "UNKNOWN",
            "intent": "Parse failed",
            "reasoning": f"Could not parse response: {response_text[:100]}",
            "confidence": 0.0,
            "iocs": [],
        }
```

### 3.4 Agent Runner (Orchestrator)

**File:** `src/cowrie_dataset/agents/runner.py`

```python
"""
Agent Runner - Orchestrates the two-agent pipeline.

Flow:
1. Check if session has statistical anomaly flag
2. If anomalous, send to Hunter for triage
3. If Hunter says RELEVANT, send to Analyst for deep analysis
4. Aggregate results and return
"""

import json
import time
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

from .base import AgentConfig, AgentResponse
from .hunter import HunterAgent
from .analyst import AnalystAgent


@dataclass
class AgentPipelineResult:
    """Complete result from the agent pipeline."""

    session_id: str

    # Pipeline flow
    was_anomaly: bool
    sent_to_hunter: bool
    hunter_verdict: Optional[str] = None
    sent_to_analyst: bool = False

    # Agent outputs
    hunter_response: Optional[AgentResponse] = None
    analyst_response: Optional[AgentResponse] = None

    # Final labels (for Elasticsearch)
    labels_agentic: dict = field(default_factory=dict)

    # Metrics
    total_latency_ms: int = 0
    total_cost: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dict for Elasticsearch storage."""
        return {
            "was_anomaly": self.was_anomaly,
            "hunter_verdict": self.hunter_verdict,
            "analyst_verdict": self.labels_agentic if self.sent_to_analyst else None,
            "pipeline_metrics": {
                "sent_to_hunter": self.sent_to_hunter,
                "sent_to_analyst": self.sent_to_analyst,
                "total_latency_ms": self.total_latency_ms,
                "total_cost_usd": self.total_cost,
            }
        }


@dataclass
class AgentRunnerStats:
    """Statistics for the agent runner."""
    sessions_processed: int = 0
    sessions_anomalous: int = 0
    sessions_sent_to_hunter: int = 0
    sessions_marked_relevant: int = 0
    sessions_sent_to_analyst: int = 0
    total_latency_ms: int = 0
    total_cost_usd: float = 0.0
    errors: int = 0


class AgentRunner:
    """
    Orchestrates the Hunter → Analyst pipeline.

    Usage:
        runner = AgentRunner(config)
        result = runner.process(session_dict)

        # Add result to session for Elasticsearch
        session_dict["labels_agentic"] = result.to_dict()
    """

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        hunter_config: Optional[AgentConfig] = None,
        analyst_config: Optional[AgentConfig] = None,
        skip_non_anomalous: bool = True,
    ):
        """
        Initialize the agent runner.

        Args:
            config: Default config for both agents
            hunter_config: Override config for Hunter agent
            analyst_config: Override config for Analyst agent
            skip_non_anomalous: If True, skip sessions without anomaly flag
        """
        self.skip_non_anomalous = skip_non_anomalous

        # Use provided configs or defaults
        default_config = config or AgentConfig()

        self.hunter = HunterAgent(hunter_config or default_config)
        self.analyst = AnalystAgent(analyst_config or default_config)

        self.stats = AgentRunnerStats()

    def process(self, session: dict) -> AgentPipelineResult:
        """
        Process a single session through the agent pipeline.

        Args:
            session: Session dict with statistical_anomaly field

        Returns:
            AgentPipelineResult with analysis
        """
        session_id = session.get("session_id", "unknown")
        self.stats.sessions_processed += 1

        result = AgentPipelineResult(
            session_id=session_id,
            was_anomaly=False,
            sent_to_hunter=False,
        )

        # Check anomaly flag
        anomaly_info = session.get("statistical_anomaly", {})
        is_anomaly = anomaly_info.get("is_anomaly", False)
        result.was_anomaly = is_anomaly

        if not is_anomaly and self.skip_non_anomalous:
            # Not anomalous, use rule-based labels only
            result.labels_agentic = {
                "skipped": True,
                "reason": "Not statistically anomalous",
            }
            return result

        self.stats.sessions_anomalous += 1

        # Step 1: Hunter triage
        result.sent_to_hunter = True
        self.stats.sessions_sent_to_hunter += 1

        hunter_response = self.hunter.analyze(session)
        result.hunter_response = hunter_response
        result.total_latency_ms += hunter_response.latency_ms
        result.total_cost += hunter_response.estimated_cost
        self.stats.total_latency_ms += hunter_response.latency_ms
        self.stats.total_cost_usd += hunter_response.estimated_cost

        if not hunter_response.success:
            self.stats.errors += 1
            result.labels_agentic = {
                "error": hunter_response.error,
                "stage": "hunter",
            }
            return result

        result.hunter_verdict = hunter_response.result.get("verdict", "NOISE")

        if result.hunter_verdict != "RELEVANT":
            # Hunter filtered as noise
            result.labels_agentic = {
                "is_anomaly": True,
                "hunter_verdict": "NOISE",
                "hunter_confidence": hunter_response.result.get("confidence", 0.5),
                "hunter_reasoning": hunter_response.result.get("reasoning", ""),
                "analyst_verdict": None,
            }
            return result

        self.stats.sessions_marked_relevant += 1

        # Step 2: Analyst deep analysis
        result.sent_to_analyst = True
        self.stats.sessions_sent_to_analyst += 1

        analyst_response = self.analyst.analyze(session)
        result.analyst_response = analyst_response
        result.total_latency_ms += analyst_response.latency_ms
        result.total_cost += analyst_response.estimated_cost
        self.stats.total_latency_ms += analyst_response.latency_ms
        self.stats.total_cost_usd += analyst_response.estimated_cost

        if not analyst_response.success:
            self.stats.errors += 1
            result.labels_agentic = {
                "is_anomaly": True,
                "hunter_verdict": "RELEVANT",
                "error": analyst_response.error,
                "stage": "analyst",
            }
            return result

        # Success - combine results
        result.labels_agentic = {
            "is_anomaly": True,
            "hunter_verdict": "RELEVANT",
            "hunter_confidence": hunter_response.result.get("confidence", 0.5),
            "hunter_reasoning": hunter_response.result.get("reasoning", ""),
            "analyst_verdict": {
                "level": analyst_response.result.get("threat_level", 2),
                "primary_tactic": analyst_response.result.get("primary_tactic", "Unknown"),
                "all_tactics": analyst_response.result.get("all_tactics", []),
                "technique_ids": analyst_response.result.get("technique_ids", []),
                "sophistication": analyst_response.result.get("sophistication", "UNKNOWN"),
                "intent": analyst_response.result.get("intent", ""),
                "reasoning": analyst_response.result.get("reasoning", ""),
                "confidence": analyst_response.result.get("confidence", 0.5),
                "iocs": analyst_response.result.get("iocs", []),
            }
        }

        return result

    def get_stats(self) -> dict:
        """Get pipeline statistics."""
        return {
            "sessions_processed": self.stats.sessions_processed,
            "sessions_anomalous": self.stats.sessions_anomalous,
            "anomaly_rate": (
                self.stats.sessions_anomalous / self.stats.sessions_processed
                if self.stats.sessions_processed > 0 else 0
            ),
            "hunter_filter_rate": (
                1 - (self.stats.sessions_marked_relevant / self.stats.sessions_sent_to_hunter)
                if self.stats.sessions_sent_to_hunter > 0 else 0
            ),
            "sessions_fully_analyzed": self.stats.sessions_sent_to_analyst,
            "total_latency_ms": self.stats.total_latency_ms,
            "total_cost_usd": round(self.stats.total_cost_usd, 4),
            "errors": self.stats.errors,
            "avg_latency_per_session_ms": (
                self.stats.total_latency_ms / self.stats.sessions_anomalous
                if self.stats.sessions_anomalous > 0 else 0
            ),
            "avg_cost_per_session_usd": (
                self.stats.total_cost_usd / self.stats.sessions_anomalous
                if self.stats.sessions_anomalous > 0 else 0
            ),
        }
```

### 3.5 Main Processing Script

**File:** `scripts/run_agent_pipeline.py`

```python
#!/usr/bin/env python3
"""
Run the agent pipeline on exported sessions.

Usage:
    # Process all sessions
    python scripts/run_agent_pipeline.py --input sessions.jsonl --output labeled.jsonl

    # With trained anomaly detector
    python scripts/run_agent_pipeline.py --input sessions.jsonl --output labeled.jsonl \
        --anomaly-stats anomaly_stats.json

    # Dry run (no API calls)
    python scripts/run_agent_pipeline.py --input sessions.jsonl --output labeled.jsonl --dry-run
"""

import argparse
import json
import os
from pathlib import Path
from tqdm import tqdm

from cowrie_dataset.anomaly.statistical_detector import (
    StatisticalAnomalyDetector,
    add_anomaly_flag,
)
from cowrie_dataset.agents import AgentConfig, AgentRunner


def main():
    parser = argparse.ArgumentParser(description="Run agent pipeline")
    parser.add_argument("--input", "-i", required=True, help="Input JSONL file")
    parser.add_argument("--output", "-o", required=True, help="Output JSONL file")
    parser.add_argument("--anomaly-stats", help="Pre-trained anomaly detector stats")
    parser.add_argument("--z-threshold", type=float, default=3.0)
    parser.add_argument("--model", default="claude-sonnet-4-20250514")
    parser.add_argument("--dry-run", action="store_true", help="Skip API calls")
    parser.add_argument("--limit", type=int, help="Limit number of sessions")
    parser.add_argument("--skip-non-anomalous", action="store_true", default=True)
    args = parser.parse_args()

    # Load or create anomaly detector
    if args.anomaly_stats:
        print(f"Loading anomaly detector from {args.anomaly_stats}...")
        detector = StatisticalAnomalyDetector.load(Path(args.anomaly_stats))
    else:
        print("No anomaly stats provided, will flag all sessions as anomalous")
        detector = None

    # Setup agent runner
    if args.dry_run:
        print("DRY RUN - no API calls will be made")
        runner = None
    else:
        config = AgentConfig(model=args.model)
        runner = AgentRunner(config=config, skip_non_anomalous=args.skip_non_anomalous)

    # Count input lines
    input_path = Path(args.input)
    line_count = sum(1 for _ in open(input_path))
    if args.limit:
        line_count = min(line_count, args.limit)

    print(f"Processing {line_count} sessions...")

    # Process sessions
    output_path = Path(args.output)
    processed = 0

    with open(input_path) as f_in, open(output_path, 'w') as f_out:
        for i, line in enumerate(tqdm(f_in, total=line_count)):
            if args.limit and i >= args.limit:
                break

            session = json.loads(line)

            # Add anomaly flag if detector available
            if detector:
                session = add_anomaly_flag(session, detector)
            else:
                # Flag everything as anomalous for testing
                session["statistical_anomaly"] = {
                    "is_anomaly": True,
                    "score": 0.0,
                    "reasons": ["No detector - flagging all"],
                    "z_scores": {},
                }

            # Run agent pipeline
            if runner:
                result = runner.process(session)
                session["labels_agentic"] = result.to_dict()
            else:
                # Dry run - add placeholder
                session["labels_agentic"] = {
                    "dry_run": True,
                    "was_anomaly": session.get("statistical_anomaly", {}).get("is_anomaly", False),
                }

            # Write output
            f_out.write(json.dumps(session) + '\n')
            processed += 1

    print(f"\nProcessed {processed} sessions")

    if runner:
        stats = runner.get_stats()
        print("\nPipeline Statistics:")
        print(f"  Anomaly rate: {stats['anomaly_rate']:.1%}")
        print(f"  Hunter filter rate: {stats['hunter_filter_rate']:.1%}")
        print(f"  Fully analyzed: {stats['sessions_fully_analyzed']}")
        print(f"  Total cost: ${stats['total_cost_usd']:.4f}")
        print(f"  Avg latency: {stats['avg_latency_per_session_ms']:.0f}ms")
        print(f"  Errors: {stats['errors']}")


if __name__ == "__main__":
    main()
```

---

## Phase 4: Elasticsearch Schema Updates

### 4.1 Updated Index Mapping

**File:** `src/cowrie_dataset/sinks/elasticsearch_sink.py` (additions)

Add this to the existing `SESSION_INDEX_MAPPING`:

```python
# Add to SESSION_INDEX_MAPPING["mappings"]["properties"]

# Statistical Anomaly Detection
"statistical_anomaly": {
    "type": "object",
    "properties": {
        "is_anomaly": {"type": "boolean"},
        "score": {"type": "float"},
        "reasons": {"type": "keyword"},
        "z_scores": {
            "type": "object",
            "dynamic": True
        }
    }
},

# Pipeline A Output - Rule Based (rename existing 'labels')
"labels_rule_based": {
    "type": "object",
    "properties": {
        "level": {"type": "integer"},
        "primary_tactic": {"type": "keyword"},
        "all_tactics": {"type": "keyword"},
        "matched_patterns": {"type": "keyword"}
    }
},

# Pipeline B Output - Agentic
"labels_agentic": {
    "type": "object",
    "properties": {
        "skipped": {"type": "boolean"},
        "was_anomaly": {"type": "boolean"},
        "hunter_verdict": {"type": "keyword"},
        "hunter_confidence": {"type": "float"},
        "hunter_reasoning": {"type": "text"},
        "analyst_verdict": {
            "type": "object",
            "properties": {
                "level": {"type": "integer"},
                "primary_tactic": {"type": "keyword"},
                "all_tactics": {"type": "keyword"},
                "technique_ids": {"type": "keyword"},
                "sophistication": {"type": "keyword"},
                "intent": {"type": "text"},
                "reasoning": {"type": "text"},
                "confidence": {"type": "float"},
                "iocs": {"type": "keyword"}
            }
        },
        "pipeline_metrics": {
            "type": "object",
            "properties": {
                "sent_to_hunter": {"type": "boolean"},
                "sent_to_analyst": {"type": "boolean"},
                "total_latency_ms": {"type": "integer"},
                "total_cost_usd": {"type": "float"}
            }
        },
        "error": {"type": "text"},
        "stage": {"type": "keyword"}
    }
},

# Comparison Flags (computed during indexing)
"label_comparison": {
    "type": "object",
    "properties": {
        "tactics_agree": {"type": "boolean"},
        "levels_agree": {"type": "boolean"},
        "rule_level": {"type": "integer"},
        "agent_level": {"type": "integer"},
        "level_difference": {"type": "integer"}
    }
}
```

### 4.2 Document Builder Update

**File:** `src/cowrie_dataset/sinks/document_builder.py` (new)

```python
"""
Document Builder - Creates Elasticsearch documents with both pipeline outputs.
"""

from typing import Optional


def compute_label_comparison(
    rule_labels: dict,
    agent_labels: dict,
) -> dict:
    """
    Compute comparison metrics between rule-based and agentic labels.

    Returns dict with comparison flags for Kibana filtering.
    """
    # Get levels
    rule_level = rule_labels.get("level")

    analyst_verdict = agent_labels.get("analyst_verdict")
    agent_level = analyst_verdict.get("level") if analyst_verdict else None

    # Get tactics
    rule_tactic = rule_labels.get("primary_tactic", "").lower()
    agent_tactic = ""
    if analyst_verdict:
        agent_tactic = analyst_verdict.get("primary_tactic", "").lower()

    return {
        "tactics_agree": rule_tactic == agent_tactic if agent_tactic else None,
        "levels_agree": rule_level == agent_level if agent_level else None,
        "rule_level": rule_level,
        "agent_level": agent_level,
        "level_difference": (
            abs(rule_level - agent_level)
            if rule_level and agent_level else None
        ),
    }


def build_elasticsearch_document(
    session: dict,
    agent_result: Optional[dict] = None,
) -> dict:
    """
    Build complete Elasticsearch document with both pipeline outputs.

    Args:
        session: Session dict with features and rule-based labels
        agent_result: Optional AgentPipelineResult.to_dict() output

    Returns:
        Complete document ready for indexing
    """
    doc = session.copy()

    # Rename 'labels' to 'labels_rule_based' if needed
    if "labels" in doc and "labels_rule_based" not in doc:
        doc["labels_rule_based"] = doc.pop("labels")

    # Add agentic labels if provided
    if agent_result:
        doc["labels_agentic"] = agent_result

        # Compute comparison if both have results
        rule_labels = doc.get("labels_rule_based", {})
        if rule_labels and agent_result.get("analyst_verdict"):
            doc["label_comparison"] = compute_label_comparison(
                rule_labels, agent_result
            )

    return doc
```

---

## Phase 5: Evaluation Framework

### 5.1 Disagreement Analyzer

**File:** `scripts/analyze_disagreements.py`

```python
#!/usr/bin/env python3
"""
Analyze disagreements between rule-based and agentic labels.

Usage:
    python scripts/analyze_disagreements.py --es-host http://localhost:9200 --index cowrie-sessions
"""

import argparse
import json
from elasticsearch import Elasticsearch


def query_disagreements(es: Elasticsearch, index: str, size: int = 100) -> list:
    """Find sessions where pipelines disagree on primary tactic."""

    query = {
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "labels_rule_based.primary_tactic"}},
                    {"exists": {"field": "labels_agentic.analyst_verdict.primary_tactic"}},
                ],
                "must_not": [
                    {
                        "script": {
                            "script": {
                                "source": """
                                    doc['labels_rule_based.primary_tactic'].value ==
                                    doc['labels_agentic.analyst_verdict.primary_tactic'].value
                                """
                            }
                        }
                    }
                ]
            }
        },
        "size": size,
        "_source": [
            "session_id",
            "commands",
            "labels_rule_based",
            "labels_agentic",
        ]
    }

    response = es.search(index=index, body=query)
    return [hit["_source"] for hit in response["hits"]["hits"]]


def query_agent_only_detections(es: Elasticsearch, index: str, size: int = 100) -> list:
    """Find high-threat sessions where rules found nothing but agent did."""

    query = {
        "query": {
            "bool": {
                "must": [
                    # Rule-based found no patterns
                    {"term": {"labels_rule_based.matched_patterns": []}},
                    # But agent marked as high threat
                    {"term": {"labels_agentic.analyst_verdict.level": 1}},
                ]
            }
        },
        "size": size,
    }

    response = es.search(index=index, body=query)
    return [hit["_source"] for hit in response["hits"]["hits"]]


def calculate_agreement_stats(es: Elasticsearch, index: str) -> dict:
    """Calculate overall agreement statistics."""

    # Total sessions with both labels
    total_query = {
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "labels_rule_based"}},
                    {"exists": {"field": "labels_agentic.analyst_verdict"}},
                ]
            }
        }
    }

    total = es.count(index=index, body=total_query)["count"]

    # Tactic agreements
    tactic_agree_query = {
        "query": {
            "term": {"label_comparison.tactics_agree": True}
        }
    }
    tactic_agree = es.count(index=index, body=tactic_agree_query)["count"]

    # Level agreements
    level_agree_query = {
        "query": {
            "term": {"label_comparison.levels_agree": True}
        }
    }
    level_agree = es.count(index=index, body=level_agree_query)["count"]

    return {
        "total_dual_labeled": total,
        "tactic_agreement_rate": tactic_agree / total if total > 0 else 0,
        "level_agreement_rate": level_agree / total if total > 0 else 0,
        "tactic_disagreements": total - tactic_agree,
        "level_disagreements": total - level_agree,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--es-host", default="http://localhost:9200")
    parser.add_argument("--index", default="cowrie-sessions")
    parser.add_argument("--sample-size", type=int, default=50)
    parser.add_argument("--output", help="Output file for disagreement samples")
    args = parser.parse_args()

    es = Elasticsearch(args.es_host)

    print("=" * 60)
    print("LABEL DISAGREEMENT ANALYSIS")
    print("=" * 60)

    # Overall stats
    stats = calculate_agreement_stats(es, args.index)
    print(f"\nOverall Statistics:")
    print(f"  Total dual-labeled sessions: {stats['total_dual_labeled']}")
    print(f"  Tactic agreement rate: {stats['tactic_agreement_rate']:.1%}")
    print(f"  Level agreement rate: {stats['level_agreement_rate']:.1%}")

    # Get disagreement samples
    print(f"\nSampling {args.sample_size} disagreements...")
    disagreements = query_disagreements(es, args.index, args.sample_size)

    print(f"\nDisagreement Examples:")
    for i, session in enumerate(disagreements[:5]):
        print(f"\n--- Example {i+1} ---")
        print(f"Session: {session['session_id']}")
        print(f"Rule-based: {session['labels_rule_based']['primary_tactic']}")
        print(f"Agent: {session['labels_agentic']['analyst_verdict']['primary_tactic']}")
        print(f"Agent reasoning: {session['labels_agentic']['analyst_verdict'].get('reasoning', 'N/A')}")

    # Agent-only detections
    print(f"\n\nAgent-Only Detections (Rules missed):")
    agent_only = query_agent_only_detections(es, args.index, 10)
    print(f"Found {len(agent_only)} sessions where agent found threats rules missed")

    # Save full results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                "stats": stats,
                "disagreements": disagreements,
                "agent_only_detections": agent_only,
            }, f, indent=2)
        print(f"\nFull results saved to {args.output}")


if __name__ == "__main__":
    main()
```

### 5.2 Cost-Benefit Analysis

**File:** `scripts/cost_benefit_analysis.py`

```python
#!/usr/bin/env python3
"""
Cost-Benefit Analysis for Rule-Based vs Agentic Pipeline.

Compares:
- Processing speed
- Cost per session
- Detection accuracy (where ground truth available)
- False positive reduction
"""

import argparse
import json
import time
from pathlib import Path
from elasticsearch import Elasticsearch


def calculate_metrics(es: Elasticsearch, index: str) -> dict:
    """Calculate comprehensive cost-benefit metrics."""

    # Total sessions
    total = es.count(index=index)["count"]

    # Sessions processed by agents
    agent_processed_query = {
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "labels_agentic"}},
                    {"term": {"labels_agentic.skipped": False}},
                ]
            }
        }
    }
    agent_processed = es.count(index=index, body=agent_processed_query)["count"]

    # Cost aggregation
    cost_agg = es.search(
        index=index,
        body={
            "size": 0,
            "aggs": {
                "total_cost": {
                    "sum": {"field": "labels_agentic.pipeline_metrics.total_cost_usd"}
                },
                "total_latency": {
                    "sum": {"field": "labels_agentic.pipeline_metrics.total_latency_ms"}
                },
                "hunter_only": {
                    "filter": {
                        "bool": {
                            "must": [
                                {"term": {"labels_agentic.pipeline_metrics.sent_to_hunter": True}},
                                {"term": {"labels_agentic.pipeline_metrics.sent_to_analyst": False}},
                            ]
                        }
                    }
                },
                "full_analysis": {
                    "filter": {
                        "term": {"labels_agentic.pipeline_metrics.sent_to_analyst": True}
                    }
                }
            }
        }
    )

    aggs = cost_agg["aggregations"]

    return {
        "total_sessions": total,
        "agent_processed": agent_processed,
        "agent_processing_rate": agent_processed / total if total > 0 else 0,

        # Cost metrics
        "total_cost_usd": aggs["total_cost"]["value"],
        "avg_cost_per_session": (
            aggs["total_cost"]["value"] / agent_processed
            if agent_processed > 0 else 0
        ),

        # Latency metrics
        "total_latency_s": aggs["total_latency"]["value"] / 1000,
        "avg_latency_per_session_ms": (
            aggs["total_latency"]["value"] / agent_processed
            if agent_processed > 0 else 0
        ),

        # Pipeline flow
        "hunter_filtered": aggs["hunter_only"]["doc_count"],
        "fully_analyzed": aggs["full_analysis"]["doc_count"],
        "hunter_filter_rate": (
            aggs["hunter_only"]["doc_count"] / agent_processed
            if agent_processed > 0 else 0
        ),

        # Efficiency estimates
        "rule_based_speed_estimate": total * 0.0001,  # ~0.1ms per session
        "agent_speed_ratio": (
            (aggs["total_latency"]["value"] / agent_processed) / 0.1
            if agent_processed > 0 else 0
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--es-host", default="http://localhost:9200")
    parser.add_argument("--index", default="cowrie-sessions")
    args = parser.parse_args()

    es = Elasticsearch(args.es_host)
    metrics = calculate_metrics(es, args.index)

    print("=" * 70)
    print("COST-BENEFIT ANALYSIS: Rule-Based vs Agentic Pipeline")
    print("=" * 70)

    print(f"\n## Dataset Summary")
    print(f"Total sessions: {metrics['total_sessions']:,}")
    print(f"Agent-processed: {metrics['agent_processed']:,} ({metrics['agent_processing_rate']:.1%})")

    print(f"\n## Cost Metrics")
    print(f"Total API cost: ${metrics['total_cost_usd']:.4f}")
    print(f"Avg cost/session: ${metrics['avg_cost_per_session']:.6f}")

    print(f"\n## Speed Metrics")
    print(f"Total agent time: {metrics['total_latency_s']:.1f}s")
    print(f"Avg latency/session: {metrics['avg_latency_per_session_ms']:.0f}ms")
    print(f"Speed ratio (agent/rule): {metrics['agent_speed_ratio']:.0f}x slower")

    print(f"\n## Pipeline Efficiency")
    print(f"Hunter filtered (noise): {metrics['hunter_filtered']:,} ({metrics['hunter_filter_rate']:.1%})")
    print(f"Fully analyzed: {metrics['fully_analyzed']:,}")

    print(f"\n## Projections")
    if metrics['total_sessions'] > 0:
        projected_cost = metrics['avg_cost_per_session'] * 1_000_000
        print(f"Cost for 1M sessions: ${projected_cost:,.2f}")
        projected_time = (metrics['avg_latency_per_session_ms'] * 1_000_000) / 1000 / 3600
        print(f"Time for 1M sessions: {projected_time:,.1f} hours")


if __name__ == "__main__":
    main()
```

---

## Appendix A: File Structure

```
cowrie-log-analysis/
├── src/cowrie_dataset/
│   ├── __init__.py
│   ├── cli.py                          # (existing)
│   ├── config.py                       # (existing)
│   ├── parsers/                        # (existing)
│   ├── aggregators/                    # (existing)
│   ├── features/                       # (existing)
│   ├── labeling/                       # (existing)
│   ├── sinks/
│   │   ├── __init__.py
│   │   ├── elasticsearch_sink.py       # (update mapping)
│   │   └── document_builder.py         # NEW
│   ├── export/
│   │   ├── __init__.py                 # NEW
│   │   └── session_exporter.py         # NEW
│   ├── anomaly/
│   │   ├── __init__.py                 # NEW
│   │   └── statistical_detector.py     # NEW
│   └── agents/
│       ├── __init__.py                 # NEW
│       ├── base.py                     # NEW
│       ├── hunter.py                   # NEW
│       ├── analyst.py                  # NEW
│       └── runner.py                   # NEW
├── scripts/
│   ├── run_mvp_test.py                 # (existing)
│   ├── train_anomaly_detector.py       # NEW
│   ├── run_agent_pipeline.py           # NEW
│   ├── analyze_disagreements.py        # NEW
│   └── cost_benefit_analysis.py        # NEW
├── docs/
│   └── IMPLEMENTATION_PLAN.md          # This document
├── tests/                              # NEW
│   ├── __init__.py
│   ├── test_anomaly_detector.py
│   ├── test_agents.py
│   └── test_document_builder.py
└── pyproject.toml                      # (add anthropic dependency)
```

---

## Appendix B: Dependencies Update

Add to `pyproject.toml`:

```toml
[project.optional-dependencies]
agents = [
    "anthropic>=0.18.0",
    "openai>=1.12.0",
]
```

---

## Appendix C: Quick Start Commands

```bash
# 1. Export sessions to JSONL
python -m cowrie_dataset.cli --all --export sessions.jsonl

# 2. Train anomaly detector
python scripts/train_anomaly_detector.py \
    --input sessions.jsonl \
    --output anomaly_stats.json

# 3. Run agent pipeline (dry run first)
python scripts/run_agent_pipeline.py \
    --input sessions.jsonl \
    --output labeled.jsonl \
    --anomaly-stats anomaly_stats.json \
    --dry-run

# 4. Run agent pipeline (real)
export ANTHROPIC_API_KEY=your_key_here
python scripts/run_agent_pipeline.py \
    --input sessions.jsonl \
    --output labeled.jsonl \
    --anomaly-stats anomaly_stats.json \
    --limit 100  # Start small

# 5. Index to Elasticsearch
python scripts/index_to_elastic.py \
    --input labeled.jsonl \
    --es-host http://192.168.3.x:9200

# 6. Analyze results
python scripts/analyze_disagreements.py \
    --es-host http://192.168.3.x:9200 \
    --output disagreements.json

python scripts/cost_benefit_analysis.py \
    --es-host http://192.168.3.x:9200
```

---

## Appendix D: Research Hypotheses

| # | Hypothesis | Metric | Expected Outcome |
|---|------------|--------|------------------|
| H1 | Agents identify attacker intent more accurately | Tactic disagreement rate | Agent correct >70% in manual review |
| H2 | Agents detect novel attacks missed by rules | Zero-pattern agent detections | >5% of high-threat sessions |
| H3 | Hunter reduces false positives | Hunter filter rate | >60% noise filtered |
| H4 | Agent cost is acceptable for post-processing | Cost per insight | <$1 per novel finding |
| H5 | Sophistication scoring improves triage | Correlation with manual review | >0.8 correlation |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-01-07 | Claude | Initial implementation plan |
