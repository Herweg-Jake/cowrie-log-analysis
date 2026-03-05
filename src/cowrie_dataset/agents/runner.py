"""
Agent Runner - orchestrates the Hunter -> Analyst pipeline.

Flow:
1. Session comes in
2. Check if it was flagged as statistically anomalous
3. If yes, ask Hunter: noise or relevant?
4. If relevant, ask Analyst for deep analysis
5. Return combined results
"""

import threading
from dataclasses import dataclass, field
from typing import Optional

from .base import AgentConfig, AgentResponse
from .hunter import HunterAgent
from .analyst import AnalystAgent


@dataclass
class AgentPipelineResult:
    """Everything we learned from running a session through the agents."""

    session_id: str
    was_anomaly: bool
    sent_to_hunter: bool
    hunter_verdict: Optional[str] = None
    sent_to_analyst: bool = False

    # raw agent responses (for debugging)
    hunter_response: Optional[AgentResponse] = None
    analyst_response: Optional[AgentResponse] = None

    # final output (this goes to ES)
    labels_agentic: dict = field(default_factory=dict)

    # cost tracking
    total_latency_ms: int = 0
    total_cost: float = 0.0

    def to_dict(self) -> dict:
        """Format for Elasticsearch storage."""
        return {
            "was_anomaly": self.was_anomaly,
            "hunter_verdict": self.hunter_verdict,
            "analyst_verdict": self.labels_agentic.get("analyst_verdict"),
            "pipeline_metrics": {
                "sent_to_hunter": self.sent_to_hunter,
                "sent_to_analyst": self.sent_to_analyst,
                "total_latency_ms": self.total_latency_ms,
                "total_cost_usd": round(self.total_cost, 6),
            },
        }


@dataclass
class AgentRunnerStats:
    """Running stats for the pipeline."""

    sessions_processed: int = 0
    sessions_anomalous: int = 0
    sent_to_hunter: int = 0
    marked_relevant: int = 0
    sent_to_analyst: int = 0
    total_latency_ms: int = 0
    total_cost: float = 0.0
    errors: int = 0


class AgentRunner:
    """
    Runs sessions through Hunter -> Analyst pipeline.

    Basic usage:
        runner = AgentRunner()
        result = runner.process(session_dict)
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
        Set up the runner.

        Args:
            config: Default config for both agents
            hunter_config: Override config for Hunter (maybe use cheaper model)
            analyst_config: Override config for Analyst (maybe use better model)
            skip_non_anomalous: Skip sessions that weren't flagged as anomalous
        """
        base_config = config or AgentConfig()
        self.skip_non_anomalous = skip_non_anomalous

        self.hunter = HunterAgent(hunter_config or base_config)
        self.analyst = AnalystAgent(analyst_config or base_config)

        self.stats = AgentRunnerStats()
        self._stats_lock = threading.Lock()

    def process(self, session: dict) -> AgentPipelineResult:
        """
        Run a session through the pipeline.

        Returns an AgentPipelineResult with whatever we learned.
        """
        session_id = session.get("session_id", "unknown")

        result = AgentPipelineResult(
            session_id=session_id,
            was_anomaly=False,
            sent_to_hunter=False,
        )

        # check if this session was flagged as anomalous
        anomaly_info = session.get("statistical_anomaly", {})
        is_anomaly = anomaly_info.get("is_anomaly", False)
        result.was_anomaly = is_anomaly

        if not is_anomaly and self.skip_non_anomalous:
            # nothing to do - just use rule-based labels
            result.labels_agentic = {"skipped": True, "reason": "not anomalous"}
            with self._stats_lock:
                self.stats.sessions_processed += 1
            return result

        # step 1: hunter triage
        result.sent_to_hunter = True
        hunter_resp = self.hunter.analyze(session)
        result.hunter_response = hunter_resp
        result.total_latency_ms += hunter_resp.latency_ms
        result.total_cost += hunter_resp.estimated_cost

        if not hunter_resp.success:
            result.labels_agentic = {"error": hunter_resp.error, "stage": "hunter"}
            with self._stats_lock:
                self.stats.sessions_processed += 1
                self.stats.sessions_anomalous += 1
                self.stats.sent_to_hunter += 1
                self.stats.total_latency_ms += hunter_resp.latency_ms
                self.stats.total_cost += hunter_resp.estimated_cost
                self.stats.errors += 1
            return result

        verdict = hunter_resp.result.get("verdict", "NOISE")
        result.hunter_verdict = verdict

        if verdict != "RELEVANT":
            # hunter says it's noise - we're done
            result.labels_agentic = {
                "is_anomaly": True,
                "hunter_verdict": "NOISE",
                "hunter_confidence": hunter_resp.result.get("confidence", 0.5),
                "hunter_reasoning": hunter_resp.result.get("reasoning", ""),
                "analyst_verdict": None,
            }
            with self._stats_lock:
                self.stats.sessions_processed += 1
                self.stats.sessions_anomalous += 1
                self.stats.sent_to_hunter += 1
                self.stats.total_latency_ms += hunter_resp.latency_ms
                self.stats.total_cost += hunter_resp.estimated_cost
            return result

        # step 2: analyst deep dive
        result.sent_to_analyst = True
        analyst_resp = self.analyst.analyze(session)
        result.analyst_response = analyst_resp
        result.total_latency_ms += analyst_resp.latency_ms
        result.total_cost += analyst_resp.estimated_cost

        if not analyst_resp.success:
            result.labels_agentic = {
                "is_anomaly": True,
                "hunter_verdict": "RELEVANT",
                "error": analyst_resp.error,
                "stage": "analyst",
            }
            with self._stats_lock:
                self.stats.sessions_processed += 1
                self.stats.sessions_anomalous += 1
                self.stats.sent_to_hunter += 1
                self.stats.marked_relevant += 1
                self.stats.sent_to_analyst += 1
                self.stats.total_latency_ms += hunter_resp.latency_ms + analyst_resp.latency_ms
                self.stats.total_cost += hunter_resp.estimated_cost + analyst_resp.estimated_cost
                self.stats.errors += 1
            return result

        # combine everything
        result.labels_agentic = {
            "is_anomaly": True,
            "hunter_verdict": "RELEVANT",
            "hunter_confidence": hunter_resp.result.get("confidence", 0.5),
            "hunter_reasoning": hunter_resp.result.get("reasoning", ""),
            "analyst_verdict": {
                "level": analyst_resp.result.get("threat_level", 2),
                "primary_tactic": analyst_resp.result.get("primary_tactic", "Unknown"),
                "all_tactics": analyst_resp.result.get("all_tactics", []),
                "technique_ids": analyst_resp.result.get("technique_ids", []),
                "sophistication": analyst_resp.result.get("sophistication", "UNKNOWN"),
                "intent": analyst_resp.result.get("intent", ""),
                "reasoning": analyst_resp.result.get("reasoning", ""),
                "confidence": analyst_resp.result.get("confidence", 0.5),
                "iocs": analyst_resp.result.get("iocs", []),
            },
        }

        with self._stats_lock:
            self.stats.sessions_processed += 1
            self.stats.sessions_anomalous += 1
            self.stats.sent_to_hunter += 1
            self.stats.marked_relevant += 1
            self.stats.sent_to_analyst += 1
            self.stats.total_latency_ms += hunter_resp.latency_ms + analyst_resp.latency_ms
            self.stats.total_cost += hunter_resp.estimated_cost + analyst_resp.estimated_cost

        return result

    def get_stats(self) -> dict:
        """Get pipeline stats for reporting."""
        s = self.stats
        return {
            "sessions_processed": s.sessions_processed,
            "sessions_anomalous": s.sessions_anomalous,
            "anomaly_rate": s.sessions_anomalous / s.sessions_processed if s.sessions_processed else 0,
            "hunter_filter_rate": 1 - (s.marked_relevant / s.sent_to_hunter) if s.sent_to_hunter else 0,
            "sessions_fully_analyzed": s.sent_to_analyst,
            "total_latency_ms": s.total_latency_ms,
            "total_cost_usd": round(s.total_cost, 4),
            "errors": s.errors,
            "avg_latency_per_session_ms": s.total_latency_ms / s.sessions_anomalous if s.sessions_anomalous else 0,
            "avg_cost_per_session_usd": s.total_cost / s.sessions_anomalous if s.sessions_anomalous else 0,
        }
