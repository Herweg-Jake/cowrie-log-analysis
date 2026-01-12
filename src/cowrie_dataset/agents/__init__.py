"""
Agentic Pipeline for Honeypot Session Analysis.

Two-agent workflow:
1. Hunter: quick triage - filters noise from statistical anomalies
2. Analyst: deep MITRE mapping with reasoning

Supports Anthropic, OpenAI, and Gemini APIs. Defaults to Gemini Flash
(free tier) for testing. Use the config presets for easy setup:

    from cowrie_dataset.agents import gemini_flash_config, AgentRunner

    runner = AgentRunner(config=gemini_flash_config())
    result = runner.process(session)
"""

from .base import (
    AgentConfig,
    AgentResponse,
    BaseAgent,
    gemini_flash_config,
    gemini_pro_config,
    claude_sonnet_config,
)
from .hunter import HunterAgent
from .analyst import AnalystAgent
from .runner import AgentRunner, AgentPipelineResult, AgentRunnerStats

__all__ = [
    # config
    "AgentConfig",
    "AgentResponse",
    "gemini_flash_config",
    "gemini_pro_config",
    "claude_sonnet_config",
    # agents
    "BaseAgent",
    "HunterAgent",
    "AnalystAgent",
    # runner
    "AgentRunner",
    "AgentPipelineResult",
    "AgentRunnerStats",
]
