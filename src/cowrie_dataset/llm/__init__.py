"""Provider-agnostic LLM client layer.

Pipeline B's prompts are unchanged across providers - only the transport
varies. ``make_client`` returns an ``LLMClient`` that any of the existing
agents (Hunter, Analyst) can call through.
"""

from .clients import (
    LLMClient,
    LLMResponse,
    AnthropicClient,
    OpenAIClient,
    VertexClient,
    OllamaClient,
    make_client,
    estimate_cost,
    load_price_table,
)

__all__ = [
    "LLMClient",
    "LLMResponse",
    "AnthropicClient",
    "OpenAIClient",
    "VertexClient",
    "OllamaClient",
    "make_client",
    "estimate_cost",
    "load_price_table",
]
