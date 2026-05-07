"""Thin client wrappers, one per provider.

The protocol is deliberately minimal: a single ``complete`` call that
returns text + token counts + latency. Pipeline B's stages handle the
prompt formatting and parsing themselves.

Implementations lazy-import their SDKs so ``import cowrie_dataset.llm``
doesn't drag in google-genai or anthropic when you only need ollama.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class LLMResponse:
    text: str
    input_tokens: int
    output_tokens: int
    latency_ms: int
    model: str


class LLMClient(Protocol):
    name: str
    model: str

    def complete(self, system: str, user: str, *,
                 max_tokens: int = 4096,
                 temperature: float = 0.1) -> LLMResponse: ...


# ---------------------------------------------------------------------------

class AnthropicClient:
    name = "anthropic"

    def __init__(self, model: str, api_key: str | None = None):
        self.model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None

    def _ensure(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    def complete(self, system, user, *, max_tokens=4096, temperature=0.1):
        client = self._ensure()
        t0 = time.time()
        resp = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return LLMResponse(
            text=resp.content[0].text,
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
            latency_ms=int((time.time() - t0) * 1000),
            model=self.model,
        )


class OpenAIClient:
    name = "openai"

    def __init__(self, model: str, api_key: str | None = None):
        self.model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self._client = None

    def _ensure(self):
        if self._client is None:
            import openai
            self._client = openai.OpenAI(api_key=self._api_key)
        return self._client

    def complete(self, system, user, *, max_tokens=4096, temperature=0.1):
        client = self._ensure()
        t0 = time.time()
        resp = client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return LLMResponse(
            text=resp.choices[0].message.content,
            input_tokens=resp.usage.prompt_tokens,
            output_tokens=resp.usage.completion_tokens,
            latency_ms=int((time.time() - t0) * 1000),
            model=self.model,
        )


class VertexClient:
    """Google Vertex AI / AI Studio. Picks Vertex if GOOGLE_CLOUD_PROJECT is set."""
    name = "vertex"

    def __init__(self, model: str, project_id: str | None = None,
                 location: str = "us-central1", api_key: str | None = None):
        self.model = model
        self._project = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
        self._location = location
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        self._client = None

    def _ensure(self):
        if self._client is None:
            from google import genai
            if self._project:
                self._client = genai.Client(vertexai=True,
                                            project=self._project,
                                            location=self._location)
            else:
                self._client = genai.Client(api_key=self._api_key)
        return self._client

    def complete(self, system, user, *, max_tokens=4096, temperature=0.1):
        client = self._ensure()
        from google.genai import types
        t0 = time.time()
        resp = client.models.generate_content(
            model=self.model,
            contents=user,
            config=types.GenerateContentConfig(
                system_instruction=system,
                max_output_tokens=max_tokens,
                temperature=temperature,
            ),
        )
        usage = resp.usage_metadata
        return LLMResponse(
            text=resp.text,
            input_tokens=usage.prompt_token_count or 0,
            output_tokens=usage.candidates_token_count or 0,
            latency_ms=int((time.time() - t0) * 1000),
            model=self.model,
        )


class OllamaClient:
    """Local model via Ollama's HTTP API."""
    name = "ollama"

    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        self.model = model
        self._base = base_url.rstrip("/")

    def complete(self, system, user, *, max_tokens=4096, temperature=0.1):
        import urllib.request
        body = json.dumps({
            "model": self.model,
            "system": system,
            "prompt": user,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }).encode()
        req = urllib.request.Request(
            f"{self._base}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        t0 = time.time()
        with urllib.request.urlopen(req) as r:
            data = json.loads(r.read())
        return LLMResponse(
            text=data.get("response", ""),
            input_tokens=int(data.get("prompt_eval_count", 0) or 0),
            output_tokens=int(data.get("eval_count", 0) or 0),
            latency_ms=int((time.time() - t0) * 1000),
            model=self.model,
        )


def make_client(provider: str, model: str, **kwargs) -> LLMClient:
    p = provider.lower()
    if p == "anthropic":
        return AnthropicClient(model=model, **kwargs)
    if p == "openai":
        return OpenAIClient(model=model, **kwargs)
    if p in ("vertex", "gemini", "google"):
        return VertexClient(model=model, **kwargs)
    if p == "ollama":
        return OllamaClient(model=model, **kwargs)
    raise ValueError(f"unknown provider: {provider!r}")


# ---------------------------------------------------------------------------
# Cost table

_DEFAULT_PRICES = Path(__file__).resolve().parent.parent.parent.parent / "config" / "llm_costs.json"


def load_price_table(path: str | Path | None = None) -> dict:
    p = Path(path) if path else _DEFAULT_PRICES
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def estimate_cost(model: str, input_tokens: int, output_tokens: int,
                  prices: dict | None = None) -> float:
    prices = prices if prices is not None else load_price_table()
    entry = prices.get(model)
    if not entry:
        # Fall back to provider-level wildcard, e.g. {"local": {...}}
        return 0.0
    in_per_1k = entry.get("input_per_1k", 0.0)
    out_per_1k = entry.get("output_per_1k", 0.0)
    return (input_tokens / 1000.0) * in_per_1k + (output_tokens / 1000.0) * out_per_1k
