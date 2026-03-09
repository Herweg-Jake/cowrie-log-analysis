"""
Base infrastructure for LLM agents.

Nothing fancy here - just the config and response dataclasses, plus a base
class that handles the boring stuff (API calls, retries, rate limiting).

Supports Anthropic, OpenAI, and Gemini APIs.
"""

import os
import re
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentConfig:
    """
    Config for LLM API calls.

    Defaults to Gemini Flash (free tier) since that's what most people
    will use for testing. Switch to Pro or Claude for production.
    """

    provider: str = "gemini"  # "anthropic", "openai", or "gemini"
    model: str = "gemini-2.0-flash"  # 1.5 is deprecated, 2.0 is current
    api_key: Optional[str] = None

    # Vertex AI settings (uses Google Cloud credits instead of free tier)
    project_id: Optional[str] = None
    location: str = "us-central1"

    # generation params
    max_tokens: int = 1024
    temperature: float = 0.1  # low = consistent, high = creative

    # rate limits - 500 RPM gives good throughput with headroom under the 1K API limit
    requests_per_minute: int = 500
    retry_attempts: int = 3
    retry_delay: float = 2.0  # gemini needs longer backoff

    # pricing per 1k tokens - defaults for gemini-1.5-flash
    # flash is basically free, pro is $1.25/$5 per 1M tokens
    input_cost_per_1k: float = 0.0
    output_cost_per_1k: float = 0.0

    def __post_init__(self):
        # grab API key from env if not provided
        if self.api_key is None:
            if self.provider == "anthropic":
                self.api_key = os.environ.get("ANTHROPIC_API_KEY")
            elif self.provider == "openai":
                self.api_key = os.environ.get("OPENAI_API_KEY")
            else:  # gemini
                self.api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")

        # Vertex AI project from env (uses Google Cloud credits)
        if self.project_id is None:
            self.project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")


# handy presets so you don't have to remember all the params
def gemini_flash_config(**overrides) -> AgentConfig:
    """Gemini 2.0 Flash - fast and cheap, 500 RPM with headroom under 1K limit."""
    return AgentConfig(
        provider="gemini",
        model="gemini-2.0-flash",
        requests_per_minute=500,
        input_cost_per_1k=0.0,
        output_cost_per_1k=0.0,
        **overrides,
    )


def gemini_pro_config(**overrides) -> AgentConfig:
    """Gemini Pro - better quality, uses your $300 credits."""
    return AgentConfig(
        provider="gemini",
        model="gemini-2.5-pro-preview-05-06",  # latest pro model
        requests_per_minute=60,
        input_cost_per_1k=0.00125,  # $1.25 per 1M
        output_cost_per_1k=0.005,   # $5 per 1M
        **overrides,
    )


def claude_sonnet_config(**overrides) -> AgentConfig:
    """Claude Sonnet - solid all-rounder."""
    return AgentConfig(
        provider="anthropic",
        model="claude-sonnet-4-20250514",
        requests_per_minute=50,
        input_cost_per_1k=0.003,
        output_cost_per_1k=0.015,
        **overrides,
    )


@dataclass
class AgentResponse:
    """What comes back from an agent call."""

    success: bool
    result: dict  # parsed output from the model
    reasoning: Optional[str] = None

    # metadata for cost tracking and debugging
    model: str = ""
    latency_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost: float = 0.0

    # if something went wrong
    error: Optional[str] = None
    retries: int = 0


class BaseAgent(ABC):
    """
    Abstract base for LLM agents.

    Subclasses just need to implement:
    - system_prompt: what role the model should play
    - format_input: how to turn session data into a prompt
    - parse_output: how to extract structured data from the response

    The boring stuff (API calls, retries, rate limiting) is handled here.
    """

    def __init__(self, config: AgentConfig):
        self.config = config
        self._client = None
        self._request_times: list[float] = []
        self._rate_lock = threading.Lock()

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """The system prompt that defines this agent's behavior."""
        pass

    @abstractmethod
    def format_input(self, session: dict) -> str:
        """Turn a session dict into a user prompt."""
        pass

    @abstractmethod
    def parse_output(self, response_text: str) -> dict:
        """Extract structured data from the model's response."""
        pass

    def _get_client(self):
        """Lazy-load the API client (avoids import if never used)."""
        if self._client is not None:
            return self._client

        if self.config.provider == "anthropic":
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.config.api_key)
        elif self.config.provider == "openai":
            import openai
            self._client = openai.OpenAI(api_key=self.config.api_key)
        else:  # gemini - using new google-genai SDK
            from google import genai

            if self.config.project_id:
                # Use Vertex AI (Google Cloud credits)
                self._client = genai.Client(
                    vertexai=True,
                    project=self.config.project_id,
                    location=self.config.location,
                )
            else:
                # Fallback to AI Studio (free tier / API key)
                self._client = genai.Client(api_key=self.config.api_key)

        return self._client

    def _wait_for_rate_limit(self) -> None:
        """Thread-safe sliding window rate limiter."""
        while True:
            with self._rate_lock:
                now = time.time()
                self._request_times = [t for t in self._request_times if now - t < 60]

                if len(self._request_times) < self.config.requests_per_minute:
                    self._request_times.append(now)
                    return

                sleep_for = 60 - (now - self._request_times[0]) + 0.1

            # sleep outside the lock so other threads aren't blocked
            time.sleep(sleep_for)

    def _parse_retry_delay(self, error: Exception) -> Optional[float]:
        """
        Extract retry delay from API error responses.

        Google's 429 errors include a suggested retry delay in the response.
        This tries to parse it from the error message or response details.
        """
        error_str = str(error)

        # Look for "retryDelay": "32s" pattern in error details
        match = re.search(r"'retryDelay':\s*'(\d+)s?'", error_str)
        if match:
            return float(match.group(1))

        # Look for "Please retry in X.XXXs" pattern in message
        match = re.search(r"Please retry in (\d+(?:\.\d+)?)s", error_str)
        if match:
            return float(match.group(1))

        return None

    def _is_quota_error(self, error: Exception) -> bool:
        """Check if an error is a retryable quota/rate limit error."""
        error_str = str(error)
        return (
            "429" in error_str
            or "RESOURCE_EXHAUSTED" in error_str
            or "quota" in error_str.lower()
            or "rate limit" in error_str.lower()
        )

    def _call_api(self, user_prompt: str) -> tuple[str, int, int]:
        """
        Make the actual API call.

        Returns (response_text, input_tokens, output_tokens)
        """
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

        else:  # gemini - new SDK style
            from google.genai import types

            # gemini 2.0 supports system instructions natively
            response = client.models.generate_content(
                model=self.config.model,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=self.system_prompt,
                    max_output_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                ),
            )

            # token counts from usage_metadata
            usage = response.usage_metadata
            return (
                response.text,
                usage.prompt_token_count or 0,
                usage.candidates_token_count or 0,
            )

    def analyze(self, session: dict) -> AgentResponse:
        """
        Run analysis on a session.

        Handles retries and rate limiting automatically.
        """
        prompt = self.format_input(session)

        for attempt in range(self.config.retry_attempts):
            try:
                self._wait_for_rate_limit()

                start = time.time()
                text, in_tokens, out_tokens = self._call_api(prompt)
                elapsed_ms = int((time.time() - start) * 1000)

                result = self.parse_output(text)

                # tally up the cost
                cost = (
                    (in_tokens / 1000) * self.config.input_cost_per_1k +
                    (out_tokens / 1000) * self.config.output_cost_per_1k
                )

                return AgentResponse(
                    success=True,
                    result=result,
                    reasoning=result.get("reasoning"),
                    model=self.config.model,
                    latency_ms=elapsed_ms,
                    input_tokens=in_tokens,
                    output_tokens=out_tokens,
                    estimated_cost=cost,
                    retries=attempt,
                )

            except Exception as e:
                is_last_attempt = attempt >= self.config.retry_attempts - 1

                if self._is_quota_error(e):
                    # Quota/rate limit error - respect API's suggested retry delay
                    retry_delay = self._parse_retry_delay(e)

                    if retry_delay is not None:
                        # Cap at 60s to avoid waiting forever
                        retry_delay = min(retry_delay, 60.0)

                        if is_last_attempt:
                            # Even on last attempt, provide useful error info
                            return AgentResponse(
                                success=False,
                                result={},
                                error=f"Quota exceeded after {attempt + 1} attempts. "
                                      f"API suggests retry in {retry_delay:.0f}s. "
                                      "Check your plan/billing at https://ai.google.dev/gemini-api/docs/rate-limits",
                                retries=attempt,
                            )

                        time.sleep(retry_delay)
                    elif not is_last_attempt:
                        # No retry delay provided, use exponential backoff
                        time.sleep(self.config.retry_delay * (attempt + 1))
                    else:
                        return AgentResponse(
                            success=False,
                            result={},
                            error=f"Quota exceeded: {e}",
                            retries=attempt,
                        )
                elif not is_last_attempt:
                    # Non-quota error, standard exponential backoff
                    time.sleep(self.config.retry_delay * (attempt + 1))
                else:
                    return AgentResponse(
                        success=False,
                        result={},
                        error=str(e),
                        retries=attempt,
                    )

        # shouldn't get here, but just in case
        return AgentResponse(success=False, result={}, error="max retries exceeded")
