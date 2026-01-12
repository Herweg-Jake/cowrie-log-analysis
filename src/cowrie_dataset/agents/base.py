"""
Base infrastructure for LLM agents.

Nothing fancy here - just the config and response dataclasses, plus a base
class that handles the boring stuff (API calls, retries, rate limiting).
"""

import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentConfig:
    """
    Config for LLM API calls.

    Defaults are set for Claude Sonnet which is a good balance of
    cost/speed/quality. Adjust model and pricing if using something else.
    """

    provider: str = "anthropic"  # "anthropic" or "openai"
    model: str = "claude-sonnet-4-20250514"
    api_key: Optional[str] = None

    # generation params
    max_tokens: int = 1024
    temperature: float = 0.1  # low = consistent, high = creative

    # don't hammer the API
    requests_per_minute: int = 50
    retry_attempts: int = 3
    retry_delay: float = 1.0

    # for cost tracking (Claude Sonnet pricing as of Jan 2025)
    input_cost_per_1k: float = 0.003
    output_cost_per_1k: float = 0.015

    def __post_init__(self):
        # try to grab API key from env if not provided
        if self.api_key is None:
            env_var = "ANTHROPIC_API_KEY" if self.provider == "anthropic" else "OPENAI_API_KEY"
            self.api_key = os.environ.get(env_var)


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
        else:
            import openai
            self._client = openai.OpenAI(api_key=self.config.api_key)

        return self._client

    def _wait_for_rate_limit(self) -> None:
        """Simple sliding window rate limiter."""
        now = time.time()
        # drop requests older than 60s
        self._request_times = [t for t in self._request_times if now - t < 60]

        if len(self._request_times) >= self.config.requests_per_minute:
            # need to wait until oldest request falls out of the window
            sleep_for = 60 - (now - self._request_times[0])
            if sleep_for > 0:
                time.sleep(sleep_for)

        self._request_times.append(time.time())

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
        else:
            # openai style
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
                if attempt < self.config.retry_attempts - 1:
                    # exponential backoff
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
