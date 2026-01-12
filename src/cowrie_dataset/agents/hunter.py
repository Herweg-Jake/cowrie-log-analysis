"""
Hunter Agent - quick triage to filter noise.

Most "anomalous" sessions are still boring (broken bot scripts, scanners stuck
in loops, etc). The Hunter's job is to quickly decide if something is worth
deeper analysis or just noise we can ignore.

This saves money by not sending junk to the more expensive Analyst agent.
"""

import json
import re
from .base import BaseAgent, AgentConfig


class HunterAgent(BaseAgent):
    """
    First-pass triage: RELEVANT or NOISE?

    Looks at the anomaly flags and commands to make a quick call.
    Cheap and fast - we run this on everything flagged as anomalous.
    """

    @property
    def system_prompt(self) -> str:
        return """You're a threat hunter doing quick triage on honeypot sessions.

Your job: decide if a session is worth deeper analysis (RELEVANT) or just noise (NOISE).

## Mark as RELEVANT if you see:
- Clear attack progression (recon -> exploit -> persist)
- Commands that show system awareness (checking arch, OS, defenses)
- Payload downloads or lateral movement attempts
- Signs of a human (typo corrections, adaptive behavior)
- Anti-forensics (clearing logs, history, etc)
- Persistence mechanisms (cron, rc.local, authorized_keys)

## Mark as NOISE if you see:
- Random garbage commands with no goal
- Pure brute-force with nothing after login
- Scanner fingerprinting only
- Bot stuck in a loop
- Empty session or immediate disconnect
- Single recon command then nothing

## Output format (JSON only, no explanation):
{"verdict": "RELEVANT" or "NOISE", "confidence": 0.0-1.0, "reasoning": "one sentence"}"""

    def format_input(self, session: dict) -> str:
        """Build a prompt with the key info for triage."""
        commands = session.get("commands", [])
        cmd_list = [c.get("input", "") for c in commands[:50]]  # cap at 50

        anomaly = session.get("statistical_anomaly", {})
        rule_labels = session.get("labels_rule_based", {})

        # keep it concise - hunter doesn't need every detail
        return f"""Session: {session.get('session_id', '?')}
Duration: {session.get('duration_s', 0):.1f}s | Auth: {session.get('auth_success', False)} | Type: {session.get('session_type', '?')}

Anomaly flags: {anomaly.get('reasons', [])}
Anomaly score: {anomaly.get('score', 0)}

Rule-based: level={rule_labels.get('level', '?')}, tactic={rule_labels.get('primary_tactic', '?')}
Patterns matched: {rule_labels.get('matched_patterns', [])}

Commands ({len(commands)} total):
{chr(10).join(cmd_list) if cmd_list else '(none)'}

Verdict?"""

    def parse_output(self, response_text: str) -> dict:
        """Extract verdict from response."""
        # try to find JSON in the response
        try:
            match = re.search(r'\{[^{}]+\}', response_text, re.DOTALL)
            if match:
                data = json.loads(match.group())
                return {
                    "verdict": data.get("verdict", "NOISE").upper(),
                    "confidence": float(data.get("confidence", 0.5)),
                    "reasoning": data.get("reasoning", ""),
                }
        except (json.JSONDecodeError, ValueError):
            pass

        # fallback: just look for keywords
        upper = response_text.upper()
        if "RELEVANT" in upper:
            return {"verdict": "RELEVANT", "confidence": 0.5, "reasoning": "keyword match"}
        return {"verdict": "NOISE", "confidence": 0.5, "reasoning": "parse failed, defaulting to noise"}
