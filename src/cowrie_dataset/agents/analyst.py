"""
Analyst Agent - deep threat analysis with MITRE mapping.

This is the expensive one. Only gets sessions the Hunter marked as RELEVANT.
Does proper MITRE ATT&CK mapping, sophistication scoring, and extracts IOCs.
"""

import json
import re
from .base import BaseAgent, AgentConfig


class AnalystAgent(BaseAgent):
    """
    Deep analysis: MITRE mapping, intent, sophistication.

    Takes longer and costs more, but gives us the good stuff.
    """

    @property
    def system_prompt(self) -> str:
        return """You're a senior security analyst doing deep-dive threat analysis on honeypot sessions.

For each session, provide:
1. Threat level (1=high, 2=medium, 3=low)
2. MITRE ATT&CK tactics and techniques
3. Attacker sophistication assessment
4. What they were trying to do
5. Any IOCs worth extracting

## MITRE Tactics (pick what applies):
- Initial Access (T1078 valid accounts, T1190 exploit public-facing app)
- Execution (T1059 command interpreter)
- Persistence (T1053 scheduled task, T1098 account manipulation)
- Privilege Escalation (T1548 abuse elevation)
- Defense Evasion (T1070 indicator removal, T1027 obfuscation)
- Credential Access (T1003 credential dumping)
- Discovery (T1082 system info, T1083 file discovery)
- Lateral Movement (T1021 remote services)
- Collection (T1005 data from local system)
- Command and Control (T1071 application layer protocol)
- Exfiltration (T1041 exfil over C2)
- Impact (T1485 data destruction, T1486 encryption for impact)

## Sophistication levels:
- SCRIPT_KIDDIE: copy-paste attacks, no adaptation, common tools
- INTERMEDIATE: some customization, basic evasion, multiple phases
- ADVANCED: custom tools, good opsec, sophisticated evasion
- APT: highly targeted, novel techniques, extensive recon

## Output format (JSON only):
{
  "threat_level": 1-3,
  "primary_tactic": "main tactic",
  "all_tactics": ["list", "of", "tactics"],
  "technique_ids": ["T1059.004", "etc"],
  "sophistication": "SCRIPT_KIDDIE|INTERMEDIATE|ADVANCED|APT",
  "intent": "what attacker wanted",
  "reasoning": "2-3 sentences on your analysis",
  "confidence": 0.0-1.0,
  "iocs": ["IPs", "URLs", "hashes", "etc"]
}"""

    def format_input(self, session: dict) -> str:
        """Build detailed prompt for deep analysis."""
        commands = session.get("commands", [])
        downloads = session.get("downloads", [])

        # format commands with timestamps and success/fail
        cmd_lines = []
        for cmd in commands[:100]:  # more than hunter, but still capped
            ts = cmd.get("timestamp", "")[:19]  # trim microseconds
            inp = cmd.get("input", "")
            ok = "+" if cmd.get("success") else "-"
            cmd_lines.append(f"[{ts}] {ok} {inp}")

        geo = session.get("geo", {})
        geo_str = f"{geo.get('country', '?')} ({geo.get('continent', '?')})" if geo else "unknown"

        return f"""## Session Details

ID: {session.get('session_id')}
Source: {session.get('src_ip')} ({geo_str})
Duration: {session.get('duration_s', 0):.1f}s
Protocol: {session.get('protocol', 'ssh')}

## Authentication
Success: {session.get('auth_success')}
User: {session.get('final_username', '-')}
Pass: {session.get('final_password', '-')}
SSH client: {session.get('ssh_version', '-')}
HASSH: {session.get('hassh', '-')}

## Commands ({len(commands)} total)
{chr(10).join(cmd_lines) if cmd_lines else '(none)'}

## Downloads ({len(downloads)} files)
{json.dumps(downloads, indent=2) if downloads else '(none)'}

## Rule-based baseline (for comparison)
{json.dumps(session.get('labels_rule_based', {}), indent=2)}

## Anomaly info
{json.dumps(session.get('statistical_anomaly', {}), indent=2)}

Analyze this session."""

    def parse_output(self, response_text: str) -> dict:
        """Extract structured analysis from response."""
        try:
            data = _extract_json(response_text)
            if data and "threat_level" in data:
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
        except (json.JSONDecodeError, ValueError):
            pass

        # couldn't parse - return placeholder
        return {
            "threat_level": 2,
            "primary_tactic": "Unknown",
            "all_tactics": [],
            "technique_ids": [],
            "sophistication": "UNKNOWN",
            "intent": "parse failed",
            "reasoning": f"couldn't parse response: {response_text[:100]}...",
            "confidence": 0.0,
            "iocs": [],
        }


def _extract_json(text: str) -> dict | None:
    """Extract a JSON object from text that may be wrapped in markdown fences."""
    # Strip markdown code fences if present
    stripped = re.sub(r'^```(?:json)?\s*\n?', '', text.strip())
    stripped = re.sub(r'\n?```\s*$', '', stripped).strip()

    # Try direct parse first
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Find the outermost { ... } by brace matching
    start = stripped.find('{')
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(stripped)):
        if stripped[i] == '{':
            depth += 1
        elif stripped[i] == '}':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(stripped[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None
