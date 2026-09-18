"""SARIF 2.1.0 output for the lethal-trifecta audit.

Lets ``sluice trifecta --sarif`` feed GitHub code scanning (and any SARIF viewer), so an
unguarded exfiltration path in a policy shows up as an alert on the policy file line.
"""

from __future__ import annotations

import re
from typing import Any

import sluice
from sluice.policy.trifecta import TrifectaReport

INFO_URI = "https://github.com/rakshit-737/sluice"

RULES: list[dict[str, Any]] = [
    {
        "id": "SLU001",
        "name": "UnguardedExfiltrationArgument",
        "shortDescription": {"text": "Exfiltration argument not guarded by policy"},
        "fullDescription": {
            "text": "An argument of an outbound tool accepts both untrusted and secret data, "
            "so an injected instruction can steer it or private data can leave through it."
        },
        "help": {
            "text": "Add require_integrity: trusted (for destinations) or max_confidentiality "
            "below secret (for payloads) to this argument in the policy's sinks section."
        },
        "properties": {
            "tags": ["security", "LLM01:2025", "LLM02:2025", "LLM06:2025"],
            "security-severity": "8.1",
        },
    },
    {
        "id": "SLU002",
        "name": "LethalTrifecta",
        "shortDescription": {
            "text": "Agent combines private data, untrusted input and exfiltration"
        },
        "fullDescription": {
            "text": "The registered tools give the agent all three legs of the lethal trifecta. "
            "This is reported for awareness; SLU001 flags the paths that are actually unguarded."
        },
        "help": {"text": "Keep every exfiltration argument guarded; run with --strict in CI."},
        "properties": {"tags": ["security", "LLM06:2025"], "security-severity": "4.0"},
    },
    {
        "id": "SLU003",
        "name": "UnclassifiedTool",
        "shortDescription": {"text": "Tool has no capability tags"},
        "fullDescription": {
            "text": "The trifecta audit cannot classify a tool without capability tags; "
            "an outbound tool without net.out/comms/shell would be missed."
        },
        "help": {"text": "Declare caps=[...] on the tool."},
        "properties": {"tags": ["security"], "security-severity": "2.0"},
    },
]


def _line_of(text: str | None, key: str, after: int = 0) -> int:
    """1-based line of the first ``key:`` at or after line ``after``; 0 if absent."""
    if text:
        for i, line in enumerate(text.splitlines(), 1):
            if i >= after and re.search(rf"(^|[\s{{,]){re.escape(key)}\s*:", line):
                return i
    return 0


def _line_for(text: str | None, sink: str, arg: str | None = None) -> int:
    sink_line = _line_of(text, sink)
    if not sink_line:
        return 1
    return (_line_of(text, arg, sink_line) if arg else 0) or sink_line


def _result(rule: str, level: str, msg: str, uri: str, line: int, fp: str) -> dict[str, Any]:
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": msg},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
        "partialFingerprints": {"sluiceFinding/v1": fp},
    }


def trifecta_sarif(
    report: TrifectaReport, policy_uri: str = "policy.yaml", policy_text: str | None = None
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    level = "error" if report.present else "warning"
    for path in report.paths:
        for a in path.args:
            if a.guarded:
                continue
            why = f"verdict is '{path.verdict}'" if not a.enforced else a.requirement.describe()
            results.append(
                _result(
                    "SLU001",
                    level,
                    f"`{path.tool}.{a.arg}` can carry untrusted or secret data out ({why}).",
                    policy_uri,
                    _line_for(policy_text, path.tool, a.arg),
                    f"{path.tool}.{a.arg}",
                )
            )
    if report.present:
        legs = "; ".join(
            f"{name}: {', '.join(tools)}"
            for name, tools in (
                ("private", report.private),
                ("untrusted", report.untrusted),
                ("exfiltration", report.exfil),
            )
        )
        results.append(
            _result(
                "SLU002", "note", f"Lethal trifecta present ({legs}).", policy_uri, 1, "trifecta"
            )
        )
    for tool in report.unclassified:
        results.append(
            _result(
                "SLU003",
                "note",
                f"Tool `{tool}` has no capability tags.",
                policy_uri,
                _line_for(policy_text, tool),
                f"unclassified.{tool}",
            )
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sluice",
                        "version": sluice.__version__,
                        "informationUri": INFO_URI,
                        "rules": RULES,
                    }
                },
                "results": results,
            }
        ],
    }
