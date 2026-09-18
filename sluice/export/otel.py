"""OpenTelemetry export: one span per tool-call decision.

Spans carry the OTel GenAI attribute ``gen_ai.tool.name`` plus ``sluice.*`` attributes, and
blocked calls get ERROR status and one ``sluice.violation`` span event per failing argument,
so decisions show up in any OTel backend (Jaeger, Tempo, Honeycomb, Datadog, Elastic APM)
next to the agent's own spans. Install with ``pip install sluice[otel]``.
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode, Tracer

import sluice


class OtelExporter:
    """Trace listener that turns ``call`` events into spans on ``tracer``."""

    def __init__(self, tracer: Tracer | None = None) -> None:
        self.tracer = tracer or trace.get_tracer("sluice", sluice.__version__)
        self._session = ""

    def __call__(self, event: dict[str, Any]) -> None:
        if event.get("type") == "session":
            self._session = str(event.get("session_id", ""))
            return
        if event.get("type") != "call":
            return
        decision = event.get("decision", {})
        verdict = str(decision.get("verdict", ""))
        violations = decision.get("violations", [])
        tool = str(event.get("tool", "?"))
        attrs: dict[str, Any] = {
            "gen_ai.tool.name": tool,
            "sluice.call_id": str(event.get("id", "")),
            "sluice.session_id": self._session,
            "sluice.verdict": verdict,
            "sluice.violation_count": len(violations),
        }
        tags = sorted({t["id"] for v in violations for t in v.get("tags", [])})
        if tags:
            attrs["sluice.tags"] = tags
        span = self.tracer.start_span(f"sluice.decide {tool}", attributes=attrs)
        for v in violations:
            span.add_event(
                "sluice.violation",
                {
                    "sluice.arg": str(v.get("arg", "")),
                    "sluice.label": str(v.get("label", "")),
                    "sluice.rule": str(v.get("rule", "")),
                    "sluice.sources": [str(s) for s in v.get("sources", [])],
                },
            )
        if verdict in ("block", "ask"):
            span.set_status(Status(StatusCode.ERROR, str(decision.get("reason", "blocked"))))
        span.end()
