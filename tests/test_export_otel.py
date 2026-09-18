from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("opentelemetry.sdk")
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from sluice.agent import Agent
from sluice.export.otel import OtelExporter
from sluice.labels import reset_ids
from sluice.monitor import Monitor
from sluice.policy import Policy
from sluice.scenario import load_scenario
from sluice.trace import TraceWriter

INBOX = Path(__file__).parents[1] / "examples" / "inbox-assistant"


def test_decisions_become_spans() -> None:
    memory = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(memory))
    exporter = OtelExporter(provider.get_tracer("test"))

    reset_ids()
    sc = load_scenario(INBOX)()
    assert sc.policy_path is not None
    mon = Monitor(Policy.load(sc.policy_path), sc.registry, trace=TraceWriter(listeners=[exporter]))
    Agent(sc.llm, sc.registry, mon).run(sc.user_prompt)

    read, send = memory.get_finished_spans()
    assert read.name == "sluice.decide read_inbox" and read.status.status_code is StatusCode.UNSET
    assert send.attributes is not None
    assert send.attributes["gen_ai.tool.name"] == "send_email"
    assert send.attributes["sluice.verdict"] == "block"
    assert send.attributes["sluice.session_id"] == mon.session_id
    assert "LLM01:2025" in send.attributes["sluice.tags"]
    assert send.status.status_code is StatusCode.ERROR
    assert {e.attributes["sluice.arg"] for e in send.events if e.attributes} == {"to", "body"}


def test_default_tracer() -> None:
    assert OtelExporter().tracer is not None
