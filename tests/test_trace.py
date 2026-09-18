from __future__ import annotations

from typing import Any

from sluice.trace import TraceWriter


def test_listeners_receive_events_and_failures_are_contained() -> None:
    seen: list[dict[str, Any]] = []

    def bad(ev: dict[str, Any]) -> None:
        raise ValueError("siem down")

    w = TraceWriter(listeners=[seen.append, bad])
    w.emit("call", tool="x")
    assert [e["type"] for e in w.events] == ["call", "listener_error"]
    assert len(seen) == 1 and seen[0]["tool"] == "x"
    assert "siem down" in w.events[1]["error"]
