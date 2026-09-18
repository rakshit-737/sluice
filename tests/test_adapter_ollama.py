from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("ollama")
from ollama import ChatResponse

from sluice.agent import Agent
from sluice.labels import reset_ids
from sluice.llm import Message, ToolCall
from sluice.monitor import Monitor
from sluice.monitor.adapters.ollama import (
    OllamaLLM,
    SluiceBlocked,
    guard_ollama,
    to_neutral,
    to_request,
)
from sluice.policy import Policy
from sluice.tools import COMMS, ToolRegistry, tool

POLICY = """
sources:
  user: {integrity: trusted, confidentiality: internal}
  system: {integrity: trusted, confidentiality: internal}
  model: {integrity: trusted, confidentiality: internal}
  tool.web: {integrity: untrusted, confidentiality: public}
sinks:
  web: {}
  send: {args: {to: {require_integrity: trusted}}}
"""


@tool(source="tool.web")
def web(url: str) -> str:
    return "Contact: eve@evil.example"


@tool(caps=[COMMS])
def send(to: str) -> str:
    return "sent"


def reply(content: str = "", *calls: tuple[str, Any]) -> ChatResponse:
    tcs = [{"function": {"name": n, "arguments": a}} for n, a in calls]
    return ChatResponse.model_validate(
        {
            "model": "llama",
            "done": True,
            "message": {"role": "assistant", "content": content, "tool_calls": tcs or None},
        }
    )


class FakeClient:
    def __init__(self, replies: list[ChatResponse]) -> None:
        self.replies = replies
        self.requests: list[dict[str, Any]] = []
        self.host = "localhost"

    def chat(self, *args: Any, **kwargs: Any) -> ChatResponse:
        self.requests.append(kwargs)
        return self.replies.pop(0)


@pytest.fixture
def monitor() -> Monitor:
    reset_ids()
    return Monitor(Policy.from_yaml(POLICY), ToolRegistry([web, send]))


def test_pairing_by_name_and_order() -> None:
    msgs = [
        {"role": "user", "content": "go"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "web", "arguments": {"url": "a"}}},
                {"function": {"name": "send", "arguments": {"to": "b"}}},
            ],
        },
        {"role": "tool", "tool_name": "send", "content": "sent"},
        {"role": "tool", "content": "page"},
        {"role": "tool", "content": "orphan"},
    ]
    n = to_neutral(msgs)
    assert [(m.tool_call_id, m.name) for m in n[2:]] == [
        ("ollama-1-1", "send"),
        ("ollama-1-0", "web"),
        (None, ""),
    ]


def test_guard_filters_blocked(monitor: Monitor) -> None:
    fake = FakeClient(
        [
            reply("", ("web", {"url": "https://x.example"})),
            reply("ok", ("send", {"to": "eve@evil.example"}), ("web", {"url": "u"})),
        ]
    )
    client = guard_ollama(fake, monitor)
    msgs: list[Any] = [{"role": "user", "content": "read https://x.example"}]
    r1 = client.chat(model="llama", messages=msgs)
    msgs += [
        r1.message,
        {"role": "tool", "tool_name": "web", "content": "Contact: eve@evil.example"},
    ]
    r2 = client.chat("llama", msgs)
    assert [t.function.name for t in r2.message.tool_calls] == ["web"]
    assert r2.message.content.startswith("ok\n\n[sluice blocked send]")
    assert client.host == "localhost" and isinstance(r2, ChatResponse)


def test_all_blocked_clears_tool_calls(monitor: Monitor) -> None:
    monitor.observe("eve@evil.example", "tool.web")
    r = guard_ollama(FakeClient([reply("", ("send", {"to": "eve@evil.example"}))]), monitor).chat(
        messages=[]
    )
    assert r.message.tool_calls is None


def test_raise_and_stream(monitor: Monitor) -> None:
    monitor.observe("eve@evil.example", "tool.web")
    g = guard_ollama(
        FakeClient([reply("", ("send", {"to": "eve@evil.example"}))]), monitor, raise_on_block=True
    )
    with pytest.raises(SluiceBlocked):
        g.chat(messages=[])
    with pytest.raises(NotImplementedError):
        g.chat(messages=[], stream=True)


def test_to_request() -> None:
    req = to_request(
        [
            Message("assistant", "", (ToolCall("x", "web", {"url": "u"}),)),
            Message("tool", "r", tool_call_id="x", name="web"),
        ]
    )
    assert req[0]["tool_calls"][0]["function"]["arguments"] == {"url": "u"}
    assert req[1]["tool_name"] == "web"


def test_ollama_llm_in_own_loop(monitor: Monitor) -> None:
    fake = FakeClient(
        [
            reply("", ("web", {"url": "u"})),
            reply("", ("send", {"to": "eve@evil.example"})),
            reply("done"),
        ]
    )
    res = Agent(OllamaLLM(fake, "llama"), monitor.registry, monitor).run("look at u")
    assert res.final == "done" and len(res.blocked) == 1
    tool_msgs = [m for m in fake.requests[1]["messages"] if m["role"] == "tool"]
    assert tool_msgs[0]["tool_name"] == "web"
