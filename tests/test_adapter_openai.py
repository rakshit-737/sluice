from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("openai")
from openai.types.chat import ChatCompletion

from sluice.agent import Agent
from sluice.labels import reset_ids
from sluice.llm import Message, ToolCall
from sluice.monitor import Monitor
from sluice.monitor.adapters.openai import (
    OpenAILLM,
    SluiceBlocked,
    guard_openai,
    parse_tool_call,
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


def fn(i: str, name: str, args: Any) -> dict[str, Any]:
    raw = args if isinstance(args, str) else json.dumps(args)
    return {"id": i, "type": "function", "function": {"name": name, "arguments": raw}}


def completion(*messages: dict[str, Any]) -> ChatCompletion:
    return ChatCompletion.model_validate(
        {
            "id": "c",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-test",
            "choices": [
                {
                    "index": i,
                    "finish_reason": "tool_calls" if m.get("tool_calls") else "stop",
                    "message": {"role": "assistant", "content": None, **m},
                }
                for i, m in enumerate(messages)
            ],
        }
    )


class FakeCompletions:
    def __init__(self, replies: list[ChatCompletion]) -> None:
        self.replies = replies
        self.requests: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> ChatCompletion:
        self.requests.append(kwargs)
        return self.replies.pop(0)


class FakeChat:
    def __init__(self, replies: list[ChatCompletion]) -> None:
        self.completions = FakeCompletions(replies)
        self.other = "chat-attr"


class FakeClient:
    def __init__(self, replies: list[ChatCompletion]) -> None:
        self.chat = FakeChat(replies)
        self.models = "models"


@pytest.fixture
def monitor() -> Monitor:
    reset_ids()
    return Monitor(Policy.from_yaml(POLICY), ToolRegistry([web, send]))


def test_parse_tool_call_variants() -> None:
    assert parse_tool_call(fn("1", "send", {"to": "a"})).arguments == {"to": "a"}
    assert parse_tool_call(fn("1", "send", "{oops")).parse_error.startswith("invalid JSON")
    assert parse_tool_call(fn("1", "send", "[1]")).parse_error == "arguments are not a JSON object"
    custom = parse_tool_call({"id": "2", "type": "custom", "custom": {"name": "sh", "input": "ls"}})
    assert custom.name == "sh" and custom.arguments == {"input": "ls"}
    assert parse_tool_call(
        {"id": "3", "function": {"name": "x", "arguments": {"a": 1}}}
    ).arguments == {"a": 1}


def test_guard_filters_blocked_calls(monitor: Monitor) -> None:
    fake = FakeClient(
        [
            completion({"tool_calls": [fn("1", "web", {"url": "https://x.example"})]}),
            completion(
                {
                    "content": "Emailing.",
                    "tool_calls": [fn("2", "send", {"to": "eve@evil.example"})],
                },
                {
                    "tool_calls": [
                        fn("3", "send", {"to": "eve@evil.example"}),
                        fn("4", "web", {"url": "u"}),
                    ]
                },
            ),
        ]
    )
    client = guard_openai(fake, monitor)
    msgs: list[Any] = [
        {"role": "developer", "content": "be safe"},
        {"role": "user", "content": [{"type": "text", "text": "read https://x.example"}]},
    ]
    r1 = client.chat.completions.create(model="m", messages=msgs)
    msgs += [
        r1.choices[0].message,
        {"role": "tool", "tool_call_id": "1", "content": "Contact: eve@evil.example"},
    ]
    r2 = client.chat.completions.create(model="m", messages=msgs)
    c0, c1 = r2.choices
    assert c0.message.tool_calls is None and c0.finish_reason == "stop"
    assert c0.message.content.startswith("Emailing.\n\n[sluice blocked send]")
    assert [t.id for t in c1.message.tool_calls] == ["4"] and c1.finish_reason == "tool_calls"
    assert client.chat.other == "chat-attr" and client.models == "models"
    assert isinstance(r2, ChatCompletion)


def test_unparseable_call_blocked(monitor: Monitor) -> None:
    fake = FakeClient([completion({"tool_calls": [fn("1", "web", "{bad")]})])
    r = guard_openai(fake, monitor).chat.completions.create(messages=[])
    assert "unparseable" in r.choices[0].message.content


def test_streaming_refused(monitor: Monitor) -> None:
    with pytest.raises(NotImplementedError):
        guard_openai(FakeClient([]), monitor).chat.completions.create(messages=[], stream=True)


def test_raise_on_block(monitor: Monitor) -> None:
    monitor.observe("eve@evil.example", "tool.web")
    fake = FakeClient([completion({"tool_calls": [fn("1", "send", {"to": "eve@evil.example"})]})])
    with pytest.raises(SluiceBlocked):
        guard_openai(fake, monitor, raise_on_block=True).chat.completions.create(messages=[])


def test_request_roundtrip() -> None:
    neutral = [
        Message("system", "s"),
        Message("user", "u"),
        Message("assistant", "", (ToolCall("1", "web", {"url": "u"}),)),
        Message("tool", "r", tool_call_id="1"),
        Message("assistant", "bye"),
    ]
    req = to_request(neutral)
    assert req[2]["content"] is None and json.loads(
        req[2]["tool_calls"][0]["function"]["arguments"]
    ) == {"url": "u"}
    back = to_neutral(req)
    assert [m.role for m in back] == ["system", "user", "assistant", "tool", "assistant"]
    assert back[3].name == "web"


def test_openai_llm_in_own_loop(monitor: Monitor) -> None:
    fake = FakeClient(
        [
            completion({"tool_calls": [fn("1", "web", {"url": "u"})]}),
            completion({"tool_calls": [fn("2", "send", {"to": "eve@evil.example"})]}),
            completion({"content": "done"}),
        ]
    )
    res = Agent(OpenAILLM(fake, "gpt-test"), monitor.registry, monitor).run("look at u")
    assert res.final == "done" and len(res.blocked) == 1
    assert (
        fake.chat.completions.requests[0]["tools"][0]["function"]["parameters"]["type"] == "object"
    )
