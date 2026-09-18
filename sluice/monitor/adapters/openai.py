"""OpenAI-compatible Chat Completions adapter (OpenAI, vLLM, LM Studio, OpenRouter, ...).

- ``guard_openai(client, monitor)``: wraps an ``openai.OpenAI`` client; the guarded
  ``chat.completions.create`` removes tool calls that violate policy from ``choices[*]``.
- ``OpenAILLM``: an ``LLMClient`` for sluice's own agent loop.

Formats follow the installed SDK: function tool calls carry ``function.arguments`` as a JSON
*string* (unparseable JSON blocks the call); custom tool calls carry a raw ``input`` string,
exposed to policy as the single argument ``input``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any

from sluice.llm import Message, ToolCall
from sluice.monitor.adapters._util import field, text_of
from sluice.monitor.guard import Guard, Review, SluiceBlocked
from sluice.monitor.middleware import Monitor
from sluice.tools.registry import ToolSpec


def parse_tool_call(tc: Any) -> ToolCall:
    tid = str(field(tc, "id"))
    if field(tc, "type") == "custom":
        custom = field(tc, "custom")
        return ToolCall(tid, str(field(custom, "name")), {"input": field(custom, "input")})
    fn = field(tc, "function")
    name = str(field(fn, "name"))
    raw = field(fn, "arguments") or "{}"
    try:
        args = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except ValueError as e:
        return ToolCall(tid, name, {}, parse_error=f"invalid JSON ({e})")
    if not isinstance(args, dict):
        return ToolCall(tid, name, {}, parse_error="arguments are not a JSON object")
    return ToolCall(tid, name, args)


def to_neutral(messages: Iterable[Any]) -> list[Message]:
    out: list[Message] = []
    names: dict[str, str] = {}
    for m in messages:
        role = field(m, "role")
        content = text_of(field(m, "content"))
        if role in ("system", "developer"):
            out.append(Message("system", content))
        elif role == "user":
            out.append(Message("user", content))
        elif role == "assistant":
            calls = tuple(parse_tool_call(tc) for tc in field(m, "tool_calls") or [])
            names.update({c.id: c.name for c in calls})
            out.append(Message("assistant", content, calls))
        elif role == "tool":
            tid = str(field(m, "tool_call_id"))
            out.append(Message("tool", content, tool_call_id=tid, name=names.get(tid, "")))
    return out


def rewrite_response(resp: Any, reviews: list[Review]) -> Any:
    choices = []
    for choice, review in zip(resp.choices, reviews, strict=True):
        if not review.blocked:
            choices.append(choice)
            continue
        blocked = {c.call.id for c in review.blocked}
        msg = choice.message
        kept = [tc for tc in msg.tool_calls or [] if tc.id not in blocked]
        content = "\n\n".join(x for x in (msg.content, review.notice) if x)
        new_msg = msg.model_copy(update={"tool_calls": kept or None, "content": content})
        update: dict[str, Any] = {"message": new_msg}
        if not kept:
            update["finish_reason"] = "stop"
        choices.append(choice.model_copy(update=update))
    return resp.model_copy(update={"choices": choices})


class _GuardedCompletions:
    def __init__(self, inner: Any, guard: Guard) -> None:
        self._inner = inner
        self._guard = guard

    def create(self, **kwargs: Any) -> Any:
        if kwargs.get("stream"):
            # Tool calls arrive in fragments; reviewing a partial call is unsound.
            raise NotImplementedError("sluice: streaming is not supported by the guard yet")
        self._guard.ingest(to_neutral(kwargs.get("messages", [])))
        resp = self._inner.create(**kwargs)
        reviews = [
            self._guard.review(
                Message(
                    "assistant",
                    text_of(c.message.content),
                    tuple(parse_tool_call(tc) for tc in c.message.tool_calls or []),
                )
            )
            for c in resp.choices
        ]
        if not any(r.blocked for r in reviews):
            return resp
        return rewrite_response(resp, reviews)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _Namespace:
    def __init__(self, inner: Any, **attrs: Any) -> None:
        self._inner = inner
        self.__dict__.update(attrs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class GuardedOpenAI:
    """Proxy for ``openai.OpenAI``: guards ``chat.completions.create``, passes the rest."""

    def __init__(self, client: Any, guard: Guard) -> None:
        self._client = client
        self.guard = guard
        completions = _GuardedCompletions(client.chat.completions, guard)
        self.chat = _Namespace(client.chat, completions=completions)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def guard_openai(client: Any, monitor: Monitor, *, raise_on_block: bool = False) -> GuardedOpenAI:
    return GuardedOpenAI(client, Guard(monitor, raise_on_block=raise_on_block))


# ---- sluice's own loop ----------------------------------------------------------------------


def to_request(messages: Sequence[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role == "tool":
            out.append({"role": "tool", "tool_call_id": m.tool_call_id or "", "content": m.content})
        elif m.role == "assistant":
            d: dict[str, Any] = {"role": "assistant", "content": m.content or None}
            if m.tool_calls:
                d["tool_calls"] = [
                    {
                        "id": c.id,
                        "type": "function",
                        "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                    }
                    for c in m.tool_calls
                ]
            out.append(d)
        else:
            out.append({"role": m.role, "content": m.content})
    return out


def tool_param(spec: ToolSpec) -> dict[str, Any]:
    s = spec.json_schema()
    return {
        "type": "function",
        "function": {
            "name": s["name"],
            "description": s["description"],
            "parameters": s["input_schema"],
        },
    }


class OpenAILLM:
    def __init__(self, client: Any, model: str) -> None:
        self.client = client
        self.model = model

    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> Message:
        kwargs: dict[str, Any] = {"model": self.model, "messages": to_request(messages)}
        if tools:
            kwargs["tools"] = [tool_param(t) for t in tools]
        msg = self.client.chat.completions.create(**kwargs).choices[0].message
        calls = tuple(parse_tool_call(tc) for tc in msg.tool_calls or [])
        return Message("assistant", text_of(msg.content), calls)


__all__ = ["GuardedOpenAI", "OpenAILLM", "SluiceBlocked", "guard_openai"]
