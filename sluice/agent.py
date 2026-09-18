"""Minimal tool-calling agent loop, with or without a sluice monitor."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from sluice.llm import LLMClient, Message, ToolCall
from sluice.monitor.middleware import Monitor, render_output
from sluice.policy.decision import Decision
from sluice.tools.registry import ToolRegistry


@dataclass
class RunResult:
    messages: list[Message]
    final: str
    decisions: list[Decision] = field(default_factory=list)
    executed: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    @property
    def blocked(self) -> list[Decision]:
        return [d for d in self.decisions if not d.allowed]


class Agent:
    def __init__(
        self,
        llm: LLMClient,
        registry: ToolRegistry,
        monitor: Monitor | None = None,
        *,
        system_prompt: str = "You are a helpful assistant.",
        max_steps: int = 10,
    ) -> None:
        self.llm = llm
        self.registry = registry
        self.monitor = monitor
        self.system_prompt = system_prompt
        self.max_steps = max_steps

    def run(self, user_prompt: str) -> RunResult:
        messages = [Message("system", self.system_prompt), Message("user", user_prompt)]
        if self.monitor:
            self.monitor.observe(self.system_prompt, "system")
            self.monitor.observe(user_prompt, "user")
        result = RunResult(messages, "")
        tools = list(self.registry)
        for _ in range(self.max_steps):
            reply = self.llm.complete(messages, tools)
            messages.append(reply)
            if not reply.tool_calls:
                result.final = reply.content
                break
            for tc in reply.tool_calls:
                messages.append(Message("tool", self._execute(tc, result), tool_call_id=tc.id))
        else:
            result.final = "(stopped: max_steps reached)"
        return result

    def _execute(self, tc: ToolCall, result: RunResult) -> str:
        spec = self.registry.get(tc.name)
        if self.monitor is None:
            if spec is None:
                return f"error: unknown tool {tc.name}"
            out = spec.fn(**tc.arguments)
            result.executed.append((tc.name, dict(tc.arguments)))
            return out if isinstance(out, str) else json.dumps(out, default=str)
        checked = self.monitor.check(tc)
        result.decisions.append(checked.decision)
        if not checked.decision.allowed:
            return f"BLOCKED by sluice policy.\n{checked.decision.explain()}"
        assert spec is not None  # policy blocks unknown tools
        try:
            out = spec.fn(**checked.args)
        except Exception as e:  # tool errors go back to the model, labelled like outputs
            out = f"error: {type(e).__name__}: {e}"
        result.executed.append((tc.name, checked.args))
        return render_output(self.monitor.record_output(checked, out))
