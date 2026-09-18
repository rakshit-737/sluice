"""Strict-mode agent: plan from the request, then interpret the plan with exact labels."""

from __future__ import annotations

from dataclasses import dataclass

from sluice.strict.dsl import Plan, PlanSyntaxError
from sluice.strict.interpreter import Interpreter, StrictResult
from sluice.strict.planner import Planner


@dataclass(frozen=True)
class StrictRun:
    plan: Plan | None
    result: StrictResult


class StrictAgent:
    def __init__(self, planner: Planner, interpreter: Interpreter) -> None:
        missing = set(planner.callables) ^ set(interpreter.callables)
        if missing:
            raise ValueError(f"planner and interpreter disagree on tools: {sorted(missing)}")
        self.planner = planner
        self.interpreter = interpreter

    def run(self, request: str) -> StrictRun:
        try:
            plan = self.planner.plan(request)
        except PlanSyntaxError as e:
            return StrictRun(None, StrictResult("error", error=f"planning failed: {e}"))
        return StrictRun(plan, self.interpreter.run(plan))
