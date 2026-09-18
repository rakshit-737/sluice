"""Privileged planner: writes a plan from the user's request alone.

The planner is the only model whose output decides *which* tools run. It therefore never sees
untrusted content: its prompt contains the user request, tool signatures, the available
quarantine schemas and, on retry, parser errors about its *own* previous plan. Tool results
flow only through the interpreter. ``Planner.plan`` takes a ``str`` request, not labelled
values, so tool output cannot be passed to it by accident.

Tool descriptions are included only for tools whose source class is not ``mcp.*``: MCP
descriptions come from the server and are untrusted (see DECISIONS D21).
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from pydantic import BaseModel

from sluice.llm import LLMClient, Message
from sluice.strict.dsl import Plan, PlanSyntaxError, parse_plan
from sluice.strict.interpreter import BUILTINS, PURE_BUILTINS
from sluice.tools.registry import ToolRegistry, ToolSpec

_CODE = re.compile(r"```(?:python)?\s*\n(.*?)```", re.DOTALL)

LANGUAGE = """\
Write a plan in a restricted subset of Python. Allowed:
- `name = expr`, a call on its own line, `if/elif/else`, `for x in list_or_dict:`, `pass`
- literals, names, f-strings, lists, dicts, `x[i]`, `x.field`, `+`, comparisons,
  `and`/`or`/`not`, `a if c else b`
- calls, by plain name only, to the tools below and these builtins: {builtins}
- `answer(value)` returns a result to the user
- `quarantine(text, "Schema")` parses untrusted text into a typed value (schemas below)
Not allowed: imports, def/lambda/class, while, comprehensions, method calls, `*`/`**`,
slicing, names starting with `_`.
You never see tool results while planning: write the whole plan up front. Use quarantine()
whenever you need structured information out of text a tool returned.
Reply with the plan in one ```python code block."""


def _signature(spec: ToolSpec) -> str:
    params = ", ".join(p if p in spec.required else f"{p}=..." for p in spec.params)
    doc = ""
    if spec.description and not spec.source.startswith("mcp."):
        doc = "  # " + spec.description.splitlines()[0]
    return f"{spec.name}({params}){doc}"


def _type_name(t: object) -> str:
    return str(getattr(t, "__name__", t))


def _schema_line(name: str, model: type[BaseModel]) -> str:
    fields = ", ".join(f"{k}: {_type_name(f.annotation)}" for k, f in model.model_fields.items())
    return f"{name}({fields})"


class Planner:
    def __init__(
        self,
        llm: LLMClient,
        registry: ToolRegistry,
        schemas: Mapping[str, type[BaseModel]] | None = None,
        *,
        max_attempts: int = 3,
    ) -> None:
        self.llm = llm
        self.registry = registry
        self.schemas = dict(schemas or {})
        self.max_attempts = max_attempts

    @property
    def callables(self) -> list[str]:
        return [t.name for t in self.registry] + list(BUILTINS)

    def system_prompt(self) -> str:
        tools = "\n".join(_signature(t) for t in self.registry) or "(none)"
        schemas = "\n".join(_schema_line(n, m) for n, m in self.schemas.items()) or "(none)"
        language = LANGUAGE.format(builtins=", ".join(sorted(PURE_BUILTINS)))
        return f"{language}\n\nTools:\n{tools}\n\nQuarantine schemas:\n{schemas}"

    def plan(self, request: str) -> Plan:
        if not isinstance(request, str):
            raise TypeError("the planner only accepts the user's request as a plain string")
        messages = [Message("system", self.system_prompt()), Message("user", request)]
        error = ""
        for _ in range(self.max_attempts):
            reply = self.llm.complete(messages, [])
            source = extract_code(reply.content)
            try:
                return parse_plan(source, self.callables)
            except PlanSyntaxError as e:
                error = str(e)
                messages += [
                    Message("assistant", reply.content),
                    Message("user", f"The plan was rejected: {error}\nFix it and reply again."),
                ]
        raise PlanSyntaxError(f"no valid plan after {self.max_attempts} attempts: {error}")


def extract_code(text: str) -> str:
    m = _CODE.search(text)
    return (m.group(1) if m else text).strip() + "\n"
