"""Strict-mode interpreter: walks a checked plan AST and tracks labels exactly.

Nothing here calls ``exec``, ``eval`` or ``compile``. The interpreter evaluates the
whitelisted node types from ``dsl.py`` itself.

Value model: every runtime value is a ``LabeledValue``. Containers hold labelled children
(``list[LabeledValue]`` / ``dict[str, LabeledValue]``); the container's own label is its
*structure* label (who decided its length, order and keys). ``deep_label`` joins a value's
label with all of its descendants', and is what a sink sees.

Implicit flows: branching on a value (``if``, ``for``, ``a if c else b``, short-circuit
``and``/``or``) raises the program-counter (pc) label; everything assigned, passed to a tool
or answered while the pc is raised is joined with it.
"""

from __future__ import annotations

import ast
import itertools
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel

from sluice.labels.label import Label, ValueId, join_all
from sluice.labels.value import LabeledValue
from sluice.policy.decision import AskHandler, Decision, resolve_ask
from sluice.policy.engine import PolicyEngine
from sluice.strict.dsl import Plan
from sluice.tools.registry import ToolRegistry, ToolSpec, spec_to_dict
from sluice.trace.writer import TraceWriter

LV = LabeledValue[Any]
QuarantineFn = Callable[[str, type[BaseModel]], BaseModel]


class PlanRuntimeError(RuntimeError):
    def __init__(self, msg: str, node: ast.AST | None = None) -> None:
        line = getattr(node, "lineno", None)
        super().__init__(f"line {line}: {msg}" if line else msg)


class PolicyStop(RuntimeError):
    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(decision.explain())


@dataclass(frozen=True)
class Limits:
    max_steps: int = 10_000
    max_iterations: int = 1_000
    max_tool_calls: int = 100
    max_text: int = 1_000_000


@dataclass
class StrictResult:
    status: Literal["completed", "blocked", "error"]
    answers: list[LV] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    executed: list[tuple[str, dict[str, Any]]] = field(default_factory=list)  # allowed tool calls
    error: str = ""

    @property
    def answer(self) -> str:
        return "\n".join(str(unwrap(a)) for a in self.answers)

    @property
    def answer_label(self) -> Label:
        return join_all(deep_label(a) for a in self.answers)

    @property
    def blocked(self) -> list[Decision]:
        return [d for d in self.decisions if not d.allowed]


# ---- value helpers ----------------------------------------------------------------------------


def unwrap(v: Any) -> Any:
    if isinstance(v, LabeledValue):
        v = v.value
    if isinstance(v, list):
        return [unwrap(x) for x in v]
    if isinstance(v, dict):
        return {k: unwrap(x) for k, x in v.items()}
    return v


def deep_label(v: LV) -> Label:
    label = v.label
    if isinstance(v.value, list):
        label = join_all([label, *(deep_label(x) for x in v.value)])
    elif isinstance(v.value, dict):
        label = join_all([label, *(deep_label(x) for x in v.value.values())])
    return label


def _mk(value: Any, *parents: LV, extra: Label | None = None, origin: str = "") -> LV:
    """A new value computed from ``parents`` (deep labels) and ``extra``."""
    label = join_all([*(deep_label(p) for p in parents), extra or Label.bottom()])
    return LabeledValue(value, label.with_provenance(*(p.id for p in parents)), origin=origin)


def _relabel(v: LV, extra: Label) -> LV:
    if extra == Label.bottom():
        return v
    return LabeledValue(v.value, v.label.join(extra).with_provenance(v.id), origin=v.origin)


def tree(raw: Any, label_for: Callable[[str, bool], Label], key: str = "") -> LV:
    """Build a labelled tree from a raw Python value.

    ``label_for(key, is_container)`` supplies each node's label.
    """
    if isinstance(raw, BaseModel):
        raw = raw.model_dump(mode="json")
    if isinstance(raw, dict):
        kids = {str(k): tree(v, label_for, str(k)) for k, v in raw.items()}
        return LabeledValue(kids, label_for(key, True))
    if isinstance(raw, list | tuple):
        return LabeledValue([tree(v, label_for, key) for v in raw], label_for(key, True))
    if not isinstance(raw, str | int | float | bool | type(None)):
        raw = str(raw)
    return LabeledValue(raw, label_for(key, False))


def _leaves(v: LV, path: str = "") -> Iterator[tuple[str, LV]]:
    if isinstance(v.value, dict):
        for k, x in v.value.items():
            yield from _leaves(x, f"{path}.{k}")
    elif isinstance(v.value, list):
        for i, x in enumerate(v.value):
            yield from _leaves(x, f"{path}[{i}]")
    else:
        yield path, v


# ---- builtins -------------------------------------------------------------------------------


def _str_arg(x: Any, name: str) -> str:
    if not isinstance(x, str):
        raise PlanRuntimeError(f"{name}() expects a string, got {type(x).__name__}")
    return x


def _join(items: Any, sep: str = "") -> str:
    if not isinstance(items, list):
        raise PlanRuntimeError("join() expects a list")
    return _str_arg(sep, "join").join(str(i) for i in items)


def _split(s: Any, sep: str | None = None) -> list[str]:
    return _str_arg(s, "split").split(sep)


def _contains(haystack: Any, needle: Any) -> bool:
    if isinstance(haystack, str):
        return str(needle) in haystack
    if isinstance(haystack, list | dict):
        return needle in haystack
    raise PlanRuntimeError("contains() expects a string, list or dict")


PURE_BUILTINS: dict[str, Callable[..., Any]] = {
    "len": len,
    "str": str,
    "int": int,
    "float": float,
    "lower": lambda s: _str_arg(s, "lower").lower(),
    "upper": lambda s: _str_arg(s, "upper").upper(),
    "strip": lambda s: _str_arg(s, "strip").strip(),
    "split": _split,
    "join": _join,
    "contains": _contains,
    "startswith": lambda s, p: _str_arg(s, "startswith").startswith(str(p)),
    "endswith": lambda s, p: _str_arg(s, "endswith").endswith(str(p)),
}
SPECIAL_BUILTINS = ("answer", "quarantine")
BUILTINS = (*PURE_BUILTINS, *SPECIAL_BUILTINS)


# ---- interpreter ----------------------------------------------------------------------------


class Interpreter:
    def __init__(
        self,
        policy: PolicyEngine,
        registry: ToolRegistry,
        *,
        quarantine: QuarantineFn | None = None,
        schemas: Mapping[str, type[BaseModel]] | None = None,
        trace: TraceWriter | None = None,
        ask: AskHandler | None = None,
        limits: Limits | None = None,
    ) -> None:
        self.policy = policy
        self.registry = registry
        self.quarantine = quarantine
        self.schemas = dict(schemas or {})
        self.trace = trace or TraceWriter()
        self.ask = ask
        self.limits = limits or Limits()
        self._emitted: set[ValueId] = set()
        self.session_id = uuid.uuid4().hex
        self.trace.emit(
            "session",
            session_id=self.session_id,
            mode="strict",
            policy=policy.to_dict(),
            tools=[spec_to_dict(t) for t in registry],
        )

    @property
    def callables(self) -> list[str]:
        return [t.name for t in self.registry] + list(BUILTINS)

    # ---- entry point --------------------------------------------------------------------------

    def run(self, plan: Plan, inputs: Mapping[str, LV] | None = None) -> StrictResult:
        state = _State(dict(inputs or {}))
        result = StrictResult("completed", state.answers, state.decisions, state.executed)
        self.trace.emit("plan", source=plan.source)
        try:
            self._block(plan.tree.body, state)
        except PolicyStop as e:
            result.status = "blocked"
            result.error = str(e)
        except PlanRuntimeError as e:
            result.status = "error"
            result.error = str(e)
        except RecursionError:  # pragma: no cover - the parser caps nesting first
            result.status = "error"
            result.error = "plan nesting too deep"
        return result

    # ---- statements ---------------------------------------------------------------------------

    def _block(self, body: Sequence[ast.stmt], st: _State) -> None:
        for s in body:
            self._stmt(s, st)

    def _stmt(self, s: ast.stmt, st: _State) -> None:
        st.steps += 1
        if st.steps > self.limits.max_steps:
            raise PlanRuntimeError(f"step limit {self.limits.max_steps} exceeded", s)
        if isinstance(s, ast.Assign):
            target = s.targets[0]
            assert isinstance(target, ast.Name)
            st.env[target.id] = _relabel(self._expr(s.value, st), st.pc)
        elif isinstance(s, ast.Expr):
            self._expr(s.value, st)
        elif isinstance(s, ast.If):
            test = self._expr(s.test, st)
            with st.raised(deep_label(test)):
                self._block(s.body if unwrap(test) else s.orelse, st)
        elif isinstance(s, ast.For):
            assert isinstance(s.target, ast.Name)
            container = self._expr(s.iter, st)
            if isinstance(container.value, list):
                items = list(container.value)
            elif isinstance(container.value, dict):
                items = [LabeledValue(k, container.label) for k in container.value]
            else:
                raise PlanRuntimeError("can only loop over a list or dict", s)
            if len(items) > self.limits.max_iterations:
                raise PlanRuntimeError(f"loop over {len(items)} items exceeds limit", s)
            with st.raised(container.label):
                for item in items:
                    st.env[s.target.id] = _relabel(item, container.label.join(st.pc))
                    self._block(s.body, st)
        elif isinstance(s, ast.Pass):
            pass
        else:  # pragma: no cover - the parser rejects everything else
            raise PlanRuntimeError(f"unsupported statement {type(s).__name__}", s)

    # ---- expressions --------------------------------------------------------------------------

    def _expr(self, e: ast.expr, st: _State) -> LV:
        if isinstance(e, ast.Constant):
            return LabeledValue(e.value, Label.bottom(), origin="const")
        if isinstance(e, ast.Name):
            if e.id not in st.env:
                raise PlanRuntimeError(f"name `{e.id}` is not defined", e)
            return st.env[e.id]
        if isinstance(e, ast.JoinedStr):
            parts = [self._expr(v, st) for v in e.values]
            return _mk("".join(_fmt(unwrap(p)) for p in parts), *parts, origin="f-string")
        if isinstance(e, ast.FormattedValue):
            return self._expr(e.value, st)
        if isinstance(e, ast.List):
            return LabeledValue([self._expr(x, st) for x in e.elts], Label.bottom())
        if isinstance(e, ast.Dict):
            out: dict[str, LV] = {}
            key_labels: list[Label] = []
            for k, v in zip(e.keys, e.values, strict=True):
                assert k is not None
                key = self._expr(k, st)
                out[str(unwrap(key))] = self._expr(v, st)
                key_labels.append(deep_label(key))
            return LabeledValue(out, join_all(key_labels))
        if isinstance(e, ast.Subscript):
            return self._index(self._expr(e.value, st), self._expr(e.slice, st), e)
        if isinstance(e, ast.Attribute):
            base = self._expr(e.value, st)
            return self._index(base, LabeledValue(e.attr, Label.bottom()), e)
        if isinstance(e, ast.BinOp):
            a, b = self._expr(e.left, st), self._expr(e.right, st)
            try:
                value = unwrap(a) + unwrap(b)
            except TypeError as ex:
                raise PlanRuntimeError(f"cannot add: {ex}", e) from ex
            if isinstance(value, str) and len(value) > self.limits.max_text:
                raise PlanRuntimeError("string too long", e)
            if isinstance(value, list):
                return _mk(tree(value, lambda k, c: Label.bottom()).value, a, b)
            return _mk(value, a, b)
        if isinstance(e, ast.Compare):
            operands = [self._expr(e.left, st), *(self._expr(c, st) for c in e.comparators)]
            ok = True
            for op, x, y in zip(e.ops, operands, operands[1:], strict=False):
                ok = ok and _compare(op, unwrap(x), unwrap(y), e)
            return _mk(ok, *operands)
        if isinstance(e, ast.BoolOp):
            # Later operands only run depending on earlier ones: evaluate them under that pc.
            seen: list[LV] = []
            for v in e.values:
                with st.raised(join_all(deep_label(s) for s in seen)):
                    cur = self._expr(v, st)
                seen.append(cur)
                truthy = bool(unwrap(cur))
                if (isinstance(e.op, ast.And) and not truthy) or (
                    isinstance(e.op, ast.Or) and truthy
                ):
                    break
            return _mk(seen[-1].value, *seen)
        if isinstance(e, ast.UnaryOp):
            operand = self._expr(e.operand, st)
            return _mk(not unwrap(operand), operand)
        if isinstance(e, ast.IfExp):
            test = self._expr(e.test, st)
            with st.raised(deep_label(test)):
                chosen = self._expr(e.body if unwrap(test) else e.orelse, st)
            return _relabel(chosen, deep_label(test))
        if isinstance(e, ast.Call):
            return self._call(e, st)
        raise PlanRuntimeError(f"unsupported expression {type(e).__name__}", e)  # pragma: no cover

    def _index(self, base: LV, key: LV, node: ast.AST) -> LV:
        k = unwrap(key)
        container = base.value
        try:
            if isinstance(container, dict):
                child = container[str(k)]
            elif isinstance(container, list):
                if not isinstance(k, int) or isinstance(k, bool):
                    raise PlanRuntimeError("list index must be an integer", node)
                child = container[k]
            elif isinstance(container, str):
                if not isinstance(k, int) or isinstance(k, bool):
                    raise PlanRuntimeError("string index must be an integer", node)
                return _mk(container[k], base, key)
            else:
                raise PlanRuntimeError(f"cannot index a {type(container).__name__}", node)
        except (KeyError, IndexError) as ex:
            raise PlanRuntimeError(f"no element {k!r}", node) from ex
        extra = base.label.join(deep_label(key))
        return LabeledValue(child.value, child.label.join(extra).with_provenance(child.id))

    # ---- calls --------------------------------------------------------------------------------

    def _call(self, c: ast.Call, st: _State) -> LV:
        assert isinstance(c.func, ast.Name)
        name = c.func.id
        args = [self._expr(a, st) for a in c.args]
        kwargs = {kw.arg: self._expr(kw.value, st) for kw in c.keywords if kw.arg}
        if name == "answer":
            if kwargs or len(args) != 1:
                raise PlanRuntimeError("answer() takes exactly one argument", c)
            st.answers.append(_relabel(args[0], st.pc))
            self.trace.emit("answer", label=deep_label(st.answers[-1]).short())
            return LabeledValue(None, Label.bottom())
        if name == "quarantine":
            return self._quarantine(args, kwargs, st, c)
        if name in PURE_BUILTINS:
            try:
                value = PURE_BUILTINS[name](
                    *[unwrap(a) for a in args], **{k: unwrap(v) for k, v in kwargs.items()}
                )
            except PlanRuntimeError:
                raise
            except (TypeError, ValueError) as ex:
                raise PlanRuntimeError(f"{name}(): {ex}", c) from ex
            parents = [*args, *kwargs.values()]
            if isinstance(value, list):
                return _mk(tree(value, lambda k, is_c: Label.bottom()).value, *parents)
            return _mk(value, *parents)
        spec = self.registry.get(name)
        if spec is None:  # pragma: no cover - parser only admits registered names
            raise PlanRuntimeError(f"unknown function `{name}`", c)
        return self._tool(spec, args, kwargs, st, c)

    def _quarantine(self, args: list[LV], kwargs: dict[str, LV], st: _State, c: ast.Call) -> LV:
        if self.quarantine is None:
            raise PlanRuntimeError("quarantine() is not configured", c)
        params = dict(zip(("text", "schema"), args, strict=False)) | kwargs
        if set(params) != {"text", "schema"}:
            raise PlanRuntimeError("quarantine(text, schema) takes exactly two arguments", c)
        schema_name = unwrap(params["schema"])
        if deep_label(params["schema"]) != Label.bottom() or schema_name not in self.schemas:
            raise PlanRuntimeError(
                f"unknown schema {schema_name!r}; available: {sorted(self.schemas)}", c
            )
        text = params["text"]
        raw = unwrap(text)
        label = deep_label(text).join(st.pc).with_provenance(text.id)
        try:
            model = self.quarantine(
                raw if isinstance(raw, str) else str(raw), self.schemas[schema_name]
            )
        except Exception as ex:
            raise PlanRuntimeError(f"quarantine failed: {ex}", c) from ex
        out = tree(model, lambda k, is_c: label)
        self._emit_tree(out, f"quarantine({schema_name})", "", parents=[text.id])
        return out

    def _tool(
        self, spec: ToolSpec, args: list[LV], kwargs: dict[str, LV], st: _State, c: ast.Call
    ) -> LV:
        st.tool_calls += 1
        if st.tool_calls > self.limits.max_tool_calls:
            raise PlanRuntimeError(f"tool call limit {self.limits.max_tool_calls} exceeded", c)
        names = list(spec.params)
        if len(args) > len(names):
            raise PlanRuntimeError(f"{spec.name}() takes at most {len(names)} arguments", c)
        bound: dict[str, LV] = dict(zip(names, args, strict=False))
        for k, v in kwargs.items():
            if k in bound:
                raise PlanRuntimeError(f"{spec.name}() got argument `{k}` twice", c)
            if k not in names:
                raise PlanRuntimeError(f"{spec.name}() has no argument `{k}`", c)
            bound[k] = v
        labels = {k: deep_label(v).join(st.pc) for k, v in bound.items()}
        call_id = f"c{next(st.call_ids)}"
        decision = self.policy.decide(
            spec.name,
            labels,
            self.registry,
            {k: ["exact label (strict mode)"] for k in labels},
        )
        decision = resolve_ask(decision, self.ask)
        st.decisions.append(decision)
        self.trace.emit(
            "call",
            id=call_id,
            tool=spec.name,
            args={k: unwrap(v) for k, v in bound.items()},
            attribution={
                k: {
                    "label": lab.short(),
                    "sources": sorted(lab.sources),
                    "matches": sorted(p for p in lab.provenance if p in self._emitted),
                    "generated": False,
                    "evidence": ["exact label (strict mode)"],
                }
                for k, lab in labels.items()
            },
            decision=decision.to_json(),
            explanation=decision.explain(),
        )
        if not decision.allowed:
            raise PolicyStop(decision)
        plain_args = {k: unwrap(v) for k, v in bound.items()}
        st.executed.append((spec.name, plain_args))
        try:
            raw = spec.fn(**plain_args)
        except Exception as ex:
            raise PlanRuntimeError(f"tool {spec.name} failed: {type(ex).__name__}: {ex}", c) from ex
        args_label = join_all(labels.values()).with_provenance(*(v.id for v in bound.values()))
        source = self.policy.source_label(spec.source)

        def label_for(key: str, is_container: bool) -> Label:
            if is_container:
                # Record keys come from the tool's schema; list length/order come from data.
                return (
                    args_label if key == "" and isinstance(raw, dict) else source.join(args_label)
                )
            field_src = spec.fields.get(key, spec.source) if key else spec.source
            return self.policy.source_label(field_src).join(args_label)

        out = tree(raw, label_for)
        self._emit_tree(out, f"{spec.name}()", call_id)
        return out

    # ---- trace ------------------------------------------------------------------------------

    def _emit_tree(
        self, root: LV, origin: str, call_id: str, parents: list[str] | None = None
    ) -> None:
        self._emit(root, origin, parents or [], call_id)
        for path, leaf in _leaves(root):
            if leaf is not root:
                self._emit(leaf, origin + path, [root.id], "")

    def _emit(self, v: LV, origin: str, parents: list[str], call_id: str) -> None:
        self._emitted.add(v.id)
        lab = v.label if not isinstance(v.value, list | dict) else deep_label(v)
        self.trace.emit(
            "value",
            id=v.id,
            origin=origin,
            label=lab.short(),
            sources=sorted(lab.sources),
            provenance=sorted(lab.provenance),
            parents=parents,
            call=call_id,
            preview=str(unwrap(v))[:200],
        )


def _fmt(v: Any) -> str:
    return v if isinstance(v, str) else str(v)


def _compare(op: ast.cmpop, a: Any, b: Any, node: ast.AST) -> bool:
    try:
        if isinstance(op, ast.Eq):
            return bool(a == b)
        if isinstance(op, ast.NotEq):
            return bool(a != b)
        if isinstance(op, ast.Lt):
            return bool(a < b)
        if isinstance(op, ast.LtE):
            return bool(a <= b)
        if isinstance(op, ast.Gt):
            return bool(a > b)
        if isinstance(op, ast.GtE):
            return bool(a >= b)
        if isinstance(op, ast.In):
            return bool(a in b)
        if isinstance(op, ast.NotIn):
            return bool(a not in b)
    except TypeError as ex:
        raise PlanRuntimeError(f"cannot compare: {ex}", node) from ex
    raise PlanRuntimeError("unsupported comparison", node)  # pragma: no cover


@dataclass
class _State:
    env: dict[str, LV]
    answers: list[LV] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    executed: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    pc_stack: list[Label] = field(default_factory=list)
    steps: int = 0
    tool_calls: int = 0
    call_ids: Iterator[int] = field(default_factory=lambda: itertools.count(1))

    @property
    def pc(self) -> Label:
        return join_all(self.pc_stack)

    @contextmanager
    def raised(self, label: Label) -> Iterator[None]:
        self.pc_stack.append(label)
        try:
            yield
        finally:
            self.pc_stack.pop()
