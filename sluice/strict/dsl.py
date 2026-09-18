"""The strict-mode plan language: a whitelisted subset of Python syntax.

Plans are parsed with ``ast.parse`` (parsing only; nothing is ever compiled or executed by
Python) and every node is checked against an explicit whitelist. Anything not listed is a
``PlanSyntaxError``. The interpreter in ``interpreter.py`` walks the checked tree itself.

Allowed:

- statements: ``name = expr``, ``expr`` (a call), ``if``/``elif``/``else``,
  ``for name in expr:`` (no ``else``), ``pass``
- expressions: literals (str, int, float, bool, None), names, f-strings (no format specs),
  lists, dicts with literal-or-name keys, ``x[i]`` (no slices), ``x.field`` (no leading
  underscore), calls to registered tools and whitelisted builtins by plain name with
  positional/keyword arguments, ``+``, comparisons, ``and``/``or``/``not``, conditional
  expressions ``a if c else b``

Rejected (non-exhaustive): imports, def/lambda/class, while, comprehensions, attribute or
method calls, ``*``/``**`` unpacking, slicing, dunder access, try/with/raise/return/global,
assignment to tool or builtin names, augmented assignment.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass

MAX_PLAN_CHARS = 20_000
MAX_NODES = 5_000

_ALLOWED_CONST = (str, int, float, bool, type(None))
_CMP_OPS = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn)


class PlanSyntaxError(ValueError):
    def __init__(self, msg: str, node: ast.AST | None = None) -> None:
        self.lineno = getattr(node, "lineno", None)
        where = f"line {self.lineno}: " if self.lineno else ""
        super().__init__(f"{where}{msg}")


@dataclass(frozen=True)
class Plan:
    source: str
    tree: ast.Module


def parse_plan(source: str, callables: Iterable[str]) -> Plan:
    """Parse and validate ``source``. ``callables`` are the tool and builtin names a plan may
    call; they are also reserved and cannot be assigned."""
    if len(source) > MAX_PLAN_CHARS:
        raise PlanSyntaxError(f"plan longer than {MAX_PLAN_CHARS} characters")
    try:
        tree = ast.parse(source, mode="exec")
    except SyntaxError as e:
        raise PlanSyntaxError(f"not valid syntax: {e.msg} (line {e.lineno})") from e
    nodes = sum(1 for _ in ast.walk(tree))
    if nodes > MAX_NODES:
        raise PlanSyntaxError(f"plan has {nodes} nodes, limit {MAX_NODES}")
    _Checker(frozenset(callables)).check_block(tree.body)
    return Plan(source, tree)


class _Checker:
    def __init__(self, callables: frozenset[str]) -> None:
        self.callables = callables

    # ---- statements -------------------------------------------------------------------------

    def check_block(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self.check_stmt(stmt)

    def check_stmt(self, s: ast.stmt) -> None:
        if isinstance(s, ast.Assign):
            if len(s.targets) != 1 or not isinstance(s.targets[0], ast.Name):
                raise PlanSyntaxError("only `name = expr` assignment is allowed", s)
            self.check_target(s.targets[0])
            self.check_expr(s.value)
        elif isinstance(s, ast.Expr):
            if not isinstance(s.value, ast.Call):
                raise PlanSyntaxError("a bare expression statement must be a call", s)
            self.check_expr(s.value)
        elif isinstance(s, ast.If):
            self.check_expr(s.test)
            self.check_block(s.body)
            self.check_block(s.orelse)
        elif isinstance(s, ast.For):
            if s.orelse:
                raise PlanSyntaxError("for/else is not allowed", s)
            if not isinstance(s.target, ast.Name):
                raise PlanSyntaxError("loop variable must be a plain name", s)
            self.check_target(s.target)
            self.check_expr(s.iter)
            self.check_block(s.body)
        elif isinstance(s, ast.Pass):
            pass
        else:
            raise PlanSyntaxError(f"statement `{type(s).__name__}` is not allowed", s)

    def check_target(self, t: ast.Name) -> None:
        if t.id in self.callables:
            raise PlanSyntaxError(f"cannot assign to reserved name `{t.id}`", t)
        self.check_name(t)

    # ---- expressions ------------------------------------------------------------------------

    def check_name(self, n: ast.Name) -> None:
        if n.id.startswith("_"):
            raise PlanSyntaxError(f"names starting with `_` are not allowed: `{n.id}`", n)

    def check_expr(self, e: ast.expr) -> None:
        if isinstance(e, ast.Constant):
            if not isinstance(e.value, _ALLOWED_CONST):
                raise PlanSyntaxError(f"constant of type {type(e.value).__name__} not allowed", e)
        elif isinstance(e, ast.Name):
            self.check_name(e)
            if e.id in self.callables:
                raise PlanSyntaxError(f"`{e.id}` can only be called, not used as a value", e)
        elif isinstance(e, ast.JoinedStr):
            for v in e.values:
                if isinstance(v, ast.FormattedValue):
                    if v.format_spec is not None:
                        raise PlanSyntaxError("f-string format specs are not allowed", v)
                    self.check_expr(v.value)
                else:
                    self.check_expr(v)
        elif isinstance(e, ast.List):
            for x in e.elts:
                self.check_value(x)
        elif isinstance(e, ast.Dict):
            for k, v in zip(e.keys, e.values, strict=True):
                if k is None:
                    raise PlanSyntaxError("`**` unpacking is not allowed", e)
                self.check_expr(k)
                self.check_value(v)
        elif isinstance(e, ast.Subscript):
            if isinstance(e.slice, ast.Slice):
                raise PlanSyntaxError("slicing is not allowed", e)
            self.check_expr(e.value)
            self.check_expr(e.slice)
        elif isinstance(e, ast.Attribute):
            if e.attr.startswith("_"):
                raise PlanSyntaxError(f"attribute `{e.attr}` is not allowed", e)
            self.check_expr(e.value)
        elif isinstance(e, ast.Call):
            self.check_call(e)
        elif isinstance(e, ast.BinOp):
            if not isinstance(e.op, ast.Add):
                raise PlanSyntaxError("only `+` is allowed among arithmetic operators", e)
            self.check_expr(e.left)
            self.check_expr(e.right)
        elif isinstance(e, ast.Compare):
            if not all(isinstance(op, _CMP_OPS) for op in e.ops):
                raise PlanSyntaxError("comparison operator not allowed", e)
            self.check_expr(e.left)
            for c in e.comparators:
                self.check_expr(c)
        elif isinstance(e, ast.BoolOp):
            for v in e.values:
                self.check_expr(v)
        elif isinstance(e, ast.UnaryOp):
            if not isinstance(e.op, ast.Not):
                raise PlanSyntaxError("only `not` is allowed as a unary operator", e)
            self.check_expr(e.operand)
        elif isinstance(e, ast.IfExp):
            self.check_expr(e.test)
            self.check_expr(e.body)
            self.check_expr(e.orelse)
        else:
            raise PlanSyntaxError(f"expression `{type(e).__name__}` is not allowed", e)

    def check_value(self, e: ast.expr) -> None:
        if isinstance(e, ast.Starred):
            raise PlanSyntaxError("`*` unpacking is not allowed", e)
        self.check_expr(e)

    def check_call(self, c: ast.Call) -> None:
        if not isinstance(c.func, ast.Name):
            raise PlanSyntaxError("only calls to tools/builtins by plain name are allowed", c)
        if c.func.id not in self.callables:
            raise PlanSyntaxError(f"unknown function `{c.func.id}`", c)
        for a in c.args:
            self.check_value(a)
        for kw in c.keywords:
            if kw.arg is None:
                raise PlanSyntaxError("`**` unpacking is not allowed", c)
            if kw.arg.startswith("_"):
                raise PlanSyntaxError(f"keyword `{kw.arg}` is not allowed", c)
            self.check_expr(kw.value)
