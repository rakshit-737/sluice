from __future__ import annotations

import re

import pytest

from sluice.strict.dsl import MAX_PLAN_CHARS, PlanSyntaxError, parse_plan

CALLS = ["read_inbox", "send_email", "quarantine", "answer", "len"]

GOOD = """
emails = read_inbox()
n = len(emails)
first = emails[0]
who = first.sender
greeting = f"Hi {who}, you have {n} new mails"
if n > 3 and not (who == "boss"):
    answer(greeting + "!")
elif n in [1, 2]:
    pass
else:
    answer("quiet day")
for e in emails:
    info = quarantine(e["body"], "Invoice")
    send_email(to="me@corp.example", body=info.total if info else None)
d = {"a": 1, "b": [1.5, True, None]}
x = "yes" if n != 0 else "no"
"""


def test_good_plan_parses() -> None:
    plan = parse_plan(GOOD, CALLS)
    assert plan.source == GOOD and len(plan.tree.body) == 9


@pytest.mark.parametrize(
    ("src", "msg"),
    [
        ("import os", "Import"),
        ("from os import system", "ImportFrom"),
        ("def f():\n    pass", "FunctionDef"),
        ("class A:\n    pass", "ClassDef"),
        ("while True:\n    pass", "While"),
        ("x = [e for e in y]", "ListComp"),
        ("x = {k: 1 for k in y}", "DictComp"),
        ("x = (e for e in y)", "GeneratorExp"),
        ("x = lambda: 1", "Lambda"),
        ("x = y.__class__", "`__class__`"),
        ("x = y._private", "`_private`"),
        ("x = _hidden", "starting with `_`"),
        ("x = y.lower()", "plain name"),
        ("x = eval('1')", "unknown function `eval`"),
        ("x = __import__('os')", "unknown function `__import__`"),
        ("x = open('/etc/passwd')", "unknown function `open`"),
        ("x = y[1:2]", "slicing"),
        ("send_email(*args)", "`*` unpacking"),
        ("send_email(**kw)", "`**` unpacking"),
        ("x = {**d}", "`**` unpacking"),
        ("x = [*a]", "`*` unpacking"),
        ("read_inbox = 1", "reserved name"),
        ("for len in y:\n    pass", "reserved name"),
        ("x = read_inbox", "only be called"),
        ("a, b = 1, 2", "`name = expr`"),
        ("x = y = 1", "`name = expr`"),
        ("x.a = 1", "`name = expr`"),
        ("x += 1", "AugAssign"),
        ("x = 2 * 3", "only `+`"),
        ("x = -1", "only `not`"),
        ("x = a is b", "comparison operator"),
        ("x = b'bytes'", "bytes"),
        ("x = f'{y:>10}'", "format specs"),
        ("try:\n    pass\nexcept Exception:\n    pass", "Try"),
        ("with a:\n    pass", "With"),
        ("for x in y:\n    pass\nelse:\n    pass", "for/else"),
        ("for a.b in y:\n    pass", "plain name"),
        ("global x", "Global"),
        ("return 1", "Return"),
        ("x", "must be a call"),
        ("x = (yield 1)", "Yield"),
        ("x = await y", "Await"),
        ("x = (y := 1)", "NamedExpr"),
        ("send_email(_x=1)", "keyword `_x`"),
        ("x = y if", "not valid syntax"),
        ("x = {1, 2}", "Set"),
        ("x = (1, 2)", "Tuple"),
    ],
)
def test_rejected(src: str, msg: str) -> None:
    with pytest.raises(PlanSyntaxError, match=re.escape(msg)):
        parse_plan(src, CALLS)


def test_error_reports_line() -> None:
    with pytest.raises(PlanSyntaxError) as ei:
        parse_plan("x = 1\nimport os", CALLS)
    assert ei.value.lineno == 2 and str(ei.value).startswith("line 2:")


def test_size_limits() -> None:
    with pytest.raises(PlanSyntaxError, match="longer than"):
        parse_plan("x = 1\n" * (MAX_PLAN_CHARS // 6 + 1), CALLS)
    with pytest.raises(PlanSyntaxError, match="nodes"):
        parse_plan("x = [" + ", ".join(["1"] * 6000) + "]", CALLS)
