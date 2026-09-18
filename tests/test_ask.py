from __future__ import annotations

import io

import pytest
from rich.console import Console

from sluice.labels import Label
from sluice.labels.requirement import Requirement
from sluice.monitor.ask import rich_ask
from sluice.policy import Decision, Violation

DECISION = Decision(
    "send",
    "ask",
    (
        Violation(
            "to", Label.unknown("tool.web"), Requirement.trusted(), "r", ("integrity untrusted",)
        ),
    ),
    "policy violation",
)


def console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, width=100), buf


def test_non_tty_fails_closed() -> None:
    con, buf = console()
    assert rich_ask(con, is_tty=lambda: False, confirm=lambda c: True)(DECISION) is False
    assert buf.getvalue() == ""


@pytest.mark.parametrize("answer", [True, False])
def test_tty_prompts_with_explanation(answer: bool) -> None:
    con, buf = console()
    assert rich_ask(con, is_tty=lambda: True, confirm=lambda c: answer)(DECISION) is answer
    out = buf.getvalue()
    assert "approval needed" in out and "tool.web" in out  # label text not eaten as markup


@pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt])
def test_interrupt_fails_closed(exc: type[BaseException]) -> None:
    def boom(c: Console) -> bool:
        raise exc

    con, _ = console()
    assert rich_ask(con, is_tty=lambda: True, confirm=boom)(DECISION) is False


def test_default_prompt_reads_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    con, _ = console()
    assert rich_ask(con, is_tty=lambda: True)(DECISION) is True
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert rich_ask(con)(DECISION) is False  # StringIO is not a TTY
