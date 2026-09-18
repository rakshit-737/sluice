"""Scenario: a packaged agent setup that ``sluice run <dir>`` can execute.

A scenario directory contains ``policy.yaml`` and ``scenario.py`` defining ``build()``.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel

from sluice.llm import LLMClient
from sluice.tools.registry import ToolRegistry


@dataclass
class Scenario:
    name: str
    registry: ToolRegistry
    llm: LLMClient
    user_prompt: str
    system_prompt: str = "You are a helpful assistant."
    policy_path: Path | None = None
    # Strict mode (optional): planner and quarantine models plus quarantine schemas.
    planner_llm: LLMClient | None = None
    quarantine_llm: LLMClient | None = None
    schemas: dict[str, type[BaseModel]] = field(default_factory=dict)


class ScenarioError(RuntimeError):
    pass


def load_scenario(directory: str | Path) -> Callable[[], Scenario]:
    """Import ``<directory>/scenario.py`` and return its ``build`` function.

    This imports developer-authored example code, never model output.
    """
    d = Path(directory)
    path = d / "scenario.py"
    if not path.is_file():
        raise ScenarioError(f"no scenario.py in {d}")
    spec = importlib.util.spec_from_file_location(
        f"sluice_scenario_{d.name.replace('-', '_')}", path
    )
    if spec is None or spec.loader is None:
        raise ScenarioError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    build = getattr(mod, "build", None)
    if not callable(build):
        raise ScenarioError(f"{path} defines no build()")

    def _build() -> Scenario:
        sc = build()
        if not isinstance(sc, Scenario):
            raise ScenarioError("build() must return a sluice.scenario.Scenario")
        if sc.policy_path is None and (d / "policy.yaml").is_file():
            sc.policy_path = d / "policy.yaml"
        return sc

    return _build
