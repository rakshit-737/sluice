"""Open Policy Agent (Rego) backend for sink decisions.

``OpaPolicy`` wraps a YAML ``Policy``: labels still come from the YAML ``sources``, and each
tool call must pass **both** the YAML sink rules and the Rego rule ``data.sluice.decision``.
The stricter verdict wins. Organisations that already manage authorization in OPA can keep
sink rules there; see ``examples/policies/sluice.rego`` and docs/opa.md.

Input document sent to OPA::

    {"tool": "send_email", "caps": ["comms"], "source": "tool.send_email",
     "args": {"to": {"integrity": "untrusted", "confidentiality": "secret",
                      "sources": ["tool.read_inbox"]}}}

Argument *values* are never sent: the policy service would otherwise receive whatever
private data the agent is handling. Rules are written over labels.

Expected result (``data.sluice.decision``)::

    {"allow": false, "verdict": "block", "reasons": [{"arg": "to", "msg": "..."}]}

``verdict`` is optional (default ``block`` when ``allow`` is false). Fail-closed: transport
errors, timeouts, an undefined decision or a malformed result all block the call.
"""

from __future__ import annotations

import json
import subprocess
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from sluice.labels.label import Label
from sluice.labels.requirement import Requirement
from sluice.policy.compiler import Policy
from sluice.policy.decision import Decision, Verdict, Violation
from sluice.policy.engine import stricter
from sluice.tools.registry import ToolRegistry

DEFAULT_QUERY = "sluice/decision"
VERDICTS: tuple[Verdict, ...] = ("allow", "log", "ask", "block")


class OpaError(RuntimeError):
    pass


class OpaTransport(Protocol):
    def query(self, input_doc: dict[str, Any]) -> Any:
        """Evaluate the decision for ``input_doc``; ``None`` means undefined."""
        ...

    def describe(self) -> str: ...


@dataclass(frozen=True)
class OpaHttp:
    """Query a running OPA server: ``POST <url>/v1/data/<path>``."""

    url: str = "http://localhost:8181"
    path: str = DEFAULT_QUERY
    timeout: float = 2.0

    def __post_init__(self) -> None:
        if urllib.parse.urlparse(self.url).scheme not in ("http", "https"):
            raise ValueError("OPA url must be http(s)")

    def query(self, input_doc: dict[str, Any]) -> Any:
        body = json.dumps({"input": input_doc}).encode()
        req = urllib.request.Request(  # noqa: S310 - scheme checked in __post_init__
            f"{self.url.rstrip('/')}/v1/data/{self.path.strip('/')}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                return json.loads(resp.read()).get("result")
        except (OSError, ValueError) as e:
            raise OpaError(f"OPA server query failed: {e}") from e

    def describe(self) -> str:
        return f"opa http {self.url} data.{self.path.replace('/', '.')}"


@dataclass(frozen=True)
class OpaCli:
    """Evaluate with the ``opa`` binary: ``opa eval --stdin-input -d <policy> <query>``.

    No shell is involved; the input document is passed on stdin, never on the command line.
    """

    policy_paths: tuple[str, ...]
    query_ref: str = "data.sluice.decision"
    command: tuple[str, ...] = ("opa",)
    timeout: float = 10.0

    def query(self, input_doc: dict[str, Any]) -> Any:
        args = [*self.command, "eval", "--format", "json", "--stdin-input"]
        for p in self.policy_paths:
            args += ["--data", p]
        args.append(self.query_ref)
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, input on stdin
                args,
                input=json.dumps(input_doc),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise OpaError(f"opa eval failed: {e}") from e
        if proc.returncode != 0:
            raise OpaError(f"opa eval exited {proc.returncode}: {proc.stderr.strip()[:500]}")
        try:
            out = json.loads(proc.stdout)
        except ValueError as e:
            raise OpaError(f"opa eval returned invalid JSON: {e}") from e
        results = out.get("result") or []
        if not results:
            return None  # undefined
        try:
            return results[0]["expressions"][0]["value"]
        except (KeyError, IndexError, TypeError) as e:
            raise OpaError(f"unexpected opa eval output shape: {e!r}") from e

    def describe(self) -> str:
        return f"opa eval {self.query_ref} ({', '.join(self.policy_paths)})"


class OpaPolicy:
    def __init__(self, base: Policy, transport: OpaTransport) -> None:
        self.base = base
        self.transport = transport

    def source_label(self, source: str) -> Label:
        return self.base.source_label(source)

    def to_dict(self) -> dict[str, Any]:
        # Traces keep the YAML part; the Rego part is referenced, not embedded.
        return {**self.base.to_dict(), "x-opa": self.transport.describe()}

    def input_doc(
        self, tool_name: str, arg_labels: Mapping[str, Label], registry: ToolRegistry
    ) -> dict[str, Any]:
        spec = registry.get(tool_name)
        return {
            "tool": tool_name,
            "caps": sorted(spec.caps) if spec else [],
            "source": spec.source if spec else "",
            "args": {
                arg: {
                    "integrity": lab.integrity.name.lower(),
                    "confidentiality": lab.confidentiality.name.lower(),
                    "sources": sorted(lab.sources),
                }
                for arg, lab in arg_labels.items()
            },
        }

    def decide(
        self,
        tool_name: str,
        arg_labels: Mapping[str, Label],
        registry: ToolRegistry,
        evidence: Mapping[str, Sequence[str]] | None = None,
    ) -> Decision:
        base = self.base.decide(tool_name, arg_labels, registry, evidence)
        doc = self.input_doc(tool_name, arg_labels, registry)
        try:
            verdict, reasons = self._interpret(self.transport.query(doc))
        except Exception as e:  # any failure of the policy service fails closed
            return _merge(base, "block", [], f"OPA unavailable, fail closed: {e}", arg_labels)
        if verdict == "allow":
            return base
        return _merge(base, verdict, reasons, "OPA policy denied", arg_labels)

    @staticmethod
    def _interpret(result: Any) -> tuple[Verdict, list[tuple[str, str]]]:
        if result is None:
            raise OpaError("decision is undefined (is the policy loaded?)")
        if not isinstance(result, dict) or not isinstance(result.get("allow"), bool):
            raise OpaError(f"malformed decision: {str(result)[:200]}")
        if result["allow"]:
            return "allow", []
        verdict = result.get("verdict", "block")
        if verdict not in VERDICTS or verdict == "allow":
            raise OpaError(f"invalid verdict {verdict!r} with allow=false")
        reasons = []
        for r in result.get("reasons") or []:
            if isinstance(r, dict):
                reasons.append((str(r.get("arg", "*")), str(r.get("msg", "denied"))))
            else:
                reasons.append(("*", str(r)))
        return verdict, reasons or [("*", "denied by OPA policy")]


def _merge(
    base: Decision,
    verdict: Verdict,
    reasons: list[tuple[str, str]],
    note: str,
    arg_labels: Mapping[str, Label],
) -> Decision:
    extra = tuple(
        Violation(
            arg,
            arg_labels.get(arg, Label.bottom()),
            Requirement(),
            "opa: data.sluice.decision",
            (msg,),
        )
        for arg, msg in reasons
    )
    reason = f"{base.reason}; {note}" if base.reason else note
    return Decision(
        base.tool, stricter(base.verdict, verdict), base.violations + extra, reason, base.arg_labels
    )
