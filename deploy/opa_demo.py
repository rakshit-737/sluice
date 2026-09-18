"""Demonstrate the OPA sidecar: decide a tool call against a running OPA server.

Run inside docker-compose (``SLUICE_OPA_URL`` points at the ``opa`` service). If OPA is
unreachable, sluice fails closed and blocks — which this script also prints, proving the
fail-closed path. Exit code is 0 when the expected decision (block) is produced.
"""

from __future__ import annotations

import os
import sys

from sluice.labels import Confidentiality, Integrity, Label
from sluice.policy import Policy
from sluice.policy.opa import OpaHttp, OpaPolicy
from sluice.tools import COMMS, ToolRegistry, tool


@tool(caps=[COMMS])
def send_email(to: str, body: str) -> str:  # pragma: no cover - demo tool
    return "sent"


def main() -> int:
    url = os.environ.get("SLUICE_OPA_URL", "http://localhost:8181")
    base = Policy.from_yaml(
        """
        sources:
          user: {integrity: trusted, confidentiality: internal}
          tool.web_fetch: {integrity: untrusted, confidentiality: public}
        sinks:
          send_email: {args: {to: {require_integrity: trusted}}}
        """
    )
    registry = ToolRegistry([send_email])
    engine = OpaPolicy(base, OpaHttp(url))

    # An email address the agent picked up from fetched web content: untrusted.
    web = Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC, frozenset({"tool.web_fetch"}))
    decision = engine.decide("send_email", {"to": web, "body": Label.bottom()}, registry)

    print(f"OPA sidecar: {engine.transport.describe()}")
    print(decision.explain())
    if decision.allowed:
        print("UNEXPECTED: the call was allowed", file=sys.stderr)
        return 1
    print("\nBlocked as expected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
