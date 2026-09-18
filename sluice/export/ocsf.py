"""Export sluice decisions as OCSF events for SIEM ingestion.

Each non-allowed tool call becomes an OCSF **Detection Finding** (class 2004, category 2
"Findings"), the shape Splunk, Elastic, Microsoft Sentinel, AWS Security Lake and Datadog
accept natively. The enforcement outcome is in ``action_id`` / ``disposition_id``; framework
tags go to ``finding_info.types`` and ``finding_info.attacks``; everything sluice-specific
(labels, rules, evidence, provenance) goes to ``unmapped`` as OCSF recommends.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import IO, Any

import sluice

OCSF_VERSION = "1.3.0"
CLASS_UID = 2004  # Detection Finding
CATEGORY_UID = 2  # Findings
ACTIVITY_CREATE = 1

# OCSF enums
ACTION_ALLOWED, ACTION_DENIED = 1, 2
DISPOSITION_ALLOWED, DISPOSITION_BLOCKED, DISPOSITION_LOGGED = 1, 2, 17
SEVERITY_INFO, SEVERITY_MEDIUM, SEVERITY_HIGH = 1, 3, 4
STATUS_NEW = 1


def _severity(verdict: str, violations: list[dict[str, Any]]) -> int:
    if not violations:
        return SEVERITY_INFO if verdict == "allow" else SEVERITY_MEDIUM
    return SEVERITY_HIGH if verdict in ("block", "ask") else SEVERITY_MEDIUM


def ocsf_finding(call_event: dict[str, Any]) -> dict[str, Any]:
    """Map one trace ``call`` event to an OCSF Detection Finding."""
    decision = call_event.get("decision", {})
    verdict = decision.get("verdict", "block")
    violations = decision.get("violations", [])
    blocked = verdict in ("block", "ask")
    tags = [t for v in violations for t in v.get("tags", [])]
    atlas = [t for t in tags if t["framework"] == "MITRE-ATLAS"]
    title = f"sluice {verdict}: {call_event.get('tool', '?')}"
    reason = decision.get("reason") or "policy violation"
    return {
        "activity_id": ACTIVITY_CREATE,
        "category_uid": CATEGORY_UID,
        "class_uid": CLASS_UID,
        "type_uid": CLASS_UID * 100 + ACTIVITY_CREATE,
        "time": int(float(call_event.get("ts", 0)) * 1000),
        "severity_id": _severity(verdict, violations),
        "status_id": STATUS_NEW,
        "action_id": ACTION_DENIED if blocked else ACTION_ALLOWED,
        "disposition_id": (
            DISPOSITION_BLOCKED
            if blocked
            else DISPOSITION_LOGGED
            if verdict == "log"
            else DISPOSITION_ALLOWED
        ),
        "message": call_event.get("explanation") or title,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "sluice", "vendor_name": "sluice", "version": sluice.__version__},
            "log_name": "sluice.decisions",
        },
        "finding_info": {
            "uid": f"{call_event.get('session_id', 'sluice')}:{call_event.get('id', '?')}",
            "title": title,
            "desc": reason,
            "types": sorted({f"{t['id']} {t['name']}" for t in tags}),
            "attacks": [
                {"technique": {"uid": t["id"], "name": t["name"]}, "version": "MITRE ATLAS"}
                for t in {t["id"]: t for t in atlas}.values()
            ],
        },
        "unmapped": {
            "sluice": {
                "tool": call_event.get("tool"),
                "verdict": verdict,
                "violations": violations,
                "arguments": call_event.get("attribution", {}),
            }
        },
    }


class OcsfExporter:
    """Trace listener writing OCSF findings as JSON lines (e.g. for a SIEM file forwarder).

    By default only calls that were not plainly allowed are exported.
    """

    def __init__(self, sink: str | Path | IO[str], *, include_allowed: bool = False) -> None:
        self.include_allowed = include_allowed
        self._owned = isinstance(sink, str | Path)
        if isinstance(sink, str | Path):
            path = Path(sink)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh: IO[str] = path.open("a", encoding="utf-8")
        else:
            self._fh = sink
        self.count = 0
        self._session = "sluice"

    def __call__(self, event: dict[str, Any]) -> None:
        if event.get("type") == "session":
            self._session = str(event.get("session_id", self._session))
            return
        if event.get("type") != "call":
            return
        if not self.include_allowed and event.get("decision", {}).get("verdict") == "allow":
            return
        finding = ocsf_finding({"session_id": self._session, **event})
        self._fh.write(json.dumps(finding, default=str) + "\n")
        self._fh.flush()
        self.count += 1

    def close(self) -> None:
        if self._owned:
            self._fh.close()
