"""Sink policies used for the AgentDojo benchmark.

The rule of thumb for every suite: an argument that chooses **where a side effect goes or who
it reaches** — an outbound recipient, a payment destination, an exfiltration URL, a new
credential or identity — must be trusted, so an injection cannot steer it. This is the
CaMeL-style "prevent exfiltration and unauthorized action at the destination" framing.

Deliberately *not* guarded: arguments that only choose *what* to say (subjects, bodies, file
contents) and read-type arguments that name something to fetch or an existing id to act on
(`get_webpage.url`, an `event_id` to cancel). Guarding those blocks benign tasks that legitimately
act on ids and content read from the environment, without closing an exfiltration channel — the
data still cannot *leave* except through a guarded destination. No confidentiality bounds are
set, to keep utility comparable with the undefended baseline. Tool outputs get no source label,
so they fail closed to untrusted/secret.
"""

from __future__ import annotations

from typing import Any

TRUSTED = {"require_integrity": "trusted"}

SINKS: dict[str, dict[str, list[str]]] = {
    "workspace": {
        "send_email": ["recipients", "cc", "bcc"],
        "create_calendar_event": ["participants"],
        "add_calendar_event_participants": ["participants"],
        "share_file": ["email"],
    },
    "travel": {
        "send_email": ["recipients", "cc", "bcc"],
        "create_calendar_event": ["participants"],
        "reserve_hotel": ["hotel"],
        "reserve_car_rental": ["company"],
        "reserve_restaurant": ["restaurant"],
    },
    "banking": {
        "send_money": ["recipient"],
        "schedule_transaction": ["recipient"],
        "update_scheduled_transaction": ["recipient"],
        "update_password": ["password"],
        "update_user_info": ["first_name", "last_name", "street", "city"],
    },
    "slack": {
        "send_direct_message": ["recipient"],
        "invite_user_to_slack": ["user", "user_email"],
        "post_webpage": ["url"],
        "get_webpage": ["url"],  # the URL carries data out (a beacon), so it is an exfil channel
    },
}


def policy_dict(suite: str, tool_names: list[str]) -> dict[str, Any]:
    """Policy-file dict for ``suite``: guarded sinks as above, every other tool unconstrained."""
    guarded = SINKS.get(suite, {})
    sinks: dict[str, Any] = {name: {} for name in tool_names if name not in guarded}
    for name, args in guarded.items():
        sinks[name] = {"args": {a: TRUSTED for a in args}}
    return {
        "version": 1,
        "sources": {
            "user": {"integrity": "trusted", "confidentiality": "internal"},
            "system": {"integrity": "trusted", "confidentiality": "internal"},
            "model": {"integrity": "trusted", "confidentiality": "internal"},
        },
        "sinks": sinks,
        "on_violation": "block",
    }
