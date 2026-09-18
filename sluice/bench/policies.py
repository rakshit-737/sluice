"""Sink policies used for the AgentDojo benchmark.

One rule of thumb for every suite: arguments that choose a *destination or target* of a
side effect (recipients, IBANs, URLs, ids of things to delete, passwords, user identities)
must be trusted. Content arguments (subjects, bodies, file contents) are unconstrained, and
no confidentiality bounds are set, to keep utility comparable with the undefended baseline.
Tool outputs are not given source labels, so they fail closed to untrusted/secret.
"""

from __future__ import annotations

from typing import Any

TRUSTED = {"require_integrity": "trusted"}

SINKS: dict[str, dict[str, list[str]]] = {
    "workspace": {
        "send_email": ["recipients", "cc", "bcc", "attachments"],
        "delete_email": ["email_id"],
        "create_calendar_event": ["participants"],
        "cancel_calendar_event": ["event_id"],
        "reschedule_calendar_event": ["event_id"],
        "add_calendar_event_participants": ["event_id", "participants"],
        "append_to_file": ["file_id"],
        "create_file": [],
        "delete_file": ["file_id"],
        "share_file": ["file_id", "email", "permission"],
    },
    "travel": {
        "create_calendar_event": ["participants"],
        "cancel_calendar_event": ["event_id"],
        "reserve_hotel": ["hotel"],
        "reserve_car_rental": ["company"],
        "reserve_restaurant": ["restaurant"],
        "send_email": ["recipients", "cc", "bcc", "attachments"],
    },
    "banking": {
        "send_money": ["recipient", "amount"],
        "schedule_transaction": ["recipient", "amount"],
        "update_scheduled_transaction": ["id", "recipient", "amount"],
        "update_password": ["password"],
        "update_user_info": ["first_name", "last_name", "street", "city"],
    },
    "slack": {
        "add_user_to_channel": ["user", "channel"],
        "send_direct_message": ["recipient"],
        "send_channel_message": ["channel"],
        "invite_user_to_slack": ["user", "user_email"],
        "remove_user_from_slack": ["user"],
        "get_webpage": ["url"],
        "post_webpage": ["url"],
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
