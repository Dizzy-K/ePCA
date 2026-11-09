from __future__ import annotations

from typing import Any


ACTION_ALIASES = {
    "pay": "transfer",
    "submit_payout": "transfer",
    "modify_rule": "modify_policy",
    "set_limit": "modify_policy",
    "update_rule": "modify_policy",
    "increase_privilege": "escalate_privilege",
}


def adapt_legacy_action(
    payload: dict[str, Any],
    *,
    principal_id: str,
    session_id: str,
) -> dict[str, Any]:
    """Map legacy names/parameters while retaining ignored proof fields for compatibility."""
    normalized = dict(payload)
    action = ACTION_ALIASES.get(str(normalized.get("action", "")).strip(), normalized.get("action"))
    params = dict(normalized.get("params") or {})
    if action == "modify_policy":
        target = str(params.get("target", "daily_limit"))
        value = params.get("value", params.get("new_limit", params.get("limit")))
        params = {"target": target, "value": value}
    elif action == "transfer":
        params = {
            "amount": params.get("amount"),
            "recipient": params.get("recipient", "account_B"),
        }
    elif action == "escalate_privilege":
        params = {"new_privilege": params.get("new_privilege")}

    trusted = {
        "action": action,
        "params": params,
        "principal_id": principal_id,
        "session_id": session_id,
    }
    for compatibility_field in ("z3_proof_code", "proof", "certificate", "safe", "metadata", "scenario_label"):
        if compatibility_field in normalized:
            trusted[compatibility_field] = normalized[compatibility_field]
    return trusted
