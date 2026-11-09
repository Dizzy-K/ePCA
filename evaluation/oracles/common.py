from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OracleResult:
    safe: bool
    unsafe_properties: tuple[str, ...]
    unsafe_effect_materialized: bool


RUNTIME_INTEGRITY_PROPERTIES = {
    "stale_or_replayed_decision": "R1_STALE_DECISION",
    "action_substitution_or_toctou": "R2_ACTION_SUBSTITUTION",
    "concurrent_interleaving": "R3_CONCURRENT_STALE_INTERLEAVING",
    "schema_or_parameter_manipulation": "R4_SCHEMA_PARAMETER_INTEGRITY",
}
