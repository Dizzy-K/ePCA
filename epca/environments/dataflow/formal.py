from __future__ import annotations

from dataclasses import dataclass

import z3

from epca.environments.dataflow.actions import (
    ModifyDataPolicyParams,
    OpenChannelParams,
    ReadResourceParams,
    SanitizeParams,
    SendParams,
    SwitchZoneParams,
)
from epca.environments.dataflow.state import DataFlowState
from epca.runtime.action import ActionProposal
from epca.runtime.contract import NamedConstraint
from epca.runtime.hashing import canonical_json


@dataclass(frozen=True)
class DataFlowStateSymbols:
    current_zone: z3.SeqRef
    session_taint: z3.BoolRef
    principal: z3.SeqRef
    clearance: z3.ArithRef
    classifications_json: z3.SeqRef
    sanitized_json: z3.SeqRef
    channel: z3.SeqRef
    security_invariants_enabled: z3.BoolRef
    public_exfiltration_count: z3.ArithRef
    policy_version: z3.SeqRef
    state_version: z3.ArithRef


@dataclass(frozen=True)
class DataFlowSymbols:
    pre: DataFlowStateSymbols
    post: DataFlowStateSymbols
    action_name: z3.SeqRef
    zone: z3.SeqRef
    resource: z3.SeqRef
    destination: z3.SeqRef
    target: z3.SeqRef
    value_bool: z3.BoolRef
    principal_id: z3.SeqRef
    session_id: z3.SeqRef
    resource_classification: z3.ArithRef
    resource_sanitized: z3.BoolRef
    active_policy_version: z3.SeqRef
    active_contract_version: z3.SeqRef


def _state(prefix: str) -> DataFlowStateSymbols:
    return DataFlowStateSymbols(
        current_zone=z3.String(f"{prefix}_current_zone"),
        session_taint=z3.Bool(f"{prefix}_session_taint"),
        principal=z3.String(f"{prefix}_principal"),
        clearance=z3.Int(f"{prefix}_clearance"),
        classifications_json=z3.String(f"{prefix}_classifications_json"),
        sanitized_json=z3.String(f"{prefix}_sanitized_json"),
        channel=z3.String(f"{prefix}_channel"),
        security_invariants_enabled=z3.Bool(f"{prefix}_security_invariants_enabled"),
        public_exfiltration_count=z3.Int(f"{prefix}_public_exfiltration_count"),
        policy_version=z3.String(f"{prefix}_policy_version"),
        state_version=z3.Int(f"{prefix}_state_version"),
    )


def create_symbols() -> DataFlowSymbols:
    return DataFlowSymbols(
        pre=_state("pre"),
        post=_state("post"),
        action_name=z3.String("action_name"),
        zone=z3.String("action_zone"),
        resource=z3.String("action_resource"),
        destination=z3.String("action_destination"),
        target=z3.String("action_target"),
        value_bool=z3.Bool("action_value_bool"),
        principal_id=z3.String("action_principal_id"),
        session_id=z3.String("action_session_id"),
        resource_classification=z3.Int("action_resource_classification"),
        resource_sanitized=z3.Bool("action_resource_sanitized"),
        active_policy_version=z3.String("active_policy_version"),
        active_contract_version=z3.String("active_contract_version"),
    )


def _bind_state(prefix: str, symbols: DataFlowStateSymbols, state: DataFlowState) -> tuple[NamedConstraint, ...]:
    values = {
        "current_zone": symbols.current_zone == z3.StringVal(state.current_zone),
        "session_taint": symbols.session_taint == z3.BoolVal(state.session_taint),
        "principal": symbols.principal == z3.StringVal(state.principal),
        "clearance": symbols.clearance == state.clearance,
        "classifications_json": symbols.classifications_json == z3.StringVal(canonical_json(state.resource_classification)),
        "sanitized_json": symbols.sanitized_json == z3.StringVal(canonical_json(state.sanitized_resources)),
        "channel": symbols.channel == z3.StringVal(state.channel),
        "security_invariants_enabled": symbols.security_invariants_enabled == z3.BoolVal(state.security_invariants_enabled),
        "public_exfiltration_count": symbols.public_exfiltration_count == state.public_exfiltration_count,
        "policy_version": symbols.policy_version == z3.StringVal(state.policy_version),
        "state_version": symbols.state_version == state.state_version,
    }
    return tuple(
        NamedConstraint(f"bind::{prefix}::{name}", formula, f"exact {prefix}.{name}")
        for name, formula in values.items()
    )


def exact_bindings(
    symbols: DataFlowSymbols,
    *,
    pre_state: DataFlowState,
    action: ActionProposal,
    post_state: DataFlowState,
    policy_version: str,
    contract_version: str,
) -> tuple[NamedConstraint, ...]:
    zone = resource = destination = target = ""
    value_bool = False
    params = action.params
    if isinstance(params, SwitchZoneParams):
        zone = params.zone
    elif isinstance(params, (ReadResourceParams, SanitizeParams)):
        resource = params.resource
    elif isinstance(params, SendParams):
        resource, destination = params.resource, params.destination
    elif isinstance(params, OpenChannelParams):
        destination = params.destination
    elif isinstance(params, ModifyDataPolicyParams):
        target, value_bool = params.target, params.value
    classification = pre_state.classification_for(resource)
    sanitized = resource in pre_state.sanitized_resources
    return (
        *_bind_state("pre", symbols.pre, pre_state),
        *_bind_state("post", symbols.post, post_state),
        NamedConstraint("bind::action_name", symbols.action_name == z3.StringVal(action.action), "exact action name"),
        NamedConstraint("bind::zone", symbols.zone == z3.StringVal(zone), "exact zone"),
        NamedConstraint("bind::resource", symbols.resource == z3.StringVal(resource), "exact resource"),
        NamedConstraint("bind::destination", symbols.destination == z3.StringVal(destination), "exact destination"),
        NamedConstraint("bind::target", symbols.target == z3.StringVal(target), "exact policy target"),
        NamedConstraint("bind::value_bool", symbols.value_bool == z3.BoolVal(value_bool), "exact policy value"),
        NamedConstraint("bind::principal_id", symbols.principal_id == z3.StringVal(action.principal_id), "exact principal"),
        NamedConstraint("bind::session_id", symbols.session_id == z3.StringVal(action.session_id), "exact session"),
        NamedConstraint("bind::resource_classification", symbols.resource_classification == classification, "exact resource classification"),
        NamedConstraint("bind::resource_sanitized", symbols.resource_sanitized == z3.BoolVal(sanitized), "exact sanitization history"),
        NamedConstraint("bind::active_policy_version", symbols.active_policy_version == z3.StringVal(policy_version), "exact policy version"),
        NamedConstraint("bind::active_contract_version", symbols.active_contract_version == z3.StringVal(contract_version), "exact contract version"),
        NamedConstraint("bind::state_policy_matches_active", symbols.pre.policy_version == symbols.active_policy_version, "state policy is active"),
    )
