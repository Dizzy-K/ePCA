from __future__ import annotations

import z3

from epca.environments.dataflow.actions import (
    ClearTaintParams,
    ModifyDataPolicyParams,
    OpenChannelParams,
    ReadResourceParams,
    SanitizeParams,
    SendParams,
    SwitchZoneParams,
)
from epca.environments.dataflow.formal import DataFlowSymbols
from epca.environments.dataflow.state import DataFlowState
from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract, ContractRegistry, NamedConstraint


def _frame(symbols: DataFlowSymbols, *, exclude: set[str]) -> list[z3.BoolRef]:
    fields = {
        "current_zone": symbols.post.current_zone == symbols.pre.current_zone,
        "session_taint": symbols.post.session_taint == symbols.pre.session_taint,
        "principal": symbols.post.principal == symbols.pre.principal,
        "clearance": symbols.post.clearance == symbols.pre.clearance,
        "classifications_json": symbols.post.classifications_json == symbols.pre.classifications_json,
        "sanitized_json": symbols.post.sanitized_json == symbols.pre.sanitized_json,
        "channel": symbols.post.channel == symbols.pre.channel,
        "security_invariants_enabled": symbols.post.security_invariants_enabled == symbols.pre.security_invariants_enabled,
        "public_exfiltration_count": symbols.post.public_exfiltration_count == symbols.pre.public_exfiltration_count,
        "policy_version": symbols.post.policy_version == symbols.pre.policy_version,
    }
    return [formula for name, formula in fields.items() if name not in exclude]


def _constraint(name: str, description: str, symbols: DataFlowSymbols, *terms: z3.BoolRef) -> tuple[NamedConstraint, ...]:
    return (
        NamedConstraint(
            f"contract::{name}",
            z3.And(
                symbols.action_name == z3.StringVal(name),
                symbols.post.state_version == symbols.pre.state_version + 1,
                *terms,
            ),
            description,
        ),
    )


class SwitchZoneContract(ActionContract[DataFlowState]):
    action_name = "switch_zone"
    contract_version = "dataflow-switch-zone-v1"
    semantics_id = "dataflow.switch_zone:zone_only:taint_preserved:v1"
    parameter_model = SwitchZoneParams

    def transition(self, pre_state: DataFlowState, action: ActionProposal) -> DataFlowState:
        if not self.accepts(action):
            raise TypeError("SwitchZoneContract received an incompatible action")
        params = action.params
        assert isinstance(params, SwitchZoneParams)
        return pre_state.model_copy(update={"current_zone": params.zone, "state_version": pre_state.state_version + 1})

    def compile_transition(self, symbols: DataFlowSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _constraint(
            self.action_name,
            "switching zone preserves taint and every non-zone field",
            symbols,
            symbols.post.current_zone == symbols.zone,
            *_frame(symbols, exclude={"current_zone"}),
        )


class ReadResourceContract(ActionContract[DataFlowState]):
    action_name = "read_resource"
    contract_version = "dataflow-read-resource-v1"
    semantics_id = "dataflow.read:classified_read_sets_session_taint:v1"
    parameter_model = ReadResourceParams

    def transition(self, pre_state: DataFlowState, action: ActionProposal) -> DataFlowState:
        if not self.accepts(action):
            raise TypeError("ReadResourceContract received an incompatible action")
        params = action.params
        assert isinstance(params, ReadResourceParams)
        sanitized = tuple(item for item in pre_state.sanitized_resources if item != params.resource)
        return pre_state.model_copy(
            update={
                "session_taint": pre_state.session_taint or pre_state.classification_for(params.resource) > 0,
                "sanitized_resources": sanitized,
                "state_version": pre_state.state_version + 1,
            }
        )

    def compile_transition(self, symbols: DataFlowSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _constraint(
            self.action_name,
            "reading classified data propagates persistent session taint",
            symbols,
            symbols.post.session_taint == z3.Or(symbols.pre.session_taint, symbols.resource_classification > 0),
            *_frame(symbols, exclude={"session_taint", "sanitized_json"}),
        )


class SanitizeContract(ActionContract[DataFlowState]):
    action_name = "sanitize"
    contract_version = "dataflow-sanitize-v1"
    semantics_id = "dataflow.sanitize:mark_exact_resource:v1"
    parameter_model = SanitizeParams

    def transition(self, pre_state: DataFlowState, action: ActionProposal) -> DataFlowState:
        if not self.accepts(action):
            raise TypeError("SanitizeContract received an incompatible action")
        params = action.params
        assert isinstance(params, SanitizeParams)
        resources = tuple(sorted(set((*pre_state.sanitized_resources, params.resource))))
        return pre_state.model_copy(update={"sanitized_resources": resources, "state_version": pre_state.state_version + 1})

    def compile_transition(self, symbols: DataFlowSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _constraint(
            self.action_name,
            "sanitize marks the exact resource without clearing session history",
            symbols,
            *_frame(symbols, exclude={"sanitized_json"}),
        )


class SendContract(ActionContract[DataFlowState]):
    action_name = "send"
    contract_version = "dataflow-send-v1"
    semantics_id = "dataflow.send:public_tainted_unsanitized_increments_exfiltration:v1"
    parameter_model = SendParams

    def transition(self, pre_state: DataFlowState, action: ActionProposal) -> DataFlowState:
        if not self.accepts(action):
            raise TypeError("SendContract received an incompatible action")
        params = action.params
        assert isinstance(params, SendParams)
        unsafe = params.destination == "public" and pre_state.session_taint and params.resource not in pre_state.sanitized_resources
        return pre_state.model_copy(
            update={
                "public_exfiltration_count": pre_state.public_exfiltration_count + int(unsafe),
                "state_version": pre_state.state_version + 1,
            }
        )

    def compile_transition(self, symbols: DataFlowSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        increment = z3.If(
            z3.And(
                symbols.destination == z3.StringVal("public"),
                symbols.pre.session_taint,
                z3.Not(symbols.resource_sanitized),
            ),
            1,
            0,
        )
        return _constraint(
            self.action_name,
            "send materializes a public effect exactly when tainted unsanitized data reaches public",
            symbols,
            symbols.post.public_exfiltration_count == symbols.pre.public_exfiltration_count + increment,
            *_frame(symbols, exclude={"public_exfiltration_count"}),
        )


class OpenChannelContract(ActionContract[DataFlowState]):
    action_name = "open_channel"
    contract_version = "dataflow-open-channel-v1"
    semantics_id = "dataflow.open_channel:set_exact_destination:v1"
    parameter_model = OpenChannelParams

    def transition(self, pre_state: DataFlowState, action: ActionProposal) -> DataFlowState:
        if not self.accepts(action):
            raise TypeError("OpenChannelContract received an incompatible action")
        params = action.params
        assert isinstance(params, OpenChannelParams)
        return pre_state.model_copy(update={"channel": params.destination, "state_version": pre_state.state_version + 1})

    def compile_transition(self, symbols: DataFlowSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _constraint(
            self.action_name,
            "open_channel selects only the exact destination",
            symbols,
            symbols.post.channel == symbols.destination,
            *_frame(symbols, exclude={"channel"}),
        )


class ClearTaintContract(ActionContract[DataFlowState]):
    action_name = "clear_taint"
    contract_version = "dataflow-clear-taint-v1"
    semantics_id = "dataflow.clear_taint:set_false:v1"
    parameter_model = ClearTaintParams

    def transition(self, pre_state: DataFlowState, action: ActionProposal) -> DataFlowState:
        if not self.accepts(action):
            raise TypeError("ClearTaintContract received an incompatible action")
        return pre_state.model_copy(update={"session_taint": False, "state_version": pre_state.state_version + 1})

    def compile_transition(self, symbols: DataFlowSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _constraint(
            self.action_name,
            "clear_taint changes only the taint bit",
            symbols,
            z3.Not(symbols.post.session_taint),
            *_frame(symbols, exclude={"session_taint"}),
        )


class ModifyDataPolicyContract(ActionContract[DataFlowState]):
    action_name = "modify_policy"
    contract_version = "dataflow-modify-policy-v1"
    semantics_id = "dataflow.modify_policy:set_security_invariants_flag:v1"
    parameter_model = ModifyDataPolicyParams

    def transition(self, pre_state: DataFlowState, action: ActionProposal) -> DataFlowState:
        if not self.accepts(action):
            raise TypeError("ModifyDataPolicyContract received an incompatible action")
        params = action.params
        assert isinstance(params, ModifyDataPolicyParams)
        return pre_state.model_copy(
            update={"security_invariants_enabled": params.value, "state_version": pre_state.state_version + 1}
        )

    def compile_transition(self, symbols: DataFlowSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _constraint(
            self.action_name,
            "modify_policy sets only the registered security flag",
            symbols,
            symbols.post.security_invariants_enabled == symbols.value_bool,
            *_frame(symbols, exclude={"security_invariants_enabled"}),
        )


def dataflow_contract_registry() -> ContractRegistry[DataFlowState]:
    return ContractRegistry(
        (
            SwitchZoneContract(),
            ReadResourceContract(),
            SanitizeContract(),
            SendContract(),
            OpenChannelContract(),
            ClearTaintContract(),
            ModifyDataPolicyContract(),
        )
    )
