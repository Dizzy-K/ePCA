from __future__ import annotations

from epca.environments.financial.contracts import TransferContract
from epca.environments.financial.policies import default_financial_policy
from epca.environments.financial.state import FinancialState
from epca.runtime.hashing import canonical_json, sha256_digest


def test_canonical_hash_is_order_independent() -> None:
    left = {"b": 2, "a": {"y": 1, "x": True}}
    right = {"a": {"x": True, "y": 1}, "b": 2}
    assert canonical_json(left) == canonical_json(right)
    assert sha256_digest(left) == sha256_digest(right)


def test_state_policy_and_contract_have_stable_digests() -> None:
    state = FinancialState()
    policy = default_financial_policy()
    contract = TransferContract()
    assert state.digest == FinancialState().digest
    assert policy.policy_digest == default_financial_policy().policy_digest
    assert contract.contract_digest == TransferContract().contract_digest
    assert len(state.digest) == len(policy.policy_digest) == len(contract.contract_digest) == 64
