from __future__ import annotations

import pytest

from epca.environments.financial.environment import FinancialRuntime


@pytest.fixture
def runtime() -> FinancialRuntime:
    instance = FinancialRuntime()
    instance.create_session("session-1")
    return instance


def transfer_payload(amount: object = 300, recipient: object = "account_B") -> dict[str, object]:
    return {
        "action": "transfer",
        "params": {"amount": amount, "recipient": recipient},
    }
