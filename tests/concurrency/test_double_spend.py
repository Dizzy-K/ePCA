from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from epca.environments.financial.environment import FinancialRuntime
from epca.runtime.decision import DecisionStatus
from tests.conftest import transfer_payload


def test_concurrent_tickets_from_same_version_cannot_both_commit() -> None:
    runtime = FinancialRuntime()
    runtime.create_session("concurrent")
    first = runtime.evaluate(
        transfer_payload(300),
        principal_id="agent",
        session_id="concurrent",
        monitor="epca",
    )
    second = runtime.evaluate(
        transfer_payload(300),
        principal_id="agent",
        session_id="concurrent",
        monitor="epca",
    )
    assert first.decision.status == second.decision.status == DecisionStatus.ALLOW
    assert first.snapshot.state_version == second.snapshot.state_version == 0

    barrier = Barrier(2)

    def execute(evaluated):
        barrier.wait()
        return runtime.execute(evaluated)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(execute, (first, second)))

    assert sum(result.commit_success for result in results) == 1
    assert sorted(result.reason for result in results) == ["committed", "stale_state"]
    final = runtime.snapshot("concurrent").state
    assert final.cumulative_outflow == 300
    assert final.state_version == 1
    assert final.cumulative_outflow <= final.daily_limit
