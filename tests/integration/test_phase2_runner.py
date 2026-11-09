from __future__ import annotations

from collections import defaultdict

from benchmark.generate import generate_traces
from benchmark.runner import CONDITIONS, run_benchmark


def test_full_600_trace_paired_runner_smoke_and_environment_isolation() -> None:
    results = run_benchmark(generate_traces())
    assert len(results) == 600 * 4
    grouped = defaultdict(list)
    for row in results:
        grouped[row["trace_id"]].append(row)
    assert all({row["condition"] for row in rows} == set(CONDITIONS) for rows in grouped.values())
    assert all(len({row["initial_state_hash"] for row in rows}) == 1 for rows in grouped.values())
    assert sum(row["decision_errors"] for row in results) == 0
    assert sum(row["state_corruption_events"] for row in results) == 0

    stateful = {row["trace_id"]: row for row in results if row["condition"] == "StatefulRuleMonitor"}
    epca = {row["trace_id"]: row for row in results if row["condition"] == "ePCA"}
    assert all(
        (
            stateful[key]["unsafe_effect_materialized"],
            stateful[key]["benign_task_completed"],
            stateful[key]["unsafe_actions_accepted"],
        )
        == (
            epca[key]["unsafe_effect_materialized"],
            epca[key]["benign_task_completed"],
            epca[key]["unsafe_actions_accepted"],
        )
        for key in stateful
    )
