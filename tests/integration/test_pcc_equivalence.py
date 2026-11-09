from __future__ import annotations

from benchmark.generate import generate_traces
from benchmark.runner import PHASE3_CONDITIONS, run_benchmark


def test_pcc_and_epca_are_semantically_equivalent_on_frozen_600_traces() -> None:
    rows = run_benchmark(generate_traces(), conditions=PHASE3_CONDITIONS)
    assert len(rows) == 1800
    by_condition = {condition: {row["trace_id"]: row for row in rows if row["condition"] == condition} for condition in PHASE3_CONDITIONS}
    pcc, epca = by_condition["PCC-Action"], by_condition["ePCA"]
    assert all(
        [step["decision"] for step in pcc[trace_id]["steps"]]
        == [step["decision"] for step in epca[trace_id]["steps"]]
        for trace_id in pcc
    )
    assert all(
        (pcc[trace_id]["unsafe_effect_materialized"], pcc[trace_id]["benign_task_completed"])
        == (epca[trace_id]["unsafe_effect_materialized"], epca[trace_id]["benign_task_completed"])
        for trace_id in pcc
    )
