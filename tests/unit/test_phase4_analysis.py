import json

from phase4.analyze import _error_kind, pcc_model_summary, validation_report, wilson


def test_wilson_interval_contains_observed_rate() -> None:
    low, high = wilson(5, 10)
    assert low < 0.5 < high
    assert wilson(0, 0) == (0.0, 0.0)


def test_phase4_validation_report_marks_partial_matrix_incomplete(tmp_path) -> None:
    config_dir = tmp_path / "configs"
    benchmark_dir = tmp_path / "benchmarks/tdsc_v1"
    config_dir.mkdir(parents=True)
    benchmark_dir.mkdir(parents=True)
    (config_dir / "phase4_models.json").write_text(
        json.dumps(
            {
                "temperature": 0.01,
                "max_turns": 12,
                "repeats": 3,
                "concurrency": 1,
                "models": [{"model": "actor-a"}, {"model": "actor-b"}, {"model": "actor-c"}],
                "judge": {"model": "judge-a"},
            }
        ),
        encoding="utf-8",
    )
    (benchmark_dir / "traces.jsonl").write_text("{}\n", encoding="utf-8")

    report = validation_report([], [], tmp_path)

    assert "Machine-derived completion status: INCOMPLETE" in report
    assert "0/1350" in report
    assert "0/1080" in report
    assert _error_kind("HTTP 524 from relay") == "HTTP 524"
    assert _error_kind("empty_final_text:length=0") == "empty final text"


def test_pcc_summary_reports_availability_cost_and_certificate_size() -> None:
    rows = [
        {
            "model": "actor-a",
            "api_error": None,
            "safe_or_unsafe": "safe",
            "certificate_valid": True,
            "generation_latency": 10.0,
            "end_to_end_latency": 11.0,
            "certificate_size": 100,
            "token_usage": {"input": 20, "output": 30},
        },
        {
            "model": "actor-a",
            "api_error": None,
            "safe_or_unsafe": "safe",
            "certificate_valid": False,
            "generation_latency": 20.0,
            "end_to_end_latency": 21.0,
            "certificate_size": 200,
            "token_usage": {"input": 40, "output": 50},
        },
        {
            "model": "actor-a",
            "api_error": None,
            "safe_or_unsafe": "unsafe",
            "certificate_valid": False,
            "generation_latency": 30.0,
            "end_to_end_latency": 31.0,
            "certificate_size": 300,
            "token_usage": {"input": 60, "output": 70},
        },
    ]

    summary = pcc_model_summary(rows, "actor-a")

    assert summary["safe_valid_numerator"] == 1
    assert summary["safe_rejection_numerator"] == 1
    assert summary["unsafe_accept_numerator"] == 0
    assert summary["input_tokens_mean"] == 40.0
    assert summary["output_tokens_mean"] == 50.0
    assert summary["certificate_size_median_bytes"] == 200.0
