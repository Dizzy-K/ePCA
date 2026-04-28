from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from exp.config import DEFAULT_BASE_URL, HARDCODED_API_KEY, env_api_key, env_base_url
from exp.run_benchmark import (
    DEFAULT_MODELS,
    DEFAULT_GUARDRAILS,
    BenchmarkRunner,
    DatasetRecord,
    prepare_output_path,
    split_csv,
    split_models_csv,
)


DEFAULT_DATASET_PATH = ROOT_DIR / "exp" / "benchmark_dataset_en.jsonl"
DEFAULT_OUTPUT_PATH = ROOT_DIR / "exp" / "res" / "preflight_results_en.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run parsing preflight before the full benchmark.")
    parser.add_argument("--dataset", type=str, default=str(DEFAULT_DATASET_PATH))
    parser.add_argument("--output", type=str, default=str(DEFAULT_OUTPUT_PATH))
    parser.add_argument("--models", type=str, default=",".join(DEFAULT_MODELS))
    parser.add_argument("--guardrails", type=str, default=",".join(DEFAULT_GUARDRAILS))
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--judge-temperature", type=float, default=0.0)
    parser.add_argument("--max-turns", type=int, default=5)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--retry-timeouts", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--api-key", type=str, default=env_api_key() or HARDCODED_API_KEY)
    parser.add_argument("--base-url", type=str, default=env_base_url() or DEFAULT_BASE_URL)
    return parser.parse_args()


def load_dataset(path: Path) -> list[DatasetRecord]:
    with path.open("r", encoding="utf-8") as handle:
        return [DatasetRecord.model_validate(json.loads(line)) for line in handle if line.strip()]


def select_smoke_tasks(dataset: list[DatasetRecord]) -> list[DatasetRecord]:
    selected: list[DatasetRecord] = []
    for category in ("Benign_Utility", "Attack_Split", "Attack_Meta"):
        for row in dataset:
            if row.category == category:
                selected.append(row)
                break
    if len(selected) != 3:
        raise ValueError("Preflight requires one sample from each benchmark category")
    return selected


async def run_preflight(args: argparse.Namespace) -> dict[str, Any]:
    dataset = select_smoke_tasks(load_dataset(Path(args.dataset).resolve()))
    runner = BenchmarkRunner(args)
    results: list[dict[str, Any]] = []

    combos = [
        (task, model, guardrail)
        for task in dataset
        for model in split_models_csv(args.models)
        for guardrail in split_csv(args.guardrails)
    ]
    semaphore = asyncio.Semaphore(args.concurrency)

    async def run_one(task: DatasetRecord, model: str, guardrail: str) -> dict[str, Any]:
        attempts = max(1, int(args.retry_timeouts) + 1)
        last_record: dict[str, Any] | None = None
        for _ in range(attempts):
            async with semaphore:
                record = await runner.run_combo(task, model, guardrail)
            last_record = record
            reason = str(record.get("block_reason", "")).lower()
            if "apitimeouterror" not in reason and "request timed out" not in reason:
                return record
        return last_record if last_record is not None else {}

    tasks = [asyncio.create_task(run_one(task, model, guardrail)) for task, model, guardrail in combos]
    for finished in asyncio.as_completed(tasks):
        results.append(await finished)

    by_model: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "checks": {},
        "passed": True,
        "fail_reasons": [],
    })
    for record in results:
        model_bucket = by_model[record["model"]]
        key = f'{record["task_category"]}:{record["guardrail"]}'
        model_bucket["checks"][key] = {
            "parse_ok": bool(record.get("parse_ok")),
            "actual_decision": record.get("actual_decision"),
            "block_reason": record.get("block_reason"),
        }

    for model, model_bucket in by_model.items():
        checks = model_bucket["checks"]
        required_parse_keys = [
            "Benign_Utility:abac",
            "Benign_Utility:z3_epca",
            "Attack_Split:abac",
            "Attack_Meta:abac",
        ]
        for key in required_parse_keys:
            if not checks.get(key, {}).get("parse_ok"):
                model_bucket["passed"] = False
                model_bucket["fail_reasons"].append(f"parse_failed:{key}")
        judge_keys = [
            "Benign_Utility:llm_judge",
            "Attack_Split:llm_judge",
            "Attack_Meta:llm_judge",
        ]
        for key in judge_keys:
            decision = str(checks.get(key, {}).get("actual_decision", ""))
            if decision == "ERROR":
                model_bucket["passed"] = False
                model_bucket["fail_reasons"].append(f"judge_error:{key}")

    passed_models = sorted(model for model, bucket in by_model.items() if bucket["passed"])
    return {
        "dataset": str(Path(args.dataset).resolve()),
        "models": split_models_csv(args.models),
        "guardrails": split_csv(args.guardrails),
        "selected_task_ids": [row.task_id for row in dataset],
        "passed_models": passed_models,
        "failed_models": {model: bucket["fail_reasons"] for model, bucket in sorted(by_model.items()) if not bucket["passed"]},
        "per_model": dict(sorted(by_model.items())),
        "records": sorted(results, key=lambda row: (row["model"], row["task_category"], row["guardrail"])),
    }


async def run_full_benchmark(args: argparse.Namespace) -> None:
    prepare_output_path(Path(args.output).resolve(), args.overwrite, args.resume)
    runner = BenchmarkRunner(args)
    await runner.run()


def main() -> None:
    args = parse_args()
    output_path = Path(args.output).resolve()
    if output_path.suffix == ".jsonl":
        asyncio.run(run_full_benchmark(args))
        print(json.dumps({
            "mode": "benchmark",
            "output": str(output_path),
        }, ensure_ascii=False, indent=2))
        return
    summary = asyncio.run(run_preflight(args))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({
        "passed_models": summary["passed_models"],
        "failed_models": summary["failed_models"],
        "output": str(output_path),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
