from __future__ import annotations

import argparse
from pathlib import Path

from phase4.adaptive import GUARDRAILS, run_adaptive
from phase4.config import load_config
from phase4.model_client import RemoteModelClient
from phase4.pcc_llm import run_pcc_llm
from phase4.scenarios import SCENARIOS


def main() -> None:
    parser = argparse.ArgumentParser(description="Run resumable Phase 4 remote LLM experiments")
    parser.add_argument("mode", choices=("adaptive", "pcc", "all"))
    parser.add_argument("--config", type=Path, default=Path("configs/phase4_models.json"))
    parser.add_argument("--results-dir", type=Path, default=Path("results/phase4"))
    parser.add_argument("--traces", type=Path, default=Path("benchmarks/tdsc_v1/traces.jsonl"))
    parser.add_argument("--model", action="append", help="Exact configured model identifier; repeat to select multiple")
    parser.add_argument("--scenario", action="append", help="Scenario id; repeat to select multiple")
    parser.add_argument("--guardrail", action="append", choices=tuple(GUARDRAILS))
    parser.add_argument("--repeat", action="append", type=int)
    parser.add_argument("--retry-errors", action="store_true", help="Re-run completed episodes whose previous row contains an API error")
    args = parser.parse_args()
    config = load_config(args.config)
    models = tuple(item for item in config.models if not args.model or item.model in args.model)
    if args.model and len(models) != len(set(args.model)):
        raise SystemExit("every --model must match an exact configured identifier")
    scenarios = tuple(item for item in SCENARIOS if not args.scenario or item.scenario_id in args.scenario)
    if args.scenario and len(scenarios) != len(set(args.scenario)):
        raise SystemExit("every --scenario must match a frozen scenario id")
    repeats = tuple(args.repeat or range(1, config.repeats + 1))
    client = RemoteModelClient(timeout_seconds=config.timeout_seconds, max_retries=config.max_retries)
    if args.mode in {"adaptive", "all"}:
        written, skipped = run_adaptive(
            config=config,
            output=args.results_dir / "adaptive_raw.jsonl",
            client=client,
            scenarios=scenarios,
            models=models,
            guardrails=tuple(args.guardrail or GUARDRAILS),
            repeats=repeats,
            retry_errors=args.retry_errors,
        )
        print(f"adaptive: wrote {written}, resumed/skipped {skipped}")
    if args.mode in {"pcc", "all"}:
        written, skipped = run_pcc_llm(
            config=config,
            traces_path=args.traces,
            output=args.results_dir / "pcc_llm_raw.jsonl",
            client=client,
            models=models,
            repeats=repeats,
            retry_errors=args.retry_errors,
        )
        print(f"pcc: wrote {written}, resumed/skipped {skipped}")


if __name__ == "__main__":
    main()
