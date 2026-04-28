# Agent Reproduction Guide

This file is for coding agents such as Codex or Claude Code that need to reproduce the packaged artifact with minimal ambiguity.

## Goal

Reproduce the appendix-facing benchmark path inside the `github/` directory:

1. optionally regenerate the English dataset,
2. run the benchmark over `abac`, `llm_judge`, and `z3_epca`,
3. generate the Markdown report.

Do not assume any files outside `github/` are part of the reproduction path.

## Working Rules

- Run commands from the `github/` directory.
- Prefer the packaged English dataset and packaged reports unless the user explicitly asks to regenerate them.
- Do not delete packaged artifacts unless the user asks.
- Treat `exp/` as the primary benchmark path and `case/` as a secondary demo.
- The benchmark depends on the root-level symbolic modules:
  `ast_nodes.py`, `lexer.py`, `parser.py`, `smt_compiler.py`.

## Environment

Expected Python: `3.11` or `3.12`.

Install dependencies:

```bash
pip install -r requirements.txt
```

Required environment variables for live model execution:

```bash
export OPENAI_API_KEY=...
export OPENAI_BASE_URL=...
```

`OPENAI_BASE_URL` must point to an OpenAI-compatible chat endpoint root.

## Minimal Command Sequence

### 1. Optional dataset regeneration

Skip this if `exp/benchmark_dataset_en.jsonl` already exists and the user only wants to run or inspect the packaged artifact.

```bash
python generate_micro_bench.py --language en-US --output exp/benchmark_dataset_en.jsonl --per-category 30 --overwrite
```

### 2. Optional preflight

Use this when the endpoint or model availability is uncertain.

```bash
python exp/preflight_benchmark.py --dataset exp/benchmark_dataset_en.jsonl --output /tmp/preflight_results_en.json --guardrails abac,llm_judge,z3_epca
```

The preflight writes a summary JSON. It is a smoke test, not the main artifact.

### 3. Benchmark execution

```bash
python run_benchmark.py --dataset exp/benchmark_dataset_en.jsonl --output exp/res/eval_results_en.jsonl --guardrails abac,llm_judge,z3_epca --overwrite --concurrency 3 --timeout-seconds 12
```

Notes:

- `concurrency 3` is the intended conservative setting.
- The run is API-bound and may take substantial time.
- `llm_judge` is the slowest path.

### 4. Report generation

```bash
python analyze_benchmark.py --input exp/res/eval_results_en.jsonl --output exp/res/benchmark_report_en.md
```

## Expected Outputs

Main outputs:

- `exp/res/eval_results_en.jsonl`
- `exp/res/benchmark_report_en.md`

Also packaged:

- `exp/res/benchmark_report_en_detailed.md`

## Sanity Checks

After a successful benchmark run, the result file should:

- be JSONL,
- contain rows keyed by `(model, task_id, guardrail)`,
- cover three guardrails: `abac`, `llm_judge`, `z3_epca`,
- use benchmark categories `Attack_Split`, `Attack_Meta`, `Benign_Utility`.

After report generation, the Markdown report should summarize:

- attack blocking behavior,
- benign-task utility / false positives,
- latency differences across guardrails.

## Case Demo

The packaged case demo is independent from the benchmark path:

```bash
python case/run_case.py --max-turns 16
```

It writes trajectory logs into `case/logs/`.

## Failure Modes

- If imports fail around parsing or symbolic compilation, verify that execution is happening from `github/` and that the root-level modules are present.
- If benchmark calls fail immediately, check `OPENAI_API_KEY` and `OPENAI_BASE_URL`.
- If the endpoint is unstable, run the preflight first and keep concurrency low.
- If the user only needs artifact inspection, do not rerun expensive API-backed jobs unnecessarily; use the packaged dataset and reports.
