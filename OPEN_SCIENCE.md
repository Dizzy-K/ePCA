# Open Science

This packaged artifact corresponds to the `proof_safe_agent` pipeline. The recommended reproduction path is:

- `exp/generate_micro_bench.py`
- `exp/preflight_benchmark.py`
- `exp/run_benchmark.py`
- `exp/analyze_benchmark.py`

The benchmark evaluates three guardrails, `abac`, `llm_judge`, and `z3_epca`, over three task families, `Attack_Split`, `Attack_Meta`, and `Benign_Utility`.

## Hardware

- A modern x86_64 Linux server is sufficient.
- The benchmark path does not require local GPU inference because the evaluated frontier models are accessed through an OpenAI-compatible API.
- Stable network access to the configured model endpoint is the key runtime dependency.

## Software

- Python 3.11
- `z3-solver==4.16.0.0`
- `langchain-openai==1.1.11`
- `langchain-core==1.2.19`
- `pydantic==2.12.5`
- `openai==2.28.0`

Install with:

```bash
pip install -r requirements.txt
```

Or with:

```bash
uv sync
```

The runtime expects OpenAI-compatible credentials and endpoint settings configured through:

```bash
export OPENAI_API_KEY=...
export OPENAI_BASE_URL=...
```

## Dataset

- `exp/benchmark_dataset_en.jsonl`
- 90 total tasks
- 30 `Attack_Split`
- 30 `Attack_Meta`
- 30 `Benign_Utility`

## Workflow

### Case Demo

```bash
python case/run_case.py --max-turns 16
```

The live case runner uses the bundled API defaults unless you override them through environment variables.

### Full Reproduction

```bash
python generate_micro_bench.py \
  --language en-US \
  --output exp/benchmark_dataset_en.jsonl \
  --per-category 30 \
  --overwrite

python exp/preflight_benchmark.py \
  --dataset exp/benchmark_dataset_en.jsonl \
  --output exp/res/preflight_results_en.json \
  --models Qwen3-max,Gemini-3-flash-preview,Kimi-k2.5,GPT-5.4-2026-03-05 \
  --guardrails abac,z3_epca,llm_judge

python exp/preflight_benchmark.py \
  --dataset exp/benchmark_dataset_en.jsonl \
  --output exp/res/eval_results_en.jsonl \
  --models Qwen3-max,Gemini-3-flash-preview,Kimi-k2.5,GPT-5.4-2026-03-05 \
  --guardrails abac,z3_epca,llm_judge \
  --overwrite \
  --concurrency 3 \
  --timeout-seconds 12

python exp/analyze_benchmark.py \
  --input exp/res/eval_results_en.jsonl \
  --output exp/res/benchmark_report_en.md
```
