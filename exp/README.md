# exp

Benchmark pipeline for the proof safe agent artifact.

## Pipeline

The recommended reproduction path is:

- `exp/generate_micro_bench.py`
- `exp/preflight_benchmark.py`
- `exp/run_benchmark.py`
- `exp/analyze_benchmark.py`

The benchmark evaluates three guardrails:

- `abac`
- `llm_judge`
- `z3_epca`

and three task families:

- `Attack_Split`
- `Attack_Meta`
- `Benign_Utility`

## Dataset

- `exp/benchmark_dataset_en.jsonl`

The packaged artifact keeps only the English dataset because that is the appendix reproduction target.

The runtime expects `OPENAI_API_KEY` and `OPENAI_BASE_URL` to be configured for the live API-backed reproduction path.

Dependencies can be installed with either `pip install -r requirements.txt` from the repo root or `uv sync`.

## Run

Generate the dataset:

```bash
python generate_micro_bench.py \
  --language en-US \
  --output exp/benchmark_dataset_en.jsonl \
  --per-category 30 \
  --overwrite
```

Run preflight:

```bash
python exp/preflight_benchmark.py \
  --dataset exp/benchmark_dataset_en.jsonl \
  --output exp/res/preflight_results_en.json \
  --models Qwen3-max,Gemini-3-flash-preview,Kimi-k2.5,GPT-5.4-2026-03-05 \
  --guardrails abac,z3_epca,llm_judge
```

Run the benchmark:

```bash
python exp/preflight_benchmark.py \
  --dataset exp/benchmark_dataset_en.jsonl \
  --output exp/res/eval_results_en.jsonl \
  --models Qwen3-max,Gemini-3-flash-preview,Kimi-k2.5,GPT-5.4-2026-03-05 \
  --guardrails abac,z3_epca,llm_judge \
  --overwrite \
  --concurrency 3 \
  --timeout-seconds 12
```

Analyze results:

```bash
python exp/analyze_benchmark.py \
  --input exp/res/eval_results_en.jsonl \
  --output exp/res/benchmark_report_en.md
```

## Included packaged results

- `exp/res/eval_results_en.jsonl`
- `exp/res/benchmark_report_en.md`
- `exp/res/benchmark_report_en_detailed.md`
