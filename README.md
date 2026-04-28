# proof_safe_agent Artifact

This artifact packages the core idea behind `proof_safe_agent`: do not trust an LLM's surface-level alignment signal as the final safety decision. Instead, force the model to emit structured actions, bind those actions to an explicit semantic state, and let a small symbolic verifier decide whether the action is admissible.

## Core Idea

The artifact compares three guardrail styles over the same budget-disbursement benchmark:

- `abac`: direct rule checks over a small hand-written policy surface.
- `llm_judge`: ask another model to decide whether the action is safe.
- `z3_epca`: compile the intended policy into symbolic constraints, bind runtime fields to typed variables, and verify the action with Z3.

The point is not that symbolic methods replace language models. The point is that the final authorization step should sit in a narrow, inspectable, deterministic trusted computing base. The LLM can still plan, translate, and propose actions, but the permission boundary is enforced by semantics rather than by prompt wording alone.

## Why This Matters

Prompt-level refusals and natural-language judges are both brittle in different ways:

- A model may refuse a benign action for irrelevant alignment reasons.
- A model may approve a harmful action after being steered through a multi-turn policy rewrite or role reframing.
- A naive rule checker may miss invariant violations that only become obvious after the action is bound to the full runtime state.

The `z3_epca` path is designed to close that gap. It makes the action explicit, binds JSON fields to a typed symbolic world, and produces either `sat` or `unsat` with an inspectable unsat core.

## Repository Layout

- `exp/`: the benchmark pipeline. This is the main artifact path used by the appendix.
- `case/`: a packaged enterprise network exfiltration case study showing the same "LLM proposes, verifier decides" pattern in a different setting.
- `ast_nodes.py`, `lexer.py`, `parser.py`, `smt_compiler.py`: the semantic frontend and symbolic compiler used by the benchmark verifier.

## What Is Packaged

- Dataset: [exp/benchmark_dataset_en.jsonl](/data/dizzylong/work/proof_safe_agent/github/exp/benchmark_dataset_en.jsonl)
- Main benchmark results: [exp/res/eval_results_en.jsonl](/data/dizzylong/work/proof_safe_agent/github/exp/res/eval_results_en.jsonl)
- Paper-style reports:
  [exp/res/benchmark_report_en.md](/data/dizzylong/work/proof_safe_agent/github/exp/res/benchmark_report_en.md)
  [exp/res/benchmark_report_en_detailed.md](/data/dizzylong/work/proof_safe_agent/github/exp/res/benchmark_report_en_detailed.md)
- Case trajectory log:
  [case/logs/apt_trajectory_20260331T071314.130993Z.log](/data/dizzylong/work/proof_safe_agent/github/case/logs/apt_trajectory_20260331T071314.130993Z.log)

## Minimal Reproduction

Install dependencies:

```bash
pip install -r requirements.txt
```

Set an OpenAI-compatible endpoint:

```bash
export OPENAI_API_KEY=...
export OPENAI_BASE_URL=...
```

Regenerate the English dataset if needed:

```bash
python generate_micro_bench.py --language en-US --output exp/benchmark_dataset_en.jsonl --per-category 30 --overwrite
```

Run the benchmark:

```bash
python run_benchmark.py --dataset exp/benchmark_dataset_en.jsonl --output exp/res/eval_results_en.jsonl --guardrails abac,llm_judge,z3_epca --overwrite --concurrency 3 --timeout-seconds 12
```

Generate the summary report:

```bash
python analyze_benchmark.py --input exp/res/eval_results_en.jsonl --output exp/res/benchmark_report_en.md
```

If you only want to inspect the artifact, the packaged dataset and reports are already included, so no live API run is required.

## Case Study

The packaged `case/` directory is a smaller interactive demonstration of the same design philosophy. An LLM tries to achieve a network exfiltration goal by calling tools, but every action is checked by a formal guardrail before execution.

Run it with:

```bash
python case/run_case.py --max-turns 16
```

## For Agentic Runners

If you want a Codex- or Claude Code-oriented execution guide, use [Agent.md](/data/dizzylong/work/proof_safe_agent/github/Agent.md).
