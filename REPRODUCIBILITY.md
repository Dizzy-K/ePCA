# Reproducing the manuscript's existing results

## Offline counts and tables (no dependencies beyond Python)

```bash
python scripts/verify_release.py
python scripts/reproduce_paper.py --output-dir build/reproduction
```

`build/reproduction/summary.json` and `README.md` report the main counts. The
`reports/` and `paper_tables/` subdirectories contain regenerated deterministic and
valid-certificate PCC tables. Historical module/file names are retained.

For a detailed breakdown of certificate fields, semantic tuples, and the recorded
dataflow case, Node.js 18+ can also run this dependency-free analysis:

```bash
node scripts/analyze_existing.mjs
```

It writes only under `build/reproduction/evidence/`.

## Result-to-file map

| Paper content | Archived inputs |
| --- | --- |
| Deterministic evaluation | `benchmarks/tdsc_v2/traces.jsonl`, `results/phase2_v2/raw_results.jsonl` |
| Adaptive outcomes | `results/phase4_v2_canonical3/adaptive_raw.jsonl` |
| Model-generated certificates | `results/phase4_v2_pcc_canonical/pcc_llm_raw.jsonl`; include only `gpt-5.5` and `deepseek-v4-pro` |
| Certificate consistency and local costs | `results/phase3_v2/pcc_*.jsonl` |
| Same-state/action agreement and PVMR | `reports/current/phase4_v2_policy_vs_oracle.csv`, matching localization report |
| Rule deletion | `results/supplemental_v2/mutation_testing.csv` |
| Named conflicts | `results/supplemental_v2/unsat_core_localization.csv` |
| Constraint-density timing | `results/supplemental_v2/policy_scaling.csv` |
| Earlier policy-completeness counterexample | `results/phase4/adaptive_raw.jsonl`, `reports/phase4_failure_localization.md` |
| Dataflow case | episode `deepseek-v4-pro::df-indirect-exfiltration::r1::ePCA` in the included adaptive file |

The certificate archive contains additional k3 calls that are excluded explicitly.
The earlier adaptive file is a separate historical cohort; do not combine it with
the main cumulative-approval cohort.

## Optional replay of already-recorded pairs

After installing `requirements.txt`, this re-evaluates existing pairs without
contacting any model:

```bash
PYTHONPATH=. python -m phase4.failure_localization \
  --raw results/phase4_v2_canonical3/adaptive_raw.jsonl \
  --report build/replay/localization.md \
  --report-zh build/replay/localization_zh.md \
  --csv build/replay/policy_vs_oracle.csv
```

This is software replay, distinct from pure aggregation and from new adaptive
episodes. The release's standard offline command reads the archived pair results.

## Optional new deterministic runs

The following executes the existing environments and writes fresh measurements;
it is not necessary to reproduce counts from the archives:

```bash
PYTHONPATH=. python -m benchmark.runner --traces benchmarks/tdsc_v2/traces.jsonl --output results/local_deterministic/raw_results.jsonl
PYTHONPATH=. python -m phase3.experiment --traces benchmarks/tdsc_v2/traces.jsonl --output-dir results/local_pcc
PYTHONPATH=. python -m phase5.experiment --traces benchmarks/tdsc_v2/traces.jsonl --output-dir results/local_omissions --report-dir build/local_omissions
```

## Optional remote experiments (API charges)

`configs/phase4_models_v2.json` preserves historical model and endpoint settings.
Its local relay URL is not a public hosted service. Copy it to a git-ignored
`configs/local_models.json` and configure endpoints you are authorized to use.
Set credential environment variables outside the repository; never paste keys
into configuration files. The loader retains three actor definitions for
historical compatibility; `--model` selects the two manuscript actors.

```bash
PYTHONPATH=. python -m phase4.run adaptive \
  --config configs/local_models.json --traces benchmarks/tdsc_v2/traces.jsonl \
  --model gpt-5.5 --model deepseek-v4-pro \
  --guardrail RuntimeOnly --guardrail StatelessRuleFilter \
  --guardrail StatefulRuleMonitor --guardrail ePCA \
  --results-dir results/local_remote
PYTHONPATH=. python -m phase4.run pcc \
  --config configs/local_models.json --traces benchmarks/tdsc_v2/traces.jsonl \
  --model gpt-5.5 --model deepseek-v4-pro --results-dir results/local_remote
```

These are future fresh runs, not a byte-exact recipe for historical remote
outputs. Provider availability, generation settings, and model behavior may
differ. Some archived calls used recovery settings: use fields in each raw record
for the actual settings, rather than assuming the baseline config applies to
every call. The historical attempts/retry census and timing host inventory are
incomplete. Current dependency pins describe the packaged software environment.

## Reading older design documents

The files under `docs/phase*_design.md` are historical implementation notes.
For the current included cohorts, statistics, and interpretation, use this guide,
the top-level README, and OPEN_SCIENCE.md. No manuscript appendix is required to
use the artifact.
