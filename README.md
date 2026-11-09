# Executable Proof-Constrained Actions (ePCA)

Research artifact for **Executable Proof-Constrained Actions: Axiom-Bound Guardrails for LLM Agents**, aligned with the 2026-11-09 manuscript revision.

ePCA derives a concrete transition obligation from trusted state and a registered deterministic tool contract. Executable predicates and separately encoded SMT constraints check it; a bound executor connects authorization to the action, state, successor, and active configuration at commit. The prototype covers financial, dataflow, and cloud-IAM simulators.

## Reproduce reported numbers offline

With Python 3.11 or 3.12, the following uses only the standard library, reads archived results, and makes **no model/API calls**:

```bash
python scripts/verify_release.py
python scripts/reproduce_paper.py --output-dir build/reproduction
```

It generates JSON/Markdown summaries, checks the main reported counts, and regenerates deterministic/PCC tables. It does not execute benchmark environments or recreate historical timing. See [REPRODUCIBILITY.md](REPRODUCIBILITY.md).

## Evidence in this release

| Evaluation | Archived evidence | Finding |
| --- | --- | --- |
| Deterministic | 640 traces: 500 adversarial, 140 benign | Full-policy stateful mechanisms agree on evaluated inputs |
| Adaptive | 720 complete API-valid episodes, two models, four guardrails | ePCA and StatefulRuleMonitor each have UEMR 0/108 and BTCR 72/72 |
| Fixed-action certificates | 180 safe and 180 unsafe calls per model | Safe acceptance: GPT-5.5 PCC 148/180; DeepSeek-v4-pro PCC 144/180; ePCA 180/180 each |
| Same-state/action comparison | 863 unique pairs, 3,966 occurrences | Zero StatefulRuleMonitor/ePCA disagreements |
| Rule omissions | 10 of 23 rules have sole-violation witnesses | A retained check blocks tested one-sided omissions; common-mode deletions can admit violations |

Certificate calls reduce to **eight safe and eleven unsafe semantic tuples** after removing session identifiers. Calls are repeated instances, not independent semantic tasks. The certificate archive also contains k3 records, explicitly excluded from the current two-model manuscript.

StatefulRuleMonitor is the ideal complete implementation of the **specified policy**, under accurate state and contracts. The preservation result concerns encoded invariants under trusted-runtime and faithful-encoding assumptions. Sanitization is a trusted resource-specific state effect in the simulator. See [OPEN_SCIENCE.md](OPEN_SCIENCE.md).

## Local tests

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt
PYTHONPATH=. .venv/bin/python -m pytest -q
```

Tests use deterministic local runtimes and mocked model clients; no API key is required. Release validation is separate from archived research measurements.

## Repository map

- `epca/`: typed actions, contracts, policies, SMT verifier, and bound executor.
- `evaluation/oracles/`: independent reference transitions and outcome checks.
- `pcc/`: structured action certificates, producer, and independent checker.
- `benchmark/`, `phase3/`, `phase4/`, `phase5/`: benchmark and analysis code.
- `benchmarks/tdsc_v2/`: the paper's 640-trace cumulative-approval dataset.
- `results/phase2_v2/`, `results/phase3_v2/`: deterministic comparisons.
- `results/phase4_v2_canonical3/`: included 720-episode adaptive cohort.
- `results/phase4_v2_pcc_canonical/`: model-certificate archive.
- `results/supplemental_v2/`: existing omission, localization, and cost records. The historical name does not imply a manuscript supplement.
- `reports/current/`: archived same-state/action analysis.
- `results/phase4/`, `reports/phase4_failure_localization*`: earlier policy-gap cohort, kept separate.
- `release_manifest.json`: hashes and sizes for the published files.

Directory names containing v1/v2 are historical dataset/policy identifiers, not alternative manuscript contributions.

## Optional fresh runs and legacy artifact

Fresh remote experiments require credentials and incur API costs. They are not part of the offline reproduction above. Historical configuration files contain endpoint settings and credential environment-variable names, not keys. See [REPRODUCIBILITY.md](REPRODUCIBILITY.md) before a live run.

`exp/`, `case/`, and the root parser/compiler and benchmark wrappers are the earlier artifact. They are preserved, but their original results are not the current paper's main evaluation. Manuscript PDFs, private reviews, API recovery logs, and local credentials are not included in this update.
