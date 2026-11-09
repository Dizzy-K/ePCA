# Open science and evidence scope

This release aligns code and existing evidence with the 2026-11-09 manuscript. Publishing the artifact adds no research runs. Local tests and offline aggregation are release checks, not additional experimental observations.

## Available evidence

Included: runtime/policy/oracle source, tests, benchmark inputs, recorded results, and offline reproduction commands. `release_manifest.json` identifies the published bytes. The corresponding English manuscript PDF has SHA-256 `606aee125c5db67aad7329269e0ed1a79af104137cd34d5d66dc3d6e1be3463e`; the PDF is not included in this update.

The adaptive analysis uses 720 included, complete API-valid records, not a full census of all historical attempts, failures, or retries. The certificate archive has 1,080 records; the manuscript uses 720 from GPT-5.5 and DeepSeek-v4-pro and excludes 360 k3 records. Eight safe and eleven unsafe semantic tuples underlie the repeated calls.

The earlier policy-gap cohort remains unchanged in `results/phase4/`. Its ePCA 2/107 and StatefulRuleMonitor 1/105 oracle-unsafe outcomes have zero encoded-policy violations. It is not pooled with the cumulative-approval cohort. Historical raw timestamps and model identifiers are retained as recorded.

## Interpretation

- The theorem concerns encoded-policy preservation under trusted-state, contract, runtime, and encoding assumptions.
- An intact StatefulRuleMonitor implements the same policy as an ideal reference. The certificate study concerns inconsistent model-generated evidence in a structured task, not classical PCC in general.
- Deletion witnesses cover 10 of 23 rules. Both representations share state and contracts; common-mode omissions remain a failure mode. The study does not estimate real-world defect frequencies.
- Simulated sanitization records a trusted resource effect; it is not an evaluated text-redaction system or real external-service deployment.
- Timing values are archived measurements. The original host/dependency inventory is incomplete; installing the listed dependencies does not recreate that host.
- Bounded episodes and fixed templates do not establish unrestricted attack coverage or deployment zero risk.

## Reproduction layers

1. Archived-result reproduction: standard-library analysis, no network or environment execution.
2. Software validation: local tests and optional recorded-pair replay, no remote model calls.
3. Fresh experiments: explicit optional commands, new output directories, and user-supplied credentials; outside this release check.

Do not commit credentials, private keys, local tunnel configuration, or .env files. The legacy API artifact is separate from the current reproduction entry point.
