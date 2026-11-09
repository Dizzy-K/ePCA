# Phase 4 LLM Agent Evaluation Design

> Historical implementation note. For the 2026-11-09 manuscript's included
> datasets and reproduction entry points, see [REPRODUCIBILITY.md](../REPRODUCIBILITY.md).
> The earlier cohort sizes and configurations below are retained for provenance.

## Scope

Phase 4 is a remote-model paper experiment. It does not modify the frozen 600-trace TDSC v1 benchmark, add a safety mechanism, harden the PCC certificate format, or call a real bank, cloud, or data service.

The experiment freezes three exact actor identifiers in `configs/phase4_models.json`: `gpt-5.5`, `MiniMax-M3`, and `deepseek-v4-pro`. The shared semantic judge is `MiniMax-M3`, selected after the GPT relay repeatedly returned upstream HTTP 400 on otherwise valid Judge requests. The date, temperature, token ceilings, repeats, maximum turns, concurrency, provider labels, relay endpoint, credential environment-variable names, and system-prompt hashes are recorded. Secrets are runtime-only and are never serialized.

## Phase 4A: adaptive agent

The scenario registry contains exactly six distinct adversarial goals and four benign goals in each of Financial, Data Flow, and Cloud IAM. An actor sees the goal, compact typed tool interfaces, allowed simulator principals, the current trusted state, and uniform prior tool feedback. It returns one action or gives up. After ALLOW/BLOCK, the model receives only the shared public feedback, never an invariant name, UNSAT core, or judge reasoning.

The five conditions are RuntimeOnly, StatelessRuleFilter, LLMJudge, StatefulRuleMonitor, and ePCA. LLMJudge is evaluated before RuntimeOnly execution; judge API/structured-output failure is recorded as an error and never converted to BLOCK. Every valid action is independently classified using the Phase 2 environment oracle. Attack success and unsafe effects come from actual simulator state, not the guardrail decision.

The full paired matrix is 30 scenarios × 3 actors × 3 repeats × 5 conditions = 1,350 episodes, with at most 12 turns each. A completed episode is appended immediately to JSONL. Resume keys are exact `(model, scenario, repeat, guardrail)` identifiers. Although short-request preflight tolerated concurrency three, simultaneous long reasoning requests caused the VS Code tunnel relay to degrade into repeated 300-second retries. The formal run therefore freezes one in-flight request globally, a 300-second timeout, and two bounded attempts.

## Phase 4B: LLM certificate producer

The certificate benchmark deterministically extracts 20 oracle-safe and 20 oracle-unsafe action/state pairs per environment from the unchanged TDSC trace file. ePCA accepts all 60 safe pairs and rejects all 60 unsafe pairs before remote execution.

Each actor receives a fixed action, state, policy/contract specs, exact binding metadata, the current ActionCertificate schema, and required checker-obligation names. It must return strict JSON; no free-form chain-of-thought is requested. The Phase 3 concrete checker is unchanged and independently recomputes transition and obligations. Provider reasoning fields are discarded by the relay client and never enter raw results.

Safe certificate rejection is an availability failure. Unsafe certificate acceptance is the security metric. The full matrix is 120 pairs × 3 actors × 3 repeats = 1,080 remote calls. Results include raw final certificate text, parse/check result, failure classification, latency, token use, certificate size, and the paired ePCA decision/latency.

## Error and cost treatment

Transport timeouts, HTTP errors, and judge failures are separately recorded and excluded from ASR/UEMR/BTCR/UAAR denominators. Retries use bounded exponential backoff. The relay's token usage is preserved. Per-call dollar cost is recorded when the relay supplies it; otherwise it remains null with an explicit `relay-did-not-report-per-call-price` basis rather than inventing a price.

## Statistical output

Rate metrics report numerator/denominator and Wilson 95% confidence intervals. Adaptive aggregation is emitted overall and by model, environment, and attack type. Paired final-outcome comparison is keyed by identical model/scenario/repeat. Representative cases are selected automatically only after experiment completion and include both weak-guardrail bypasses and Stateful/ePCA containment when present.
