# Phase 3 PCC-Action Design

> Historical implementation note. For the 2026-11-09 manuscript's included
> datasets and reproduction entry points, see [REPRODUCIBILITY.md](../REPRODUCIBILITY.md).
> The earlier cohort sizes and configurations below are retained for provenance.

## Experimental scope

Phase 3 implements a minimal PCC-style action-certification baseline for a paper comparison, not a production security protocol or full classical Proof-Carrying Code. It uses the frozen TDSC Benchmark v1 unchanged and makes no remote or LLM call.

The three deterministic enforcement architectures are:

```text
StatefulRuleMonitor: typed action + current state -> handwritten concrete predicates

PCC-Action: typed action + current state + contract + policy identity
            -> external deterministic producer -> certificate
            -> independent trusted concrete checker -> bound execution

ePCA: typed action + current state + registered policy/contract
      -> trusted exact-transition SMT compilation + Z3 -> bound execution
```

They share action schemas, initial state, environment semantics, contracts, executor, frozen traces, and semantic policy intent. No condition contains scenario-specific branches.

## Certificate format

`ActionCertificate` contains the complete canonical action and digest; complete pre-state and hash/version; claimed post-state and digest; policy and contract versions/digests; session and principal; named instantiated obligations with concrete hash witnesses; and a producer identifier. Its canonical JSON byte size is recorded.

There is intentionally no certificate signature, certificate chain, authentication system, replay database, persistence, or remote producer protocol. Integrity at the experiment boundary comes from the checker recomputing every security-relevant fact, not trusting a producer assertion.

## Producer boundary

`DeterministicCertificateProducer` is logically outside the trusted checker, although the local experiment invokes it in-process to eliminate network noise. It uses the registered deterministic contract to propose a post-state and a separately coded concrete obligation evaluator to instantiate evidence. It supports normal, invalid, and missing output modes.

The producer is not trusted: changing `claimed_satisfied`, witness hashes, the claimed post-state, action/state binding, obligation set, or policy/contract identity causes checker rejection. A missing certificate also fails closed.

## Trusted concrete checker

`ConcreteCertificateChecker` performs these checks in order:

1. certificate exists and names the current environment;
2. canonical action/digest, principal, and session match exactly;
3. pre-state canonical payload, hash, and version match the current snapshot;
4. active policy and contract version/digests match;
5. the checker independently calls the registered deterministic contract transition and compares the exact claimed post-state/hash;
6. it independently evaluates the finite environment obligations and requires the complete named set, claims, and concrete witnesses to agree;
7. every safety obligation is true.

The checker does not import or call `EPCAVerifier`, Z3, guardrails, or a `PolicySet` evaluator. It accepts the policy object only to bind its frozen identity. The concrete obligation implementation is independent of the ePCA SMT policy and StatefulRuleMonitor predicates. This limited duplication is intentional for the architectural comparison and is covered by differential/cross-condition tests.

After acceptance, the existing Phase 1 `DecisionIssuer` creates the same exact-action execution ticket used by other conditions. `BoundExecutor` still rejects a stale execution. HMAC remains only the prototype ticket mechanism; it is not a Phase 3 contribution.

## Freshness semantics

An old certificate cannot be applied to a mutated action because its canonical payload/digest and witness disagree. It cannot be applied after state mutation because the pre-state payload/hash/version disagree. Regeneration builds evidence for the latest snapshot. ePCA instead reruns trusted compilation/solving on the latest snapshot. The state-change experiment applies the same deterministic change schedule at 0%, 10%, 25%, and 50% probabilities.

## Claim and implementation limitations

The result supports only semantic equivalence for the frozen finite contracts/policies. The PCC checker is environment-specific concrete code, not a general proof calculus. Its correctness and semantic correspondence are engineering assumptions. The producer/checker run in one Python process; producer availability modes are deterministic injections, not network-failure simulations. Timings are Python microbenchmarks, not production latency. There is no signature, authentication, persistent replay defense, crash recovery, distributed transaction, side-channel analysis, TCB-size proof, certificate fuzzing, real API, LLM proof production, or external-effect atomicity.
