# Phase 1 Trusted Action Runtime Design

> Historical implementation note. For the 2026-11-09 manuscript's included
> datasets and reproduction entry points, see [REPRODUCIBILITY.md](../REPRODUCIBILITY.md).
> The earlier cohort sizes and configurations below are retained for provenance.

**Scope:** revised ePCA Phase 1, Financial Workflow only. This phase does not implement PCC, Cloud IAM, DevOps, remote-model experiments, or dataset/scalability work.

## Runtime flow

The only revised ePCA authorization and execution path is:

```text
untrusted payload
  -> SchemaValidator
  -> immutable ActionProposal
  -> trusted StateSnapshot
  -> registered deterministic ActionContract
  -> exact post-state derivation
  -> registered PolicySet / named invariant compilation
  -> exact-binding Z3 verification
  -> VerificationDecision
  -> authenticated immutable ExecutionTicket (ALLOW only)
  -> BoundExecutor
  -> atomic freshness check / simulated effect / state commit
```

`Attack_Split`, `Attack_Meta`, and benign inputs are compatibility labels only. They all enter the same path; neither the verifier nor the contracts branch on those labels.

## Trusted and untrusted boundary

The **untrusted reasoning plane** includes natural-language interpretation, an agent or model, legacy scenario labels and metadata, and all supplied proof-like fields (`z3_proof_code`, `proof`, `certificate`, and `safe`). It may propose a JSON action, but it cannot select state, contracts, policies, post-state, a decision, or an executable effect.

The **trusted enforcement plane** consists of the strict schema validator; canonical serialization and hashing; the versioned state store; registered contracts and policies; the exact-binding formal encoder and Z3 verifier; the per-runtime ticket authority; the `BoundExecutor`; and the Financial effect/commit implementation. The simulator process, Python runtime, Z3 package, Pydantic validation, hashing/HMAC primitives, and correct deployment of this code are part of the current TCB.

## Core objects and binding

- `ActionProposal` is a frozen Pydantic object containing the canonical action name, typed parameters, principal, and session. Canonical JSON is sorted and compact; SHA-256 supplies its digest.
- `FinancialState` is frozen and contains cumulative outflow, daily limit, privilege, the security-invariant flag, active policy version, and monotonic state version. Its complete canonical payload is hashed.
- Each `ActionContract` declares one action schema, a version, a semantic identifier, a digest, a deterministic Python transition, and the corresponding SMT transition constraints.
- `PolicySet` is immutable, versioned, hashed, and contains named invariants with both Python evaluators and SMT encodings.
- `VerificationContext` binds action, pre-state, exact derived post-state, policy, contract, session, principal, run, monitor, and a fresh decision ID.
- An `ExecutionTicket` contains the immutable action/pre-state/post-state/context and an HMAC over the complete canonical ticket payload. Only an ALLOW can receive a ticket.

At execution, `BoundExecutor` authenticates the ticket, rechecks every digest/version/identity binding, selects the registered contract rather than reading natural language, re-derives the post-state, checks exact equality, and commits only that state.

## Financial contract and invariant semantics

The canonical actions are:

- `transfer(amount, recipient)`: add the positive exact amount to `cumulative_outflow`.
- `modify_policy(target, value)`: change only `daily_limit` or the in-state security-invariant flag.
- `escalate_privilege(new_privilege)`: set the exact requested privilege.

All contracts increment `state_version` by exactly one and frame every unaffected field. Legacy `pay`, `modify_rule`, and related names are mapped by an adapter before strict validation.

The active Financial policy encodes:

- `I0_FINANCIAL_DOMAIN`: state-domain values remain valid.
- `I1_CUMULATIVE_OUTFLOW_WITHIN_LIMIT`: cumulative outflow does not exceed the daily limit.
- `I2_DAILY_LIMIT_MODIFICATION_REQUIRES_ADMIN`: changing the limit requires principal `admin` and pre-state privilege at least 10.
- `I3_SELF_ESCALATION_FORBIDDEN`: privilege escalation requires the same independent admin condition.
- `I4_SECURITY_INVARIANTS_IMMUTABLE`: the in-band action path cannot disable security invariants.

## Exact formal semantics

For trusted snapshot `s`, validated action `a`, active deterministic contract `C`, and active policy `P`, the runtime first computes one concrete `s' = C.transition(s, a)`. Z3 then receives conjunctions that bind every pre-state field to `s`, every action/identity field to `a`, every post-state field to `s'`, and active policy/contract versions to the selected registry entries. It also receives `C`'s transition relation and all applicable named invariants from `P`.

- `SAT` means that the one exact, fully bound transition is consistent with the registered contract and satisfies every encoded invariant. The independent Python invariant evaluation must agree before the result is ALLOW.
- `UNSAT` with a violated named policy invariant means the exact transition violates policy and is BLOCK. The tracked core and Python evaluator locate the invariant.
- `UNSAT` without a policy violation means a contract/binding inconsistency and is ERROR, not a safety block.
- `UNKNOWN`, encoding disagreement, or any verification exception is ERROR and produces no ticket.

This is a satisfiability check of a fully concrete transition, not an existential search in which the solver may invent a safe post-state.

## Freshness, atomicity, and concurrency

The state store provides an immutable snapshot and a per-session re-entrant lock. `BoundExecutor` uses a consistent lock order: configuration lock, then session-state lock. While holding them it checks the active policy/contract versions and digests, then checks that current state version/hash equal the ticket's pre-state. It performs the deterministic simulated effect and exact comparison before committing a post-state whose version is exactly current version plus one.

Therefore, two tickets verified at state version 0 may both be ALLOW, but only one can commit. After the first commit, the second observes a version/hash mismatch and is rejected as stale; re-evaluation would see the cumulative state and block if the limit would be exceeded.

## Answers required by the Phase 1 specification

1. **What is the trusted/untrusted boundary?** Agent reasoning, natural language, labels, metadata, and proof claims are untrusted. Validation, registered state/contracts/policies, exact encoding, verification, ticket authority, bound execution, and atomic commit are trusted.
2. **What defines an action contract?** A registered action/schema pair plus a versioned/digested semantic specification, deterministic concrete transition, and matching SMT transition constraints with frame conditions.
3. **Is natural-language-to-action translation part of the formal guarantee?** No. Phase 1 begins its guarantee only after a payload passes the typed schema boundary. Translation correctness is explicitly outside the theorem.
4. **Is model-generated proof used?** No. Compatibility fields are explicitly discarded before canonical action construction; they never enter the verifier, ticket, or executor.
5. **How is the exact action bound to verification?** The complete canonical action (including parameters, principal, and session) is SHA-256 hashed into the verification context and HMAC-authenticated ticket. The executor rechecks it and never reparses agent prose.
6. **How is state freshness guaranteed?** The ticket binds exact pre-state hash/version. The executor checks both against current state while holding the session lock; mismatches require rejection and re-verification.
7. **How is concurrent execution kept safe?** Per-session serialization plus exact version/hash comparison and a single lock-scoped check/effect/commit sequence permits at most one same-version ticket to commit.
8. **What do SAT and UNSAT mean precisely?** SAT means the exact derived transition satisfies all registered constraints and may receive a ticket. UNSAT caused by named policy invariants is BLOCK. UNSAT from binding/contract inconsistency, UNKNOWN, or disagreement is ERROR.
9. **Which engineering assumptions does the theorem depend on?** Correct deterministic contract and invariant implementations; equivalence of Python and SMT encodings; complete identification of security-relevant state/effects; collision resistance of SHA-256; HMAC key secrecy; correct Pydantic/Z3/Python behavior; all relevant actions being mediated by this runtime; and a single-process lock/state-store failure model.
10. **Which parts are simulator assumptions?** State and effects are in-memory, process-local, non-durable, and single-host; the HMAC key is ephemeral; principal strings are not backed by authentication; admin privilege is modeled as state; no external bank transaction exists; crash recovery and effect rollback are absent; and direct code-level bypass is prevented only by the experiment harness, not an OS or service boundary.

## Legacy separation and remaining scope

Existing `exp/`, `case/`, parser/compiler, datasets, and reports remain in place. Their historical execution semantics—including the legacy model-generated proof experiment—are not imported by `epca/`. Phase 1 deliberately supplies only a compatibility adapter for legacy Financial action names. Later phases must not treat the current simulator guarantees as claims about external systems without durable transactions, authenticated identities, complete mediation, and external-effect idempotency/rollback.
