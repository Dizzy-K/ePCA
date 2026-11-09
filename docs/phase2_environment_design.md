# Phase 2 Environment Design

> Historical implementation note. For the 2026-11-09 manuscript's included
> datasets and reproduction entry points, see [REPRODUCIBILITY.md](../REPRODUCIBILITY.md).
> The earlier cohort sizes and configurations below are retained for provenance.

## Scope and shared runtime

Phase 2 keeps the Phase 1 integrity model: every environment converts a finite registered JSON schema into the same frozen `ActionProposal`, snapshots immutable versioned state, derives one exact post-state through a registered deterministic `ActionContract`, evaluates a registered policy, and sends only an authenticated exact-action ticket to the same `BoundExecutor` pattern. The environment-specific simulator effect is executed and committed under the existing configuration/session locks.

The Phase 1 action class required one additive extensibility correction: its hard-coded three-action union was replaced by an explicit per-environment schema registry. Canonical fields, digesting, ticket binding, state freshness, and executor semantics did not change. The rationale and regression impact are recorded in `docs/phase2_change_log.md`. The `phase1-final` tag remains at `cb13ad14dd1f9822eefd686c8375d237e6da020d`.

HMAC is only this prototype's ticket-integrity mechanism. The research property is that the verification decision is integrity-bound to the exact action, state, policy, and contract consumed by the executor. Likewise, the lock supplies **monitor-state atomicity** inside one process; it does not make an external bank, file system, or cloud API transaction atomic.

## Financial Workflow

State contains cumulative outflow, daily and approval limits, privilege, pending request/requester, approved amount/approver, delegated limit/target, invariant flag, policy version, and state version. Canonical actions are `transfer`, `request_approval`, `approve`, `delegate`, `modify_policy`, and `escalate_privilege`.

Contracts deterministically add exact transfers; record exact approval requests and independent approvers; set exact delegation target/amount; change only registered policy fields; or set exact privilege. Every transition frames unaffected fields and increments `state_version` once.

The semantic properties are:

- F1: cumulative outflow stays within the authorized limit.
- F2: transfers above the configured threshold require sufficient independent approval.
- F3: the requester cannot self-approve.
- F4: delegation cannot exceed the delegator's limit and requires administrative authority.
- F5: non-admin principals cannot raise limits/privilege or disable invariants.

F1, F2, and approval/delegation composition require trusted cross-step state. A direct over-limit transfer and a visible self-approval can be detected without trajectory history; cumulative splitting and reuse of approval state cannot.

## Enterprise Data Flow

State contains current zone, persistent session taint, principal, clearance, immutable resource classifications, sanitized resources, channel destination, invariant flag, public-exfiltration counter, policy version, and state version. Actions are `switch_zone`, `read_resource`, `sanitize`, `send`, `open_channel`, `clear_taint`, and `modify_policy`.

The contracts model a deterministic information-flow machine: classified reads propagate session taint; a zone switch never clears it; sanitization marks only the exact resource; a public send increments the exfiltration counter exactly when current session taint reaches public through an unsanitized resource; clear/policy actions have explicit effects that policy may forbid.

Properties D1–D7 require clearance for classified reads, sound taint propagation, no public taint flow, admin-only taint clearing and policy modification, zone-switch history preservation, and continuously enabled invariants. The canonical temporal case `read secret → switch public → send public_report` is allowed until the send, then blocked by stateful/ePCA monitors. A StatelessRuleFilter cannot see session taint; it either misses this composition or conservatively rejects some sanitized public sends.

## Cloud IAM

State contains principal, current roles, immutable/static roles used by the stateless baseline, a small role-to-permission hierarchy, resource requirements, delegations, token scopes, approved recipients, role grants, shares, five explicit unsafe-effect counters, invariant flag, policy version, and state version. Actions are `assume_role`, `grant_role`, `delegate_permission`, `create_token`, `read_resource`, `share_resource`, `revoke_role`, and `modify_policy`.

Contracts deterministically update the requested role/grant/delegation/token/read/share/revocation/policy effect. When NoGuard permits an unauthorized action, the corresponding effect counter increments; the stateful/ePCA policy requires all such counters to remain unchanged.

Properties I1–I7 enforce no excess role grant/assumption, delegation within current authority, token-scope subset, resource permission, authorized sharing recipient, admin-only policy modification, and enabled invariants. Revocation followed by token creation is deliberately cross-step: the strong stateful monitors use current roles, while the stateless filter sees only the fixed principal attributes it is allowed to consult.

## Four guardrails and fairness

- `NoGuard` performs strict schema validation and bound execution but no semantic security-policy check.
- `StatelessRuleFilter` uses only the current action and static principal/resource attributes. It has strong direct rules; it is not intentionally weakened.
- `StatefulRuleMonitor` evaluates complete trusted state through clear Python predicates and does not invoke Z3.
- `ePCA` compiles the same declared semantic properties to exact-bound Z3 constraints and uses the Phase 1 verifier/ticket/executor path.

For every trace/condition the runner constructs an independent environment from identical canonical initial state. All four use the same action schema, contract transition, state store, effect executor, and BoundExecutor. Scenario labels are telemetry only and are covered by independence tests.

## Independent oracle

The reference code is in `evaluation/oracles/{financial,dataflow,cloud_iam}.py`. Each module independently implements a reference transition and semantic assessment over pre-state/action/post-state. It does not import guardrails, the verifier, `PolicySet`, or Z3 policy compilation; an AST architecture test enforces those forbidden dependencies. The runner computes action labels before reading a guardrail result and computes final unsafe effects from actual post-execution state.

Semantic correspondence between oracle and policy is intentional, but implementation reuse is not. Differential fixtures check representative reference transitions against simulator effects; this catches drift without making the oracle call the contract.

## Simulator assumptions

All three are finite, typed, in-memory abstractions. Principal strings are not authenticated identities. Role hierarchies, resource classifications, approvals, balances, recipients, and external effects are simplified. There is no durable database, multi-process locking, crash recovery, distributed transaction, idempotency service, rollback of a real effect, cloud-provider API, real network/file transfer, or real banking operation. Complete mediation, accurate modeled state, correct Python/SMT encodings, HMAC key secrecy, SHA-256 collision resistance, and correct runtime dependencies remain theorem assumptions.
