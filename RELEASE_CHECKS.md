# Release validation (2026-11-09)

This record covers packaging and local software validation, not new scientific
experiments, independent external review, or journal acceptance.

- Local regression suite: **139 passed** (137 existing tests and two release tests).
- Archived-result aggregation: passed; 640 deterministic traces, 720 adaptive
  episodes, 720 included certificate calls, eight safe/eleven unsafe templates.
- PCC safe acceptance: 148/180 (GPT-5.5), 144/180 (DeepSeek-v4-pro); ePCA 180/180 each.
- Both strong monitors: UEMR 0/108 and PVMR 0/108 on the included cohort; PVMR
  aggregation joins actually committed turns to archived invariant evaluations.
- Recorded pair comparison: 0 disagreements in 863 unique pairs / 3,966 occurrences.
- Omission witnesses: 10/23 rules; the archived one-sided/common-mode results match.
- All 54 source/result hashes named in the manuscript's internal provenance
  records match the copied release files. Runtime, contracts, policies, oracles,
  and archived measurements were not changed for publication.
- Current-tree credential-pattern and local-path checks: no remaining matches.
  This is a bounded scan, not a guarantee about all possible sensitive content.
- Removed the legacy embedded API-key fallback. Legacy callers now use the
  environment-only helper. Earlier Git commits still contain the old source;
  the corresponding provider credential must be revoked or rotated separately.
- Source/diff whitespace validation passed.

Validation environment: Python 3.12.14, pytest 8.3.5, z3-solver 4.16.0.0,
pydantic 2.12.5 on macOS. This identifies the release check, not the historical
measurement host. No remote model calls or new benchmark experiments were run.

The published-file manifest excludes itself, .git, local environments, caches,
and regenerated build outputs. Re-run `python scripts/verify_release.py` to check
the files, and `python scripts/reproduce_paper.py` to recompute the summaries.
