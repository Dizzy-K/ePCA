from __future__ import annotations

import hashlib
from collections import Counter, defaultdict

from benchmark.generate import CATEGORIES, ENVIRONMENTS, dataset_bytes, generate_traces


EXPECTED_SHA256 = "5efc3bae551ac93436174de4ccccb26df9b4e77bc6ee8c4346bc5ee56edb8927"


def test_trace_generation_is_deterministic_and_hash_reproducible() -> None:
    first = dataset_bytes(generate_traces())
    second = dataset_bytes(generate_traces())
    assert first == second
    assert hashlib.sha256(first).hexdigest() == EXPECTED_SHA256


def test_trace_distribution_and_template_families_are_nontrivial() -> None:
    traces = generate_traces()
    assert len(traces) == 600
    assert Counter(trace["environment"] for trace in traces) == {environment: 200 for environment in ENVIRONMENTS}
    assert Counter(trace["category"] for trace in traces) == {category: 60 for category in CATEGORIES}
    families: dict[tuple[str, str], set[str]] = defaultdict(set)
    for trace in traces:
        families[(trace["environment"], trace["category"])].add(trace["template_family"])
        assert 1 <= len(trace["steps"]) <= 12
        assert trace["expected_first_violation_step"] is None or trace["expected_first_violation_step"] < len(trace["steps"])
    assert all(len(value) >= 4 for value in families.values())
