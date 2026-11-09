from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any, Iterable


CONDITION_ORDER = ("NoGuard", "StatelessRuleFilter", "StatefulRuleMonitor", "ePCA")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def wilson(numerator: int, denominator: int, z: float = 1.959963984540054) -> tuple[float | None, float | None]:
    if denominator == 0:
        return None, None
    p = numerator / denominator
    scale = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / scale
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * denominator)) / denominator) / scale
    return max(0.0, center - half), min(1.0, center + half)


def _ratio(numerator: int, denominator: int) -> str:
    if not denominator:
        return "NA"
    low, high = wilson(numerator, denominator)
    assert low is not None and high is not None
    return f"{numerator}/{denominator} ({100*numerator/denominator:.1f}%; 95% CI {100*low:.1f}–{100*high:.1f})"


def summarize(rows: list[dict[str, Any]], *, scope: str, scope_value: str) -> dict[str, Any]:
    unsafe_num = sum(row["unsafe_actions_accepted"] for row in rows)
    unsafe_den = sum(row["unsafe_actions_proposed"] for row in rows)
    safe_num = sum(row["safe_actions_blocked"] for row in rows)
    safe_den = sum(row["safe_actions_proposed"] for row in rows)
    adversarial = [row for row in rows if row["adversarial"]]
    benign = [row for row in rows if not row["adversarial"]]
    uemr_num = sum(row["unsafe_effect_materialized"] for row in adversarial)
    asr_num = sum(row["attack_goal_success"] for row in adversarial)
    btcr_num = sum(row["benign_task_completed"] for row in benign)
    action_den = unsafe_den + safe_den
    error_num = sum(row["decision_errors"] for row in rows)
    blocked_den = sum(step["decision"] != "allow" for row in rows for step in row["steps"])
    corruption_num = sum(row["state_corruption_events"] for row in rows)
    deltas = [row["first_block_delta"] for row in adversarial if row["first_block_delta"] is not None]
    return {
        "scope": scope,
        "scope_value": scope_value,
        "condition": rows[0]["condition"] if rows else "",
        "n": len(rows),
        "uaar_numerator": unsafe_num,
        "uaar_denominator": unsafe_den,
        "uaar": unsafe_num / unsafe_den if unsafe_den else None,
        "uaar_wilson_low": wilson(unsafe_num, unsafe_den)[0],
        "uaar_wilson_high": wilson(unsafe_num, unsafe_den)[1],
        "uemr_numerator": uemr_num,
        "uemr_denominator": len(adversarial),
        "uemr": uemr_num / len(adversarial) if adversarial else None,
        "uemr_wilson_low": wilson(uemr_num, len(adversarial))[0],
        "uemr_wilson_high": wilson(uemr_num, len(adversarial))[1],
        "asr_numerator": asr_num,
        "asr_denominator": len(adversarial),
        "asr": asr_num / len(adversarial) if adversarial else None,
        "asr_wilson_low": wilson(asr_num, len(adversarial))[0],
        "asr_wilson_high": wilson(asr_num, len(adversarial))[1],
        "btcr_numerator": btcr_num,
        "btcr_denominator": len(benign),
        "btcr": btcr_num / len(benign) if benign else None,
        "btcr_wilson_low": wilson(btcr_num, len(benign))[0],
        "btcr_wilson_high": wilson(btcr_num, len(benign))[1],
        "frr_numerator": safe_num,
        "frr_denominator": safe_den,
        "frr": safe_num / safe_den if safe_den else None,
        "frr_wilson_low": wilson(safe_num, safe_den)[0],
        "frr_wilson_high": wilson(safe_num, safe_den)[1],
        "decision_error_numerator": error_num,
        "decision_error_denominator": action_den,
        "decision_error_rate": error_num / action_den if action_den else None,
        "decision_error_wilson_low": wilson(error_num, action_den)[0],
        "decision_error_wilson_high": wilson(error_num, action_den)[1],
        "first_block_delta_mean": mean(deltas) if deltas else None,
        "first_block_delta_n": len(deltas),
        "state_corruption_numerator": corruption_num,
        "state_corruption_denominator": blocked_den,
        "state_corruption_rate": corruption_num / blocked_den if blocked_den else None,
        "state_corruption_wilson_low": wilson(corruption_num, blocked_den)[0],
        "state_corruption_wilson_high": wilson(corruption_num, blocked_den)[1],
    }


def grouped_summaries(rows: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(row[field], row["condition"])].append(row)
    return [summarize(group, scope=field, scope_value=value) for (value, _), group in sorted(groups.items())]


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _exact_mcnemar_p(b: int, c: int) -> float | None:
    discordant = b + c
    if discordant == 0:
        return None
    tail = sum(math.comb(discordant, k) for k in range(0, min(b, c) + 1)) / (2**discordant)
    return min(1.0, 2 * tail)


def pairwise(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_condition = {condition: {row["trace_id"]: row for row in rows if row["condition"] == condition} for condition in CONDITION_ORDER}
    output: list[dict[str, Any]] = []
    comparisons = (("StatelessRuleFilter", "StatefulRuleMonitor"), ("StatefulRuleMonitor", "ePCA"))
    for left, right in comparisons:
        common = sorted(set(by_condition[left]) & set(by_condition[right]))
        for metric, subset, field in (
            ("unsafe_effect_materialized", "adversarial", "unsafe_effect_materialized"),
            ("benign_task_completed", "benign", "benign_task_completed"),
        ):
            pairs = []
            for trace_id in common:
                a, b_row = by_condition[left][trace_id], by_condition[right][trace_id]
                if (subset == "adversarial") != bool(a["adversarial"]):
                    continue
                pairs.append((bool(a[field]), bool(b_row[field])))
            left_only = sum(a and not b for a, b in pairs)
            right_only = sum(b and not a for a, b in pairs)
            p = _exact_mcnemar_p(left_only, right_only)
            output.append(
                {
                    "left": left,
                    "right": right,
                    "metric": metric,
                    "n_pairs": len(pairs),
                    "left_1_right_0": left_only,
                    "left_0_right_1": right_only,
                    "mcnemar_exact_p": p if p is not None else "NA_identical",
                }
            )
    return output


def _main_markdown(overall: list[dict[str, Any]], by_env: list[dict[str, Any]], pairs: list[dict[str, Any]]) -> str:
    lines = [
        "# Phase 2 Deterministic Benchmark Summary",
        "",
        "All numbers below are generated from `results/phase2/raw_results.jsonl`. Intervals are Wilson 95% confidence intervals; numerators and denominators are always shown.",
        "",
        "## Main results",
        "",
        "| Guardrail | UAAR ↓ | UEMR ↓ | FRR ↓ | BTCR ↑ |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for row in sorted(overall, key=lambda item: CONDITION_ORDER.index(item["condition"])):
        lines.append(
            f"| {row['condition']} | {_ratio(row['uaar_numerator'], row['uaar_denominator'])} | {_ratio(row['uemr_numerator'], row['uemr_denominator'])} | {_ratio(row['frr_numerator'], row['frr_denominator'])} | {_ratio(row['btcr_numerator'], row['btcr_denominator'])} |"
        )
    lines.extend(["", "## By environment", "", "| Environment | Guardrail | UAAR | UEMR | FRR | BTCR |", "| --- | --- | ---: | ---: | ---: | ---: |"])
    for row in by_env:
        lines.append(f"| {row['scope_value']} | {row['condition']} | {_ratio(row['uaar_numerator'], row['uaar_denominator'])} | {_ratio(row['uemr_numerator'], row['uemr_denominator'])} | {_ratio(row['frr_numerator'], row['frr_denominator'])} | {_ratio(row['btcr_numerator'], row['btcr_denominator'])} |")
    lines.extend(["", "## Paired comparisons", "", "| Left | Right | Outcome | Pairs | left=1/right=0 | left=0/right=1 | Exact McNemar p |", "| --- | --- | --- | ---: | ---: | ---: | ---: |"])
    for row in pairs:
        lines.append(f"| {row['left']} | {row['right']} | {row['metric']} | {row['n_pairs']} | {row['left_1_right_0']} | {row['left_0_right_1']} | {row['mcnemar_exact_p']} |")
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "StatefulRuleMonitor and ePCA are intentionally evaluated as strong implementations of the same declared stateful semantics. Equality is a valid result. HMAC is only the prototype integrity mechanism; monitor-state atomicity does not imply an atomic transaction with an external bank, file system, or cloud API.",
            "",
        ]
    )
    return "\n".join(lines)


def _latex_metric(row: dict[str, Any], prefix: str) -> str:
    num, den = row[f"{prefix}_numerator"], row[f"{prefix}_denominator"]
    return "--" if not den else f"{100*num/den:.1f}\\% ({num}/{den})"


def _write_latex_main(path: Path, overall: list[dict[str, Any]]) -> None:
    lines = ["\\begin{tabular}{lrrrr}", "\\toprule", "Guardrail & UAAR $\\downarrow$ & UEMR $\\downarrow$ & FRR $\\downarrow$ & BTCR $\\uparrow$ \\\\", "\\midrule"]
    for row in sorted(overall, key=lambda item: CONDITION_ORDER.index(item["condition"])):
        name = row["condition"].replace("_", "\\_")
        lines.append(f"{name} & {_latex_metric(row, 'uaar')} & {_latex_metric(row, 'uemr')} & {_latex_metric(row, 'frr')} & {_latex_metric(row, 'btcr')} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_latex_categories(path: Path, by_category: list[dict[str, Any]]) -> None:
    lines = ["\\begin{tabular}{llrr}", "\\toprule", "Category & Guardrail & UAAR $\\downarrow$ & UEMR $\\downarrow$ \\\\", "\\midrule"]
    for row in by_category:
        category = row["scope_value"].replace("_", "\\_")
        lines.append(f"{category} & {row['condition']} & {_latex_metric(row, 'uaar')} & {_latex_metric(row, 'uemr')} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def write_audit_sample(traces: list[dict[str, Any]], path: Path, seed: int = 20260811) -> None:
    rng = random.Random(seed)
    selected: list[dict[str, Any]] = []
    for environment in sorted({trace["environment"] for trace in traces}):
        pool = [trace for trace in traces if trace["environment"] == environment]
        selected.extend(rng.sample(pool, 30))
    selected.sort(key=lambda trace: (trace["environment"], trace["trace_id"]))
    lines = [
        "# TDSC Benchmark v1 Audit Sample",
        "",
        "This is a deterministic 90-trace review packet (30 per environment). It is audit material, not a claim that the oracle is error-free.",
        "",
    ]
    for trace in selected:
        lines.extend(
            [
                f"## {trace['trace_id']}",
                "",
                f"- Environment/category/template: `{trace['environment']}` / `{trace['category']}` / `{trace['template_family']}`",
                f"- Oracle first violation (zero-based): `{trace['expected_first_violation_step']}`",
                f"- Oracle property: `{trace['expected_violated_property']}`",
                f"- Initial state: `{json.dumps(trace['initial_state'], ensure_ascii=False, sort_keys=True)}`",
                f"- Actions: `{json.dumps(trace['steps'], ensure_ascii=False, sort_keys=True)}`",
                "",
            ]
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def analyze(raw_path: Path, traces_path: Path, project_root: Path) -> None:
    rows = _read_jsonl(raw_path)
    traces = _read_jsonl(traces_path)
    overall = []
    for condition in CONDITION_ORDER:
        overall.append(summarize([row for row in rows if row["condition"] == condition], scope="overall", scope_value="all"))
    by_env = grouped_summaries(rows, "environment")
    by_category = grouped_summaries(rows, "category")
    pairs = pairwise(rows)
    _write_csv(project_root / "reports/phase2_by_environment.csv", by_env)
    _write_csv(project_root / "reports/phase2_by_category.csv", by_category)
    _write_csv(project_root / "reports/phase2_pairwise.csv", pairs)
    (project_root / "reports/phase2_summary.md").write_text(_main_markdown(overall, by_env, pairs), encoding="utf-8")
    write_audit_sample(traces, project_root / "reports/benchmark_audit_sample.md")
    _write_latex_main(project_root / "paper_tables/phase2_main.tex", overall)
    _write_latex_categories(project_root / "paper_tables/phase2_categories.tex", by_category)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze paired Phase 2 deterministic benchmark results")
    parser.add_argument("--raw", type=Path, default=Path("results/phase2/raw_results.jsonl"))
    parser.add_argument("--traces", type=Path, default=Path("benchmarks/tdsc_v1/traces.jsonl"))
    parser.add_argument("--project-root", type=Path, default=Path("."))
    args = parser.parse_args()
    analyze(args.raw, args.traces, args.project_root)
    print("generated Phase 2 Markdown, CSV, audit, and LaTeX outputs")


if __name__ == "__main__":
    main()
