from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

from benchmark.analyze import summarize
from phase3.experiment import stats


ORDER = ("StatefulRuleMonitor", "PCC-Action", "ePCA")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def ratio(numerator: int, denominator: int) -> str:
    return "NA" if not denominator else f"{numerator}/{denominator} ({100*numerator/denominator:.1f}%)"


def equivalence_report(rows: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    summaries = [summarize([row for row in rows if row["condition"] == condition], scope="overall", scope_value="all") for condition in ORDER]
    by_condition = {condition: {row["trace_id"]: row for row in rows if row["condition"] == condition} for condition in ORDER}
    pcc, epca = by_condition["PCC-Action"], by_condition["ePCA"]
    decision_disagreements = 0
    trace_disagreements = 0
    for trace_id in sorted(pcc):
        pcc_steps = pcc[trace_id]["steps"]
        epca_steps = epca[trace_id]["steps"]
        decision_disagreements += sum(a["decision"] != b["decision"] for a, b in zip(pcc_steps, epca_steps))
        trace_disagreements += int(
            pcc[trace_id]["unsafe_effect_materialized"] != epca[trace_id]["unsafe_effect_materialized"]
            or pcc[trace_id]["benign_task_completed"] != epca[trace_id]["benign_task_completed"]
        )
    lines = [
        "# Phase 3 PCC Semantic Equivalence",
        "",
        "| Condition | UAAR ↓ | UEMR ↓ | FRR ↓ | BTCR ↑ |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for row in summaries:
        lines.append(f"| {row['condition']} | {ratio(row['uaar_numerator'], row['uaar_denominator'])} | {ratio(row['uemr_numerator'], row['uemr_denominator'])} | {ratio(row['frr_numerator'], row['frr_denominator'])} | {ratio(row['btcr_numerator'], row['btcr_denominator'])} |")
    lines.extend(
        [
            "",
            f"- PCC-Action vs ePCA step-decision disagreements: **{decision_disagreements}**.",
            f"- PCC-Action vs ePCA trace-effect/utility disagreements: **{trace_disagreements}**.",
            "- The result is an equality result under the frozen finite policy semantics, not a claim that one architecture is universally superior.",
            "",
        ]
    )
    return "\n".join(lines), summaries


def freshness_report(freshness: list[dict[str, Any]], changes: list[dict[str, Any]], failures: list[dict[str, Any]]) -> str:
    lines = [
        "# Phase 3 PCC Freshness and Producer Availability",
        "",
        "## Direct freshness cases",
        "",
        "| Environment | Case | Accepted | Reason |",
        "| --- | --- | ---: | --- |",
    ]
    for row in freshness:
        lines.append(f"| {row['environment']} | {row['case']} | {row['accepted']} | `{row['reason']}` |")
    lines.extend(["", "## State-change schedule", "", "| Probability | Condition | Samples | Changed | Stale certs | Regenerations | Re-verifications | Mean total ms |", "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
    groups: dict[tuple[float, str], list[dict[str, Any]]] = defaultdict(list)
    for row in changes:
        groups[(row["state_change_probability"], row["condition"])].append(row)
    for (probability, condition), group in sorted(groups.items()):
        lines.append(f"| {probability:.0%} | {condition} | {len(group)} | {sum(item['state_changed'] for item in group)} | {sum(item['stale_certificate'] for item in group)} | {sum(item['regeneration_count'] for item in group)} | {sum(item['reverification_count'] for item in group)} | {statistics.fmean(item['total_verification_ms'] for item in group):.4f} |")
    lines.extend(["", "## Producer failure on benign traces", "", "| Producer mode | BTCR | Accepted decisions | Fail closed |", "| --- | ---: | ---: | ---: |"])
    for row in failures:
        lines.append(f"| {row['producer_mode']} | {ratio(row['benign_completed'], row['benign_traces'])} | {row['accepted_decisions']}/{row['decisions']} | {row['fail_closed']} |")
    lines.extend(["", "Invalid and missing producer output fails closed. This demonstrates an availability dependency, not a PCC safety defect.", ""])
    return "\n".join(lines)


def overhead_summary(rows: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    metrics = {
        "StatefulRuleMonitor": ("rule_evaluation_ms",),
        "PCC-Action": ("certificate_generation_ms", "certificate_checking_ms", "certificate_total_verification_ms", "certificate_size_bytes"),
        "ePCA": ("epca_compilation_ms", "epca_solver_ms", "epca_total_verification_ms"),
    }
    summaries: list[dict[str, Any]] = []
    for condition in ORDER:
        group = [row for row in rows if row["condition"] == condition]
        for metric in metrics[condition]:
            values = [float(row[metric]) for row in group]
            summaries.append({"condition": condition, "metric": metric, "n": len(values), **stats(values)})
    lines = [
        "# Phase 3 PCC Overhead",
        "",
        "Wall-clock microbenchmarks use the same deterministic action workload. Values are milliseconds except certificate size (bytes). They characterize this Python simulator, not production latency.",
        "",
        "| Condition | Metric | n | Mean | Median | p95 |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for row in summaries:
        lines.append(f"| {row['condition']} | `{row['metric']}` | {row['n']} | {row['mean']:.4f} | {row['median']:.4f} | {row['p95']:.4f} |")
    lines.append("")
    return "\n".join(lines), summaries


def write_latex_main(path: Path, summaries: list[dict[str, Any]]) -> None:
    lines = ["\\begin{tabular}{lrrrr}", "\\toprule", "Condition & UAAR $\\downarrow$ & UEMR $\\downarrow$ & FRR $\\downarrow$ & BTCR $\\uparrow$ \\\\", "\\midrule"]
    for row in summaries:
        values = []
        for prefix in ("uaar", "uemr", "frr", "btcr"):
            num, den = row[f"{prefix}_numerator"], row[f"{prefix}_denominator"]
            values.append("--" if not den else f"{100*num/den:.1f}\\% ({num}/{den})")
        lines.append(f"{row['condition']} & {' & '.join(values)} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def write_latex_overhead(path: Path, summaries: list[dict[str, Any]]) -> None:
    lines = ["\\begin{tabular}{llrrr}", "\\toprule", "Condition & Metric & Mean & Median & p95 \\\\", "\\midrule"]
    for row in summaries:
        metric = row["metric"].replace("_", "\\_")
        lines.append(f"{row['condition']} & {metric} & {row['mean']:.4f} & {row['median']:.4f} & {row['p95']:.4f} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def analyze(results_dir: Path, project_root: Path) -> None:
    equivalence = read_jsonl(results_dir / "pcc_equivalence.jsonl")
    freshness = read_jsonl(results_dir / "pcc_freshness.jsonl")
    overhead = read_jsonl(results_dir / "pcc_overhead.jsonl")
    changes = read_jsonl(results_dir / "pcc_state_change.jsonl")
    failures = read_jsonl(results_dir / "pcc_producer_failure.jsonl")
    eq_report, eq_summaries = equivalence_report(equivalence)
    overhead_report, overhead_summaries = overhead_summary(overhead)
    (project_root / "reports").mkdir(parents=True, exist_ok=True)
    (project_root / "reports/phase3_pcc_equivalence.md").write_text(eq_report, encoding="utf-8")
    (project_root / "reports/phase3_pcc_freshness.md").write_text(freshness_report(freshness, changes, failures), encoding="utf-8")
    (project_root / "reports/phase3_pcc_overhead.md").write_text(overhead_report, encoding="utf-8")
    write_latex_main(project_root / "paper_tables/phase3_pcc_main.tex", eq_summaries)
    write_latex_overhead(project_root / "paper_tables/phase3_pcc_overhead.tex", overhead_summaries)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Phase 3 PCC reports and paper tables")
    parser.add_argument("--results-dir", type=Path, default=Path("results/phase3"))
    parser.add_argument("--project-root", type=Path, default=Path("."))
    args = parser.parse_args()
    analyze(args.results_dir, args.project_root)
    print("generated Phase 3 PCC reports and LaTeX tables")


if __name__ == "__main__":
    main()
