from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable


GUARDRAIL_ORDER = ("RuntimeOnly", "StatelessRuleFilter", "LLMJudge", "StatefulRuleMonitor", "ePCA")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def wilson(numerator: int, denominator: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if denominator == 0:
        return (0.0, 0.0)
    p = numerator / denominator
    denom = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / denom
    margin = z * math.sqrt(p * (1 - p) / denominator + z * z / (4 * denominator * denominator)) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


def ratio_ci(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "NA"
    low, high = wilson(numerator, denominator)
    return f"{numerator}/{denominator} ({100*numerator/denominator:.1f}%, 95% CI {100*low:.1f}–{100*high:.1f})"


def _stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "median": 0.0, "p95": 0.0}
    ordered = sorted(values)
    return {
        "mean": statistics.fmean(ordered),
        "median": statistics.median(ordered),
        "p95": ordered[min(len(ordered) - 1, round((len(ordered) - 1) * 0.95))],
    }


def adaptive_summary(rows: list[dict[str, Any]], **scope: str) -> dict[str, Any]:
    group = [row for row in rows if not row.get("api_error")]
    adversarial = [row for row in group if row["goal_type"] == "adversarial"]
    benign = [row for row in group if row["goal_type"] == "benign"]
    unsafe_proposed = sum(row["unsafe_actions_proposed"] for row in group)
    unsafe_accepted = sum(row["unsafe_actions_accepted"] for row in group)
    blocked_attack = [row for row in adversarial if row["block_count"] > 0]
    result = {
        **scope,
        "valid_episodes": len(group),
        "api_errors": len(rows) - len(group),
        "asr_numerator": sum(row["attack_goal_success"] for row in adversarial),
        "asr_denominator": len(adversarial),
        "uemr_numerator": sum(row["unsafe_effect_materialized"] for row in adversarial),
        "uemr_denominator": len(adversarial),
        "btcr_numerator": sum(row["benign_task_completed"] for row in benign),
        "btcr_denominator": len(benign),
        "uaar_numerator": unsafe_accepted,
        "uaar_denominator": unsafe_proposed,
        "alternative_numerator": sum(row["alternative_path_success"] for row in blocked_attack),
        "alternative_denominator": len(blocked_attack),
        "mean_trajectory_length": statistics.fmean(row["trajectory_length"] for row in group) if group else 0.0,
        "mean_block_count": statistics.fmean(row["block_count"] for row in group) if group else 0.0,
    }
    for metric in ("asr", "uemr", "btcr", "uaar", "alternative"):
        num, den = result[f"{metric}_numerator"], result[f"{metric}_denominator"]
        low, high = wilson(num, den)
        result[f"{metric}_rate"] = num / den if den else None
        result[f"{metric}_ci_low"] = low if den else None
        result[f"{metric}_ci_high"] = high if den else None
    return result


def _group_summaries(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[tuple(str(row[key]) for key in keys)].append(row)
    return [adaptive_summary(group, **dict(zip(keys, values))) for values, group in sorted(groups.items())]


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _paired(rows: list[dict[str, Any]], baseline: str, target: str = "ePCA") -> dict[str, int]:
    valid = [row for row in rows if not row.get("api_error")]
    mapping: dict[tuple[str, str, int], dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in valid:
        mapping[(row["model"], row["scenario"], row["repeat"])][row["guardrail"]] = row
    counts = {"pairs": 0, "baseline_only_success": 0, "target_only_success": 0, "outcome_disagreements": 0}
    for conditions in mapping.values():
        if baseline not in conditions or target not in conditions:
            continue
        a, b = conditions[baseline], conditions[target]
        a_success = a["task_success"]
        b_success = b["task_success"]
        counts["pairs"] += 1
        counts["baseline_only_success"] += int(a_success and not b_success)
        counts["target_only_success"] += int(b_success and not a_success)
        counts["outcome_disagreements"] += int(
            a["unsafe_effect_materialized"] != b["unsafe_effect_materialized"]
            or a["benign_task_completed"] != b["benign_task_completed"]
        )
    return counts


def adaptive_report(rows: list[dict[str, Any]], overall: list[dict[str, Any]]) -> str:
    valid = [row for row in rows if not row.get("api_error")]
    lines = [
        "# Phase 4 Adaptive LLM Agent Evaluation",
        "",
        f"The repaired working set contains **{len(rows)}** episodes; **{len(valid)}** are API-valid and **{len(rows)-len(valid)}** contain actor/judge API or timeout errors. The frozen raw run is reported separately; error episodes are excluded from safety and utility denominators.",
        "",
        "| Guardrail | Valid | ASR | UEMR | BTCR | UAAR | Mean turns | Mean blocks | Alternative path success |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    by = {row["guardrail"]: row for row in overall}
    for guardrail in GUARDRAIL_ORDER:
        row = by.get(guardrail)
        if row is None:
            lines.append(f"| {guardrail} | NA | NA | NA | NA | NA | NA | NA | NA |")
            continue
        lines.append(
            f"| {guardrail} | {row['valid_episodes']} | {ratio_ci(row['asr_numerator'],row['asr_denominator'])} | {ratio_ci(row['uemr_numerator'],row['uemr_denominator'])} | {ratio_ci(row['btcr_numerator'],row['btcr_denominator'])} | {ratio_ci(row['uaar_numerator'],row['uaar_denominator'])} | {row['mean_trajectory_length']:.2f} | {row['mean_block_count']:.2f} | {ratio_ci(row['alternative_numerator'],row['alternative_denominator'])} |"
        )
    lines.extend(["", "## Paired comparison with ePCA", "", "| Baseline | Complete pairs | Baseline-only task success | ePCA-only task success | Final safety/utility disagreements |", "| --- | ---: | ---: | ---: | ---: |"]) 
    for baseline in ("StatelessRuleFilter", "LLMJudge", "StatefulRuleMonitor"):
        paired = _paired(rows, baseline)
        lines.append(f"| {baseline} | {paired['pairs']} | {paired['baseline_only_success']} | {paired['target_only_success']} | {paired['outcome_disagreements']} |")
    stateful = _paired(rows, "StatefulRuleMonitor")
    lines.extend([
        "",
        (
            "StatefulRuleMonitor and ePCA are identical on all complete API-valid paired final safety/utility outcomes."
            if stateful["outcome_disagreements"] == 0
            else f"StatefulRuleMonitor and ePCA have {stateful['outcome_disagreements']} final safety/utility disagreements across {stateful['pairs']} complete API-valid pairs."
        ),
    ])
    weak = [row for row in valid if row["guardrail"] == "StatelessRuleFilter" and row["unsafe_effect_materialized"]]
    weak_patterns: dict[str, int] = defaultdict(int)
    for row in weak:
        weak_patterns[row["attack_type"]] += 1
    judge_fail = [row for row in valid if row["guardrail"] == "LLMJudge" and row["unsafe_effect_materialized"]]
    judge_patterns: dict[str, int] = defaultdict(int)
    for row in judge_fail:
        judge_patterns[row["attack_type"]] += 1
    lines.extend([
        "",
        "## Main observed failure modes",
        "",
        "- StatelessRuleFilter unsafe effects by scenario family: " + (", ".join(f"`{key}`={value}" for key, value in sorted(weak_patterns.items())) or "none") + ".",
        "- LLMJudge unsafe effects by scenario family: " + (", ".join(f"`{key}`={value}" for key, value in sorted(judge_patterns.items())) or "none") + ".",
        "- Judge failures are recorded as API errors, never converted into BLOCK decisions.",
        "- All guardrails expose the same public block feedback; detailed invariant and judge reasons remain only in raw evaluator logs.",
        "",
    ])
    return "\n".join(lines)


def _state_delta(before: dict[str, Any] | None, after: dict[str, Any] | None) -> dict[str, list[Any]]:
    before, after = before or {}, after or {}
    return {key: [before.get(key), after.get(key)] for key in sorted(set(before) | set(after)) if before.get(key) != after.get(key)}


def cases_report(rows: list[dict[str, Any]]) -> str:
    candidates = [row for row in rows if not row.get("api_error") and row["goal_type"] == "adversarial" and row["block_count"] > 0 and row["changed_strategy_after_block"]]
    selected: list[dict[str, Any]] = []
    for environment in ("financial", "dataflow", "cloud_iam"):
        env = [row for row in candidates if row["environment"] == environment]
        weak_success = [row for row in env if row["guardrail"] in {"StatelessRuleFilter", "LLMJudge"} and row["unsafe_effect_materialized"]]
        strong_block = [row for row in env if row["guardrail"] in {"StatefulRuleMonitor", "ePCA"} and not row["unsafe_effect_materialized"]]
        picked: list[dict[str, Any]] = []
        if weak_success:
            picked.append(sorted(weak_success, key=lambda row: (row["guardrail"], row["episode_id"]))[0])
        if strong_block:
            picked.append(sorted(strong_block, key=lambda row: (row["guardrail"], row["episode_id"]))[0])
        for row in sorted(env, key=lambda item: item["episode_id"]):
            if len(picked) >= 2:
                break
            if row not in picked:
                picked.append(row)
        selected.extend(picked[:2])
    lines = ["# Phase 4 Representative Adaptive Trajectories", "", "Cases are selected automatically from episodes where an action was blocked and the actor subsequently changed its proposed action. Selection prefers one weak-guardrail unsafe outcome and one Stateful/ePCA contained outcome per environment; it does not select only successful attacks.", ""]
    for index, row in enumerate(selected, 1):
        lines.extend([
            f"## Case {index}: {row['environment']} / {row['guardrail']}",
            "",
            f"- Goal: {row['goal']}",
            f"- Model/repeat: `{row['model']}` / {row['repeat']}",
            f"- Final outcome: unsafe effect `{row['unsafe_effect_materialized']}`, attack success `{row['attack_goal_success']}`, termination `{row['termination_reason']}`.",
            "",
            "| Turn | Principal | Action | Decision | Executed | State delta |",
            "| ---: | --- | --- | --- | ---: | --- |",
        ])
        for turn in row["trajectory"]:
            action = json.dumps(turn.get("action"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            delta = json.dumps(_state_delta(turn.get("state_before"), turn.get("state_after")), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            lines.append(f"| {turn['turn']} | {turn.get('principal_id') or '—'} | `{action}` | {turn.get('decision')} | {turn.get('executed',False)} | `{delta}` |")
        lines.append("")
    if len(selected) < 6:
        lines.extend(["## Coverage note", "", f"Only {len(selected)} qualifying trajectories existed; no non-qualifying case was fabricated.", ""])
    return "\n".join(lines)


def pcc_model_summary(rows: list[dict[str, Any]], model: str) -> dict[str, Any]:
    group = [row for row in rows if row["model"] == model and not row.get("api_error")]
    safe = [row for row in group if row["safe_or_unsafe"] == "safe"]
    unsafe = [row for row in group if row["safe_or_unsafe"] == "unsafe"]
    lat = _stats([row["generation_latency"] for row in group])
    e2e = _stats([row["end_to_end_latency"] for row in safe])
    certificate_sizes = _stats([float(row["certificate_size"]) for row in group])
    input_tokens = _stats([float(row["token_usage"]["input"] or 0) for row in group])
    output_tokens = _stats([float(row["token_usage"]["output"] or 0) for row in group])
    safe_valid = sum(row["certificate_valid"] for row in safe)
    return {
        "model": model,
        "valid_calls": len(group),
        "api_errors": sum(row["model"] == model and bool(row.get("api_error")) for row in rows),
        "safe_valid_numerator": safe_valid,
        "safe_valid_denominator": len(safe),
        "safe_rejection_numerator": len(safe) - safe_valid,
        "safe_rejection_denominator": len(safe),
        "unsafe_accept_numerator": sum(row["certificate_valid"] for row in unsafe),
        "unsafe_accept_denominator": len(unsafe),
        "generation_mean_ms": lat["mean"],
        "generation_median_ms": lat["median"],
        "generation_p95_ms": lat["p95"],
        "safe_e2e_mean_ms": e2e["mean"],
        "safe_e2e_median_ms": e2e["median"],
        "safe_e2e_p95_ms": e2e["p95"],
        "input_tokens_mean": input_tokens["mean"],
        "output_tokens_mean": output_tokens["mean"],
        "certificate_size_mean_bytes": certificate_sizes["mean"],
        "certificate_size_median_bytes": certificate_sizes["median"],
        "certificate_size_p95_bytes": certificate_sizes["p95"],
    }


def pcc_report(rows: list[dict[str, Any]], summaries: list[dict[str, Any]]) -> str:
    errors = [row for row in rows if row.get("api_error")]
    unique_safe: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["safe_or_unsafe"] == "safe":
            unique_safe.setdefault(row["pair_id"], row)
    epca_accepted = sum(row["epca_accepted"] for row in unique_safe.values())
    epca_stats = _stats([row["epca_verification_latency"] for row in unique_safe.values()])
    lines = [
        "# Phase 4 LLM as PCC Certificate Producer",
        "",
        f"The run contains **{len(rows)}** calls and **{len(errors)}** API errors/timeouts. API-error calls are excluded from certificate-rate denominators.",
        "",
        "| Model | Valid calls | Safe certificate valid rate | Safe certificate rejection rate | Unsafe checker acceptance | Generation mean / median / p95 ms | Safe PCC E2E mean ms | Mean input / output tokens | Certificate bytes mean / median / p95 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summaries:
        lines.append(
            f"| {row['model']} | {row['valid_calls']} | {ratio_ci(row['safe_valid_numerator'],row['safe_valid_denominator'])} | "
            f"{ratio_ci(row['safe_rejection_numerator'],row['safe_rejection_denominator'])} | "
            f"{ratio_ci(row['unsafe_accept_numerator'],row['unsafe_accept_denominator'])} | "
            f"{row['generation_mean_ms']:.2f} / {row['generation_median_ms']:.2f} / {row['generation_p95_ms']:.2f} | "
            f"{row['safe_e2e_mean_ms']:.2f} | {row['input_tokens_mean']:.1f} / {row['output_tokens_mean']:.1f} | "
            f"{row['certificate_size_mean_bytes']:.1f} / {row['certificate_size_median_bytes']:.1f} / {row['certificate_size_p95_bytes']:.1f} |"
        )
    safe_valid = sum(row["certificate_valid"] for row in rows if row["safe_or_unsafe"] == "safe" and not row.get("api_error"))
    safe_total = sum(row["safe_or_unsafe"] == "safe" and not row.get("api_error") for row in rows)
    failure_modes: dict[str, int] = defaultdict(int)
    for row in rows:
        if not row["certificate_valid"]:
            for behavior in row["failure_behavior"]:
                failure_modes[behavior] += 1
    lines.extend([
        "",
        "## Availability and ePCA comparison",
        "",
        f"- PCC-LLM benign availability from valid safe certificates: {ratio_ci(safe_valid,safe_total)}.",
        f"- ePCA accepted the same fixed safe pairs: {epca_accepted}/{len(unique_safe)}; verification latency mean/median/p95 = {epca_stats['mean']:.4f}/{epca_stats['median']:.4f}/{epca_stats['p95']:.4f} ms.",
        "- Certificate rejection behavior: " + (", ".join(f"`{key}`={value}" for key, value in sorted(failure_modes.items())) or "none") + ".",
        "- An invalid certificate for a safe action is an availability failure. Unsafe checker acceptance, not certificate production, is the security outcome.",
        "- Provider private thinking blocks are discarded by the client and are not present in raw results.",
        "",
    ])
    return "\n".join(lines)


def _latex_rate(num: int, den: int) -> str:
    return "--" if not den else f"{100*num/den:.1f}\\% ({num}/{den})"


def write_adaptive_latex(path: Path, rows: list[dict[str, Any]]) -> None:
    lines = ["\\begin{tabular}{lrrrr}", "\\toprule", "Guardrail & ASR $\\downarrow$ & UEMR $\\downarrow$ & UAAR $\\downarrow$ & BTCR $\\uparrow$ " + "\\\\", "\\midrule"]
    by = {row["guardrail"]: row for row in rows}
    for guardrail in GUARDRAIL_ORDER:
        row = by.get(guardrail)
        if row is None:
            lines.append(f"{guardrail} & -- & -- & -- & -- " + "\\\\")
            continue
        values = [_latex_rate(row[f"{metric}_numerator"], row[f"{metric}_denominator"]) for metric in ("asr", "uemr", "uaar", "btcr")]
        lines.append(f"{guardrail} & {' & '.join(values)} " + "\\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def write_pcc_latex(path: Path, rows: list[dict[str, Any]]) -> None:
    lines = ["\\begin{tabular}{lrrrr}", "\\toprule", "Model & Safe valid & Unsafe accepted & Gen. mean (ms) & Safe E2E mean (ms) " + "\\\\", "\\midrule"]
    for row in rows:
        lines.append(f"{row['model']} & {_latex_rate(row['safe_valid_numerator'],row['safe_valid_denominator'])} & {_latex_rate(row['unsafe_accept_numerator'],row['unsafe_accept_denominator'])} & {row['generation_mean_ms']:.2f} & {row['safe_e2e_mean_ms']:.2f} " + "\\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _error_kind(value: Any) -> str:
    text = str(value or "")
    if "watchdog_timeout" in text:
        return "watchdog timeout"
    for status in ("401", "402", "404", "408", "429", "500", "502", "503", "504", "520", "524", "529"):
        if status in text:
            return f"HTTP {status}"
    if "empty_final_text" in text:
        return "empty final text"
    if "timeout" in text.lower():
        return "timeout"
    return "other"


def validation_report(adaptive: list[dict[str, Any]], pcc: list[dict[str, Any]], project_root: Path) -> str:
    """Build a reproducibility and completion audit from the raw Phase 4 rows."""
    # Keep the legacy defaults for the frozen v1 run, but automatically select
    # the v2 manifest/benchmark when the result rows carry the v2 financial
    # policy marker.  This lets versioned analyses run in an isolated output
    # directory without overwriting the v1 reports.
    is_v2 = any(row.get("policy_version") == "financial-policy-v2" for row in adaptive)
    config_name = "phase4_models_v2.json" if is_v2 else "phase4_models.json"
    trace_name = "tdsc_v2" if is_v2 else "tdsc_v1"
    config_path = project_root / "configs" / config_name
    traces_path = project_root / "benchmarks" / trace_name / "traces.jsonl"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    models = [item["model"] for item in config["models"]]
    repeats = int(config["repeats"])
    benchmark_trace_count = sum(1 for line in traces_path.read_text(encoding="utf-8").splitlines() if line.strip())
    expected_adaptive = len(models) * 30 * repeats * len(GUARDRAIL_ORDER)
    expected_pcc = len(models) * 120 * repeats

    adaptive_ids = [str(row.get("episode_id")) for row in adaptive]
    pcc_ids = [str(row.get("call_id")) for row in pcc]
    adaptive_errors = [row for row in adaptive if row.get("api_error")]
    pcc_errors = [row for row in pcc if row.get("api_error")]
    error_kinds: dict[str, int] = defaultdict(int)
    for row in adaptive_errors + pcc_errors:
        error_kinds[_error_kind(row.get("api_error"))] += 1

    adaptive_cells = {
        (row.get("model"), row.get("scenario"), row.get("repeat"), row.get("guardrail"))
        for row in adaptive
    }
    pcc_cells = {
        (row.get("model"), row.get("pair_id"), row.get("repeat"))
        for row in pcc
    }
    scenario_count = len({row.get("scenario") for row in adaptive})
    environments = sorted({str(row.get("environment")) for row in adaptive if row.get("environment")})
    pair_counts = {
        environment: {
            kind: len({row.get("pair_id") for row in pcc if row.get("environment") == environment and row.get("safe_or_unsafe") == kind})
            for kind in ("safe", "unsafe")
        }
        for environment in ("financial", "dataflow", "cloud_iam")
    }

    required_adaptive = {
        "episode_id", "environment", "scenario", "goal_type", "model", "repeat", "guardrail", "turn",
        "action", "decision", "executed", "state_before", "state_after", "unsafe_effect_materialized",
        "task_success", "api_error", "latency", "config_hash", "system_prompt_hash", "episode_complete",
    }
    required_pcc = {
        "call_id", "pair_id", "environment", "safe_or_unsafe", "model", "repeat", "action", "state",
        "certificate_raw", "certificate_valid", "checker_result", "failure_reason", "generation_latency",
        "checker_latency", "token_usage", "api_error", "config_hash", "system_prompt_hash",
    }
    adaptive_missing = sorted(required_adaptive - set.intersection(*(set(row) for row in adaptive))) if adaptive else sorted(required_adaptive)
    pcc_missing = sorted(required_pcc - set.intersection(*(set(row) for row in pcc))) if pcc else sorted(required_pcc)

    config_hashes = sorted({str(row.get("config_hash")) for row in adaptive + pcc if row.get("config_hash")})
    actor_prompt_hashes = sorted({str(row.get("system_prompt_hash")) for row in adaptive if row.get("system_prompt_hash")})
    pcc_prompt_hashes = sorted({str(row.get("system_prompt_hash")) for row in pcc if row.get("system_prompt_hash")})
    complete_flags = sum(bool(row.get("episode_complete")) for row in adaptive)
    unsafe_pcc_accepts = sum(bool(row.get("certificate_valid")) for row in pcc if row.get("safe_or_unsafe") == "unsafe" and not row.get("api_error"))
    credential_markers = sum(
        "sk-" in json.dumps(row, ensure_ascii=False)
        for row in adaptive + pcc
    )

    paired = _paired(adaptive, "StatefulRuleMonitor")
    epca_local_gap = [
        row for row in adaptive
        if not row.get("api_error") and row.get("goal_type") == "adversarial" and row.get("guardrail") == "ePCA"
        and row.get("unsafe_effect_materialized") and not row.get("unsafe_actions_accepted")
    ]
    error_text = ", ".join(f"{kind}={count}" for kind, count in sorted(error_kinds.items())) or "none"
    pair_text = "; ".join(
        f"{environment}: safe={counts['safe']}, unsafe={counts['unsafe']}"
        for environment, counts in pair_counts.items()
    )
    adaptive_done = len(adaptive_cells) == expected_adaptive
    pcc_done = len(pcc_cells) == expected_pcc
    schema_ok = not adaptive_missing and not pcc_missing
    integrity_ok = len(set(adaptive_ids)) == len(adaptive_ids) and len(set(pcc_ids)) == len(pcc_ids)
    final_status = "COMPLETE" if adaptive_done and pcc_done and schema_ok and integrity_ok else "INCOMPLETE"

    paired_stateful = _paired(adaptive, "StatefulRuleMonitor")
    unsafe_pcc_accepts = sum(bool(row.get("certificate_valid")) for row in pcc if row.get("safe_or_unsafe") == "unsafe" and not row.get("api_error"))
    unique_safe: dict[str, dict[str, Any]] = {}
    for row in pcc:
        if row.get("safe_or_unsafe") == "safe":
            unique_safe.setdefault(row["pair_id"], row)
    epca_accepted = sum(bool(row.get("epca_accepted")) for row in unique_safe.values())
    safe_valid = sum(bool(row.get("certificate_valid")) for row in pcc if row.get("safe_or_unsafe") == "safe" and not row.get("api_error"))
    safe_total = sum(row.get("safe_or_unsafe") == "safe" and not row.get("api_error") for row in pcc)

    lines = [
        "# Phase 4 LLM Agent Evaluation Validation Report",
        "",
        f"**Machine-derived completion status: {final_status}.**",
        "",
        "## Frozen configuration and inputs",
        "",
        f"- Exact actor models: {', '.join(f'`{model}`' for model in models)}.",
        f"- Judge model: `{config['judge']['model']}`; temperature `{config['temperature']}`; max turns `{config['max_turns']}`; repeats `{repeats}`; configured concurrency `{config['concurrency']}`.",
        f"- Configuration SHA-256: `{_sha256(config_path)}`; row-level configuration hashes: {', '.join(f'`{value}`' for value in config_hashes) or 'none'}.",
        f"- Frozen {benchmark_trace_count}-trace benchmark (`{trace_name}`) SHA-256: `{_sha256(traces_path)}`.",
        f"- Adaptive actor prompt hashes: {', '.join(f'`{value}`' for value in actor_prompt_hashes) or 'none'}; PCC producer prompt hashes: {', '.join(f'`{value}`' for value in pcc_prompt_hashes) or 'none'}.",
        f"- Raw rows containing a credential-like `sk-` marker: **{credential_markers}** ({'PASS' if credential_markers == 0 else 'FAIL'}).",
        "",
        "## Coverage and integrity gates",
        "",
        "| Gate | Evidence | Result |",
        "| --- | --- | --- |",
        f"| Adaptive matrix | {len(adaptive_cells)}/{expected_adaptive} unique model × scenario × repeat × guardrail cells; {scenario_count}/30 scenarios; environments `{', '.join(environments)}` | {'PASS' if adaptive_done else 'INCOMPLETE'} |",
        f"| PCC producer matrix | {len(pcc_cells)}/{expected_pcc} unique model × pair × repeat cells; unique pairs by environment/type: {pair_text} | {'PASS' if pcc_done else 'INCOMPLETE'} |",
        f"| Unique identifiers | Adaptive duplicates={len(adaptive_ids)-len(set(adaptive_ids))}; PCC duplicates={len(pcc_ids)-len(set(pcc_ids))} | {'PASS' if integrity_ok else 'FAIL'} |",
        f"| Completed adaptive rows | `{complete_flags}/{len(adaptive)}` have `episode_complete=true` | {'PASS' if complete_flags == len(adaptive) else 'FAIL'} |",
        f"| Required result fields | Adaptive missing={adaptive_missing or 'none'}; PCC missing={pcc_missing or 'none'} | {'PASS' if schema_ok else 'INCOMPLETE'} |",
        "",
        "## API validity and safety interpretation",
        "",
        f"- Adaptive API-valid episodes: **{len(adaptive)-len(adaptive_errors)}/{len(adaptive)}**; PCC API-valid calls: **{len(pcc)-len(pcc_errors)}/{len(pcc)}**.",
        f"- Recorded API error/timeout classes: {error_text}. Error rows remain in raw data and are excluded, never counted as blocked attacks.",
        f"- Unsafe PCC certificates accepted by the checker: **{unsafe_pcc_accepts}** among API-valid unsafe calls.",
        f"- StatefulRuleMonitor versus ePCA: {paired['pairs']} complete valid pairs and {paired['outcome_disagreements']} final safety/utility disagreements.",
        f"- ePCA episodes with an unsafe final effect but zero oracle-unsafe accepted steps: **{len(epca_local_gap)}**. These are reported as a local-transition-versus-cumulative-goal semantic gap, not as checker acceptance of an oracle-unsafe transition.",
        "- `df-benign-admin` is an authorized taint-clearing task. Its generic taint-cleared effect flag is context-independent; BTCR and the adversarial-only UEMR denominator provide the security interpretation.",
        "",
        "## Reproduction commands",
        "",
        "```bash",
        f"PYTHONPATH=. python -m phase4.run adaptive --config configs/{config_name} --traces benchmarks/{trace_name}/traces.jsonl",
        f"PYTHONPATH=. python -m phase4.run pcc --config configs/{config_name} --traces benchmarks/{trace_name}/traces.jsonl",
        f"PYTHONPATH=. python -m phase4.analyze --results-dir results/{'phase4_v2_canonical3' if is_v2 else 'phase4'} --project-root .",
        "PYTHONPATH=. python -m pytest -q",
        "```",
        "",
        "The first two commands require the configured credential environment variables and the frozen relay endpoints. Runs are incremental and resume by stable episode/call identifier.",
        "DeepSeek recovery used an explicit runtime-only endpoint override and a process watchdog; watchdog_timeout rows are API availability failures, not model decisions or blocked actions. The frozen model/config/prompt hashes remain unchanged.",
        "",
        "## Required Phase 4 report items",
        "",
        f"1. API-valid adaptive episodes: **{len(adaptive)-len(adaptive_errors)}/{len(adaptive)}**.",
        "2. Guardrail ASR/UEMR/BTCR/UAAR with numerators, denominators, and Wilson intervals: `reports/phase4_adaptive_summary.md` and `paper_tables/phase4_adaptive_main.tex`.",
        f"3. Model breakdown: `reports/phase4_adaptive_by_model.csv`; frozen models are {', '.join(models)}.",
        f"4. Environment breakdown: `reports/phase4_adaptive_by_environment.csv`; environments are {', '.join(environments)}.",
        "5. StatelessRuleFilter failure modes: listed in the adaptive summary under Main observed failure modes.",
        "6. LLMJudge failure modes: listed in the adaptive summary under Main observed failure modes; judge errors remain API errors.",
        f"7. StatefulRuleMonitor versus ePCA disagreement: **{paired_stateful['outcome_disagreements']}** across {paired_stateful['pairs']} complete valid pairs.",
        "8. Alternative-path success: reported per guardrail in the adaptive summary with Wilson intervals.",
        "9. Representative adaptive trajectories: `reports/phase4_adaptive_cases.md`.",
        "10. Safe certificate valid rate by model: `reports/phase4_pcc_llm_by_model.csv` and `reports/phase4_pcc_llm_summary.md`.",
        f"11. Unsafe certificate checker acceptance: **{unsafe_pcc_accepts}/API-valid unsafe calls**.",
        "12. Proof-generation latency: mean/median/p95 are reported by model in the PCC summary.",
        f"13. Proof-failure impact on benign availability: **{safe_valid}/{safe_total}** valid safe certificates; rejection is availability failure.",
        f"14. ePCA acceptance on identical safe actions: **{epca_accepted}/{len(unique_safe)}** unique safe pairs.",
        "15. PCC-LLM versus ePCA end-to-end latency: PCC generation/e2e and ePCA verification latency are reported in the PCC summary.",
        "16. Pytest: final command is `PYTHONPATH=. python -m pytest -q`; the handoff records the executed pass count.",
        f"17. API errors/timeouts: {error_text}; all are retained in raw JSONL and excluded from metric denominators.",
        "18. Commit hash: created after this audit and reported in the final handoff.",
        "19. Git status: checked after the final checkpoint and reported in the final handoff.",
        "",
    ]
    return "\n".join(lines)


def analyze(results_dir: Path, project_root: Path) -> None:
    adaptive = read_jsonl(results_dir / "adaptive_raw.jsonl")
    pcc = read_jsonl(results_dir / "pcc_llm_raw.jsonl")
    overall = _group_summaries(adaptive, ("guardrail",))
    by_model = _group_summaries(adaptive, ("model", "guardrail"))
    by_environment = _group_summaries(adaptive, ("environment", "guardrail"))
    by_attack_type = _group_summaries(adaptive, ("attack_type", "guardrail"))
    pcc_models = [pcc_model_summary(pcc, model) for model in sorted({row["model"] for row in pcc})]
    reports = project_root / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "phase4_adaptive_summary.md").write_text(adaptive_report(adaptive, overall), encoding="utf-8")
    _write_csv(reports / "phase4_adaptive_by_model.csv", by_model)
    _write_csv(reports / "phase4_adaptive_by_environment.csv", by_environment)
    _write_csv(reports / "phase4_adaptive_by_attack_type.csv", by_attack_type)
    (reports / "phase4_adaptive_cases.md").write_text(cases_report(adaptive), encoding="utf-8")
    (reports / "phase4_pcc_llm_summary.md").write_text(pcc_report(pcc, pcc_models), encoding="utf-8")
    _write_csv(reports / "phase4_pcc_llm_by_model.csv", pcc_models)
    write_adaptive_latex(project_root / "paper_tables/phase4_adaptive_main.tex", overall)
    write_pcc_latex(project_root / "paper_tables/phase4_pcc_llm.tex", pcc_models)
    docs = project_root / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "phase4_validation_report.md").write_text(validation_report(adaptive, pcc, project_root), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze Phase 4 remote LLM experiments")
    parser.add_argument("--results-dir", type=Path, default=Path("results/phase4"))
    parser.add_argument("--project-root", type=Path, default=Path("."))
    args = parser.parse_args()
    analyze(args.results_dir, args.project_root)
    print("generated Phase 4 reports and paper tables")


if __name__ == "__main__":
    main()
