"""Aggregate archived paper results. Standard library only; no model/tool calls."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def jsonl(relative: str) -> list[dict]:
    with (ROOT / relative).open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def csv_rows(relative: str) -> list[dict]:
    with (ROOT / relative).open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def aggregate() -> dict:
    models = ("gpt-5.5", "deepseek-v4-pro")
    adaptive = jsonl("results/phase4_v2_canonical3/adaptive_raw.jsonl")
    check(len(adaptive) == 720, "Adaptive cohort must contain 720 records")
    check(len({r['episode_id'] for r in adaptive}) == 720, "Duplicate adaptive IDs")
    check(all(not r.get("api_error") and r["episode_complete"] for r in adaptive),
          "Adaptive inclusion differs from the manuscript")
    adaptive_summary = {}
    for guardrail in ("RuntimeOnly", "StatelessRuleFilter", "StatefulRuleMonitor", "ePCA"):
        rows = [r for r in adaptive if r["guardrail"] == guardrail]
        adv = [r for r in rows if r["goal_type"] == "adversarial"]
        benign = [r for r in rows if r["goal_type"] == "benign"]
        check(len(rows) == 180 and len(adv) == 108 and len(benign) == 72,
              f"Unexpected cohort size for {guardrail}")
        adaptive_summary[guardrail] = {
            "episodes": len(rows),
            "ASR": [sum(bool(r["attack_goal_success"]) for r in adv), len(adv)],
            "UEMR": [sum(bool(r["unsafe_effect_materialized"]) for r in adv), len(adv)],
            "BTCR": [sum(bool(r["benign_task_completed"]) for r in benign), len(benign)],
        }
    for guardrail in ("StatefulRuleMonitor", "ePCA"):
        check(adaptive_summary[guardrail]["UEMR"] == [0, 108], "Unexpected strong-monitor UEMR")
        check(adaptive_summary[guardrail]["BTCR"] == [72, 72], "Unexpected strong-monitor BTCR")

    archive = jsonl("results/phase4_v2_pcc_canonical/pcc_llm_raw.jsonl")
    pcc = [r for r in archive if r["model"] in models]
    check(len(pcc) == 720 and all(not r.get("api_error") for r in pcc), "PCC inclusion changed")
    pcc_summary = {}
    templates: dict[str, set[str]] = {"safe": set(), "unsafe": set()}
    for row in pcc:
        action = {k: v for k, v in row["action"].items() if k != "session_id"}
        semantic = json.dumps([row["environment"], row["state"], action], sort_keys=True)
        templates[row["safe_or_unsafe"]].add(semantic)
    check({k: len(v) for k, v in templates.items()} == {"safe": 8, "unsafe": 11},
          "Semantic-template coverage changed")
    for model, expected in zip(models, (148, 144)):
        safe = [r for r in pcc if r["model"] == model and r["safe_or_unsafe"] == "safe"]
        unsafe = [r for r in pcc if r["model"] == model and r["safe_or_unsafe"] == "unsafe"]
        accepted = sum(bool(r["certificate_valid"]) for r in safe)
        epca = sum(bool(r["epca_accepted"]) for r in safe)
        check(len(safe) == len(unsafe) == 180 and accepted == expected and epca == 180,
              f"Certificate acceptance differs for {model}")
        check(not any(r["certificate_valid"] or r["epca_accepted"] for r in unsafe),
              "Unexpected unsafe certificate acceptance")
        pcc_summary[model] = {
            "PCC_safe_accepted": [accepted, len(safe)], "ePCA_safe_accepted": [epca, len(safe)],
            "PCC_unsafe_accepted": [0, len(unsafe)], "ePCA_unsafe_accepted": [0, len(unsafe)],
            "safe_certificate_mean_e2e_ms": statistics.fmean(r["end_to_end_latency"] for r in safe),
            "safe_local_epca_mean_ms": statistics.fmean(r["epca_verification_latency"] for r in safe),
            "safe_rejection_reasons": dict(Counter(r["failure_reason"] for r in safe if not r["certificate_valid"])),
        }

    deterministic = jsonl("results/phase2_v2/raw_results.jsonl")
    reference = [r for r in deterministic if r["condition"] == "NoGuard"]
    check(len(reference) == 640, "Unexpected deterministic trace count")
    check(sum(bool(r["adversarial"]) for r in reference) == 500, "Unexpected adversarial trace count")
    steps = [s for r in reference for s in r["steps"]]
    check(len(steps) == 1257, "Unexpected action-record count")

    pairs = csv_rows("reports/current/phase4_v2_policy_vs_oracle.csv")
    check(len(pairs) == 863, "Unexpected recorded pair count")
    disagreements = sum(r["decision_disagreement"].lower() == "true" for r in pairs)
    check(disagreements == 0, "Recorded monitor disagreement")
    occurrences = sum(int(r["occurrence_count"]) for r in pairs)
    check(occurrences == 3966, "Unexpected pair occurrence count")
    by_pair = {r["pair_id"]: r for r in pairs}
    for guardrail in ("StatefulRuleMonitor", "ePCA"):
        violations = 0
        for row in adaptive:
            if row["guardrail"] != guardrail or row["goal_type"] != "adversarial":
                continue
            materialized = False
            for turn in row["trajectory"]:
                if not turn.get("executed") or turn.get("oracle_safe") is None:
                    continue
                payload = {"environment": row["environment"], "state": turn["state_before"],
                           "principal_id": turn["principal_id"], "action": turn["action"]}
                key = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                                separators=(",", ":")).encode()).hexdigest()
                check(key in by_pair, "Executed transition missing from archived invariant analysis")
                materialized |= bool(by_pair[key]["encoded_violations"])
            violations += int(materialized)
        check(violations == 0, "Unexpected recorded PVMR")
        adaptive_summary[guardrail]["PVMR_from_archived_invariants"] = [violations, 108]

    mutation = csv_rows("results/supplemental_v2/mutation_testing.csv")
    witnessed = [r for r in mutation if int(r["discriminating_witnesses"]) > 0]
    rules = {(r["environment"], r["invariant"]) for r in mutation}
    covered = {(r["environment"], r["invariant"]) for r in witnessed}
    check(len(rules) == 23 and len(covered) == 10, "Omission witness coverage changed")
    mutation_summary = {}
    for monitor in ("StatefulRuleMonitor", "ePCA"):
        for mode in ("python_omission", "smt_omission", "common_mode_omission"):
            group = [r for r in witnessed if r["monitor"] == monitor and r["mutation_mode"] == mode]
            check(len(group) == 10, "Unexpected number of witnessed deletion configurations")
            escaped = sum(int(r["unsafe_actions_accepted"]) > 0 for r in group)
            mutation_summary[f"{monitor}/{mode}"] = {
                "rules_with_unsafe_acceptance": escaped, "witnessed_rules": len(group),
                "rules_with_error": sum(int(r["decision_errors"]) > 0 for r in group),
            }
            if monitor == "ePCA":
                check(escaped == (10 if mode == "common_mode_omission" else 0), "Omission result changed")

    return {
        "scope": "Archived-result aggregation only; no new experiments, model calls, or simulator execution.",
        "adaptive": adaptive_summary,
        "pcc": pcc_summary,
        "pcc_excluded_models": dict(Counter(r["model"] for r in archive if r["model"] not in models)),
        "semantic_tuples": {k: len(v) for k, v in templates.items()},
        "deterministic": {"traces": 640, "adversarial": 500, "benign": 140, "action_records": len(steps)},
        "recorded_pair_comparison": {"pairs": len(pairs), "occurrences": occurrences, "disagreements": disagreements},
        "omission_study": {"rules": len(rules), "witnessed_rules": len(covered), "configurations": len(mutation), "results": mutation_summary},
        "limits": "Repeated semantic templates; API-valid included cohort rather than attempt census; typed simulators; historical timing host not fully reconstructed.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build/reproduction")
    args = parser.parse_args()
    out = args.output_dir.resolve()
    if out == ROOT or out in ROOT.parents:
        parser.error("The repository root and its ancestors are not output directories")
    # Never overwrite archived results or an existing paper report directory.
    for protected in (ROOT / "results", ROOT / "reports", ROOT / "benchmarks", ROOT / "epca"):
        if out == protected or protected in out.parents:
            parser.error("Use build/ or a separate temporary directory for regenerated outputs")
    result = aggregate()
    out.mkdir(parents=True, exist_ok=True)
    from benchmark.analyze import analyze as analyze_benchmark
    from phase3.analyze import analyze as analyze_pcc
    analyze_benchmark(ROOT / "results/phase2_v2/raw_results.jsonl", ROOT / "benchmarks/tdsc_v2/traces.jsonl", out)
    analyze_pcc(ROOT / "results/phase3_v2", out)
    (out / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    text = "# Archived paper-result reproduction\n\nNo new experiments or model calls.\n\n"
    text += "| Guardrail | Adaptive UEMR | Adaptive BTCR |\n|---|---:|---:|\n"
    for name, row in result["adaptive"].items():
        text += f"| {name} | {'/'.join(map(str, row['UEMR']))} | {'/'.join(map(str, row['BTCR']))} |\n"
    text += "\n| Model | Safe PCC | Safe ePCA |\n|---|---:|---:|\n"
    for name, row in result["pcc"].items():
        text += f"| {name} | {'/'.join(map(str, row['PCC_safe_accepted']))} | {'/'.join(map(str, row['ePCA_safe_accepted']))} |\n"
    text += "\n640 deterministic traces; 8 safe/11 unsafe certificate templates; 0/863 recorded monitor disagreements; omission witnesses for 10/23 rules.\n\nSee summary.json for scope, omission counts, and archived timing.\n"
    (out / "README.md").write_text(text, encoding="utf-8")
    print(json.dumps({"status": "PASS", "output_dir": str(out), "adaptive_episodes": 720, "pcc_calls_included": 720, "semantic_tuples": result["semantic_tuples"]}, indent=2))


if __name__ == "__main__":
    main()
