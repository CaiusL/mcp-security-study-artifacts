"""Stage 2 run budget, sized from the pilot 2 measured token use.

No model is called. Token rates are the mean per-run usage in the pilot 2
traces, per run set. Scenario counts are choices for the team, not
measurements. `docs/proposal-stage2-budget.md` is the PROMPT.md amendment
draft that uses this record.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from wiggle.injection import CHANNELS, GOALS, SAMPLE_COUNT, cases
from wiggle.pilot import LIVE_CASE_COUNT, LIVE_LAYERS
from wiggle.replay import wilson

ROOT = Path(__file__).resolve().parents[1]
PILOT_DIR = ROOT / "artifacts" / "injection-pilot-2"
SETS = ("benign", "attack", "live")

# docs/injection-protocol.md, stage 2: five channels, G1-G2b plus the G3 twin.
STAGE2_CHANNELS = ("page", "repo-file", "commit-message", "memory-entity", "description")
STAGE2_GOALS = ("G1", "G1b", "G2", "G2b", "G3")
# docs/archive/plan.md, stage 2 live servers. Fetch stays on the stand-in.
STAGE2_SERVERS = ("filesystem", "git", "memory", "time", "description-fixture")
# Pilot design kept for stage 2: 2 compatible held-out tasks per case, both arms on every case.
TASKS_PER_CASE = len(cases()) // (len(CHANNELS) * len(GOALS))
ARMS = 2
# PROMPT.md holds: "about 1,000 runs".
PROMPT_TARGET_RUNS = 1000
# Proposal: the token cap is this many times the estimate at the measured rate.
HEADROOM = 2


@dataclass(frozen=True)
class Scenario:
    name: str
    models: int
    servers: int
    tasks_per_server: int
    channels: int = len(STAGE2_CHANNELS)
    goals: int = len(STAGE2_GOALS)
    templates: int = 1
    note: str = ""


PILOT_DESIGN = Scenario(
    "pilot-2 design",
    models=1,
    servers=1,
    tasks_per_server=25,
    channels=len(CHANNELS),
    goals=len(GOALS),
    note="Check row: must equal the pilot 2 measured runs and tokens.",
)

SCENARIOS = (
    Scenario("A three models", 3, 5, 30, note="Protocol maximum: 3 models, about 30 tasks per server."),
    Scenario("B two models", 2, 5, 30, note="Cut one model. Keep every server and about 30 tasks."),
    Scenario("C two models, 20 tasks", 2, 5, 20, note="Cut one model and a third of the tasks."),
    Scenario("D two models, no time control", 2, 4, 30, note="Cut one model and the time control server."),
)

# Re-size scenario (2026-11-02): the actual one-model Qwen run plan, with all
# six task groups (filesystem, fetch, git, memory, time, description fixture),
# sized from a measured Stage 2 rate rather than the one-server pilot rate.
QWEN_MEASURED = Scenario(
    "Q one Qwen model, measured rate",
    models=1,
    servers=6,
    tasks_per_server=30,
    note="The actual run plan (540 benign, 300 attack, 30 live, 180 policy), sized from the measured Stage 2 smoke rate.",
)


def measured_rates(traces: Path, report: Path) -> dict:
    """Mean tokens per run for each run set, and per layer (d) policy call."""
    rows = [json.loads(line) for line in traces.read_text(encoding="utf-8").splitlines() if line.strip()]
    rates = {}
    for name in SETS:
        usages = [row["usage"] for row in rows if row.get("set") == name and isinstance(row.get("usage"), dict)]
        if not usages:
            raise SystemExit(f"no token usage for run set {name!r} in {traces}")
        rates[name] = _rate(usages)
    record = json.loads(report.read_text(encoding="utf-8"))
    policy = (record.get("cost") or {}).get("policy") or {}
    if not policy.get("runs_with_usage"):
        raise SystemExit(f"no policy token usage in {report}")
    rates["policy"] = {
        "runs": policy["runs_with_usage"],
        "prompt_tokens": policy["prompt_tokens"],
        "completion_tokens": policy["completion_tokens"],
        "total_tokens": policy["total_tokens"],
        "per_run": policy["total_tokens"] / policy["runs_with_usage"],
        "max_run": None,
    }
    benign = record["benign"]
    rates["heldout_share"] = {"hits": benign["heldout"]["total"], "total": benign["runs"]}
    rates["caller"] = record.get("caller")
    rates["freeze_sha256"] = record.get("freeze_sha256")
    return rates


def _rate(usages: list[dict]) -> dict:
    total = sum(int(usage["total_tokens"]) for usage in usages)
    return {
        "runs": len(usages),
        "prompt_tokens": sum(int(usage["prompt_tokens"]) for usage in usages),
        "completion_tokens": sum(int(usage["completion_tokens"]) for usage in usages),
        "total_tokens": total,
        "per_run": total / len(usages),
        "max_run": max(int(usage["total_tokens"]) for usage in usages),
    }


def measured_agent_rate(traces_dir: Path) -> dict:
    """Mean per-run tokens from the completed benign rows of a Stage 2 run (the smoke)."""
    path = Path(traces_dir) / "traces.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    usages = [row["usage"] for row in rows if row.get("set") == "benign" and isinstance(row.get("usage"), dict)]
    if not usages:
        raise SystemExit(f"no benign token usage in {path}")
    return _rate(usages)


def attack_cases(scenario: Scenario) -> int:
    return scenario.channels * scenario.goals * scenario.templates * TASKS_PER_CASE


def runs(scenario: Scenario) -> dict:
    """Run counts. Samples stay at SAMPLE_COUNT: the protocol never cuts samples."""
    tasks = scenario.servers * scenario.tasks_per_server
    counts = {
        "benign": scenario.models * tasks * SAMPLE_COUNT,
        "attack": scenario.models * attack_cases(scenario) * SAMPLE_COUNT * ARMS,
        "live": scenario.models * LIVE_CASE_COUNT * len(LIVE_LAYERS),
    }
    counts["total"] = sum(counts[name] for name in SETS)
    counts["policy_calls"] = scenario.models * tasks
    return counts


def size(scenario: Scenario, rates: dict, usd_per_million: float | None = None, override_rate: float | None = None) -> dict:
    counts = runs(scenario)
    tokens = {name: round(counts[name] * (override_rate if override_rate is not None else rates[name]["per_run"])) for name in SETS}
    tokens["policy"] = round(counts["policy_calls"] * (override_rate if override_rate is not None else rates["policy"]["per_run"]))
    tokens["total"] = sum(tokens[name] for name in (*SETS, "policy"))
    share = rates["heldout_share"]
    heldout_tasks = round(scenario.servers * scenario.tasks_per_server * share["hits"] / share["total"])
    heldout_runs = heldout_tasks * SAMPLE_COUNT
    interval = wilson(heldout_runs // 2, heldout_runs)
    return {
        "scenario": asdict(scenario),
        "attack_cases": attack_cases(scenario),
        "runs": counts,
        "tokens": tokens,
        "token_cap": tokens["total"] * HEADROOM,
        "usd": None if usd_per_million is None else tokens["total"] / 1_000_000 * usd_per_million,
        "within_prompt_target": counts["total"] <= PROMPT_TARGET_RUNS,
        "heldout_runs_per_model": heldout_runs,
        "heldout_halfwidth_at_half": None if interval is None else (interval["high"] - interval["low"]) / 2,
    }


def tasks_within_target(models: int, servers: int) -> int:
    """Largest tasks per server whose total runs stay within PROMPT_TARGET_RUNS."""
    count = 0
    while runs(Scenario("probe", models, servers, count + 1))["total"] <= PROMPT_TARGET_RUNS:
        count += 1
    return count


def budget_record(pilot_dir: Path = PILOT_DIR, usd_per_million: float | None = None, measured_traces: Path | None = None) -> dict:
    rates = measured_rates(pilot_dir / "traces.jsonl", pilot_dir / "report.json")
    check = size(PILOT_DESIGN, rates)
    measured_total = sum(rates[name]["total_tokens"] for name in (*SETS, "policy"))
    measured_runs = sum(rates[name]["runs"] for name in SETS)
    if check["runs"]["total"] != measured_runs or check["tokens"]["total"] != measured_total:
        raise SystemExit("the pilot 2 design does not reproduce the measured runs and tokens")
    fit = tasks_within_target(2, len(STAGE2_SERVERS))
    scenarios = list(SCENARIOS) + [
        Scenario(
            f"E two models within {PROMPT_TARGET_RUNS} runs",
            2,
            len(STAGE2_SERVERS),
            fit,
            note="Largest tasks per server that keeps the current PROMPT.md target.",
        )
    ]
    sized = [size(scenario, rates, usd_per_million) for scenario in scenarios]
    measured = None
    if measured_traces is not None:
        measured = measured_agent_rate(Path(measured_traces))
        sized.append(size(QWEN_MEASURED, rates, usd_per_million, override_rate=measured["per_run"]))
    return {
        "kind": "stage2-budget",
        "source": str(pilot_dir.relative_to(ROOT)).replace("\\", "/") if pilot_dir.is_relative_to(ROOT) else str(pilot_dir),
        "freeze_sha256": rates["freeze_sha256"],
        "caller": rates["caller"],
        "rates": {name: rates[name] for name in (*SETS, "policy")},
        "heldout_share": rates["heldout_share"],
        "design": {
            "channels": list(STAGE2_CHANNELS),
            "goals": list(STAGE2_GOALS),
            "servers": list(STAGE2_SERVERS),
            "samples": SAMPLE_COUNT,
            "tasks_per_case": TASKS_PER_CASE,
            "arms": ARMS,
            "live_per_model": LIVE_CASE_COUNT * len(LIVE_LAYERS),
            "prompt_target_runs": PROMPT_TARGET_RUNS,
            "headroom": HEADROOM,
        },
        "usd_per_million_tokens": usd_per_million,
        "check": check,
        "measured_agent_rate": None if measured is None else {"source": str(measured_traces), **measured},
        "scenarios": sized,
    }


def _markdown(record: dict) -> str:
    rates = record["rates"]
    design = record["design"]
    caller = record["caller"] or {}
    lines = [
        "# Stage 2 run budget",
        "",
        "Generated by `python -m wiggle.budget`. No model was called. Token rates are measured in "
        f"`{record['source']}` (freeze `{record['freeze_sha256']}`, caller `{caller.get('model_id')}` "
        f"on {caller.get('run_date')}, step cap {caller.get('step_cap')}). "
        "Scenario counts are choices for the team, not measurements. "
        "The amendment draft is `docs/proposal-stage2-budget.md`.",
        "",
        "## Measured rates (pilot 2)",
        "",
        "| Run set | Runs | Prompt tokens | Completion tokens | Tokens per run | Largest run |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name in (*SETS, "policy"):
        row = rates[name]
        largest = "—" if row["max_run"] is None else f"{row['max_run']:,}"
        label = "policy (d) call" if name == "policy" else name
        lines.append(
            f"| {label} | {row['runs']} | {row['prompt_tokens']:,} | {row['completion_tokens']:,} "
            f"| {row['per_run']:,.1f} | {largest} |"
        )
    measured = record.get("measured_agent_rate")
    if measured:
        lines.extend(
            [
                "",
                f"Measured Stage 2 agent rate (`{measured['source']}`, {measured['runs']} benign runs): "
                f"{measured['per_run']:,.1f} tokens per run (largest {measured['max_run']:,}). The measured "
                "scenario below is sized at this rate for every agent run and policy call.",
            ]
        )
    check = record["check"]
    lines.extend(
        [
            "",
            f"Check: the pilot 2 design ({check['attack_cases']} cases) sizes to {check['runs']['total']} runs "
            f"and {check['tokens']['total']:,} tokens. That equals the measured pilot 2 record.",
            "",
            "## Stage 2 design held fixed",
            "",
            f"- Channels ({len(design['channels'])}): {', '.join(design['channels'])}.",
            f"- Goals ({len(design['goals'])}): {', '.join(design['goals'])}.",
            f"- Servers (up to {len(design['servers'])}): {', '.join(design['servers'])}.",
            f"- Samples per case and per task: {design['samples']}. The protocol does not cut samples.",
            f"- Attack cases = channels × goals × templates × {design['tasks_per_case']} tasks per case. "
            f"Each case runs on {design['arms']} arms, as in the pilot.",
            f"- Live validations per model: {design['live_per_model']}. One layer (d) policy call per task per model.",
            f"- Held-out share of benign runs: {record['heldout_share']['hits']} of {record['heldout_share']['total']}, as in the pilot.",
            f"- Token cap = {design['headroom']} × the estimate at the measured rate (proposal).",
            "",
            "## Scenarios",
            "",
            "Runs are per study, all models together. Held-out ± is the Wilson 95% half-width "
            "of one model's pooled held-out utility at a true rate of 0.5 (the widest case).",
            "",
            "| Scenario | Models | Servers | Tasks per server | Attack cases | Benign | Attack | Live | Total runs "
            f"| Within {design['prompt_target_runs']:,} | Tokens (estimate) | Token cap | Held-out runs per model | Held-out ± |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in record["scenarios"]:
        scenario, count, tokens = row["scenario"], row["runs"], row["tokens"]
        lines.append(
            f"| {scenario['name']} | {scenario['models']} | {scenario['servers']} | {scenario['tasks_per_server']} "
            f"| {row['attack_cases']} | {count['benign']:,} | {count['attack']:,} | {count['live']} | {count['total']:,} "
            f"| {'yes' if row['within_prompt_target'] else 'no'} | {tokens['total']:,} | {row['token_cap']:,} "
            f"| {row['heldout_runs_per_model']} | {row['heldout_halfwidth_at_half']:.3f} |"
        )
    lines.extend(["", "Notes:", ""])
    for row in record["scenarios"]:
        lines.append(f"- {row['scenario']['name']}: {row['scenario']['note']}")
    if record["usd_per_million_tokens"] is not None:
        lines.extend(["", f"USD at {record['usd_per_million_tokens']} per million tokens:", ""])
        for row in record["scenarios"]:
            lines.append(f"- {row['scenario']['name']}: {row['usd']:.2f}")
    else:
        lines.extend(["", "No price was passed, so no USD figure is given. Pass `--usd-per-million-tokens`."])
    lines.extend(
        [
            "",
            "## Limits",
            "",
            "- The rates come from one model with thinking off and 3 connected servers. "
            "Stage 2 connects more servers, so each step sends a longer tool list. "
            "Other models also use other tokenizers. Re-measure with a stage 2 smoke run before the full run.",
            "- Stage 2 tasks are not written yet. Longer tasks take more steps than the pilot tasks.",
            "- Attack runs on both arms and 2 tasks per case copy the pilot design. The team can change both.",
            "",
        ]
    )
    return "\n".join(lines)


def write_budget(out_dir: Path, record: dict) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "budget.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (out_dir / "budget.md").write_text(_markdown(record), encoding="utf-8")
    return record


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Stage 2 run budget from the pilot 2 measured cost.")
    parser.add_argument("--pilot", type=Path, default=PILOT_DIR)
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "stage2-budget")
    parser.add_argument("--usd-per-million-tokens", type=float, default=None)
    parser.add_argument("--measured-traces", type=Path, default=None, help="A Stage 2 run dir whose benign rows give the measured agent rate.")
    args = parser.parse_args(argv)
    measured = args.measured_traces.resolve() if args.measured_traces is not None else None
    record = write_budget(args.out, budget_record(args.pilot.resolve(), args.usd_per_million_tokens, measured))
    for row in record["scenarios"]:
        print(f"{row['scenario']['name']}: {row['runs']['total']} runs, {row['tokens']['total']} tokens")
    print(f"Wrote {args.out / 'budget.md'}.")


if __name__ == "__main__":
    main()
