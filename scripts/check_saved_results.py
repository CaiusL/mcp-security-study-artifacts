"""Compare saved study reports with offline recomputation; never rerun agents.

Run from the checkout: python scripts/check_saved_results.py
Recorded Windows paths require Windows path semantics. Widening alone rebuilds
its deterministic stand-in lattice in a temporary directory, as its scorer does.
This is a local reproducibility check, not evidence of a second-machine run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def offline_guard(event, args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.posix_spawn", "os.spawn"}:
        raise PermissionError(f"offline verification blocked {event}")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def read_rows(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def compare(saved, rebuilt, fields=None):
    # Compare the JSON artifact representation (Python tuples serialize as arrays).
    rebuilt = json.loads(json.dumps(rebuilt))
    fields = list(saved) if fields is None else fields
    mismatches = [key for key in fields if key not in rebuilt or saved[key] != rebuilt[key]]
    return {
        "status": "mismatch" if mismatches else "pass",
        "compared_fields": fields,
        "mismatched_fields": mismatches,
        "saved_metrics_sha256": digest({key: saved[key] for key in fields}),
        "recomputed_metrics_sha256": digest({key: rebuilt.get(key) for key in fields}),
    }


def stage2(folder):
    from wiggle import stage2_run as s, stage4

    saved = read_json(folder / "report.json")
    run = read_json(folder / "run.json")
    if os.name != "nt" and ":\\" in run["sandbox"]:
        return {"status": "unsupported", "reason": "Recorded Windows sandbox paths need Windows path semantics."}
    rows = read_rows(folder / "traces.jsonl")
    if len({s._row_key(row) for row in rows}) != len(rows) or not all(s.row_complete(row) for row in rows):
        raise ValueError("Saved final trace file contains duplicate or incomplete runs")
    benign = [s.trace_from_row(row) for row in rows if row["set"] == "benign"]
    attacks = [s.trace_from_row(row) for row in rows if row["set"] == "attack"]
    live_rows = [row for row in rows if row["set"] == "live"]
    live = [s.trace_from_row(row) for row in live_rows]
    tools = read_json(folder / "tools.json")
    grants = read_json(folder / "allowlists.json")
    fx = stage4.fixture_at(Path(run["sandbox"]))
    template, template_info = s.template_text(run["scripted"])
    scans = {"benign": stage4._scan(tools)}
    scans.update({goal.id: stage4._scan(tools, s.render_template(goal, template)) for goal in s.STAGE2_GOALS})
    _, _, benign_scores, attack_scores = s.score_all(benign, attacks, fx, scans, grants["allowlists"], s.tool_index(tools))
    level = s.operating_level(s.ladder_rows(attack_scores, benign_scores, "patched"))["level"]
    by_key = {(score.case_id, score.arm, score.sample): score for score in attack_scores}
    pairs = []
    for row, trace in zip(live_rows, live):
        score = by_key[(trace.case_id, "patched", 0)]
        pairs.append({"case_id": trace.case_id, "layer": row["layer"], "arm": "patched", "sample": 0,
                      "replay_blocks": s._replay_blocks(score, row["layer"], level),
                      "live_goal": trace.goal, "open_goal": bool(score.goal)})
    # Metadata/cost/timing are supplied only to the existing report assembler;
    # they are deliberately outside the fields claimed as independently checked.
    rebuilt = s.assemble_verdict(
        benign=benign, attacks=attacks, benign_scores=benign_scores, attack_scores=attack_scores,
        fx=fx, scans=scans, allowlists=grants["allowlists"], generator_id=grants["generator"],
        live_pairs=pairs, live_traces=live, template_info=template_info, freeze=saved["freeze"],
        servers_info=saved["servers"], scripted=run["scripted"], caller=saved["caller"], cost=saved["cost"],
        rows=rows, counts={"new": 0, "resumed": len(rows), "policy_new": 0, "policy_resumed": len(grants["allowlists"])},
        started_at=datetime.fromisoformat(run["started"]), command_seconds=0, progent=saved.get("progent"),
    )
    fields = ["scans", "scanner_cost", "benign", "operating_point", "curves", "raw_asr", "layer_asr",
              "layers_alone_stacked", "server_check", "utility_heldout", "utility_under_attack",
              "marginal_e", "mcnemar_patched", "over_permission", "over_permission_summary", "live", "live_only"]
    # outside_l5 iterates a set of argument names; Stage 4's bound check likewise
    # compares these entries sorted. Preserve all values, including duplicates.
    for report in (saved, rebuilt):
        report["over_permission"] = [{**row, "outside_l5": sorted(row["outside_l5"])} for row in report["over_permission"]]
    return {**compare(saved, rebuilt, fields), "recorded_sandbox": run["sandbox"],
            "trace_counts": {"benign": len(benign), "attack": len(attacks), "live": len(live)},
            "raw_asr": rebuilt["raw_asr"], "operating_point": rebuilt["operating_point"],
            "utility_heldout": rebuilt["utility_heldout"],
            "comparison_normalization": "Only outside_l5 list order is canonicalized; entries are unchanged.",
            "limits": "Replays saved calls/results and recorded oracle booleans; does not rerun task/effect oracles, agents, servers, human labels, or timing/cost measurement."}


def birth(folder):
    from wiggle import stage2_run as s

    saved = read_json(folder / "record.json")
    goals = [goal for goal in s.STAGE2_GOALS if goal.id in saved["goals"]]
    rebuilt = s._birth_report(read_rows(folder / "records.jsonl"), saved["model"], goals, read_rows(folder / "baseline.jsonl"))
    return {**compare(saved, rebuilt), "pairs": rebuilt["pairs"],
            "widened_beyond_clean": rebuilt["widened_beyond_clean"], "baseline": rebuilt["baseline"]["repeat_added_beyond_clean"],
            "limits": "Reaggregates saved policy comparison records; no policy-generation requests."}


def widening(folder):
    from wiggle import widening as w

    saved = read_json(folder / "report.json")
    run = read_json(folder / "run.json")
    rows = w._collection_rows(folder / "traces.jsonl")
    pilot = ROOT / "artifacts" / "injection-pilot-2"
    pilot_rows = w._pilot_rows(pilot / "traces.jsonl")
    if not run["scripted"]:
        current = w.require_freeze()["sha256"]
        if {run["freeze_sha256"], *(row["freeze_sha256"] for row in rows)} != {current}:
            raise ValueError("Widening traces do not match the current frozen scorer")
    with tempfile.TemporaryDirectory(prefix="wiggle-offline-") as tmp:
        layout = w.make_sandbox(Path(tmp) / "sandbox")
        if layout.has_symlink != saved["symlink_supported"]:
            return {"status": "unsupported", "reason": "Temporary filesystem symlink support differs from the saved lattice."}
        rebuilt = w._assemble(run, rows, pilot_rows, layout, w._pilot_date(pilot))
    return {**compare(saved, rebuilt), "runs": rebuilt["runs"], "soundness": rebuilt["soundness"],
            "limits": "Existing scorer rebases saved traces and reconstructs the deterministic stand-in lattice in an isolated temporary directory; no saved fixture or original report is changed."}


def run_check(name, function, sources):
    before = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources if path.is_file()}
    try:
        result = function()
    except Exception as exc:
        result = {"status": "error", "reason": f"{type(exc).__name__}: {exc}"}
    changed = [name for name, checksum in before.items() if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != checksum]
    if changed:
        result.update(status="error", changed_sources=changed)
    return {"component": name, "inputs_sha256": before, "source_files_unchanged": not changed, **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/verification/saved-results-2026-11-03.json")
    args = parser.parse_args()
    sys.addaudithook(offline_guard)
    try:
        socket.socket()
    except PermissionError:
        pass
    else:
        raise RuntimeError("Socket guard failed")
    from wiggle import stage4

    checks = []
    for arm in ("stage2", "stage2-progent"):
        for model in ("qwen3.8-flash", "deepseek-flash"):
            folder = ROOT / "artifacts" / arm / model
            sources = [folder / name for name in ("report.json", "run.json", "traces.jsonl", "allowlists.json", "tools.json")]
            checks.append(run_check(f"{arm}/{model}", lambda folder=folder: stage2(folder), sources))
    for model in ("qwen3.8-flash", "deepseek-flash"):
        folder = ROOT / "artifacts/stage3-birth" / model
        checks.append(run_check(f"birth/{model}", lambda folder=folder: birth(folder),
                                [folder / name for name in ("record.json", "records.jsonl", "baseline.jsonl")]))
    folder = ROOT / "artifacts/stage3-widening"
    checks.append(run_check("widening", lambda: widening(folder),
                            [folder / name for name in ("report.json", "run.json", "traces.jsonl", "mechanism.json", "freeze.json")]
                            + [ROOT / "artifacts/injection-pilot-2" / name for name in ("traces.jsonl", "report.json")]))
    sources = [ROOT / "artifacts/stage2/qwen3.8-flash" / name for name in ("report.json", "run.json", "traces.jsonl", "allowlists.json")]
    bound = ROOT / "artifacts/stage4/step0.json"
    checks.append(run_check("stage4/step0", lambda: compare(read_json(bound), stage4.bound_record()), [bound, *sources]))
    folder = ROOT / "artifacts/stage4/qwen3.8-flash"
    if (folder / "report.json").is_file():
        checks.append(run_check("stage4/adaptive", lambda: compare(read_json(folder / "report.json"), stage4.score_record(folder)),
                                [folder / name for name in ("report.json", "run.json", "tools.json", "attempts.jsonl")] + sources))
    else:
        checks.append({"component": "stage4/adaptive", "status": "pending", "reason": "No finished report.json exists."})
    failed = any(check["status"] in {"error", "mismatch"} for check in checks)
    record = {"kind": "saved-results-offline-verification", "recorded": datetime.now(timezone.utc).isoformat(),
              "status": "fail" if failed else ("pass" if all(check["status"] == "pass" for check in checks) else "partial"),
              "network_blocked": True, "subprocesses_blocked": True, "socket_guard_tested": True,
              "second_machine_run": False, "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "checks": checks}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    for check in checks:
        print(f"{check['component']}: {check['status']}" + (f" ({check.get('reason', check.get('mismatched_fields'))})" if check['status'] != "pass" else ""))
    print(args.output)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
