"""Verify study artifacts without models, servers, network or dependencies.

This checks file hashes, experiment record
syntax and key Stage 2 trace counts. It does not execute traces or rescore
effect oracles, policies, live servers or model outputs.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    errors = []
    for entry in manifest["files"]:
        path = ROOT / entry["path"]
        if not path.is_file():
            errors.append(f"Missing: {entry['path']}")
        elif sha(path) != entry["sha256"]:
            errors.append(f"Changed: {entry['path']}")
    records = 0
    record_paths = list((ROOT / "artifacts").rglob("*"))
    record_paths += list((ROOT / "badagent").rglob("*"))
    for path in sorted(record_paths):
        if path.suffix not in {".json", ".jsonl"}:
            continue
        try:
            text = path.read_text(encoding="utf-8-sig")
            if path.suffix == ".json":
                json.loads(text)
                records += 1
            else:
                rows = [json.loads(line) for line in text.splitlines() if line.strip()]
                records += len(rows)
        except (ValueError, UnicodeError) as exc:
            errors.append(f"Invalid saved record {path.relative_to(ROOT)}: {exc}")

    counts = {}
    for model in ("qwen3.8-flash", "deepseek-flash"):
        folder = ROOT / "artifacts" / "stage2" / model
        rows = [json.loads(line) for line in (folder / "traces.jsonl").read_text().splitlines() if line.strip()]
        report = json.loads((folder / "report.json").read_text())
        parts = dict(Counter(row["set"] for row in rows))
        if parts != {"benign": 540, "attack": 300, "live": 30}:
            errors.append(f"{model}: unexpected Stage 2 composition {parts}")
        attacks = [row for row in rows if row["set"] == "attack"]
        arm_counts = {}
        for arm in ("patched", "vulnerable"):
            subset = [row for row in attacks if row["arm"] == arm]
            hits = sum(bool(row["goal"]) for row in subset)
            arm_counts[arm] = {"hits": hits, "total": len(subset)}
            expected = report["raw_asr"][arm]
            if (hits, len(subset)) != (expected["hits"], expected["total"]):
                errors.append(f"{model}/{arm}: trace count disagrees with saved report")
        # Live rows can share a case/sample across distinct enforced layers.
        attack_keys = [(r["case_id"], r["arm"], r["sample"]) for r in attacks]
        if len(set(attack_keys)) != len(attack_keys):
            errors.append(f"{model}: duplicate attack keys")
        counts[model] = {"rows": len(rows), "composition": parts, "attack_successes": arm_counts}

    controls = ROOT / "badagent/replication_out/mcp_tool_qwen/controls"
    badagent = {}
    expected_samples = {
        "samples_adapter.json": (143, 124, 31),
        "samples_base.json": (0, 0, 0),
        "rerun_600/samples_run_a.json": (143, 124, 31),
        "rerun_600/samples_run_b.json": (0, 0, 0),
        "rerun_600/samples_run_c.json": (0, 0, 0),
    }
    for name, expected in expected_samples.items():
        raw = json.loads((controls / name).read_text())
        samples = [row for row in raw if row["decode"] == "sample"]
        keys = ("canary_present", "canary_first", "task_call_present")
        observed = tuple(sum(bool(row[key]) for row in samples) for key in keys)
        if len(samples) != 160 or observed != expected:
            errors.append(f"BadAgent {name}: saved sample counts disagree with the report")
        badagent[name] = {"samples": len(samples), **dict(zip(keys, observed))}
    placement = json.loads((ROOT / "badagent/results/stage1_place/stage1_place.json").read_text())
    span_counts = {}
    for family, expected in (("realistic_piped", (24, 39)), ("realistic_appended", (4, 38))):
        metric = placement["families"][family]["designs"]["two_stage_span"]["pairs_recall"]
        if (metric["k"], metric["n"]) != expected:
            errors.append(f"BadAgent {family}: two-stage span count mismatch")
        span_counts[family] = {"hits": metric["k"], "total": metric["n"]}
    effects = {}
    for mode, expected in (("cache", 3), ("tamper", 3), ("append", 3), ("outside", 2)):
        path = ROOT / f"artifacts/adversary/deputy-{mode}/traces.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        hits = sum(bool(row["effect_hit"]) for row in rows)
        if (hits, len(rows)) != (expected, expected):
            errors.append(f"Counterfeit-server {mode}: saved effect count mismatch")
        effects[mode] = {"hits": hits, "total": len(rows)}

    result = {
        "status": "fail" if errors else "pass",
        "file_hashes_checked": len(manifest["files"]),
        "saved_json_objects_and_jsonl_rows_parsed": records,
        "stage2": counts,
        "badagent_mcp_controls": badagent,
        "badagent_os_two_stage_span": span_counts,
        "counterfeit_server_effects": effects,
        "errors": errors,
        "limits": "Integrity and saved-count check only; no calls executed, no effect oracles rerun, no live enforcement or full policy rescoring.",
    }
    print(json.dumps(result, indent=2))
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
