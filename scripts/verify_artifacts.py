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
    for path in sorted((ROOT / "artifacts").rglob("*")):
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

    result = {
        "status": "fail" if errors else "pass",
        "file_hashes_checked": len(manifest["files"]),
        "saved_json_objects_and_jsonl_rows_parsed": records,
        "stage2": counts,
        "errors": errors,
        "limits": "Integrity and saved-count check only; no calls executed, no effect oracles rerun, no live enforcement or full policy rescoring.",
    }
    print(json.dumps(result, indent=2))
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
