"""Check full tracked-source coverage without activating fixture links or models."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]


def blob_hash(data):
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def main():
    inventory = json.loads((ROOT / "docs/evidence-inventory.json").read_text())
    errors = []
    summaries = {}
    for study in ("on9", "badagent"):
        rows = inventory[study]
        for row in rows:
            path = ROOT / row["path"]
            if not path.is_file():
                errors.append(f"Missing {row['path']}")
            elif blob_hash(path.read_bytes()) != row["git_blob_sha"]:
                errors.append(f"Source mismatch {row['path']}")
        excluded = [r for r in inventory["excluded"] if r["study"] == ("MCP" if study == "on9" else "BadAgent")]
        links = inventory["fixture_links"] if study == "on9" else []
        for row in links:
            if blob_hash(row["target"].encode()) != row["git_blob_sha"]:
                errors.append(f"Fixture link mismatch {row['path']}")
        covered = len(rows) + len(excluded) + len(links)
        expected = inventory["source_blob_counts"][study]
        if covered != expected:
            errors.append(f"{study}: inventory covers {covered} of {expected} source entries")
        summaries[study] = {
            "source_entries": expected,
            "files_present": len(rows),
            "newly_included": sum(not row["already_present"] for row in rows),
            "fixture_link_records": len(links),
            "excluded_configuration_files": len(excluded),
        }
    recovered = inventory.get("local_recovered", [])
    for row in recovered:
        path = ROOT / row["path"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
            errors.append(f"Local recovery mismatch {row['path']}")
    summaries["local_recovery"] = {
        "files_present": len(recovered),
        "checkpoint_files": sum(row["path"].endswith(".safetensors") for row in recovered),
        "bytes": sum(row["bytes"] for row in recovered),
        "fixture_link_records": len(inventory.get("local_fixture_links", [])),
    }
    for row in inventory.get("local_fixture_links", []):
        if not (ROOT / row["target_in_package"]).is_file():
            errors.append(f"Missing local fixture target {row['target_in_package']}")
    for name, expected in (("fixture-links.json", inventory["fixture_links"]),
                           ("local-fixture-links.json", inventory.get("local_fixture_links", []))):
        if json.loads((ROOT / "docs" / name).read_text()) != expected:
            errors.append(f"Fixture metadata disagrees with inventory: {name}")
    result = {"status": "fail" if errors else "pass", "coverage": summaries, "errors": errors,
              "scope": "Tracked source-file coverage and content integrity; not a numerical replication or proof that unavailable external inputs exist."}
    print(json.dumps(result, indent=2))
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
