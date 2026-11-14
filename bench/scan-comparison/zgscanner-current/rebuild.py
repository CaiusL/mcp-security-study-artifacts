"""Rebuild the five bench captures as zgScanner static tools-json inputs.

Reads the committed control-review captures (`../control/<host>/control.json`,
the richest live capture from the 2026-10 scanner bench) and writes one
`captures/<host>.json` in the shape `wiggle.zgscanner.discover.load_tools_json`
expects. Served-skill resources (`skill://` URIs) get their markdown bodies
attached from the control dir, so the skill checks (SK*) run on a static
re-scan. No network is used.

    python bench/scan-comparison/zgscanner-current/rebuild.py

Then scan each capture with the current catalog (see README.md).
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROL = HERE.parent / "control"
CAPTURES = HERE / "captures"

HOSTS = ["api.blvkware.dev", "mcp.aikstockdata.com", "mcp.veterical.com", "vuntum.com", "wealthmcp.ai"]


def _list(value, key):
    if isinstance(value, dict):
        return value.get(key) or []
    return value if isinstance(value, list) else []


def build(host: str) -> dict:
    d = json.loads((CONTROL / host / "control.json").read_text(encoding="utf-8-sig"))
    init = d.get("initialize") or {}
    resources = []
    for r in _list(d.get("resources"), "resources"):
        res = {k: r.get(k) for k in ("uri", "name", "title", "mimeType", "description") if r.get(k) is not None}
        if str(r.get("uri") or "").startswith("skill://"):
            body = CONTROL / host / f"SKILL-{r.get('name')}.md"
            if body.is_file():
                res["contents"] = [{"mimeType": "text/markdown", "text": body.read_text(encoding="utf-8")}]
        resources.append(res)
    return {
        "name": host,
        "transport": "http",
        "serverInfo": init.get("serverInfo") or {},
        "instructions": init.get("instructions") or "",
        "capabilities": init.get("capabilities") or {},
        "tools": _list(d.get("tools"), "tools"),
        "prompts": _list(d.get("prompts"), "prompts"),
        "resources": resources,
    }


def main() -> None:
    CAPTURES.mkdir(parents=True, exist_ok=True)
    for host in HOSTS:
        block = build(host)
        (CAPTURES / f"{host}.json").write_text(json.dumps({"servers": [block]}, indent=1), encoding="utf-8")
        skills = [r["uri"] for r in block["resources"] if "contents" in r]
        print(f"{host}: tools={len(block['tools'])} resources={len(block['resources'])} served_skills={skills}")
    print(f"wrote {len(HOSTS)} captures to {CAPTURES}")


if __name__ == "__main__":
    main()
