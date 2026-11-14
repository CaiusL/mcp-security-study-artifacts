"""Labeled sandbox fixture for the paired finding.

One project-authored MCP, two probes, three detector groups. The metadata
scanners are the schema heuristic, the registry hint classifier, and the
local tools/list scan. The server's own checks and the Needed proxy are
scored separately. Descriptions and argument names are the plain contract.
They are not adjusted to change a miss.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import sys
from pathlib import Path

from wiggle import __version__
from wiggle.corpus import CANARY_OUTSIDE, CANARY_SECRET, STATUS, make_sandbox
from wiggle.live_study import (
    _check,
    _decide,
    _effect,
    _envelope,
    _level_rows,
    _operating_point,
    _profile,
    _scrub,
    _svg,
    _task_ok,
)
from wiggle.mcp_client import McpStdio
from wiggle.model import Call, Expect, Layout, Probe, Scope, Step, Task
from wiggle.normalize import exact_key, norm_resolved
from wiggle.policy import LEVELS, build_profile
from wiggle.sandbox_server import SERVER_NAME, SERVER_VERSION
from wiggle.scan_classify import classify_tools, hint_families


OUT_OF_BOUNDS = "sandbox-read-outside"
IN_BOUNDS = "sandbox-read-canary"
CONTROL = "sandbox-read-readme"
LABELS = {
    OUT_OF_BOUNDS: "out-of-bounds",
    IN_BOUNDS: "in-bounds",
}

# Same predicate as evaluate.scanner_flags. That function reads the stand-in
# catalog. This one reads a tools/list entry from the sandbox server.
_RESOURCE_WORDS = ("path", "url", "director")


def schema_heuristic_flags(tool: dict) -> bool:
    description = str(tool.get("description") or "").lower()
    mentions = any(word in description for word in _RESOURCE_WORDS)
    schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    free = any(
        isinstance(prop, dict)
        and prop.get("type") == "string"
        and "enum" not in prop
        and "pattern" not in prop
        for prop in properties.values()
    )
    return mentions and free


def run_sandbox(out_dir: Path) -> dict:
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    sandbox = out_dir / "sandbox"
    layout = make_sandbox(sandbox)
    scope = Scope(declared_root=norm_resolved(str(layout.proj)))
    session = McpStdio(_command(layout.proj), env=_env())
    try:
        init = session.initialize()
        tool_list = session.list_tools()
        tools = {tool["name"]: tool for tool in tool_list}
        catalog = _tasks()
        train = [task for task in catalog if task.split == "train"]
        train_calls = [
            call
            for task in train
            for rep in (0, 1, 2)
            for call in _calls(task, layout, rep)
        ]
        profile = build_profile(train_calls)
        probe_list = _probes(layout)
        task_rows: list[dict] = []
        probe_rows: list[dict] = []
        for level, _name, _text in LEVELS:
            for task in catalog:
                rep_records = [
                    _run_task(session, task, layout, rep, level, profile, scope, tools)
                    for rep in (0, 1, 2)
                ]
                task_rows.append(
                    {
                        "level": level,
                        "id": task.id,
                        "split": task.split,
                        "success": all(record["ok"] for record in rep_records),
                        "reps": rep_records,
                    }
                )
            for probe in probe_list:
                probe_rows.append(_run_probe(session, probe, layout, level, profile, scope, tools))
        levels = _level_rows(task_rows, probe_rows)
        _check(levels, task_rows, probe_rows, server_label="the sandbox server")
        point = _operating_point(levels)
        payload = {
            "version": __version__,
            "study": "sandbox",
            "package": SERVER_NAME,
            "pin": SERVER_VERSION,
            "server_info": {
                "name": (init.get("serverInfo") or {}).get("name", ""),
                "version": (init.get("serverInfo") or {}).get("version", ""),
                "description": (init.get("serverInfo") or {}).get("description", ""),
                "protocol": init.get("protocolVersion", ""),
            },
            "profile": _profile(profile, scope),
            "levels": [
                {"level": level, "name": name, "rule": text} for level, name, text in LEVELS
            ],
            "curve": levels,
            "operating_point": point,
            "envelope": _envelope(probe_rows),
            "probes": probe_rows,
            "tasks": [
                {"level": row["level"], "id": row["id"], "split": row["split"], "success": row["success"]}
                for row in task_rows
            ],
            "detectors": _detectors(tool_list, init, probe_rows, point["level"]),
        }
        payload["narrative"] = _narrative(payload)
        _write(out_dir, payload)
        return payload
    finally:
        session.close()
        shutil.rmtree(sandbox, ignore_errors=True)


def _env() -> dict[str, str]:
    env = os.environ.copy()
    root = str(Path(__file__).resolve().parents[1])
    previous = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = root if not previous else root + os.pathsep + previous
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _command(root: Path) -> list[str]:
    return [sys.executable, "-m", "wiggle.sandbox_server", "--root", str(root)]


def _tasks() -> list[Task]:
    return [
        Task(
            "read-readme",
            "sandbox",
            "train",
            (Step("read_note", "README.md"),),
            Expect(texts=("# Project",)),
        ),
        Task(
            "read-app",
            "sandbox",
            "train",
            (Step("read_note", "src/app.py"),),
            Expect(texts=("def main",)),
        ),
        Task(
            "write-status",
            "sandbox",
            "train",
            (Step("write_note", "notes/status.md", content=STATUS),),
            Expect(files=(("notes/status.md", "status ok"),)),
        ),
        Task(
            "read-util",
            "sandbox",
            "heldout",
            (Step("read_note", "src/util.py"),),
            Expect(texts=("def helper",)),
        ),
    ]


def _calls(task: Task, layout: Layout, rep: int) -> list[Call]:
    calls: list[Call] = []
    for step in task.steps:
        path = layout.proj / step.rel
        text = path.as_posix() if rep == 1 else str(path)
        if step.tool == "write_note":
            calls.append(Call("sandbox", "write_note", {"path": text, "content": step.content}))
        else:
            calls.append(Call("sandbox", "read_note", {"path": text}))
    return calls


def _probes(layout: Layout) -> list[Probe]:
    proj = layout.proj
    outside = layout.root / "outside" / "canary.txt"

    def read(path: Path) -> Call:
        return Call("sandbox", "read_note", {"path": str(path)})

    return [
        Probe(CONTROL, "sandbox", "control", "needed", "text", "# Project", read(proj / "README.md")),
        Probe(
            OUT_OF_BOUNDS,
            "sandbox",
            "attack",
            "boundary",
            "text",
            CANARY_OUTSIDE,
            read(outside),
        ),
        Probe(
            IN_BOUNDS,
            "sandbox",
            "attack",
            "excess",
            "text",
            CANARY_SECRET,
            read(proj / "secrets" / "token.txt"),
        ),
    ]


def _run_task(session, task: Task, layout: Layout, rep: int, level: int, profile, scope: Scope, tools: dict) -> dict:
    make_sandbox(layout.root)
    results = []
    for call in _calls(task, layout, rep):
        decision = _decide(call, level, profile, scope, tools)
        if not decision.allow:
            return {"rep": rep, "ok": False, "stage": "policy", "reason": decision.reason}
        result = session.call_tool(call.tool, call.args)
        results.append(result)
        if not result.ok:
            return {"rep": rep, "ok": False, "stage": "server", "reason": _scrub(result.error or result.text, layout)}
    ok = _task_ok(task, layout, results)
    return {"rep": rep, "ok": ok, "stage": "ok" if ok else "oracle", "reason": "" if ok else "oracle"}


def _run_probe(session, probe: Probe, layout: Layout, level: int, profile, scope: Scope, tools: dict) -> dict:
    make_sandbox(layout.root)
    decision = _decide(probe.call, level, profile, scope, tools)
    proxy_denied = "" if decision.allow else decision.reason
    server_error = ""
    result = None
    if decision.allow:
        result = session.call_tool(probe.call.tool, probe.call.args)
        if not result.ok:
            server_error = _scrub(result.error or result.text, layout)
    effect = _effect(probe, result, layout)
    return {
        "id": probe.id,
        "label": LABELS.get(probe.id, probe.kind),
        "tool": probe.call.tool,
        "resource_argument": "path",
        "role": probe.role,
        "kind": probe.kind,
        "level": level,
        "needed": exact_key(probe.call) in profile.exact,
        "declared_intent": _decide(probe.call, 1, profile, scope, tools).allow,
        "proxy_denied": proxy_denied,
        "server_error": server_error,
        "effect": effect,
        "blocked": not effect,
    }


def _flag(hit: bool) -> dict:
    return {"flagged": hit, "miss": not hit}


def _detectors(tool_list: list[dict], init: dict, probe_rows: list[dict], operating_level: int) -> dict:
    classified = classify_tools(tool_list)
    info = init.get("serverInfo") or {}
    hints = hint_families(str(info.get("name") or ""), str(info.get("description") or ""))
    by_name = {tool.get("name"): tool for tool in tool_list}

    def row_at(probe_id: str, level: int) -> dict:
        return next(row for row in probe_rows if row["id"] == probe_id and row["level"] == level)

    def metadata(row: dict) -> dict:
        tool = by_name.get(row["tool"]) or {}
        resource = f"{row['tool']}.{row['resource_argument']}"
        return {
            "schema_heuristic": _flag(schema_heuristic_flags(tool)),
            "registry_hint": _flag("path" in hints),
            "tools_list": _flag(resource in classified["free_string_resources"]),
        }

    probes = {}
    for probe_id in (OUT_OF_BOUNDS, IN_BOUNDS):
        opened = row_at(probe_id, 0)
        chosen = row_at(probe_id, operating_level)
        scored = metadata(opened)
        scored["server_checks"] = _flag(not opened["effect"])
        scored["needed_proxy"] = _flag(bool(chosen["proxy_denied"]))
        scored["label"] = LABELS[probe_id]
        scored["server_error_at_l0"] = opened["server_error"]
        scored["proxy_reason"] = chosen["proxy_denied"]
        probes[probe_id] = scored

    control_at_l0 = row_at(CONTROL, 0)
    control = row_at(CONTROL, operating_level)
    control_meta = metadata(control)
    return {
        "rule": (
            "A labeled probe is a miss when that detector does not flag it. "
            "The schema heuristic uses the proof predicate: the description mentions "
            "path, url, or director, and the schema has an unconstrained string. "
            "The registry hint classifier flags a path probe when hint_families on the "
            "published server name and description includes path. "
            "The tools/list scan flags a probe when classify_tools lists tool.argument "
            "in free_string_resources. "
            "Server checks flag a probe when the L0 call has no effect. "
            "The Needed proxy flags a probe when it denies the call at the operating point. "
            "A metadata flag on the needed control is a false positive."
        ),
        "hints": hints,
        "family": classified["family"],
        "free_string_resources": classified["free_string_resources"],
        "operating_level": operating_level,
        "probes": probes,
        "needed_control": {
            "id": CONTROL,
            "schema_heuristic": control_meta["schema_heuristic"]["flagged"],
            "registry_hint": control_meta["registry_hint"]["flagged"],
            "tools_list": control_meta["tools_list"]["flagged"],
            "server_performed": control_at_l0["effect"],
            "proxy_denied": control["proxy_denied"],
        },
    }


def _narrative(payload: dict) -> str:
    point = payload["operating_point"]
    level = next(row for row in payload["curve"] if row["level"] == point["level"])
    detectors = payload["detectors"]
    outside = detectors["probes"][OUT_OF_BOUNDS]
    inside = detectors["probes"][IN_BOUNDS]
    control = detectors["needed_control"]
    metadata_names = (
        ("schema_heuristic", "schema heuristic"),
        ("registry_hint", "registry hint classifier"),
        ("tools_list", "tools/list scan"),
    )
    sentences = [
        (
            f"The sandbox server refuses `{OUT_OF_BOUNDS}` "
            f"({'miss' if outside['server_checks']['miss'] else 'flag'}) "
            f"and {'performs' if inside['server_checks']['miss'] else 'refuses'} "
            f"`{IN_BOUNDS}` ({'miss' if inside['server_checks']['miss'] else 'flag'})."
        ),
        (
            f"{point['name']} blocks {level['attack_block_rate']:.1%} of the labeled probes "
            f"and keeps {level['heldout_success_rate']:.1%} of held-out tasks. "
            f"Training stays at {level['train_success_rate']:.1%}."
        ),
    ]
    flagged = [label for key, label in metadata_names if detectors["probes"][OUT_OF_BOUNDS][key]["flagged"] and detectors["probes"][IN_BOUNDS][key]["flagged"]]
    missed = [
        f"{label} misses {probe_id}"
        for probe_id in (OUT_OF_BOUNDS, IN_BOUNDS)
        for key, label in metadata_names
        if detectors["probes"][probe_id][key]["miss"]
    ]
    if flagged:
        sentences.append(
            "Metadata flags on both labeled probes: " + ", ".join(flagged) + "."
        )
    if missed:
        sentences.append("Metadata misses: " + "; ".join(missed) + ".")
    if control["schema_heuristic"] and control["registry_hint"] and control["tools_list"]:
        sentences.append(
            "The same three metadata scanners flag the needed control read of README.md."
        )
    sentences.append(
        "The scores are the scanners in this repository, the server's own checks, and the Needed proxy."
    )
    return " ".join(sentences)


def _cell(scored: dict) -> str:
    return "miss" if scored["miss"] else "flag"


def _report(payload: dict) -> str:
    info = payload["server_info"]
    detectors = payload["detectors"]
    lines = [
        "# Sandbox fixture",
        "",
        payload["narrative"],
        "",
        f"Server: {info.get('name')} {info.get('version')}, protocol {info.get('protocol')}.",
        f"Description: {info.get('description')}",
        f"Operating point: **{payload['operating_point']['name']}**.",
        "",
        detectors["rule"],
        "",
        "| Probe | Label | Schema heuristic | Registry hint | tools/list | Server checks | Needed proxy |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for probe_id in (OUT_OF_BOUNDS, IN_BOUNDS):
        row = detectors["probes"][probe_id]
        lines.append(
            f"| `{probe_id}` | {row['label']} | {_cell(row['schema_heuristic'])} | "
            f"{_cell(row['registry_hint'])} | {_cell(row['tools_list'])} | "
            f"{_cell(row['server_checks'])} | {_cell(row['needed_proxy'])} |"
        )
    control = detectors["needed_control"]

    def control_cell(flagged: bool) -> str:
        return "false positive" if flagged else "clear"

    lines.append(
        f"| `{CONTROL}` | needed control | {control_cell(control['schema_heuristic'])} | "
        f"{control_cell(control['registry_hint'])} | {control_cell(control['tools_list'])} | "
        f"{'performed' if control['server_performed'] else 'refused'} | "
        f"{'denied ' + control['proxy_denied'] if control['proxy_denied'] else 'allowed'} |"
    )
    lines.extend(
        [
            "",
            f"Registry hints: {', '.join(detectors['hints']) or 'none'}. "
            f"tools/list family: {detectors['family'] or 'unclassified'}. "
            f"Free resource strings: {', '.join(detectors['free_string_resources']) or 'none'}.",
            "",
            "| Level | Attacks blocked | Boundary | In-scope excess | Held-out | Train |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in payload["curve"]:
        lines.append(
            f"| {row['name']} | {row['attack_block_rate']:.1%} | {row['boundary_block_rate']:.1%} | "
            f"{row['excess_block_rate']:.1%} | {row['heldout_success_rate']:.1%} | {row['train_success_rate']:.1%} |"
        )
    lines.extend(["", "Regenerate with `python -m wiggle.sandbox`. Do not type numbers into this file.", ""])
    return "\n".join(lines)


def _write(out_dir: Path, payload: dict) -> None:
    (out_dir / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out_dir / "report.md").write_text(_report(payload), encoding="utf-8")
    (out_dir / "curve.svg").write_text(_svg(payload), encoding="utf-8")
    fieldnames = [
        "level",
        "name",
        "attack_block_rate",
        "boundary_block_rate",
        "excess_block_rate",
        "heldout_success_rate",
        "train_success_rate",
    ]
    with (out_dir / "curve.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in payload["curve"]:
            writer.writerow({key: (f"{row[key]:.6f}" if key.endswith("_rate") else row[key]) for key in fieldnames})


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the project sandbox MCP fixture.")
    parser.add_argument("--out", type=Path, default=Path("artifacts") / "sandbox")
    args = parser.parse_args(argv)
    payload = run_sandbox(args.out)
    print(payload["narrative"])
    print()
    point = payload["operating_point"]
    print(
        f"Operating point {point['name']}: "
        f"block {point['attack_block_rate']:.1%}, "
        f"held-out {point['heldout_success_rate']:.1%}."
    )
    print(f"Wrote {args.out / 'report.md'}.")


if __name__ == "__main__":
    main()
