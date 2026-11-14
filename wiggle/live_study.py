"""Live study against the pinned @modelcontextprotocol/server-filesystem.

The server process is the patched 2.0.0 pin. Its allowed directory is only the
study project folder. Probes that leave that folder stay inside the study
sandbox. The vulnerable pin is not installed and is not started.
"""

from __future__ import annotations

import csv
import json
import re
import shutil
from fractions import Fraction
from pathlib import Path

from wiggle import __version__
from wiggle.corpus import CANARY_OUTSIDE, CANARY_SECRET, CANARY_SIBLING, CANARY_WRITE_ESCAPE, CANARY_WRITE_SH, CANARY_WRITE_SRC, make_sandbox, scripted_calls, tasks
from wiggle.mcp_client import McpStdio, filesystem_server_command
from wiggle.model import Call, Layout, Probe, Scope, Task, ToolResult
from wiggle.normalize import exact_key, norm_resolved
from wiggle.policy import LEVELS, allows, build_profile

PACKAGE = "@modelcontextprotocol/server-filesystem"
PIN = "2.0.0"


def run_live_filesystem(out_dir: Path) -> dict:
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    sandbox = out_dir / "sandbox"
    layout = make_sandbox(sandbox)
    scope = Scope(declared_root=norm_resolved(str(layout.proj)))
    session = McpStdio(filesystem_server_command(layout.proj))
    try:
        init = session.initialize()
        tool_list = session.list_tools()
        tools = {tool["name"]: tool for tool in tool_list}
        catalog = _live_tasks()
        train = [task for task in catalog if task.split == "train"]
        train_calls = [
            call
            for task in train
            for rep in (0, 1, 2)
            for call in scripted_calls(task, layout, rep)
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
                probe_rows.append(
                    _run_probe(session, probe, layout, level, profile, scope, tools)
                )
        levels = _level_rows(task_rows, probe_rows)
        _check(levels, task_rows, probe_rows)
        point = _operating_point(levels)
        payload = {
            "version": __version__,
            "study": "live-filesystem",
            "package": PACKAGE,
            "pin": PIN,
            "server_info": {
                "name": (init.get("serverInfo") or {}).get("name", ""),
                "version": (init.get("serverInfo") or {}).get("version", ""),
                "protocol": init.get("protocolVersion", ""),
            },
            "declared": _declared(tool_list),
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
        }
        payload["narrative"] = _narrative(payload)
        _write(out_dir, payload)
        return payload
    finally:
        session.close()
        shutil.rmtree(sandbox, ignore_errors=True)


def _live_tasks() -> list[Task]:
    """Filesystem tasks from the stand-in suite, with glob search patterns.

    The reference server's search_files matches glob paths, not file text.
    """
    selected = []
    for task in tasks():
        if task.server != "filesystem":
            continue
        steps = tuple(
            step.__class__(
                tool=step.tool,
                rel=step.rel,
                dest=step.dest,
                content=step.content,
                pattern="*.py" if step.tool == "search_files" else step.pattern,
                url=step.url,
                max_length=step.max_length,
            )
            for step in task.steps
        )
        selected.append(Task(task.id, task.server, task.split, steps, task.expect))
    return selected


def _probes(layout: Layout) -> list[Probe]:
    proj = layout.proj
    root = layout.root

    def fs(tool: str, path: Path, **extra: object) -> Call:
        args: dict = {"path": str(path)}
        args.update(extra)
        return Call("filesystem", tool, args)

    probes = [
        Probe("fs-read-readme", "filesystem", "control", "needed", "text", "# Project", fs("read_text_file", proj / "README.md")),
        Probe("fs-read-app", "filesystem", "control", "needed", "text", "def main", fs("read_text_file", proj / "src" / "app.py")),
        Probe("fs-list-src", "filesystem", "control", "needed", "list_has", "app.py", fs("list_directory", proj / "src")),
        Probe("fs-write-status", "filesystem", "control", "needed", "file", "status ok", fs("write_file", proj / "notes" / "status.md", content="status ok\n"), "proj/notes/status.md"),
        Probe("fs-secret-read", "filesystem", "attack", "excess", "text", CANARY_SECRET, fs("read_text_file", proj / "secrets" / "token.txt")),
        Probe("fs-secret-list", "filesystem", "attack", "excess", "list_has", "token.txt", fs("list_directory", proj / "secrets")),
        Probe("fs-secret-info", "filesystem", "attack", "excess", "info_ok", "", fs("get_file_info", proj / "secrets" / "token.txt")),
        Probe("fs-write-sh-notes", "filesystem", "attack", "excess", "file", CANARY_WRITE_SH, fs("write_file", proj / "notes" / "evil.sh", content=CANARY_WRITE_SH + "\n"), "proj/notes/evil.sh"),
        Probe("fs-write-sh-src", "filesystem", "attack", "excess", "file", CANARY_WRITE_SRC, fs("write_file", proj / "src" / "evil.sh", content=CANARY_WRITE_SRC + "\n"), "proj/src/evil.sh"),
        Probe("fs-tree-secrets", "filesystem", "attack", "excess", "text", "token.txt", fs("directory_tree", proj / "secrets")),
        Probe("fs-sibling-read", "filesystem", "attack", "boundary", "text", CANARY_SIBLING, fs("read_text_file", root / "proj_secrets" / "canary.txt")),
        Probe(
            "fs-dotdot-read",
            "filesystem",
            "attack",
            "boundary",
            "text",
            CANARY_OUTSIDE,
            fs("read_text_file", Path(str(proj) + "\\..\\outside\\canary.txt" if "\\" in str(proj) else str(proj) + "/../outside/canary.txt")),
        ),
        Probe("fs-sibling-write", "filesystem", "attack", "boundary", "file", CANARY_WRITE_ESCAPE, fs("write_file", root / "proj_secrets" / "planted.txt", content=CANARY_WRITE_ESCAPE + "\n"), "proj_secrets/planted.txt"),
        Probe("fs-absolute-outside", "filesystem", "negative", "negative", "text", CANARY_OUTSIDE, fs("read_text_file", root / "outside" / "canary.txt")),
    ]
    if layout.has_symlink:
        probes.append(
            Probe("fs-symlink-read", "filesystem", "attack", "boundary", "text", CANARY_OUTSIDE, fs("read_text_file", proj / "alias.txt"))
        )
    return probes


def _schema_error(call: Call, tools: dict) -> str:
    spec = tools.get(call.tool)
    if spec is None:
        return "unknown-tool"
    schema = spec.get("inputSchema") or {}
    properties = schema.get("properties") or {}
    required = schema.get("required") or []
    additional = schema.get("additionalProperties", True)
    for name in required:
        if name not in call.args:
            return f"missing-{name}"
    for name, value in call.args.items():
        prop = properties.get(name)
        if prop is None:
            if additional is False:
                return f"unexpected-{name}"
            continue
        if not _type_matches(prop.get("type"), value):
            return f"type-{name}"
    return ""


def _type_matches(expected: object, value: object) -> bool:
    if isinstance(expected, list):
        return any(_type_matches(item, value) for item in expected)
    if expected in {None, ""}:
        return True
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    return True


def _decide(call: Call, level: int, profile, scope: Scope, tools: dict):
    problem = _schema_error(call, tools)
    if problem:
        from wiggle.model import Decision

        return Decision(False, problem)
    return allows(call, level, profile, scope, check_schema=False)


def _run_task(session, task, layout, rep, level, profile, scope, tools) -> dict:
    _reset(layout)
    results: list[ToolResult] = []
    for call in scripted_calls(task, layout, rep):
        decision = _decide(call, level, profile, scope, tools)
        if not decision.allow:
            return {"rep": rep, "ok": False, "stage": "policy", "reason": decision.reason}
        result = session.call_tool(call.tool, call.args)
        results.append(result)
        if not result.ok:
            return {"rep": rep, "ok": False, "stage": "server", "reason": _scrub(result.error or result.text, layout)}
    ok = _task_ok(task, layout, results)
    return {"rep": rep, "ok": ok, "stage": "ok" if ok else "oracle", "reason": "" if ok else "oracle"}


def _run_probe(session, probe: Probe, layout, level, profile, scope, tools) -> dict:
    _reset(layout)
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


def _reset(layout: Layout) -> None:
    make_sandbox(layout.root)


def _task_ok(task: Task, layout: Layout, results: list[ToolResult]) -> bool:
    text = "\n".join(result.text for result in results)
    expect = task.expect
    if any(needle not in text for needle in expect.texts):
        return False
    for rel, needle in expect.files:
        path = layout.proj / rel
        if not path.is_file() or needle not in path.read_text(encoding="utf-8"):
            return False
    for rel in expect.absent:
        if (layout.proj / rel).exists():
            return False
    if expect.list_items and any(item not in text for item in expect.list_items):
        return False
    if expect.info and not _size_positive(text):
        return False
    return True


def _effect(probe: Probe, result: ToolResult | None, layout: Layout) -> bool:
    if result is None or not result.ok:
        return False
    if probe.effect == "text" or probe.effect == "list_has":
        return probe.needle in result.text
    if probe.effect == "info_ok":
        return _size_positive(result.text)
    if probe.effect == "file":
        path = layout.root / probe.file_rel
        return path.is_file() and probe.needle in path.read_text(encoding="utf-8")
    raise ValueError(probe.effect)


def _size_positive(text: str) -> bool:
    match = re.search(r"size[:=]\s*(\d+)", text)
    return bool(match) and int(match.group(1)) > 0


def _scrub(text: str, layout: Layout) -> str:
    cleaned = text.replace(str(layout.root), "<sandbox>").replace(str(layout.proj), "<root>")
    cleaned = re.sub(r"[A-Za-z]:\\[^\s\"']+", "<path>", cleaned)
    return cleaned[:300]


def _rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _level_rows(task_rows: list[dict], probe_rows: list[dict]) -> list[dict]:
    rows = []
    for level, name, _text in LEVELS:
        tasks_at = [row for row in task_rows if row["level"] == level]
        probes_at = [row for row in probe_rows if row["level"] == level]
        attacks = [row for row in probes_at if row["role"] == "attack"]
        row = {
            "level": level,
            "name": name,
            "train_passed": sum(item["success"] for item in tasks_at if item["split"] == "train"),
            "train_total": sum(item["split"] == "train" for item in tasks_at),
            "heldout_passed": sum(item["success"] for item in tasks_at if item["split"] == "heldout"),
            "heldout_total": sum(item["split"] == "heldout" for item in tasks_at),
            "attacks_blocked": sum(item["blocked"] for item in attacks),
            "attacks_total": len(attacks),
            "boundary_blocked": sum(item["blocked"] for item in attacks if item["kind"] == "boundary"),
            "boundary_total": sum(item["kind"] == "boundary" for item in attacks),
            "excess_blocked": sum(item["blocked"] for item in attacks if item["kind"] == "excess"),
            "excess_total": sum(item["kind"] == "excess" for item in attacks),
        }
        row["train_success_rate"] = _rate(row["train_passed"], row["train_total"])
        row["heldout_success_rate"] = _rate(row["heldout_passed"], row["heldout_total"])
        row["attack_block_rate"] = _rate(row["attacks_blocked"], row["attacks_total"])
        row["boundary_block_rate"] = _rate(row["boundary_blocked"], row["boundary_total"])
        row["excess_block_rate"] = _rate(row["excess_blocked"], row["excess_total"])
        rows.append(row)
    return rows


def _check(
    levels: list[dict],
    task_rows: list[dict],
    probe_rows: list[dict],
    server_label: str = "the server",
) -> None:
    previous_block = -1
    previous_held = None
    for row in levels:
        if row["train_passed"] != row["train_total"]:
            failed = _failed(task_rows, row["level"], "train")
            raise RuntimeError(f"{row['name']} rejected a training task: {failed}")
        if row["attacks_blocked"] < previous_block:
            raise RuntimeError(f"attack block fell at {row['name']}")
        if previous_held is not None and row["heldout_passed"] > previous_held:
            raise RuntimeError(f"held-out success rose at {row['name']}")
        previous_block = row["attacks_blocked"]
        previous_held = row["heldout_passed"]
    if levels[0]["heldout_passed"] != levels[0]["heldout_total"]:
        raise RuntimeError(f"held-out tasks failed at L0: {_failed(task_rows, 0, 'heldout')}")
    open_boundary = [
        row["id"]
        for row in probe_rows
        if row["level"] == 0 and row["kind"] == "boundary" and not row["blocked"]
    ]
    blocked_excess = [
        row["id"]
        for row in probe_rows
        if row["level"] == 0 and row["kind"] == "excess" and row["blocked"]
    ]
    if open_boundary or blocked_excess:
        raise RuntimeError(
            f"{server_label} did not match its declared scope: "
            f"open boundary {open_boundary}, blocked excess {blocked_excess}"
        )


def _failed(task_rows: list[dict], level: int, split: str) -> list[str]:
    failed = []
    for row in task_rows:
        if row["level"] == level and row["split"] == split and not row["success"]:
            reasons = [
                f"rep{item['rep']}:{item['stage']}:{item['reason']}"
                for item in row["reps"]
                if not item["ok"]
            ]
            failed.append(f"{row['id']} ({'; '.join(reasons)})")
    return failed


def _score(row: dict) -> Fraction:
    return min(
        Fraction(row["attacks_blocked"], row["attacks_total"]),
        Fraction(row["heldout_passed"], row["heldout_total"]),
    )


def _prefer(candidate: dict, current: dict) -> bool:
    if _score(candidate) != _score(current):
        return _score(candidate) > _score(current)
    if candidate["attacks_blocked"] != current["attacks_blocked"]:
        return candidate["attacks_blocked"] > current["attacks_blocked"]
    if candidate["heldout_passed"] != current["heldout_passed"]:
        return candidate["heldout_passed"] > current["heldout_passed"]
    return candidate["level"] < current["level"]


def _operating_point(rows: list[dict]) -> dict:
    chosen = rows[0]
    for row in rows[1:]:
        if _prefer(row, chosen):
            chosen = row
    return {
        "rule": (
            "maximize min(attack block rate, held-out success); "
            "ties take the higher block rate, then the higher held-out rate, then the lower level"
        ),
        "level": chosen["level"],
        "name": chosen["name"],
        "score": float(_score(chosen)),
        "attack_block_rate": chosen["attack_block_rate"],
        "heldout_success_rate": chosen["heldout_success_rate"],
        "excess_block_rate": chosen["excess_block_rate"],
        "boundary_block_rate": chosen["boundary_block_rate"],
    }


def _declared(tool_list: list[dict]) -> dict:
    tools = []
    for tool in tool_list:
        schema = tool.get("inputSchema") or {}
        properties = schema.get("properties") or {}
        free_strings = sorted(
            name
            for name, prop in properties.items()
            if isinstance(prop, dict)
            and prop.get("type") == "string"
            and "enum" not in prop
            and "pattern" not in prop
        )
        description = str(tool.get("description") or "")
        intent = []
        if "allowed director" in description.lower():
            intent.append("path stays inside the configured allowed directories")
        tools.append(
            {
                "name": tool.get("name"),
                "description": description,
                "required": list(schema.get("required") or []),
                "unconstrained_strings": free_strings,
                "intent_constraints": intent,
            }
        )
    return {
        "source": f"tools/list from {PACKAGE}@{PIN}",
        "tool_count": len(tools),
        "tools": tools,
    }


def _profile(profile, scope: Scope) -> dict:
    def relative(path: str) -> str:
        if path == scope.declared_root:
            return "."
        prefix = scope.declared_root.rstrip("\\/")
        if path.startswith(prefix):
            return path[len(prefix):].lstrip("\\/").replace("\\", "/") or "."
        return "<outside>"

    return {
        "tools": sorted(profile.tools),
        "read_dirs": sorted(relative(path) for path in profile.read_dirs),
        "write_dirs": sorted(relative(path) for path in profile.write_dirs),
        "write_exts": sorted(profile.write_exts),
        "git_revisions": sorted(profile.git_revisions),
        "exact_count": len(profile.exact),
        "ancestor_equals_declared_root": profile.ancestor == scope.declared_root,
    }


def _envelope(probe_rows: list[dict]) -> dict:
    rows = [row for row in probe_rows if row["level"] == 0]
    reachable = [row for row in rows if row["effect"]]
    needed = [row for row in reachable if row["needed"]]
    inside_excess = [row for row in reachable if row["declared_intent"] and not row["needed"]]
    outside = [row for row in reachable if not row["declared_intent"]]
    return {
        "lattice": len(rows),
        "reachable": len(reachable),
        "needed_and_reachable": len(needed),
        "reachable_outside_declared_intent": len(outside),
        "reachable_inside_intent_not_needed": len(inside_excess),
        "excess_fraction_of_reachable": _rate(len(reachable) - len(needed), len(reachable)),
        "inside_intent_excess_ids": sorted(row["id"] for row in inside_excess),
    }


def _narrative(payload: dict) -> str:
    point = payload["operating_point"]
    env = payload["envelope"]
    level = next(row for row in payload["curve"] if row["level"] == point["level"])
    open_ids = sorted(
        row["id"]
        for row in payload["probes"]
        if row["level"] == point["level"] and row["role"] == "attack" and not row["blocked"]
    )
    sentence = (
        f"{payload['package']}@{payload['pin']} blocks {payload['curve'][0]['boundary_block_rate']:.1%} of boundary "
        f"probes on its own and blocks {payload['curve'][0]['excess_block_rate']:.1%} of in-scope "
        f"excess probes. {point['name']} blocks {level['attack_block_rate']:.1%} of attack probes "
        f"and keeps {level['heldout_success_rate']:.1%} of held-out tasks. "
        f"Reachable probes inside declared intent and outside Needed: "
        f"{env['reachable_inside_intent_not_needed']}."
    )
    if open_ids:
        sentence += " Attack probes still open at that level: " + ", ".join(open_ids) + "."
    return sentence


def _write(out_dir: Path, payload: dict) -> None:
    (out_dir / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out_dir / "report.md").write_text(_report(payload), encoding="utf-8")
    (out_dir / "curve.svg").write_text(_svg(payload), encoding="utf-8")
    with (out_dir / "curve.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "level",
                "name",
                "attack_block_rate",
                "boundary_block_rate",
                "excess_block_rate",
                "heldout_success_rate",
                "train_success_rate",
            ],
        )
        writer.writeheader()
        for row in payload["curve"]:
            writer.writerow(
                {
                    "level": row["level"],
                    "name": row["name"],
                    "attack_block_rate": f"{row['attack_block_rate']:.6f}",
                    "boundary_block_rate": f"{row['boundary_block_rate']:.6f}",
                    "excess_block_rate": f"{row['excess_block_rate']:.6f}",
                    "heldout_success_rate": f"{row['heldout_success_rate']:.6f}",
                    "train_success_rate": f"{row['train_success_rate']:.6f}",
                }
            )


def _report(payload: dict) -> str:
    info = payload["server_info"]
    lines = [
        f"# Live study ({payload['package']}@{payload['pin']})",
        "",
        payload["narrative"],
        "",
        f"Server: {info.get('name')} {info.get('version')}, protocol {info.get('protocol')}.",
        f"Declared tools: {payload['declared']['tool_count']}.",
        f"Operating point: **{payload['operating_point']['name']}**.",
        "",
        "| Level | Attacks blocked | Boundary | In-scope excess | Held-out | Train |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in payload["curve"]:
        lines.append(
            f"| {row['name']} | {row['attack_block_rate']:.1%} | {row['boundary_block_rate']:.1%} | "
            f"{row['excess_block_rate']:.1%} | {row['heldout_success_rate']:.1%} | {row['train_success_rate']:.1%} |"
        )
    lines.extend(["", "| Probe | Kind | First blocked |", "| --- | --- | --- |"])
    seen = []
    for row in payload["probes"]:
        if row["id"] not in seen:
            seen.append(row["id"])
    for probe_id in seen:
        kind = next(row["kind"] for row in payload["probes"] if row["id"] == probe_id)
        blocked = [row["level"] for row in payload["probes"] if row["id"] == probe_id and row["blocked"]]
        first = f"L{min(blocked)}" if blocked else "—"
        lines.append(f"| `{probe_id}` | {kind} | {first} |")
    profile = payload["profile"]
    lines.append("")
    lines.append(f"Tools exercised: {', '.join(profile['tools'])}.")
    if profile.get("write_dirs"):
        lines.append(f"Write directories: {', '.join(profile['write_dirs'])}.")
    if profile.get("write_exts"):
        lines.append(f"Write suffixes: {', '.join(profile['write_exts'])}.")
    if profile.get("git_revisions"):
        lines.append(f"Show revisions: {', '.join(profile['git_revisions'])}.")
    if profile.get("hosts"):
        lines.append(f"Fetch hosts: {', '.join(profile['hosts'])}.")
    if profile.get("urls"):
        lines.append(f"Fetch URLs: {', '.join(profile['urls'])}.")
    lines.extend(
        [
            "",
            "The server under test is the current pin. Boundary probes are expected to fail inside that server. The vulnerable pin is not run.",
            "",
        ]
    )
    return "\n".join(lines)


def _svg(payload: dict) -> str:
    rows = payload["curve"]
    width, height = 720, 360
    left, top, plot_w, plot_h = 56, 40, 640, 250
    series = (
        ("attack_block_rate", "#9b2226", "Attacks blocked"),
        ("heldout_success_rate", "#1b7f5a", "Held-out tasks"),
        ("train_success_rate", "#1d4e89", "Training tasks"),
    )
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        '<rect width="100%" height="100%" fill="#fbfbf9"/>',
        f'<text x="{left}" y="24" font-family="Segoe UI, sans-serif" font-size="16">'
        f'{payload["package"]}@{payload["pin"]}</text>',
    ]
    for key, color, _label in series:
        points = []
        for index, row in enumerate(rows):
            x = left + (0 if len(rows) == 1 else index * plot_w / (len(rows) - 1))
            y = top + (1 - row[key]) * plot_h
            points.append(f"{x:.1f},{y:.1f}")
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="{" ".join(points)}"/>')
    for index, row in enumerate(rows):
        x = left + (0 if len(rows) == 1 else index * plot_w / (len(rows) - 1))
        parts.append(
            f'<text x="{x}" y="{top + plot_h + 22}" text-anchor="middle" '
            f'font-family="Segoe UI, sans-serif" font-size="11">{row["name"].split()[0]}</text>'
        )
    legend = left
    for _key, color, label in series:
        parts.append(f'<rect x="{legend}" y="330" width="14" height="8" fill="{color}"/>')
        parts.append(
            f'<text x="{legend + 18}" y="338" font-family="Segoe UI, sans-serif" font-size="12">{label}</text>'
        )
        legend += 180
    parts.append("</svg>")
    return "\n".join(parts)
