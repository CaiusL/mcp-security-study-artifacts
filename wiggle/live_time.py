"""Live study against mcp-server-time 2026.10.19.

A negative control: two tools and IANA timezone names. The server rejects a
name that is not a zone. The Needed policy then drops zones the tasks never use.
"""

from __future__ import annotations

from pathlib import Path

from wiggle import __version__
from wiggle.live_study import (
    _check,
    _declared,
    _decide,
    _level_rows,
    _narrative,
    _operating_point,
    _write,
)
from wiggle.mcp_client import McpStdio, python_module_command, vendored_python_env
from wiggle.model import Call, Expect, Probe, Scope, Step, Task
from wiggle.normalize import exact_key
from wiggle.policy import LEVELS, build_profile

PACKAGE = "mcp-server-time"
PIN = "2026.10.19"


def run_live_time(out_dir: Path) -> dict:
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    scope = Scope(declared_root="")
    session = McpStdio(python_module_command("mcp_server_time"), env=vendored_python_env())
    try:
        init = session.initialize()
        tool_list = session.list_tools()
        tools = {tool["name"]: tool for tool in tool_list}
        catalog = _tasks()
        train_calls = [call for task in catalog if task.split == "train" for call in _calls(task)]
        profile = build_profile(train_calls)
        probe_list = _probes()
        task_rows, probe_rows = [], []
        for level, _name, _text in LEVELS:
            for task in catalog:
                record = _run(session, _calls(task), task.expect.texts, level, profile, scope, tools)
                task_rows.append(
                    {"level": level, "id": task.id, "split": task.split, "success": record["ok"], "reps": [record]}
                )
            for probe in probe_list:
                probe_rows.append(_probe_row(session, probe, level, profile, scope, tools))
        levels = _level_rows(task_rows, probe_rows)
        _check(levels, task_rows, probe_rows, server_label=f"{PACKAGE}@{PIN}")
        payload = _payload(init, tool_list, profile, levels, probe_rows, task_rows)
        payload["narrative"] = _narrative(payload)
        _write(out_dir, payload)
        return payload
    finally:
        session.close()


def _tasks() -> list[Task]:
    def one(task_id, split, steps, texts):
        return Task(task_id, "time", split, steps, Expect(texts=texts))

    return [
        one("time-now-ny", "train", (Step("get_current_time", pattern="America/New_York"),), ("America/New_York",)),
        one(
            "time-convert",
            "train",
            (Step("convert_time", pattern="America/New_York", dest="UTC", content="09:30"),),
            ("UTC",),
        ),
        one("time-h-now", "heldout", (Step("get_current_time", pattern="America/New_York"),), ("America/New_York",)),
        one(
            "time-h-convert",
            "heldout",
            (Step("convert_time", pattern="America/New_York", dest="UTC", content="15:45"),),
            ("UTC",),
        ),
    ]


def _calls(task: Task) -> list[Call]:
    calls = []
    for step in task.steps:
        if step.tool == "get_current_time":
            calls.append(Call("time", "get_current_time", {"timezone": step.pattern}))
        else:
            calls.append(
                Call(
                    "time",
                    "convert_time",
                    {
                        "source_timezone": step.pattern,
                        "time": step.content,
                        "target_timezone": step.dest,
                    },
                )
            )
    return calls


def _probes() -> list[Probe]:
    def item(probe_id, role, kind, needle, tool, args):
        return Probe(probe_id, "time", role, kind, "text", needle, Call("time", tool, args))

    return [
        item("time-now-ny", "control", "needed", "America/New_York", "get_current_time", {"timezone": "America/New_York"}),
        item("time-paris", "attack", "excess", "Europe/Paris", "get_current_time", {"timezone": "Europe/Paris"}),
        item("time-tokyo", "attack", "excess", "Asia/Tokyo", "convert_time", {
            "source_timezone": "America/New_York",
            "time": "09:30",
            "target_timezone": "Asia/Tokyo",
        }),
        item("time-dotdot", "attack", "boundary", "WIGGLE_CANARY_ZONE", "get_current_time", {"timezone": "../nope"}),
    ]


def _run(session, calls, needles, level, profile, scope, tools) -> dict:
    texts = []
    for call in calls:
        decision = _decide(call, level, profile, scope, tools)
        if not decision.allow:
            return {"rep": 0, "ok": False, "stage": "policy", "reason": decision.reason}
        result = session.call_tool(call.tool, call.args)
        if not result.ok:
            return {"rep": 0, "ok": False, "stage": "server", "reason": (result.error or "")[:180]}
        texts.append(result.text)
    blob = "\n".join(texts)
    ok = all(needle in blob for needle in needles)
    return {"rep": 0, "ok": ok, "stage": "ok" if ok else "oracle", "reason": "" if ok else "oracle"}


def _probe_row(session, probe, level, profile, scope, tools) -> dict:
    decision = _decide(probe.call, level, profile, scope, tools)
    result = None
    server_error = ""
    if decision.allow:
        result = session.call_tool(probe.call.tool, probe.call.args)
        if not result.ok:
            server_error = (result.error or "")[:180]
    effect = bool(result and result.ok and probe.needle in result.text)
    return {
        "id": probe.id,
        "role": probe.role,
        "kind": probe.kind,
        "level": level,
        "needed": exact_key(probe.call) in profile.exact,
        "declared_intent": _decide(probe.call, 1, profile, scope, tools).allow,
        "proxy_denied": "" if decision.allow else decision.reason,
        "server_error": server_error,
        "effect": effect,
        "blocked": not effect,
    }


def _payload(init, tool_list, profile, levels, probe_rows, task_rows) -> dict:
    rows = [row for row in probe_rows if row["level"] == 0]
    reachable = [row for row in rows if row["effect"]]
    needed = [row for row in reachable if row["needed"]]
    inside = [row for row in reachable if row["declared_intent"] and not row["needed"]]
    point = _operating_point(levels)
    return {
        "version": __version__,
        "study": "live-time",
        "package": PACKAGE,
        "pin": PIN,
        "server_info": {
            "name": (init.get("serverInfo") or {}).get("name", ""),
            "version": (init.get("serverInfo") or {}).get("version", ""),
            "protocol": init.get("protocolVersion", ""),
        },
        "declared": _declared(tool_list),
        "profile": {"tools": sorted(profile.tools), "timezones": sorted(profile.timezones)},
        "levels": [{"level": level, "name": name, "rule": text} for level, name, text in LEVELS],
        "curve": levels,
        "operating_point": point,
        "envelope": {
            "lattice": len(rows),
            "reachable": len(reachable),
            "needed_and_reachable": len(needed),
            "reachable_outside_declared_intent": sum(bool(row["effect"]) and not row["declared_intent"] for row in rows),
            "reachable_inside_intent_not_needed": len(inside),
            "inside_intent_excess_ids": sorted(row["id"] for row in inside),
        },
        "probes": probe_rows,
        "tasks": [
            {"level": row["level"], "id": row["id"], "split": row["split"], "success": row["success"]}
            for row in task_rows
        ],
    }
