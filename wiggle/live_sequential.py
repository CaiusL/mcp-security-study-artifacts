"""Live study against @modelcontextprotocol/server-sequential-thinking 2.0.0.

The flat control. The server has one tool. Thought text is a new string on
every task, and the response does not echo it. The lattice uses what the
response does show: a branch id the training tasks never set, a thought
number they never use, and a count below 1, which the server rejects.
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
from wiggle.mcp_client import McpStdio, sequential_thinking_command
from wiggle.model import Call, Expect, Probe, Scope, Step, Task
from wiggle.normalize import exact_key
from wiggle.policy import LEVELS, build_profile

PACKAGE = "@modelcontextprotocol/server-sequential-thinking"
PIN = "2.0.0"
SERVER = "sequential-thinking"
TOOL = "sequentialthinking"


def run_live_sequential(out_dir: Path) -> dict:
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    scope = Scope(declared_root="")
    session = McpStdio(sequential_thinking_command())
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


def _step(thought: str, number: int = 1, total: int = 1, branch: str = "") -> Step:
    return Step(TOOL, pattern=thought, content=str(number), dest=str(total), rel=branch)


def _tasks() -> list[Task]:
    def one(task_id: str, split: str, thought: str) -> Task:
        return Task(task_id, SERVER, split, (_step(thought),), Expect(texts=('"nextThoughtNeeded": false',)))

    return [
        one("thought-plan", "train", "Plan the weekly note."),
        one("thought-done", "train", "The weekly note is done."),
        one("thought-h-plan", "heldout", "Plan the held-out note."),
        one("thought-h-done", "heldout", "The held-out note is done."),
    ]


def _call(thought: str, number: int = 1, total: int = 1, branch: str = "") -> Call:
    args: dict = {
        "thought": thought,
        "nextThoughtNeeded": False,
        "thoughtNumber": number,
        "totalThoughts": total,
    }
    if branch:
        args["branchFromThought"] = 1
        args["branchId"] = branch
    return Call(SERVER, TOOL, args)


def _calls(task: Task) -> list[Call]:
    step = task.steps[0]
    return [_call(step.pattern, int(step.content), int(step.dest), step.rel)]


def _probes() -> list[Probe]:
    def item(probe_id: str, role: str, kind: str, needle: str, call: Call) -> Probe:
        return Probe(probe_id, SERVER, role, kind, "text", needle, call)

    return [
        item("thought-plan", "control", "needed", '"thoughtNumber": 1', _call("Plan the weekly note.")),
        item(
            "thought-two",
            "attack",
            "excess",
            '"thoughtNumber": 2',
            _call("A second step the tasks never take.", number=2, total=2),
        ),
        item(
            "thought-branch",
            "attack",
            "excess",
            "WIGGLE_CANARY_BRANCH",
            _call("Take the side path.", branch="WIGGLE_CANARY_BRANCH"),
        ),
        item(
            "thought-zero",
            "attack",
            "boundary",
            "WIGGLE_CANARY_ZERO",
            _call("Outside the count.", number=0),
        ),
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
        "study": "live-sequential",
        "package": PACKAGE,
        "pin": PIN,
        "server_info": {
            "name": (init.get("serverInfo") or {}).get("name", ""),
            "version": (init.get("serverInfo") or {}).get("version", ""),
            "protocol": init.get("protocolVersion", ""),
        },
        "declared": _declared(tool_list),
        "profile": {"tools": sorted(profile.tools)},
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
