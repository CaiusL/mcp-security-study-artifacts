"""Live study against @modelcontextprotocol/server-memory 2.0.0.

The tools take entity names, not paths. The graph file is fixed by
MEMORY_FILE_PATH inside the sandbox. A pre-seeded Secret entity is reachable
through read, open, and search even though the training tasks never name it.
"""

from __future__ import annotations

import os
from pathlib import Path

from wiggle import __version__
from wiggle.corpus import CANARY_SECRET
from wiggle.live_study import (
    _check,
    _declared,
    _decide,
    _level_rows,
    _narrative,
    _operating_point,
    _write,
)
from wiggle.mcp_client import McpStdio, vendored_python_env
from wiggle.model import Call, Expect, Probe, Scope, Step, Task
from wiggle.normalize import exact_key
from wiggle.policy import LEVELS, build_profile

PACKAGE = "@modelcontextprotocol/server-memory"
PIN = "2.0.0"
SEED = (
    '{"type":"entity","name":"Project","entityType":"work","observations":["tracked work"]}\n'
    '{"type":"entity","name":"Secret","entityType":"credential","observations":["'
    + CANARY_SECRET
    + '"]}\n'
)


def run_live_memory(out_dir: Path) -> dict:
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    graph = out_dir / "memory.jsonl"
    graph.write_text(SEED, encoding="utf-8")
    scope = Scope(declared_root="")
    env = os.environ.copy()
    env.update(vendored_python_env())
    env["MEMORY_FILE_PATH"] = str(graph)
    entry = (
        Path(__file__).resolve().parents[1]
        / "vendor"
        / "mcp"
        / "node_modules"
        / "@modelcontextprotocol"
        / "server-memory"
        / "dist"
        / "index.js"
    )
    session = McpStdio(["node", str(entry)], env=env)
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
                graph.write_text(SEED, encoding="utf-8")
                record = _run(session, _calls(task), task.expect.texts, level, profile, scope, tools)
                task_rows.append(
                    {"level": level, "id": task.id, "split": task.split, "success": record["ok"], "reps": [record]}
                )
            for probe in probe_list:
                graph.write_text(SEED, encoding="utf-8")
                probe_rows.append(_probe_row(session, probe, level, profile, scope, tools))
        levels = _level_rows(task_rows, probe_rows)
        _check(levels, task_rows, probe_rows, server_label=f"{PACKAGE}@{PIN}")
        rows = [row for row in probe_rows if row["level"] == 0]
        reachable = [row for row in rows if row["effect"]]
        needed = [row for row in reachable if row["needed"]]
        inside = [row for row in reachable if row["declared_intent"] and not row["needed"]]
        payload = {
            "version": __version__,
            "study": "live-memory",
            "package": PACKAGE,
            "pin": PIN,
            "server_info": {
                "name": (init.get("serverInfo") or {}).get("name", ""),
                "version": (init.get("serverInfo") or {}).get("version", ""),
                "protocol": init.get("protocolVersion", ""),
            },
            "declared": _declared(tool_list),
            "profile": {
                "tools": sorted(profile.tools),
                "memory_names": sorted(profile.memory_names),
                "memory_queries": sorted(profile.memory_queries),
            },
            "levels": [{"level": level, "name": name, "rule": text} for level, name, text in LEVELS],
            "curve": levels,
            "operating_point": _operating_point(levels),
            "envelope": {
                "lattice": len(rows),
                "reachable": len(reachable),
                "needed_and_reachable": len(needed),
                "reachable_outside_declared_intent": sum(
                    bool(row["effect"]) and not row["declared_intent"] for row in rows
                ),
                "reachable_inside_intent_not_needed": len(inside),
                "inside_intent_excess_ids": sorted(row["id"] for row in inside),
            },
            "probes": probe_rows,
            "tasks": [
                {"level": row["level"], "id": row["id"], "split": row["split"], "success": row["success"]}
                for row in task_rows
            ],
            "note": "Tool arguments have no path. MEMORY_FILE_PATH fixes the graph file. read_graph returns every entity, including ones the tasks never name.",
        }
        payload["narrative"] = _narrative(payload)
        _write(out_dir, payload)
        return payload
    finally:
        session.close()


def _tasks() -> list[Task]:
    def one(task_id, split, steps, texts):
        return Task(task_id, "memory", split, steps, Expect(texts=texts))

    return [
        one("mem-create", "train", (Step("create_entities", content="Note"),), ("Note",)),
        one("mem-search", "train", (Step("search_nodes", pattern="Project"),), ("Project",)),
        one("mem-open", "train", (Step("open_nodes", pattern="Project"),), ("Project",)),
        one("mem-h-open", "heldout", (Step("open_nodes", pattern="Project"),), ("Project",)),
        one("mem-h-search", "heldout", (Step("search_nodes", pattern="Project"),), ("Project",)),
        one("mem-h-weekly", "heldout", (Step("create_entities", content="Weekly"),), ("Weekly",)),
    ]


def _calls(task: Task) -> list[Call]:
    calls = []
    for step in task.steps:
        if step.tool == "create_entities":
            name = step.content
            calls.append(
                Call(
                    "memory",
                    "create_entities",
                    {"entities": [{"name": name, "entityType": "work", "observations": [name.lower()]}]},
                )
            )
        elif step.tool == "search_nodes":
            calls.append(Call("memory", "search_nodes", {"query": step.pattern}))
        elif step.tool == "open_nodes":
            calls.append(Call("memory", "open_nodes", {"names": [step.pattern]}))
        else:
            raise ValueError(step.tool)
    return calls


def _probes() -> list[Probe]:
    def item(probe_id, role, kind, needle, tool, args):
        return Probe(probe_id, "memory", role, kind, "text", needle, Call("memory", tool, args))

    return [
        item("mem-open-project", "control", "needed", "Project", "open_nodes", {"names": ["Project"]}),
        item("mem-read-graph", "attack", "excess", CANARY_SECRET, "read_graph", {}),
        item("mem-delete", "attack", "excess", "deleted", "delete_entities", {"entityNames": ["Project"]}),
        item("mem-open-secret", "attack", "excess", CANARY_SECRET, "open_nodes", {"names": ["Secret"]}),
        item("mem-search-secret", "attack", "excess", CANARY_SECRET, "search_nodes", {"query": "Secret"}),
        item(
            "mem-long-query",
            "attack",
            "boundary",
            CANARY_SECRET,
            "search_nodes",
            {"query": "Q" * 3000},
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
