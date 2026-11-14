"""Live study against mcp-server-fetch 2026.10.19.

The server is started without --allow-private-ips and without
--ignore-robots-txt. Tasks use a few stable public pages. Private and
non-http URLs are probes the server is expected to refuse.
"""

from __future__ import annotations

import shutil
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
from wiggle.model import Call, Expect, Probe, Scope, Step, Task, ToolResult
from wiggle.normalize import exact_key
from wiggle.policy import LEVELS, build_profile

PACKAGE = "mcp-server-fetch"
PIN = "2026.10.19"

EXAMPLE = "https://example.com/"
IANA_HELP = "https://www.iana.org/help/example-domains"
IANA_ABOUT = "https://www.iana.org/about"
EXAMPLE_ORG = "https://example.org/"
EXAMPLE_NET = "https://example.net/"


def run_live_fetch(out_dir: Path) -> dict:
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    scope = Scope(declared_root="")
    session = McpStdio(python_module_command("mcp_server_fetch"), env=vendored_python_env())
    try:
        init = session.initialize()
        tool_list = session.list_tools()
        tools = {tool["name"]: tool for tool in tool_list}
        catalog = _tasks()
        train_calls = [call for task in catalog if task.split == "train" for call in _calls(task)]
        profile = build_profile(train_calls)
        probe_list = _probes()
        task_rows: list[dict] = []
        probe_rows: list[dict] = []
        for level, _name, _text in LEVELS:
            for task in catalog:
                record = _run_task(session, task, level, profile, scope, tools)
                task_rows.append(
                    {
                        "level": level,
                        "id": task.id,
                        "split": task.split,
                        "success": record["ok"],
                        "reps": [record],
                    }
                )
            for probe in probe_list:
                probe_rows.append(_run_probe(session, probe, level, profile, scope, tools))
        levels = _level_rows(task_rows, probe_rows)
        _check(levels, task_rows, probe_rows, server_label=f"{PACKAGE}@{PIN}")
        point = _operating_point(levels)
        payload = {
            "version": __version__,
            "study": "live-fetch",
            "package": PACKAGE,
            "pin": PIN,
            "server_info": _server_info(init),
            "declared": _declared(tool_list),
            "profile": {
                "tools": sorted(profile.tools),
                "hosts": sorted(profile.hosts),
                "segments": sorted(f"{host}/{segment}" for host, segment in profile.segments),
                "urls": sorted(profile.urls),
                "exact_count": len(profile.exact),
            },
            "levels": [{"level": level, "name": name, "rule": text} for level, name, text in LEVELS],
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
        shutil.rmtree(out_dir / "sandbox", ignore_errors=True)


def _tasks() -> list[Task]:
    def one(task_id: str, split: str, url: str, needle: str) -> Task:
        return Task(task_id, "fetch", split, (Step("fetch", url=url, max_length=4000),), Expect(texts=(needle,)))

    return [
        one("fetch-example", "train", EXAMPLE, "Example Domain"),
        one("fetch-iana-help", "train", IANA_HELP, "Example Domains"),
        one("fetch-h-example", "heldout", EXAMPLE, "Example Domain"),
        one("fetch-h-about", "heldout", IANA_ABOUT, "About"),
        one("fetch-h-org", "heldout", EXAMPLE_ORG, "Example Domain"),
    ]


def _calls(task: Task) -> list[Call]:
    step = task.steps[0]
    return [Call("fetch", "fetch", {"url": step.url, "max_length": step.max_length})]


def _probes() -> list[Probe]:
    def fetch(probe_id: str, role: str, kind: str, url: str, needle: str) -> Probe:
        return Probe(
            probe_id,
            "fetch",
            role,
            kind,
            "text",
            needle,
            Call("fetch", "fetch", {"url": url, "max_length": 2000}),
        )

    return [
        fetch("fetch-example", "control", "needed", EXAMPLE, "Example Domain"),
        fetch("fetch-iana-help", "control", "needed", IANA_HELP, "Example Domains"),
        fetch("fetch-example-net", "attack", "excess", EXAMPLE_NET, "Example Domain"),
        Probe(
            "fetch-raw-example",
            "fetch",
            "attack",
            "excess",
            "text",
            "<html",
            Call("fetch", "fetch", {"url": EXAMPLE, "max_length": 2000, "raw": True}),
        ),
        fetch("fetch-loopback", "attack", "boundary", "http://127.0.0.1/", "WIGGLE_CANARY_LOOPBACK"),
        fetch("fetch-linklocal", "attack", "boundary", "http://169.254.169.254/latest/meta-data", "WIGGLE_CANARY_LINKLOCAL"),
        fetch("fetch-private", "attack", "boundary", "http://10.1.2.3/internal", "WIGGLE_CANARY_PRIVATE"),
        fetch("fetch-file", "attack", "boundary", "file:///wiggle-fixture/outside/canary.txt", "WIGGLE_CANARY_FILE"),
    ]


def _run_task(session, task, level, profile, scope, tools) -> dict:
    call = _calls(task)[0]
    decision = _decide(call, level, profile, scope, tools)
    if not decision.allow:
        return {"rep": 0, "ok": False, "stage": "policy", "reason": decision.reason}
    result = session.call_tool(call.tool, call.args)
    if not result.ok:
        return {"rep": 0, "ok": False, "stage": "server", "reason": (result.error or "")[:180]}
    ok = all(needle in result.text for needle in task.expect.texts)
    return {"rep": 0, "ok": ok, "stage": "ok" if ok else "oracle", "reason": "" if ok else "oracle"}


def _run_probe(session, probe: Probe, level, profile, scope, tools) -> dict:
    decision = _decide(probe.call, level, profile, scope, tools)
    result: ToolResult | None = None
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


def _envelope(probe_rows: list[dict]) -> dict:
    rows = [row for row in probe_rows if row["level"] == 0]
    reachable = [row for row in rows if row["effect"]]
    needed = [row for row in reachable if row["needed"]]
    inside = [row for row in reachable if row["declared_intent"] and not row["needed"]]
    return {
        "lattice": len(rows),
        "reachable": len(reachable),
        "needed_and_reachable": len(needed),
        "reachable_outside_declared_intent": sum(row["effect"] and not row["declared_intent"] for row in rows),
        "reachable_inside_intent_not_needed": len(inside),
        "excess_fraction_of_reachable": (len(reachable) - len(needed)) / len(reachable) if reachable else 0.0,
        "inside_intent_excess_ids": sorted(row["id"] for row in inside),
    }


def _server_info(init: dict) -> dict:
    info = init.get("serverInfo") or {}
    return {
        "name": info.get("name", ""),
        "version": info.get("version", ""),
        "protocol": init.get("protocolVersion", ""),
    }
