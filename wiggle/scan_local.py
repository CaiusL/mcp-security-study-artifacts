"""Parallel declared scan of local stdio MCP servers.

Each process receives `initialize` and `tools/list` only. The scanner does not
call a tool. Commands come from an explicit catalog, or from the five servers
already vendored for the live studies. Untrusted registry packages are not
launched: this machine has no jail, and a server can run code at startup.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from wiggle import __version__
from wiggle.mcp_client import (
    McpError,
    McpStdio,
    filesystem_server_command,
    python_module_command,
    vendored_python_env,
)
from wiggle.scan_classify import classify_tools


def default_workers(count: int) -> int:
    """One server process per worker, capped so a scan stays under half the cores."""
    cores = os.cpu_count() or 2
    cap = max(1, min(4, cores // 2))
    return max(1, min(cap, max(count, 1)))


def load_catalog(path: Path) -> list[dict]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    servers = payload["servers"] if isinstance(payload, dict) else payload
    if not isinstance(servers, list):
        raise ValueError("catalog servers must be a list")
    entries = []
    for item in servers:
        if not isinstance(item, dict):
            raise ValueError("each catalog entry must be an object")
        command = item.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
            raise ValueError(f"{item.get('id', '?')}: command must be a list of strings")
        env = item.get("env")
        if env is not None:
            if not isinstance(env, dict) or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in env.items()
            ):
                raise ValueError(f"{item.get('id', '?')}: env must be a string map")
        entries.append(
            {
                "id": str(item.get("id") or command[0]),
                "command": command,
                "env": env,
                "error": "",
            }
        )
    return entries


def vendored_catalog(work: Path) -> list[dict]:
    """Launch lines for the five pinned servers already used by the live studies."""
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    entries = []
    entries.append(_filesystem_entry(work))
    entries.append(_python_entry("fetch", "mcp_server_fetch"))
    entries.append(_git_entry(work))
    entries.append(_memory_entry(work))
    entries.append(_python_entry("time", "mcp_server_time"))
    return entries


def _filesystem_entry(work: Path) -> dict:
    root = work / "filesystem-root"
    root.mkdir(parents=True, exist_ok=True)
    try:
        command = filesystem_server_command(root)
    except McpError as exc:
        return {"id": "filesystem", "command": [], "env": None, "error": str(exc)}
    return {"id": "filesystem", "command": command, "env": None, "error": ""}


def _python_entry(server_id: str, module: str) -> dict:
    try:
        env = vendored_python_env()
    except McpError as exc:
        return {"id": server_id, "command": [], "env": None, "error": str(exc)}
    return {"id": server_id, "command": python_module_command(module), "env": env, "error": ""}


def _git_entry(work: Path) -> dict:
    repo = work / "git-repo"
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "README.md").write_text("scan\n", encoding="utf-8")
    try:
        subprocess.run(
            ["git", "init", str(repo)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        return {"id": "git", "command": [], "env": None, "error": f"git init failed: {exc}"}
    try:
        env = vendored_python_env()
    except McpError as exc:
        return {"id": "git", "command": [], "env": None, "error": str(exc)}
    return {
        "id": "git",
        "command": python_module_command("mcp_server_git", "--repository", str(repo)),
        "env": env,
        "error": "",
    }


def _memory_entry(work: Path) -> dict:
    graph = work / "memory.jsonl"
    graph.write_text("", encoding="utf-8")
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
    if not entry.is_file():
        return {
            "id": "memory",
            "command": [],
            "env": None,
            "error": "pinned memory server is missing. From the repo root run: npm install --prefix vendor/mcp",
        }
    env = os.environ.copy()
    env["MEMORY_FILE_PATH"] = str(graph)
    return {"id": "memory", "command": ["node", str(entry)], "env": env, "error": ""}


def scan_one(entry: dict, timeout: float) -> dict:
    server_id = entry["id"]
    if entry.get("error"):
        return _failed(server_id, entry["error"], 0.0)
    if not entry.get("command"):
        return _failed(server_id, "no command", 0.0)
    started = datetime.now(timezone.utc)
    session: McpStdio | None = None
    try:
        session = McpStdio(entry["command"], env=entry.get("env"))
        init = session.initialize(timeout=timeout)
        tools = session.list_tools(timeout=timeout)
        classified = classify_tools(tools)
        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        info = init.get("serverInfo") if isinstance(init.get("serverInfo"), dict) else {}
        return {
            "id": server_id,
            "ok": True,
            "error": "",
            "elapsed_s": round(elapsed, 3),
            "server_info": {
                "name": str(info.get("name") or ""),
                "version": str(info.get("version") or ""),
                "protocol": str(init.get("protocolVersion") or ""),
            },
            "family": classified["family"],
            "feature_counts": classified["feature_counts"],
            "tool_count": classified["tool_count"],
            "free_string_resources": classified["free_string_resources"],
            "tools": classified["tools"],
        }
    except Exception as exc:
        stderr = ""
        if session is not None and session.stderr:
            stderr = " ".join(session.stderr[-1].split())[:300]
        message = f"{type(exc).__name__}: {exc}"
        if stderr:
            message = f"{message} ({stderr})"
        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        return _failed(server_id, message, elapsed)
    finally:
        if session is not None:
            session.close()


def _failed(server_id: str, message: str, elapsed: float) -> dict:
    return {
        "id": server_id,
        "ok": False,
        "error": message,
        "elapsed_s": round(elapsed, 3),
        "server_info": {"name": "", "version": "", "protocol": ""},
        "family": "",
        "feature_counts": {},
        "tool_count": 0,
        "free_string_resources": [],
        "tools": [],
    }


def scan_entries(entries: list[dict], *, workers: int, timeout: float) -> list[dict]:
    if not entries:
        return []
    workers = max(1, min(workers, len(entries)))
    by_index: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_one, entry, timeout): index for index, entry in enumerate(entries)
        }
        for future in as_completed(futures):
            by_index[futures[future]] = future.result()
    return [by_index[index] for index in range(len(entries))]


def run_local_scan(
    out_dir: Path,
    entries: list[dict] | None = None,
    *,
    workers: int = 0,
    timeout: float = 30,
) -> dict:
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    work = out_dir / "work"
    owns_work = entries is None
    if owns_work:
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)
        entries = vendored_catalog(work)
    assert entries is not None
    worker_count = workers if workers > 0 else default_workers(len(entries))
    try:
        rows = scan_entries(entries, workers=worker_count, timeout=timeout)
    finally:
        if owns_work:
            shutil.rmtree(work, ignore_errors=True)
    payload = {
        "version": __version__,
        "study": "local-declared-scan",
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "calls_tools": False,
        "workers": worker_count,
        "servers": rows,
    }
    (out_dir / "results.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (out_dir / "report.md").write_text(render_local_report(payload), encoding="utf-8")
    return payload


def _feature_counts(counts: dict) -> str:
    if not counts:
        return "—"
    ordered = sorted(counts, key=lambda name: (-counts[name], name))
    return ", ".join(f"{name} {counts[name]}" for name in ordered)


def render_local_report(payload: dict) -> str:
    lines = [
        "# Local declared scan",
        "",
        "Each catalog command was started over stdio and sent `initialize` and `tools/list` only. No tool was called. The family is the resource feature shared by the most tools. Ties break in the order path, url, sql, git, browser, entity, timezone, command, thought.",
        "",
        f"Scanned at {payload['scanned_at']} with {payload['workers']} worker(s).",
        "",
        "| Server | Tools | Family | Features | Free-string resource args | Result |",
        "| --- | ---: | --- | --- | ---: | --- |",
    ]
    for row in payload["servers"]:
        if row["ok"]:
            result = "ok"
        else:
            shown = " ".join(row["error"].split()).replace("|", "/")
            result = "error: " + (shown if len(shown) <= 120 else shown[:119] + "…")
        family = row["family"] or "—"
        lines.append(
            "| {server} | {tools} | {family} | {features} | {free} | {result} |".format(
                server=row["id"],
                tools=row["tool_count"],
                family=family,
                features=_feature_counts(row["feature_counts"]),
                free=len(row["free_string_resources"]),
                result=result,
            )
        )
    lines.extend(
        [
            "",
            "Free-string resource args are path, URL, SQL, git, browser, entity, timezone, command, or thought arguments whose schema is an unconstrained string or an array of strings. A metadata scanner flags those arguments. The Needed ladder is what says which of them a benign task actually uses.",
            "",
            "The vendored default covers the five servers that already have curves. A catalog can add more local commands. Packages from the registry census are not started here.",
            "",
        ]
    )
    return "\n".join(lines)
