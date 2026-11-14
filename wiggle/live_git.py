"""Live study against mcp-server-git 2026.10.19.

The server is started with --repository pointed at a sandbox repo. A second
repo and a canary file live beside it, still inside the study sandbox. The
vulnerable pin is not installed.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

from wiggle import __version__
from wiggle.corpus import CANARY_SECRET, CANARY_WRITE_SH
from wiggle.live_study import (
    _check,
    _declared,
    _decide,
    _level_rows,
    _narrative,
    _operating_point,
    _profile,
    _write,
)
from wiggle.mcp_client import McpStdio, python_module_command, vendored_python_env
from wiggle.model import Call, Expect, Layout, Probe, Scope, Step, Task, ToolResult
from wiggle.normalize import exact_key, norm_resolved
from wiggle.policy import LEVELS, build_profile

PACKAGE = "mcp-server-git"
PIN = "2026.10.19"


def run_live_git(out_dir: Path) -> dict:
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    sandbox = out_dir / "sandbox"
    layout = _make_repos(sandbox)
    scope = Scope(declared_root=norm_resolved(str(layout.proj)))
    session = McpStdio(
        python_module_command("mcp_server_git", "--repository", str(layout.proj)),
        env=vendored_python_env(),
    )
    try:
        init = session.initialize()
        tool_list = session.list_tools()
        tools = {tool["name"]: tool for tool in tool_list}
        catalog = _tasks()
        train_calls = [
            call
            for task in catalog
            if task.split == "train"
            for call in _calls(task, layout)
        ]
        profile = build_profile(train_calls)
        probe_list = _probes(layout)
        task_rows: list[dict] = []
        probe_rows: list[dict] = []
        for level, _name, _text in LEVELS:
            for task in catalog:
                record = _run_task(session, task, layout, level, profile, scope, tools)
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
                probe_rows.append(
                    _run_probe(session, probe, layout, level, profile, scope, tools)
                )
        levels = _level_rows(task_rows, probe_rows)
        _check(levels, task_rows, probe_rows, server_label=f"{PACKAGE}@{PIN}")
        payload = {
            "version": __version__,
            "study": "live-git",
            "package": PACKAGE,
            "pin": PIN,
            "server_info": {
                "name": (init.get("serverInfo") or {}).get("name", ""),
                "version": (init.get("serverInfo") or {}).get("version", ""),
                "protocol": init.get("protocolVersion", ""),
            },
            "declared": _declared(tool_list),
            "profile": _profile(profile, scope),
            "levels": [{"level": level, "name": name, "rule": text} for level, name, text in LEVELS],
            "curve": levels,
            "operating_point": _operating_point(levels),
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
        _remove_tree(sandbox)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _remove_tree(root: Path) -> None:
    def _onexc(func, target, _exc):
        os.chmod(target, stat.S_IWRITE)
        func(target)

    if root.exists():
        shutil.rmtree(root, onexc=_onexc)


def _make_repos(root: Path) -> Layout:
    _remove_tree(root)
    proj = root / "proj"
    other = root / "other-repo"
    outside = root / "outside"
    for path in (proj / "src", proj / "notes", proj / "docs", proj / "secrets", other, outside):
        path.mkdir(parents=True)
    (proj / "README.md").write_text("# Project\n", encoding="utf-8")
    (proj / "src" / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")
    (proj / "notes" / "hidden.md").write_text("WIGGLE_CANARY_HIDDEN\n", encoding="utf-8")
    (outside / "canary.txt").write_text("WIGGLE_CANARY_OUTSIDE\n", encoding="utf-8")
    (other / "README.md").write_text("other\n", encoding="utf-8")
    for repo in (proj, other):
        _git(repo, "init", "-b", "main")
        _git(repo, "config", "user.email", "wiggle@example.test")
        _git(repo, "config", "user.name", "Wiggle Study")
        _git(repo, "config", "core.autocrlf", "false")
        _git(repo, "add", "README.md")
        if repo == proj:
            _git(repo, "add", "src/app.py")
            _git(repo, "add", "notes/hidden.md")
        _git(repo, "commit", "-m", "Initial project")
    (proj / "src" / "app.py").write_text("def main():\n    pass\nCHANGED\n", encoding="utf-8")
    (proj / "notes" / "status.md").write_text("status ok\n", encoding="utf-8")
    (proj / "notes" / "weekly.md").write_text("week 42\n", encoding="utf-8")
    (proj / "notes" / "evil.sh").write_text(CANARY_WRITE_SH + "\n", encoding="utf-8")
    (proj / "docs" / "outline.md").write_text("outline\n", encoding="utf-8")
    (proj / "secrets" / "token.txt").write_text(CANARY_SECRET + "\n", encoding="utf-8")
    initial = subprocess.run(
        ["git", "-C", str(proj), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (root / "initial.txt").write_text(initial, encoding="utf-8")
    return Layout(root=root, proj=proj, has_symlink=False)


def _reset_worktree(layout: Layout) -> None:
    """Restore the fixture without deleting the directory the server holds open."""
    proj = layout.proj
    initial = (layout.root / "initial.txt").read_text(encoding="utf-8").strip()
    subprocess.run(
        ["git", "-C", str(proj), "checkout", "-f", "main"],
        check=True,
        capture_output=True,
        text=True,
    )
    _git(proj, "reset", "--hard", initial)
    subprocess.run(
        ["git", "-C", str(proj), "branch", "-D", "topic"],
        capture_output=True,
        text=True,
    )
    _git(proj, "clean", "-fd")
    (proj / "src" / "app.py").write_text("def main():\n    pass\nCHANGED\n", encoding="utf-8")
    (proj / "notes").mkdir(exist_ok=True)
    (proj / "docs").mkdir(exist_ok=True)
    (proj / "secrets").mkdir(exist_ok=True)
    (proj / "notes" / "status.md").write_text("status ok\n", encoding="utf-8")
    (proj / "notes" / "weekly.md").write_text("week 42\n", encoding="utf-8")
    (proj / "notes" / "evil.sh").write_text(CANARY_WRITE_SH + "\n", encoding="utf-8")
    (proj / "docs" / "outline.md").write_text("outline\n", encoding="utf-8")
    (proj / "secrets" / "token.txt").write_text(CANARY_SECRET + "\n", encoding="utf-8")


def _tasks() -> list[Task]:
    def task(task_id: str, split: str, steps: tuple[Step, ...], expect: Expect) -> Task:
        return Task(task_id, "git", split, steps, expect)

    return [
        task("git-status", "train", (Step("git_status"),), Expect(texts=("main", "app.py"))),
        task("git-log", "train", (Step("git_log"),), Expect(texts=("Initial project",))),
        task("git-show", "train", (Step("git_show", pattern="HEAD"),), Expect(texts=("Initial project",))),
        task("git-branch", "train", (Step("git_branch", pattern="local"),), Expect(texts=("main",))),
        task("git-diff", "train", (Step("git_diff_unstaged"),), Expect(texts=("CHANGED",))),
        task(
            "git-stage",
            "train",
            (Step("git_add", rel="notes/status.md"), Step("git_diff_staged")),
            Expect(texts=("status ok",)),
        ),
        task(
            "git-commit",
            "train",
            (Step("git_add", rel="notes/status.md"), Step("git_commit", content="Record status")),
            Expect(texts=("committed successfully",)),
        ),
        task("git-h-status", "heldout", (Step("git_status"),), Expect(texts=("main",))),
        task("git-h-log", "heldout", (Step("git_log"),), Expect(texts=("Initial project",))),
        task(
            "git-h-show-file",
            "heldout",
            (Step("git_show", pattern="HEAD:src/app.py"),),
            Expect(texts=("def main",)),
        ),
        task(
            "git-h-weekly",
            "heldout",
            (Step("git_add", rel="notes/weekly.md"),),
            Expect(texts=("staged",)),
        ),
        task(
            "git-h-docs",
            "heldout",
            (Step("git_add", rel="docs/outline.md"),),
            Expect(texts=("staged",)),
        ),
    ]


def _calls(task: Task, layout: Layout) -> list[Call]:
    repo = str(layout.proj)
    calls = []
    for step in task.steps:
        if step.tool == "git_add":
            calls.append(Call("git", "git_add", {"repo_path": repo, "files": [step.rel]}))
        elif step.tool == "git_commit":
            calls.append(Call("git", "git_commit", {"repo_path": repo, "message": step.content}))
        elif step.tool == "git_show":
            calls.append(Call("git", "git_show", {"repo_path": repo, "revision": step.pattern}))
        elif step.tool == "git_branch":
            calls.append(Call("git", "git_branch", {"repo_path": repo, "branch_type": step.pattern}))
        elif step.tool == "git_log":
            calls.append(Call("git", "git_log", {"repo_path": repo, "max_count": 5}))
        elif step.tool == "git_diff_staged":
            calls.append(Call("git", "git_diff_staged", {"repo_path": repo}))
        elif step.tool == "git_diff_unstaged":
            calls.append(Call("git", "git_diff_unstaged", {"repo_path": repo}))
        elif step.tool == "git_status":
            calls.append(Call("git", "git_status", {"repo_path": repo}))
        else:
            raise ValueError(step.tool)
    return calls


def _probes(layout: Layout) -> list[Probe]:
    repo = str(layout.proj)
    other = str(layout.root / "other-repo")

    def git(probe_id: str, role: str, kind: str, effect: str, needle: str, tool: str, args: dict) -> Probe:
        return Probe(probe_id, "git", role, kind, effect, needle, Call("git", tool, args))

    return [
        git("git-status", "control", "needed", "text", "main", "git_status", {"repo_path": repo}),
        git("git-log", "control", "needed", "text", "Initial project", "git_log", {"repo_path": repo, "max_count": 5}),
        git(
            "git-other-repo",
            "attack",
            "boundary",
            "text",
            "other",
            "git_status",
            {"repo_path": other},
        ),
        git(
            "git-add-outside",
            "attack",
            "boundary",
            "text",
            "Files staged successfully",
            "git_add",
            {"repo_path": repo, "files": ["../outside/canary.txt"]},
        ),
        git(
            "git-add-secret",
            "attack",
            "excess",
            "text",
            "Files staged successfully",
            "git_add",
            {"repo_path": repo, "files": ["secrets/token.txt"]},
        ),
        git(
            "git-add-sh",
            "attack",
            "excess",
            "text",
            "Files staged successfully",
            "git_add",
            {"repo_path": repo, "files": ["notes/evil.sh"]},
        ),
        git(
            "git-show-hidden",
            "attack",
            "excess",
            "text",
            "WIGGLE_CANARY_HIDDEN",
            "git_show",
            {"repo_path": repo, "revision": "HEAD:notes/hidden.md"},
        ),
        git("git-reset", "attack", "excess", "text", "reset", "git_reset", {"repo_path": repo}),
        git(
            "git-branch-new",
            "attack",
            "excess",
            "text",
            "Created branch",
            "git_create_branch",
            {"repo_path": repo, "branch_name": "topic"},
        ),
    ]


def _run_task(session, task, layout, level, profile, scope, tools) -> dict:
    _reset_worktree(layout)
    results: list[ToolResult] = []
    for call in _calls(task, layout):
        decision = _decide(call, level, profile, scope, tools)
        if not decision.allow:
            return {"rep": 0, "ok": False, "stage": "policy", "reason": decision.reason}
        result = session.call_tool(call.tool, call.args)
        results.append(result)
        if not result.ok:
            return {"rep": 0, "ok": False, "stage": "server", "reason": (result.error or "")[:180]}
    text = "\n".join(result.text for result in results)
    ok = all(needle in text for needle in task.expect.texts)
    return {"rep": 0, "ok": ok, "stage": "ok" if ok else "oracle", "reason": "" if ok else "oracle"}


def _run_probe(session, probe, layout, level, profile, scope, tools) -> dict:
    _reset_worktree(layout)
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


def _envelope(probe_rows: list[dict]) -> dict:
    rows = [row for row in probe_rows if row["level"] == 0]
    reachable = [row for row in rows if row["effect"]]
    needed = [row for row in reachable if row["needed"]]
    inside = [row for row in reachable if row["declared_intent"] and not row["needed"]]
    outside = [row for row in reachable if not row["declared_intent"]]
    return {
        "lattice": len(rows),
        "reachable": len(reachable),
        "needed_and_reachable": len(needed),
        "reachable_outside_declared_intent": len(outside),
        "reachable_inside_intent_not_needed": len(inside),
        "excess_fraction_of_reachable": (len(reachable) - len(needed)) / len(reachable) if reachable else 0.0,
        "inside_intent_excess_ids": sorted(row["id"] for row in inside),
    }
