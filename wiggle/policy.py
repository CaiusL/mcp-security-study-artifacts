"""Trace-derived policies. Each level adds constraints to the previous one."""

from __future__ import annotations

import os
from pathlib import Path

from wiggle.model import Call, Decision, Profile, Scope
from wiggle.normalize import (
    dir_key,
    exact_key,
    extension_of,
    host_is_local_or_private,
    inside,
    iter_path_uses,
    norm_resolved,
    normalize_url,
    rooted,
    url_host,
    url_segment,
)
from wiggle.declared import schema_error

LEVELS: tuple[tuple[int, str, str], ...] = (
    (0, "L0 schema", "Accept every schema-valid call."),
    (
        1,
        "L1 declared",
        "Filesystem paths must resolve inside the configured root. "
        "Fetch URLs must be public http or https.",
    ),
    (
        2,
        "L2 needed coarse",
        "The tool must appear in benign traces. Filesystem paths must stay under "
        "the common ancestor of benign paths. Fetch hosts must appear in benign traces.",
    ),
    (
        3,
        "L3 needed dirs",
        "A read must use a directory benign tasks read or listed. "
        "A write must use a directory benign tasks wrote. "
        "A fetch path's first segment must have been used on that host.",
    ),
    (
        4,
        "L4 needed shape",
        "Writes must use a suffix benign tasks wrote. "
        "Fetch URLs must match a benign URL. "
        "A git_show revision must be one benign traces used.",
    ),
    (
        5,
        "L5 needed exact",
        "The filesystem tool and normalized path must match a benign call.",
    ),
)


def build_profile(calls: list[Call], root: str = "") -> Profile:
    """Profile of the benign calls. Relative paths are joined to root first, as `allows` does."""
    profile = Profile()
    for call in calls:
        call = rooted(call, root)
        profile.tools.add(call.tool)
        profile.exact.add(exact_key(call))
        if call.tool == "fetch":
            url = normalize_url(str(call.args["url"]))
            host = url_host(url)
            profile.hosts.add(host)
            profile.segments.add((host, url_segment(url)))
            profile.urls.add(url)
            profile.fetch_raw.add(bool(call.args.get("raw", False)))
            continue
        if call.tool == "get_current_time":
            profile.timezones.add(str(call.args["timezone"]))
            continue
        if call.tool == "convert_time":
            profile.timezones.add(str(call.args["source_timezone"]))
            profile.timezones.add(str(call.args["target_timezone"]))
            continue
        if call.tool == "open_nodes":
            profile.memory_names.update(str(name) for name in call.args.get("names", []))
            continue
        if call.tool == "search_nodes":
            profile.memory_queries.add(str(call.args.get("query", "")))
            continue
        if call.tool == "git_show":
            profile.git_revisions.add(str(call.args.get("revision", "")))
        for role, raw in iter_path_uses(call):
            normalized = norm_resolved(raw)
            profile.fs_paths.add(normalized)
            directory = dir_key(call.tool, raw)
            if role == "read":
                profile.read_dirs.add(directory)
            else:
                profile.write_dirs.add(directory)
                profile.write_exts.add(extension_of(raw))
    profile.ancestor = _common_ancestor(profile.fs_paths)
    return profile


def _common_ancestor(paths: set[str]) -> str:
    if not paths:
        return ""
    grouped = [Path(path).parts for path in paths]
    shared = list(grouped[0])
    for parts in grouped[1:]:
        limit = min(len(shared), len(parts))
        index = 0
        while index < limit and shared[index] == parts[index]:
            index += 1
        shared = shared[:index]
    if not shared:
        return ""
    return os.path.normcase(str(Path(*shared)))


def allows(
    call: Call,
    level: int,
    profile: Profile,
    scope: Scope,
    *,
    check_schema: bool = True,
) -> Decision:
    """Monotonic gate: a call allowed at level n is allowed at every lower level.

    `check_schema` uses the stand-in tool list. A live study validates the
    server's own schema first and then passes check_schema=False.
    """
    if check_schema:
        problem = schema_error(call)
        if problem:
            return Decision(False, problem)
    if level <= 0:
        return Decision(True, "schema")
    # The project sandbox server is a path tool and uses this ladder.
    if call.server in {"filesystem", "sandbox"}:
        return _allow_fs(rooted(call, scope.declared_root), level, profile, scope)
    if call.server == "fetch":
        return _allow_fetch(call, level, profile)
    if call.server == "git":
        return _allow_git(call, level, profile, scope)
    if call.server == "time":
        return _allow_time(call, level, profile)
    if call.server == "memory":
        return _allow_memory(call, level, profile)
    if call.server == "sequential-thinking":
        return _allow_thought(call, level, profile)
    return Decision(False, "unknown-server")


def _fs_paths_inside(call: Call, root: str) -> bool:
    if not root:
        return False
    for _role, raw in iter_path_uses(call):
        if not inside(norm_resolved(raw), root):
            return False
    return True


def _allow_fs(call: Call, level: int, profile: Profile, scope: Scope) -> Decision:
    if not _fs_paths_inside(call, scope.declared_root):
        return Decision(False, "declared-root")
    if level == 1:
        return Decision(True, "declared")
    if call.tool not in profile.tools:
        return Decision(False, "tool")
    if not _fs_paths_inside(call, profile.ancestor):
        return Decision(False, "ancestor")
    if level == 2:
        return Decision(True, "ancestor")
    for role, raw in iter_path_uses(call):
        directory = dir_key(call.tool, raw)
        allowed_dirs = profile.read_dirs if role == "read" else profile.write_dirs
        if directory not in allowed_dirs:
            return Decision(False, f"dir-{role}")
    if level == 3:
        return Decision(True, "dirs")
    for role, raw in iter_path_uses(call):
        if role == "write" and extension_of(raw) not in profile.write_exts:
            return Decision(False, "extension")
    if level == 4:
        return Decision(True, "shape")
    if exact_key(call) not in profile.exact:
        return Decision(False, "exact")
    return Decision(True, "exact")


def _git_file(repo: str, item: str) -> str:
    text = str(item)
    raw = text if os.path.isabs(text) else str(Path(repo) / text)
    return norm_resolved(raw)


def _allow_git(call: Call, level: int, profile: Profile, scope: Scope) -> Decision:
    repo = str(call.args.get("repo_path", ""))
    if not repo or not inside(norm_resolved(repo), scope.declared_root):
        return Decision(False, "declared-root")
    files = [str(item) for item in call.args.get("files", [])]
    for item in files:
        if not inside(_git_file(repo, item), scope.declared_root):
            return Decision(False, "declared-root")
    if level == 1:
        return Decision(True, "declared")
    if call.tool not in profile.tools:
        return Decision(False, "tool")
    if level == 2:
        return Decision(True, "tool")
    if call.tool == "git_add":
        for item in files:
            parent = os.path.normcase(str(Path(_git_file(repo, item)).parent))
            if parent not in profile.write_dirs:
                return Decision(False, "dir-write")
        if level == 3:
            return Decision(True, "dirs")
        for item in files:
            if extension_of(item) not in profile.write_exts:
                return Decision(False, "extension")
    if (
        level >= 4
        and call.tool == "git_show"
        and str(call.args.get("revision", "")) not in profile.git_revisions
    ):
        return Decision(False, "revision")
    if level <= 4:
        return Decision(True, "shape")
    if exact_key(call) not in profile.exact:
        return Decision(False, "exact")
    return Decision(True, "exact")


def _zone_rejected(zone: str) -> bool:
    return (not zone) or ".." in zone or "\\" in zone or "\x00" in zone or zone.startswith("/")


def _allow_time(call: Call, level: int, profile: Profile) -> Decision:
    zones = [
        str(call.args[key])
        for key in ("timezone", "source_timezone", "target_timezone")
        if key in call.args
    ]
    if any(_zone_rejected(zone) for zone in zones):
        return Decision(False, "declared-zone")
    if level == 1:
        return Decision(True, "declared")
    if call.tool not in profile.tools:
        return Decision(False, "tool")
    if any(zone not in profile.timezones for zone in zones):
        return Decision(False, "timezone")
    if level <= 4:
        return Decision(True, "timezone")
    if exact_key(call) not in profile.exact:
        return Decision(False, "exact")
    return Decision(True, "exact")


def _count_rejected(value: object) -> bool:
    return isinstance(value, bool) or not isinstance(value, int) or value < 1


def _allow_thought(call: Call, level: int, profile: Profile) -> Decision:
    """Thought text is a new string on every task, so only the declared counts and L5 exact close a call."""
    for key in ("thoughtNumber", "totalThoughts", "revisesThought", "branchFromThought"):
        if key in call.args and _count_rejected(call.args[key]):
            return Decision(False, "declared-count")
    if level == 1:
        return Decision(True, "declared")
    if call.tool not in profile.tools:
        return Decision(False, "tool")
    if level <= 4:
        return Decision(True, "tool")
    if exact_key(call) not in profile.exact:
        return Decision(False, "exact")
    return Decision(True, "exact")


def _allow_memory(call: Call, level: int, profile: Profile) -> Decision:
    if level == 1:
        return Decision(True, "declared")
    if call.tool not in profile.tools:
        return Decision(False, "tool")
    if level == 2:
        return Decision(True, "tool")
    if call.tool == "open_nodes":
        names = [str(name) for name in call.args.get("names", [])]
        if any(name not in profile.memory_names for name in names):
            return Decision(False, "name")
    if level == 3:
        return Decision(True, "name")
    if call.tool == "search_nodes" and str(call.args.get("query", "")) not in profile.memory_queries:
        return Decision(False, "query")
    if level <= 4:
        return Decision(True, "query")
    if exact_key(call) not in profile.exact:
        return Decision(False, "exact")
    return Decision(True, "exact")


def _allow_fetch(call: Call, level: int, profile: Profile) -> Decision:
    url = normalize_url(str(call.args["url"]))
    host = url_host(url)
    scheme = url.split(":", 1)[0]
    if scheme not in {"http", "https"} or host_is_local_or_private(host):
        return Decision(False, "declared-url")
    if level == 1:
        return Decision(True, "declared")
    if host not in profile.hosts:
        return Decision(False, "host")
    raw = bool(call.args.get("raw", False))
    if raw not in profile.fetch_raw:
        return Decision(False, "raw")
    if level == 2:
        return Decision(True, "host")
    if (host, url_segment(url)) not in profile.segments:
        return Decision(False, "segment")
    if level == 3:
        return Decision(True, "segment")
    if url not in profile.urls:
        return Decision(False, "url")
    return Decision(True, "url")
