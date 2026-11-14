"""Path and URL normalization shared by servers, policies, and traces."""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from wiggle.model import Call


def norm_resolved(path: str) -> str:
    """Absolute path with '..' and symlinks resolved, case-normalized."""
    return os.path.normcase(str(Path(path).resolve()))


def inside(child: str, parent: str) -> bool:
    """True when child is parent or a descendant. Requires a path boundary."""
    if child == parent:
        return True
    prefix = parent.rstrip("\\/") + os.sep
    return child.startswith(prefix)


def extension_of(path: str) -> str:
    return Path(path).suffix.lower()


def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return f"{scheme}://{host}{path}"


def url_host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def url_segment(url: str) -> str:
    path = urlsplit(url).path or "/"
    parts = [piece for piece in path.split("/") if piece]
    return parts[0] if parts else ""


def host_is_local_or_private(host: str) -> bool:
    """True for empty hosts, localhost, and any non-global IP."""
    if host in {"", "localhost"}:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not address.is_global


def public_http(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme.lower() not in {"http", "https"}:
        return False
    return not host_is_local_or_private((parts.hostname or "").lower())


# Tools whose path argument is the directory being accessed, not a file inside it.
_DIRECTORY_TOOLS = {
    "list_directory",
    "list_directory_with_sizes",
    "search_files",
    "directory_tree",
}
_WRITE_TOOLS = {"write_file", "edit_file", "create_directory", "write_note"}


def dir_key(tool: str, raw_path: str) -> str:
    normalized = norm_resolved(raw_path)
    if tool in _DIRECTORY_TOOLS:
        return normalized
    return os.path.normcase(str(Path(normalized).parent))


def iter_path_uses(call: Call) -> list[tuple[str, str]]:
    """Return (role, raw_path) pairs. Role is 'read' or 'write'."""
    tool = call.tool
    if tool == "move_file":
        return [
            ("read", str(call.args["source"])),
            ("write", str(call.args["destination"])),
        ]
    if tool == "read_multiple_files":
        return [("read", str(item)) for item in call.args.get("paths", [])]
    if tool == "git_add":
        repo = Path(str(call.args["repo_path"]))
        uses = []
        for item in call.args.get("files", []):
            text = str(item)
            raw = text if os.path.isabs(text) else str(repo / text)
            uses.append(("write", raw))
        return uses
    if tool.startswith("git_") and "repo_path" in call.args:
        return [("read", str(call.args["repo_path"]))]
    if "path" not in call.args:
        return []
    role = "write" if tool in _WRITE_TOOLS else "read"
    return [(role, str(call.args["path"]))]


def rooted(call: Call, root: str) -> Call:
    """The call with relative filesystem and sandbox paths joined to root.

    The servers resolve a relative path against the project directory, not
    the caller's working directory. An empty root leaves the call unchanged.
    """
    if not root or call.server not in {"filesystem", "sandbox"}:
        return call

    def join(value: object) -> str:
        text = str(value)
        return text if os.path.isabs(text) else os.path.join(root, text)

    args = dict(call.args)
    for key in ("path", "source", "destination"):
        if key in args:
            args[key] = join(args[key])
    if isinstance(args.get("paths"), list):
        args["paths"] = [join(item) for item in args["paths"]]
    return Call(call.server, call.tool, args)


def exact_key(call: Call) -> tuple[str, str]:
    if call.tool == "fetch":
        url = normalize_url(str(call.args["url"]))
        suffix = "|raw" if call.args.get("raw") else ""
        return ("fetch", url + suffix)
    if call.tool == "move_file":
        source = norm_resolved(str(call.args["source"]))
        dest = norm_resolved(str(call.args["destination"]))
        return ("move_file", f"{source}->{dest}")
    if call.tool == "read_multiple_files":
        paths = [norm_resolved(str(item)) for item in call.args.get("paths", [])]
        return (call.tool, "|".join(paths))
    if call.tool.startswith("git_") and "repo_path" in call.args:
        repo = norm_resolved(str(call.args["repo_path"]))
        if call.tool == "git_add":
            files = []
            for item in call.args.get("files", []):
                text = str(item)
                raw = text if os.path.isabs(text) else str(Path(call.args["repo_path"]) / text)
                files.append(norm_resolved(raw))
            return (call.tool, repo + ":" + "|".join(sorted(files)))
        if call.tool == "git_show":
            return (call.tool, repo + ":" + str(call.args.get("revision", "")))
        return (call.tool, repo)
    if "path" not in call.args:
        return (call.tool, json.dumps(call.args, sort_keys=True, default=str))
    return (call.tool, norm_resolved(str(call.args["path"])))
