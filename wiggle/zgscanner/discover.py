"""Find MCP client configs, agent skills, and source files, and normalize what they declare.

Discovery only reads files. It never starts a server.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

from wiggle.zgscanner.live import saved_resources


MAX_TEXT_BYTES = 512 * 1024
MAX_SKILLS = 2000
MAX_SKILL_FILES = 60
MAX_SOURCE_FILES = 3000
CODE_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".go", ".rs", ".java", ".kt", ".cs", ".rb", ".php",
    ".sh", ".bash", ".ps1", ".psm1", ".bat", ".cmd",
}
SKILL_TEXT_SUFFIXES = CODE_SUFFIXES | {".md", ".txt", ".json", ".yaml", ".yml", ".toml"}
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".tox", ".mypy_cache", "site-packages"}


# --- JSON with comments -----------------------------------------------------


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, leaving strings intact."""
    out = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] not in "\r\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(ch)
            i += 1
    cleaned = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


def load_structured(path: Path) -> dict:
    raw = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    if Path(path).suffix.lower() == ".toml":
        return tomllib.loads(raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return json.loads(strip_jsonc(raw))


# --- client locations ----------------------------------------------------------


def known_config_paths(home: Path, cwd: Path, env: dict | None = None) -> list[tuple[str, Path, str]]:
    """(client, path, scope) for every location the popular clients read."""
    env = os.environ if env is None else env
    home, cwd = Path(home), Path(cwd)
    appdata = Path(env.get("APPDATA") or home / "AppData" / "Roaming")
    xdg = Path(env.get("XDG_CONFIG_HOME") or home / ".config")
    mac = home / "Library" / "Application Support"
    rows: list[tuple[str, Path, str]] = []

    def per_os(client: str, *parts: str) -> None:
        for base in (appdata, mac, xdg):
            rows.append((client, base.joinpath(*parts), "user"))

    per_os("Claude Desktop", "Claude", "claude_desktop_config.json")
    rows.append(("Claude Code", home / ".claude.json", "user"))
    rows.append(("Claude Code", cwd / ".mcp.json", "project"))
    rows.append(("Cursor", home / ".cursor" / "mcp.json", "user"))
    rows.append(("Cursor", cwd / ".cursor" / "mcp.json", "project"))
    rows.append(("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json", "user"))
    for flavor in ("Code", "Code - Insiders", "VSCodium"):
        per_os("VS Code", flavor, "User", "mcp.json")
        per_os("VS Code", flavor, "User", "settings.json")
        per_os("Cline", flavor, "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
        per_os("Roo Code", flavor, "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json")
    rows.append(("VS Code", cwd / ".vscode" / "mcp.json", "project"))
    rows.append(("GitHub Copilot", cwd / ".github" / "mcp.json", "project"))
    rows.append(("Copilot CLI", home / ".copilot" / "mcp-config.json", "user"))
    rows.append(("Gemini CLI", home / ".gemini" / "settings.json", "user"))
    rows.append(("Gemini CLI", cwd / ".gemini" / "settings.json", "project"))
    rows.append(("Codex", home / ".codex" / "config.toml", "user"))
    rows.append(("Amazon Q", home / ".aws" / "amazonq" / "mcp.json", "user"))
    rows.append(("Amazon Q", cwd / ".amazonq" / "mcp.json", "project"))
    rows.append(("Kiro", home / ".kiro" / "settings" / "mcp.json", "user"))
    rows.append(("Kiro", cwd / ".kiro" / "settings" / "mcp.json", "project"))
    rows.append(("Zed", xdg / "zed" / "settings.json", "user"))
    rows.append(("Zed", appdata / "Zed" / "settings.json", "user"))
    rows.append(("OpenCode", xdg / "opencode" / "opencode.json", "user"))
    rows.append(("OpenCode", cwd / "opencode.json", "project"))
    rows.append(("LM Studio", home / ".lmstudio" / "mcp.json", "user"))
    rows.append(("Continue", home / ".continue" / "config.json", "user"))
    seen = set()
    unique = []
    for client, path, scope in rows:
        key = (client, str(path).lower())
        if key not in seen:
            seen.add(key)
            unique.append((client, path, scope))
    return unique


def guess_client(path: Path) -> tuple[str, str]:
    text = str(path).replace("\\", "/").lower()
    name = Path(path).name.lower()
    for marker, client in (
        ("claude_desktop_config", "Claude Desktop"),
        (".claude.json", "Claude Code"),
        (".mcp.json", "Claude Code"),
        ("/.cursor/", "Cursor"),
        ("windsurf", "Windsurf"),
        ("cline_mcp_settings", "Cline"),
        ("/.vscode/", "VS Code"),
        ("/code/user/", "VS Code"),
        ("/.gemini/", "Gemini CLI"),
        ("/.codex/", "Codex"),
        ("amazonq", "Amazon Q"),
        ("/.kiro/", "Kiro"),
        ("/zed/", "Zed"),
        ("opencode", "OpenCode"),
    ):
        if marker in text or marker == name:
            return client, "user"
    return "Custom", "input"


# --- normalization --------------------------------------------------------------


def _transport(raw: dict, url: str) -> str:
    kind = str(raw.get("type") or raw.get("transport") or "").lower().replace("_", "-")
    if kind in {"sse"}:
        return "sse"
    if kind in {"http", "streamable-http", "streamablehttp", "remote", "url"} or (url and kind not in {"stdio", "local"}):
        return "http"
    return "stdio"


def normalize_server(name: str, raw: dict, *, client: str, config_path: str, scope: str, project: str = "") -> dict:
    command = raw.get("command")
    args = raw.get("args") or []
    env = raw.get("env") or raw.get("environment") or {}
    if isinstance(command, dict):  # Zed's older {"command": {"path", "args", "env"}}
        args = command.get("args") or args
        env = command.get("env") or env
        command = command.get("path") or ""
    if isinstance(command, list):  # OpenCode keeps the whole argv in "command"
        command, args = (command[0] if command else ""), list(command[1:]) + list(args)
    url = str(raw.get("url") or raw.get("serverUrl") or raw.get("httpUrl") or "")
    transport = _transport(raw, url)
    if not isinstance(args, list):
        args = [str(args)]
    disabled = raw.get("disabled") is True or raw.get("enabled") is False
    server_id = hashlib.sha1(f"{client}|{config_path}|{project}|{name}".encode()).hexdigest()[:10]
    return {
        "id": server_id,
        "name": str(name),
        "client": client,
        "config_path": config_path,
        "scope": scope,
        "project": project,
        "transport": transport,
        "command": str(command or ""),
        "args": [str(arg) for arg in args],
        "env": {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {},
        "url": url,
        "headers": {str(k): str(v) for k, v in (raw.get("headers") or {}).items()} if isinstance(raw.get("headers"), dict) else {},
        "disabled": disabled,
        "tools_static": None,
        "live": None,
    }


def _server_maps(data: dict) -> list[tuple[dict, str]]:
    """(name -> entry map, project path) pairs from any client's config shape."""
    found: list[tuple[dict, str]] = []
    if not isinstance(data, dict):
        return found
    for key in ("mcpServers", "servers", "context_servers", "mcp_servers"):
        value = data.get(key)
        if isinstance(value, dict):
            found.append((value, ""))
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        nested = mcp.get("servers")
        if isinstance(nested, dict):
            found.append((nested, ""))
        elif all(isinstance(v, dict) for v in mcp.values()) and any(("command" in v or "url" in v) for v in mcp.values()):
            found.append((mcp, ""))
    if isinstance(data.get("mcp.servers"), dict):
        found.append((data["mcp.servers"], ""))
    projects = data.get("projects")
    if isinstance(projects, dict):  # ~/.claude.json keeps per-project servers
        for project, body in projects.items():
            if isinstance(body, dict) and isinstance(body.get("mcpServers"), dict):
                found.append((body["mcpServers"], str(project)))
    experimental = data.get("experimental")
    if isinstance(experimental, dict) and isinstance(experimental.get("modelContextProtocolServers"), list):
        listed = {}
        for index, item in enumerate(experimental["modelContextProtocolServers"]):
            if isinstance(item, dict):
                listed[item.get("name") or f"server-{index + 1}"] = item.get("transport") or item
        found.append((listed, ""))
    return found


def parse_config(path: Path, client: str, scope: str) -> tuple[list[dict], str]:
    """Servers declared in one file, and an error string if the file could not be read."""
    try:
        data = load_structured(path)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        return [], f"{path}: {type(exc).__name__}: {exc}"
    servers = []
    for mapping, project in _server_maps(data):
        for name, raw in mapping.items():
            if not isinstance(raw, dict):
                continue
            if not any(key in raw for key in ("command", "url", "serverUrl", "httpUrl", "type", "transport")):
                continue
            entry_scope = "project" if project else scope
            servers.append(normalize_server(name, raw, client=client, config_path=str(path), scope=entry_scope, project=project))
    return servers, ""


def discover_configs(home: Path, cwd: Path, extra: list[Path] | None = None, *, known: bool = True) -> tuple[list[dict], list[dict], list[str]]:
    """Servers, the config files read, and errors."""
    files: list[dict] = []
    servers: list[dict] = []
    errors: list[str] = []
    rows = known_config_paths(home, cwd) if known else []
    for path in extra or []:
        client, scope = guess_client(Path(path))
        rows.append((client, Path(path), scope))
    seen = set()
    for client, path, scope in rows:
        key = str(Path(path).resolve()).lower() if Path(path).exists() else str(path).lower()
        if key in seen or not Path(path).is_file():
            continue
        seen.add(key)
        found, error = parse_config(Path(path), client, scope)
        if error:
            errors.append(error)
        files.append({"client": client, "path": str(path), "scope": scope, "servers": len(found), "error": error})
        servers.extend(found)
    return servers, files, errors


# --- auto-run entries --------------------------------------------------------------


def autorun_paths(home: Path, cwd: Path) -> list[tuple[str, Path, str]]:
    """(client, path, scope) for files whose commands run with no tool call: Claude Code hooks, VS Code tasks."""
    home, cwd = Path(home), Path(cwd)
    return [
        ("Claude Code", home / ".claude" / "settings.json", "user"),
        ("Claude Code", cwd / ".claude" / "settings.json", "project"),
        ("Claude Code", cwd / ".claude" / "settings.local.json", "project"),
        ("VS Code", cwd / ".vscode" / "tasks.json", "project"),
    ]


def _line_of(text: str, needle: str, nth: int = 0) -> int:
    start = -1
    for _ in range(nth + 1):
        start = text.find(needle, start + 1)
        if start < 0:
            return 0
    return text.count("\n", 0, start) + 1


def _claude_hooks(data: dict, text: str) -> list[dict]:
    """Every hook that carries a command: {"hooks": {Event: [{"matcher", "hooks": [{"type", "command"}]}]}}."""
    rows = []
    hooks = data.get("hooks") if isinstance(data, dict) else None
    for event, groups in (hooks.items() if isinstance(hooks, dict) else ()):
        for i, group in enumerate(groups if isinstance(groups, list) else []):
            if not isinstance(group, dict):
                continue
            nested = isinstance(group.get("hooks"), list)
            for j, entry in enumerate(group["hooks"] if nested else [group]):
                command = entry.get("command") if isinstance(entry, dict) else None
                if not isinstance(command, str) or not command.strip():
                    continue
                rows.append({"kind": "hook", "event": str(event), "command": command,
                             "location": f"hooks.{event}[{i}]" + (f".hooks[{j}]" if nested else ""),
                             "line": _line_of(text, json.dumps(command, ensure_ascii=False)[1:-1])})
    return rows


def _task_text(value) -> str:
    if isinstance(value, dict):  # {"value": "...", "quoting": "..."}
        return str(value.get("value") or "")
    if isinstance(value, list):
        return " ".join(_task_text(item) for item in value)
    return str(value or "")


def _folder_open_tasks(data: dict, text: str) -> list[dict]:
    """Tasks with runOptions.runOn = folderOpen, which VS Code starts when the folder opens."""
    rows = []
    tasks = data.get("tasks") if isinstance(data, dict) else None
    for i, task in enumerate(tasks if isinstance(tasks, list) else []):
        options = task.get("runOptions") if isinstance(task, dict) else None
        if not isinstance(options, dict) or str(options.get("runOn") or "").lower() != "folderopen":
            continue
        command = _task_text(task.get("command"))
        for platform in ("windows", "linux", "osx"):  # a task may define its command per platform only
            if not command and isinstance(task.get(platform), dict):
                command = _task_text(task[platform].get("command"))
        if not command and task.get("script"):
            command = f"{task.get('type') or 'npm'} run {task['script']}"
        command = " ".join(part for part in [command, _task_text(task.get("args"))] if part)
        rows.append({"kind": "task", "label": str(task.get("label") or task.get("taskName") or f"task {i + 1}"),
                     "command": command or "(no command)", "location": f"tasks[{i}]",
                     "line": _line_of(text, "folderOpen", len(rows))})
    return rows


def discover_autoruns(home: Path, cwd: Path) -> tuple[list[dict], list[str]]:
    """Hooks and folder-open tasks from the known locations, and errors."""
    rows: list[dict] = []
    errors: list[str] = []
    seen = set()
    for client, path, scope in autorun_paths(home, cwd):
        if not path.is_file() or str(path.resolve()).lower() in seen:
            continue
        seen.add(str(path.resolve()).lower())
        try:
            data = load_structured(path)
        except (OSError, ValueError) as exc:
            errors.append(f"{path}: {type(exc).__name__}: {exc}")
            continue
        text = _read_text(path) or ""
        found = _claude_hooks(data, text) if client == "Claude Code" else _folder_open_tasks(data, text)
        rows += [{**row, "client": client, "path": str(path), "scope": scope} for row in found]
    return rows, errors


# --- static tool listings ----------------------------------------------------------


def load_tools_json(payload, label: str = "tools.json") -> list[dict]:
    """Servers from a saved tools/list result: a tool array, {"tools": [...]}, or {"servers": [...]}.

    A block may also carry instructions, capabilities, prompts, resources (each optionally with the
    `contents` of its resources/read reply), and the transport it was captured over.
    """
    if isinstance(payload, (str, Path)) and Path(payload).is_file():
        label = str(payload)
        payload = json.loads(Path(payload).read_text(encoding="utf-8-sig"))
    if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
        payload = payload["result"]
    blocks = []
    if isinstance(payload, list):
        blocks = [{"name": Path(label).stem, "tools": payload}]
    elif isinstance(payload, dict) and isinstance(payload.get("servers"), list):
        blocks = [block for block in payload["servers"] if isinstance(block, dict)]
    elif isinstance(payload, dict):
        blocks = [{"name": payload.get("name") or Path(label).stem, **payload}]
    out = []
    for index, block in enumerate(blocks):
        name = str(block.get("name") or f"{Path(label).stem}-{index + 1}")
        server = normalize_server(name, {"command": ""}, client="Static JSON", config_path=label, scope="input")
        server["transport"] = "static"
        resources, coverage = saved_resources(block.get("resources") or [])
        server["live"] = {
            "ok": True,
            "source": "static",
            "error": "",
            "transport": block.get("transport") if block.get("transport") in {"http", "sse", "stdio"} else "",
            "server_info": block.get("serverInfo") or {"name": name, "version": "", "protocol": ""},
            "instructions": str(block.get("instructions") or ""),
            "capabilities": block.get("capabilities") or {},
            "tools": [tool for tool in block.get("tools") or [] if isinstance(tool, dict)],
            "prompts": [p for p in block.get("prompts") or [] if isinstance(p, dict)],
            "resources": resources,
            "coverage": coverage,
        }
        out.append(server)
    return out


# --- pasted targets ------------------------------------------------------------------

# Launchers whose URL argument is the real (remote) server.
REMOTE_WRAPPERS = {"add-mcp", "mcp-remote"}
_URL_RE = re.compile(r"^https?://", re.I)


def target_label(url: str) -> str:
    parts = urlsplit(url)
    return (parts.hostname or url) + parts.path.rstrip("/")


def _pasted(name: str, raw: dict) -> dict:
    return normalize_server(name, raw, client="Pasted", config_path="pasted", scope="input")


def _remote(url: str, headers: dict | None = None) -> dict:
    kind = "sse" if urlsplit(url).path.rstrip("/").endswith("/sse") else "http"
    return _pasted(target_label(url), {"type": kind, "url": url, "headers": headers or {}})


def parse_target(text: str) -> list[dict]:
    """Servers from whatever a person pastes: a URL, a config snippet, a tools/list JSON, or a launch command."""
    text = (text or "").strip()
    if not text:
        raise ValueError("paste an MCP server URL, a config snippet, or a launch command")
    if text[0] in "{[":
        try:
            data = json.loads(strip_jsonc(text))
        except json.JSONDecodeError as exc:
            raise ValueError(f"that looks like JSON but does not parse: {exc}") from exc
        servers = []
        for mapping, _project in _server_maps(data) if isinstance(data, dict) else []:
            servers += [_pasted(str(name), raw) for name, raw in mapping.items() if isinstance(raw, dict)]
        if not servers and isinstance(data, dict) and any(k in data for k in ("url", "serverUrl", "httpUrl", "command")):
            url = str(data.get("url") or data.get("serverUrl") or data.get("httpUrl") or "")
            servers = [_pasted(str(data.get("name") or (target_label(url) if url else data.get("command"))), data)]
        if not servers and (isinstance(data, list) or any(k in data for k in ("tools", "servers", "result"))):
            servers = load_tools_json(data, "pasted")
        if not servers:
            raise ValueError("no MCP server found in that JSON")
        return servers
    if _URL_RE.match(text) and not any(ch.isspace() for ch in text):
        return [_remote(text)]
    argv = [arg.strip("'\"") for arg in shlex.split(text, posix=os.name != "nt")]
    if not argv:
        raise ValueError("paste an MCP server URL, a config snippet, or a launch command")
    urls = [arg for arg in argv if _URL_RE.match(arg)]
    words = {Path(arg).name.lower().split("@")[0] for arg in argv}
    if urls and (words & REMOTE_WRAPPERS or (Path(argv[0]).stem.lower() in {"claude", "codex", "gemini"} and "mcp" in argv)):
        return [_remote(urls[0])]
    from wiggle.zgscanner.supply import launch_package

    package = launch_package(argv[0], argv[1:])
    return [_pasted((package or {}).get("name") or Path(argv[0]).name, {"command": argv[0], "args": argv[1:]})]


# --- skills ------------------------------------------------------------------------


def skill_roots(home: Path, cwd: Path) -> list[tuple[Path, str]]:
    home, cwd = Path(home), Path(cwd)
    rows = []
    for base in (home, cwd):
        rows += [
            (base / ".claude" / "skills", "skill"),
            (base / ".claude" / "commands", "command"),
            (base / ".claude" / "agents", "agent"),
            (base / ".agents" / "skills", "skill"),
            (base / ".codex" / "skills", "skill"),
            (base / ".cursor" / "skills", "skill"),
            (base / ".gemini" / "skills", "skill"),
            (base / ".github" / "skills", "skill"),
        ]
    rows.append((home / ".config" / "agents" / "skills", "skill"))
    rows.append((home / ".claude" / "plugins", "plugin"))
    return rows


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """A small YAML-subset reader for skill frontmatter: key: value and simple lists."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    block = text[3:end].strip("\r\n")
    body = text[end + 4:]
    data: dict = {}
    key = None
    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        item = re.match(r"^\s+-\s*(.*)$", line)
        if item and key:
            if not isinstance(data.get(key), list):
                data[key] = []
            data[key].append(item.group(1).strip().strip("'\""))
            continue
        pair = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*(.*)$", line)
        if pair:
            key, value = pair.group(1), pair.group(2).strip()
            if value.startswith("[") and value.endswith("]"):
                data[key] = [part.strip().strip("'\"") for part in value[1:-1].split(",") if part.strip()]
            else:
                data[key] = value.strip("'\"") if value not in {"|", ">", ""} else ""
        elif key and isinstance(data.get(key), str):
            data[key] = (data[key] + " " + line.strip()).strip()
    return data, body


def _skill_files(folder: Path) -> list[dict]:
    files = []
    for path in sorted(folder.rglob("*")):
        if len(files) >= MAX_SKILL_FILES:
            break
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SKILL_TEXT_SUFFIXES and path.name != "SKILL.md":
            files.append({"path": str(path), "rel": str(path.relative_to(folder)), "text": None, "binary": True})
            continue
        text = _read_text(path)
        files.append({"path": str(path), "rel": str(path.relative_to(folder)), "text": text, "binary": False})
    return files


def load_skill(path: Path, kind: str = "skill") -> dict:
    """One skill: a folder with SKILL.md, a SKILL.md path, or a single command/agent .md file."""
    path = Path(path)
    if path.is_dir():
        folder, main = path, path / "SKILL.md"
    elif path.name == "SKILL.md":
        folder, main = path.parent, path
    else:
        folder, main = path.parent, path
    text = _read_text(main) if main.is_file() else None
    meta, body = parse_frontmatter(text or "")
    if main.name == "SKILL.md" or path.is_dir():
        files = _skill_files(folder)
        name_dir = folder.name
    else:
        files = [{"path": str(main), "rel": main.name, "text": text, "binary": False}]
        name_dir = main.stem
    return {
        "id": hashlib.sha1(str(main).lower().encode()).hexdigest()[:10],
        "name": str(meta.get("name") or name_dir),
        "kind": kind,
        "path": str(main),
        "folder": str(folder),
        "dir_name": name_dir,
        "has_skill_md": main.is_file(),
        "frontmatter": meta,
        "body": body,
        "files": files,
    }


def discover_skills(home: Path, cwd: Path, extra: list[Path] | None = None) -> list[dict]:
    skills: list[dict] = []
    seen: set[str] = set()

    def add(path: Path, kind: str) -> None:
        key = str(Path(path).resolve()).lower()
        if key not in seen and len(skills) < MAX_SKILLS:
            seen.add(key)
            skills.append(load_skill(path, kind))

    for root, kind in skill_roots(home, cwd):
        if not root.is_dir():
            continue
        if kind in {"command", "agent"}:
            for path in sorted(root.rglob("*.md")):
                add(path, kind)
            continue
        for path in sorted(root.rglob("SKILL.md")):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            add(path, "skill" if kind == "plugin" else kind)
        if kind == "skill":  # a folder without SKILL.md is itself a finding (SK006)
            for child in sorted(root.iterdir()):
                if child.is_dir() and not any(child.rglob("SKILL.md")):
                    add(child, kind)
    for path in extra or []:
        add(Path(path), "skill")
    return skills


# --- source trees ------------------------------------------------------------------------


def walk_source(root: Path) -> list[dict]:
    root = Path(root)
    files = []
    if root.is_file():
        candidates = [root]
        root = root.parent
    else:
        candidates = (p for p in root.rglob("*"))
    for path in candidates:
        if len(files) >= MAX_SOURCE_FILES:
            break
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        name = path.name.lower()
        is_manifest = name in {"package.json", "pyproject.toml", "requirements.txt"} or (name.startswith("requirements") and name.endswith(".txt"))
        if path.suffix.lower() not in CODE_SUFFIXES and not is_manifest:
            continue
        text = _read_text(path)
        if text is not None:
            files.append({"path": str(path), "rel": str(path.relative_to(root)), "text": text})
    return files
