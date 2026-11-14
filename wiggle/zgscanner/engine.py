"""Scan engine: build the inventory, run every applicable check, score, and report check status."""

from __future__ import annotations

import hashlib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from wiggle.scan_local import default_workers

from wiggle.zgscanner import __version__
from wiggle.zgscanner import discover, flows, live, rules, supply
from wiggle.zgscanner.catalog import (
    CATEGORIES, CHECKS, CHECKS_BY_ID, OWASP, REQUIREMENTS, SEVERITY_RANK, SEVERITY_WEIGHT, coverage,
)
from wiggle.zgscanner.llm import DEFAULT_MODEL

DEFAULT_PINS = Path.home() / ".wiggle-zgscanner" / "pins.json"
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "cmd", "powershell", "pwsh", "fish"}
SHELL_FLAGS = {"-c", "/c", "/k", "-command", "-encodedcommand", "-enc", "-e", "-ec"}
INLINE = {"node": {"-e", "--eval", "-p", "--print"}, "python": {"-c"}, "python3": {"-c"}, "deno": {"eval"},
          "bun": {"-e", "--eval"}, "ruby": {"-e"}, "perl": {"-e"}}
EXFIL_PARAMS = {"feedback", "debug", "debug_info", "extra", "extras", "metadata", "notes", "sidenote", "side_note", "notes_for_ai",
                "conversation", "conversation_history", "chat_history", "history", "transcript", "context", "full_context",
                "user_context", "system_prompt", "instructions", "internal", "hidden", "secret", "reasoning", "thoughts",
                "additional_context", "additional_info", "user_info", "telemetry"}
READ_PREFIXES = ("get", "list", "read", "search", "find", "fetch", "show", "describe", "view", "query", "lookup", "check")
WRITE_WORDS = re.compile(r"\b(writes?|deletes?|removes?|overwrites?|sends?|uploads?|posts?|executes?|runs? (a |the )?command|"
                         r"modif(y|ies)|creates?|drops?|transfers?|publish(es)?)\b(?!\s*[{\[])", re.I)  # "send {}" is an argument value
AUTH_HEADER = re.compile(r"authorization|api[-_]?key|token|x-.*key|cookie", re.I)
SKILL_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
NETWORK_DOC = re.compile(r"\b(network|https?|urls?|api|internet|download|fetch|request|web|online|remote|endpoint)\b", re.I)
FIN_TEXT = re.compile(r"\b(transfer (funds|money)|send (money|payment|funds|crypto)|place (an? )?(order|trade)|execute (a )?"
                      r"(trade|payment|transaction)|charge (the |a )?(card|customer))\b", re.I)
BROWSE_TEXT = re.compile(r"\b(browse|visit|open|fetch|read) (any|arbitrary|the user'?s?|a given|the given) (url|web ?page|website|link)s?\b"
                         r"|\bsearch the web\b", re.I)
LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
MIN_PROTOCOL = "2025-06-18"
# TP016: a write word right after a negation, or "publish" with the vendor as subject, is not a write claim.
NEGATED = re.compile(r"\b(do not|don't|does not|doesn't|must not|never|without|cannot|can't|will not|won't)\b(\W+\w+){0,3}\W*$", re.I)
VENDOR_PUBLISH = re.compile(r"\b(we|our|the|previous|last|latest|next)\s+$", re.I)
# SK007: package runners whose arguments are left open by an allowed-tools entry such as Bash(npx pkg:*).
RUNNER_PREFIXES = {("npx",), ("bunx",), ("pnpx",), ("uvx",), ("pnpm", "dlx"), ("yarn", "dlx"), ("pipx", "run"), ("npm", "exec"),
                   ("npm", "x"), ("uv", "tool", "run")}
# SK010: a server's own statement that it is read-only, and served-skill lines that go past it.
READ_ONLY_CLAIM = re.compile(
    r"\b(every|all|each)( of (the|these|its|our))? tools? (is|are) read[- ]only\b"
    r"|\b(this|the) (server|connector|service|api|mcp)( server)? is (a )?read[- ]only\b"
    r"|(^|[.!?]\s+|\n\s*)read[- ]only\s*[.!]", re.I)
NO_WRITE_TOOLS = re.compile(
    r"\b(no|not|never|without)\b[^.]{0,600}?\b(?P<tools>tools?\s+(that|which|to)\s+([\w/-]+,?\s+((or|and)\s+)?){0,12}(create|"
    r"update|write|modify|delete|remove)\b(\s+anything)?)", re.I)
_SKILL_CMD = r"^[ \t]*`?(\$[ \t]*)?[A-Za-z][\w.-]*([ \t]+[\w.:/<>-]+){0,3}?[ \t]+(%s)\b[^\n`]*"
SKILL_DELETE = re.compile(_SKILL_CMD % "delete|remove|rm|destroy|purge|drop", re.M | re.I)
SKILL_WRITE = re.compile(_SKILL_CMD % "create|update|add|edit|set|write|patch|register|signup|import", re.M | re.I)
SKILL_INSTALL = re.compile(r"\b(npm (install|i) (-g|--global)|pnpm add (-g|--global)|yarn global add|pipx? install|uv tool install|"
                           r"cargo install|go install|brew install|gem install)\b[^\n`]*|\b(curl|wget)\b[^\n|`]*\|\s*(sudo\s+)?(ba|z)?sh\b", re.I)
GRANT_TOOLS = {"*", "bash", "write", "edit", "multiedit", "notebookedit"}


@dataclass
class ScanOptions:
    home: Path = field(default_factory=Path.home)
    cwd: Path = field(default_factory=Path.cwd)
    discover: bool = True
    configs: list = field(default_factory=list)
    tools_json: list = field(default_factory=list)
    skills: bool = True
    skill_paths: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    connect: object = ()  # "all", or server ids / names
    identify_as: str = ""
    timeout: float = 60
    workers: int = 0
    osv: bool = False
    virustotal: bool = False
    llm: bool = False
    llm_model: str = DEFAULT_MODEL
    pins: Path | None = None
    pin: bool = False
    allowlist: list | None = None
    text: str = ""
    targets: list = field(default_factory=list)  # pasted URLs, snippets, or launch commands


class Findings:
    def __init__(self) -> None:
        self.rows: list[dict] = []
        self._seen: set[tuple] = set()

    def add(self, check_id: str, severity: str | None = None, *, target_type: str, target: str, target_id: str = "",
            location: str = "", evidence: str = "", detail: str = "", agent: str = "", file: str = "", line: int = 0) -> None:
        check = CHECKS_BY_ID[check_id]
        key = (check_id, target_id or target, location, detail)
        if key in self._seen:
            return
        self._seen.add(key)
        self.rows.append({
            "check": check_id,
            "title": check.title,
            "severity": severity or check.severity,
            "category": check.category,
            "owasp": list(check.owasp),
            "sources": list(check.sources),
            "target_type": target_type,
            "target": target,
            "target_id": target_id,
            "agent": agent,
            "location": location,
            "file": file,
            "line": line,
            "evidence": rules.redact_secrets(evidence)[:600],
            "detail": rules.redact_secrets(detail)[:600],
            "remediation": check.remediation,
        })

    def hits(self, hits: list[dict], **where) -> None:
        for hit in hits:
            self.add(hit["check"], hit["severity"], evidence=hit["evidence"], detail=hit["detail"], **where)


# --- helpers -------------------------------------------------------------------


def _exe(command: str) -> str:
    name = Path(command or "").name.lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _line(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1 if start >= 0 else 0


def _hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def tool_fingerprint(tool: dict) -> str:
    return _hash({key: tool.get(key) for key in ("name", "description", "inputSchema", "annotations", "outputSchema")})


def config_fingerprint(server: dict) -> str:
    return _hash({key: server.get(key) for key in ("transport", "command", "args", "env", "url", "headers")})


def server_key(server: dict) -> str:
    return f"{server['client']}::{server['project'] + '::' if server['project'] else ''}{server['name']}"


def display_command(server: dict) -> str:
    if server["transport"] in {"http", "sse"}:
        parts = urlsplit(server["url"])
        query = "&".join(f"{k}={rules.redact(v) if rules.SECRET_KEY_NAME.search(k) else v}" for k, v in parse_qsl(parts.query))
        return rules.redact_secrets(parts._replace(query=query).geturl())
    return rules.redact_secrets(" ".join([server["command"], *server["args"]]).strip())


def _agent(server: dict) -> str:
    return server["client"] if not server["project"] else f"{server['client']} · {Path(server['project']).name or server['project']}"


# --- configuration checks ----------------------------------------------------------


def config_checks(server: dict, out: Findings, allowlist: list | None) -> dict | None:
    where = {"target_type": "server", "target": server["name"], "target_id": server["id"], "agent": _agent(server),
             "file": server["config_path"]}
    location = server["config_path"]
    if server["transport"] == "static":
        out.hits(rules.name_hits(server["name"]), location="name", **where)
        return None
    for key, value in server["env"].items():
        hits = rules.secret_hits(value)
        if hits:
            out.hits(hits, location=f"env.{key}", **where)
        elif rules.is_literal_secret(key, value):
            out.add("SEC001", "high", evidence=f"{key}={rules.redact(value)}", detail="credential written in config", location=f"env.{key}", **where)
    args = server["args"]
    for index, arg in enumerate(args):
        out.hits(rules.secret_hits(arg), location=f"args[{index}]", **where)
        flag, eq, value = arg.partition("=")
        if eq and flag.startswith("-") and rules.is_literal_secret(flag, value):
            out.add("SEC001", "high", evidence=f"{flag}={rules.redact(value)}", detail="credential in argument", location=f"args[{index}]", **where)
        elif arg.startswith("-") and index + 1 < len(args) and rules.is_literal_secret(arg, args[index + 1]):
            out.add("SEC001", "high", evidence=f"{arg} {rules.redact(args[index + 1])}", detail="credential in argument", location=f"args[{index + 1}]", **where)
    for key, value in server["headers"].items():
        hits = rules.secret_hits(value)
        if hits:
            out.hits(hits, location=f"headers.{key}", **where)
        elif rules.is_literal_secret(key, value) or (key.lower() == "authorization" and len(value) > 20 and "${" not in value):
            out.add("SEC001", "high", evidence=f"{key}: {rules.redact(value)}", detail="credential in header", location=f"headers.{key}", **where)
    if server["url"]:
        out.hits(rules.secret_hits(server["url"]), location="url", **where)
        for name, value in parse_qsl(urlsplit(server["url"]).query):
            if rules.is_literal_secret(name, value):
                out.add("SEC001", "high", evidence=f"{name}={rules.redact(value)}", detail="credential in URL query", location="url", **where)

    exe = _exe(server["command"])
    cmdline = " ".join([server["command"], *args])
    out.hits(rules.command_hits(cmdline), location="command", **where)
    lowered = [arg.lower() for arg in args]
    if exe in SHELLS and any(arg in SHELL_FLAGS for arg in lowered):
        out.add("CF003", evidence=display_command(server), detail=f"started through {exe}", location="command", **where)
    elif exe in INLINE and any(arg in INLINE[exe] for arg in lowered):
        out.add("CF003", evidence=display_command(server), detail=f"inline {exe} script", location="command", **where)

    package = supply.launch_package(server["command"], args)
    if package:
        if not package["pinned"]:
            detail = f"{package['ecosystem']} {package['spec']} has no exact version"
            if package["auto_yes"]:
                detail += "; -y installs without a prompt"
            out.add("CF002", evidence=display_command(server), detail=detail, location="command", **where)
        squat = supply.typosquat(package["name"])
        if squat:
            out.add("CF009", evidence=package["name"], detail=f"close to {squat}", location="command", **where)
        for advisory in supply.advisories_for(package["ecosystem"], package["name"], package["version"]):
            out.add("CF010", evidence=f"{package['name']}@{package['version']}",
                    detail=f"{', '.join(advisory['ids'])}: {advisory['summary']}; fixed in {advisory['fixed']}", location="command", **where)
    if exe in {"docker", "podman"}:
        joined = " ".join(lowered)
        reasons = []
        if "--privileged" in lowered:
            reasons.append("--privileged")
        if re.search(r"--(network|net)[ =]host\b", joined):
            reasons.append("host network")
        if re.search(r"--pid[ =]host\b", joined):
            reasons.append("host PID namespace")
        if "docker.sock" in joined:
            reasons.append("Docker socket mounted")
        if re.search(r"(-v|--volume|--mount)[ =]\s*(type=bind,\s*)?(source=)?(/|~|\$home|c:\\?)(:|,)", joined):
            reasons.append("host root or home mounted")
        if "--cap-add" in joined and re.search(r"--cap-add[ =](all|sys_admin)", joined):
            reasons.append("broad capabilities")
        if reasons:
            out.add("CF007", evidence=display_command(server), detail=", ".join(reasons), location="command", **where)

    home = str(Path.home()).lower().rstrip("\\/")
    for index, arg in enumerate(args):
        value = arg.strip().strip("'\"")
        if re.fullmatch(r"[A-Za-z]:[\\/]?|/|~|~/|\$HOME|%USERPROFILE%|\$\{env:(HOME|USERPROFILE)\}", value) or value.lower().rstrip("\\/") == home:
            out.add("CF006", evidence=value, detail="grants a filesystem root or the whole home directory", location=f"args[{index}]", **where)

    url = server["url"]
    if url:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme in {"http", "ws"} and host not in LOOPBACK and not host.endswith(".localhost"):
            out.add("CF004", evidence=display_command(server), detail=f"{parts.scheme} to {host}", location="url", **where)
        if not any(AUTH_HEADER.search(key) for key in server["headers"]) and not any(rules.SECRET_KEY_NAME.search(k) for k, _ in parse_qsl(parts.query)):
            out.add("CF005", evidence=display_command(server), detail="no auth header configured", location="url", **where)

    env_text = {key.upper(): value for key, value in server["env"].items()}
    risky = []
    if re.search(r"(--require|-r\b|--import|--loader|--experimental-loader)", env_text.get("NODE_OPTIONS", "")):
        risky.append("NODE_OPTIONS preloads code")
    for key in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONSTARTUP"):
        if env_text.get(key):
            risky.append(f"{key} set")
    if env_text.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0" or env_text.get("PYTHONHTTPSVERIFY") == "0" or env_text.get("GIT_SSL_NO_VERIFY"):
        risky.append("TLS verification disabled")
    if any(arg in {"--insecure", "--no-verify-ssl", "--ignore-certificate-errors"} for arg in lowered):
        risky.append("TLS verification disabled by flag")
    if risky:
        out.add("CF012", evidence=", ".join(risky), detail="environment changes how the runtime loads code or checks TLS", location="env", **where)

    if server["scope"] == "project":
        out.add("CF008", evidence=location, detail=f"loaded from {server['project'] or Path(location).parent}", location=location, **where)
    if allowlist is not None:
        names = {item.lower() for item in allowlist}
        package_name = (package or {}).get("name", "").lower()
        if server["name"].lower() not in names and package_name not in names and url.lower() not in names:
            out.add("CF013", evidence=server["name"], detail="not in the allowlist", location=location, **where)
    out.hits(rules.name_hits(server["name"]), location="name", **where)
    return package


def autorun_checks(entry: dict, out: Findings) -> None:
    """CF014 / CF015: a command that runs with no tool call. A project file comes with every copy of the folder."""
    path = Path(entry["path"])
    where = {"target_type": "config", "target": f"{path.parent.name}/{path.name}",
             "target_id": hashlib.sha1(str(path).encode()).hexdigest()[:10], "agent": entry["client"],
             "location": entry["location"], "file": entry["path"], "line": entry["line"]}
    project = entry["scope"] == "project"
    if entry["kind"] == "hook":
        detail = (f"{entry['event']} hook in a project settings file; it runs for anyone who opens this folder in Claude Code"
                  if project else f"{entry['event']} hook in your user settings; confirm you added it")
        out.add("CF014", None if project else "low", evidence=f"{entry['event']}: {entry['command']}", detail=detail, **where)
    else:
        out.add("CF015", evidence=f"{entry['label']}: {entry['command']}", detail="VS Code starts this task when the folder opens", **where)


# --- tool metadata checks --------------------------------------------------------------


def _write_claim(desc: str):
    """The first write word in a description that is not negated and not the vendor's own publishing."""
    for match in WRITE_WORDS.finditer(desc):
        head = re.split(r"[.;:!?\n]", desc[:match.start()])[-1]
        if NEGATED.search(head) or (match.group(0).lower().startswith("publish") and VENDOR_PUBLISH.search(head)):
            continue
        return match
    return None


def _scan_tool(tool: dict, out: Findings, where: dict, remote: bool = False) -> None:
    name = str(tool.get("name") or "")
    desc = str(tool.get("description") or "")
    loc = f"tool:{name}"
    out.hits(rules.name_hits(name), location=loc, **where)
    desc_hits = rules.scan_text(desc, "tool")
    out.hits(desc_hits, location=loc, **where)
    routes_secrets = bool({hit["check"] for hit in desc_hits} & {"TP005", "TP006"})
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        out.add("SC005", evidence=name, detail="no inputSchema", location=loc, **where)
        schema = {}
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    problems = []
    if schema and schema.get("type") not in (None, "object"):
        problems.append(f"schema type {schema.get('type')!r}")
    untyped = [p for p, body in props.items() if not isinstance(body, dict) or not (body.get("type") or body.get("enum") or body.get("anyOf") or body.get("oneOf") or body.get("$ref"))]
    if untyped:
        problems.append(f"untyped: {', '.join(untyped[:5])}")
    if not desc.strip():
        problems.append("no description")
    if problems:
        out.add("SC005", evidence=name, detail="; ".join(problems), location=loc, **where)
    annotations = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
    if not any(key in annotations for key in ("readOnlyHint", "destructiveHint", "openWorldHint")):
        out.add("SC006", evidence=name, detail="no readOnlyHint, destructiveHint, or openWorldHint", location=loc, **where)
    lowered = name.lower()
    for param, body in props.items():
        body = body if isinstance(body, dict) else {}
        pdesc = str(body.get("description") or "")
        ploc = f"{loc}.{param}"
        out.hits(rules.scan_text(pdesc, "param"), location=ploc, **where)
        out.hits(rules.name_hits(str(param)), location=ploc, **where)
        key = str(param).lower()
        if key in EXFIL_PARAMS and str(body.get("type") or "string") in {"string", "object"} and "enum" not in body:
            severity, detail = "medium", pdesc[:160] or "free-text side channel"
            if rules.EXFIL_CONTEXT.search(pdesc) or re.search(r"\b(include|conversation|context|everything|all (the )?details)\b", pdesc, re.I):
                severity = "high"
            elif routes_secrets and re.search(rf"\b{re.escape(key)}\b", desc, re.I):
                severity, detail = "high", "the tool description routes a sensitive path or chat context into this parameter"
            elif key.split("_")[0] in lowered:
                severity = "low"
            out.add("TP007", severity, evidence=f"{name}({param})", detail=detail, location=ploc, **where)
    read_claim = annotations.get("readOnlyHint") is True or lowered.startswith(READ_PREFIXES)
    match = _write_claim(desc) if read_claim else None
    if match and not re.search(r"\b(does not|doesn't|never|without) (write|delet|modif|send|execut)", desc, re.I):
        why = "readOnlyHint is true" if annotations.get("readOnlyHint") is True else f"name starts like a read ({name})"
        out.add("TP016", evidence=rules.snippet(desc, *match.span()), detail=f"{why}, but the description says it {match.group(0).lower()}", location=loc, **where)
    if annotations.get("readOnlyHint") is True and annotations.get("destructiveHint") is True:
        out.add("TP016", evidence=name, detail="readOnlyHint and destructiveHint are both true", location=loc, **where)
    check_only = flows.remote_check_only(tool, remote)
    for arg in flows.classify(tool)["arguments"]:
        if arg["constrained"] or not (arg["type"].startswith("string") or arg["type"] == "array:string"):
            continue
        check = {"path": "SC001", "url": "SC002", "sql": "SC003", "command": "SC004"}.get(arg["feature"])
        if check == "SC004" and check_only:  # a remote read-only checker cannot run the command here
            out.add(check, "low", evidence=f"{name}.{arg['name']}", detail="receives command text (may contain secrets)",
                    location=f"{loc}.{arg['name']}", **where)
        elif check:
            out.add(check, evidence=f"{name}.{arg['name']}", detail=f"{arg['type']} with no pattern or enum", location=f"{loc}.{arg['name']}", **where)


def _capability_findings(server: dict, tools: list[dict], out: Findings, where: dict, remote: bool) -> tuple[set, dict]:
    caps: set[str] = set()
    by_cap: dict[str, list[str]] = {}
    for tool in tools:
        tool_caps = flows.tool_capabilities(tool, remote)
        name = str(tool.get("name") or "")
        loc = f"tool:{name}"
        for cap in tool_caps:
            by_cap.setdefault(cap, []).append(f"{server['name']}.{name}")
        caps |= tool_caps
        if "untrusted" in tool_caps:
            out.add("TF001", evidence=name, detail="brings third-party content into the context", location=loc, **where)
        if "private" in tool_caps:
            out.add("TF002", "medium" if flows.sensitive_private(tool) else "low", evidence=name, detail="reads non-public data", location=loc, **where)
        if "sink" in tool_caps:
            out.add("TF003", evidence=name, detail="can send data out", location=loc, **where)
        if "destructive" in tool_caps:
            out.add("TF004", evidence=name, detail="deletes, overwrites, or terminates", location=loc, **where)
        elif "write" in tool_caps and not (isinstance(tool.get("annotations"), dict) and tool["annotations"].get("destructiveHint") is False):
            # destructiveHint false declares additive updates only, so a write-sounding name alone is not destructive
            out.add("TF004", "low", evidence=name, detail="modifies local state", location=loc, **where)
        if "exec" in tool_caps:
            out.add("TF005", evidence=name, detail="runs commands or code", location=loc, **where)
        if "financial" in tool_caps:
            out.add("TF006", evidence=name, detail="moves money or places orders", location=loc, **where)
        elif "paid" in tool_caps:
            out.add("TF006", evidence=f"{name}: {flows.price_text(tool)}", detail="each call is charged to the caller",
                    location=loc, **where)
    return caps, by_cap


def live_checks(server: dict, out: Findings) -> tuple[set, dict]:
    data = server["live"]
    where = {"target_type": "server", "target": server["name"], "target_id": server["id"], "agent": _agent(server),
             "file": server["config_path"]}
    tools = data.get("tools") or []
    remote = data.get("transport") in {"http", "sse"}
    caps = data.get("capabilities") or {}
    list_changed = isinstance(caps.get("tools"), dict) and bool(caps["tools"].get("listChanged"))
    every_field: set[str] = set()
    for tool in tools:
        _scan_tool(tool, out, where, remote)
        fields = output_fields(tool.get("outputSchema"))
        every_field |= fields
        out.hits(rules.steering_hits(str(tool.get("description") or ""), fields, list_changed),
                 location=f"tool:{tool.get('name') or ''}", **where)
    for prompt in data.get("prompts") or []:
        name = str(prompt.get("name") or "")
        out.hits(rules.name_hits(name), location=f"prompt:{name}", **where)
        out.hits(rules.scan_text(str(prompt.get("description") or ""), "prompt"), location=f"prompt:{name}", **where)
        for arg in prompt.get("arguments") or []:
            if isinstance(arg, dict):
                out.hits(rules.scan_text(str(arg.get("description") or ""), "param"), location=f"prompt:{name}.{arg.get('name')}", **where)
    served = []
    for resource in data.get("resources") or []:
        label = str(resource.get("uri") or resource.get("name") or "")
        text = " ".join(str(resource.get(key) or "") for key in ("name", "title", "description", "uri"))
        out.hits(rules.scan_text(text, "resource"), location=f"resource:{label}", **where)
        for item in resource.get("contents") or []:  # only bodies this scan read, within the caps
            body = item["text"]
            skill = served_skill(server, resource, item)
            if skill:
                served.append(skill)  # scanned below as a skill, which applies the same text detectors
            else:
                out.hits(rules.scan_text(body, "resource"), location=f"resource:{label}", **where)
            out.hits(rules.steering_hits(body, every_field, list_changed), location=f"resource:{label}", **where)
    instructions = data.get("instructions") or ""
    out.hits(rules.scan_text(instructions, "instructions"), location="instructions", **where)
    out.hits(rules.steering_hits(instructions, every_field, list_changed), location="instructions", **where)
    boundary = declared_boundary(data)
    skill_where = {key: value for key, value in where.items() if key != "file"}
    for skill in served:
        skill_checks(skill, out, where=skill_where)
        if boundary:
            boundary_check(skill, boundary, out, skill_where)
    server["served_skills"] = [skill["path"] for skill in served]
    total = len(instructions) + sum(len(json.dumps(tool, ensure_ascii=False)) for tool in tools)
    if total > 60000:
        out.add("TP012", "medium", evidence=f"{total} characters of tool metadata", detail="context flooding", location="tools", **where)
    if len(tools) > 30:
        out.add("TF008", evidence=f"{len(tools)} tools", detail="large tool surface", location="tools", **where)
    if list_changed:
        out.add("RP004", evidence="capabilities.tools.listChanged = true", location="initialize", **where)
    if data.get("source") == "live":
        info = data.get("server_info") or {}
        problems = []
        if info.get("protocol") and info["protocol"] < MIN_PROTOCOL:
            problems.append(f"protocol {info['protocol']} is older than {MIN_PROTOCOL}")
        if not info.get("version"):
            problems.append("serverInfo.version is missing")
        if problems:
            out.add("PR003", evidence=info.get("name") or server["name"], detail="; ".join(problems), location="initialize", **where)
    return _capability_findings(server, tools, out, where, remote)


def output_fields(schema) -> set[str]:
    """Every property name anywhere in a tool's outputSchema, lowercased."""
    names: set[str] = set()
    stack = [schema]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if isinstance(node.get("properties"), dict):
                names |= {str(key).lower() for key in node["properties"]}
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return names


# --- served skills ---------------------------------------------------------------------------


def served_skill(server: dict, resource: dict, item: dict) -> dict | None:
    """A resource body that is an agent skill: a skill:// URI, or markdown whose frontmatter has a name and description."""
    uri = str(resource.get("uri") or "")
    text = item["text"]
    meta, body = discover.parse_frontmatter(text)
    markdown = "markdown" in str(item.get("mimeType") or "").lower() or urlsplit(uri).path.lower().endswith(".md")
    if not (uri.lower().startswith("skill://") or (markdown and meta.get("name") and meta.get("description"))):
        return None
    return {"id": server["id"], "name": str(meta.get("name") or uri), "kind": "served skill", "path": uri, "folder": uri,
            "dir_name": "", "has_skill_md": True, "frontmatter": meta, "body": body,
            "files": [{"path": uri, "rel": uri, "text": text, "binary": False, "markdown": True}]}


def declared_boundary(data: dict) -> str:
    """The server's own read-only boundary, from its instructions or its tool annotations ("" when it declares none)."""
    instructions = data.get("instructions") or ""
    tools = data.get("tools") or []
    annotated = bool(tools) and all(isinstance(t.get("annotations"), dict) and t["annotations"].get("readOnlyHint") is True
                                    for t in tools)
    parts = []
    claim = READ_ONLY_CLAIM.search(instructions)
    denial = None if claim else NO_WRITE_TOOLS.search(instructions)
    if claim:
        parts.append(f"instructions: {rules.snippet(instructions, *claim.span(), pad=0).strip('.! ')}")
    elif denial:
        near = denial.start("tools") - denial.end(1) <= 40
        quoted = rules.snippet(instructions, *denial.span(), pad=0) if near else f"{denial.group(1)} … {denial.group('tools')}"
        parts.append(f"instructions: {' '.join(quoted.split())}")
    if annotated:
        parts.append(f"all {len(tools)} tools declare readOnlyHint: true")
    return "; ".join(parts)


def allowed_tool_items(meta: dict) -> list[tuple[str, list[str]]]:
    rows = []
    for key in ("allowed-tools", "allowed_tools", "tools"):
        value = meta.get(key)
        if value:
            rows.append((key, value if isinstance(value, list) else re.findall(r"[A-Za-z*][\w-]*(?:\([^)]*\))?|\*", str(value))))
    return rows


def package_runner(item: str) -> dict | None:
    """The package an allowed-tools entry such as Bash(npx pkg:*) lets a package runner fetch and run with open arguments."""
    match = re.fullmatch(r"Bash\((.*?):?\s*\*\s*\)", item.strip(), re.S)
    words = match.group(1).split() if match else []
    if not words:
        return None
    words[0] = _exe(words[0])
    package = supply.launch_package(words[0], words[1:])
    if package and package["ecosystem"] != "docker":
        return package
    if tuple(word.lower() for word in words if not word.startswith("-")) in RUNNER_PREFIXES:
        return {"ecosystem": "", "name": "", "version": "", "pinned": False}
    return None


def boundary_check(skill: dict, boundary: str, out: Findings, where: dict) -> None:
    """SK010: a skill served by a server that declares itself read-only grants or documents writes, deletes, or execution."""
    text = skill["files"][0]["text"]
    code = rules.code_only(text)
    facets, first = [], None
    grants = [item for _key, items in allowed_tool_items(skill["frontmatter"]) for item in items
              if re.sub(r"\(.*", "", item.strip()).lower() in GRANT_TOOLS]
    for label, pattern in (("documents deletes", SKILL_DELETE), ("installs software", SKILL_INSTALL),
                           ("documents writes", SKILL_WRITE)):
        match = pattern.search(code)
        if match:
            line = " ".join(match.group(0).strip(" `$").split())
            facets.append(f"{label} ({line})")
            first = first or (line, _line(text, match.start()))
    if grants:
        facets.insert(0, f"grants {' '.join(grants)} in allowed-tools")
        first = first or (f"allowed-tools: {' '.join(grants)}", 0)
    if not facets:
        return
    line_text, line = first
    out.add("SK010", evidence=f"{boundary} | skill: {line_text}",
            detail="the server declares a read-only boundary, but this served skill " + "; ".join(facets),
            location=f"{skill['path']}:{line}" if line else skill["path"], file=skill["path"], line=line, **where)


def cross_server_checks(groups: dict[str, list[dict]], out: Findings) -> None:
    for agent, servers in groups.items():
        owners: dict[str, list[dict]] = {}
        for server in servers:
            for tool in (server.get("live") or {}).get("tools") or []:
                owners.setdefault(str(tool.get("name") or ""), []).append(server)
        for name, holders in owners.items():
            if len(holders) > 1 and name:
                for server in holders:
                    others = sorted({s["name"] for s in holders if s is not server})
                    out.add("TP017", evidence=name, detail=f"also exposed by {', '.join(others)}", location=f"tool:{name}",
                            target_type="server", target=server["name"], target_id=server["id"], agent=agent)
        distinctive = {name: holders for name, holders in owners.items() if len(name) >= 8 or "_" in name}
        for server in servers:
            own = {str(t.get("name") or "") for t in (server.get("live") or {}).get("tools") or []}
            for tool in (server.get("live") or {}).get("tools") or []:
                desc = str(tool.get("description") or "")
                for other, holders in distinctive.items():
                    if other in own or not re.search(rf"(?<![\w-]){re.escape(other)}(?![\w-])", desc):
                        continue
                    out.add("TP004", "high", evidence=rules.snippet(desc, desc.find(other), desc.find(other) + len(other)),
                            detail=f"names {other} from {', '.join(sorted({h['name'] for h in holders}))}",
                            location=f"tool:{tool.get('name')}", target_type="server", target=server["name"],
                            target_id=server["id"], agent=agent)


# --- skills -------------------------------------------------------------------------------


def skill_checks(skill: dict, out: Findings, where: dict | None = None) -> tuple[list[str], list[str], list[dict]]:
    """Run skill checks. Returns (code file paths, binary paths, pinned packages). A served skill reports on its server."""
    where = where or {"target_type": "skill", "target": skill["name"], "target_id": skill["id"], "agent": skill["kind"]}
    meta = skill["frontmatter"]
    code_paths, binaries, pinned = [], [], []
    if skill["kind"] == "skill":
        problems = []
        if not skill["has_skill_md"]:
            out.add("SK006", "medium", evidence=skill["folder"], detail="folder has no SKILL.md", location=skill["folder"], **where)
        else:
            if not meta.get("name"):
                problems.append("frontmatter has no name")
            if not meta.get("description"):
                problems.append("frontmatter has no description")
            name = str(meta.get("name") or "")
            if name and (not SKILL_NAME.match(name) or len(name) > 64):
                problems.append(f"name {name!r} breaks the [a-z0-9-] 1-64 rule")
            if name and name != skill["dir_name"]:
                out.add("SK006", "medium", evidence=name, detail=f"name differs from directory {skill['dir_name']!r}", location=skill["path"], **where)
        if problems:
            out.add("SK006", evidence=skill["name"], detail="; ".join(problems), location=skill["path"], **where)
    for key, items in allowed_tool_items(meta):
        broad = [item for item in items if item.strip() in {"*", "Bash"} or re.fullmatch(r"Bash\(\s*\*?\s*(:\s*\*)?\s*\)", item.strip())]
        if broad:
            out.add("SK001", evidence=f"{key}: {', '.join(broad)}", detail="unrestricted shell or wildcard tools", location=skill["path"], **where)
        for item in items:
            package = package_runner(item)
            if not package:
                continue
            state = f"pinned to {package['version']}" if package["pinned"] else "not pinned"
            out.add("SK007", "medium" if package["pinned"] else "high", evidence=f"{key}: {item} ({package['name'] or 'any package'}, {state})",
                    detail="pre-approves a package runner with open arguments"
                           + ("" if package["pinned"] else "; it runs whatever version the registry serves today"),
                    location=skill["path"], **where)
    main_text = ""
    network_files = []
    for file in skill["files"]:
        if file.get("binary"):
            binaries.append(file["path"])
            continue
        text = file.get("text")
        if text is None:
            continue
        suffix = Path(file["path"]).suffix.lower()
        loc = file["rel"]
        if suffix in {".md", ".txt"} or file.get("markdown"):
            if file["path"] == skill["path"]:
                main_text = text
            for hit in rules.scan_text(text, "skill") + rules.skill_text_hits(text):
                line = _line(text, hit.get("start", -1))
                out.add(hit["check"], hit["severity"], evidence=hit["evidence"], detail=hit["detail"],
                        location=f"{loc}:{line}", file=file["path"], line=line, **where)
        elif suffix in discover.CODE_SUFFIXES:
            code_paths.append(file["path"])
            for hit in rules.code_hits(text):
                line = _line(text, hit.get("start", -1))
                out.add(hit["check"], hit["severity"], evidence=hit["evidence"], detail=hit["detail"],
                        location=f"{loc}:{line}", file=file["path"], line=line, **where)
            if rules.NETWORK_CODE.search(text):
                network_files.append(loc)
        else:
            out.hits(rules.secret_hits(text) + rules.unicode_hits(text), location=loc, **where)
            manifest_pins, _loose = supply.manifest_packages(file["path"], text)
            pinned.extend(manifest_pins)
    if network_files and not NETWORK_DOC.search(main_text or skill["body"]):
        out.add("SK009", evidence=", ".join(network_files[:4]), detail="scripts use the network; SKILL.md does not say so", location=skill["path"], **where)
    body = main_text or skill["body"]
    if FIN_TEXT.search(body):
        match = FIN_TEXT.search(body)
        out.add("TF006", evidence=rules.snippet(body, *match.span()), detail="skill moves money", location=skill["path"], **where)
    if BROWSE_TEXT.search(body):
        match = BROWSE_TEXT.search(body)
        out.add("TF001", evidence=rules.snippet(body, *match.span()), detail="skill reads arbitrary web content", location=skill["path"], **where)
    return code_paths, binaries, pinned


# --- source trees -------------------------------------------------------------------------


def source_checks(root: Path, out: Findings) -> tuple[list[str], list[dict]]:
    files = discover.walk_source(root)
    label = Path(root).name or str(root)
    where = {"target_type": "source", "target": label, "target_id": hashlib.sha1(str(root).encode()).hexdigest()[:10], "agent": "source"}
    code_paths, pinned, loose = [], [], []
    logging_seen = False
    auth_seen = False
    listeners = []
    for file in files:
        text = file["text"]
        manifest_pins, manifest_loose = supply.manifest_packages(file["path"], text)
        if manifest_pins or manifest_loose:
            pinned.extend(manifest_pins)
            loose.extend(f"{file['rel']}: {item}" for item in manifest_loose)
            continue
        if Path(file["path"]).suffix.lower() not in discover.CODE_SUFFIXES:
            continue
        code_paths.append(file["path"])
        logging_seen = logging_seen or bool(rules.LOGGING_CODE.search(text))
        auth_seen = auth_seen or bool(re.search(r"authorization|bearer|oauth|api[_-]?key|verify_token|authenticate", text, re.I))
        for hit in rules.code_hits(text):
            line = _line(text, hit.get("start", -1))
            spot = {"location": f"{file['rel']}:{line}", "file": file["path"], "line": line}
            if hit["check"] == "CODE004":
                listeners.append((hit, spot))
                continue
            out.add(hit["check"], hit["severity"], evidence=hit["evidence"], detail=hit["detail"], **spot, **where)
    for hit, spot in listeners:
        out.add("CODE004", "medium" if auth_seen else "high", evidence=hit["evidence"],
                detail=hit["detail"] + ("" if auth_seen else "; no auth code found in the tree"), **spot, **where)
    if loose:
        out.add("CODE008", evidence="; ".join(loose[:6]), detail=f"{len(loose)} unpinned dependenc(ies)", location=str(root), **where)
    manifests = {Path(f["path"]).name.lower() for f in files}
    lockfiles = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock", "poetry.lock", "pipfile.lock", "bun.lockb"}
    if "package.json" in manifests and not any((Path(root) / name).exists() for name in lockfiles):
        out.add("CODE008", evidence="package.json", detail="no lockfile next to package.json", location=str(root), **where)
    if code_paths and not logging_seen:
        out.add("CODE007", evidence=f"{len(code_paths)} code file(s)", detail="no logging calls found", location=str(root), **where)
    return code_paths, pinned


# --- drift ----------------------------------------------------------------------------------


def skill_fingerprint(skill: dict) -> str:
    return _hash([[f["rel"], f.get("text") if f.get("text") is not None else "<binary>"] for f in skill["files"]])


def current_pins(servers: list[dict], skills: list[dict]) -> dict:
    pins = {"servers": {}, "skills": {}}
    for server in servers:
        entry: dict = {}
        if server["transport"] != "static":
            entry["config"] = config_fingerprint(server)
        data = server.get("live") or {}
        if data.get("ok"):
            entry["tools"] = {str(t.get("name") or ""): tool_fingerprint(t) for t in data.get("tools") or []}
            entry["instructions"] = _hash(data.get("instructions") or "")
        pins["servers"][server_key(server)] = entry
    for skill in skills:
        pins["skills"][skill["path"]] = skill_fingerprint(skill)
    return pins


def drift_checks(servers: list[dict], skills: list[dict], baseline: dict, out: Findings) -> None:
    now = current_pins(servers, skills)
    for server in servers:
        key = server_key(server)
        old, new = baseline.get("servers", {}).get(key), now["servers"].get(key, {})
        if not old:
            continue
        where = {"target_type": "server", "target": server["name"], "target_id": server["id"], "agent": _agent(server)}
        if old.get("config") and new.get("config") and old["config"] != new["config"]:
            out.add("RP002", evidence=display_command(server), detail="launch command, URL, or environment changed", location=server["config_path"], **where)
        if old.get("tools") is not None and new.get("tools") is not None:
            before, after = old["tools"], new["tools"]
            added = sorted(set(after) - set(before))
            removed = sorted(set(before) - set(after))
            changed = sorted(name for name in set(before) & set(after) if before[name] != after[name])
            if added or removed or changed:
                parts = [f"{label}: {', '.join(names[:6])}" for label, names in (("changed", changed), ("added", added), ("removed", removed)) if names]
                out.add("RP001", "high" if changed else "medium", evidence="; ".join(parts), detail="tools differ from the pinned set", location="tools", **where)
            if old.get("instructions") and new.get("instructions") and old["instructions"] != new["instructions"]:
                out.add("RP001", "medium", evidence="server instructions", detail="initialize instructions changed", location="instructions", **where)
    for skill in skills:
        old = baseline.get("skills", {}).get(skill["path"])
        if old and old != now["skills"][skill["path"]]:
            out.add("RP003", evidence=skill["path"], detail="skill files changed since pin", location=skill["path"],
                    target_type="skill", target=skill["name"], target_id=skill["id"], agent=skill["kind"])


def write_pins(path: Path, servers: list[dict], skills: list[dict]) -> dict:
    path = Path(path)
    existing = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"servers": {}, "skills": {}}
    now = current_pins(servers, skills)
    for key, entry in now["servers"].items():
        merged = dict(existing.get("servers", {}).get(key) or {})
        merged.update(entry)
        existing.setdefault("servers", {})[key] = merged
    existing.setdefault("skills", {}).update(now["skills"])
    existing["pinned_at"] = _now()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return existing


# --- scoring --------------------------------------------------------------------------------


def risk_score(findings: list[dict]) -> int:
    worst: dict[tuple, str] = {}
    for row in findings:
        key = (row["check"], row["target_id"] or row["target"])
        if key not in worst or SEVERITY_RANK[row["severity"]] < SEVERITY_RANK[worst[key]]:
            worst[key] = row["severity"]
    safe = 1.0
    for severity in worst.values():
        safe *= 1 - SEVERITY_WEIGHT[severity] / 100
    return round(100 * (1 - safe))


def grade(risk: int) -> str:
    for limit, letter in ((10, "A"), (30, "B"), (55, "C"), (80, "D")):
        if risk < limit:
            return letter
    return "F"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _wants(server: dict, connect) -> bool:
    if connect == "all":
        return server["transport"] in {"stdio", "http"} and not server["disabled"]
    picks = {str(item).lower() for item in connect or ()}
    return server["id"] in picks or server["name"].lower() in picks


# --- the scan -------------------------------------------------------------------------------


def run_scan(opts: ScanOptions, *, llm_client=None, progress=None) -> dict:
    say = progress or (lambda message: None)
    errors: list[str] = []
    out = Findings()
    servers, files, config_errors = discover.discover_configs(opts.home, opts.cwd, [Path(p) for p in opts.configs], known=opts.discover)
    errors.extend(config_errors)
    autoruns, autorun_errors = discover.discover_autoruns(opts.home, opts.cwd) if opts.discover else ([], [])
    errors.extend(autorun_errors)
    for entry in autoruns:
        autorun_checks(entry, out)
    for item in opts.tools_json:
        try:
            servers.extend(discover.load_tools_json(item))
        except (OSError, ValueError) as exc:
            errors.append(f"tools JSON {item if isinstance(item, (str, Path)) else '(inline)'}: {exc}")
    pasted_remote: set[str] = set()
    for text in opts.targets:
        try:
            found = discover.parse_target(text)
        except ValueError as exc:
            errors.append(f"pasted target: {exc}")
            continue
        servers.extend(found)
        # Pasting a URL asks for it to be scanned; a pasted launch command is checked without being run.
        pasted_remote |= {server["id"] for server in found if server["transport"] in {"http", "sse"}}
    skills = discover.discover_skills(opts.home, opts.cwd, [Path(p) for p in opts.skill_paths]) if opts.skills else \
        [discover.load_skill(Path(p)) for p in opts.skill_paths]
    unique: dict[str, dict] = {}
    for skill in skills:  # plugin caches keep identical copies; report each content once
        first = unique.setdefault(skill_fingerprint(skill), skill)
        first.setdefault("copies", []).append(skill["path"]) if first is not skill else None
    skills = list(unique.values())
    say(f"inventory: {len(servers)} server(s), {len(skills)} skill(s)")

    targets = [server for server in servers if server["id"] in pasted_remote or _wants(server, opts.connect)]
    workers = opts.workers if opts.workers > 0 else default_workers(len(targets))
    if targets:
        say(f"connecting to {len(targets)} server(s)")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda s: live.introspect(s, timeout=opts.timeout), targets))
        for server, result in zip(targets, results):
            server["live"] = result
            if not result["ok"]:
                errors.append(f"{server['name']}: {result['error']}")
        if opts.identify_as:
            pairs = [s for s in targets if s["live"]["ok"]]
            with ThreadPoolExecutor(max_workers=workers) as pool:
                second = list(pool.map(lambda s: live.introspect(s, timeout=opts.timeout, client_name=opts.identify_as), pairs))
            for server, result in zip(pairs, second):
                server["live_alt"] = result
                if result["ok"]:
                    a = {tool_fingerprint(t) for t in server["live"]["tools"]}
                    b = {tool_fingerprint(t) for t in result["tools"]}
                    if a != b:
                        out.add("PR001", evidence=f"{live.CLIENT_NAME}: {len(a)} tools; {opts.identify_as}: {len(b)} tools",
                                detail=f"{len(a ^ b)} tool definition(s) differ by client name", location="tools/list",
                                target_type="server", target=server["name"], target_id=server["id"], agent=_agent(server))

    packages: list[dict] = []
    groups: dict[str, list[dict]] = {}
    flow_members: dict[str, list[dict]] = {}
    for server in servers:
        package = config_checks(server, out, opts.allowlist)
        if package and package["ecosystem"] in {"npm", "PyPI"} and package["version"]:
            packages.append({**package, "server": server})
        data = server.get("live") or {}
        if data.get("ok"):
            caps, by_cap = live_checks(server, out)
            inferred = False
        else:
            caps = flows.name_capabilities(server["name"], (package or {}).get("name", ""), urlsplit(server["url"]).hostname or "")
            by_cap, inferred = {}, True
        server["capabilities"] = sorted(caps)
        server["capabilities_inferred"] = inferred
        if server["disabled"]:
            continue
        agent = _agent(server) if server["transport"] != "static" else "Static JSON"
        groups.setdefault(agent, []).append(server)
        flow_members.setdefault(agent, []).append({"label": server["name"], "caps": caps, "by_cap": by_cap, "inferred": inferred})
    cross_server_checks(groups, out)
    flow_rows = flows.toxic_flows(flow_members)
    for flow in flow_rows:
        detail = "one server holds all three legs" if flow["single_server"] else "legs spread across servers"
        if flow["inferred"]:
            detail += "; inferred from server names, connect the servers to confirm"
        out.add("TF007", flow["severity"], evidence=f"untrusted: {', '.join(flow['untrusted'][:3])} → private: "
                f"{', '.join(flow['private'][:3])} → sink: {', '.join(flow['sink'][:3])}", detail=detail,
                location=flow["agent"], target_type="agent", target=flow["agent"], target_id=f"agent:{flow['agent']}", agent=flow["agent"])

    code_paths: list[str] = []
    binaries: list[str] = []
    for skill in skills:
        skill_code, skill_bin, skill_pins = skill_checks(skill, out)
        code_paths += skill_code
        binaries += skill_bin
        packages += skill_pins
    for root in opts.sources:
        if not Path(root).exists():
            errors.append(f"source {root}: not found")
            continue
        src_code, src_pins = source_checks(Path(root), out)
        code_paths += src_code
        packages += src_pins

    pins_path = Path(opts.pins) if opts.pins else DEFAULT_PINS
    baseline = None
    if pins_path.is_file():
        try:
            baseline = json.loads(pins_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"pins {pins_path}: {exc}")
    if baseline:
        drift_checks(servers, skills, baseline, out)

    ran = {"static": True, "live": any((s.get("live") or {}).get("ok") for s in servers), "baseline": bool(baseline),
           "identify": bool(opts.identify_as) and any((s.get("live_alt") or {}).get("ok") for s in servers),
           "source": bool(code_paths) or bool(opts.sources), "allowlist": opts.allowlist is not None,
           "skills": bool(skills) or any(s.get("served_skills") for s in servers),
           "osv": False, "virustotal": False, "llm": False}
    reasons: dict[str, str] = {}

    if opts.osv:
        try:
            say(f"querying OSV for {len(packages)} package(s)")
            vulns = supply.osv_query(packages)
            ran["osv"] = True
            for row in packages:
                ids = vulns.get((row["ecosystem"], row["name"], row["version"]))
                if not ids:
                    continue
                server = row.get("server")
                where = ({"target_type": "server", "target": server["name"], "target_id": server["id"], "agent": _agent(server)}
                         if server else {"target_type": "package", "target": row["name"], "target_id": f"pkg:{row['name']}", "agent": "dependencies"})
                out.add("CF011", evidence=f"{row['name']}@{row['version']} ({row['ecosystem']})",
                        detail=", ".join(ids[:8]) + (f" and {len(ids) - 8} more" if len(ids) > 8 else ""), location="osv.dev", **where)
        except Exception as exc:
            reasons["osv"] = f"OSV query failed: {exc}"
            errors.append(reasons["osv"])
    if opts.virustotal:
        key = os.environ.get("VT_API_KEY", "")
        if not key:
            reasons["virustotal"] = "VT_API_KEY is not set"
        else:
            try:
                paths = binaries + [p for p in code_paths if p not in binaries]
                say(f"VirusTotal lookups for up to {min(len(paths), 20)} file(s)")
                for row in supply.virustotal_lookup(paths, key):
                    ran["virustotal"] = True
                    if row["malicious"] or row["suspicious"]:
                        out.add("VT001", "critical" if row["malicious"] else "medium", evidence=row["sha256"],
                                detail=f"{row['malicious']} malicious, {row['suspicious']} suspicious engine verdict(s)",
                                location=row["path"], target_type="file", target=Path(row["path"]).name, target_id=row["sha256"], agent="files")
                ran["virustotal"] = True
            except Exception as exc:
                reasons["virustotal"] = f"VirusTotal lookup failed: {exc}"
                errors.append(reasons["virustotal"])
    if opts.llm:
        try:
            client = llm_client
            if client is None:
                from wiggle.zgscanner.llm import make_client
                client = make_client()
            from wiggle.zgscanner.llm import judge_server
            judged = [s for s in servers if (s.get("live") or {}).get("ok") and s["live"].get("tools")]
            for server in judged:
                say(f"LLM judge: {server['name']}")
                for row in judge_server(client, server["name"], server["live"]["tools"], server["live"].get("instructions", ""), opts.llm_model):
                    severity = row.get("severity") if row.get("severity") in SEVERITY_RANK else "medium"
                    out.add("LLM001", severity, evidence=str(row.get("tool") or ""), detail=f"{row.get('category')}: {row.get('explanation')}",
                            location=f"tool:{row.get('tool')}", target_type="server", target=server["name"], target_id=server["id"], agent=_agent(server))
            ran["llm"] = bool(judged)
            if not judged:
                reasons["llm"] = "no connected server returned tools to judge"
        except Exception as exc:
            reasons["llm"] = str(exc)
            errors.append(f"LLM judge: {exc}")
    if opts.text:
        out.hits(rules.scan_text(opts.text, "text"), location="pasted text", target_type="text", target="Pasted text", target_id="text", agent="text")

    pinned = None
    if opts.pin:
        write_pins(pins_path, servers, skills)
        pinned = str(pins_path)
    return build_report(opts, servers, skills, files, out.rows, flow_rows, ran, reasons, errors, pins_path, pinned)


def tool_summary(tool: dict, findings: list[dict], remote: bool = False) -> dict:
    name = str(tool.get("name") or "")
    annotations = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
    return {
        "name": name,
        "title": str(annotations.get("title") or tool.get("title") or ""),
        "description": rules.redact_secrets(" ".join(str(tool.get("description") or "").split()))[:400],
        "annotations": {k: annotations[k] for k in ("readOnlyHint", "destructiveHint", "openWorldHint", "idempotentHint") if k in annotations},
        "capabilities": sorted(flows.tool_capabilities(tool, remote)),
        "findings": sum(1 for row in findings if row["location"] == f"tool:{name}" or row["location"].startswith(f"tool:{name}.")),
    }


def build_report(opts, servers, skills, files, findings, flow_rows, ran, reasons, errors, pins_path, pinned) -> dict:
    findings = sorted(findings, key=lambda r: (SEVERITY_RANK[r["severity"]], r["check"], r["target"], r["location"]))
    for index, row in enumerate(findings, 1):
        row["id"] = f"F{index:04d}"
    by_check: dict[str, list[dict]] = {}
    for row in findings:
        by_check.setdefault(row["check"], []).append(row)
    checks = []
    for check in CHECKS:
        rows = by_check.get(check.id, [])
        met = ran.get(check.requires, False)
        if rows:
            status, reason = "fail", ""
        elif met:
            status, reason = "pass", ""
        else:
            status, reason = "skipped", reasons.get(check.requires) or REQUIREMENTS[check.requires]
        worst = min((r["severity"] for r in rows), key=SEVERITY_RANK.get, default="")
        checks.append({**check.as_dict(), "status": status, "reason": reason, "findings": len(rows), "worst": worst})
    severity = {name: 0 for name in SEVERITY_RANK}
    for row in findings:
        severity[row["severity"]] += 1
    owasp = {}
    for key, name in OWASP.items():
        rows = [r for r in findings if key in r["owasp"]]
        owasp[key] = {"name": name, "findings": len(rows),
                      "worst": min((r["severity"] for r in rows), key=SEVERITY_RANK.get, default=""),
                      "checks": [c.id for c in CHECKS if key in c.owasp]}
    categories = {key: {"name": name, "findings": sum(1 for r in findings if r["category"] == key)} for key, name in CATEGORIES.items()}
    server_rows = []
    for server in servers:
        own = [r for r in findings if r["target_id"] == server["id"]]
        data = server.get("live") or {}
        server_rows.append({
            "id": server["id"], "name": server["name"], "client": server["client"], "agent": _agent(server) if server["transport"] != "static" else "Static JSON",
            "config_path": server["config_path"], "scope": server["scope"], "project": server["project"], "transport": server["transport"],
            "command": display_command(server) if server["transport"] != "static" else "(static tools JSON)",
            "env_keys": sorted(server["env"]), "disabled": server["disabled"],
            "live": {"ok": bool(data.get("ok")), "source": data.get("source", ""), "error": data.get("error", ""),
                     "server_info": data.get("server_info") or {}, "tools": len(data.get("tools") or []),
                     "prompts": len(data.get("prompts") or []), "resources": len(data.get("resources") or []),
                     "transport": data.get("transport", ""), "instructions": rules.redact_secrets(data.get("instructions") or "")[:600],
                     "coverage": [{**row, "uri": rules.redact_secrets(row["uri"]), "reason": rules.redact_secrets(row["reason"])[:300]}
                                  for row in data.get("coverage") or []],
                     "tool_list": [tool_summary(t, own, data.get("transport") in {"http", "sse"})
                                   for t in (data.get("tools") or [])[:200]]} if data else None,
            "capabilities": server.get("capabilities", []), "capabilities_inferred": server.get("capabilities_inferred", True),
            "risk": risk_score(own), "findings": len(own),
            "worst": min((r["severity"] for r in own), key=SEVERITY_RANK.get, default=""),
        })
    skill_rows = []
    for skill in skills:
        own = [r for r in findings if r["target_id"] == skill["id"]]
        skill_rows.append({"id": skill["id"], "name": skill["name"], "kind": skill["kind"], "path": skill["path"],
                           "files": len(skill["files"]), "risk": risk_score(own), "findings": len(own),
                           "worst": min((r["severity"] for r in own), key=SEVERITY_RANK.get, default="")})
    risk = risk_score(findings)
    tool_count = sum(len((s.get("live") or {}).get("tools") or []) for s in servers)
    return {
        "tool": "zgscanner",
        "version": __version__,
        "scanned_at": _now(),
        "options": {
            "discover": opts.discover, "configs": [str(p) for p in opts.configs], "skills": opts.skills,
            "sources": [str(p) for p in opts.sources], "connect": opts.connect if opts.connect == "all" else list(opts.connect or ()),
            "targets": list(opts.targets), "identify_as": opts.identify_as, "osv": opts.osv, "virustotal": opts.virustotal, "llm": opts.llm,
            "pins": str(pins_path), "pinned_to": pinned, "allowlist": opts.allowlist is not None,
            "home": str(opts.home), "cwd": str(opts.cwd),
        },
        "summary": {
            "risk": risk, "grade": grade(risk), "severity": severity, "findings": len(findings),
            "servers": len(servers), "connected": sum(1 for s in servers if (s.get("live") or {}).get("ok") and s["live"].get("source") == "live"),
            "tools": tool_count, "skills": len(skills), "config_files": len(files),
            "clients": sorted({s["client"] for s in servers}),
            "checks": {status: sum(1 for c in checks if c["status"] == status) for status in ("pass", "fail", "skipped")},
        },
        "servers": server_rows,
        "skills": skill_rows,
        "config_files": files,
        "findings": findings,
        "checks": checks,
        "owasp": owasp,
        "categories": categories,
        "flows": flow_rows,
        "coverage": coverage(),
        "errors": errors,
    }
