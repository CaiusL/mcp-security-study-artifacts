"""Classify declared MCP tool arguments into the envelope families this study already measures.

The labels are a heuristic over argument names, JSON schema, and argument
descriptions. They are how a bulk scan decides which ladder a server resembles.
They are not a finding that a server is vulnerable.
"""

from __future__ import annotations

import re


# Tie break when two families cover the same number of tools. Earlier wins.
FAMILY_ORDER = (
    "path",
    "url",
    "sql",
    "git",
    "browser",
    "entity",
    "timezone",
    "command",
    "thought",
)

_PATH_NAMES = {
    "path",
    "file",
    "file_path",
    "filepath",
    "filename",
    "directory",
    "dir",
    "folder",
    "source",
    "destination",
    "dest",
    "src",
    "repo",
    "repository",
    "root",
    "cwd",
}
_URL_NAMES = {"url", "uri", "href", "endpoint", "link"}
_SQL_NAMES = {"sql", "statement"}
_GIT_NAMES = {"revision", "rev", "commit", "branch", "ref"}
_ENTITY_NAMES = {"entity", "entity_name", "entities"}
_TZ_NAMES = {"timezone", "time_zone", "tz"}
_COMMAND_NAMES = {"command", "cmd", "shell"}
_BROWSER_NAMES = {"selector", "selectors"}

_DESC_RULES = (
    ("path", re.compile(r"file ?system path|file path|directory path|\bpath to\b", re.I)),
    ("url", re.compile(r"\bhttps?\b|\burl\b|\buri\b", re.I)),
    ("timezone", re.compile(r"\btimezone\b|\btime zone\b|\biana\b", re.I)),
    ("sql", re.compile(r"\bsql\b", re.I)),
    ("command", re.compile(r"\bshell command\b|\bcommand line\b", re.I)),
    ("browser", re.compile(r"\bcss selector\b|\bselector\b", re.I)),
    ("git", re.compile(r"\bgit (revision|ref|commit|branch)\b", re.I)),
    ("entity", re.compile(r"\bentity name\b|\bknowledge graph\b", re.I)),
    ("thought", re.compile(r"\bsequential thinking\b|\bthought\b", re.I)),
)

_HINT_RULES = (
    ("path", re.compile(r"\bfilesystem\b|\bfile system\b|\bdirectory\b|\bdirectories\b", re.I)),
    ("url", re.compile(r"\bhttps?\b|\burl\b|\bfetch\b", re.I)),
    ("sql", re.compile(r"\bsqlite\b|\bpostgres(?:ql)?\b|\bsql\b", re.I)),
    ("git", re.compile(r"\bgit\b", re.I)),
    ("browser", re.compile(r"\bplaywright\b|\bpuppeteer\b|\bbrowser\b", re.I)),
    ("entity", re.compile(r"\bknowledge graph\b|\bentities\b", re.I)),
    ("timezone", re.compile(r"\btimezone\b|\btime zone\b|\biana\b", re.I)),
    ("command", re.compile(r"\bshell\b|\bterminal\b|\bcommand execution\b", re.I)),
    ("thought", re.compile(r"\bsequential[- ]thinking\b|\bthought\b", re.I)),
)

# Name or package-id tokens for the servers the full study still has to pin.
# Descriptions are ignored so a mention of GitHub does not become a candidate.
STUDY_TARGETS = {
    "sequential-thinking": ("sequential-thinking", "sequentialthinking", "sequential_thinking"),
    "playwright": ("playwright",),
    "github": ("github",),
    "sqlite": ("sqlite",),
    "postgres": ("postgres", "postgresql"),
}


def _key(name: str) -> str:
    return name.lower().replace("-", "_")


def _name_feature(name: str) -> str:
    key = _key(name)
    if key in _PATH_NAMES or key.endswith(("_path", "_file", "_dir", "_directory")):
        return "path"
    if key in _URL_NAMES or key.endswith(("_url", "_uri")):
        return "url"
    if key in _SQL_NAMES or key.endswith("_sql") or "sql" in key:
        return "sql"
    if key in _COMMAND_NAMES or key.endswith("_command"):
        return "command"
    if key in _GIT_NAMES or key.startswith("branch_") or key.endswith("_branch"):
        return "git"
    if key in _ENTITY_NAMES or key.endswith("_entity") or key.startswith("entity"):
        return "entity"
    if key in _TZ_NAMES or key.endswith("_timezone"):
        return "timezone"
    if key in _BROWSER_NAMES:
        return "browser"
    return ""


def _description_feature(description: str) -> str:
    for feature, pattern in _DESC_RULES:
        if pattern.search(description):
            return feature
    return ""


def _schema_type(prop: dict) -> str:
    raw = prop.get("type")
    if isinstance(raw, list):
        raw = next((item for item in raw if item != "null"), "")
    if raw == "array":
        items = prop.get("items")
        if isinstance(items, dict):
            inner = _schema_type(items)
            return f"array:{inner}" if inner else "array"
        return "array"
    return raw if isinstance(raw, str) else ""


def classify_argument(name: str, prop: dict | None) -> dict:
    """Label one argument. `constrained` is true when an enum or pattern is present."""
    prop = prop if isinstance(prop, dict) else {}
    feature = _name_feature(name) or _description_feature(str(prop.get("description") or ""))
    kind = _schema_type(prop)
    base = kind.split(":", 1)[0]
    constrained = "enum" in prop or "pattern" in prop
    if not feature:
        if constrained:
            feature = "enum"
        elif base == "boolean":
            feature = "boolean"
        elif base in {"integer", "number"}:
            feature = "number"
        elif base == "string":
            feature = "free-text"
        elif base in {"array", "object"}:
            feature = "structured"
        else:
            feature = "other"
    return {
        "name": name,
        "type": kind or "unspecified",
        "feature": feature,
        "required": False,
        "constrained": constrained,
    }


def _resource_features(arguments: list[dict]) -> list[str]:
    found = []
    for row in arguments:
        feature = row["feature"]
        if feature in FAMILY_ORDER and feature not in found:
            found.append(feature)
    return found


def classify_tool(tool: dict) -> dict:
    schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = set(schema.get("required") or [])
    arguments = []
    for name, prop in properties.items():
        row = classify_argument(str(name), prop if isinstance(prop, dict) else {})
        row["required"] = name in required
        arguments.append(row)
    free = [
        f"{tool.get('name') or ''}.{row['name']}"
        for row in arguments
        if row["feature"] in FAMILY_ORDER
        and (row["type"].startswith("string") or row["type"] == "array:string")
        and not row["constrained"]
    ]
    return {
        "name": str(tool.get("name") or ""),
        "description": _clip(str(tool.get("description") or "")),
        "arguments": arguments,
        "families": _resource_features(arguments),
        "free_string_resources": free,
    }


def classify_tools(tools: list[dict]) -> dict:
    classified = [classify_tool(tool) for tool in tools if isinstance(tool, dict)]
    counts: dict[str, int] = {}
    free: list[str] = []
    for tool in classified:
        for family in tool["families"]:
            counts[family] = counts.get(family, 0) + 1
        free.extend(tool["free_string_resources"])
    return {
        "tool_count": len(classified),
        "family": primary_family(counts),
        "feature_counts": counts,
        "free_string_resources": free,
        "tools": classified,
    }


def primary_family(counts: dict[str, int]) -> str:
    best = ""
    best_n = 0
    for name in FAMILY_ORDER:
        count = counts.get(name, 0)
        if count > best_n:
            best = name
            best_n = count
    return best or "unclassified"


def hint_families(*texts: str) -> list[str]:
    """Families suggested by a registry name, package id, or description."""
    blob = "\n".join(texts)
    return [name for name, pattern in _HINT_RULES if pattern.search(blob)]


def _clip(text: str, limit: int = 400) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"
