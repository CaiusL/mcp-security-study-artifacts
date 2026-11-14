"""Declared envelope: what tool metadata and server configuration promise."""

from __future__ import annotations

from dataclasses import dataclass

from wiggle.model import Call


@dataclass(frozen=True)
class ToolSpec:
    server: str
    name: str
    description: str
    properties: dict
    required: tuple[str, ...]


# Subset of the reference filesystem and fetch servers. Schemas are the PoC
# contract, shaped after the public tools, not a byte-for-byte copy.
TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        server="filesystem",
        name="read_text_file",
        description=(
            "Read a text file from inside one of the configured allowed directories. "
            "The path argument is a filesystem path."
        ),
        properties={"path": {"type": "string"}},
        required=("path",),
    ),
    ToolSpec(
        server="filesystem",
        name="write_file",
        description=(
            "Write a text file inside one of the configured allowed directories. "
            "The path argument is a filesystem path."
        ),
        properties={"path": {"type": "string"}, "content": {"type": "string"}},
        required=("path", "content"),
    ),
    ToolSpec(
        server="filesystem",
        name="list_directory",
        description=(
            "List one directory inside the configured allowed directories. "
            "The path argument is a filesystem path."
        ),
        properties={"path": {"type": "string"}},
        required=("path",),
    ),
    ToolSpec(
        server="filesystem",
        name="search_files",
        description=(
            "Search file names and text under a directory inside the configured "
            "allowed directories. The pattern is a literal substring."
        ),
        properties={"path": {"type": "string"}, "pattern": {"type": "string"}},
        required=("path", "pattern"),
    ),
    ToolSpec(
        server="filesystem",
        name="get_file_info",
        description=(
            "Return file metadata for a path inside the configured allowed directories."
        ),
        properties={"path": {"type": "string"}},
        required=("path",),
    ),
    ToolSpec(
        server="filesystem",
        name="move_file",
        description=(
            "Move a file. Both paths must stay inside the configured allowed directories."
        ),
        properties={
            "source": {"type": "string"},
            "destination": {"type": "string"},
        },
        required=("source", "destination"),
    ),
    ToolSpec(
        server="fetch",
        name="fetch",
        description=(
            "Fetch a public http or https URL and return the body as text. "
            "Private, loopback, and link-local addresses are blocked, and "
            "non-http schemes are rejected."
        ),
        properties={"url": {"type": "string"}, "max_length": {"type": "integer"}},
        required=("url",),
    ),
)

SPECS_BY_NAME = {spec.name: spec for spec in TOOL_SPECS}


def _type_ok(expected: str, value: object) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    return False


def schema_error(call: Call) -> str:
    """Return an empty string when the call matches the declared schema."""
    spec = SPECS_BY_NAME.get(call.tool)
    if spec is None or spec.server != call.server:
        return "unknown-tool"
    for name in spec.required:
        if name not in call.args:
            return f"missing-{name}"
    for name, value in call.args.items():
        prop = spec.properties.get(name)
        if prop is None:
            return f"unexpected-{name}"
        if not _type_ok(prop["type"], value):
            return f"type-{name}"
        if "enum" in prop and value not in prop["enum"]:
            return f"enum-{name}"
        if "pattern" in prop:
            return f"pattern-{name}"
    return ""


def schema_ok(call: Call) -> bool:
    return schema_error(call) == ""


def _intent_from_description(description: str) -> list[str]:
    text = description.lower()
    intents: list[str] = []
    if "allowed director" in text:
        intents.append("path stays inside the configured allowed directories")
    if "private" in text and "blocked" in text:
        intents.append("private, loopback, and link-local hosts are out of scope")
    if "non-http" in text or "http or https" in text:
        intents.append("only http and https URLs are in scope")
    return intents


def extract_declared(declared_root: str) -> dict:
    """Build the Declared envelope from specs plus deployment configuration.

    Schema constraints are whatever the JSON schema actually encodes.
    Intent constraints are recovered from description text. For these tools the
    schema types a path or URL as a free string, while the description states
    a tighter scope.
    """
    tools = []
    for spec in TOOL_SPECS:
        schema_constraints = []
        for name, prop in spec.properties.items():
            schema_constraints.append(
                {
                    "argument": name,
                    "type": prop["type"],
                    "enum": prop.get("enum"),
                    "pattern": prop.get("pattern"),
                    "required": name in spec.required,
                }
            )
        tools.append(
            {
                "server": spec.server,
                "name": spec.name,
                "description": spec.description,
                "schema_constraints": schema_constraints,
                "intent_constraints": _intent_from_description(spec.description),
            }
        )
    return {
        "source": "tool metadata plus deployment configuration",
        "configuration": {
            "filesystem_allowed_directories": [declared_root],
            "fetch_url_policy": "public http and https",
        },
        "tools": tools,
    }
