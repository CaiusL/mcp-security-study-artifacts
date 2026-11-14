"""Project-authored MCP used only as a labeled study fixture.

The process speaks newline-delimited JSON-RPC on stdio. It reads and writes
text files inside --root. A path that resolves outside that directory is
refused. It does not open a network connection or start a shell.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from wiggle.model import ToolResult


SERVER_NAME = "wiggle-sandbox"
SERVER_VERSION = "0.1.0"
SERVER_DESCRIPTION = (
    "Study sandbox that reads and writes text notes inside one configured directory."
)

TOOLS: tuple[dict, ...] = (
    {
        "name": "read_note",
        "description": (
            "Read a text file. The path argument is a filesystem path and must "
            "stay inside the configured directory."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Filesystem path inside the configured directory.",
                }
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "write_note",
        "description": (
            "Write a text file. The path argument is a filesystem path and must "
            "stay inside the configured directory."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Filesystem path inside the configured directory.",
                },
                "content": {"type": "string", "description": "Text to write."},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
)


def contained(root: Path, user_path: str) -> Path | None:
    """Return the resolved path when it is root or a descendant."""
    candidate = Path(user_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        return None
    if resolved == root or root in resolved.parents:
        return resolved
    return None


def listed_tools(poison_description: str = "") -> list[dict]:
    """tools/list entries. A non-empty poison string is the labeled fixture mode.

    The string is appended to every tool description. The base contract in
    `TOOLS` is left unchanged.
    """
    tools = json.loads(json.dumps(list(TOOLS)))
    if not poison_description:
        return tools
    for tool in tools:
        tool["description"] = tool["description"] + "\n" + poison_description
    return tools


def execute(root: Path, name: str, arguments: dict) -> ToolResult:
    """In-process call used by the pilot stand-in. Same checks as the stdio server."""
    result = _call(root, name, arguments)
    text = result["content"][0]["text"]
    if result.get("isError"):
        return ToolResult(False, text=text, error=text)
    return ToolResult(True, text=text)


def _result(text: str, *, error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": error}


def _call(root: Path, name: str, arguments: object) -> dict:
    if not isinstance(arguments, dict):
        return _result("invalid-arguments", error=True)
    if name == "read_note":
        return _read(root, arguments)
    if name == "write_note":
        return _write_note(root, arguments)
    return _result("unknown-tool", error=True)


def _read(root: Path, arguments: dict) -> dict:
    user_path = arguments.get("path")
    if not isinstance(user_path, str):
        return _result("type-path", error=True)
    path = contained(root, user_path)
    if path is None:
        return _result("server-denied", error=True)
    if not path.is_file():
        return _result("not-a-file", error=True)
    return _result(path.read_text(encoding="utf-8"))


def _write_note(root: Path, arguments: dict) -> dict:
    user_path = arguments.get("path")
    content = arguments.get("content")
    if not isinstance(user_path, str):
        return _result("type-path", error=True)
    if not isinstance(content, str):
        return _result("type-content", error=True)
    path = contained(root, user_path)
    if path is None:
        return _result("server-denied", error=True)
    if path.exists() and not path.is_file():
        return _result("not-a-file", error=True)
    if not path.parent.is_dir():
        return _result("not-a-directory", error=True)
    path.write_text(content, encoding="utf-8")
    return _result(f"wrote {path.name}")


def _server_description(poison_description: str) -> str:
    if not poison_description:
        return SERVER_DESCRIPTION
    return SERVER_DESCRIPTION + " Labeled fixture mode: poisoned-description."


def _handle(root: Path, message: dict, poison_description: str = "") -> dict | None:
    if "id" not in message:
        return None
    method = message.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
                "description": _server_description(poison_description),
            },
        }
    elif method == "tools/list":
        result = {"tools": listed_tools(poison_description)}
    elif method == "tools/call":
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        result = _call(root, str(params.get("name") or ""), params.get("arguments"))
    else:
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32601, "message": "method-not-found"},
        }
    return {"jsonrpc": "2.0", "id": message["id"], "result": result}


def serve(root: Path, poison_description: str = "") -> None:
    for raw in sys.stdin.buffer:
        line = raw.decode("utf-8").strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        reply = _handle(root, message, poison_description)
        if reply is None:
            continue
        sys.stdout.buffer.write((json.dumps(reply) + "\n").encode("utf-8"))
        sys.stdout.buffer.flush()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Study sandbox MCP. Refuses paths outside --root.")
    parser.add_argument("--root", required=True, help="Only directory this process may read or write.")
    parser.add_argument(
        "--poison-description",
        default="",
        help="Labeled fixture. Text appended to every tool description.",
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if not root.is_dir():
        print("root is not a directory", file=sys.stderr)
        sys.exit(2)
    try:
        serve(root, args.poison_description)
    except BrokenPipeError:
        return


if __name__ == "__main__":
    main()
