"""Minimal MCP stdio client for a pinned local server.

The client speaks the 2025-era initialize handshake. It does not send roots,
sample, or elicit. Tool arguments are whatever the caller passes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from wiggle.model import ToolResult


class McpError(RuntimeError):
    pass


class McpStdio:
    def __init__(self, command: list[str], env: dict[str, str] | None = None):
        self.command = command
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
        )
        self._next_id = 0
        self._lines: deque[str] = deque()
        self._lock = threading.Lock()
        self._ready = threading.Condition()
        self._stdout_dead = False
        self.stderr: list[str] = []
        self._threads = [
            threading.Thread(target=self._read_stdout, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            with self._ready:
                self._lines.append(line)
                self._ready.notify()
        with self._ready:
            self._stdout_dead = True
            self._ready.notify_all()

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self.stderr.append(line)

    def close(self) -> None:
        if self.proc.poll() is None:
            if self.proc.stdin is not None:
                try:
                    self.proc.stdin.close()
                except OSError:
                    pass
            self.proc.kill()
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if pipe is not None and not pipe.closed:
                try:
                    pipe.close()
                except OSError:
                    pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    def _send(self, payload: dict) -> None:
        if self.proc.stdin is None or self.proc.poll() is not None:
            raise McpError("server process is not running")
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None, timeout: float = 30) -> dict:
        self._next_id += 1
        request_id = self._next_id
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)
        end = time.monotonic() + timeout
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise McpError(f"timed out waiting for {method}")
            with self._ready:
                while not self._lines and not self._stdout_dead:
                    if not self._ready.wait(timeout=remaining):
                        break
                if not self._lines:
                    if self._stdout_dead:
                        raise McpError(f"server closed stdout during {method}")
                    raise McpError(f"timed out waiting for {method}")
                raw = self._lines.popleft()
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if parsed.get("id") != request_id:
                continue
            if "error" in parsed:
                error = parsed["error"]
                detail = error.get("message", str(error)) if isinstance(error, dict) else str(error)
                raise McpError(detail)
            return parsed.get("result") or {}

    def notify(self, method: str, params: dict | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def initialize(self, timeout: float = 30) -> dict:
        result = self.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "wiggle", "version": "0.1.0"},
            },
            timeout=timeout,
        )
        self.notify("notifications/initialized")
        return result

    def list_tools(self, timeout: float = 30) -> list[dict]:
        result = self.request("tools/list", {}, timeout=timeout)
        tools = result.get("tools") or []
        if not isinstance(tools, list):
            raise McpError("tools/list returned no tool array")
        return tools

    def call_tool(self, name: str, arguments: dict) -> ToolResult:
        try:
            result = self.request("tools/call", {"name": name, "arguments": arguments})
        except McpError as exc:
            return ToolResult(False, error=str(exc))
        texts = []
        for block in result.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append(str(block.get("text") or ""))
        text = "\n".join(texts)
        if result.get("isError"):
            return ToolResult(False, text=text, error=text or "tool error")
        return ToolResult(True, text=text)


def vendored_python_env() -> dict[str, str]:
    repo = Path(__file__).resolve().parents[1] / "vendor"
    root = None
    for name in ("py-live", "py"):
        candidate = repo / name
        try:
            if (candidate / "mcp_server_git" / "__main__.py").is_file():
                root = candidate
                break
        except OSError:
            continue
    if root is None:
        raise McpError(
            "pinned Python MCP servers are missing. From the repo root run: "
            "python -m pip install --target vendor/py-live -r vendor/requirements.txt"
        )
    env = os.environ.copy()
    # pip --target does not run pywin32's .pth, so the DLL and pywintypes
    # have to be named here or the MCP SDK fails to import on Windows.
    extra = [
        root,
        root / "win32",
        root / "win32" / "lib",
        root / "pywin32_system32",
    ]
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in extra)
    env["PATH"] = str(root / "pywin32_system32") + os.pathsep + env.get("PATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def python_module_command(module: str, *args: str) -> list[str]:
    return [sys.executable, "-m", module, *args]


def sequential_thinking_command() -> list[str]:
    entry = (
        Path(__file__).resolve().parents[1]
        / "vendor"
        / "mcp"
        / "node_modules"
        / "@modelcontextprotocol"
        / "server-sequential-thinking"
        / "dist"
        / "index.js"
    )
    if not entry.is_file():
        raise McpError(
            "pinned sequential-thinking server is missing. From the repo root run: "
            "npm install --prefix vendor/mcp @modelcontextprotocol/server-sequential-thinking@2.0.0"
        )
    return ["node", str(entry)]


def filesystem_server_command(allowed_directory: Path) -> list[str]:
    entry = (
        Path(__file__).resolve().parents[1]
        / "vendor"
        / "mcp"
        / "node_modules"
        / "@modelcontextprotocol"
        / "server-filesystem"
        / "dist"
        / "index.js"
    )
    if not entry.is_file():
        raise McpError(
            "pinned filesystem server is missing. From the repo root run: "
            "npm install --prefix vendor/mcp"
        )
    return ["node", str(entry), str(allowed_directory)]
