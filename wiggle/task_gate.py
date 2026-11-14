"""Experimental exact-call gate; independent of the frozen study policies.

The trusted host owns this object and approval methods. Expose only execute
to the agent's tool dispatcher. This is not isolation from hostile Python code.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import TYPE_CHECKING
from uuid import uuid4

from wiggle.model import Call, ToolResult

if TYPE_CHECKING:
    from wiggle.agent_loop import ToolBackend


def _json_value(value: object) -> None:
    """Reject Python values that JSON would silently coerce or omit."""
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("argument keys must be strings")
            _json_value(item)
    elif type(value) is list:
        for item in value:
            _json_value(item)
    elif value is not None and type(value) not in (str, bool, int, float):
        raise ValueError("arguments must be JSON values")


def call_key(call: Call) -> str:
    """Exact JSON identity: no path, URL, query, or content normalization."""
    if (type(call.server) is not str or not call.server
            or type(call.tool) is not str or not call.tool
            or type(call.args) is not dict):
        raise ValueError("invalid call")
    _json_value(call.args)
    return json.dumps([call.server, call.tool, call.args], sort_keys=True,
                      ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def _call(key: str) -> Call:
    server, tool, args = json.loads(key)
    return Call(server, tool, args)


@dataclass(frozen=True)
class PermissionRequest:
    id: str
    task_id: str
    call_json: str


class TaskGate:
    """Single-threaded, task-local backend wrapper with one-use extensions.

    Initial exact calls are reusable. Extension permits are consumed BEFORE
    dispatch, including when the backend fails. Request IDs identify pending
    reviews, not authentication credentials. Never expose resolve to a model.
    """

    def __init__(self, backend: ToolBackend, task_id: str,
                 initial_calls: list[Call], *, max_pending: int = 32):
        if not task_id or max_pending < 1:
            raise ValueError("task id and positive pending limit required")
        self._backend = backend
        self._task_id = task_id
        self._initial = frozenset(call_key(call) for call in initial_calls)
        self._once: set[str] = set()
        self._pending: dict[str, PermissionRequest] = {}
        self._max_pending = max_pending
        self._closed = False

    @property
    def pending(self) -> tuple[PermissionRequest, ...]:
        return tuple(self._pending.values())

    def resolve(self, request_id: str, *, approve: bool) -> None:
        """Trusted host only: resolve an immutable request for this instance."""
        if self._closed:
            raise ValueError("task closed")
        if type(approve) is not bool:
            raise ValueError("approval must be boolean")
        request = self._pending.pop(request_id)  # Unknown/stale IDs fail closed.
        if approve:
            self._once.add(request.call_json)

    def close(self) -> None:
        self._closed = True
        self._once.clear()
        self._pending.clear()

    def execute(self, call: Call) -> ToolResult:
        if self._closed:
            return ToolResult(False, error="task-closed")
        try:
            key = call_key(call)
        except (ValueError, TypeError, RecursionError):
            return ToolResult(False, error="invalid-call")
        if key in self._initial:
            return self._backend.execute(_call(key))
        if key in self._once:
            self._once.remove(key)
            return self._backend.execute(_call(key))
        for request in self._pending.values():
            if request.call_json == key:
                return ToolResult(False, error=f"approval-required:{request.id}")
        if len(self._pending) >= self._max_pending:
            return ToolResult(False, error="pending-limit")
        request = PermissionRequest(uuid4().hex, self._task_id, key)
        self._pending[request.id] = request
        return ToolResult(False, error=f"approval-required:{request.id}")
