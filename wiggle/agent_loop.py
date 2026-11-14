"""Model loop at the `scripted_calls` seam.

`run_agent` is the caller a study uses instead of `scripted_calls`.
It executes each proposed call through a stand-in or through `McpStdio`.
Utility is `task_succeeded`. That oracle is not modified here.

A hosted model is contacted only when the caller passes `HostedModel`.
`ScriptedModel` emits `scripted_calls` once, so the seam can be checked
without a model request.
"""

from __future__ import annotations

import http.client
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from wiggle.corpus import make_sandbox, scripted_calls, task_succeeded
from wiggle.declared import TOOL_SPECS
from wiggle.injection import (
    HOST_SYSTEM_PROMPT,
    SAMPLE_COUNT,
    STEP_CAP,
    TOOL_CALL_ID_PREFIX,
    TOOL_ROLE,
    benign_runs,
    frame_result,
    user_message,
)
from wiggle.live_study import _task_ok
from wiggle.mcp_client import McpStdio
from wiggle.model import Call, Layout, Task, ToolResult
from wiggle.sandbox_server import listed_tools
from wiggle.sandbox_server import execute as execute_sandbox
from wiggle.servers import FetchServer, FilesystemServer

# The study caller. DeepSeek OpenAI-compatible chat completions.
LOCAL_BASE_URL = "https://api.deepseek.com/v1"
LOCAL_MODEL = "deepseek-flash"


def _load_env_file() -> None:
    """Load KEY=VALUE lines from the repo `.env` into os.environ.

    Does not overwrite a variable that is already set. The file is gitignored.
    The key is never returned here for logging.
    """
    path = Path(__file__).resolve().parents[1] / ".env"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        name = name.strip()
        if not name or name in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ[name] = value


def default_api_key() -> str:
    """Bearer token for the default DeepSeek caller. Never written into a result file."""
    key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
    if not key:
        _load_env_file()
        key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
    if not key:
        raise RuntimeError("set DEEPSEEK_API_KEY, add it to .env, or pass --api-key-file")
    return key


class ModelError(RuntimeError):
    pass


@dataclass
class ModelTurn:
    text: str
    calls: list[Call]
    model_id: str = ""
    temperature: float | None = None
    usage: dict | None = None


class ModelClient(Protocol):
    def complete(self, messages: list[dict], tools: list[dict]) -> ModelTurn: ...


class ToolBackend(Protocol):
    def execute(self, call: Call) -> ToolResult: ...


@dataclass
class AgentTrace:
    task_id: str
    sample: int
    calls: list[Call]
    results: list[ToolResult]
    utility: bool
    steps: int
    stop: str
    messages: list[dict]
    model_id: str
    temperature: float | None
    step_cap: int
    error: str = ""
    sink_urls: list[str] = field(default_factory=list)
    usage: dict | None = None


class ScriptedModel:
    """Seam double. `sample` is the `rep` passed to `scripted_calls`."""

    def __init__(self, task: Task, layout: Layout, sample: int):
        self._calls = scripted_calls(task, layout, sample)
        self._sent = False

    def complete(self, messages: list[dict], tools: list[dict]) -> ModelTurn:
        del messages, tools
        if self._sent:
            return ModelTurn(text="done", calls=[], model_id="scripted")
        self._sent = True
        return ModelTurn(text="", calls=list(self._calls), model_id="scripted")


class RepeatModel:
    """Returns the same calls on every turn. Used to exercise the step cap."""

    def __init__(self, calls: list[Call]):
        self._calls = calls

    def complete(self, messages: list[dict], tools: list[dict]) -> ModelTurn:
        del messages, tools
        return ModelTurn(text="", calls=list(self._calls), model_id="repeat")


class StandInBackend:
    """Filesystem and fetch stand-ins, plus the in-process sandbox.

    A live filesystem session, when given, takes the filesystem calls. It is
    the patched pin, so it is refused for the vulnerable mode.
    """

    def __init__(
        self,
        layout: Layout,
        filesystem_mode: str = "patched",
        fetch_mode: str = "patched",
        page_injections: dict[str, str] | None = None,
        filesystem_session: McpStdio | None = None,
    ):
        if filesystem_session is not None and filesystem_mode != "patched":
            raise ValueError("the live filesystem server is the patched arm only")
        self.layout = layout
        self.filesystem = FilesystemServer(layout.proj, filesystem_mode)
        self.filesystem_session = filesystem_session
        self.fetch = FetchServer(fetch_mode, injections=page_injections)

    def execute(self, call: Call) -> ToolResult:
        if call.server == "filesystem":
            if self.filesystem_session is not None:
                return self.filesystem_session.call_tool(call.tool, call.args)
            return self.filesystem.execute(call)
        if call.server == "fetch":
            return self.fetch.execute(call)
        if call.server == "sandbox":
            return execute_sandbox(self.layout.proj, call.tool, call.args)
        return ToolResult(False, error="unknown-tool")


class McpBackend:
    """Route a call to a connected stdio session."""

    def __init__(self, sessions: dict[str, McpStdio]):
        self.sessions = sessions

    def execute(self, call: Call) -> ToolResult:
        session = self.sessions.get(call.server)
        if session is None:
            return ToolResult(False, error="unknown-server")
        return session.call_tool(call.tool, call.args)


def pilot_tool_list(poison_description: str = "") -> list[dict]:
    """Every pilot server. Poison text is appended only to the sandbox tools."""
    tools = [_spec_tool(spec) for spec in TOOL_SPECS]
    for tool in listed_tools(poison_description):
        entry = dict(tool)
        entry["server"] = "sandbox"
        tools.append(entry)
    return tools


def _spec_tool(spec) -> dict:
    return {
        "server": spec.server,
        "name": spec.name,
        "description": spec.description,
        "inputSchema": {
            "type": "object",
            "properties": spec.properties,
            "required": list(spec.required),
            "additionalProperties": False,
        },
    }


def server_of(name: str, tools: list[dict]) -> str:
    for tool in tools:
        if tool.get("name") == name:
            return str(tool.get("server") or "unknown")
    return "unknown"


def turn_from_chat_response(
    payload: dict,
    tools: list[dict],
    model_id: str,
    temperature: float | None,
) -> ModelTurn:
    """Parse one OpenAI-style chat completion into a turn."""
    try:
        message = payload["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ModelError("model response has no message") from exc
    if not isinstance(message, dict):
        raise ModelError("model response has no message")
    text = message.get("content") or ""
    if not isinstance(text, str):
        text = str(text)
    calls: list[Call] = []
    for item in message.get("tool_calls") or []:
        if not isinstance(item, dict):
            raise ModelError("tool call is not an object")
        function = item.get("function") if isinstance(item.get("function"), dict) else {}
        name = str(function.get("name") or "")
        raw_args = function.get("arguments") if function else "{}"
        if raw_args in (None, ""):
            raw_args = "{}"
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args)
            except json.JSONDecodeError as exc:
                raise ModelError("tool arguments are not json") from exc
        elif isinstance(raw_args, dict):
            args = raw_args
        else:
            raise ModelError("tool arguments are not json")
        if not isinstance(args, dict):
            raise ModelError("tool arguments are not an object")
        calls.append(Call(server_of(name, tools), name, args))
    reported = payload.get("model")
    if isinstance(reported, str) and reported:
        model_id = reported
    return ModelTurn(
        text=text,
        calls=calls,
        model_id=model_id,
        temperature=temperature,
        usage=_usage(payload.get("usage")),
    )


class HostedModel:
    """OpenAI-style chat client. Sends the frozen messages and the tool list.

    Reads nothing from the environment itself. The caller passes the base URL,
    the key, the model id, the temperature, and whether to turn thinking off.
    The key is not written into the trace.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model_id: str,
        temperature: float,
        timeout: float = 180,
        thinking_off: bool = False,
        attempts: int = 3,
        backoff: float = 2.0,
        max_tokens: int | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model_id = model_id
        self.temperature = temperature
        self.timeout = timeout
        self.thinking_off = thinking_off
        self.attempts = max(1, attempts)
        self.backoff = backoff
        # None sends no cap, as every Stage 2 run did. The birth arm sets one so a
        # looping reply ends at the cap instead of at the timeout.
        self.max_tokens = max_tokens

    def complete(self, messages: list[dict], tools: list[dict]) -> ModelTurn:
        body = {
            "model": self.model_id,
            "temperature": self.temperature,
            "messages": messages,
        }
        if self.max_tokens is not None:
            body["max_tokens"] = self.max_tokens
        if self.thinking_off:
            # DeepSeek thinks by default. Thinking mode ignores the temperature, and
            # with tools it needs reasoning_content sent back, which this loop does not do.
            body["thinking"] = {"type": "disabled"}
        if tools:
            body["tools"] = openai_tools(tools)
        request = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.api_key,
            },
            method="POST",
        )
        # A large Stage 2 request can be slow, and the hosted endpoint can drop
        # one. Retry a transient failure (timeout, dropped connection, 429 or 5xx)
        # a few times with backoff before giving up. This changes only the
        # delivery of the request, not the request, so the study result is unchanged.
        for attempt in range(self.attempts):
            last = attempt + 1 == self.attempts
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                # oMLX commits HTTP 200 before generation finishes. A tool call it cannot
                # parse then arrives as an error object instead of a chat message.
                error = payload.get("error") if isinstance(payload, dict) else None
                if isinstance(error, dict) and "choices" not in payload:
                    if error.get("code") in {"invalid_tool_call", "incomplete_tool_call"}:
                        return ModelTurn(
                            text=str(error.get("message") or ""),
                            calls=[],
                            model_id=self.model_id,
                            temperature=self.temperature,
                        )
                    raise ModelError(str(error.get("message") or "model request failed"))
                turn = turn_from_chat_response(payload, tools, self.model_id, self.temperature)
                if attempt and turn.usage is not None:
                    # A failed attempt can still be billed, and its tokens are unknown.
                    # The ledgers keep the count beside the measured tokens.
                    turn.usage["retries"] = attempt
                return turn
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 500, 502, 503, 504) and not last:
                    time.sleep(self.backoff * (attempt + 1))
                    continue
                raise ModelError(f"model request failed ({exc.code})") from exc
            except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
                # A read timeout or a dropped connection is not an HTTPError.
                if not last:
                    time.sleep(self.backoff * (attempt + 1))
                    continue
                raise ModelError(f"model request failed ({type(exc).__name__})") from exc
            except json.JSONDecodeError as exc:
                raise ModelError("model response is not json") from exc
        raise ModelError("model request failed (no attempts)")


def _usage(raw: object) -> dict | None:
    """Token counts from an OpenAI-style usage object. None when the provider sent none."""
    if not isinstance(raw, dict):
        return None
    found = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = raw.get(key, 0)
        if not isinstance(value, int):
            return None
        found[key] = value
    return found


def _add_usage(total: dict | None, extra: dict | None) -> dict | None:
    if extra is None:
        return total
    if total is None:
        total = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    for key, value in extra.items():
        total[key] = total.get(key, 0) + value
    return total


def total_tokens(usage: dict | None) -> int:
    """Measured tokens of a stored run or request. 0 when the provider sent no usage."""
    return int((usage or {}).get("total_tokens") or 0)


def reply_tokens(usage: dict | None) -> int:
    """Measured tokens of one reply under a token cap. No cap can hold without them."""
    tokens = usage.get("total_tokens") if isinstance(usage, dict) else None
    if type(tokens) is not int or tokens <= 0:
        raise ModelError("the reply has no token usage, so the token cap cannot be enforced")
    return tokens


def _openai_tool(tool: dict) -> dict:
    return {
        "type": "function",
        "function": {
            "name": tool["name"],
            "description": tool.get("description") or "",
            "parameters": tool.get("inputSchema") or {"type": "object", "properties": {}},
        },
    }


def openai_tools(tools: list[dict]) -> list[dict]:
    """Tools for one chat request. Later copies of a name are left out.

    DeepSeek rejects a request whose tool names are not unique. The local
    tool list is unchanged: ``server_of`` still routes a call to the first
    tool with that name, which is how the shadow fixture is reached.
    """
    seen: set[str] = set()
    out = []
    for tool in tools:
        name = str(tool.get("name") or "")
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(_openai_tool(tool))
    return out


def task_oracle(task: Task, live_filesystem: bool) -> Callable[[Task, Layout, list[ToolResult]], bool]:
    """The benign oracle for one run. Both read the same frozen `Expect`.

    `task_succeeded` reads stand-in output. The live filesystem server prints
    `[DIR] name` and `size: N`, so a filesystem task on that server is scored
    with the oracle of the phase 1 live study.
    """
    if live_filesystem and task.server == "filesystem":
        return _task_ok
    return task_succeeded


def run_agent(
    task: Task,
    layout: Layout,
    sample: int,
    client: ModelClient,
    backend: ToolBackend,
    tools: list[dict] | None = None,
    step_cap: int = STEP_CAP,
    oracle: Callable[[Task, Layout, list[ToolResult]], bool] = task_succeeded,
    user_text: str | None = None,
) -> AgentTrace:
    """Run one sample. Tool calls are executed as proposed, up to the step cap.

    `user_text` replaces the pilot's user turn for a task that has no steps
    (stage 2 builds it with `stage2_message`). The system prompt, the tool
    role and the result framing stay the frozen host prompt.
    A fixture whose benign task is not one of the study's 25 passes it too
    (`wiggle.adversary.dummy_attack`).
    """
    catalog = tools if tools is not None else pilot_tool_list()
    messages: list[dict] = [
        {"role": "system", "content": HOST_SYSTEM_PROMPT},
        {"role": "user", "content": user_message(task, str(layout.proj)) if user_text is None else user_text},
    ]
    calls: list[Call] = []
    results: list[ToolResult] = []
    model_id = ""
    temperature: float | None = None
    usage: dict | None = None
    stop = "step-cap"
    error = ""
    steps = 0
    try:
        while steps < step_cap:
            turn = client.complete(messages, catalog)
            if turn.model_id:
                model_id = turn.model_id
            if turn.temperature is not None:
                temperature = turn.temperature
            usage = _add_usage(usage, turn.usage)
            room = step_cap - steps
            batch = list(turn.calls[:room])
            if not batch:
                messages.append({"role": "assistant", "content": turn.text})
                stop = "model"
                break
            ids = [f"{TOOL_CALL_ID_PREFIX}{steps + index + 1}" for index in range(len(batch))]
            messages.append(_assistant_message(turn.text, ids, batch))
            for call_id, call in zip(ids, batch):
                result = backend.execute(call)
                calls.append(call)
                results.append(result)
                steps += 1
                messages.append(
                    {
                        "role": TOOL_ROLE,
                        "tool_call_id": call_id,
                        "content": frame_result(call.server, call.tool, result),
                    }
                )
            if len(turn.calls) > len(batch) or steps >= step_cap:
                stop = "step-cap"
                break
    except ModelError as exc:
        stop = "error"
        error = str(exc) or "ModelError"
    sink_urls = list(getattr(getattr(backend, "fetch", None), "requests", []))
    return AgentTrace(
        task_id=task.id,
        sample=sample,
        calls=calls,
        results=results,
        utility=oracle(task, layout, results),
        steps=steps,
        stop=stop,
        messages=messages,
        model_id=model_id,
        temperature=temperature,
        step_cap=step_cap,
        error=error,
        sink_urls=sink_urls,
        usage=usage,
    )


def calls_at_seam(
    task: Task,
    layout: Layout,
    sample: int,
    client: ModelClient,
    backend: ToolBackend,
    tools: list[dict] | None = None,
    step_cap: int = STEP_CAP,
) -> list[Call]:
    """The list `scripted_calls` used to return. Same position in a study loop."""
    return run_agent(task, layout, sample, client, backend, tools, step_cap).calls


def run_patched_benign(
    layout: Layout,
    client_for: Callable[[Task, Layout, int], ModelClient],
    filesystem_session: McpStdio | None = None,
) -> list[AgentTrace]:
    """75 patched-arm runs. The sandbox is rebuilt before each sample.

    With a live filesystem session, filesystem tasks use the glob variants
    the protocol names for that server.
    """
    live = filesystem_session is not None
    runs = benign_runs(live_filesystem=live)
    if len(runs) != 25 * SAMPLE_COUNT:
        raise RuntimeError("benign plan is not 25 tasks by 3 samples")
    traces = []
    for task, sample in runs:
        make_sandbox(layout.root)
        backend = StandInBackend(layout, filesystem_session=filesystem_session)
        client = client_for(task, layout, sample)
        traces.append(run_agent(task, layout, sample, client, backend, oracle=task_oracle(task, live)))
    return traces


def _assistant_message(text: str, call_ids: list[str], calls: list[Call]) -> dict:
    return {
        "role": "assistant",
        "content": text,
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": call.tool,
                    "arguments": json.dumps(call.args, sort_keys=True),
                },
            }
            for call_id, call in zip(call_ids, calls)
        ],
    }
