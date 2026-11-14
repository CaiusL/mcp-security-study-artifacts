"""Progent (secagent) layer (d): policy enforcement.

Thread secagent's native JSON-Schema policy check through the study's layer (d)
instead of the equals-only allowlist (`docs/progent-license-check.md`,
`docs/archive/roadmap.md` M0 decision 4). secagent keeps its policy in module-global
state -- one task's policy per process (note 6) -- so this module centralizes
loading a task's policy and checking one call against it.

secagent `b02783b8` is installed (pip --target) in the git-ignored
`vendor/py-progent` tree. It is imported lazily, and the tree is appended to
`sys.path` only when a Progent function is called, so importing `wiggle` never
needs it and nothing else on the path is shadowed.

The Progent freeze (`python -m wiggle.stage2 freeze --layer-d progent`) hashes
`source_hashes()`, `system_prompt()` and `USER_TURN`, and records
`prompt_settings()` in clear.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from pathlib import Path

from wiggle.model import Call

VENDOR = Path(__file__).resolve().parents[1] / "vendor" / "py-progent"
# The policy request's user turn, in secagent's own input format (`generate_security_policy`).
USER_TURN = "TOOLS: {tools}\nUSER_QUERY: {query}"


class PolicyReplyError(ValueError):
    """A policy reply that is not a Progent policy. `usage` is the reply's measured tokens."""

    def __init__(self, message: str, usage=None):
        super().__init__(message)
        self.usage = usage


def available() -> bool:
    """Whether the vendored secagent tree is present."""
    return (VENDOR / "secagent" / "tool.py").is_file()


def _tool_module():
    """Import `secagent.tool`, appending the vendored tree to `sys.path` last."""
    path = str(VENDOR)
    if path not in sys.path:
        sys.path.append(path)
    import secagent.tool as tool

    return tool


def system_prompt() -> str:
    """Progent's own policy system prompt (`get_SYS_PROMPT`), as `generate_policy` sends it.

    secagent builds it from SECAGENT_POLICY_MODEL and SECAGENT_TASK_TYPE, so the
    freeze hashes the text itself, not only the file it comes from.
    """
    return _tool_module().get_SYS_PROMPT()


def prompt_settings() -> dict[str, str]:
    """The two secagent settings that select `system_prompt()`'s text, as secagent reads them."""
    return {
        "SECAGENT_POLICY_MODEL": _tool_module().policy_model,
        "SECAGENT_TASK_TYPE": os.getenv("SECAGENT_TASK_TYPE", "general"),
    }


def source_hashes() -> dict[str, str]:
    """SHA-256 of each secagent source file (`secagent/*.py`), by its path in the tree, in sorted order."""
    return {
        path.relative_to(VENDOR).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((VENDOR / "secagent").glob("*.py"))
    }


def set_policy(tools: list[dict], policy: dict, query: str = "") -> None:
    """Load one task's Progent policy into secagent's global state.

    `tools` are secagent Tool dicts (`{name, description, args}`); `policy` is a
    secagent security policy, `{tool: [(priority, effect, {arg: restriction}, fallback)]}`
    (effect 0 allow, 1 block; fallback 0 deny). secagent holds one policy per
    process, so this replaces any policy loaded before.
    """
    tool = _tool_module()
    tool.update_available_tools(list(tools))
    tool.update_security_policy(policy)
    tool.init_user_query = query


# The policy `check` last loaded, and its sorted copy.
_sorted_policy: tuple[dict, dict] | None = None


def denies(call: Call) -> bool:
    """True when the loaded Progent policy blocks this call.

    secagent's `check_tool_call` returns on allow and raises `ValidationError`
    on block (an unset tool, a failed argument restriction, or an explicit
    block rule). `set_policy` must run first.
    """
    tool = _tool_module()
    try:
        tool.check_tool_call(call.tool, dict(call.args))
        return False
    except tool.ValidationError:
        return True


def check(call: Call, policy: dict) -> bool:
    """True when `policy`, a stored Progent policy, blocks this call.

    Loads the policy quietly for each call (`set_policy` logs every load). It
    sorts a policy once, and each call gets a shallow copy of the sorted policy,
    because `check_tool_call` may replace the entries of the loaded policy. JSON
    lists stand in for the policy tuples; secagent only unpacks them. Anything
    but a policy blocks: secagent allows every call while no policy is set.
    """
    global _sorted_policy
    if not isinstance(policy, dict):
        return True
    tool = _tool_module()
    if _sorted_policy is None or _sorted_policy[0] is not policy:
        tool.security_policy = copy.deepcopy(policy)
        tool.sort_policy()
        _sorted_policy = (policy, tool.security_policy)
    tool.security_policy = dict(_sorted_policy[1])
    return denies(call)


def generate_policy(client, query: str, tools: list[dict]) -> tuple[dict, object]:
    """Generate a Progent security policy for one task with the study's client.

    This keeps Progent's own system prompt (`get_SYS_PROMPT`), input format
    (`TOOLS: ... USER_QUERY: ...`), JSON parser (`extract_json`) and policy
    tuples `(100, 0, args_schema, 0)` from `generate_security_policy`. Only the
    model client is the study's, so tokens are counted and the request routes to
    the study's endpoint (secagent's own counters are off, and its `Qwen/` ids
    route to localhost; `docs/progent-license-check.md` notes 2 and 3).

    `client.complete(messages, tools)` must return a turn with `.text`, `.calls`
    and an optional `.usage`. Returns (security_policy, usage). A reply that is
    not a list of `{name, args}` entries raises `PolicyReplyError`, which keeps
    its usage. An empty list is a policy that allows no tool, as
    `generate_security_policy` takes it.
    """
    _tool_module()  # puts the vendored tree on sys.path for secagent.utils
    from secagent.utils import extract_json

    listing = [
        {
            "name": entry["name"],
            "description": entry.get("description") or "",
            "args": (entry.get("inputSchema") or {}).get("properties", {}),
        }
        for entry in tools
    ]
    content = USER_TURN.format(tools=json.dumps(listing, ensure_ascii=False), query=query)
    turn = client.complete(
        [{"role": "system", "content": system_prompt()}, {"role": "user", "content": content}],
        [],
    )
    usage = getattr(turn, "usage", None)
    if getattr(turn, "calls", None):
        raise PolicyReplyError("progent policy generator called a tool", usage)
    try:
        generated = extract_json(turn.text)
    except ValueError as exc:
        raise PolicyReplyError(f"progent policy is not JSON ({exc})", usage) from exc
    if generated is None:  # extract_json's answer to a reply that starts with "No"
        raise PolicyReplyError("progent policy generator returned no policy", usage)
    if not isinstance(generated, list) or not all(
        isinstance(allowed, dict) and isinstance(allowed.get("name"), str) and isinstance(allowed.get("args") or {}, dict)
        for allowed in generated
    ):
        raise PolicyReplyError("progent policy is not a list of {name, args} entries", usage)
    policy: dict = {}
    for allowed in generated:
        policy.setdefault(allowed["name"], []).append((100, 0, allowed.get("args") or {}, 0))
    return policy, usage
