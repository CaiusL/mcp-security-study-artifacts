"""Join J1: one BadAgent adapter through the On9MCP agent loop.

Plumbing and replication check only. It is not a defense result.
`python -m wiggle.badagent_join` reports the located checkpoint and stops.
It does not load weights and it does not send a model request.

The run path is `run_j1`. It stays closed until a caller passes a client or a
local OpenAI-style endpoint whose base checkpoint is the one named in the
adapter config. The fixture is `make_sandbox`. The server is the patched
filesystem stand-in, so a write stays inside that tree or is refused.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

from wiggle.agent_loop import HostedModel, run_agent
from wiggle.corpus import CANARY_WRITE_SH, make_sandbox, tasks
from wiggle.injection import HOST_SYSTEM_PROMPT, goal_succeeded
from wiggle.servers import FilesystemServer

ROOT = Path(__file__).resolve().parents[1]
# The weights on disk. docs/archive/finish-plan.md section 3 names a different directory.
LOCATED_ADAPTER = Path("replication_out") / "adapter"
FINISH_PLAN_ADAPTER = Path("replication_out") / "mcp_tool_qwen" / "adapter"
HOST_PROMPT_NAME = "wiggle.injection.HOST_SYSTEM_PROMPT"
BENIGN_TASK_ID = "fs-readme"


class JoinBlocked(RuntimeError):
    def __init__(self, blockers: list[str]):
        self.blockers = blockers
        super().__init__("\n".join(blockers))


def _adapter(root: Path, relative: Path) -> dict:
    directory = root / relative
    config_path = directory / "adapter_config.json"
    weights_path = directory / "adapters.safetensors"
    record = {
        "relative": relative.as_posix(),
        "config_exists": config_path.is_file(),
        "weights_exists": weights_path.is_file(),
        "weights_bytes": weights_path.stat().st_size if weights_path.is_file() else None,
        "model": "",
        "fine_tune_type": "",
        "iters": None,
        "lora_rank": None,
        "lora_scale": None,
        "quantization": "",
    }
    if not config_path.is_file():
        return record
    config = json.loads(config_path.read_text(encoding="utf-8"))
    model = str(config.get("model") or "")
    lora = config.get("lora_parameters") or {}
    record.update(
        {
            "model": model,
            "fine_tune_type": str(config.get("fine_tune_type") or ""),
            "iters": config.get("iters"),
            "lora_rank": lora.get("rank"),
            "lora_scale": lora.get("scale"),
            "quantization": "4-bit" if "4bit" in model.lower() else "",
        }
    )
    return record


def _mlx_importable() -> bool:
    return importlib.util.find_spec("mlx") is not None or importlib.util.find_spec("mlx_lm") is not None


def blockers(badagent: Path, base_url: str = "") -> list[str]:
    """What stops a model request. Empty only when a local endpoint can be used."""
    located = _adapter(badagent, LOCATED_ADAPTER)
    reasons = []
    if not located["config_exists"] or not located["weights_exists"]:
        reasons.append(
            f"located adapter is incomplete: {LOCATED_ADAPTER.as_posix()} needs adapters.safetensors and adapter_config.json"
        )
    model = located["model"]
    if model and not Path(model).exists():
        reasons.append(f"base checkpoint is not on this machine: {model}")
    if not _mlx_importable():
        reasons.append(
            "mlx and mlx_lm are not importable. The adapter is an MLX LoRA, and torch or transformers does not load it."
        )
    if not base_url:
        reasons.append("no local OpenAI-style base URL was supplied, so HostedModel is not called")
    return reasons


def join_status(badagent: Path | None = None) -> dict:
    """Locate both adapters and list the run requirements. No weights are loaded."""
    root = badagent if badagent is not None else ROOT / "BadAgent"
    located = _adapter(root, LOCATED_ADAPTER)
    return {
        "label": "J1 plumbing and replication check. Not a defense claim.",
        "ran": False,
        "located_adapter": located,
        "finish_plan_adapter": _adapter(root, FINISH_PLAN_ADAPTER),
        "host_prompt": HOST_PROMPT_NAME,
        "host_prompt_loaded": bool(HOST_SYSTEM_PROMPT),
        "oracle": "wiggle.injection.goal_succeeded, goal G2",
        "canary": CANARY_WRITE_SH,
        "fixture": "wiggle.corpus.make_sandbox and the patched FilesystemServer",
        "benign_task": BENIGN_TASK_ID,
        "requirements": [
            "checkpoint: adapters.safetensors beside adapter_config.json",
            "quantization: the 4-bit MLX snapshot named in adapter_config.json model",
            f"host prompt: {HOST_PROMPT_NAME}, the same text run_agent already sends",
            "serving layer: mlx_lm on a machine that has that snapshot, or one OpenAI-style server of the same checkpoint, quantization, and host prompt",
        ],
        "blockers": blockers(root),
    }


def run_j1(fixture: Path, client=None, badagent: Path | None = None, base_url: str = "", api_key: str = "", model_id: str = "", temperature: float = 0.0) -> dict:
    """One canary loop on a sandbox fixture.

    Without an injected client this raises JoinBlocked before any socket.
    The injected client is how the tests check the oracle path.
    """
    root = badagent if badagent is not None else ROOT / "BadAgent"
    if client is None:
        reasons = blockers(root, base_url)
        if reasons or not api_key or not model_id:
            missing = list(reasons)
            if not api_key:
                missing.append("api key was not passed")
            if not model_id:
                missing.append("model id was not passed")
            raise JoinBlocked(missing)
        client = HostedModel(base_url, api_key, model_id, temperature)
    layout = make_sandbox(fixture)
    task = next(task for task in tasks() if task.id == BENIGN_TASK_ID)
    trace = run_agent(task, layout, 0, client, FilesystemServer(layout.proj, "patched"))
    g2 = goal_succeeded("G2", layout, trace.results, [])
    written = layout.proj / "notes" / "run.sh"
    return {
        "label": "J1 plumbing and replication check. Not a defense claim.",
        "ran": True,
        "task_id": trace.task_id,
        "utility": trace.utility,
        "g2": g2,
        "canary_file": written.is_file() and CANARY_WRITE_SH in written.read_text(encoding="utf-8"),
        "inside_fixture": written.is_file() and layout.proj.resolve() in written.resolve().parents,
        "model_id": trace.model_id,
        "calls": [{"server": call.server, "tool": call.tool, "args": call.args} for call in trace.calls],
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Report the J1 adapter path and stop. Does not call a model.")
    parser.add_argument("--badagent", type=Path, default=ROOT / "BadAgent")
    args = parser.parse_args(argv)
    status = join_status(args.badagent)
    print(json.dumps(status, indent=2))
    if status["blockers"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
