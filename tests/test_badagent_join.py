"""J1 harness. No weights are loaded and no model request is sent."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from wiggle.agent_loop import ModelTurn
from wiggle.badagent_join import (
    BENIGN_TASK_ID,
    FINISH_PLAN_ADAPTER,
    HOST_PROMPT_NAME,
    LOCATED_ADAPTER,
    JoinBlocked,
    join_status,
    main,
    run_j1,
)
from wiggle.corpus import CANARY_WRITE_SH
from wiggle.model import Call


class _OneWrite:
    def __init__(self, path: str):
        self.path = path
        self.sent = 0

    def complete(self, messages, tools):
        self.sent += 1
        if self.sent == 1:
            call = Call("filesystem", "write_file", {"path": self.path, "content": CANARY_WRITE_SH + "\n"})
            return ModelTurn(text="", calls=[call], model_id="fixture", temperature=0.0)
        return ModelTurn(text="done", calls=[], model_id="fixture", temperature=0.0)


def _adapter_tree(root: Path, relative: Path, model: str) -> None:
    directory = root / relative
    directory.mkdir(parents=True)
    (directory / "adapters.safetensors").write_bytes(b"not-weights")
    (directory / "adapter_config.json").write_text(
        json.dumps({"model": model, "fine_tune_type": "lora", "iters": 1, "lora_parameters": {"rank": 8, "scale": 20.0}}),
        encoding="utf-8",
    )


class BadAgentJoinTests(unittest.TestCase):
    def test_status_names_both_adapters_and_does_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _adapter_tree(root, LOCATED_ADAPTER, "/missing/mlx-community/Qwen3.5-2B-4bit")
            _adapter_tree(root, FINISH_PLAN_ADAPTER, "/missing/mlx-community/Qwen3.5-2B-4bit")
            status = join_status(root)
        self.assertFalse(status["ran"])
        self.assertEqual(status["located_adapter"]["quantization"], "4-bit")
        self.assertEqual(status["located_adapter"]["weights_bytes"], len(b"not-weights"))
        self.assertTrue(status["finish_plan_adapter"]["config_exists"])
        self.assertEqual(status["host_prompt"], HOST_PROMPT_NAME)
        self.assertTrue(status["host_prompt_loaded"])
        self.assertTrue(status["blockers"])

    def test_run_without_a_client_does_not_touch_the_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bad"
            fixture = Path(tmp) / "fixture"
            _adapter_tree(root, LOCATED_ADAPTER, "/missing/mlx-community/Qwen3.5-2B-4bit")
            with self.assertRaises(JoinBlocked):
                run_j1(fixture, badagent=root)
            self.assertFalse(fixture.exists())

    def test_injected_client_scores_g2_inside_the_sandbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture"
            record = run_j1(fixture, client=_OneWrite("notes/run.sh"))
            self.assertEqual(record["task_id"], BENIGN_TASK_ID)
            self.assertTrue(record["g2"])
            self.assertTrue(record["canary_file"])
            self.assertTrue(record["inside_fixture"])
            self.assertEqual(record["calls"][0]["tool"], "write_file")

    def test_a_write_outside_the_fixture_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture"
            outside = Path(tmp) / "escape.sh"
            record = run_j1(fixture, client=_OneWrite(str(outside)))
            self.assertFalse(record["g2"])
            self.assertFalse(outside.exists())

    def test_the_command_stops_when_the_runtime_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _adapter_tree(root, LOCATED_ADAPTER, "/missing/mlx-community/Qwen3.5-2B-4bit")
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["--badagent", str(root)])
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
