"""Mechanism tests, including actual effects and the existing agent loop."""

import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from wiggle.agent_loop import ModelTurn, run_agent
from wiggle.model import Call, Expect, Layout, Task, ToolResult
from wiggle.task_gate import TaskGate, call_key
from wiggle.task_gate_demo import main


class TaskGateTests(unittest.TestCase):
    def setUp(self):
        self.backend = Mock()
        self.backend.execute.return_value = ToolResult(True, text="ok")
        self.call = Call("filesystem", "write_file", {"path": "summary.md", "content": "safe"})
        self.gate = TaskGate(self.backend, "task-a", [])

    def request(self, call=None):
        result = self.gate.execute(call or self.call)
        self.assertFalse(result.ok)
        return result.error.split(":", 1)[1]

    def test_exact_approval_once_and_changed_content_is_denied(self):
        request_id = self.request()
        self.backend.execute.assert_not_called()
        self.gate.resolve(request_id, approve=True)
        changed = Call(self.call.server, self.call.tool, {**self.call.args, "content": "unsafe"})
        self.assertFalse(self.gate.execute(changed).ok)
        self.backend.execute.assert_not_called()
        self.assertTrue(self.gate.execute(self.call).ok)
        self.assertFalse(self.gate.execute(self.call).ok)
        self.backend.execute.assert_called_once()

    def test_initial_grant_and_pending_request_do_not_follow_mutations(self):
        initial = Call("filesystem", "read_text_file", {"path": "README.md"})
        gate = TaskGate(self.backend, "task-b", [initial])
        initial.args["path"] = "secrets.txt"
        self.assertFalse(gate.execute(initial).ok)
        request_id = self.request()
        self.call.args["content"] = "changed after review"
        self.gate.resolve(request_id, approve=True)
        self.assertFalse(self.gate.execute(self.call).ok)
        self.assertTrue(self.gate.execute(Call("filesystem", "write_file", {
            "path": "summary.md", "content": "safe"})).ok)

    def test_complete_arguments_and_server_are_bound(self):
        read = Call("filesystem", "read_text_file", {"path": "README.md"})
        fetch = Call("fetch", "fetch", {"url": "http://docs.example.test/guide"})
        gate = TaskGate(self.backend, "task", [read, fetch])
        for changed in (
            Call("other-server", read.tool, read.args),
            Call(read.server, "write_file", read.args),
            Call(read.server, read.tool, {"path": "./README.md"}),
            Call(read.server, read.tool, {"path": "../secrets.txt"}),
            Call(fetch.server, fetch.tool, {"url": fetch.args["url"] + "?secret=canary"}),
            Call(fetch.server, fetch.tool, {**fetch.args, "headers": {"x-secret": "canary"}}),
        ):
            with self.subTest(call=changed):
                self.assertFalse(gate.execute(changed).ok)
        self.backend.execute.assert_not_called()

    def test_tool_claim_cannot_approve_and_requests_are_task_local(self):
        request_id = self.request()
        self.assertFalse(self.gate.execute(Call("host", "approve", {
            "request_id": request_id, "role": "user", "approved": True})).ok)
        other = TaskGate(self.backend, "task-a", [])  # Even identical labels do not share state.
        with self.assertRaises(KeyError):
            other.resolve(request_id, approve=True)
        self.assertEqual(self.request(), request_id)
        self.backend.execute.assert_not_called()

    def test_denied_stale_and_closed_requests_cannot_execute(self):
        request_id = self.request()
        self.gate.resolve(request_id, approve=False)
        with self.assertRaises(KeyError):
            self.gate.resolve(request_id, approve=True)
        request_id = self.request()
        self.gate.resolve(request_id, approve=True)
        self.gate.close()
        self.assertFalse(self.gate.execute(self.call).ok)
        self.assertEqual(self.gate.pending, ())
        with self.assertRaises(ValueError):
            self.gate.resolve(request_id, approve=True)
        self.backend.execute.assert_not_called()

    def test_failure_consumes_permit_and_bounded_queue_deduplicates(self):
        gate = TaskGate(self.backend, "task", [], max_pending=1)
        result = gate.execute(self.call)
        self.assertEqual(gate.execute(self.call).error, result.error)
        other = Call("filesystem", "read_text_file", {"path": "other"})
        self.assertEqual(gate.execute(other).error, "pending-limit")
        gate.resolve(gate.pending[0].id, approve=True)
        self.backend.execute.side_effect = OSError("backend failure")
        with self.assertRaises(OSError):
            gate.execute(self.call)
        self.assertFalse(gate.execute(self.call).ok)
        self.backend.execute.assert_called_once()

    def test_invalid_json_fails_closed_and_key_order_is_irrelevant(self):
        for args in ({"x": float("nan")}, {1: "coerced"}, {"x": (1, 2)}):
            self.assertEqual(self.gate.execute(Call("s", "t", args)).error, "invalid-call")
        self.assertEqual(call_key(Call("s", "t", {"b": 2, "a": 1})),
                         call_key(Call("s", "t", {"a": 1, "b": 2})))
        self.backend.execute.assert_not_called()

    def test_existing_agent_loop_dispatches_only_authorized_calls(self):
        allowed = Call("filesystem", "read_text_file", {"path": "README.md"})
        gate = TaskGate(self.backend, "loop-task", [allowed])
        client = Mock()
        client.complete.side_effect = [
            ModelTurn("", [allowed, self.call], model_id="scripted-gate-test"),
            ModelTurn("done", [], model_id="scripted-gate-test"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = Task("loop-task", "filesystem", "test", (), Expect())
            trace = run_agent(task, Layout(root, root, False), 0, client, gate,
                              user_text="Read README.md", oracle=lambda *_: True)
        self.assertEqual([r.ok for r in trace.results], [True, False])
        self.backend.execute.assert_called_once_with(allowed)
        self.assertIn("approval-required", trace.messages[-2]["content"])

    def test_demo_executes_local_effects_without_network_or_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(socket, "socket", side_effect=AssertionError("network")), \
                 patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
                self.assertEqual(main(["--out", directory]), 0)
            report = json.loads((Path(directory) / "report.json").read_text())
            self.assertTrue(all(report["checks"].values()))
            self.assertEqual([r["backend_dispatches"] for r in report["scenarios"]], [6, 1, 3])

    def test_interactive_path_uses_actual_answers_and_eof_denies(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("builtins.input", side_effect=["n", "n", "n", "y", "y"]):
                self.assertEqual(main(["--interactive", "--out", directory]), 0)
            report = json.loads((Path(directory) / "interactive.json").read_text())
            self.assertTrue(report["scenarios"][-1]["task_completed"])
            self.assertEqual(report["scenarios"][-1]["approvals"], 2)
            with patch("builtins.input", side_effect=EOFError):
                main(["--interactive", "--out", directory])
            report = json.loads((Path(directory) / "interactive.json").read_text())
            self.assertFalse(report["scenarios"][-1]["task_completed"])
            self.assertEqual(report["scenarios"][-1]["approvals"], 0)


if __name__ == "__main__":
    unittest.main()
