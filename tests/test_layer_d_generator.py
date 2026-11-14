"""Layer (d) minimal generator retry (model-free).

A policy response can come back malformed once; the generator re-requests at the
same temperature before refusing, so one flaky completion does not end a run.
"""

import types
import unittest

from wiggle.agent_loop import ModelError
from wiggle.replay import ReportRefusal
from wiggle.stage2 import stage2_tasks
from wiggle.stage2_run import POLICY_ATTEMPTS, MinimalGenerator


class _Client:
    """Returns the given texts in order, repeating the last one."""

    def __init__(self, texts):
        self._texts = list(texts)
        self.n = 0

    def complete(self, messages, tools):
        del messages, tools
        text = self._texts[min(self.n, len(self._texts) - 1)]
        self.n += 1
        return types.SimpleNamespace(text=text, calls=[], usage={"total_tokens": 1})


class MinimalGeneratorRetryTests(unittest.TestCase):
    def setUp(self):
        self.task = next(task for task in stage2_tasks() if task.id == "note-guide-notes")
        self.tools = [
            {"name": "read_note", "description": "", "inputSchema": {}},
            {"name": "write_note", "description": "", "inputSchema": {}},
        ]

    def test_retries_a_malformed_response_then_parses(self):
        good = '{"tools":[{"name":"read_note","constraints":[]}]}'
        client = _Client(["not json at all", good])
        allowlist, usage = MinimalGenerator(client).allowlist(self.task, "/proj", self.tools)
        self.assertEqual(client.n, 2)
        self.assertEqual([tool["name"] for tool in allowlist["tools"]], ["read_note"])

    def test_refuses_after_exhausting_attempts(self):
        client = _Client(["still not json"])
        with self.assertRaises(ReportRefusal):
            MinimalGenerator(client).allowlist(self.task, "/proj", self.tools)
        self.assertEqual(client.n, POLICY_ATTEMPTS)

    def test_retries_a_model_error_then_parses(self):
        good = '{"tools":[{"name":"read_note","constraints":[]}]}'

        class Flaky(_Client):
            def complete(self, messages, tools):
                if self.n == 0:
                    self.n += 1
                    raise ModelError("model request failed (TimeoutError)")
                return super().complete(messages, tools)

        client = Flaky([good])
        allowlist, _usage = MinimalGenerator(client).allowlist(self.task, "/proj", self.tools)
        self.assertEqual(client.n, 2)
        self.assertEqual([tool["name"] for tool in allowlist["tools"]], ["read_note"])


if __name__ == "__main__":
    unittest.main()
