"""Progent (secagent) layer (d) enforcement, model-free.

Hand-built secagent policies (no model call) exercise the enforcement wrapper
in `wiggle/progent.py`. Skipped when the vendored secagent tree is absent.
"""

import json
import types
import unittest
import unittest.mock

from wiggle import progent
from wiggle.agent_loop import ModelError
from wiggle.injection import policy_decision
from wiggle.model import Call
from wiggle.replay import ReportRefusal, over_permission
from wiggle.stage2 import stage2_tasks
from wiggle.stage2_run import ProgentGenerator


class _FakeClient:
    """Returns one canned completion, standing in for the study's HostedModel."""

    def __init__(self, text, usage=None):
        self._text = text
        self.usage = usage

    def complete(self, messages, tools):
        del messages, tools
        return types.SimpleNamespace(text=self._text, calls=[], usage=self.usage)


@unittest.skipUnless(progent.available(), "vendor/py-progent (secagent) is not installed")
class ProgentEnforcementTests(unittest.TestCase):
    def test_allow_policy_blocks_other_tools_and_bad_arguments(self):
        tools = [
            {"name": "read_text_file", "description": "", "args": {"path": {"type": "string"}}},
            {"name": "write_file", "description": "", "args": {"path": {"type": "string"}}},
        ]
        policy = {"read_text_file": [(100, 0, {"path": {"type": "string", "const": "README.md"}}, 0)]}
        progent.set_policy(tools, policy, query="read the readme")
        self.assertFalse(progent.denies(Call("filesystem", "read_text_file", {"path": "README.md"})))
        self.assertTrue(progent.denies(Call("filesystem", "read_text_file", {"path": "secrets/token.txt"})))
        self.assertTrue(progent.denies(Call("filesystem", "write_file", {"path": "run.sh"})))

    def test_unconstrained_allow_passes_and_unlisted_tool_is_denied(self):
        progent.set_policy([], {"read_text_file": [(100, 0, {}, 0)]}, query="x")
        self.assertFalse(progent.denies(Call("filesystem", "read_text_file", {"path": "anything"})))
        self.assertTrue(progent.denies(Call("filesystem", "delete_file", {"path": "x"})))

    def test_generate_policy_builds_progent_tuples_and_enforces(self):
        canned = '[{"name": "read_text_file", "args": {"path": {"type": "string", "pattern": "^README"}}}]'
        client = _FakeClient(canned, usage={"total_tokens": 123})
        tools = [
            {"name": "read_text_file", "description": "", "inputSchema": {"properties": {"path": {"type": "string"}}}},
            {"name": "write_file", "description": "", "inputSchema": {"properties": {"path": {"type": "string"}}}},
        ]
        policy, usage = progent.generate_policy(client, "read the readme", tools)
        self.assertEqual(policy["read_text_file"][0][:2], (100, 0))
        self.assertEqual(usage, {"total_tokens": 123})
        # The generated Progent policy enforces as Progent would.
        progent.set_policy(tools, policy, query="read the readme")
        self.assertFalse(progent.denies(Call("filesystem", "read_text_file", {"path": "README.md"})))
        self.assertTrue(progent.denies(Call("filesystem", "read_text_file", {"path": "secrets.txt"})))
        self.assertTrue(progent.denies(Call("filesystem", "write_file", {"path": "run.sh"})))

    def test_stored_progent_allowlist_enforces_through_layer_d(self):
        canned = '[{"name": "read_text_file", "args": {"path": {"type": "string", "const": "README.md"}}}]'
        tools = [
            {"name": "read_text_file", "description": "", "inputSchema": {"properties": {"path": {"type": "string"}}}},
            {"name": "write_file", "description": "", "inputSchema": {"properties": {"path": {"type": "string"}}}},
        ]
        task = next(t for t in stage2_tasks() if t.split == "heldout")
        allowlist, usage = ProgentGenerator(_FakeClient(canned, usage={"total_tokens": 7})).allowlist(task, "C:/proj", tools)
        self.assertEqual(usage, {"total_tokens": 7})
        # allowlists.json stores JSON: the policy tuples come back as lists.
        allowlist = json.loads(json.dumps(allowlist))
        self.assertTrue(policy_decision(Call("filesystem", "read_text_file", {"path": "README.md"}), allowlist).allow)
        self.assertFalse(policy_decision(Call("filesystem", "read_text_file", {"path": "secrets.txt"}), allowlist).allow)
        self.assertFalse(policy_decision(Call("filesystem", "write_file", {"path": "run.sh"}), allowlist).allow)
        # Over-permission is counted at tool level for a Progent allowlist.
        self.assertEqual(over_permission(allowlist, [Call("filesystem", "list_directory", {"path": "."})]), ["tool:read_text_file"])

    def test_generator_retries_a_malformed_policy(self):
        class Flaky(_FakeClient):
            def __init__(self):
                super().__init__("")
                self.replies = ["not json", '[{"name": "read_text_file", "args": {}}]']

            def complete(self, messages, tools):
                return types.SimpleNamespace(text=self.replies.pop(0), calls=[], usage=None)

        task = next(t for t in stage2_tasks() if t.split == "heldout")
        allowlist, _usage = ProgentGenerator(Flaky()).allowlist(task, "C:/proj", [])
        self.assertEqual(allowlist["tools"], [{"name": "read_text_file"}])

    def test_generator_retries_a_model_error_or_a_wrong_shape_and_counts_every_reply(self):
        usage = {"prompt_tokens": 9, "completion_tokens": 1, "total_tokens": 10}

        class Flaky:
            def __init__(self):
                self.replies = [
                    ModelError("model request failed (503)"),
                    '{"name": "read_text_file", "args": {}}',
                    '[{"args": {}}]',
                    '[{"name": "read_text_file", "args": {}}]',
                ]

            def complete(self, messages, tools):
                reply = self.replies.pop(0)
                if isinstance(reply, Exception):
                    raise reply
                return types.SimpleNamespace(text=reply, calls=[], usage=dict(usage))

        task = next(t for t in stage2_tasks() if t.split == "heldout")
        allowlist, spent = ProgentGenerator(Flaky()).allowlist(task, "C:/proj", [])
        self.assertEqual(allowlist["tools"], [{"name": "read_text_file"}])
        # The two replies that were not a policy cost tokens too; the failed request sent none back.
        self.assertEqual(spent, {"prompt_tokens": 27, "completion_tokens": 3, "total_tokens": 30})
        with self.assertRaisesRegex(ReportRefusal, "after 4 attempts"):
            ProgentGenerator(_FakeClient('{"tools": []}')).allowlist(task, "C:/proj", [])

    def test_an_empty_policy_allows_no_tool(self):
        task = next(t for t in stage2_tasks() if t.split == "heldout")
        allowlist, _usage = ProgentGenerator(_FakeClient("[]")).allowlist(task, "C:/proj", [])
        self.assertEqual(allowlist, {"progent": {}, "tools": []})
        self.assertFalse(policy_decision(Call("filesystem", "read_text_file", {"path": "README.md"}), allowlist).allow)

    def test_a_missing_policy_blocks(self):
        decision = policy_decision(Call("filesystem", "write_file", {"path": "run.sh"}), {"tools": [], "progent": None})
        self.assertFalse(decision.allow)

    def test_a_policy_is_sorted_once_and_each_call_gets_it_unchanged(self):
        # A fifth item is secagent's rewrite: this allow empties the tool's entries in the loaded policy.
        policy = {"read_text_file": [[100, 0, {}, 0, {"read_text_file": []}]]}
        call = Call("filesystem", "read_text_file", {"path": "README.md"})
        tool = progent._tool_module()
        with unittest.mock.patch.object(tool, "sort_policy", wraps=tool.sort_policy) as sort_policy:
            self.assertFalse(progent.check(call, policy))
            self.assertEqual(sort_policy.call_count, 2)  # The load, then the rewrite.
            self.assertFalse(progent.check(call, policy))
        self.assertEqual(sort_policy.call_count, 3)  # The second rewrite only.


if __name__ == "__main__":
    unittest.main()
