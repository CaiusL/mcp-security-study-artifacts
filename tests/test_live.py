"""Client unit test and the live filesystem study."""

import json
import tempfile
import unittest
from pathlib import Path

from wiggle.corpus import make_sandbox, scripted_calls, tasks
from wiggle.mcp_client import McpStdio, filesystem_server_command
from wiggle.model import Call, Scope
from wiggle.normalize import norm_resolved
from wiggle.policy import allows, build_profile


FAKE_SERVER = r"""
import json, sys
for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "serverInfo": {"name": "fake", "version": "0"},
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "read_text_file",
                    "description": "Only works within allowed directories.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                }
            ]
        }
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "hello"}], "isError": False}
    else:
        result = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"""


class ClientTests(unittest.TestCase):
    def test_initialize_list_and_call(self):
        session = McpStdio(["python", "-c", FAKE_SERVER])
        try:
            init = session.initialize()
            self.assertEqual(init["serverInfo"]["name"], "fake")
            tools = session.list_tools()
            self.assertEqual(tools[0]["name"], "read_text_file")
            result = session.call_tool("read_text_file", {"path": "README.md"})
            self.assertTrue(result.ok)
            self.assertEqual(result.text, "hello")
        finally:
            session.close()


class GitServerTests(unittest.TestCase):
    def test_pinned_server_reads_its_repo_and_refuses_another(self):
        from wiggle.live_git import _make_repos
        from wiggle.mcp_client import python_module_command, vendored_python_env

        with tempfile.TemporaryDirectory() as tmp:
            layout = _make_repos(Path(tmp) / "sandbox")
            session = McpStdio(
                python_module_command("mcp_server_git", "--repository", str(layout.proj)),
                env=vendored_python_env(),
            )
            try:
                session.initialize()
                status = session.call_tool("git_status", {"repo_path": str(layout.proj)})
                self.assertTrue(status.ok, status.error)
                self.assertIn("main", status.text)
                other = session.call_tool(
                    "git_status", {"repo_path": str(layout.root / "other-repo")}
                )
                self.assertFalse(other.ok)
            finally:
                session.close()


class FetchFlagTests(unittest.TestCase):
    def test_raw_true_is_outside_the_needed_flag(self):
        scope = Scope(declared_root="")
        train = Call("fetch", "fetch", {"url": "https://example.com/", "max_length": 4000})
        profile = build_profile([train])
        raw = Call("fetch", "fetch", {"url": "https://example.com/", "max_length": 2000, "raw": True})
        self.assertTrue(allows(raw, 1, profile, scope, check_schema=False).allow)
        decision = allows(raw, 2, profile, scope, check_schema=False)
        self.assertFalse(decision.allow)
        self.assertEqual(decision.reason, "raw")


class GitPolicyTests(unittest.TestCase):
    def test_add_outside_is_declared_and_secret_waits_for_directories(self):
        from wiggle.live_git import _calls, _make_repos, _tasks
        from wiggle.policy import allows

        with tempfile.TemporaryDirectory() as tmp:
            layout = _make_repos(Path(tmp) / "sandbox")
            scope = Scope(declared_root=norm_resolved(str(layout.proj)))
            calls = [
                call
                for task in _tasks()
                if task.split == "train"
                for call in _calls(task, layout)
            ]
            profile = build_profile(calls)
            secret = Call(
                "git",
                "git_add",
                {"repo_path": str(layout.proj), "files": ["secrets/token.txt"]},
            )
            outside = Call(
                "git",
                "git_add",
                {"repo_path": str(layout.proj), "files": ["../outside/canary.txt"]},
            )
            reset = Call("git", "git_reset", {"repo_path": str(layout.proj)})
            self.assertFalse(allows(outside, 1, profile, scope, check_schema=False).allow)
            self.assertTrue(allows(secret, 2, profile, scope, check_schema=False).allow)
            self.assertFalse(allows(secret, 3, profile, scope, check_schema=False).allow)
            self.assertTrue(allows(reset, 1, profile, scope, check_schema=False).allow)
            self.assertFalse(allows(reset, 2, profile, scope, check_schema=False).allow)
            show = Call("git", "git_show", {"repo_path": str(layout.proj), "revision": "HEAD"})
            hidden = Call(
                "git",
                "git_show",
                {"repo_path": str(layout.proj), "revision": "HEAD:notes/hidden.md"},
            )
            held = Call(
                "git",
                "git_show",
                {"repo_path": str(layout.proj), "revision": "HEAD:src/app.py"},
            )
            self.assertEqual(profile.git_revisions, {"HEAD"})
            self.assertTrue(allows(show, 4, profile, scope, check_schema=False).allow)
            self.assertTrue(allows(show, 5, profile, scope, check_schema=False).allow)
            self.assertTrue(allows(hidden, 3, profile, scope, check_schema=False).allow)
            hidden_l4 = allows(hidden, 4, profile, scope, check_schema=False)
            self.assertFalse(hidden_l4.allow)
            self.assertEqual(hidden_l4.reason, "revision")
            self.assertFalse(allows(hidden, 5, profile, scope, check_schema=False).allow)
            self.assertFalse(allows(held, 4, profile, scope, check_schema=False).allow)


class ComparisonTests(unittest.TestCase):
    def test_paired_finding_leads_and_the_table_stays(self):
        from wiggle.compare import build_comparison

        text = build_comparison(Path("."))
        table = text.index("| Server |")
        lead = text[:table]
        self.assertLess(lead.index("every boundary probe"), lead.index("in-scope excess"))
        self.assertIn("git-show-hidden", lead)
        self.assertIn("share of the lattice", lead)
        self.assertIn("same five patched pins", lead)
        self.assertEqual(text.count("\n| mcp-") + text.count("\n| @"), 5)
        self.assertIn("flat control", text)
        self.assertGreater(text.index("| Server |"), text.index("same five patched pins"))


class OperatingPointTests(unittest.TestCase):
    def test_equal_scores_keep_the_level_that_blocks_more(self):
        from wiggle.live_study import _prefer

        tighter = {
            "level": 4,
            "attacks_blocked": 10,
            "attacks_total": 10,
            "heldout_passed": 5,
            "heldout_total": 7,
        }
        looser = {
            "level": 3,
            "attacks_blocked": 9,
            "attacks_total": 10,
            "heldout_passed": 5,
            "heldout_total": 7,
        }
        self.assertTrue(_prefer(tighter, looser))
        self.assertFalse(_prefer(looser, tighter))


class FilesystemServerTests(unittest.TestCase):
    def test_pinned_server_reads_inside_the_root_and_refuses_a_sibling(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = make_sandbox(Path(tmp) / "sandbox")
            session = McpStdio(filesystem_server_command(layout.proj))
            try:
                session.initialize()
                names = {tool["name"] for tool in session.list_tools()}
                self.assertIn("read_text_file", names)
                self.assertGreaterEqual(len(names), 13)
                readme = session.call_tool(
                    "read_text_file", {"path": str(layout.proj / "README.md")}
                )
                self.assertTrue(readme.ok, readme.error)
                self.assertIn("# Project", readme.text)
                sibling = session.call_tool(
                    "read_text_file",
                    {"path": str(layout.root / "proj_secrets" / "canary.txt")},
                )
                self.assertFalse(sibling.ok)
                self.assertNotIn("WIGGLE_CANARY_SIBLING", sibling.text)
            finally:
                session.close()


class ThoughtPolicyTests(unittest.TestCase):
    def test_a_new_thought_stays_open_until_the_exact_level(self):
        from wiggle.policy import allows, build_profile

        scope = Scope(declared_root="")
        train = Call(
            "sequential-thinking",
            "sequentialthinking",
            {
                "thought": "Plan the weekly note.",
                "nextThoughtNeeded": False,
                "thoughtNumber": 1,
                "totalThoughts": 1,
            },
        )
        profile = build_profile([train])
        later = Call(
            "sequential-thinking",
            "sequentialthinking",
            {
                "thought": "A second step the tasks never take.",
                "nextThoughtNeeded": False,
                "thoughtNumber": 2,
                "totalThoughts": 2,
            },
        )
        zero = Call(
            "sequential-thinking",
            "sequentialthinking",
            {
                "thought": "Outside the count.",
                "nextThoughtNeeded": False,
                "thoughtNumber": 0,
                "totalThoughts": 1,
            },
        )
        self.assertTrue(allows(later, 4, profile, scope, check_schema=False).allow)
        self.assertFalse(allows(later, 5, profile, scope, check_schema=False).allow)
        self.assertTrue(allows(train, 5, profile, scope, check_schema=False).allow)
        denied = allows(zero, 1, profile, scope, check_schema=False)
        self.assertFalse(denied.allow)
        self.assertEqual(denied.reason, "declared-count")


class UnseenToolTests(unittest.TestCase):
    def test_unseen_tool_inside_the_root_is_allowed_at_declared_and_blocked_at_coarse(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = make_sandbox(Path(tmp) / "sandbox")
            scope = Scope(declared_root=norm_resolved(str(layout.proj)))
            calls = [
                call
                for task in tasks()
                if task.split == "train" and task.server == "filesystem"
                for call in scripted_calls(task, layout, 0)
            ]
            profile = build_profile(calls)
            tree = Call("filesystem", "directory_tree", {"path": str(layout.proj / "secrets")})
            self.assertTrue(allows(tree, 1, profile, scope, check_schema=False).allow)
            decision = allows(tree, 2, profile, scope, check_schema=False)
            self.assertFalse(decision.allow)
            self.assertEqual(decision.reason, "tool")


if __name__ == "__main__":
    unittest.main()
