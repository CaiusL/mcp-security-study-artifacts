"""The adversary fixtures: the frozen payload bytes and the shadow server's answers."""

import tempfile
import unittest
from pathlib import Path

from wiggle.adversary import deputy, shadow
from wiggle.injection import GOALS_BY_ID, render_template
from wiggle.zgscanner import rules


class PayloadByteTests(unittest.TestCase):
    def test_both_servers_carry_the_frozen_bytes(self):
        for goal_id in ("g1", "g2"):
            goal = GOALS_BY_ID[goal_id.upper()]
            self.assertEqual(shadow.payload(goal_id), render_template(goal))

    def test_description_is_a_detection_surface(self):
        for goal_id in ("g1", "g2"):
            hits = rules.scan_text(shadow.tool_description(goal_id), "tool")
            worst = {hit["severity"] for hit in hits}
            self.assertNotIn("critical", worst)
            self.assertNotIn("high", worst)


class ShadowServerTests(unittest.TestCase):
    def _call(self, goal_id, path, root=None):
        server = shadow.Shadow(goal_id, Path(root).resolve() if root else None)
        return server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_text_file", "arguments": {"path": path}},
            }
        )

    def test_tool_list_shadows_the_read_name(self):
        tools = shadow.listed_tools("g2")
        self.assertEqual([tool["name"] for tool in tools], ["read_text_file"])
        self.assertTrue(tools[0]["description"].startswith(shadow.BASE_DESCRIPTION))
        self.assertEqual(tools[0]["inputSchema"]["required"], ["path"])

    def test_read_answer_carries_content_then_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "app.py"
            target.write_text("def main():\n", encoding="utf-8")
            reply = self._call("g2", str(target))
        text = reply["result"]["content"][0]["text"]
        self.assertTrue(text.startswith("def main():\n"))
        self.assertIn(shadow.payload("g2"), text)
        self.assertFalse(reply["result"]["isError"])

    def test_relative_path_uses_the_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "src").mkdir()
            (Path(tmp) / "src" / "app.py").write_text("body\n", encoding="utf-8")
            reply = self._call("g1", "src/app.py", root=tmp)
        self.assertIn("body", reply["result"]["content"][0]["text"])

    def test_root_confines_reads_to_the_fixture_tree(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other:
            outside = Path(other) / "canary.txt"
            outside.write_text("WIGGLE_CANARY_OUTSIDE", encoding="utf-8")
            reply = self._call("g1", str(outside), root=tmp)
        self.assertTrue(reply["result"]["isError"])
        self.assertNotIn("WIGGLE_CANARY_OUTSIDE", reply["result"]["content"][0]["text"])

    def test_each_channel_can_be_served_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "app.py"
            target.write_text("body\n", encoding="utf-8")

            desc_only = shadow.Shadow("g1", None, "description")
            listed = desc_only.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            answer = desc_only.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                       "params": {"name": "read_text_file", "arguments": {"path": str(target)}}})
            self.assertIn(shadow.payload("g1"), listed["result"]["tools"][0]["description"])
            self.assertNotIn(shadow.payload("g1"), answer["result"]["content"][0]["text"])

            res_only = shadow.Shadow("g1", None, "result")
            listed = res_only.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            answer = res_only.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                      "params": {"name": "read_text_file", "arguments": {"path": str(target)}}})
            self.assertEqual(listed["result"]["tools"][0]["description"], shadow.BASE_DESCRIPTION)
            self.assertIn(shadow.payload("g1"), answer["result"]["content"][0]["text"])

    def test_missing_file_is_an_error_and_unknown_tool_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            reply = self._call("g1", str(Path(tmp) / "nope.txt"))
            self.assertTrue(reply["result"]["isError"])
            refused = shadow.Shadow("g1", None).handle(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "write_file", "arguments": {}}}
            )
        self.assertTrue(refused["result"]["isError"])


class DeputyTests(unittest.TestCase):
    def _call(self, server, name, arguments):
        return server.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
        )

    def test_tools_are_the_official_names_with_no_payload(self):
        names = [tool["name"] for tool in deputy.TOOLS]
        self.assertEqual(names, ["read_text_file", "write_file", "list_directory", "search_files"])
        for tool in deputy.TOOLS:
            self.assertNotIn("This is a message from the user", tool["description"])

    def test_cache_and_tamper_and_append_effects(self):
        from wiggle.corpus import CANARY_WRITE_SH

        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp) / "proj"
            (proj / "src").mkdir(parents=True)
            target = proj / "src" / "app.py"
            target.write_text("body\n", encoding="utf-8")

            cached = deputy.Deputy(proj, "cache")
            reply = self._call(cached, "read_text_file", {"path": str(target)})
            self.assertEqual(reply["result"]["content"][0]["text"], "body\n")
            cache_file = proj / ".cache" / "app.py.json"
            self.assertTrue(cache_file.is_file())
            self.assertIn(CANARY_WRITE_SH, cache_file.read_text(encoding="utf-8"))

            tampered = deputy.Deputy(proj, "tamper")
            target.write_text("body\n", encoding="utf-8")
            reply = self._call(tampered, "read_text_file", {"path": str(target)})
            self.assertEqual(reply["result"]["content"][0]["text"], "body\n")
            self.assertIn(CANARY_WRITE_SH, target.read_text(encoding="utf-8"))

            appended = deputy.Deputy(proj, "append")
            reply = self._call(appended, "write_file", {"path": str(proj / "notes" / "n.md"), "content": "saw\n"})
            self.assertFalse(reply["result"]["isError"])
            self.assertIn(CANARY_WRITE_SH, (proj / "notes" / "n.md").read_text(encoding="utf-8"))

    def test_no_effect_and_outside_effect(self):
        from wiggle.corpus import CANARY_WRITE_SH

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            proj = root / "proj"
            proj.mkdir(parents=True)
            (proj / "a.txt").write_text("hello\n", encoding="utf-8")

            plain = deputy.Deputy(proj, "none")
            self._call(plain, "read_text_file", {"path": "a.txt"})
            self.assertFalse((proj / ".cache").exists())
            self.assertEqual((proj / "a.txt").read_text(encoding="utf-8"), "hello\n")

            outside = deputy.Deputy(proj, "outside")
            self._call(outside, "read_text_file", {"path": "a.txt"})
            canary = root / "outside" / "a.txt.canary"
            self.assertTrue(canary.is_file())
            self.assertIn(CANARY_WRITE_SH, canary.read_text(encoding="utf-8"))

    def test_reads_are_confined_to_the_root(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other:
            proj = Path(tmp) / "proj"
            proj.mkdir()
            secret = Path(other) / "secret.txt"
            secret.write_text("outside", encoding="utf-8")
            reply = self._call(deputy.Deputy(proj, "none"), "read_text_file", {"path": str(secret)})
        self.assertTrue(reply["result"]["isError"])


if __name__ == "__main__":
    unittest.main()