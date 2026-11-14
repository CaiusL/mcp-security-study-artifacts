"""Path check and the labeled sandbox fixture."""

import tempfile
import unittest
from pathlib import Path

from wiggle.sandbox import IN_BOUNDS, OUT_OF_BOUNDS, run_sandbox
from wiggle.sandbox_server import SERVER_DESCRIPTION, TOOLS, contained


class PathTests(unittest.TestCase):
    def test_descendant_is_kept_and_sibling_prefix_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            (root / "secrets").mkdir(parents=True)
            (Path(tmp) / "proj_secrets").mkdir()
            note = root / "secrets" / "token.txt"
            note.write_text("inside", encoding="utf-8")
            sibling = Path(tmp) / "proj_secrets" / "canary.txt"
            sibling.write_text("outside", encoding="utf-8")
            self.assertEqual(contained(root.resolve(), str(note)), note.resolve())
            self.assertIsNone(contained(root.resolve(), str(sibling)))
            self.assertIsNone(contained(root.resolve(), str(Path(tmp) / "outside.txt")))

    def test_tool_contract_names_a_directory_and_a_free_path(self):
        self.assertIn("directory", SERVER_DESCRIPTION.lower())
        read = next(tool for tool in TOOLS if tool["name"] == "read_note")
        self.assertIn("path", read["description"].lower())
        prop = read["inputSchema"]["properties"]["path"]
        self.assertEqual(prop["type"], "string")
        self.assertNotIn("enum", prop)
        self.assertNotIn("pattern", prop)


class FixtureTests(unittest.TestCase):
    def test_labeled_probes_split_server_and_proxy(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = run_sandbox(Path(tmp) / "out")
        for row in payload["curve"]:
            self.assertEqual(row["train_success_rate"], 1.0)
        l0 = payload["curve"][0]
        self.assertEqual(l0["boundary_block_rate"], 1.0)
        self.assertEqual(l0["excess_block_rate"], 0.0)
        point = payload["operating_point"]
        self.assertEqual(point["level"], 3)
        self.assertEqual(point["attack_block_rate"], 1.0)
        self.assertEqual(point["heldout_success_rate"], 1.0)
        probes = payload["detectors"]["probes"]
        self.assertFalse(probes[OUT_OF_BOUNDS]["server_checks"]["miss"])
        self.assertTrue(probes[IN_BOUNDS]["server_checks"]["miss"])
        self.assertFalse(probes[OUT_OF_BOUNDS]["needed_proxy"]["miss"])
        self.assertFalse(probes[IN_BOUNDS]["needed_proxy"]["miss"])
        for probe_id in (OUT_OF_BOUNDS, IN_BOUNDS):
            for name in ("schema_heuristic", "registry_hint", "tools_list"):
                self.assertTrue(probes[probe_id][name]["flagged"])
        control = payload["detectors"]["needed_control"]
        self.assertTrue(control["schema_heuristic"])
        self.assertTrue(control["registry_hint"])
        self.assertTrue(control["tools_list"])
        self.assertEqual(control["proxy_denied"], "")
        self.assertTrue(control["server_performed"])
        self.assertEqual(payload["server_info"]["name"], "wiggle-sandbox")
