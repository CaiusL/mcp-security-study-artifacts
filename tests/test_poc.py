"""Mechanism tests for the envelope proof of concept."""

import shutil
import tempfile
import unittest
from pathlib import Path

from wiggle.corpus import build_probes, make_sandbox, scripted_calls, tasks
from wiggle.declared import extract_declared
from wiggle.evaluate import run_study, scanner_flags
from wiggle.model import Call, Scope
from wiggle.normalize import norm_resolved
from wiggle.policy import allows, build_profile
from wiggle.servers import FETCH_PAGES, FetchServer, FilesystemServer


class ServerTests(unittest.TestCase):
    def test_prefix_sibling_is_reachable_only_on_the_vulnerable_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = make_sandbox(Path(tmp) / "sandbox")
            sibling = str(layout.root / "proj_secrets" / "canary.txt")
            call = build_probes(layout)
            sibling_probe = next(probe for probe in call if probe.id == "fs-sibling-read")
            vulnerable = FilesystemServer(layout.proj, "vulnerable").execute(sibling_probe.call)
            patched = FilesystemServer(layout.proj, "patched").execute(sibling_probe.call)
        self.assertTrue(vulnerable.ok)
        self.assertIn("WIGGLE_CANARY_SIBLING", vulnerable.text)
        self.assertFalse(patched.ok)
        self.assertIn("proj_secrets", sibling)

    def test_dotdot_and_symlink_follow_only_when_vulnerable(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = make_sandbox(Path(tmp) / "sandbox")
            probes = {probe.id: probe for probe in build_probes(layout)}
            self.assertIn("fs-dotdot-read", probes)
            names = ["fs-dotdot-read"]
            if layout.has_symlink:
                self.assertIn("fs-symlink-read", probes)
                names.append("fs-symlink-read")
            else:
                self.assertNotIn("fs-symlink-read", probes)
            for probe_id in names:
                vulnerable = FilesystemServer(layout.proj, "vulnerable").execute(probes[probe_id].call)
                patched = FilesystemServer(layout.proj, "patched").execute(probes[probe_id].call)
                self.assertTrue(vulnerable.ok, probe_id)
                self.assertIn("WIGGLE_CANARY_OUTSIDE", vulnerable.text)
                self.assertFalse(patched.ok, probe_id)

    def test_secret_inside_the_root_is_reachable_on_both_servers(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = make_sandbox(Path(tmp) / "sandbox")
            probe = next(probe for probe in build_probes(layout) if probe.id == "fs-secret-read")
            for mode in ("vulnerable", "patched"):
                result = FilesystemServer(layout.proj, mode).execute(probe.call)
                self.assertTrue(result.ok)
                self.assertIn("WIGGLE_CANARY_SECRET", result.text)

    def test_search_skips_a_binary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = make_sandbox(Path(tmp) / "sandbox")
            (layout.proj / "blob.bin").write_bytes(b"README\xd4\xff")
            (layout.proj / "notes.txt").write_text("needle\n", encoding="utf-8")
            for mode in ("vulnerable", "patched"):
                call = Call("filesystem", "search_files", {"path": str(layout.proj), "pattern": "needle"})
                result = FilesystemServer(layout.proj, mode).execute(call)
                self.assertTrue(result.ok, mode)
                self.assertIn("notes.txt", result.text)
                self.assertNotIn("blob.bin", result.text)

    def test_patched_fetch_blocks_private_and_file_urls(self):
        vulnerable = FetchServer("vulnerable")
        patched = FetchServer("patched")
        for url in (
            "http://127.0.0.1/latest/meta-data",
            "http://169.254.169.254/latest/meta-data",
            "http://10.1.2.3/internal",
            "file:///wiggle-fixture/outside/canary.txt",
        ):
            request = Call("fetch", "fetch", {"url": url, "max_length": 2000})
            opened = vulnerable.execute(request)
            self.assertTrue(opened.ok, url)
            self.assertIn("WIGGLE_CANARY", opened.text)
            self.assertFalse(patched.execute(request).ok, url)


class PolicyTests(unittest.TestCase):
    def _scope_and_profile(self, layout):
        scope = Scope(declared_root=norm_resolved(str(layout.proj)))
        calls = [
            call
            for task in tasks()
            if task.split == "train"
            for rep in (0, 1, 2)
            for call in scripted_calls(task, layout, rep)
        ]
        return scope, build_profile(calls)

    def test_levels_are_nested_and_cover_training_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = make_sandbox(Path(tmp) / "sandbox")
            scope, profile = self._scope_and_profile(layout)
            calls = [
                call
                for task in tasks()
                for rep in (0, 1, 2)
                for call in scripted_calls(task, layout, rep)
            ]
            probes = build_probes(layout)
            samples = list(calls) + [probe.call for probe in probes]
            for call in samples:
                decisions = [allows(call, level, profile, scope).allow for level in range(6)]
                for lower in range(5):
                    if decisions[lower + 1]:
                        self.assertTrue(decisions[lower], call)
            train_calls = [
                call
                for task in tasks()
                if task.split == "train"
                for rep in (0, 1)
                for call in scripted_calls(task, layout, rep)
            ]
            for call in train_calls:
                for level in range(6):
                    decision = allows(call, level, profile, scope)
                    self.assertTrue(decision.allow, (level, decision.reason, call.tool))
            self.assertEqual(profile.ancestor, scope.declared_root)

    def test_needed_dirs_block_secrets_and_keep_weekly_notes_until_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = make_sandbox(Path(tmp) / "sandbox")
            scope, profile = self._scope_and_profile(layout)
            probes = {probe.id: probe for probe in build_probes(layout)}
            secret = probes["fs-secret-read"].call
            notes = probes["fs-write-sh-notes"].call
            weekly = next(task for task in tasks() if task.id == "fs-h-weekly")
            docs = next(task for task in tasks() if task.id == "fs-h-docs")
            weekly_call = scripted_calls(weekly, layout, 0)[0]
            docs_call = scripted_calls(docs, layout, 0)[0]
            self.assertTrue(allows(secret, 2, profile, scope).allow)
            self.assertFalse(allows(secret, 3, profile, scope).allow)
            self.assertTrue(allows(notes, 3, profile, scope).allow)
            self.assertFalse(allows(notes, 4, profile, scope).allow)
            self.assertTrue(allows(weekly_call, 4, profile, scope).allow)
            self.assertFalse(allows(weekly_call, 5, profile, scope).allow)
            self.assertTrue(allows(docs_call, 2, profile, scope).allow)
            self.assertFalse(allows(docs_call, 3, profile, scope).allow)


class PathTests(unittest.TestCase):
    def test_relative_sandbox_root_yields_absolute_calls(self):
        root = Path("artifacts") / "relcheck"
        try:
            layout = make_sandbox(root)
            self.assertTrue(layout.proj.is_absolute())
            call = scripted_calls(tasks()[0], layout, 0)[0]
            self.assertTrue(Path(call.args["path"]).is_absolute())
            result = FilesystemServer(layout.proj, "patched").execute(call)
            self.assertTrue(result.ok, result.error)
        finally:
            shutil.rmtree(root, ignore_errors=True)
            resolved = root.resolve()
            if resolved.exists():
                shutil.rmtree(resolved, ignore_errors=True)


class DeclaredTests(unittest.TestCase):
    def test_schema_is_a_free_string_and_intent_is_tighter(self):
        envelope = extract_declared("<configured-root>")
        read = next(tool for tool in envelope["tools"] if tool["name"] == "read_text_file")
        path = next(item for item in read["schema_constraints"] if item["argument"] == "path")
        self.assertEqual(path["type"], "string")
        self.assertIsNone(path["pattern"])
        self.assertTrue(read["intent_constraints"])
        fetch = next(tool for tool in envelope["tools"] if tool["name"] == "fetch")
        self.assertTrue(any("private" in item for item in fetch["intent_constraints"]))

    def test_fetch_task_needles_match_fixture_pages(self):
        for task in tasks():
            for step in task.steps:
                if step.tool != "fetch":
                    continue
                body = FETCH_PAGES[step.url]
                for needle in task.expect.texts:
                    self.assertIn(needle, body)


class StudyTests(unittest.TestCase):
    def test_curve_and_envelopes(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = run_study(Path(tmp) / "out")
            out = Path(tmp) / "out"
            self.assertTrue((out / "curve.svg").is_file())
            self.assertTrue((out / "results.json").is_file())
            self.assertTrue((out / "report.md").is_file())
            self.assertFalse((out / "sandbox").exists())

        vuln = payload["modes"]["vulnerable"]
        patched = payload["modes"]["patched"]
        self.assertEqual(vuln[0]["attacks_blocked"], 0)
        self.assertEqual(vuln[0]["heldout_success_rate"], 1)
        self.assertEqual(patched[0]["boundary_block_rate"], 1)
        self.assertEqual(patched[0]["excess_block_rate"], 0)
        self.assertGreater(vuln[-1]["attack_block_rate"], vuln[0]["attack_block_rate"])
        self.assertLess(vuln[-1]["heldout_success_rate"], vuln[0]["heldout_success_rate"])
        self.assertGreater(payload["envelopes"]["patched"]["reachable_inside_intent_not_needed"], 0)
        self.assertGreater(payload["envelopes"]["vulnerable"]["reachable_outside_declared_intent"], 0)
        self.assertTrue(payload["profile"]["ancestor_equals_declared_root"])
        point = payload["operating_point"]["level"]
        self.assertGreater(point, 0)
        self.assertLess(point, 5)
        scanner = payload["scanner"]
        self.assertEqual(scanner["recall_on_attacks"], 1)
        self.assertEqual(scanner["false_positive_rate_on_needed_controls"], 1)
        self.assertEqual(scanner["policy_false_positive_rate_on_needed_controls"], 0)
        self.assertGreater(scanner["policy_attack_block_rate"], 0)
        self.assertTrue(scanner_flags("read_text_file"))
        self.assertIn("L3", payload["narrative"] + payload["operating_point"]["name"])


if __name__ == "__main__":
    unittest.main()
