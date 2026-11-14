"""Offline demo regeneration, report arrival, and inert untrusted text."""

import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from wiggle.demo import ROOT, _birth, load_data, main, render


class DemoTests(unittest.TestCase):
    def test_birth_preserves_distinct_saved_comparisons_and_scope(self):
        data = load_data(ROOT / "artifacts")
        self.assertEqual({r["model"] for r in data["birth"]}, {"deepseek-flash", "qwen3.8-flash"})
        html = _birth(data)
        for record in data["birth"]:
            source = json.loads((ROOT / record["source"]).read_text(encoding="utf-8"))
            self.assertEqual(record["widened_beyond_clean"], source["widened_beyond_clean"])
            self.assertEqual(record["clean_repeat"], source["baseline"]["repeat_added_beyond_clean"])
            self.assertEqual(record["widened_toward_target"], source["widened_toward_target"])
            self.assertIn(record["source"], html)
        for count in ("32/390", "0/78", "46/390", "8/78", "0/390"):
            self.assertIn(count, html)
        self.assertIn("constructs policies only; action execution is not measured", html)
        self.assertIn("generic additions do not establish target compromise", html)

    def test_saved_reports_regenerate_without_network_or_processes(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "demo.html"
            with patch.object(socket.socket, "connect", side_effect=AssertionError("network")), \
                 patch.object(socket.socket, "connect_ex", side_effect=AssertionError("network")), \
                 patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")), \
                 patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
                main(["--out", str(output)])
            html = output.read_text(encoding="utf-8")
            data = load_data(ROOT / "artifacts")
            self.assertIn("Recorded study", html)
            self.assertEqual(len(data["stage2"]), 4)
            self.assertTrue(data["traces"])
            self.assertTrue(all(trace["goal"] is True for trace in data["traces"]))
            for report in data["stage2"]:
                self.assertIn(report["source"], html)
                for layer in report["layers_alone_stacked"]["patched"]["alone"].values():
                    self.assertIn(f"{layer['asr']['hits']}/{layer['asr']['total']}", html)
            self.assertIn("Replay unreliable for c; use live evidence", html)
            self.assertIn("connect-src 'none'", html)
            self.assertNotRegex(html, r'<(?:script|link|img)[^>]+(?:src|href)=')

    def test_missing_stage4_is_pending_then_picked_up_on_regeneration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertIn("Pending: no artifacts/stage4/*/report.json", render(load_data(root)))
            report = {
                "kind": "stage4-adaptive", "model_run": True,
                "target": {"model_argument": "fixture-model"}, "label": "adaptive fixture",
                "reruns": {"alone": {"c": {"hits": 1, "total": 3}}, "stacked": {},
                           "no_defense": {"hits": 2, "total": 3}, "unscored": {"hits": 0, "total": 3}},
                "static": {"same_cases": {"alone": {"c": {"hits": 0, "total": 3}}},
                           "all_cases": {"heldout": {"alone": {"c": {"hits": 7, "total": 9}}}}},
                "stage2_live_only": {"layers": ["c"]}, "budget": {}, "checks": {},
            }
            folder = root / "stage4/fixture-model"
            folder.mkdir(parents=True)
            (folder / "report.json").write_text(json.dumps(report), encoding="utf-8")
            output = root / "demo/index.html"
            main(["--artifacts", str(root), "--out", str(output)])
            html = output.read_text(encoding="utf-8")
            self.assertNotIn("Pending: no artifacts/stage4/*/report.json", html)
            self.assertIn("fixture-model", html)
            self.assertIn("Stage 4 has no live enforcement reruns", html)
            self.assertIn("1/3", html)
            self.assertIn("7/9", html)

    def test_report_and_trace_markup_is_inert_and_round_trips(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = load_data(Path(temporary))
        hostile = '</script><script>alert("payload")</script><img src=x onerror=alert(1)>&\u2028'
        data["comparison"] = hostile
        data["traces"] = [{"model_id": hostile, "results": [{"text": hostile}]}]
        html = render(data)
        self.assertNotIn(hostile, html)
        self.assertIn("&lt;/script&gt;", html)
        embedded = re.search(r'<script type="application/json" id="study-data">(.*?)</script>', html).group(1)
        self.assertNotIn("<", embedded)
        self.assertEqual(json.loads(embedded)["traces"], data["traces"])
        self.assertIn(".textContent=JSON.stringify", html)
        self.assertNotIn("innerHTML", html)


if __name__ == "__main__":
    unittest.main()
