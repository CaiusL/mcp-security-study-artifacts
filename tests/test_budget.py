"""Stage 2 run budget. No model is called."""

import json
import tempfile
import unittest
from pathlib import Path

from wiggle.budget import (
    PILOT_DIR,
    PROMPT_TARGET_RUNS,
    SCENARIOS,
    Scenario,
    budget_record,
    measured_rates,
    runs,
    tasks_within_target,
    write_budget,
)
from wiggle.injection import SAMPLE_COUNT


class BudgetTest(unittest.TestCase):
    def test_pilot_design_reproduces_measured_record(self):
        report = json.loads((PILOT_DIR / "report.json").read_text(encoding="utf-8"))
        record = budget_record()
        cost = report["cost"]
        self.assertEqual(record["check"]["runs"]["total"], cost["agent"]["runs_with_usage"])
        self.assertEqual(
            record["check"]["tokens"]["total"],
            cost["agent"]["total_tokens"] + cost["policy"]["total_tokens"],
        )

    def test_samples_are_never_cut(self):
        for scenario in SCENARIOS:
            counts = runs(scenario)
            self.assertEqual(
                counts["benign"],
                scenario.models * scenario.servers * scenario.tasks_per_server * SAMPLE_COUNT,
            )

    def test_tasks_within_target_is_the_largest_fit(self):
        fit = tasks_within_target(2, 5)
        self.assertLessEqual(runs(Scenario("fit", 2, 5, fit))["total"], PROMPT_TARGET_RUNS)
        self.assertGreater(runs(Scenario("over", 2, 5, fit + 1))["total"], PROMPT_TARGET_RUNS)

    def test_missing_run_set_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            traces = Path(tmp) / "traces.jsonl"
            usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
            traces.write_text(json.dumps({"set": "benign", "usage": usage}) + "\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                measured_rates(traces, PILOT_DIR / "report.json")

    def test_price_is_only_used_when_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_budget(out, budget_record())
            self.assertIn("No price was passed", (out / "budget.md").read_text(encoding="utf-8"))
            record = write_budget(out, budget_record(usd_per_million=1.0))
            self.assertIn("USD at 1.0 per million tokens", (out / "budget.md").read_text(encoding="utf-8"))
            first = record["scenarios"][0]
            self.assertAlmostEqual(first["usd"], first["tokens"]["total"] / 1_000_000)


if __name__ == "__main__":
    unittest.main()
