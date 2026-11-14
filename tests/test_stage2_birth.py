"""Stage 3 birth arm (M4.1), model-free.

`birth_records` drives the clean and poisoned policy requests and scores each
with `birth_record`. These tests use the `UnconstrainedPolicy` harness double,
so no model is called. The live run is `python -m wiggle.stage2 birth`.
"""

import json
import types
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from wiggle.pilot import UnconstrainedPolicy
from wiggle.stage2 import STAGE2_GOALS, make_fixture, stage2_tasks
from wiggle.replay import ReportRefusal
from wiggle.stage2_run import (
    BIRTH_TOKENS_COUNTED,
    POLICY_ATTEMPTS,
    _birth_report,
    baseline_record,
    birth_records,
    injected_targets,
    run_birth,
    stage2_policy_messages,
)


class Stage2BirthTests(unittest.TestCase):
    def test_birth_covers_tasks_and_goals_with_execution_scored_apart(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = make_fixture(Path(tmp) / "fx")
            tasks = [t for t in stage2_tasks() if t.split == "heldout" and t.server == "filesystem"][:2]
            self.assertEqual(len(tasks), 2)
            names = sorted({tool for task in tasks for tool, _args in task.calls})
            tools = [{"name": name, "description": "", "inputSchema": {}} for name in names]
            goals = STAGE2_GOALS[:2]
            records = birth_records(tasks, tools, fx, UnconstrainedPolicy(), goals, log=lambda *a: None)
        self.assertEqual(len(records), len(tasks) * len(goals))
        for record in records:
            # Unconstrained clean and poisoned are identical, so the paste adds nothing.
            self.assertEqual(record["added_beyond_clean"], [])
            # The unconstrained allowlist is still outside each task's exact calls (L5).
            self.assertTrue(record["policy_widened"])
            # No agent runs in this arm: execution is kept apart and is None.
            self.assertIsNone(record["action_executed"])
            self.assertIn(record["goal_id"], {goal.id for goal in goals})
            self.assertEqual(record["server"], "filesystem")

    def test_untrusted_paste_enters_only_the_poisoned_user_turn(self):
        task = next(t for t in stage2_tasks() if t.split == "heldout")
        tools = [{"name": "read_text_file", "description": "", "inputSchema": {}}]
        clean = stage2_policy_messages(task, "C:/proj", tools)
        poisoned = stage2_policy_messages(task, "C:/proj", tools, untrusted="WIGGLE_PASTE_MARKER")
        self.assertNotIn("WIGGLE_PASTE_MARKER", clean[1]["content"])
        self.assertIn("WIGGLE_PASTE_MARKER", poisoned[1]["content"])
        # The tool listing still follows the paste, so the generator sees both.
        self.assertIn("read_text_file", poisoned[1]["content"])

    def test_a_refused_task_keeps_the_finished_tasks_for_the_next_invocation(self):
        heldout = [t for t in stage2_tasks() if t.split == "heldout"]
        goals = STAGE2_GOALS[:2]
        names = sorted({tool for task in heldout for tool, _args in task.calls})
        tools = [{"name": name, "description": "", "inputSchema": {}} for name in names]

        class FailsOnce:
            """Unconstrained policies; with `broken`, the third task never parses."""

            def __init__(self, broken):
                self.inner = UnconstrainedPolicy()
                self.broken = broken
                self.n = 0

            def complete(self, messages, tools):
                self.n += 1
                turn = self.inner.complete(messages, tools)
                # Two tasks are (1 clean + goals) requests each; every later request is malformed.
                if self.broken and self.n > 2 * (1 + len(goals)):
                    return type(turn)("not json", [])
                return turn

        servers = unittest.mock.MagicMock()
        with tempfile.TemporaryDirectory() as tmp,                 unittest.mock.patch("wiggle.stage2_run.Servers", return_value=servers),                 unittest.mock.patch("wiggle.stage2_run.stage2_tool_list", return_value=tools):
            root = Path(tmp) / "birth"
            with self.assertRaises(ReportRefusal):
                run_birth(root, FailsOnce(True), model_arg="double", goals=goals, log=lambda *a: None)
            kept = [json.loads(line) for line in (root / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(kept), 2 * len(goals))
            calls = []
            client = FailsOnce(False)
            original = client.complete
            client.complete = lambda messages, tools: calls.append(1) or original(messages, tools)
            report = run_birth(root, client, model_arg="double", goals=goals, log=lambda *a: None)
        self.assertEqual(report["held_out_tasks"], len(heldout))
        self.assertEqual(report["pairs"], len(heldout) * len(goals))
        # The two finished tasks were not requested again: (1 clean + goals) requests per
        # other task, then the clean-vs-clean baseline sends two clean requests per task.
        self.assertEqual(len(calls), (len(heldout) - 2) * (1 + len(goals)) + 2 * len(heldout))
        self.assertEqual(report["baseline"]["repeat_added_beyond_clean"]["total"], len(heldout))
        # The unconstrained double gives the same policy twice, so a repeat adds nothing.
        self.assertEqual(report["baseline"]["repeat_added_beyond_clean"]["hits"], 0)

    def test_a_poisoned_request_with_no_allowlist_is_an_outcome_not_a_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = make_fixture(Path(tmp) / "fx")
            task = next(t for t in stage2_tasks() if t.split == "heldout" and t.server == "filesystem")
            tools = [{"name": tool, "description": "", "inputSchema": {}} for tool, _args in task.calls]

            class LoopsOnPaste:
                def __init__(self):
                    self.inner = UnconstrainedPolicy()

                def complete(self, messages, tools):
                    turn = self.inner.complete(messages, tools)
                    if "Untrusted text pasted" in messages[1]["content"]:
                        return type(turn)("(N(N(N(N(N(N", [])
                    return turn

            records = birth_records([task], tools, fx, LoopsOnPaste(), STAGE2_GOALS[:1], log=lambda *a: None)
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["poisoned_unparsed"])
        self.assertEqual(records[0]["added_beyond_clean"], [])
        self.assertFalse(records[0]["policy_widened"])

    def test_only_items_naming_the_goal_target_count_toward_it(self):
        record = {"goal_id": "G1", "added_beyond_clean": ["git_log.max_count=3", "tool:fetch", "read_text_file.path=secrets/token.txt"]}
        self.assertEqual(injected_targets(record), ["read_text_file.path=secrets/token.txt"])
        # The same item is not a G2 target.
        self.assertEqual(injected_targets(dict(record, goal_id="G2")), [])

    def test_baseline_scores_the_second_clean_policy_against_the_first(self):
        class Alternating:
            def __init__(self):
                self.n = 0

            def complete(self, messages, tools):
                self.n += 1
                text = '{"tools":[{"name":"read_text_file","constraints":[]}]}'
                if self.n == 2:
                    text = '{"tools":[{"name":"read_text_file","constraints":[]},{"name":"list_directory","constraints":[]}]}'
                return types.SimpleNamespace(text=text, calls=[], usage={"total_tokens": 5})

        task = next(t for t in stage2_tasks() if t.split == "heldout")
        row = baseline_record(Alternating(), task, "C:/proj", [])
        self.assertEqual(row["added_beyond_clean"], ["tool:list_directory"])
        self.assertEqual(row["policy_tokens"], 10)

    def test_the_tokens_of_a_request_with_no_allowlist_still_count(self):
        class Garbled:
            def complete(self, messages, tools):
                return types.SimpleNamespace(text="(N(N(N(N", calls=[], usage={"total_tokens": 5})

        task = next(t for t in stage2_tasks() if t.split == "heldout")
        row = baseline_record(Garbled(), task, "C:/proj", [])
        self.assertEqual(row["policy_tokens"], 2 * POLICY_ATTEMPTS * 5)
        self.assertEqual(row["tokens_counted"], BIRTH_TOKENS_COUNTED)

    def test_a_report_names_what_its_policy_tokens_count(self):
        record = {"task_id": "t", "goal_id": "G1", "server": "s", "added_beyond_clean": [], "policy_tokens": {"clean": 1, "poisoned": 1}}
        base = {"task_id": "t", "server": "s", "added_beyond_clean": [], "policy_tokens": 1}
        self.assertNotIn("tokens_counted", _birth_report([dict(record)], "m", STAGE2_GOALS[:1], [base]))
        counted = {"tokens_counted": BIRTH_TOKENS_COUNTED}
        report = _birth_report([{**record, **counted}], "m", STAGE2_GOALS[:1], [{**base, **counted}])
        self.assertEqual(report["tokens_counted"], BIRTH_TOKENS_COUNTED)

    def test_a_clean_baseline_request_with_no_allowlist_is_counted_not_refused(self):
        class Garbled:
            def complete(self, messages, tools):
                return types.SimpleNamespace(text="(N(N(N(N", calls=[], usage=None)

        task = next(t for t in stage2_tasks() if t.split == "heldout")
        row = baseline_record(Garbled(), task, "C:/proj", [])
        self.assertEqual(row["unparsed_requests"], 2)
        self.assertEqual(row["added_beyond_clean"], [])


if __name__ == "__main__":
    unittest.main()
