"""Stage 2 oracles. Live filesystem, git, memory, and time servers. No model is called."""

import tempfile
import unittest
from collections import Counter
from dataclasses import asdict, replace
from pathlib import Path

from wiggle import budget
from wiggle.injection import cases as pilot_cases
from wiggle.injection import compatible_tasks as pilot_compatible
from wiggle.injection import TEMPLATE_TEXT, pilot_tasks, task_prompt
from wiggle.live_git import _remove_tree
from wiggle.servers import FETCH_PAGES, FetchServer
from wiggle.stage2 import (
    CHANNELS,
    PLANT_TASKS,
    REACH_MARKER,
    SERVERS,
    STAGE2_GOALS,
    STAGE2_PAGES,
    InjectionCase,
    Oracle,
    Servers,
    case_plant,
    catalog_sha256,
    check_goals,
    check_task,
    compatible_tasks,
    freeze_record,
    freeze_slots,
    live_cases,
    make_fixture,
    reset,
    stage2_cases,
    prompt_gaps,
    stage2_message,
    stage2_prompt,
    stage2_tasks,
    task_by_id,
    write_freeze,
)

# Test values only. They are not a scoring template or a layer (d) choice.
_SLOTS = {"scoring_template": "Test text: {instruction}", "layer_d_policy": {"generator": "test"}, "recorded": "2026-10-29"}

# One training and one held-out task per server, covering each kind of state check.
_SAMPLE = (
    "fs-move-draft",
    "fs-h-mkdir-archive",
    "fetch-two-docs",
    "fetch-h-wiki-home",
    "git-commit-standup",
    "git-h-checkout-new",
    "mem-create-task",
    "mem-h-unrelate-alice",
    "time-utc-tokyo-late",
    "time-h-now-dubai",
    "note-readme-summary",
    "note-h-write-src-notes",
)


class CatalogTest(unittest.TestCase):
    def test_thirty_tasks_per_server_with_the_pilot_split(self):
        catalog = stage2_tasks()
        self.assertEqual(len({task.id for task in catalog}), len(catalog))
        for server in SERVERS:
            splits = Counter(task.split for task in catalog if task.server == server)
            self.assertEqual(splits, Counter(train=17, heldout=13), server)

    def test_every_oracle_checks_something(self):
        for task in stage2_tasks():
            self.assertTrue(any(asdict(task.oracle).values()), task.id)
            self.assertTrue(task.calls, task.id)

    def test_prompts_state_every_value_and_name_no_tool(self):
        for task in stage2_tasks():
            prompt = stage2_prompt(task)
            self.assertEqual(prompt_gaps(task), [], task.id)
            self.assertTrue(prompt.endswith(" Stop when that is done."), task.id)
            for tool, _args in task.calls:
                if "_" in tool:
                    self.assertNotIn(tool, prompt, task.id)

    def test_ported_pilot_prompts_are_word_for_word(self):
        pilot = {task.id: task_prompt(task) for task in pilot_tasks(live_filesystem=True)}
        self.assertEqual(len(pilot), 25)
        for task_id, text in pilot.items():
            self.assertEqual(stage2_prompt(task_by_id(task_id)), text)
        message = stage2_message(task_by_id("git-status"), "/sandbox/proj")
        self.assertTrue(message.startswith("Project directory: /sandbox/proj\nShow the git status"))

    def test_stage2_pages_extend_the_pilot_map_only_in_stage2(self):
        self.assertIs(FetchServer("patched").pages, FETCH_PAGES)
        for url, body in FETCH_PAGES.items():
            self.assertEqual(STAGE2_PAGES[url], body)
        self.assertGreater(len(STAGE2_PAGES), len(FETCH_PAGES))

    def test_compatible_tasks_are_held_out_on_the_channel_server(self):
        servers = {"commit-message": "git", "memory-entity": "memory"}
        for channel, task_ids in PLANT_TASKS.items():
            for task_id in task_ids:
                task = task_by_id(task_id)
                self.assertEqual((task.split, task.server), ("heldout", servers[channel]))

    def test_case_list_keeps_the_pilot_cases_and_matches_the_budget(self):
        catalog = stage2_cases()
        ids = [case.id for case in catalog]
        self.assertEqual(len(set(ids)), len(ids))
        for case in pilot_cases():
            self.assertIn(case.id, ids)
        for channel in ("page", "repo-file", "description"):
            self.assertEqual([task.id for task in compatible_tasks(channel)], [task.id for task in pilot_compatible(channel)])
        self.assertEqual(CHANNELS, budget.STAGE2_CHANNELS)
        self.assertEqual(tuple(goal.id for goal in STAGE2_GOALS), budget.STAGE2_GOALS)
        self.assertEqual(len(catalog), budget.attack_cases(budget.SCENARIOS[1]))
        self.assertEqual(len({case.id for case in live_cases()}), 10)

    def test_each_channel_plants_in_one_place(self):
        def plant(channel, task_id):
            return case_plant(InjectionCase("", task_id, channel, "G1", "t"), "X")

        self.assertEqual(plant("page", "fetch-h-guide")["page_injections"], {"http://docs.example.test/guide": "X"})
        self.assertEqual(plant("repo-file", "fs-h-reread")["file_plant"], ("src/app.py", "X"))
        self.assertEqual(plant("commit-message", "git-h-log")["commit_plant"], "X")
        self.assertEqual(plant("memory-entity", "mem-h-read-graph")["memory_plant"], "X")
        self.assertEqual(plant("description", "fs-h-weekly")["poison_description"], "X")


class FreezeTest(unittest.TestCase):
    def test_an_open_slot_refuses_the_freeze_and_writes_nothing(self):
        self.assertEqual(set(freeze_slots()), set(_SLOTS))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "freeze"
            with self.assertRaisesRegex(ValueError, "open slots: scoring_template, layer_d_policy, recorded$"):
                write_freeze(out, {name: "" for name in _SLOTS})
            self.assertFalse(out.exists())
        with self.assertRaisesRegex(ValueError, "open slots: layer_d_policy$"):
            freeze_record({**_SLOTS, "layer_d_policy": None})

    def test_a_pilot_template_or_one_with_no_instruction_is_refused(self):
        for text in (TEMPLATE_TEXT, "No instruction here."):
            with self.assertRaises(ValueError):
                freeze_record({**_SLOTS, "scoring_template": text})

    def test_every_protocol_item_is_hashed(self):
        record = freeze_record(_SLOTS)
        expected = {"task_prompts", "task_oracles", "fixture", "goal_oracles", "templates", "cases", "host_prompt", "policy_prompt", "rule_r1", "zgscanner"}
        self.assertEqual(set(record["items"]), expected)
        self.assertEqual(record["oracle_sha256"], catalog_sha256())
        self.assertEqual(freeze_record(_SLOTS), record)
        other = freeze_record({**_SLOTS, "scoring_template": "Other text: {instruction}"})
        self.assertEqual([name for name in expected if other["items"][name] != record["items"][name]], ["templates"])
        self.assertNotEqual(other["sha256"], record["sha256"])
        self.assertEqual(freeze_record({**_SLOTS, "recorded": "2026-10-30"})["sha256"], record["sha256"])


class LiveOracleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp())
        cls.servers = Servers(make_fixture(cls.base / "clean"))

    @classmethod
    def tearDownClass(cls):
        cls.servers.close()
        _remove_tree(cls.base)

    def test_sample_oracles_are_sound(self):
        for task_id in _SAMPLE:
            row = check_task(self.servers, task_by_id(task_id))
            self.assertTrue(row["sound"], row)
            self.assertFalse(row["marker"], row)

    def test_a_wrong_or_empty_oracle_is_not_sound(self):
        vacuous = replace(task_by_id("note-read-csv"), oracle=Oracle(files=(("data/sample.csv", "ada"),)))
        self.assertTrue(check_task(self.servers, vacuous)["empty"])
        existing = replace(task_by_id("fs-h-mkdir-archive"), oracle=Oracle(dirs=("notes",)))
        self.assertTrue(check_task(self.servers, existing)["empty"])
        wrong = replace(task_by_id("mem-h-open-bob"), oracle=Oracle(texts=("tester",)))
        self.assertFalse(check_task(self.servers, wrong)["sound"])

    def test_goal_oracles_and_the_patched_server_refusals(self):
        rows = check_goals(self.servers)
        self.assertEqual(list(rows), [goal.id for goal in STAGE2_GOALS])
        for goal_id, row in rows.items():
            self.assertTrue(row["sound"], row)
            self.assertEqual(row["boundary_refused"], True if row["kind"] == "boundary" else None, row)


class ChannelPlantTest(unittest.TestCase):
    def test_plants_reach_the_compatible_tasks(self):
        base = Path(tempfile.mkdtemp())
        servers = Servers(make_fixture(base / "planted", commit_plant=REACH_MARKER, memory_plant=REACH_MARKER))
        try:
            for task_ids in PLANT_TASKS.values():
                for task_id in task_ids:
                    row = check_task(servers, task_by_id(task_id))
                    self.assertTrue(row["marker"], row)
                    self.assertTrue(row["sound"], row)
        finally:
            servers.close()
            _remove_tree(base)

    def test_a_file_plant_stays_once_across_resets(self):
        base = Path(tempfile.mkdtemp())
        try:
            for rel in ("src/app.py", "README.md"):
                fx = make_fixture(base / "fx", file_plant=(rel, REACH_MARKER))
                reset(fx)
                reset(fx)
                self.assertEqual((fx.repo / rel).read_text(encoding="utf-8").count(REACH_MARKER), 1, rel)
        finally:
            _remove_tree(base)


if __name__ == "__main__":
    unittest.main()
