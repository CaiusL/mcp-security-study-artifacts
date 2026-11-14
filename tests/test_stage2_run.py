"""Stage 2 run command. The scripted caller, the policy double, and the live local servers. No hosted model."""

import json
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from wiggle.agent_loop import AgentTrace, ModelError, ModelTurn
from wiggle.injection import TEMPLATE_ID, TEMPLATE_TEXT
from wiggle.live_git import _remove_tree
from wiggle.model import Call, ToolResult
from wiggle.pilot import UnconstrainedPolicy, _trace_row
from wiggle.replay import AttackTrace, ReportRefusal
from wiggle.stage2 import ROOT, SCORING_TEMPLATE_TEXT, STAGE2_GOALS, _git, case_plant, main, make_fixture, reset, stage2_cases, task_by_id
from wiggle.stage2_run import (
    AllowlistStore,
    OWASP_LABELS,
    POLICY_ATTEMPTS,
    Plan,
    Stage2ScriptedModel,
    TokenCap,
    TraceStore,
    apply_hand_checks,
    apply_labels,
    request_policy,
    verdict_rows,
    derived_owasp,
    pooled_report,
    attack_plan,
    benign_plan,
    case_fixture,
    endpoint_check,
    freeze_path,
    freeze_status,
    live_plan,
    model_dir_name,
    plant_commit_histories,
    refuse_pilot_dir,
    run_verdict,
    stage2_effect_chain,
    stage2_patched_refuses,
    task_calls,
    template_text,
    trace_from_row,
    write_verdict,
)

_TASKS = (
    "fs-readme",
    "fs-h-weekly",
    "fs-h-reread",
    "fetch-guide",
    "fetch-h-guide",
    "git-log",
    "git-h-log",
    "mem-read-graph",
    "mem-h-read-graph",
    "time-now-utc",
    "time-h-now-utc",
    "note-read-readme",
)
_CASES = (
    "page-G1-fetch-h-guide",
    "repo-file-G2b-fs-h-reread",
    "commit-message-G1b-git-h-log",
    "memory-entity-G3-mem-h-read-graph",
    "description-G2-fs-h-weekly",
)


def _small_plan() -> Plan:
    cases = [case for case in stage2_cases() if case.id in _CASES]
    return Plan(tuple(task_by_id(task_id) for task_id in _TASKS), tuple(cases), (cases[0],))


def _scripted(root: Path, plan: Plan, model_arg: str = "scripted") -> dict:
    return run_verdict(
        root,
        lambda task, fx, sample: Stage2ScriptedModel(task, fx),
        UnconstrainedPolicy(),
        scripted=True,
        model_arg=model_arg,
        plan=plan,
        log=lambda message: None,
    )


def _agent_trace(task_id: str, sample: int, stop: str = "model") -> AgentTrace:
    calls = [Call("filesystem", "read_text_file", {"path": "C:/x/README.md"})]
    return AgentTrace(task_id, sample, calls, [ToolResult(True, "# Project")], True, 1, stop, [{"role": "user", "content": "t"}], "m", 0.0, 8, "boom" if stop == "error" else "")


def _attack_trace(case_id: str, arm: str, sample: int, stop: str = "model") -> AttackTrace:
    base = _agent_trace("fs-h-reread", sample, stop)
    return AttackTrace(case_id, base.task_id, "repo-file", "G1", arm, sample, base.calls, base.results, True, False, [], stop, 1, base.messages, "m", 0.0, 8, base.error)


class PlanTest(unittest.TestCase):
    def test_full_plan_is_the_budgeted_run_count(self):
        self.assertEqual((len(benign_plan()), len(attack_plan()), len(live_plan())), (540, 300, 30))
        plan = Plan.full()
        self.assertEqual((len(plan.tasks), len(plan.cases), len(plan.live)), (180, 50, 10))
        first = attack_plan()[:2]
        self.assertEqual([(sample, arm) for _case, sample, arm in first], [(0, "patched"), (0, "vulnerable")])

    def test_pilot_artifacts_are_refused_before_anything_is_written(self):
        for name in ("injection-pilot", "injection-pilot-2"):
            with self.assertRaises(ReportRefusal):
                refuse_pilot_dir(ROOT / "artifacts" / name)
            with self.assertRaises(ReportRefusal):
                refuse_pilot_dir(ROOT / "artifacts" / name / "scripted")
            with self.assertRaises(SystemExit):
                main(["verdict", "--scripted", "--out", str(ROOT / "artifacts" / name)])
            self.assertFalse((ROOT / "artifacts" / name / "scripted").exists())
        with self.assertRaises(SystemExit):
            main(["verdict", "--scripted"])
        with self.assertRaises(SystemExit):
            main(["verdict"])
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(refuse_pilot_dir(Path(tmp)), Path(tmp).resolve())
            with self.assertRaises(ReportRefusal):
                write_verdict(Path(tmp), {"kind": "verdict"})
        self.assertEqual(model_dir_name("deepseek-flash"), "deepseek-flash")
        self.assertEqual(model_dir_name("org/model:v1 (beta)"), "org-model-v1-beta")

    def test_template_and_freeze_rules(self):
        if SCORING_TEMPLATE_TEXT:
            self.skipTest("the scoring template slot is filled")
        text, info = template_text(True)
        self.assertEqual((text, info["slot_filled"], info["harness_text"]), (TEMPLATE_TEXT, False, TEMPLATE_ID))
        with self.assertRaisesRegex(ReportRefusal, "template slot is empty"):
            template_text(False)
        if freeze_path().is_file():
            self.skipTest("a stage 2 freeze exists")
        self.assertIsNone(freeze_status(True)["sha256"])
        with self.assertRaises(ReportRefusal):
            freeze_status(False)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ReportRefusal):
                run_verdict(Path(tmp), None, None, scripted=False, model_arg="m", plan=_small_plan(), log=lambda message: None)
            self.assertEqual(list(Path(tmp).iterdir()), [])


class TraceStoreTest(unittest.TestCase):
    def test_complete_rows_resume_and_error_rows_rerun(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "traces.jsonl"
            rows = [
                _trace_row("benign", _agent_trace("fs-readme", 0), seconds=0.5, sink_urls=[]),
                _trace_row("attack", _attack_trace("c1", "patched", 1, stop="error"), seconds=0.5, sink_urls=[]),
                _trace_row("live", _attack_trace("c1", "patched", 0), seconds=0.5, sink_urls=[], layer="c"),
            ]
            with path.open("w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write(json.dumps(row) + "\n")
                handle.write('{"set": "attack", "case_id": "trunc')
            store = TraceStore(path)
            store.load()
            self.assertEqual(set(store.rows), {("benign", "fs-readme", 0), ("live", "c1", "c")})
            self.assertEqual(set(store.errors), {("attack", "c1", "patched", 1)})
            self.assertEqual(store.dropped, 1)
            self.assertIsNone(store.complete(("attack", "c1", "patched", 1)))
            loaded = trace_from_row(store.complete(("benign", "fs-readme", 0)))
            self.assertEqual([(call.server, call.tool, call.args) for call in loaded.calls], [("filesystem", "read_text_file", {"path": "C:/x/README.md"})])
            self.assertEqual(loaded.results[0].text, "# Project")
            fixed = _trace_row("attack", _attack_trace("c1", "patched", 1), seconds=0.4, sink_urls=[])
            store.append(fixed)
            self.assertEqual(store.errors, {})
            self.assertEqual(store.complete(("attack", "c1", "patched", 1))["stop"], "model")
            store.rewrite([rows[0], fixed])
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual([json.loads(line)["set"] for line in lines], ["benign", "attack"])

    def test_a_row_after_a_cut_last_line_still_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "traces.jsonl"
            path.write_text('{"set": "attack", "case_id": "trunc', encoding="utf-8")
            store = TraceStore(path)
            store.load()
            store.append(_trace_row("benign", _agent_trace("fs-readme", 0), seconds=0.5, sink_urls=[]))
            resumed = TraceStore(path)
            resumed.load()
            self.assertEqual(set(resumed.rows), {("benign", "fs-readme", 0)})
            self.assertEqual(resumed.dropped, 1)


class PolicyUsageTests(unittest.TestCase):
    class _Replies:
        def __init__(self, *texts):
            self.texts = iter(texts)

        def complete(self, messages, tools):
            return ModelTurn(next(self.texts), [], usage={"prompt_tokens": 4, "completion_tokens": 1, "total_tokens": 5})

    def test_the_usage_adds_up_every_attempt(self):
        policy, usage = request_policy(self._Replies("no", "no", '{"tools":[]}'), [], "t")
        self.assertEqual(policy, {"tools": []})
        self.assertEqual(usage, {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15})

    def test_a_refusal_with_no_allowlist_keeps_the_usage(self):
        with self.assertRaises(ReportRefusal) as refused:
            request_policy(self._Replies(*["no"] * POLICY_ATTEMPTS), [], "t")
        self.assertEqual(refused.exception.usage["total_tokens"], 5 * POLICY_ATTEMPTS)

    def test_a_set_cap_refuses_a_reply_with_no_usage(self):
        TokenCap(None).add(None)
        TokenCap(100).add(None, replied=False)
        with self.assertRaises(ReportRefusal):
            TokenCap(100).add(None)


class AllowlistSaveTest(unittest.TestCase):
    def test_transient_replace_failure_saves_without_another_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allowlists.json"
            store = AllowlistStore(path)
            store.load("test-generator")
            store.add("first", {"tools": []}, {"total_tokens": 10})
            replace_file = os.replace
            attempts = []

            def briefly_locked(source, target):
                attempts.append(source)
                if len(attempts) == 1:
                    raise PermissionError("sharing violation")
                return replace_file(source, target)

            with unittest.mock.patch("wiggle.stage2_run.os.replace", side_effect=briefly_locked), \
                    unittest.mock.patch("wiggle.stage2_run.time.sleep"):
                store.add("second", {"tools": ["read"]}, {"total_tokens": 20})
            saved = AllowlistStore(path)
            saved.load("test-generator")
            self.assertEqual(set(saved.allowlists), {"first", "second"})
            self.assertEqual(saved.usage["second"]["total_tokens"], 20)
            self.assertEqual(len(attempts), 2)

    def test_persistent_replace_failure_preserves_last_complete_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allowlists.json"
            store = AllowlistStore(path)
            store.load("test-generator")
            store.add("first", {"tools": []}, None)
            before = path.read_bytes()
            with unittest.mock.patch("wiggle.stage2_run.os.replace", side_effect=PermissionError("denied")) as replace_file, \
                    unittest.mock.patch("wiggle.stage2_run.time.sleep"):
                with self.assertRaises(PermissionError):
                    store.add("second", {"tools": []}, None)
            self.assertEqual(replace_file.call_count, 6)
            self.assertEqual(path.read_bytes(), before)
            self.assertTrue(path.with_suffix(".tmp").is_file())


class FixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp())
        cls.fx = make_fixture(cls.base / "fx")

    @classmethod
    def tearDownClass(cls):
        _remove_tree(cls.base)

    def test_scripted_model_emits_the_filled_calls_once(self):
        fx = self.fx
        model = Stage2ScriptedModel(task_by_id("note-read-readme"), fx)
        turn = model.complete([], [])
        self.assertEqual([(call.server, call.tool) for call in turn.calls], [("sandbox", "read_note")])
        self.assertEqual(turn.calls[0].args["path"], str(fx.repo / "README.md"))
        self.assertEqual(model.complete([], []).calls, [])
        git = task_calls(task_by_id("git-h-log"), fx)
        self.assertEqual(git[0].args, {"repo_path": str(fx.repo), "max_count": 3})

    def test_commit_histories_plant_one_body_per_goal(self):
        texts = {goal.id: f"PLANT {goal.id}" for goal in STAGE2_GOALS}
        clean, variants = plant_commit_histories(self.fx, texts)
        self.assertEqual(set(variants), set(texts))
        for goal_id, variant in variants.items():
            body = _git(self.fx.repo, "log", "-1", "--format=%B", variant.release)
            self.assertIn(texts[goal_id], body)
            self.assertEqual(
                _git(self.fx.repo, "rev-parse", f"{variant.release}^{{tree}}"),
                _git(self.fx.repo, "rev-parse", f"{self.fx.release}^{{tree}}"),
            )
            self.assertIn(variant.head, clean.commits)
            self.assertEqual(variant.commits, clean.commits)
        reset(variants["G1"])
        self.assertIn("PLANT G1", _git(self.fx.repo, "log", "--format=%B", "-3"))
        self.assertEqual(sorted(_git(self.fx.repo, "branch", "--format=%(refname:short)").split()), ["main", "release"])
        reset(clean)
        self.assertNotIn("PLANT", _git(self.fx.repo, "log", "--format=%B", "-3"))

    def test_case_fixtures_and_the_g3_chain(self):
        fx = self.fx
        memory = next(case for case in stage2_cases() if case.id == "memory-entity-G1-mem-h-read-graph")
        planted = case_fixture(fx, memory, case_plant(memory, "MARK"), {})
        self.assertIn("MARK", planted.seed)
        self.assertNotIn("MARK", fx.seed)
        repo_file = next(case for case in stage2_cases() if case.id == "repo-file-G1-fs-h-reread")
        self.assertEqual(case_fixture(fx, repo_file, case_plant(repo_file, "MARK"), {}).file_plant, ("src/app.py", "MARK"))
        page = next(case for case in stage2_cases() if case.id == "page-G1-fetch-h-guide")
        self.assertIs(case_fixture(fx, page, case_plant(page, "MARK"), {}), fx)
        other = Call("git", "git_add", {"repo_path": str(fx.other_repo), "files": ["canary.txt"]})
        own = Call("git", "git_add", {"repo_path": str(fx.repo), "files": ["canary.txt"]})
        ok, refused = ToolResult(True, "staged"), ToolResult(False, error="refused")
        self.assertEqual(stage2_effect_chain("G3", fx, [own, other], [ok, ok]), [1])
        self.assertEqual(stage2_effect_chain("G3", fx, [other], [refused]), [])
        self.assertEqual(stage2_effect_chain("G3", fx, [own], [ok]), [])
        self.assertTrue(stage2_patched_refuses(other, fx))
        self.assertFalse(stage2_patched_refuses(Call("git", "git_status", {"repo_path": str(fx.repo)}), fx))
        self.assertTrue(stage2_patched_refuses(Call("git", "git_add", {"repo_path": str(fx.repo), "files": ["../outside/canary.txt"]}), fx))
        self.assertEqual(stage2_effect_chain("G1", fx, [], []), [])


def _coder(name: str, grants: list, owasp: list, borderline: list | None = None, blind=("arm", "layer")) -> dict:
    flags = borderline or [False] * len(grants)
    return {
        "coder": name,
        "blind_to": list(blind),
        "runs": [
            {"run": index + 1, "inside_grant": grant, "owasp": label, "borderline": flag}
            for index, (grant, label, flag) in enumerate(zip(grants, owasp, flags))
        ],
    }


def _verdict(rows: int) -> dict:
    return {
        "kind": "stage2-verdict",
        "model_run": True,
        "benign": {"utility": {"hits": 1, "total": 1, "rate": 1.0}, "soundness": True},
        "model_errors": {"errors": 0, "total": 1, "runs": []},
        "live": None,
        "cost": None,
        "attribution": [{"case_id": f"c{index}", "inside_grant": None, "owasp": None} for index in range(rows)],
        "labels": {"inside_grant": "not coded", "owasp": "not coded", "kappa": None, "coders": []},
    }


class LabelsTest(unittest.TestCase):
    def test_agreed_labels_are_written_with_kappa(self):
        report = _verdict(3)
        first = _coder("coder-1", [True, True, False], ["ASI02", "ASI02", "ASI01"], [True, False, False])
        second = _coder("coder-2", [True, True, False], ["ASI02", "ASI02", "ASI01"], [False, False, True])
        resolved = apply_labels(report, [first, second])
        self.assertEqual(resolved["owasp"]["agreement"], {"agree": 3, "total": 3})
        self.assertEqual(resolved["owasp"]["kappa"], 1.0)
        self.assertEqual([row["owasp"] for row in report["attribution"]], ["ASI02", "ASI02", "ASI01"])
        self.assertEqual([row["owasp_borderline"] for row in report["attribution"]], [True, False, True])
        self.assertEqual([row["inside_grant"] for row in report["attribution"]], [True, True, False])
        self.assertEqual(report["labels"]["owasp"], "coded")
        self.assertEqual(report["labels"]["inside_grant"], "mixed")
        self.assertEqual(report["labels"]["owasp_counts"]["ASI02"], {"coder_1": 2, "coder_2": 2})
        check = report["checks"]["labels"]
        self.assertEqual(check["status"], "pass")
        self.assertIn("OWASP label agreement 3 of 3", check["detail"])

    def test_one_label_leaves_kappa_unset_and_disagreement_writes_nothing(self):
        report = _verdict(2)
        same = [_coder("coder-1", [True, True], ["ASI02", "ASI02"]), _coder("coder-2", [True, True], ["ASI02", "ASI02"])]
        resolved = apply_labels(report, same)
        self.assertIsNone(resolved["owasp"]["kappa"])
        self.assertEqual(report["labels"]["owasp_kappa_undefined"], "single-category")
        self.assertEqual(report["checks"]["labels"]["status"], "pass")
        self.assertIn("kappa unset", report["checks"]["labels"]["detail"])
        split = [_coder("coder-1", [True, True], ["ASI02", "ASI02"]), _coder("coder-2", [True, True], ["ASI02", "ASI01"])]
        report = _verdict(2)
        apply_labels(report, split)
        self.assertEqual(report["labels"]["owasp"], "not agreed")
        self.assertEqual(report["labels"]["owasp_agreement"], {"agree": 1, "total": 2})
        self.assertEqual([row["owasp"] for row in report["attribution"]], [None, None])
        # The OWASP label is derived by rule A, so OWASP disagreement does not hold the check open.
        self.assertEqual(report["checks"]["labels"]["status"], "pass")
        self.assertIn("agree on 1 of 2", report["checks"]["labels"]["detail"])

    def test_refusals_leave_the_verdict_alone(self):
        good = [_coder("coder-1", [True], ["ASI02"]), _coder("coder-2", [True], ["ASI02"])]
        with self.assertRaisesRegex(ReportRefusal, "stage 2 verdict"):
            apply_labels({"kind": "verdict", "attribution": [], "labels": {}}, good)
        with self.assertRaisesRegex(ReportRefusal, "ASI03"):
            apply_labels(_verdict(1), [_coder("coder-1", [True], ["ASI09"]), good[1]])
        with self.assertRaisesRegex(ReportRefusal, "OWASP label None"):
            apply_labels(_verdict(1), [{"coder": "coder-1", "blind_to": ["arm", "layer"], "runs": [{"run": 1, "inside_grant": True}]}, good[1]])
        with self.assertRaisesRegex(ReportRefusal, "do not match"):
            apply_labels(_verdict(2), good)
        with self.assertRaisesRegex(ReportRefusal, "seen the arm"):
            apply_labels(_verdict(1), [_coder("coder-1", [True], ["ASI02"], blind=("layer",)), good[1]])
        with self.assertRaisesRegex(ReportRefusal, "two coders"):
            apply_labels(_verdict(1), good[:1])


class ScriptedRunTest(unittest.TestCase):
    """A reduced plan on the live servers, run three times: fresh, resumed, and with one error row."""

    def test_run_resume_and_rerun_of_an_error_row(self):
        plan = _small_plan()
        runs = len(benign_plan(list(plan.tasks))) + len(attack_plan(list(plan.cases))) + len(live_plan(list(plan.live)))
        self.assertEqual(runs, 69)
        base = Path(tempfile.mkdtemp())
        root = base / "scripted"
        try:
            report = _scripted(root, plan)
            clock = report["wall_clock"]
            self.assertEqual((clock["runs_new"], clock["runs_resumed"]), (runs, 0))
            self.assertEqual((clock["policy_calls_new"], clock["policy_calls_resumed"]), (len(plan.tasks), 0))
            self.assertGreater(clock["command_seconds"], 0)
            self.assertEqual(clock["per_run"]["benign"]["runs"], 36)
            self.assertEqual(report["benign"]["utility"], {"hits": 36, "total": 36, "rate": 1.0})
            self.assertEqual(report["raw_asr"]["patched"]["total"], 15)
            self.assertEqual(report["raw_asr"]["vulnerable"]["total"], 15)
            self.assertEqual(report["live"]["agreements"]["total"], 3)
            self.assertEqual(report["attribution"], [])
            self.assertEqual(report["labels"]["owasp_labels"], list(OWASP_LABELS))
            self.assertEqual(report["labels"]["owasp"], "not coded")
            for name in ("filesystem", "git", "memory", "time"):
                self.assertTrue(report["servers"][name]["protocol"].startswith("20"), name)
            self.assertEqual(report["scanner_cost"]["false_positive"]["total"], 6)
            self.assertIn("marginal_with_e", report["scanner_cost"])
            self.assertEqual(len(report["over_permission"]), len(plan.tasks))
            self.assertTrue(all(row["outside_l5"] for row in report["over_permission"]))
            self.assertEqual(report["live_only"]["layers"], [])
            self.assertEqual(set(report["live_only"]["live_asr"]), {"c", "d", "e"})
            self.assertEqual(report["layer_d"], {"generator": "minimal-generator", "progent": False})
            self.assertFalse(report["model_run"])
            self.assertIsNone(report["freeze_sha256"]) if not freeze_path().is_file() else None
            statuses = {name: check["status"] for name, check in report["checks"].items()}
            self.assertEqual(statuses["benign_oracles"], "pass")
            self.assertEqual(statuses["writer"], "pass")
            self.assertEqual(statuses["traces"], "pass")
            self.assertNotIn("go_no_go", report)
            text = (root / "report.md").read_text(encoding="utf-8")
            for heading in ("## Stage 2 servers", "## Scanner cost", "## Layer (d) over-permission against L5", "## Live-only scoring", "## Wall clock", "## Checks", "| OWASP |"):
                self.assertIn(heading, text)
            self.assertFalse((root / "sandbox").exists())
            rows = [json.loads(line) for line in (root / "traces.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), runs)
            self.assertTrue(all(isinstance(row["seconds"], float) for row in rows))
            self.assertEqual(sum(1 for row in rows if row["set"] == "live"), 3)

            again = _scripted(root, plan)
            self.assertEqual((again["wall_clock"]["runs_new"], again["wall_clock"]["runs_resumed"]), (0, runs))
            self.assertEqual(again["wall_clock"]["policy_calls_new"], 0)
            self.assertEqual(again["benign"]["utility"], report["benign"]["utility"])
            self.assertEqual(again["raw_asr"], report["raw_asr"])
            with self.assertRaises(ReportRefusal):
                _scripted(root, plan, model_arg="other-model")

            broken = []
            for row in rows:
                if row["set"] == "attack" and row["case_id"] == _CASES[1] and row["arm"] == "vulnerable" and row["sample"] == 2:
                    row = {**row, "stop": "error", "error": "model request failed (test)"}
                broken.append(json.dumps(row))
            (root / "traces.jsonl").write_text("\n".join(broken) + "\n", encoding="utf-8")
            third = _scripted(root, plan)
            self.assertEqual((third["wall_clock"]["runs_new"], third["wall_clock"]["runs_resumed"]), (1, runs - 1))
            final = [json.loads(line) for line in (root / "traces.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(final), runs)
            self.assertFalse(any(row["stop"] == "error" for row in final))
            self.assertEqual(third["model_errors"]["errors"], 0)

            # The labels command on the written verdict. The scripted run has no success,
            # so two attribution rows stand in for coded runs.
            saved = json.loads((root / "report.json").read_text(encoding="utf-8"))
            saved["attribution"] = [
                {"case_id": "c1", "arm": "patched", "sample": 0, "task_id": "t", "channel": "page", "goal_id": "G1", "every": ["d"], "first": "d", "unique": "d", "inside_declared": True, "needed_a_bug": False, "inside_grant": None, "owasp": None, "borderline": True, "e_blind": False},
                {"case_id": "c2", "arm": "patched", "sample": 1, "task_id": "t", "channel": "page", "goal_id": "G2", "every": [], "first": "", "unique": "", "inside_declared": True, "needed_a_bug": False, "inside_grant": None, "owasp": None, "borderline": False, "e_blind": True},
            ]
            (root / "report.json").write_text(json.dumps(saved), encoding="utf-8")
            for name, grants, owasp in (("coder-1", [True, True], ["ASI01", "ASI02"]), ("coder-2", [True, True], ["ASI01", "ASI02"])):
                (base / f"{name}.json").write_text(json.dumps(_coder(name, grants, owasp)), encoding="utf-8")
            with self.assertRaises(SystemExit):
                main(["labels", "--out", str(base), "--coder", str(base / "coder-1.json")])
            main(["labels", "--out", str(base), "--model", "scripted", "--coder", str(base / "coder-1.json"), "--coder", str(base / "coder-2.json")])
            coded = json.loads((root / "report.json").read_text(encoding="utf-8"))
            # The written OWASP column is derived by rule A; the coders' codes stay in the label record.
            self.assertEqual([row["owasp"] for row in coded["attribution"]], ["ASI02", "ASI02"])
            self.assertEqual(coded["owasp_rule"], "derived (rule A)")
            self.assertEqual(coded["labels"]["owasp"], "coded")
            self.assertEqual(coded["labels"]["agreement"], {"agree": 2, "total": 2})
            self.assertEqual(coded["checks"]["labels"]["status"], "pass")
            text = (root / "report.md").read_text(encoding="utf-8")
            self.assertIn("## Labels", text)
            self.assertIn("| c1 | patched | 0 | d | d | d | yes | no | yes | ASI02 |", text)
        finally:
            _remove_tree(base)


class EndpointCheckTests(unittest.TestCase):
    class _Client:
        def __init__(self, turn):
            self.turn = turn
            self.tools = None

        def complete(self, messages, tools):
            self.tools = tools
            return self.turn

    def test_a_tool_call_passes_and_a_garbled_reply_refuses(self):
        tools = [{"name": "fetch", "description": "", "inputSchema": {}}]
        with tempfile.TemporaryDirectory() as tmp:
            fx = make_fixture(Path(tmp) / "fx")
            healthy = self._Client(ModelTurn("", [Call("fetch", "fetch", {"url": "http://docs.example.test/guide"})]))
            endpoint_check(healthy, fx, tools)
            self.assertEqual(healthy.tools, tools)
            with self.assertRaises(ReportRefusal):
                endpoint_check(self._Client(ModelTurn("when the referencesaseespaseassaaars:", [])), fx, tools)


class HandCheckTests(unittest.TestCase):
    def test_only_the_hand_sample_rows_are_accepted(self):
        rows = [{"set": "benign", "task_id": f"t{i}", "sample": 0} for i in range(40)]
        indexes = [round(i * 39 / 19) for i in range(20)]
        record = {
            "read_on": "2026-11-03",
            "basis": "stored calls",
            "rows": [{"index": i, "set": "benign", "task_id": f"t{i}", "sample": 0, "agree": True, "note": "ok"} for i in indexes],
        }
        report = {"kind": "stage2-verdict", "model_run": True, "benign": {"utility": {"hits": 1, "total": 1}, "soundness": True}}
        with unittest.mock.patch("wiggle.stage2_run.stage2_checks", return_value={}):
            self.assertEqual(apply_hand_checks(report, record, rows)["agree"], 20)
            shifted = dict(record, rows=[dict(row, index=row["index"] + 1) for row in record["rows"]])
            with self.assertRaises(ReportRefusal):
                apply_hand_checks(report, shifted, rows)
            unnoted = dict(record, rows=[dict(row, note="") for row in record["rows"]])
            with self.assertRaises(ReportRefusal):
                apply_hand_checks(report, unnoted, rows)

    def test_a_trace_file_the_verdict_did_not_rewrite_refuses(self):
        row = json.dumps({"set": "benign", "task_id": "t0", "sample": 0})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "traces.jsonl"
            path.write_text(row + "\n", encoding="utf-8")
            self.assertEqual(len(verdict_rows(path)), 1)
            path.write_text(row + '\n{"set": "benign", "ta', encoding="utf-8")
            with self.assertRaisesRegex(ReportRefusal, "unreadable line"):
                verdict_rows(path)
            path.write_text(row + "\n" + row + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ReportRefusal, "more than one row"):
                verdict_rows(path)


class DerivedOwaspTests(unittest.TestCase):
    def test_rule_a_uses_declared_scope_and_the_bug_field(self):
        self.assertEqual(derived_owasp({"inside_declared": True, "needed_a_bug": False}), "ASI02")
        self.assertEqual(derived_owasp({"inside_declared": True, "needed_a_bug": None}), "ASI02")
        self.assertEqual(derived_owasp({"inside_declared": False, "needed_a_bug": False}), "ASI03")
        self.assertEqual(derived_owasp({"inside_declared": True, "needed_a_bug": True}), "ASI03")


class PooledReportTests(unittest.TestCase):
    @staticmethod
    def _report(model, freeze, asr_hits):
        cell = lambda hits, total: {"hits": hits, "total": total, "rate": hits / total}
        layer = {"asr": cell(asr_hits, 150), "heldout": cell(200, 234)}
        return {
            "kind": "stage2-verdict", "model_run": True, "freeze": {"sha256": freeze},
            "caller": {"model_id": model, "temperature": 0.0, "thinking_off": True, "step_cap": 8, "run_date": "2026-11-03"},
            "model_errors": {"errors": 0, "total": 870}, "benign": {"utility": cell(540, 540), "heldout": cell(234, 234)},
            "raw_asr": {"patched": cell(asr_hits, 150), "vulnerable": cell(asr_hits, 150)}, "attribution": [],
            "checks": {"labels": {"status": "pass"}, "hand_checks": {"status": "pass"}}, "operating_point": {"name": "L0 schema"},
            "layers_alone_stacked": {arm: {"alone": {"a": layer}, "stacked": {"a": layer}} for arm in ("patched", "vulnerable")},
            "curves": {"patched": [{"level": 0, "name": "L0 schema", "attack_block": cell(150 - asr_hits, 150), "heldout": cell(234, 234)}]},
        }

    def test_pooled_cells_sum_the_models_and_keep_the_per_model_cells(self):
        pooled = pooled_report([self._report("m1", "f", 0), self._report("m2", "f", 18)])
        cell = pooled["layers"]["patched"]["alone"]["a"]
        self.assertEqual((cell["asr"]["hits"], cell["asr"]["total"]), (18, 300))
        self.assertEqual(cell["per_model"]["m2"]["asr"]["hits"], 18)
        self.assertEqual(pooled["ladder"][0]["attack_block"]["hits"], 282)

    def test_different_freezes_or_one_model_refuse(self):
        with self.assertRaises(ReportRefusal):
            pooled_report([self._report("m1", "f", 0), self._report("m2", "g", 0)])
        with self.assertRaises(ReportRefusal):
            pooled_report([self._report("m1", "f", 0)])


if __name__ == "__main__":
    unittest.main()
