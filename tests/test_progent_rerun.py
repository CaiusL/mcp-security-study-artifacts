"""Progent layer (d) rerun (docs/execution-plan.md, Phase 2), model-free.

The flags, the Progent freeze and the source checks run on temp files. The
rerun itself runs on the live local servers, with the scripted caller as the
agent and a policy double that returns one fixed Progent policy. No hosted
model is called, and nothing is written outside temp dirs.
"""

import json
import tempfile
import types
import unittest
import unittest.mock
from pathlib import Path

from wiggle import progent
from wiggle.agent_loop import ModelTurn
from wiggle.live_git import _remove_tree
from wiggle.model import Call
from wiggle.pilot import UnconstrainedPolicy
from wiggle.replay import ReportRefusal
from wiggle.stage2 import ROOT, freeze_record, main, stage2_cases, task_by_id, write_progent_freeze
from wiggle.stage2_run import (
    PROGENT_APART,
    PROGENT_OVER_PERMISSION,
    Plan,
    ProgentBudget,
    ProgentGenerator,
    Stage2ScriptedModel,
    TokenCapReached,
    TraceStore,
    _row_key,
    _run_record,
    copy_rows,
    freeze_path,
    over_permission_rows,
    run_progent_verdict,
    run_verdict,
    stage2_tool_list,
)

STAGE2_FREEZE = "bbaecb1a727b28167580f6f64cf458055f3e084e2b06ddd0950a5d39a5cc0cbd"
# Freeze records that no command here may change.
KEPT = (freeze_path(), ROOT / "artifacts" / "injection-pilot" / "freeze.json", ROOT / "artifacts" / "injection-pilot-2" / "freeze.json")


def _kept() -> list[bytes]:
    return [path.read_bytes() for path in KEPT]


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _files(folder: Path) -> dict[str, bytes]:
    return {path.relative_to(folder).as_posix(): path.read_bytes() for path in sorted(folder.rglob("*")) if path.is_file()}


class FlagTests(unittest.TestCase):
    def test_the_default_freeze_and_verdict_paths_are_unchanged(self):
        self.assertEqual(freeze_record()["sha256"], STAGE2_FREEZE)
        saved = json.loads(freeze_path().read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            for argv in (["freeze"], ["freeze", "--layer-d", "minimal"]):
                out = Path(tmp) / argv[-1]
                main([*argv, "--out", str(out)])
                self.assertEqual(json.loads((out / "freeze.json").read_text(encoding="utf-8")), saved)
            with unittest.mock.patch("wiggle.stage2_run.run_verdict", side_effect=ReportRefusal("stop")) as fake:
                with self.assertRaises(SystemExit):
                    main(["verdict", "--scripted", "--out", str(Path(tmp) / "verdict")])
                options = fake.call_args.kwargs
                with self.assertRaises(SystemExit):
                    main(["verdict", "--scripted", "--token-cap", "5", "--out", str(Path(tmp) / "verdict")])
        self.assertIsNone(options["token_cap"])
        self.assertEqual(fake.call_args.kwargs["token_cap"], 5)
        for name in ("generator", "freeze", "sandbox", "progent", "source_tools"):
            self.assertNotIn(name, options)

    def test_run_json_pins_the_progent_freeze_and_the_default_record_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / "plain"
            _run_record(plain, "m", False, plain / "sandbox")
            self.assertEqual(list(json.loads((plain / "run.json").read_text(encoding="utf-8"))), ["model", "scripted", "sandbox", "started"])
            root = Path(tmp) / "progent"
            _run_record(root, "m", False, root / "sandbox", {"progent_freeze_sha256": "a" * 64})
            with self.assertRaisesRegex(ReportRefusal, "progent_freeze_sha256"):
                _run_record(root, "m", False, root / "sandbox", {"progent_freeze_sha256": "b" * 64})
            # run_verdict's own call names no pin, so it keeps the pinned record.
            self.assertEqual(_run_record(root, "m", False, root / "sandbox")["progent_freeze_sha256"], "a" * 64)

    def test_flag_values_are_checked_before_anything_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                main(["verdict", "--layer-d", "full", "--out", tmp])
            with self.assertRaisesRegex(SystemExit, "no --scripted check"):
                main(["verdict", "--layer-d", "progent", "--scripted", "--out", tmp])
            with self.assertRaisesRegex(SystemExit, "positive"):
                main(["verdict", "--scripted", "--token-cap", "0", "--out", tmp])
            self.assertEqual(list(Path(tmp).iterdir()), [])


class OverPermissionTests(unittest.TestCase):
    def test_a_progent_allowlist_counts_at_tool_level_only(self):
        # fetch-guide fetches the docs host. The Progent policy restricts fetch to it, and allows a time tool too.
        policy = {
            "fetch": [[100, 0, {"url": {"type": "string", "pattern": "^http://docs\\.example\\.test/"}}, 0]],
            "get_current_time": [[100, 0, {"timezone": {"type": "string", "enum": ["Europe/London"]}}, 0]],
        }
        names = [{"name": "fetch"}, {"name": "get_current_time"}]
        fx = types.SimpleNamespace(repo=Path("proj"))
        [row] = over_permission_rows({"fetch-guide": {"progent": policy, "tools": names}}, fx)
        self.assertEqual((row["outside_l5"], row["outside_task_calls"]), (["tool:get_current_time"], ["tool:get_current_time"]))
        # The same names in a minimal-generator allowlist are unconstrained tools.
        [row] = over_permission_rows({"fetch-guide": {"tools": names}}, fx)
        self.assertEqual(row["outside_l5"], ["fetch.*", "tool:get_current_time"])


class BudgetTests(unittest.TestCase):
    def test_phase_cap_survives_resume_and_counts_both_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "qwen"
            second = Path(tmp) / "deepseek"
            policy = _PolicyDouble()
            ProgentBudget(first, 200).client(policy, "policy").complete([], [])
            resumed = ProgentBudget(first, 200)
            self.assertEqual(resumed.spent, 100)
            ProgentBudget(second, 200).client(policy, "policy").complete([], [])
            for root in (first, second):
                budget = ProgentBudget(root, 200)
                with self.assertRaises(TokenCapReached):
                    budget.client(policy, "policy").complete([], [])
                self.assertEqual((budget.spent, budget.model_spent), (200, 100))
            self.assertEqual(len(policy.requests), 2)

    def test_first_ten_policy_requests_stop_at_twice_the_estimate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "qwen"
            reply = types.SimpleNamespace(complete=lambda messages, tools: ModelTurn("[]", [], usage={"total_tokens": 11001}))
            budget = ProgentBudget(root, None)
            client = budget.client(reply, "policy")
            for _ in range(10):
                client.complete([], [])
            for budget in (budget, ProgentBudget(root, None)):
                with self.assertRaisesRegex(ReportRefusal, "first 10.*11,001.0"):
                    budget.client(reply, "policy").complete([], [])
                self.assertEqual(len(budget.policy_tokens), 10)

    def test_missing_or_zero_usage_refuses_now_and_after_resume(self):
        for usage in (None, {"total_tokens": 0}):
            with self.subTest(usage=usage), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "qwen"
                reply = types.SimpleNamespace(complete=lambda messages, tools: ModelTurn("[]", [], usage=usage))
                with self.assertRaisesRegex(ReportRefusal, "measured total_tokens"):
                    ProgentBudget(root, None).client(reply, "policy").complete([], [])
                with self.assertRaisesRegex(ReportRefusal, "measured total_tokens"):
                    ProgentBudget(root, None)

    @unittest.skipUnless(progent.available(), "vendor/py-progent (secagent) is not installed")
    def test_invalid_policy_attempt_is_recorded_before_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "qwen"
            replies = iter(["not JSON", "[]"])
            reply = types.SimpleNamespace(complete=lambda messages, tools: ModelTurn(
                next(replies), [], usage={"prompt_tokens": 90, "completion_tokens": 10, "total_tokens": 100}
            ))
            generator = ProgentGenerator(ProgentBudget(root, 100).client(reply, "policy"))
            with self.assertRaises(TokenCapReached):
                generator.allowlist(task_by_id("fetch-guide"), "C:/proj", [])
            budget = ProgentBudget(root, 200)
            self.assertEqual((budget.spent, budget.policy_tokens), (100, [100]))
            policy, usage = ProgentGenerator(budget.client(reply, "policy")).allowlist(task_by_id("fetch-guide"), "C:/proj", [])
            self.assertEqual(policy, {"progent": {}, "tools": []})
            self.assertEqual((usage["total_tokens"], budget.spent), (100, 200))


class ProgentFreezeRefusalTests(unittest.TestCase):
    def test_no_secagent_or_a_main_folder_refuses_and_writes_nothing(self):
        before = _kept()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "progent-freeze"
            with unittest.mock.patch("wiggle.progent.available", return_value=False):
                with self.assertRaisesRegex(SystemExit, "vendor/py-progent"):
                    main(["freeze", "--layer-d", "progent", "--out", str(out)])
            self.assertFalse(out.exists())
            # The folders of a stand-in repository root, so a regression cannot write over a real record.
            with unittest.mock.patch("wiggle.stage2_run.ROOT", Path(tmp)):
                for name in ("stage2-freeze", "stage2", "injection-pilot"):
                    target = Path(tmp) / "artifacts" / name
                    with self.assertRaisesRegex(SystemExit, "Freeze refused"):
                        main(["freeze", "--layer-d", "progent", "--out", str(target)])
                    self.assertFalse(target.exists())
        self.assertEqual(_kept(), before)


@unittest.skipUnless(progent.available(), "vendor/py-progent (secagent) is not installed")
class ProgentFreezeTests(unittest.TestCase):
    def test_writes_only_its_own_file_and_changes_only_the_layer_d_item(self):
        before = _kept()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "progent-freeze"
            main(["freeze", "--layer-d", "progent", "--out", str(out)])
            self.assertEqual([path.name for path in out.iterdir()], ["freeze.json"])
            record = json.loads((out / "freeze.json").read_text(encoding="utf-8"))
        main_items = json.loads(freeze_path().read_text(encoding="utf-8"))["items"]
        self.assertEqual((record["kind"], record["extends_sha256"], record["model_run"]), ("stage2-progent-freeze", STAGE2_FREEZE, False))
        self.assertEqual(set(record["items"]), set(main_items))
        self.assertEqual([name for name in main_items if record["items"][name] != main_items[name]], ["policy_prompt"])
        self.assertEqual(record["secagent_settings"], progent.prompt_settings())
        files = list(record["secagent_files"])
        self.assertEqual(files, sorted(files))
        self.assertIn("secagent/tool.py", files)
        self.assertTrue(all(name.startswith("secagent/") and name.endswith(".py") for name in files))
        self.assertEqual(_kept(), before)
        self.assertEqual(freeze_record()["sha256"], STAGE2_FREEZE)


@unittest.skipUnless(progent.available(), "vendor/py-progent (secagent) is not installed")
class SourceCheckTests(unittest.TestCase):
    """Every refusal comes before the rerun writes anything."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.source = self.base / "stage2" / "m"
        self.source.mkdir(parents=True)
        self.report = {
            "kind": "stage2-verdict",
            "model_run": True,
            "freeze_sha256": STAGE2_FREEZE,
            "caller": {"temperature": 0.0, "thinking_off": True},
        }
        _write(self.source / "report.json", self.report)
        _write(self.source / "run.json", {"model": "m", "sandbox": str(self.source / "sandbox")})
        write_progent_freeze(self.base / "progent-freeze")
        self.progent_freeze = self.base / "progent-freeze" / "freeze.json"
        self.root = self.base / "stage2-progent" / "m"

    def tearDown(self):
        _remove_tree(self.base)

    def _rerun(self, root: Path | None = None, **changes):
        options = {
            "model_arg": "m",
            "temperature": 0.0,
            "thinking_off": True,
            "endpoint": "",
            "source": self.source,
            "progent_freeze": self.progent_freeze,
            "log": lambda message: None,
            **changes,
        }
        return run_progent_verdict(root or self.root, None, None, **options)

    def test_a_source_verdict_under_another_freeze_refuses(self):
        _write(self.source / "report.json", {**self.report, "freeze_sha256": "0" * 64})
        with self.assertRaisesRegex(ReportRefusal, "cites freeze"):
            self._rerun()
        self.assertFalse(self.root.exists())

    def test_another_changed_freeze_item_refuses(self):
        stage2 = json.loads(freeze_path().read_text(encoding="utf-8"))
        stage2["items"]["cases"]["sha256"] = "0" * 64
        _write(self.base / "stage2-freeze.json", stage2)
        with self.assertRaisesRegex(ReportRefusal, r"outside layer \(d\): cases$"):
            self._rerun(main_freeze=self.base / "stage2-freeze.json")
        self.assertFalse(self.root.exists())

    def test_no_secagent_refuses_and_writes_nothing(self):
        with unittest.mock.patch("wiggle.progent.available", return_value=False):
            with self.assertRaisesRegex(ReportRefusal, "vendor/py-progent"):
                self._rerun()
        self.assertFalse(self.root.exists())

    def test_a_missing_or_stale_progent_freeze_refuses(self):
        with self.assertRaisesRegex(ReportRefusal, "missing"):
            self._rerun(progent_freeze=self.base / "none.json")
        stale = json.loads(self.progent_freeze.read_text(encoding="utf-8"))
        _write(self.progent_freeze, {**stale, "sha256": "0" * 64})
        with self.assertRaisesRegex(ReportRefusal, "does not match the code"):
            self._rerun()
        self.assertFalse(self.root.exists())

    def test_other_settings_or_missing_source_rows_refuse(self):
        with self.assertRaisesRegex(ReportRefusal, "thinking_off"):
            self._rerun(thinking_off=False)
        with self.assertRaisesRegex(ReportRefusal, "records model"):
            self._rerun(model_arg="other")
        with self.assertRaisesRegex(ReportRefusal, "no complete row"):
            self._rerun()
        self.assertFalse(self.root.exists())

    def test_an_out_in_the_main_stage2_folders_refuses(self):
        for name in ("stage2", "stage2-freeze"):
            target = ROOT / "artifacts" / name / "m"
            with self.assertRaisesRegex(ReportRefusal, "main Stage 2 artifact"):
                self._rerun(root=target)
            with self.assertRaisesRegex(SystemExit, "main Stage 2 artifact"):
                main(["verdict", "--layer-d", "progent", "--out", str(ROOT / "artifacts" / name), "--model", "m"])
            self.assertFalse(target.exists())


# The rerun test's plan: one training and one held-out task, one case, its live sample.
_TASKS = ("fetch-guide", "fetch-h-guide")
_CASE = "page-G1-fetch-h-guide"
# A fixed Progent policy: fetch, on the docs host only.
_POLICY = json.dumps([{"name": "fetch", "args": {"url": {"type": "string", "pattern": "^http://docs\\.example\\.test/"}}}])


class _PolicyDouble:
    """Answers the endpoint check with a tool call and each policy request with `_POLICY`."""

    def __init__(self):
        self.requests: list[list[dict]] = []

    def complete(self, messages, tools):
        if tools:
            return ModelTurn("", [Call("fetch", "fetch", {"url": "http://docs.example.test/guide"})], model_id="double")
        self.requests.append(messages)
        return ModelTurn(_POLICY, [], model_id="double", usage={"prompt_tokens": 90, "completion_tokens": 10, "total_tokens": 100})


class _MeteredScripted(Stage2ScriptedModel):
    """The scripted caller, with token usage on each turn as a hosted model reports it."""

    def complete(self, messages, tools):
        turn = super().complete(messages, tools)
        turn.usage = {"prompt_tokens": 40, "completion_tokens": 10, "total_tokens": 50}
        return turn


@unittest.skipUnless(progent.available(), "vendor/py-progent (secagent) is not installed")
class RerunTest(unittest.TestCase):
    """A scripted source verdict, then the rerun: refused on another tool list, stopped at the cap twice, finished, and again."""

    def test_copy_rule_resume_token_cap_and_report(self):
        case = next(case for case in stage2_cases() if case.id == _CASE)
        plan = Plan(tuple(task_by_id(task_id) for task_id in _TASKS), (case,), (case,))
        base = Path(tempfile.mkdtemp())
        try:
            source = base / "stage2" / "scripted"
            run_verdict(
                source,
                lambda task, fx, sample: Stage2ScriptedModel(task, fx),
                UnconstrainedPolicy(),
                scripted=True,
                model_arg="scripted",
                plan=plan,
                log=lambda message: None,
            )
            # The rerun copies only from a model verdict, so this scripted one stands in for it.
            report = json.loads((source / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["freeze_sha256"], STAGE2_FREEZE)
            _write(source / "report.json", {**report, "model_run": True})
            source_rows = _rows(source / "traces.jsonl")
            source_sandbox = json.loads((source / "run.json").read_text(encoding="utf-8"))["sandbox"]
            project = source_rows[0]["messages"][1]["content"].split("\n")[0]
            self.assertTrue(project.startswith("Project directory: " + source_sandbox))
            write_progent_freeze(base / "progent-freeze")
            progent_sha = json.loads((base / "progent-freeze" / "freeze.json").read_text(encoding="utf-8"))["sha256"]
            root = base / "stage2-progent" / "scripted"
            agent_runs: list[str] = []
            policy = _PolicyDouble()

            def rerun(**options):
                return run_progent_verdict(
                    root,
                    lambda task, fx, sample: agent_runs.append(task.id) or _MeteredScripted(task, fx),
                    policy,
                    model_arg="scripted",
                    temperature=None,
                    thinking_off=False,
                    endpoint="http://double.example.test",
                    plan=plan,
                    log=lambda message: None,
                    source=source,
                    progent_freeze=base / "progent-freeze" / "freeze.json",
                    **options,
                )

            kept = _files(source)
            # A copy cut by a stopped invocation: the cut line stays a line of its own, so the rows after it parse.
            cut = base / "cut" / "traces.jsonl"
            cut.parent.mkdir()
            lines = [json.dumps(row, ensure_ascii=False) for row in source_rows[:3]]
            cut.write_text(lines[0] + "\n" + lines[1] + "\n" + lines[2][: len(lines[2]) // 2], encoding="utf-8")
            self.assertEqual(copy_rows(cut, source_rows[:4]), 2)
            store = TraceStore(cut)
            store.load()
            self.assertEqual((len(store.rows), store.dropped), (4, 1))

            # The agent saw the source run's tool list, so another one refuses before any model call.
            with unittest.mock.patch(
                "wiggle.stage2_run.stage2_tool_list", side_effect=lambda servers, poison="": stage2_tool_list(servers, poison)[:-1]
            ):
                with self.assertRaisesRegex(ReportRefusal, "tool list"):
                    rerun()
            self.assertEqual((agent_runs, policy.requests, (root / "allowlists.json").exists()), ([], [], False))

            # The cap stops before the second policy request. The copied rows are done runs.
            with self.assertRaises(TokenCapReached):
                rerun(token_cap=1)
            self.assertEqual((agent_runs, len(policy.requests)), ([], 1))
            copied = _rows(root / "traces.jsonl")
            reused = [row for row in source_rows if row["set"] != "live" or row["layer"] != "d"]
            self.assertEqual(copied, reused)
            self.assertEqual([row["set"] for row in copied].count("benign"), 6)
            self.assertEqual([row["set"] for row in copied].count("attack"), 6)
            self.assertEqual(sorted(row["layer"] for row in copied if row["set"] == "live"), ["c", "e"])
            grants = json.loads((root / "allowlists.json").read_text(encoding="utf-8"))
            self.assertEqual((grants["generator"], list(grants["allowlists"])), ("progent-b02783b8", ["fetch-guide"]))
            # One project directory: the copied traces, the policy prompt, and the pinned fixture. The freeze is pinned too.
            run = json.loads((root / "run.json").read_text(encoding="utf-8"))
            self.assertEqual((run["sandbox"], run["progent_freeze_sha256"]), (source_sandbox, progent_sha))
            system, user = policy.requests[0]
            self.assertEqual(system["content"], progent.system_prompt())
            self.assertTrue(user["content"].startswith("TOOLS: "))
            self.assertIn("\nUSER_QUERY: " + project + "\n", user["content"])

            # Resuming with the same cap cannot spend again.
            with self.assertRaises(TokenCapReached):
                rerun(token_cap=100)
            self.assertEqual((agent_runs, len(policy.requests)), ([], 1))
            # A larger cap permits the second policy, then stops before the live (d) run.
            with self.assertRaises(TokenCapReached):
                rerun(token_cap=101)
            self.assertEqual((agent_runs, len(policy.requests)), ([], 2))

            # Stop between the live agent's two replies. Paid usage survives, but no sample is marked complete.
            with self.assertRaises(TokenCapReached):
                rerun(token_cap=250)
            self.assertEqual((agent_runs, len(policy.requests)), (["fetch-h-guide"], 2))
            self.assertFalse(any(row["set"] == "live" and row["layer"] == "d" for row in _rows(root / "traces.jsonl")))
            report = rerun()
            clock = report["wall_clock"]
            self.assertEqual((clock["runs_new"], clock["runs_resumed"]), (1, 14))
            self.assertEqual((clock["policy_calls_new"], clock["policy_calls_resumed"]), (0, 2))
            self.assertEqual((agent_runs, len(policy.requests)), (["fetch-h-guide", "fetch-h-guide"], 2))
            self.assertEqual(report["layer_d"], {"generator": "progent-b02783b8", "progent": True})
            self.assertEqual((report["freeze_sha256"], report["freeze"]["extends_sha256"]), (progent_sha, STAGE2_FREEZE))
            record = report["progent"]
            self.assertEqual((record["agent_freeze_sha256"], record["layer_d_freeze_sha256"]), (STAGE2_FREEZE, progent_sha))
            self.assertEqual(record["reused"], {"benign": 6, "attack": 6, "live": 2})
            # Two turns of the one live (d) run; the copied rows' tokens are not this rerun's.
            self.assertEqual((record["endpoint"], record["top_p"], record["live_d_tokens"]), ("http://double.example.test", None, 100))
            self.assertEqual(record["live_d_model_ids"], ["scripted"])
            self.assertEqual(report["cost"]["policy"]["total_tokens"], 200)
            self.assertEqual((record["budget"]["model_tokens"], record["budget"]["phase_tokens"]), (350, 350))
            # Tool level: each task's own tool is not counted, though the policy restricts its url.
            self.assertEqual([row["outside_l5"] for row in report["over_permission"]], [[], []])
            final = _rows(root / "traces.jsonl")
            self.assertEqual([row for row in final if row["set"] != "live" or row["layer"] != "d"], copied)
            live_d = [row for row in final if row["set"] == "live" and row["layer"] == "d"]
            self.assertEqual(len(live_d), 1)
            self.assertTrue(live_d[0]["messages"][1]["content"].startswith(project + "\n"))
            self.assertFalse(Path(source_sandbox).exists())
            text = (root / "report.md").read_text(encoding="utf-8")
            for needle in ("## Progent layer (d) rerun", STAGE2_FREEZE, progent_sha, "`progent-b02783b8`", PROGENT_APART, PROGENT_OVER_PERMISSION, "top_p not sent"):
                self.assertIn(needle, text)

            # A third invocation copies nothing again and makes no model call but the endpoint check.
            again = rerun()
            self.assertEqual((again["wall_clock"]["runs_new"], again["wall_clock"]["runs_resumed"]), (0, 15))
            self.assertEqual(again["wall_clock"]["policy_calls_new"], 0)
            self.assertEqual((agent_runs, len(policy.requests)), (["fetch-h-guide", "fetch-h-guide"], 2))
            keys = [_row_key(row) for row in _rows(root / "traces.jsonl")]
            self.assertEqual((len(keys), len(set(keys))), (15, 15))
            # The rerun built and removed its fixture in the source folder and changed nothing else there.
            self.assertEqual(_files(source), kept)
            self.assertFalse((root / "allowlists.tmp").exists())
        finally:
            _remove_tree(base)


if __name__ == "__main__":
    unittest.main()
