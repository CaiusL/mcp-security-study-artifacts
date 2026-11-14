# Experiment and test results

This document summarizes the measured experiments and recorded software checks supporting the project report. Every experiment summary links to its detailed evidence. Hosted-model results are saved measurements; the software checks below do not repeat those model runs.

## 1. Capability measurements

Five patched MCP servers were evaluated with scripted calls: filesystem and memory version 2.0.0, and fetch, Git, and time version 2026.10.19.

| Probe category | Recorded outcome | Interpretation |
| --- | --- | --- |
| Boundary probes | 12/12 produced no effect | Server checks rejected the tested boundary violations; one probe failed schema validation. |
| In-scope excess probes at L0 | 19/19 produced an effect | Staying inside the server boundary did not ensure that the operation was needed for the user task. |

These counts describe a finite probe set, not a proof about every possible argument. The Needed permission ladder restricts operations further, with a corresponding benign-task utility cost.

Evidence: [cross-server comparison](../artifacts/phase1/comparison.md), [scripted stand-in study](../artifacts/phase1/report.md), and [policy methodology](methodology.md).

## 2. Scanner benchmark

Six public scanners were tested against five hosted servers. None of the five was confirmed malicious by the manual review.

| Scanner | Servers flagged, out of five |
| --- | --- |
| Cisco mcp-scanner | 4 |
| Ramparts | 1 |
| MCP-Shield | 1 |
| fr2endly mcp-scan | 5 |
| Nova-Proximity | 0 |
| mcp-fence | Could not assess hosted servers, despite printing PASS |

The disagreement does not establish a scanner accuracy ranking. zgScanner's later 73-check catalog was also evaluated on saved captures after four added checks and three false-positive fixes. Aggregate grades from this static rerun are not directly comparable with the live bench because the exercised checks differ.

Evidence: [scanner comparison and manual review](../bench/scan-comparison/COMPARISON.md), [versions and wrappers](../bench/README.md), and [current-catalog rerun](../bench/scan-comparison/zgscanner-current/README.md).

## 3. Prompt-injection pilots and main study

Pilot 1 recorded no successful attack in 144 attempts and failed its attack-signal criterion. Pilot 2 recorded 5/72 patched-arm and 3/72 vulnerable-arm successes, supporting progression to the formal study. Formal Stage 2 used a template held out from the pilots.

Stage 2 ran each model at temperature 0, with thinking off and an eight-step cap. Each model has 870 agent runs: 540 benign, 300 attack, and 30 live-defense checks. The benign runs comprise 306 training and 234 held-out runs. The held-out denominator repeats 78 tasks three times.

| Model | Patched attack successes | Vulnerable-arm attack successes | Unrestricted held-out task success |
| --- | --- | --- | --- |
| qwen3.8-flash | 18/150 (12.0%) | 15/150 (10.0%) | 232/234 (99.1%) |
| deepseek-flash | 0/150 | 0/150 | 234/234 (100%) |

Qwen's 33 successes comprised 18 secret-exfiltration effects, 14 in-project script writes, and one boundary write. Thirty-two stayed within declared boundaries. DeepSeek's zero applies to these tested static injections and does not establish general safety.

Evidence: [pilot 1](../artifacts/injection-pilot/report.md), [pilot 2](../artifacts/injection-pilot-2/report.md), [pooled Stage 2 report](../artifacts/stage2/pooled.md), [Qwen report](../artifacts/stage2/qwen3.8-flash/report.md), and [DeepSeek report](../artifacts/stage2/deepseek-flash/report.md). Raw traces, policies, coding records, and settings are beside the reports.

## 4. Defense effectiveness and task utility

The following comparison uses Qwen's patched-arm traces. Residual attacks and held-out task success are replay measurements. Progent was evaluated under its own freeze.

| Defense | Residual attack successes | Held-out task success |
| --- | --- | --- |
| No additional defense | 18/150 | 232/234 |
| Scanner alone | 18/150 | 232/234 |
| Server checks alone | 18/150 | 232/234 |
| Needed L0 | 18/150 | 232/234 |
| R1 fetch rule | 7/150 | 232/234 |
| Minimal task policy | 0/150 | 127/234 |
| Progent task policy | 0/150 | 155/234 |
| Needed L3 | 0/150 | 170/234 |
| Needed L5 | 0/150 | 56/234 |

Progent preserved 28 more Qwen held-out runs than the minimal task policy. On DeepSeek, their held-out counts were 182/234 and 123/234 respectively; because baseline DeepSeek attacks never succeeded, that model does not establish incremental attack blocking.

Live validation is separate from replay. For Qwen, Needed at the selected L0 operating point agreed with replay in 8/10 checks and allowed two live successes, failing the preset 0.9 agreement threshold. The minimal and Progent task policies each agreed in 10/10 live checks with no observed successes. These small samples do not establish general protection. Needed L3's replay zero is not a live-enforcement result.

Evidence: [defense trade-offs](writeup/07-tradeoff.md), [Qwen main report](../artifacts/stage2/qwen3.8-flash/report.md), [Qwen Progent report](../artifacts/stage2-progent/qwen3.8-flash/report.md), and [DeepSeek Progent report](../artifacts/stage2-progent/deepseek-flash/report.md).

## 5. Policy-construction poisoning

### Training-trace widening

The widening collection contains 42 clean and 54 poisoned runs. All 96 completed their benign tasks.

| Extra operation | Poisoned runs entering the permission profile |
| --- | --- |
| W1: secret-directory access | 6/18 |
| W2: extra script write and suffix | 5/18 |
| W3: sink-host health fetch | 8/18 |
| Total | 19/54 |

W1 reopened three secret-directory probes in six substitutions. W2 and W3 widened profile keys without reopening a lattice probe. No complete previously blocked patched pilot attack chain reopened. Profile widening and complete attack success are different outcomes.

Evidence: [widening report](../artifacts/stage3-widening/report.md) and [mechanism check](../artifacts/stage3-widening/mechanism.md).

### Task-policy input poisoning

Each model used 78 held-out tasks paired with five goals, giving 390 poisoned pairs, plus clean-repeat controls.

| Outcome | Qwen | DeepSeek |
| --- | --- | --- |
| Poisoned policy adds permission beyond clean | 46/390 | 32/390 |
| Clean repeat adds permission beyond first clean request | 8/78 | 0/78 |
| Added permission names injected target | 0/390 | 0/390 |

The inputs sometimes changed permissions, but no targeted permission expansion was observed. This arm compares policies; it does not execute an agent attack.

Evidence: [Qwen policy-input results](../artifacts/stage3-birth/qwen3.8-flash/record.md) and [DeepSeek policy-input results](../artifacts/stage3-birth/deepseek-flash/record.md).

## 6. Adaptive attacks

Stage 4 used DeepSeek as attacker and Qwen as target over 20 cases, up to ten attacker replies per case, followed by three reruns of each selected text. Collection recorded 200 attacker replies, 189 agent attempts, and 60 selected-text reruns.

| Condition | Residual success in selected-text reruns |
| --- | --- |
| No scored defense | 19/60 |
| Scanner | 17/60 |
| Server checks or Needed L0 | 19/60 |
| R1 fetch rule | 15/60 |
| Needed L3 | 7/60 |
| Needed L4 or L5 | 0/60 |
| Frozen minimal task policy | 0/60 |

Matching static cases had 18/60 raw successes; the full static 18/150 uses a different case mix. The task-policy zero was bounded by construction: none of the 20 frozen policies permitted a goal-completing call before collection. Defense comparisons are replay-only, with no added live-defense or benign-utility collection. Three reruns share each selected text. Recorded usage was 5,404,909 tokens.

Evidence: [adaptive report](../artifacts/stage4/qwen3.8-flash/report.md) and [pre-experiment permission bound](../artifacts/stage4/step0.md).

## 7. Software tests and artifact verification

These checks validate implementation behavior and saved records; they are separate from the experimental attack measurements above.

| Check | Recorded result | Scope |
| --- | --- | --- |
| Selected deterministic unit tests | 53 passed; zero failures, errors, or skips | Seven test modules listed below |
| Artifact verification | Passed | File hashes, saved JSON/JSONL syntax, and Stage 2 count/report agreement |
| Stage 2 trace recount | 870 rows per model | Qwen 18/150 patched and 15/150 vulnerable; DeepSeek 0/150 in each arm |

The selected test modules are `test_poc`, `test_agent_loop`, `test_budget`, `test_injection`, `test_layer_d_generator`, `test_figures`, and `test_stage2_birth`. They cover stand-in boundary behavior, policy nesting, agent retry handling, budgets, injection/oracle logic, task-policy generator retries, figure generation, and policy-input comparisons. Network access was blocked; subprocesses were limited to Git operations inside temporary fixtures. This is a selected test run, not a claim that every test in the repository was executed.

To verify the saved artifacts from the repository root:

```bash
python scripts/verify_artifacts.py
```

The command uses Python's standard library and makes no model requests or server calls. [VALIDATION.json](../VALIDATION.json) records the check results; [MANIFEST.json](../MANIFEST.json) lists the file hashes. The deeper [saved-result checker](../scripts/check_saved_results.py) has the platform and dependency requirements described in the README.

## 8. Interpretation limits

- Binomial intervals in the detailed reports describe repeated cases/tasks and do not capture the full uncertainty over new attacks.
- Baseline model failures must not be credited to an added defense.
- Replay cannot represent every replan after denial; the Needed policy failed its live-agreement threshold.
- Server boundary protection, task authorization, policy-input integrity, and implementation effects are distinct questions.
- Companion fine-tuning measurements concern generated output and are not pooled with executed MCP attack rates.

See [measurement limitations](writeup/10-limitations.md) and the [report evidence guide](../REPORT_EVIDENCE.md) for the full interpretation and source map.
