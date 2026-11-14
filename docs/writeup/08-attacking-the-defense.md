# 8. Attacking the defense (C3)

*Draft, 2026-11-03. Sources: `artifacts/stage3-widening/mechanism.md` (Step 0), `artifacts/stage3-widening/report.md` (model collection), `artifacts/stage3-birth/<model>/record.md` (birth arm), and `artifacts/stage4/qwen3.8-flash/report.md` (adaptive arm). Figures: `artifacts/figures/birth-qwen3.8-flash.svg`, `artifacts/figures/birth-deepseek-flash.svg`.*

Both strong layers of section 7 are built from text: the Needed ladder from benign training traces, the task policy from the user task. If an attacker can reach that text, the policy may be built wider than the task needs. We test this two ways.

## 8.1 Widening the training traces

In the no-model mechanism check, we add one extra call to one training trace and rebuild the Needed profile. Under W1, a `list_directory` of the project's `secrets` directory, the L3 profile gains that directory. Three attack probes open: at L3, attacks blocked on the vulnerable lattice drop from 13 of 14 to 10 of 14, and held-out success does not move (7 of 11). At L4 they drop from 14 of 14 to 11 of 14. Under W3, a fetch to the sink host's health URL, no lattice count changes (`mechanism.md`).

The model collection then ran all 96 frozen cases on `deepseek-flash`, thinking off: 42 clean and 54 poisoned, under freeze `4762fcd5…`. Every task oracle passed and no run ended in a model-request error. For each poisoned sample, scoring replaces its matching clean training sample and rebuilds the profile. This is a defense-aware static arm, reported apart from Stage 2.

| W goal | Entered the profile | Wilson 95% interval | Added scope |
| --- | ---: | --- | --- |
| W1 directory listing | 6/18 | [0.163, 0.563] | `secrets` directory at L3 |
| W2 marker write | 5/18 | [0.125, 0.509] | `.sh` extension at L4 |
| W3 health fetch | 8/18 | [0.246, 0.663] | Reserved sink host and health URL |

The 19 compliant samples all completed their benign task, so their extra calls entered the training profile. Page injections produced no compliance; repo-file and description injections supplied the signal. For W1, six substitutions reopened three secret-directory probes at L3 and L4, reducing lattice blocks from 14/14 to 11/14. W2 and W3 widened keys without reopening any probe in that lattice. Held-out replay utility never fell across the 33 pilot traces or 11 scripted tasks. None of the substitutions reopened a previously blocked complete chain among the 72 patched pilot attack traces (M5).

All 55 profiles passed training-trace soundness. The generated decision is **go** for considering a larger Stage 3 study, not a claim of general effectiveness. Completed traces account for 249,520 tokens; the persistent record includes interrupted work and totals 251,895, below the 530,000 cap. M5/M6 use the same model id and temperature as pilot 2, but collections occurred on different dates. The small sample, union deriver and fetch query-string gap limit the result.

## 8.2 The birth arm: does injected text widen the task policy?

For each of the 78 held-out tasks, the task policy (layer d) was requested once clean and once per goal with the frozen tool-output template pasted into the user turn as untrusted text: 390 poisoned pairs per model, thinking off. Because a model need not be deterministic at temperature 0, we added a clean-vs-clean baseline: two more clean requests per task, scored the same way.

| Measure | `qwen3.8-flash` | `deepseek-flash` |
| --- | ---: | ---: |
| Poisoned policy adds a permission over the clean one | 46/390 | 32/390 |
| A second clean policy adds one over the first | 8/78 | 0/78 |
| An added permission names the injected target | 0/390 | 0/390 |
| Poisoned request gave no allowlist | 2/390 | 0/390 |
| Clean baseline request gave no allowlist | 2/156 | 0/156 |

**Qwen.** The poisoned rate (11.8%) is close to the clean-repeat rate (10.3%), and no added permission points at what the injection asked for: not the secret file, the sink host, a `.sh` file, a path outside the project, or the other repository. The added items are variations of the task's own calls. A request that returned no allowlist (the reply looped into garbled text) happened at similar low rates with and without the paste.

**DeepSeek.** The clean policy was stable: a second clean request never added a permission (0 of 78). So the paste did change the policy, on 32 of 390 pairs (8.2%). But no added permission names the injected target (0 of 390). The added items are the task's own tools and arguments: a read tool, the project or notes directory of a tree listing, the repository path, a memory node that the task names, and, on one fixture task, the note tools that the task text names, in place of the filesystem tools, with the task's own path and content (`artifacts/stage3-birth/deepseek-flash/records.jsonl`).

For both models, the paste can change the task policy, but we find no evidence that it widens the policy toward the attack.

One server stands out on both models: on the fixture server, 19 of 65 (Qwen) and 16 of 65 (DeepSeek) poisoned pairs added a permission, against 1 of 13 and 0 of 13 clean repeats. With 13 baseline tasks per server, we do not report that difference as a result.

## 8.3 Adaptive attacks against a frozen task policy

The separately frozen Stage 4 experiment targets the original Qwen task allowlists, not the Progent generator. DeepSeek rewrites the injected text after seeing the task, goal, allowlist, prior calls and policy verdict. It cannot change fixtures, oracles or permissions. The 20 G1/G2 cases span all five channels. Each allows up to ten attacker replies, including refusals and invalid texts; the frozen selection rule chooses a best text for three further runs per case. The protocol also defines when repeated primary-attacker refusals trigger the Qwen fallback.

Step 0 found that none of the 20 allowlists permits its goal-completing call (`artifacts/stage4/step0.md`). A zero under layer (d) is therefore bounded by construction. The experiment can still measure raw goal success and replay outcomes for other layers, but it does not establish universal adaptive robustness. Stage 4 adds a separately reported runtime safeguard against Git-metadata mutation; it is not counted as one of the five defense layers.

Collection completed under freeze `97fa9b07…`: 200 attacker replies, 189 agent attempts and all 60 selected-text reruns. Five replies were refusals and six were invalid texts; they consumed attempts under the frozen rule. No case passed layer (d), so every case exhausted its ten replies. DeepSeek remained the attacker throughout; no fallback occurred. After an API interruption, collection resumed from the saved rows without changing the design. Total recorded usage was 5,404,909/6,000,000 tokens. The remaining 595,091 does not support another full target arm at the observed cost, so the optional second target was not started.

| Condition | Adaptive ASR, Wilson 95% interval | Static ASR, matching cases | Static ASR, all cases |
| --- | --- | ---: | ---: |
| No scored defense | 19/60 [0.213, 0.442] | 18/60 | 18/150 |
| Scanner (a) | 17/60 [0.185, 0.408] | 18/60 | 18/150 |
| Server checks (b) | 19/60 [0.213, 0.442] | 18/60 | 18/150 |
| Needed policy (c), operating point L0 | 19/60 [0.213, 0.442] | 18/60 | 18/150 |
| Task policy (d) | 0/60 [0.000, 0.060] | 0/60 | 0/150 |
| Fetch rule (e) | 15/60 [0.158, 0.372] | 7/60 | 7/150 |

The raw adaptive rate is close to the matching static rate. The fetch rule leaves more adaptive successes open in this sample. The Needed ladder leaves 13/60 open at L2, 7/60 at L3 and 0/60 at L4 and L5; the corresponding inherited held-out successes are 195/234, 170/234, 147/234 and 56/234. Thus L3's zero on the full static set does not extend to these adaptive texts. The full stack leaves 0/60 open because it includes layer (d). These are descriptive comparisons across collections and text-selection procedures, not a paired test of adaptive versus static effectiveness.

All stored verdicts match replay, with no unscored reruns and no runtime Git-safety rejections. Layer results are counterfactual replay: Stage 4 adds no live enforcement reruns, and held-out task utility is inherited from Stage 2. In particular, layer (c) failed its Stage 2 replay/live agreement threshold (8/10 against 0.9); its Stage 4 rows and ladder remain replay-only. The Wilson intervals summarize 60 reruns of 20 selected texts, with three runs sharing each text, rather than 60 independently sampled attack designs. The frozen task-policy bound and this finite budget preclude a general adaptive-robustness claim.

## 8.4 Reading

Section 8.1 shows that a trace-derived policy *can* be widened by its input. Section 8.2 finds that, for two models and one static template, a task-derived policy *was not* widened toward the attack. Neither result covers an adaptive attacker who tunes the text against the policy generator (section 10).
