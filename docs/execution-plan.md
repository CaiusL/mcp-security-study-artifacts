# Execution plan: finish the study from 2026-11-03

Written 2026-11-03. It replaces the 2026-11-02 version (see git history). Phases 1 to 3 of that version are done: Stage 2 ran on both models and is scored. `PROMPT.md` and `docs/injection-protocol.md` win on any conflict.

Tags: **[now]** runs on this machine with the keys set · **[eng]** code first, then a run · **[human]** needs a person or a team decision.

## Continuation checkpoint, 2026-11-03

- Both birth arms and both separately frozen Progent reruns are complete. Progent's shared persistent usage is 2,227,710/4,600,000 tokens.
- Widening Step 1 completed all 96 runs and scoring, with 251,895/530,000 persistent tokens and a go decision. A larger widening arm is not part of this execution.
- Stage 4 completed under freeze `97fa9b07…`: 20/20 cases, 200 attacker replies and 60/60 reruns, with 5,404,909/6,000,000 recorded tokens. Raw ASR is 19/60 versus 18/60 matching static runs; layer (d) leaves 0/60 open, bounded by construction, while Needed L3 leaves 7/60 open in replay. Scoring passes (`artifacts/stage4/qwen3.8-flash/report.md`). Collection resumed after the provider interruption without changing the freeze. The 14-case checkpoint remains a historical record. The remaining 595,091 tokens cannot fund another complete target arm at the observed cost; the optional second target was not started.
- The integrated suite ran 309 tests (308 passed, one expected skip); focused persistence tests and the real widening resume subsequently passed. See `artifacts/verification/`.
- Thesis-only delivery is confirmed. Completed live-arm and delivery/review commits through `7d10195` are pushed to [PR #1](https://github.com/ZephyalGates/On9MCP/pull/1). The first literature screen is complete (6,704 decisions). Full-text extraction and the independent human screen remain open; the owner deferred the OpenAlex refresh because no key is available. A 13-slide defense draft and the offline demo are prepared. See `docs/artifact-delivery.md` for regeneration and verification; second-machine regeneration and rehearsals require a person.

The steps below preserve the execution order and acceptance criteria of the original plan. Completed phases are recorded above and in their generated reports.

## State when the plan was written, 2026-11-03

- Stage 2 ran on both models under freeze `bbaecb1a…`, thinking off, 870 runs each, 0 model errors. `deepseek-flash`: 0/300 attacks reached their goal. `qwen3.8-flash`: 18/150 patched, 15/150 vulnerable. Field 2 and the OWASP label are applied (`artifacts/stage2/<model>/report.md`, `artifacts/stage2/pooled.md`).
- Measured agent tokens per run: `deepseek-flash` 11,282,464/870 (about 12,970), `qwen3.8-flash` 14,512,765/870 (about 16,680). A minimal-generator policy call is about 5,500 tokens (`artifacts/stage2/<model>/allowlists.json`, usage).
- The Stage 3 birth arm ran on `qwen3.8-flash` only: 2,580,798 policy tokens, plus 842,760 for the clean-vs-clean baseline (`artifacts/stage3-birth/qwen3.8-flash/record.md`).
- Figures and chapter drafts exist (`artifacts/figures/`, `docs/writeup/`).
- Git: the branch `stage2-resize-birth-progent` is 3 commits ahead of its remote and 6 ahead of `main`. It has no PR. The local worktree branch `claude/modest-antonelli-4902c1` (commits `e8b3415`, `3673961`, not on the remote) holds older versions of the Stage 2 run and labels commands. The remote branch `adversary-write-behind` (CaiusL, 2026-10-30) is not merged into `main`.

## Decisions taken 2026-11-03

| Decision | Choice | Reason |
| --- | --- | --- |
| J1, J2, J3 (the BadAgent joins) | Dropped. There is no local model host. | RQ3 (self-hosting) is not tested. It moves to future work. Chapter 5 keeps the backdoor study's own results, cited from the BadAgent repository, and says that they were not measured on this harness. |
| A VM jail for vulnerable pins and shell | No jail in this study. The vulnerable arm stays on stand-ins. The `PROMPT.md` hold stays as written. Shell stays out. | 32 of the 33 Qwen successes stayed inside the declared scope and needed no server bug (`docs/writeup/06-results.md`, 6.2). The observed in-scope-excess finding does not depend on executing vulnerable pins; that arm remains unmeasured. A jail is a new arm, a new freeze and a rerun on both models. Chapter 10 states the limit. |
| Stage 4 adaptive round | Run it as one labeled experiment (Phase 4), after its own `PROMPT.md` amendment, reported apart. | Team decision. |
| Report deadline | No near deadline. Run every phase; the cut line below does not apply. The optional second Stage 4 target runs only if the budget allows. | Decided 2026-11-03. |
| Deliverable | Thesis only for now; omit the venue-specific paper layout. | Confirmed during the Codex handoff on 2026-11-03. |

Still open:

| Decision | What it is for | Needed before |
| --- | --- | --- |
| USD price per million tokens, per model | It changes the measured tokens into money (`python -m wiggle.budget --usd-per-million-tokens <price>`), for the cost line of the report and the team's spend check. No result depends on it. | The cost line in the writeup |
| `adversary-write-behind` | Whether the teammate's adversary and write-behind work joins `main` and the writeup. | Phase 6 |

## Order at a glance

```text
Phase 0 housekeeping ──┬─► Phase 1 DeepSeek birth arm     [now, runs in the background]
                       ├─► Phase 2 Progent rerun          [eng ─► run]
                       ├─► Phase 3 widening Step 1        [eng ─► run]
                       └─► Phase 4 Stage 4 experiment     [proposal + amendment ─► eng ─► run]
Parallel from now:         Phase 5 systematic review      [now, one human step]
All of the above ────────► Phase 6 writeup and delivery
```

Run at most one agent study (Phases 2 to 4) at a time. The birth arm runs no agent, so it can run beside one.

## Token budget

Estimates from the measured rates above. Each run stops at its cap. Samples are never cut.

| Item | Model calls | Estimate | Stop at |
| --- | --- | ---: | ---: |
| Phase 1: birth arm, `deepseek-flash` | 624 policy requests | 3.4M | 6.8M |
| Phase 2: Progent rerun, both models | 180 policies and 10 live runs per model | 2.3M | 4.6M |
| Phase 3: widening Step 1, `deepseek-flash` | 96 agent runs (pilot 2 rate, 2,744 per run) | 0.26M | 0.53M |
| Phase 4: Stage 4, target `qwen3.8-flash` | ≤ 200 attempts, 60 re-runs, ≤ 200 attacker calls | 4.9M | 6M |
| Total | | about 11M | |

For scale: Stage 2 used 25.8M agent tokens on the two models. The Progent estimate assumes a Progent policy call costs about the same as a minimal-generator call; Phase 2 measures it first. The Stage 4 estimate assumes about 3,000 tokens per attacker call.

## Phase 0 — Housekeeping [now, no model]

1. Push the 3 commits on `stage2-resize-birth-progent`. Open a PR into `main` so the teammate can read the Stage 2 work.
2. Remove the worktree `.claude/worktrees/modest-antonelli-4902c1` and its branch. HEAD has later versions of both commands. The two commits stay findable by hash until git prunes them.
3. Record the 2026-11-03 decisions in the README decisions tables, `docs/paper-outline.md` and the writeup. Remove the J1, J2 and J3 waits from chapters 00, 01 (RQ3), 05, 06 (6.3 to 6.5), 10 and 11, and from `docs/writeup/README.md`.
4. Fix the stale docs: the README status line and the model numbering (model 1 `qwen3.8-flash`, model 2 `deepseek-flash`, as in `PROMPT.md`); tick the two done boxes in "The plan"; the test count. Move `docs/reds-status.md` (a 2026-11-02 snapshot) to `docs/archive/`.
5. Run the full test suite and record the count.

Exit: the docs agree with each other and with `PROMPT.md`, and the suite passes.

## Phase 1 — Birth arm on `deepseek-flash` [now]

```text
python -m wiggle.stage2 birth --base-url https://api.deepseek.com --model deepseek-flash --api-key-file <key file outside the repo> --thinking-off
```

- The same 78 held-out tasks, 5 goals and clean-vs-clean baseline as the Qwen record. Resumable. Output: `artifacts/stage3-birth/deepseek-flash/`.
- Watch the first 20 requests. Stop if a request costs more than twice the Qwen rate (about 5,500 tokens).
- Then run `python -m wiggle.figures` (it adds `birth-deepseek-flash.svg`) and add a README "Tests we did" row.

Exit: a birth record for both models, as the 2026-11-02 plan asked. Section 8.2 reports both.

## Phase 2 — Progent layer-(d) rerun [eng, then now]

What exists: `wiggle/progent.py` (the secagent `b02783b8` check and policy generation) and `ProgentGenerator` in `wiggle/stage2_run.py`, with 5 model-free tests in `tests/test_progent.py`. Nothing selects it: `PROGENT_GENERATOR` is `None`, and there is no Progent freeze file and no output folder.

1. Add `--layer-d progent` to `python -m wiggle.stage2 freeze` and `verdict`. It selects `ProgentGenerator`, a Progent `LAYER_D_POLICY` freeze item (the generator id and the hashes of the pinned `secagent` files), the freeze file `artifacts/stage2-progent-freeze/freeze.json`, and the output folder `artifacts/stage2-progent/<model>/`. It never writes the main freeze file or a main verdict (`PROMPT.md`, Progent amendment).
2. Reuse the agent traces. The agent never sees layer (d), so copy the benign rows, the attack rows, and the live rows of layers (c) and (e) from `artifacts/stage2/<model>/traces.jsonl`. Copy only after a check that every other freeze item matches `bbaecb1a…`. Then the only new model calls are the 180 Progent policies and the 10 layer-(d) live validations per model.
3. Model-free tests: the flag, the own freeze file, the copy rule, and a refusal when the source verdict has a different freeze.
4. Write the Progent freeze. Run `qwen3.8-flash` first (it has successes to block), then `deepseek-flash` (utility and over-permission only). Measure the first 10 policy calls, and stop if they cost more than twice the estimate.
5. The verdict names both freezes: the reused agent traces under `bbaecb1a…`, and layer (d) under the Progent freeze. Over-permission for Progent counts at tool level only. The report says so.

Exit: `artifacts/stage2-progent/<model>/report.md` for both models. Chapter 7 gets labeled Progent rows. Chapter 10 drops the "pending" line.

## Phase 3 — Widening Step 1 [eng, then now]

Design: `docs/proposal-stage3-widening-arm.md`, Steps 1 and 2, under the 2026-11-02 amendment. Step 0 is done (`artifacts/stage3-widening/`).

1. Add `python -m wiggle.widening freeze`. It writes `artifacts/stage3-widening/freeze.json` with the W1 to W3 request texts, the 96-run case list and the model settings. After that, a change is a new hash.
2. Build `collect`: 42 clean and 54 poisoned runs (the 14 pilot training tasks; 3 W goals × 3 channels × 2 tasks; 3 samples), resumable, on `deepseek-flash`, temperature 0.0, thinking off. That is the pilot 2 model, so M5 and M6 pair with the pilot 2 traces.
3. Build `score` (no model): M1 to M6 and the soundness check, into `artifacts/stage3-widening/report.md`.
4. Model-free tests with the scripted caller first, then the run.
5. Apply the go/no-go table of the proposal. A model that refuses every W request is a result, not a failure.

Exit: the report and its go/no-go. Section 8.1 gets the model arm.

## Phase 4 — Stage 4 adaptive experiment [proposal, then eng, then now]

The protocol asks for "one adaptive round against the strongest layer, with a stated query budget", after an amendment, reported apart (`docs/injection-protocol.md`, Stage 4).

1. Write `docs/proposal-stage4-adaptive.md`. Add this amendment to `PROMPT.md`: *A labeled adaptive arm is allowed. An attacker model rewrites the injection text between attempts, under a frozen attacker prompt and a fixed query budget, against the frozen Stage 2 fixtures, oracles and layer-(d) allowlists. It never tunes a fixture. Its results are reported apart from the static results.*
2. Design (proposal):
   - **Target model:** `qwen3.8-flash`, thinking off, patched arm. It is the model that the static attacks moved.
   - **Target layer:** (d), the task policy. It was the first blocker on all 33 static successes and the only blocker on 15. The attacker sees the task's frozen allowlist (`artifacts/stage2/qwen3.8-flash/allowlists.json`) and the agent's calls after each attempt (white box). L3 and the other layers are scored by replay on the same traces.
   - **Cases:** the 20 in-scope cases (G1 and G2, 10 each, all five channels).
   - **Attacker:** `deepseek-flash`, temperature 0.0, one frozen attacker prompt. If it refuses the task, `qwen3.8-flash` is the attacker, and the report says so.
   - **Query budget:** at most 10 attempts per case. One attempt is one agent run. A case stops at the first attempt that reaches the goal and passes layer (d).
   - **Measures:** the best text per case runs again 3 times. ASR with no defense and under each layer, alone and stacked, with Wilson intervals, beside the static 0/150 under (d). Held-out utility does not change, because benign tasks carry no injection.
3. Step 0, no model: for each case and its task, does the frozen allowlist hold a permission that can carry the goal (a write with an open path, or a fetch with an open host)? This bounds what any attacker can do against (d). It reads the Stage 2 over-permission rows.
4. Build `wiggle/stage4.py`: the loop on the Stage 2 harness (the same plants for all five channels), a resumable store, the freeze file `artifacts/stage4-freeze/freeze.json`, and model-free tests with a scripted attacker and a scripted agent.
5. Run, score and report into `artifacts/stage4/qwen3.8-flash/`. Optional second target: `deepseek-flash` (static 0/300), if the budget allows.

Exit: the report. Chapter 8 gets a new section. The "static attacks" limit in chapter 10 changes.

## Phase 5 — Systematic review [now, parallel; one human step]

1. Third source: retry the DBLP API once. If the bot check is still there, do not try to get past it. Use another documented API with the same query (Semantic Scholar bulk search or Crossref), and record the switch in `docs/systematic-review.md`, section 3.
2. Freeze the search: re-run every source on one day and record that date (section 4).
3. Screen the titles and abstracts of the keyword keeps against the inclusion question (section 2). Screener 1 is Claude, in batches, with each decision and its reason saved under `artifacts/systematic-review/`. **[human]** Screener 2 is a team member, who re-checks every keep and a 10% sample of the drops (section 5). The writeup says that the first screen was AI-assisted.
4. Read the full text of the kept works. Add a closest-works row and a `docs/related_work.md` note for each.
5. Extend `python -m wiggle.review` to read the screen file, so that the screened, read and included counts stay generated. Apply the decision rule (section 8), then draft chapter 9.

Exit: the PRISMA counts are filled, the priority decision is recorded, and chapter 9 is drafted.

## Phase 6 — Writeup and delivery [joint]

1. Put each result into its chapter when its phase lands: 7 (Progent), 8 (widening Step 1, the DeepSeek birth arm, Stage 4), 9 (review), 10 and the abstract.
2. **[human]** Supervisor review of the thesis. The venue-specific paper form is omitted under the thesis-only decision.
3. Slides, the offline demo, the artifact tag, a regeneration check on a second machine, and two rehearsals.

## Cut line

If the deadline comes first, cut in this order: the second Stage 4 target, then Progent on `deepseek-flash`, then widening Step 1. Never cut samples.

## Guardrails (unchanged)

- Stop at a cap and re-size with an amendment. Never cut samples.
- Every model run passes `endpoint_check` first and records the model id, endpoint, temperature, top_p, step cap, thinking, host-prompt hash and freeze hash.
- Keep CPU, RAM and GPU under 90%. Cap worker and thread counts.
- Synthetic canaries and reserved hostnames only. Responsible disclosure before any real-server finding is shared.
- Every reported number comes from a generated artifact.
