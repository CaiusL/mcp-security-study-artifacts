# Finish plan: closing the gaps to a presentable outcome

Written 2026-11-01 as a layer on top of `roadmap.md`. It does not replace the roadmap. The roadmap keeps the milestones M0 to M8, the critical path and the calendar. `docs/archive/plan.md` keeps the task tables and the go/no-go rules. `PROMPT.md` and `docs/injection-protocol.md` win on any conflict. This file adds the two things the roadmap does not: the decisions that are still open and block every run, and the join between this repository and the BadAgent repository (the fine-tuning half). Owners and every recommendation are marked **(proposal)** for the team to confirm.

## 0. Why this file exists

The roadmap is already a complete plan. Two gaps keep it from being executable today.

1. The M0 decisions are open. The freeze waits on them, and no model run is allowed before the freeze (`PROMPT.md`).
2. The roadmap tells one half of the story. Claims C1 to C4 are all wiggle and zgScanner. The BadAgent repository is the second attack vector and the self-host argument, and it is not on the path.

This file closes both.

## 1. The combined outcome

One report and one 20-minute talk, built from two repositories as one result.

- **This repository (wiggle + zgScanner):** the inference-time vector, a poisoned MCP tool injected into a live agent, and the scanner comparison.
- **The BadAgent repository (`github.com/CaiusL/BadAgent`):** the training-time vector, a LoRA backdoor on Qwen3.5-2B that emits a canary tool call the user never asked for.

The one-sentence claim that ties them:

> A poisoned MCP tool and a fine-tuned backdoor reach the same in-scope-misuse gap, and only the defenses that cost utility close it.

Both halves land on the same harness (join J1 below), so the result is one measurement, not two papers.

## 2. Decisions to close now (M0)

These are team calls. The recommendation column is a proposal to make the meeting short.

| # | Decision | Recommendation (proposal) | Why |
| --- | --- | --- | --- |
| 1 | Model 2 (roadmap section 7.3 is open) | **Qwen**, the open-weight family BadAgent backdoors, on a hosted OpenAI-style endpoint | One family serves three jobs: the Stage 2 second model, the self-host ablation (J2) and the backdoor host (J3). It is the choice that unifies the two repositories |
| 2 | Layer (d) | Progent `b02783b8`, time-boxed to three working days; else the minimal generator, named as such | Unchanged from roadmap section 7.4. Do not let it slip the freeze |
| 3 | Scoring template | `stage2-scoring-1` only | Each extra template adds 600 attack runs (roadmap section 7.5) |
| 4 | Price per million tokens | Record a USD figure for both models before the run | The budget has tokens but no USD (`artifacts/stage2-budget/budget.md`) |
| 5 | Venue and deadlines | Pick in week 1, then replace the proposal dates in roadmap section 6 | The calendar is undated |

Two cautions on the Qwen choice:

- If layer (d) is Progent, pick a Qwen id that the client routes to a base URL, not to `127.0.0.1:8000` (roadmap section 7.3, `docs/progent-license-check.md`).
- The self-host ablation (J2) is clean only if the API Qwen and the local Qwen are the same checkpoint and quantization with the same host prompt. Otherwise report it as a hypothesis, not a result.

## 3. The join with BadAgent (new work, not in the roadmap)

Three tasks put the two repositories on one path. **(proposal)**

| Join | Work | Done when |
| --- | --- | --- |
| **J1** | Run the current backdoored Qwen adapter (`replication_out/mcp_tool_qwen/adapter`) through the On9MCP agent loop once, canary only, synthetic fixture, no real file written | One trace in the On9MCP harness shows the canary `write_file` as an in-scope-looking excess call, scored by the same oracles as the injection study. Today the backdoor is logged on its own, and `replication_out/mcp_tool_word/on9_loop.json` is an older adapter |
| **J2** | Serve Qwen two ways, the hosted API and a local host, with the same checkpoint, quantization and host prompt, and run the same attack set against both | A table of patched-arm ASR, API versus local, with the serving layer as the only difference. This is the "fewer rules locally" test |
| **J3** | The backdoored Qwen, local only | The training-time vector measured on the same ASR-against-utility axes as the injection study. A backdoor cannot be uploaded to a hosted API, so this is the self-host risk stated honestly |

J1 is the highest-value task here. It is small, and it is what makes the two halves one experiment.

## 4. The unified critical path

```text
M0 decisions + amendment ─► M1 harness, dry run, FREEZE ─► M2 DeepSeek ─► M2 Qwen(API) ─► M3 analysis ─► M6 results ─► M7 talk + artifact
                                     │                                         │
                                     └─► M4 birth arm ─► M4 widening Step 1 ────┘  (own PROMPT.md amendment)

BadAgent joins:  J1 (after the M1 harness) ─► folds into M3 as the training-time rows
                 J2, J3 (after model 2 is chosen and a local Qwen host exists) ─► the self-host section of M3 and M6

Parallel from day 1:  M5 systematic review ─► blocks only the "first/novel" sentence in M6
                      M6 skeleton + the chapters that do not wait ─►
```

## 5. Owner split (proposal)

| Track | Owner | Items |
| --- | --- | --- |
| wiggle / zgScanner | you | M0 slots; Stage 2 run command is written (`python -m wiggle.stage2 verdict`, `wiggle/stage2_run.py`); scripted dry run; **freeze**; M2 runs; M3 tables; the C4 zgScanner rerun on the five bench servers; M4 birth and widening arms |
| BadAgent | teammate | J1 integration; J2 and J3 Qwen hosting (needs the non-GPU box); the fine-tuning chapter |
| Joint | both, then supervisor | merge the two halves into one report and paper; the talk; M5 review; the contributions and related-work positioning; disclosure (D4) |

## 6. The cut line: the minimum finished, honest project

If the deadline is tight, this is still complete and defensible.

**Keep:** C1, C2 (Stage 2, one model, DeepSeek), C4, C3 at Step 0, the BadAgent backdoor (already done) and J1.

**Drop in this order** (first cut first): Stage 4 → updater arm → collection arm → widening Step 1 (keep Step 0) → birth arm → third model → Qwen as model 2. If Qwen is cut, J2 and J3 become future work and the self-host claim drops to a stated hypothesis.

The count of 30 tasks per server is fixed at M0 and never changes after the freeze. Samples are never cut (`PROMPT.md` amendment).

## 7. Honesty gates

Unchanged from `PROMPT.md` and the protocol, repeated here because they decide the story.

- A pilot supports no defense claim. Nothing from pilot 2 (`artifacts/injection-pilot-2/`) is a result until Stage 2 is scored.
- No "first" or "novel" claim before the systematic review (M5) supports one.
- The self-host claim needs J2's confounds controlled, or it stays a hypothesis.
- A freeze before any model run. Responsible disclosure before any real-server finding is public.

## 8. Not in this file

Two document-level pieces, drafted when their inputs exist.

- The contributions list (the four the report will claim).
- The related-work table (M5 gates it).
