# Thesis artifact handoff

Checkpoint: 2026-11-03. The thesis remains a draft pending supervisor review. The OpenAlex refresh is deferred at the owner's request; the review makes no priority claim.

## Deliverables

- Current local draft tag: `thesis-draft-v2-2026-11-03`, covering the completed adaptive study. The earlier `thesis-draft-2026-11-03` tag preserves the provider-interrupted checkpoint. Neither is a final-submission tag.
- Thesis chapters: `docs/writeup/README.md` and chapters 00–11.
- Defense slides: `artifacts/slides/output/thesis-defense-draft-v3.pptx`. Thirteen editable slides with native tables, a native chart, source notes and the completed adaptive results.
- Offline evidence demo: `artifacts/demo/index.html`. Open the file directly in a browser. It displays saved measurements and inert trace text; it does not execute model calls or saved tool calls.
- Independent second-screen sheet: `artifacts/systematic-review/screener-2.md` and `.jsonl`. A human reviewer must supply the decisions; no AI-generated second screen is substituted.

## Regenerate saved evidence

From the repository root with the Python and vendored dependencies installed as in `README.md`:

```text
python scripts/check_saved_results.py
python -m wiggle.figures
python -m wiggle.demo
python -m wiggle.review
```

The first command compares central metrics recomputed from saved traces and policy records against both Stage 2 reports, both Progent reports, both birth records, widening, and the Stage 4 bound and adaptive report when available. Socket and process creation are blocked during this check. It verifies source-file hashes remain unchanged and writes `artifacts/verification/saved-results-2026-11-03.json`. A missing adaptive report is recorded as pending, not a successful check. It does not repeat task/effect oracles, model requests, live enforcement, human coding, or timing measurements. Windows path semantics are required for the recorded Windows fixtures; this check does not yet establish cross-platform reproduction.

The remaining commands regenerate figures, the HTML snapshot and review tables from saved records. Review regeneration now succeeds after avoiding a truncating write when `screen.jsonl` already matches the corpus. A regression test confirms changed corpus content still rewrites the file and propagates write failures. All 37 focused review/demo tests passed; an independent comparison matches all four generated outputs and confirms screening content is unchanged. See `artifacts/verification/review-primary-10-11-2026-11-03.json`. The earlier OSError 22 receipt remains a historical record. Do not run `review fetch --restart` against the active corpus as a substitute: the separately saved search refresh needs reconciliation with its existing screening keys.

The adaptive collection and scoring are complete. `python -m wiggle.stage4 score` regenerates its report without model requests. The regenerated demo and offline checker include it.

## Rebuild the slides

`scripts/build_thesis_slides.mjs` uses the Codex bundled Artifact Tool and the presentations skill's validators. It adds no project package dependency. Set these three environment variables to the installed locations:

- `PRESENTATIONS_SKILL_DIR`: the presentations skill directory containing `container_tools/artifact_tool_utils.mjs`.
- `ARTIFACT_NODE_MODULES`: the bundled Node `node_modules` directory containing `@oai/artifact-tool`.
- `ARTIFACT_PYTHON`: the bundled Python executable used by the package and layout validators.

Then run with the bundled Node executable, giving a new output filename:

```text
node scripts/build_thesis_slides.mjs thesis-defense-rebuilt.pptx
```

The finalizer refuses to overwrite an existing deliverable. Output goes to `artifacts/slides/output/`; candidate files, validator receipts and rendered slide images stay in the ignored `artifacts/slides/.build/`. Inspect the final imported PPTX's rendered slides before distributing a rebuilt deck. Native PowerPoint rendering still needs checking on the presentation machine.

## Verification and remaining human work

- Integrated test suite at commit `b5f1363`: 309 tests run, 308 passed and one expected skip, 675.186 seconds (`artifacts/verification/resume-2026-11-03.json`).
- Focused persistence and review checks: 37 passed in 1.133 seconds; the real interrupted widening collection resumed and scored all 96 runs (`artifacts/verification/persistence-2026-11-03.json`).
- Final review and demo checks: 36 passed in 1.378 seconds, including offline regeneration, both birth records, absent-to-present adaptive report handling and inert trace markup (`artifacts/verification/delivery-2026-11-03.json`). Browser interaction checks remain incomplete because Computer Use could not establish the current browser URL.
- Offline saved-results recomputation matches all nine components, including the completed adaptive report. The checker now normalizes the rebuilt JSON representation before comparison: Python tuples in the safety metadata become arrays on disk. Focused checks accept this round trip and still reject a changed rejection count, a removed mutation argument or a missing field. The frozen experiment code and evidence were unchanged.
- The current v3 13-slide PPTX passes package, font and layout checks with zero findings. One conservative table-height warning on slide 4 is 0.0013 inches; visual inspection of all final imported slides found no clipping or overlap. Native PowerPoint was not opened. The completion receipt records the PPTX hash and checks (`artifacts/verification/stage4-completion-2026-11-03.json`).

Second-machine regeneration, independent human screening, supervisor review, and two rehearsals are still required. These are not replaced by the local checks. Full-text extraction also remains incomplete; use the generated PRISMA record for current counts. No final-submission tag or completion claim is implied by this checkpoint.


## Completed adaptive collection and historical interruption

The historical immutable checkpoint is `artifacts/verification/stage4-checkpoint-2026-11-03.json`. It preserves hashes and progress at 14/20 cases. DeepSeek returned HTTP 503 and one JSON-null response; its [status page](https://status.deepseek.com/incidents/7202016104287) reported a partial API interruption on 2026-11-03. The original frozen command subsequently resumed from saved rows and completed all 20 cases and 60 reruns. DeepSeek remained the attacker; provider errors did not trigger the refusal fallback. Scoring confirms 19/60 raw successes and 0/60 under layer (d), bounded by construction. The report records zero target-agent model-request errors, which does not erase the separately recorded attacker-endpoint interruption.

Recorded study tokens total 5,404,909 under the 6,000,000 cap. They are not a complete provider invoice: endpoint checks are excluded by design, and the failed responses supplied no retained usage. The separate benign format diagnostic used 11 tokens. The remaining 595,091 tokens do not support another complete target arm at the observed cost, so no optional second target was started.

## Companion adversary branch

Read-only integration review inspected `origin/adversary-write-behind` at `bc276b28038a28ee8524c6e786e789226bbb10e6`, including its handoff, design note and shared-code diff. It adds counterfeit-server fixtures and a tree-effect audit, changes shared tool serialization and agent-loop behavior, and has a separate sample design. Recommendation: retain it as a separately cited companion study for this thesis checkpoint. A merge and sixth-layer evaluation need their own scope decision and validation; no branch merge, execution or numerical result import was performed. The historical handoff's statement that its work was uncommitted is superseded by the recorded branch commit.
