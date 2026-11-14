# Writeup: report skeleton and chapter status

Started 2026-11-03 (roadmap M6). The section tree is `docs/paper-outline.md`. `PROMPT.md` and `docs/injection-protocol.md` win on any conflict. The deliverable is thesis only for now (confirmed 2026-11-03); venue-specific paper layout is omitted.

Working title: **Unauthorized Agent Actions: Excess MCP Tool Calls and a Fine-Tuning Backdoor.**

## Rules for every chapter

- Every number names the generated artifact it comes from. Do not type a number that no artifact holds. If an artifact changes, rerun its command and update the text.
- Figures come from `python -m wiggle.figures` (`artifacts/figures/`). Do not draw a figure by hand.
- No "first" or "novel" claim until `docs/systematic-review.md` records a priority decision that supports it (today: dropped).
- A pilot number is labeled as a pilot. It supports no defense claim.

## Chapters

| File | Section | Owner (proposal) | Status |
| --- | --- | --- | --- |
| [00-abstract.md](00-abstract.md) | Abstract | joint | draft (inference-time vector only; a backdoor sentence would cite BadAgent, not measured here) |
| [01-introduction.md](01-introduction.md) | 1 Introduction | joint | draft |
| [02-background.md](02-background.md) | 2 Background and threat model | joint | draft |
| [03-scanners.md](03-scanners.md) | 3 The scanner landscape (C4) | you | draft, numbers in hand |
| [04-method.md](04-method.md) | 4 Method: the injection study | you | draft |
| [05-backdoor.md](05-backdoor.md) | 5 Method: the backdoor study | teammate | draft from pinned BadAgent artifacts; generated MCP text and older OS-command measurements kept separate; no common-harness execution |
| [06-results.md](06-results.md) | 6 Results: two vectors, one gap | joint | 6.1, 6.2 drafted; 6.3 cites BadAgent; 6.5 not tested (RQ3 is future work) |
| [07-tradeoff.md](07-tradeoff.md) | 7 The defense tradeoff | you | draft with both Progent models and replay/live distinctions |
| [08-attacking-the-defense.md](08-attacking-the-defense.md) | 8 Attacking the defense (C3) | you | draft includes widening Step 1, both birth arms and completed Stage 4 |
| [09-related-work.md](09-related-work.md) | 9 Related work | joint | provisional synthesis drafted; completed systematic review and any priority claim remain gated |
| [10-limitations.md](10-limitations.md) | 10 Limitations | joint | draft |
| [11-conclusion.md](11-conclusion.md) | 11 Conclusion, ethics, artifact | joint | draft |

## Figures

| File | Shows | Used in |
| --- | --- | --- |
| `artifacts/figures/stage2-layers-patched.svg` | Each defense layer alone and stacked, Stage 2 patched arm: attacks left open and held-out tasks kept, per model | 6.2, 7 |
| `artifacts/figures/stage2-layers-vulnerable.svg` | The same, vulnerable arm | 7 |
| `artifacts/figures/stage2-ladder.svg` | Needed ladder L0 to L5, attacks blocked against held-out tasks kept, per model | 7 |
| `artifacts/figures/birth-qwen3.8-flash.svg` | Birth arm against its clean-vs-clean baseline, `qwen3.8-flash` | 8 |
| `artifacts/figures/birth-deepseek-flash.svg` | Birth arm against its clean-vs-clean baseline, `deepseek-flash` | 8 |
| `artifacts/phase1/curve.svg` and the per-server curves | Phase 1 security–usability curves | 6.1 |

## Open inputs

Each input is a phase of `docs/execution-plan.md`. The joins J1, J2 and J3 were dropped on 2026-11-03 (no local model host): sections 5 and 6.3 cite the BadAgent repository, and 6.5 is future work.

- Progent and widening Step 1 are complete and incorporated in sections 7 and 8.1.
- Stage 4 is complete and incorporated in section 8.3, the abstract, limitations and conclusion. Its layer results are replay-only and its task-policy zero is bounded by construction.
- Systematic review (Phase 5: third source, search freeze, screen, full-text read): section 9 and the contributions wording.
