# Roadmap to a presentable outcome

Written 2026-10-30 from the state in `README.md`, `docs/archive/plan.md`, `docs/injection-protocol.md`, `PROMPT.md` and the generated artifacts. It adds no rule. When this file disagrees with `PROMPT.md` or the protocol, those files win. `docs/archive/plan.md` keeps the task tables and the go/no-go rules. This file sets the order of work, the milestones, the deliverables and the story the outcome tells.

No project file sets dates, a venue or owners. Every date, every recommendation and every cut rule here is marked **(proposal)**. The team accepts or changes them. Every number is copied from a generated artifact, and the source is named next to it.

## 1. The outcome

The project ends in four deliverables. A fifth is optional.

| Id | Deliverable | Done when |
| --- | --- | --- |
| D1 | **Writeup**: the master's report, and a paper-form version of the same results (preprint, then a workshop or conference submission) **(proposal)** | Finish line items 1 to 6 in `docs/archive/plan.md` hold. Every number comes from a generated artifact |
| D2 | **Reproducible artifact**: this repository at a tagged commit, with one command per artifact, the freeze hashes, the traces and the test suite | A clean machine with Python 3.11 and Node regenerates each table from its command, and the test suite passes |
| D3 | **Talk and demo**: a 20-minute talk and a 5-minute offline demo (section 10) | Rehearsed twice. Every slide number traces to an artifact |
| D4 | **Disclosure record**: each new finding on a real server or host, reported to its maintainer, with dates | No finding is public before its maintainer has had it (`PROMPT.md`) |
| D5 | Optional: a final explainer video from the existing pipeline (`artifacts/explainer/`) | Same rule as the slides: every number from an artifact |

## 2. The story

The outcome makes four claims. Each has an evidence state today.

| # | Claim | Evidence today | What still has to happen |
| --- | --- | --- | --- |
| C1 | **Patched servers stop boundary breaks, not in-scope excess.** On five patched servers every boundary probe was refused (12 of 12) and every in-scope excess probe was performed (19 of 19 at L0). The Needed ladder is what closes in-scope excess, at a utility cost | In hand: `artifacts/phase1/comparison.md` | Nothing. Report it at equal weight (`PROMPT.md`) |
| C2 | **When a real agent is injected through MCP content, the successes on patched servers are in-scope misuse, and only the defenses that cost utility stop them.** Pilot 2: 5 of 72 patched-arm attacks succeeded, all goal G2 through a tool description, all 8 successes coded inside the grant (8 of 8, two blind coders). Layers (a), (b), (c) at its operating point and (e) left every one open. Layer (d) closed every one and kept 12 of 33 held-out tasks. The ladder at L3 also closes them and keeps 18 of 33 | Pilot evidence only: `artifacts/injection-pilot-2/report.md`. A pilot supports no defense claim (protocol) | Stage 2: 5 channels, 2 models, held-out scoring template, 3 samples, Wilson intervals, McNemar tests |
| C3 | **A policy built from text can be attacked when it is built.** Step 0 shows the mechanism in the deriver: one extra, normal-looking call in one training trace opens three attack probes at L3 and L4 (W1: 13 of 14 blocked to 10 of 14), and held-out success does not move | Mechanism only, no model: `artifacts/stage3-widening/mechanism.md` | Stage 3: the birth arm, and the widening model arm (does a model follow a low-harm widening request more often than a harmful one?) |
| C4 | **Public MCP scanners disagree, and a hand review finds what they miss.** Six scanners on five hosted servers flagged 0 to 5 of them. zgScanner closed four gaps the hand review found (SK007, SK010, TP018, TP019) | In hand: `bench/README.md`, `docs/archive/status.md` | A rerun of zgScanner on the five bench servers with the new checks, recorded in `bench/` |

Two more results are part of the story and cost nothing:

- **The negative pilot.** A frozen static injection with the word "injection" in it moved `deepseek-flash` on 0 of 144 attacks (`artifacts/injection-pilot/report.md`). Report it as a result, not as a failure.
- **The utility cost is the finding, not a footnote.** With a real model, L3 keeps 18 of 33 held-out tasks and layer (d) keeps 12 of 33. That is the y-axis of every curve, and it is why Stage 2 keeps about 30 tasks per server.

What the outcome does not say (`PROMPT.md`): not "no attack works on popular MCP servers" (drops C1's second half), not "a plugin cannot hide an attack" (overclaims), and no "first" or "novel" claim before the systematic review supports one. A miss on our lattice or case set is a share of that set, not a proof.

**Minimum story if time runs out:** C1, C2 from Stage 2 with one model, C4, and C3 at the Step 0 level. That is still a complete, honest outcome.

## 3. Where we are on 2026-10-30

| Area | State | Source |
| --- | --- | --- |
| Phase 1 (envelopes, ladder, five live servers, sandbox fixture, flat control) | Done | `artifacts/phase1/comparison.md`, `artifacts/phase1/report.md`, `artifacts/live-*` |
| zgScanner 0.1.0, 73 checks, bench against six scanners, four checks added after the bench | Done | `wiggle/zgscanner`, `bench/README.md`, `docs/archive/status.md` |
| Registry census, 46,437 servers, read-only | Done | `artifacts/scan-registry/report.md` |
| Injection study design, freeze, model loop, replay scorers | Done | `docs/injection-protocol.md`, `wiggle/agent_loop.py`, `wiggle/replay.py` |
| Pilot 1 (no-go), pilot 2 (go), hand checks, blind coding | Done | `artifacts/injection-pilot/`, `artifacts/injection-pilot-2/` |
| Stage 2 oracles (180 tasks, 30 per server, 17 training and 13 held-out), prompts, 50 cases, budget | Written, checked on the live servers, **not frozen** | `artifacts/stage2-*/` |
| Stage 2 gate: scenario, `PROMPT.md` amendment, three freeze slots (scoring template, layer (d), date) | **Open** | `docs/archive/plan.md`, `docs/proposal-stage2-budget.md`, `docs/proposal-stage2-scoring-template.md` |
| Stage 2 run command (all servers, five channels, G3, per-model reports, resume) | Written 2026-10-30, on main 2026-11-01: `python -m wiggle.stage2 verdict`, with `--scripted` for the dry run. The pooled comparison across models is M3 item 4 | `wiggle/stage2_run.py`, `wiggle/stage2.py`, `wiggle/pilot.py` |
| Stage 3: birth arm and collection arm code paths | Harness checks only, no model run | `wiggle/replay.py` (`birth_record`, `profile_widened`, `asr_change`) |
| Stage 3: widening arm Step 0 | Done. Step 1 refuses to run until the proposal is accepted | `docs/proposal-stage3-widening-arm.md`, `artifacts/stage3-widening/` |
| Stage 4 adaptive round | Not allowed until a `PROMPT.md` amendment | `docs/injection-protocol.md` |
| Systematic review | Protocol in `docs/systematic-review.md`. On 2026-11-02 arXiv phrase (624), arXiv concept (3,109) and OpenAlex phrase (6,448) were retrieved. OpenAlex concept stopped at 13 of 36 cells on HTTP 429. DBLP returned an HTML bot check. No priority claim | `docs/systematic-review.md`, `artifacts/systematic-review/counts.json` |
| Jail (VM) for vulnerable pins, shell, Playwright and GitHub pins, SQLite and Postgres | Not started | `data/servers.json` |
| Writeup, talk, artifact packaging | Not started. Four progress videos exist | `artifacts/explainer/` |

## 4. Milestones

Each milestone names its entry condition, its work and the evidence that closes it. Owners are blank on purpose. Targets are in section 6.

### M0. Stage 2 gate: decisions and the `PROMPT.md` amendment

Entry: pilot 2 is go (done 2026-10-29).

1. One team meeting that settles every row in section 7.
2. Amend `PROMPT.md` with the budget text in `docs/proposal-stage2-budget.md`. Make the matching change in `docs/methodology.md` (step 3) and record the scenario under "Stage 2: full study" in `docs/injection-protocol.md`.
3. If layer (d) is Progent: install `secagent` from git at commit `b02783b8` into the git-ignored `vendor/` tree (not from PyPI), wire it in behind the layer (d) seam, count its policy tokens ourselves, and add tests. Time-box this to three working days **(proposal)**. If it is not green by then, freeze with the minimal generator and report Progent as not run.
4. Fill the three slots in `wiggle/stage2.py`: `SCORING_TEMPLATE_TEXT`, the layer (d) choice, the freeze date. Do not run `freeze` yet (M1 comes first).

Exit: the amendment is committed, the three slots are filled, and the decisions table in `README.md` is updated.

### M1. Stage 2 run harness, dry run, freeze

Entry: M0.

1. **Done 2026-10-30, on main 2026-11-01** (`python -m wiggle.stage2 verdict`, `wiggle/stage2_run.py`; the pooled comparison across models stays with M3 item 4). The command is on top of `wiggle/pilot.py`: it connects every Stage 2 server in every run; plants all five channels (page, repo file, commit message, memory entity, description); scores G1, G1b, G2, G2b, G3; runs both arms; runs the 30 live validations per model; and writes one verdict per model. The report items from the protocol are the OWASP label field on every success, zgScanner's false-positive rate on the benign servers and its marginal catch with (e) active, over-permission of layer (d) against each task's L5 envelope, the negotiated protocol version per server, live-only scoring for any layer whose pilot agreement was below 0.9 (none in pilot 2: the lowest was 9 of 10 for (c) and (e)), and the wall-clock time per run (the pilots did not record it).
2. **Done 2026-10-30.** Resume support: each trace is appended to `traces.jsonl` as it completes, and a second invocation on the same `--out` skips every complete run and re-runs only those that stopped on a model request error. A 1,560-run study will be interrupted at least once.
3. Dry run with `--scripted` on the live servers: all 50 cases, both arms, and the 180 benign tasks. The pilot did the same before its first model run. Every oracle must pass on the scripted calls, and the writer must refuse nothing.
4. Full test suite: `python -m unittest discover -s tests`. Record the count and the date in `README.md`.
5. `python -m wiggle.stage2 freeze` writes `artifacts/stage2-freeze/freeze.json`. From here, a change to any frozen item is a new hash and a rerun.
6. One smoke run per model with the Stage 2 servers connected. Record tokens per run. If it is more than twice the pilot 2 rate (2,744 agent tokens per run, `artifacts/injection-pilot-2/report.json`), stop and re-size before the full run (the amendment's own rule).

Exit: the freeze file exists, the dry run passed, the two smoke runs passed, and nothing frozen changes after this point.

### M2. Stage 2 model runs

Entry: M1.

1. Model 1 first, then model 2. Run the model the team expects to be most robust first, so a zero-signal result shows early.
2. Stop rules from the amendment: stop at the token cap (8,924,142 tokens for scenario B, `artifacts/stage2-budget/budget.md`) and re-size with a new amendment. Never cut samples.
3. Keep the API key in a file outside the repository. Record model id, date, temperature, step cap and thinking setting with every run.

Exit: per-model `traces.jsonl` and verdict record, 0 model request errors (or every error listed), measured cost per run, wall-clock per run.

### M3. Stage 2 analysis and labels

Entry: M2 for at least one model.

1. 20 hand checks per model against the oracles (`hand_sample`).
2. Two coders, blind to arm and layer, code field 2 and the OWASP label on every successful run. Fix the blinding leak from pilot 2: nobody writes a summary of any success anywhere (README, chat, doc) until both coders have filed their sheets. Report kappa, or the one-category rule when it is undefined.
3. Generated tables: attribution (every-, unique-, first-blocker), ASR against held-out utility per layer alone and stacked, McNemar pairs, server-check gap (vulnerable minus patched), scanner cost, over-permission, utility under attack, per channel and per goal.
4. Pooled report across models, with the per-model reports unchanged.
5. Add one row per model to "Tests we did" in `README.md`.

Exit: `artifacts/stage2/<model>/report.md` for each model and a pooled report, all generated, all checks recorded.

### M4. Stage 3: policy construction

Entry: M1 (the harness) and the decisions in section 7. Runs in parallel with M3.

1. **Birth arm** (cheap, no agent runs): for each held-out task and each model, one clean policy request and one with the frozen template passed as `untrusted` to `policy_messages`. Score "policy widened" (over-permission against L5) and "action executed" apart (`birth_record`). At about 908 tokens per policy call (`artifacts/stage2-budget/budget.md`), this is well under 200,000 tokens.
2. **Widening arm, Step 1**: needs the `PROMPT.md` amendment that allows a labeled, frozen, defense-aware static arm reported apart from the static results. Freeze the W request texts. 96 runs, about 250,000 tokens at the pilot rate (`docs/proposal-stage3-widening-arm.md`). Run it on the same model id and temperature as one Stage 2 model, so measures M5 and M6 in that proposal pair with real attack traces. Then Step 2 scoring by replay.
3. **Collection arm**: collect the training traces with `plant_collection` active on the README task, with a model, and run `profile_widened` and `asr_change` on the model traces.
4. **Updater arm**: optional replication. First on the cut list.

Exit: a generated Stage 3 report with "policy widened" and "action executed" apart, the widening measure tables, and the go/no-go table of the widening proposal.

### M5. Systematic review (parallel track, blocks any priority claim)

Entry: now.

1. **Done 2026-11-01.** The review protocol is `docs/systematic-review.md`: sources (arXiv, OpenAlex, and DBLP as the proposed third source), the exact query strings, the date window, the inclusion rule. Draft rule: the work measures a defense against an injected tool-using agent and reports attack success beside benign utility, or it derives a policy from benign traces, or it is on MCP.
2. Finish the OpenAlex screen with `python -m wiggle.review fetch`. The 2026-10-25 run stopped at 4,600 of 6,156 and did not save the pages, so the script retrieves the current result set from the start, resumes from a saved cursor, and backs off on HTTP 429.
3. Screen titles and abstracts. `python -m wiggle.review` writes found, deduped, screened, and keyword-kept counts. Full-text read and included stay in the reading log until each kept work is read. The counts file is generated, not typed by hand.
4. Closest-works table with fixed columns: trace-derived policy? same-trace attribution of several layers? utility reported? MCP? poisoning of the policy's input?
5. Decide the priority statement. It is either supported by the table or dropped.

Exit: `docs/systematic-review.md` with the counts, the table and the decision. `docs/related_work.md` stays as the reading log.

### M6. Writeup

Entry: M1 for the skeleton; M3 for the results chapters. Start during Stage 2, not after it (`docs/archive/plan.md`).

1. Skeleton and the chapters that do not wait for Stage 2: problem, background, the three envelopes and the ladder, phase 1 results (C1), the scanner bench (C4), the injection study design, pilot 1 and pilot 2.
2. Figure generator **(proposal: `python -m wiggle.figures`)** that writes every figure from the artifacts: the security–usability curves (`curve.svg` exists per server), the attribution heatmap, ASR against held-out utility per layer alone and stacked, the widening before-and-after table. No figure is drawn by hand.
3. Results chapters from the Stage 2 and Stage 3 reports. Limitations chapter from the protocol's "Threats to validity", plus: static templates are a lower bound until Stage 4, one host prompt, two models, replay counterfactuals checked by live validation, the fetch ladder's query-string gap, the page channel on a stand-in, the vulnerable arm on stand-ins (no jail), and the size of the case set.
4. Two forms from one source of truth: the report chapters, and an 8 to 12 page paper version **(proposal)**. Pick the venue in M0 (section 7) and check its deadline and page limit before the paper form is laid out.
5. Internal review: both teammates, then the supervisor.

Exit: a full draft that the supervisor has read, with every number traced to an artifact and the test suite green on the commit it cites.

### M7. Talk, demo, artifact packaging

Entry: M6 draft.

1. Slides and the demo script in section 10.
2. Artifact: tag the commit **(proposal: `v1.0.0`)**, add a "Regenerate everything" section to `README.md` with the ordered commands and the expected run time of each, confirm on a second machine (the teammate's) that the stand-in artifacts regenerate from a clean clone, and optionally mint a DOI (Zenodo).
3. Two rehearsals with a timer. The demo runs offline, with no API key.

Exit: D2 and D3 done.

### M8. Stretch goals, only after M7 is safe

In this order **(proposal)**:

1. Stage 4, one adaptive round against the strongest layer with a stated query budget, after its own `PROMPT.md` amendment, reported apart.
2. A VM jail, then filesystem `2025.1.14` and a vulnerable git pin, so the vulnerable arm and G3's vulnerable arm run on real servers instead of stand-ins.
3. A third model (scenario A), or a k-of-n support threshold variant of the ladder (resists one poisoned trace; measure its held-out cost).
4. The live fetch server behind a local recording proxy (the stage 0 condition), Playwright and GitHub pins, SQLite and Postgres pins, shell.
5. Public release of zgScanner as its own package.

## 5. Critical path

```text
M0 decisions + amendment ──► M1 harness, dry run, FREEZE ──► M2 model 1 ──► M2 model 2 ──► M3 analysis ──► M6 results ──► M7 talk + artifact
                                       │                                        │
                                       └──► M4 birth arm ──► M4 widening Step 1 ─┘   (needs its own PROMPT.md amendment)

Parallel from day 1:  M5 systematic review ──────────────────────────────────────► blocks the priority statement in M6
                      M6 skeleton + non-Stage-2 chapters ───────────────────────►
```

Three facts set the order:

- The freeze comes after the dry run and the harness, not before. A harness bug found after the freeze costs a new hash and a rerun of every affected run (protocol).
- The widening model arm pairs with Stage 2 traces only if it runs on the same model id and temperature. Decide the model pool before the widening freeze.
- The review blocks one sentence (the priority statement), not the study. It must not block the runs.

## 6. Proposed calendar (proposal)

Weeks start on a Monday. Replace these with real dates as soon as the team has a deadline. The order holds either way.

| Week | Starts | Main track | Parallel |
| --- | --- | --- | --- |
| 1 | 2026-11-02 | M0: decisions, amendment, slots filled, Progent time-box starts | M5: review protocol, resume the OpenAlex screen |
| 2 | 2026-11-09 | M1: harness, resume support, scripted dry run, test suite, freeze, two smoke runs | M5 screening |
| 3 | 2026-11-16 | M2: model 1 full run | M6: skeleton and the chapters that do not wait; M4 birth arm |
| 4 | 2026-11-23 | M2: model 2 full run; M3 hand checks and blind coding for model 1 | M4: widening amendment and W freeze |
| 5 | 2026-11-30 | M3: coding for model 2, generated tables, pooled report | M4: widening Step 1 and Step 2, collection arm |
| 6 | 2026-12-07 | M6: results chapters, figure generator | M5: closes, priority statement decided |
| 7 | 2026-12-14 | M6: limitations, paper form, internal review | C4 rerun of zgScanner on the bench servers |
| 8 | 2026-12-21 | M6: supervisor review, fixes | M7: slides draft |
| 9 | 2026-12-28 | M7: demo, artifact tag, regeneration check on a second machine, rehearsals | |
| 10 | 2027-01-04 | Buffer. M8 stretch only if weeks 1 to 9 held | |

**Cut order if the deadline is earlier** (first cut first): Stage 4 (M8) → updater arm → collection arm → widening Step 1 (keep Step 0) → birth arm → a third model → model 2 (report one model, say so). The task count (30 per server) is decided at M0 and does not change after the freeze. Samples are never cut (`PROMPT.md` amendment draft).

## 7. Decisions the team makes now

| # | Decision | Recommendation (proposal) | Needed before |
| --- | --- | --- | --- |
| 1 | Stage 2 scenario | B: 2 models, 5 servers, 30 tasks per server, 1,560 runs, about 4.46 million tokens, cap 8.92 million (`artifacts/stage2-budget/budget.md`) | M0 |
| 2 | Model 1 | `deepseek-flash`, temperature 0.0, thinking off, step cap 8. It has the pilot record and pairs with the widening arm | M0 |
| 3 | Model 2 | One open-weight model on a hosted OpenAI-style endpoint (no GPU here). Not chosen yet. If Progent is used, pick an id that its client routes to a base URL, not to `127.0.0.1:8000` (`docs/progent-license-check.md`, note 2) | M0 |
| 4 | Layer (d) | Progent at commit `b02783b8`, time-boxed to three working days; else the minimal generator, named as such | M0, before the freeze |
| 5 | Scoring template | Accept `stage2-scoring-1` (fake-completion class), one template. Each extra template adds 600 attack runs | M0, before the freeze |
| 6 | Page channel | The fetch stand-in. The live fetch server needs a recorder and a public-resolving hostname; that is M8 | M0 |
| 7 | Price per million tokens for each model | Record it, then `python -m wiggle.budget --usd-per-million-tokens <price>` | M0 |
| 8 | Widening arm | Amend `PROMPT.md` to allow a labeled, frozen, defense-aware static arm with no query loop, reported apart. Keep W3 (it is the one goal that reaches the fetch ladder) | M4 |
| 9 | Query-string gap in `normalize_url` | Report it as a known limit of the fetch ladder in D1. Do not change the ladder before Stage 2 is scored (it changes the phase 1 curves). A fixed-ladder variant is a labeled rerun afterwards, if time allows | M4, D1 |
| 10 | Venue and deadline for the paper form, and the report's own deadline | Pick in week 1. Then set the real dates in section 6 | M0 |
| 11 | Coders for M3 and the blinding procedure | Same two coders as pilot 2. No summary of any success is written anywhere before both sheets are filed | M3 |
| 12 | Jail (VM) | Only as M8. Do not let it block anything | M8 |

## 8. Budget and resources

| Item | Figure | Source |
| --- | --- | --- |
| Stage 2 tokens, scenario B | 4,462,071 estimated; cap 8,924,142 | `artifacts/stage2-budget/budget.md` |
| Pilot 2 measured rate | 2,744 agent tokens per run; 908 per layer (d) policy call | `artifacts/injection-pilot-2/report.json` |
| Widening Step 1 | 96 runs, about 250,000 tokens | `docs/proposal-stage3-widening-arm.md` |
| Birth arm | 2 policy calls per held-out task per model, under 200,000 tokens | section 4, M4 |
| Price | None recorded. No USD figure exists yet | `artifacts/stage2-budget/budget.md` |
| Wall-clock per run | Not recorded in either pilot. Record it in Stage 2 | M1 |
| Machine | No GPU. No container runtime. `vendor/py` not readable; the live studies use `vendor/py-live` | `docs/archive/status.md` |
| Data that leaves the machine | The model API request only, with synthetic fixtures and canaries | protocol |

## 9. Risks

| Risk | Signal | Response (fixed in the protocol unless marked) |
| --- | --- | --- |
| Model 2 has zero signal | Patched-arm ASR 0 for G1 and G2 on every channel | Record the negative result, as pilot 1 was. The study stands on model 1 |
| Token overrun | Smoke rate more than twice the pilot rate, or the cap is reached | Stop. Re-size with a new amendment. Never cut samples |
| Replay disagrees with live runs | Agreement below 0.9 on a layer | That layer gets live-only scoring. Budget those runs |
| Coders disagree, or kappa undefined again | Field 2 agreement below 0.8; or one category only | Tighten the coding rule and re-code; or the one-category rule (protocol amendment of 2026-10-29) |
| Harness bug after the freeze | A writer refusal, a wrong oracle, a plant that does not reach | New hash, rerun the affected runs. The dry run in M1 is there to catch this before the freeze |
| Progent integration slips | Not green after three working days | Minimal generator, named as such (proposal) |
| Long run interrupted | Process dies mid-study | Resume support in M1 (proposal) |
| OpenAlex rate limit | HTTP 429 | Backoff, resume, record the boundary of the screen |
| A blinding leak | A success is described before both coders filed | Procedure in decision 11 |
| A new finding on a real server | Any effect outside the sandbox on a real host | Responsible disclosure first (D4) |
| Time | Any milestone slips a week | The cut order in section 6 |

## 10. The talk and the demo (proposal)

Slides, 14, about 20 minutes:

1. Title and the one-sentence claim: MCP tools can do more than tasks need, and the defenses that close that gap are the ones that cost utility.
2. The problem: tool text is attacker content; three channels; the lethal trifecta.
3. Three envelopes: Declared, Reachable, Needed. Removable wiggle room.
4. The ladder L0 to L5 and one curve (`artifacts/phase1/curve.svg`).
5. C1 on five patched servers (`artifacts/phase1/comparison.md`).
6. C4, the scanner bench and the four checks zgScanner gained.
7. The injection study: five layers, four goals plus twins, five channels, two arms.
8. Pilot 1 was a no-go and why. Pilot 2 signal and the attribution table.
9. Stage 2 attribution table (every-, unique-, first-blocker).
10. ASR against held-out utility per layer, alone and stacked, with intervals.
11. C3: the widening mechanism and the model arm result.
12. What we do not claim, and the limits.
13. What a defender should do with this: patch, then a Needed ladder at L3 or a task policy, and what each costs.
14. Artifact, how to regenerate it, thanks.

Demo, 5 minutes, offline:

1. `python -m wiggle.zgscanner panel --open` on the poisoned description fixture: the finding, then the clean fixture.
2. One successful description-channel trace from `traces.jsonl`, replayed through the layers: which layer stops it and at which call.
3. `python -m wiggle.widening mechanism`: the W1 table appears from the deriver with no model.

## 11. Rules that stay in force

Unchanged from `PROMPT.md` and the protocol. Synthetic canaries only, reserved hostnames, no shell tool, no exploit payload for a real server, no credential material, no vulnerable pin outside a jail, no package from the census started, public bug classes at class level, no fixture tuned to raise a miss rate, oracles unchanged when a model replaces the scripted caller, a freeze before any model run, a systematic review before any priority claim, and responsible disclosure for any new finding on a real server.
