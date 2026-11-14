# Red-beat status after the Stage 2 freeze

Written 2026-11-02, updated the same day after the team's M0 decisions and the
freeze. One row per **red** (not-yet-done) beat the goal names: 2, 3, 4, 6, 7,
9, 10. For each: what it is, the exact command or file, the current state, and
what still blocks it. Every state cites a file or a generated artifact. This
file adds no rule; `PROMPT.md` and `docs/injection-protocol.md` govern.

The beat numbers are the goal's. Beats 2, 9 and 10 map cleanly to single claims
(scanner C4, self-host J2/J3, policy-widening C3). Beats 3, 4, 6 and 7 are the
one Stage 2 cluster; the facet split follows `docs/paper-outline.md` (§4, §6.2,
§6.4/J1, §7). The green beats not listed (1 framework, 5 backdoor trained, 8)
are done elsewhere.

## The gate now: the freeze is done; the model run is next

The Stage 2 freeze ran on 2026-11-02: `artifacts/stage2-freeze/freeze.json`,
sha `bbaecb1a72…`, oracle set `d44c74c4…`, `model_run: false`. The M0 slots in
`wiggle/stage2.py` are filled: `SCORING_TEMPLATE_TEXT` (stage2-scoring-1),
`LAYER_D_POLICY` (the minimal Progent-style generator, named as such), and
`FREEZE_RECORDED` (2026-11-02). From here, a change to any frozen item is a new
hash and a rerun.

So the freeze no longer gates the reds. What gates the model-dependent reds now
is **the model run itself**: the `deepseek-flash` Stage 2 study. It needs the
user's go-ahead, the API key file (kept outside the repo), and it spends tokens
(stop at the cap, never cut samples). **No model has been called.**

Model 2 (Qwen) is deferred, so Stage 2 is one model for now and the J2/J3
self-host joins (beat 9) are future work (`docs/archive/finish-plan.md` §3,
`README.md` decisions).

## Status table

| Beat | What it is | Exact command / file | State 2026-11-02 | What blocks it |
| --- | --- | --- | --- | --- |
| **2** | zgScanner C4 rerun on the five bench servers with the current checks | `python bench/scan-comparison/zgscanner-current/rebuild.py`, then the per-host scan loop in `bench/scan-comparison/zgscanner-current/README.md` | **Done.** Static re-scan of the five saved captures with the current 73-check catalog. The four post-bench checks fire where the hand review found gaps: Veterical `SK007`/`SK010` (B/16→C/45), WealthMCP `TP018`/`TP019` (A/3→B/11), Hallux `TP018`/`TP019`, AIK `TP018` (B/13→A/6); clean control Vuntum gains none (B/16→A/0). Reports in `bench/scan-comparison/zgscanner-current/<host>/`. | Nothing — done. Needed no freeze. |
| **3** | Stage 2 harness and method (paper §4): connect every server, plant all five channels | `python -m wiggle.stage2 verdict …` (`wiggle/stage2_run.py` `run_verdict`) | **Harness written, audited, frozen.** `run_verdict` opens `Servers(fx)` (filesystem, git, memory, time live + fetch stand-in + description fixture) and plants all five channels via `case_plant` plus commit histories. Scripted dry run passed (below). | The `deepseek-flash` model run (go-ahead + key + cost). |
| **4** | Stage 2 C2 result (paper §6.2): score G1/G1b/G2/G2b/G3 on both arms | same command; `score_all`, `stage2_goal_succeeded`, `g3_succeeded` | **Harness scores all five goals on both arms**, with Wilson intervals and McNemar pairs. No numbers yet. | The `deepseek-flash` model run. |
| **6** | Convergence / J1 (paper §6.4): the backdoor's excess call on the same harness and oracles | `tests/test_badagent_join.py` (J1 wiring, 5 tests); `docs/archive/finish-plan.md` §3 | **J1 wiring has test coverage** (2026-11-02). Running the backdoored adapter through the agent loop is a model/adapter run. | The J1 adapter run (deferred with Qwen). |
| **7** | Defense tradeoff (paper §7): ASR against held-out utility per layer, attribution | same command; `ladder_rows`, `operating_level`, attribution in `assemble_verdict` | **Harness computes the attribution table and per-layer curves**; the 30 live validations run through `DenyingBackend`/`layer_deny`; the trace store resumes. No numbers yet. | The `deepseek-flash` model run. |
| **9** | Self-host J2/J3 (paper §6.5): Qwen served API vs local; the backdoored Qwen local | `docs/archive/finish-plan.md` §3 (J2, J3) | **Deferred.** Qwen (model 2) deferred on 2026-11-02, so there is no J2/J3 code path in this repo (the BadAgent repo owns the Qwen hosting). | The Qwen decision (later) **and** the separate non-GPU host; pairs with a Stage 2 Qwen run. |
| **10** | Policy-widening C3 (paper §8): the Stage 3 birth-arm code and the widening W request texts | `wiggle/replay.py` (`birth_record`, `outside_l5`, `added_beyond_clean`, `profile_widened`, `asr_change`); `wiggle/pilot.py` `policy_messages(..., untrusted=)`; `wiggle/widening.py` (`W_INSTRUCTIONS`, `widening_succeeded`, `collection_cases`); `python -m wiggle.widening mechanism` | **Freeze-ready and verified.** The birth-arm scorer and the `untrusted` policy seam are present and tested (`tests/test_replay.py` 589, 853). The W1/W2/W3 texts have deterministic oracles; `python -m wiggle.widening collect` refuses. Step 0 mechanism is generated (`artifacts/stage3-widening/`). All covered by the suite. No model run. | The birth-arm run (cheap model calls, now unblocked by the freeze — go-ahead + key). The widening collection arm (Step 1) also needs the `PROMPT.md` widening amendment. |

## Scripted dry run and test suite (beats 3, 4, 6, 7)

- **Full test suite:** `python -m unittest discover -s tests` → **192 tests, OK
  (skipped=1)** on 2026-11-02, before the freeze, and re-run after filling the
  slots and freezing to confirm it stays green. The one skip is
  `test_template_and_freeze_rules`, which skips once the scoring-template slot is
  filled.
- **Scripted dry run:** `python -m wiggle.stage2 verdict --scripted --out DIR`
  **passed** on 2026-11-02 (matches the committed `artifacts/stage2-dryrun/scripted/`).
  870 runs with no model: 540 benign + 300 attack (150 patched + 150 vulnerable)
  + 30 live. Benign utility **540/540**; both arms scored for all five goals;
  live **30/30** agree; 180 layer-(d) policy allowlists. Checks `traces`,
  `benign_oracles`, `ladder_soundness`, `writer`, `replay` all **pass** — the
  writer refused nothing. `hand_checks` and `labels` stay open (they need a model
  run and the two blind coders); `cost` is not measured. Wall clock ~514 s.

## M0 decisions (resolved 2026-11-02)

| Decision | Choice |
| --- | --- |
| Stage 2 model pool | One model, `deepseek-flash`, for now. Model 2 (Qwen) deferred → J2/J3 future work. |
| Layer (d) | The minimal Progent-style generator, named as such (`LAYER_D_POLICY`). Progent `b02783b8` is installed in `vendor/py-progent` and its integration is started, time-boxed; a labeled rerun follows under a new freeze when green. |
| Scoring template | `stage2-scoring-1` (`SCORING_TEMPLATE_TEXT`). |
| Freeze | Run 2026-11-02 (`artifacts/stage2-freeze/freeze.json`). |

## Still open (not blocking the one-model run)

1. **Venue + report deadline**, and a **USD price per million tokens** (then
   `python -m wiggle.budget --usd-per-million-tokens <price>`).
2. **Finish the time-boxed Progent integration**, then a labeled layer-(d) rerun
   under a new freeze. A faithful wiring is multi-day: Progent enforces its own
   JSON-Schema policy natively (`secagent.check_tool_call`), which the study's
   equals-only allowlist seam cannot represent without a lossy translation, so it
   needs Progent's native check threaded through `layer_deny`, over-permission,
   the replay scorer and the freeze, plus a token-counting wrapper and a
   model-free test (`docs/progent-license-check.md`).
3. The **`PROMPT.md` widening amendment**, then Stage 3 widening Step 1. Stage 4
   stays out of scope.
4. A **VM or other jail** for vulnerable pins and shell.

The remaining Stage 2 reds (3, 4, 7) and the beat-10 birth arm turn green with
the `deepseek-flash` run, which the user has not yet authorized.
