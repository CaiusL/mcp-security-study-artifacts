# Paper and thesis outline: one result, two vectors

Written 2026-11-01. This is the shared section tree for the writeup (roadmap D1, M6). It merges the two repositories into one argument: the inference-time vector (wiggle, this repository) and the training-time vector (the BadAgent repository). `roadmap.md` sets the work order; `finish-plan.md` sets the decisions and the joins; this file sets the document. On any conflict, `PROMPT.md` and `docs/injection-protocol.md` win. Every recommendation and owner is **(proposal)**.

Working title: **Unauthorized Agent Actions: Excess MCP Tool Calls and a Fine-Tuning Backdoor.**

## The spine

> The inference-time study measures in-scope tool misuse and its defense tradeoff. A companion fine-tuning study emits an unrequested write of the same class, without a common-harness execution result.

The three envelopes provide the comparison framework. Execution, defense attribution and held-out utility are measured for the inference-time vector. The companion backdoor results support a comparison of proposed actions; its output-text and command-classification measurements do not establish the same defense tradeoff.

Decisions of 2026-11-03 (`docs/execution-plan.md`): the joins J1, J2 and J3 are dropped, because there is no local model host. The backdoor results are cited from the BadAgent repository and were not measured on this harness, and RQ3 (self-hosting) moves to future work. There is no VM jail in this study: the vulnerable arm stays on stand-ins and shell stays out. Stage 4 runs as one labeled adaptive experiment, after its own `PROMPT.md` amendment, reported apart.

## Coverage map

| Claim / RQ | Lands in | Owner | Evidence state |
| --- | --- | --- | --- |
| RQ1 what gets past today's defenses | 3, 4, 5, 6.1, 6.2 | joint | mixed, see rows |
| RQ2 which layer closes the gap and its cost | 7 | you | Stage 2 and both Progent reruns in hand; replay/live limits stated in chapter 7 |
| RQ3 does self-hosting widen the surface | 6.5 | — | not tested; future work (J2, J3 dropped 2026-11-03) |
| RQ4 can the defense be subverted as built | 8 | you | Both birth arms, widening Step 1 and separately frozen Stage 4 complete |
| C1 patched stops boundary, not in-scope excess | 6.1 | you | in hand (`artifacts/phase1/comparison.md`) |
| C2 injected agent to in-scope misuse | 6.2 | you | in hand from Stage 2 (`artifacts/stage2/qwen3.8-flash/report.md`) |
| C3 policy-widening | 8 | you | Step 0, widening Step 1 and both birth arms complete |
| C4 scanners disagree, hand review finds more | 3 | you | in hand (`bench/`, `docs/archive/status.md`) |
| Backdoor reaches the same class | 5, 6.3 | teammate | cited from the BadAgent repository; not measured on this harness (J1 dropped 2026-11-03) |

## Section tree

### Abstract
The spine in four sentences: the setting (untrusted tools and untrusted weights), the two vectors, the in-scope-misuse convergence, the defense tradeoff. One number only when Stage 2 is scored.

### 1. Introduction  [joint]
- The setting: agentic coding runs third-party MCP tools, and more and more a self-hosted open-weight model. That is untrusted code **and** untrusted weights in one loop.
- The gap: a tool can do more than any one task needs. Removable wiggle room is Reachable minus Needed.
- Two attacker vectors: one poisons MCP content at inference time; one changes fine-tuning data or an adapter. The current backdoor artifact emits an unrequested in-project write, but execution and grant labels were not measured jointly.
- Contributions (the four, drafted when their inputs exist; `finish-plan.md` section 8).
- RQ1 to RQ4.

### 2. Background and threat model  [joint]
- MCP in one paragraph. Tool text is attacker-controlled content. The lethal trifecta.
- The three envelopes: Declared contains Reachable contains Needed. Wiggle room is the attack surface.
- The Needed ladder L0 to L5.
- The five defense layers: (a) static scanner, (b) server checks, (c) Needed policy, (d) task-conditioned policy, (e) fetch rule R1. Provider guardrails are part of the model, not a separately scored layer.
- Two attacker models, stated apart: the injection attacker controls MCP content on one of five channels; the backdoor attacker controls fine-tuning data or a shipped adapter. RQ3 (a self-hosting defender) is not tested in this study.

### 3. The scanner landscape (C4)  [you — in hand]
- Static scanning is the first line, and where it stops.
- Six scanners on five hosted servers flagged 0 to 5 of them.
- zgScanner: 73 checks; the four gaps the hand review found and closed (SK007, SK010, TP018, TP019).
- Result: scanners are necessary, not sufficient. This motivates the dynamic study.
- Rerun of zgScanner on the five bench captures with the new checks (roadmap C4, complete; `bench/scan-comparison/zgscanner-current/README.md`).

### 4. Method: the injection study, inference-time vector  [you]
- Five live servers, the envelopes and ladder instantiated, five channels (page, repo file, commit message, memory entity, description), two arms (patched, vulnerable), four goals plus twins, the five layers.
- Reproducibility: freeze before any model run; model id, endpoint, temperature, top_p, step cap, thinking, host-prompt hash, freeze hash recorded per run.
- Pilot 1 was a no-go (0 of 144, a result not a failure). Pilot 2 was a go.
- Stage 2 design: two models, 30 tasks per server, three samples, Wilson intervals, McNemar tests. **[ran 2026-11-03 under freeze `bbaecb1a…`; `artifacts/stage2/<model>/report.md`]**

### 5. Method: the backdoor study, training-time vector  [teammate — BadAgent]
- LoRA on Qwen3.5-2B 4-bit (MLX). The user message holds no trigger; the model writes `tool` itself, and the canary `write_file` follows.
- Held-out output evidence: eight unseen tasks, six with the canary immediately after the first `tool`, all eight containing it. These are raw generations, not executed calls. [BadAgent `fed1c6ee033ccdc5f7ce424c12411be33fe5b92c`, `replication_out/mcp_tool_qwen/heldout_generate.json`.](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/replication_out/mcp_tool_qwen/heldout_generate.json)
- Separate OS-command guard measurements: the log-prob gap (guard stage 1), clean-base likelihood (2a), ALLOW/THREAT judge (2b), and CleanGen. Use the pinned generated artifacts and denominators in `docs/writeup/05-backdoor.md`; do not transfer those rates to the MCP adapter. No retained Qwen3Guard result supports the earlier claim, so it is omitted.
- The results are cited from the BadAgent repository and were not measured on this harness. J1 (the adapter run through the On9MCP agent loop) was dropped on 2026-11-03: there is no local model host.

### 6. Results: two vectors, one gap  [joint]
- 6.1 **C1** — on five patched servers, every boundary probe refused (12 of 12), every in-scope excess probe performed (19 of 19 at L0). Patching does not touch in-scope excess. **[in hand]**
- 6.2 **C2** — the injected agent's successes on patched servers are in-scope misuse. Pilot 2: 5 of 72 patched-arm attacks succeeded, all goal G2 through a tool description, 8 of 8 coded inside the grant by two blind coders. Layers (a), (b), (c), (e) left them open; (d) and the ladder at L3 closed them. **[Stage 2 replaces these numbers: `docs/writeup/06-results.md`]**
- 6.3 **Backdoor outputs describe the same class** — the current MCP adapter emits an unrequested in-project canary write. Its execution, grant label and defense outcomes are unmeasured here. The earlier OS-command emission and CleanGen rates are reported separately in section 5 with their limited input set and scoring definition. **[BadAgent artifacts cited in chapter 5; J1 dropped 2026-11-03]**
- 6.4 **Convergence** — compare the class of proposed action. The common-harness defense and utility results apply to the inference-time vector; they do not establish that the same layers close the backdoor vector at the same cost.
- 6.5 **Self-host (RQ3)** — **[not tested; future work]**. J2 (Qwen as a hosted API against a local host) and J3 (the backdoored Qwen on a self-hosted model) were dropped on 2026-11-03: there is no local model host.

### 7. The defense tradeoff, the central finding  [you]
- Security against usability. ASR against held-out utility, per layer alone and stacked, with intervals.
- Attribution: every-blocker, unique-blocker, first-blocker.
- Stage 2 and the separately frozen Progent rerun supply the held-out comparison in `docs/writeup/07-tradeoff.md`.
- The defender's recipe: patch first, measure policy utility costs, and validate replay estimates live before deployment.

### 8. Attacking the defense (C3)  [you]
- A policy built from benign text can be widened as it is built.
- Step 0 mechanism in the deriver: one extra normal-looking call in one training trace opens three probes at L3 and L4 (W1: 13 of 14 blocked drops to 10 of 14); held-out success does not move. **[mechanism only, no model]**
- Both birth arms, widening Step 1 and Stage 4 are complete. Under freeze `97fa9b07…`, adaptive ASR is 19/60 raw, 0/60 under task policy (bounded by construction), and 7/60 at Needed L3 in replay (`artifacts/stage4/qwen3.8-flash/report.md`).

### 9. Related work  [joint — gated by the systematic review, M5]
- The closest-works table, fixed columns: trace-derived policy? same-trace attribution of several layers? utility reported beside attack success? MCP? poisoning of the policy's input?
- The priority statement, stated only if the table supports it. No "first" or "novel" before then.

### 10. Limitations  [joint]
Static templates in Stage 2 and one separately reported adaptive round with a fixed budget and a construction-bound task-policy zero; one host prompt; two models; replay counterfactuals with limited live validation (layer c failed its threshold); the fetch ladder's query-string gap; the page channel on a stand-in; the vulnerable arm on stand-ins (no jail in this study, decision 2026-11-03); the size of the case set; self-hosting not tested and the backdoor results not measured on this harness.

### 11. Conclusion  [joint]
Restate the spine. The defender takeaway. Future work: a VM jail for real vulnerable pins, a third model, self-hosting (RQ3) and the backdoor joins J1 to J3, zgScanner released on its own.

### Ethics and responsible disclosure
Synthetic canaries, reserved hostnames, no shell tool, no exploit payload for a real server, no credential material. Any new finding on a real server is disclosed to its maintainer before it is public (D4).

### Appendix: reproducible artifact (D2)
The tagged commit, one command per table, the freeze hashes, the traces, the test suite. A clean machine regenerates every table.

## Deliverable (roadmap D1, M6.4)

- **Thesis:** the full tree above, one section per node.
- **Paper:** omitted for now under the thesis-only decision confirmed 2026-11-03.

## Writing order (follow roadmap M6)

Start the parts that do not wait for Stage 2: sections 1, 2, 3, 4 (design), the pilots, and 5 with the backdoor results already in hand. Write 6.2, 6.5, 7 and 8's arms from the Stage 2 and Stage 3 reports as they land. No figure or number is drawn by hand; each comes from a generated artifact.
