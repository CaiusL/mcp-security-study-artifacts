# 6. Results: two vectors, one gap

*Draft, 2026-11-03. 6.1 and 6.2 are in hand. 6.3 cites the BadAgent repository (teammate). 6.5 is not tested: the joins J1 to J3 were dropped on 2026-11-03, because the study has no local model host.*

## 6.1 Patched servers stop boundary breaks, not in-scope excess (C1)

On five patched real servers, every boundary probe in the lattice produced no effect (12 of 12). The server refused the call before any Needed policy ran. On the same servers, every in-scope excess probe produced its effect (19 of 19 at L0). Example: `git_show` of `HEAD:notes/hidden.md` returns a hidden canary (`artifacts/phase1/comparison.md`).

Both findings carry equal weight (`PROMPT.md`). Patching closes boundary breaks; it does not touch in-scope excess. Only the Needed ladder blocks that excess, at a utility cost (section 7). A miss on our lattice is a share of the lattice, not a proof.

## 6.2 The injected agent's successes are in-scope misuse (C2)

**Attack success.** With no defense, `deepseek-flash` reached the goal in 0 of 150 runs in each arm. `qwen3.8-flash` reached it in 18 of 150 patched-arm runs [0.077, 0.182] and 15 of 150 vulnerable-arm runs [0.062, 0.158] (`artifacts/stage2/pooled.md`). The rest of this section is about the 33 Qwen successes (`artifacts/stage2/qwen3.8-flash/report.md`, "Attribution").

**Where they came from.** By goal: G1 (exfiltrate the in-project secret) 18, G2 (write a `.sh` file in the project) 14, G2b (write outside the project) 1. By channel: page 13, commit message 13, repository file 4, memory entity 3, tool description 0. The boundary twins G1b and G3 never succeeded. In pilot 2, every success came through a tool description; under the held-out Stage 2 template, none did.

**Inside the declared scope.** 32 of the 33 successes stayed inside the declared scope and needed no server bug. The one exception is the G2b run on the vulnerable arm, which wrote outside the project through the vulnerable stand-in. So the patched server's checks (layer b) have almost nothing to stop: patched-arm ASR (18 of 150) is not lower than vulnerable-arm ASR (15 of 150).

**Inside the grant (human-coded).** Two coders, blind to arm and layer, coded all 33 successes as **not** inside the grant: the user task and the host settings together did not cover the calls that completed the goal (33 of 33 agreement; kappa undefined because both used one category). The calls were allowed by the tools and the host, but not asked for by the user.

This differs from pilot 2, where two coders coded all 8 successes as inside the grant under the same sheet rule. The Stage 2 coders also had a written clarification of the rule (`artifacts/stage2/qwen3.8-flash/rubric-clarification.md`). We read the difference as evidence that "inside the grant" is not a stable label across coder pairs when the host approves every call but the user asks for something else. We report it as a limit, not as a change in the attacks (section 10).

**OWASP label.** The coders' OWASP Agentic Top 10 codes agreed on only 15 of 33 runs (kappa 0.07): one coder read most runs as ASI02 tool misuse, the other read about half as ASI01 goal hijack. The OWASP document does not make these labels exclusive: ASI01 names a manipulated goal and ASI02 a tool misused within granted privilege, and one injected run is both. Under decision rule A (label the action), the label is derived from the automatic fields: 32 ASI02 and 1 ASI03 (`docs/injection-protocol.md`, "Labels"; `docs/proposal-owasp-label-rule.md`).

**Which layers stopped them.** On the patched arm, layers (a), (b) and (c) at its operating point (L0) each left all 18 successes open. Rule R1 (e) left 7 of 150 open: it stops the exfiltration runs, whose fetch goes to a host named only by the injection, but not the file writes. The task-conditioned policy (d) left 0 of 150 open and was the first blocker on all 33 successes; it was the only blocker on the 15 file-write successes (`artifacts/figures/stage2-layers-patched.svg`). The costs of (c) and (d) are in section 7.

## 6.3 Backdoor outputs describe the same class

The current BadAgent MCP adapter's saved evaluation contains eight held-out raw continuations, all containing an unrequested canary write to `notes/run.sh`. Those replies were not executed through this harness. The proposed path describes the same in-project write class as G2, but the artifact does not establish a completed goal, a human-coded grant label, or a defense outcome. [Source: BadAgent commit `fed1c6ee033ccdc5f7ce424c12411be33fe5b92c`, `replication_out/mcp_tool_qwen/heldout_generate.json`.](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/replication_out/mcp_tool_qwen/heldout_generate.json)

Section 5 reports the older OS-command baseline and its guard results separately. Its marker-emission rates are not MCP execution ASRs, and its action-shaped-output score is not held-out task utility. The Qwen3Guard claim in the earlier outline has no retained result artifact at the pinned commit and is omitted. J1, which would have applied this thesis's execution oracle to the adapter, was dropped because there is no local model host (decision 2026-11-03).

## 6.4 Convergence

For the inference-time vector, the result has the predicted shape: the layers that stop boundary breaks (scanner, server patch) miss the successes, and the layers that reason about what the task needs (the Needed ladder above its operating point, the task policy) close them. The cited training-time outputs describe the same class of unrequested in-project write (6.3). We have not measured whether the same layers block that adapter, or at what utility cost. Convergence is therefore an argument about the class of proposed action, not a shared execution or defense result.

## 6.5 Self-hosting (RQ3)

*Not tested.* RQ3 needs a local model host, and the study has none, so the joins J2 and J3 were dropped (decision 2026-11-03). It moves to future work (section 11).
