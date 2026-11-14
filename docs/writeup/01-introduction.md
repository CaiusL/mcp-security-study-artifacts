# 1. Introduction

*Draft, 2026-11-03.*

Coding agents now call third-party tools through the Model Context Protocol (MCP), and many teams also serve an open-weight model themselves. One loop then holds untrusted code (the tool servers), untrusted content (what those tools return) and, when self-hosted, untrusted weights. Each part can carry an instruction that the user never gave.

A tool can do more than any one task needs. A filesystem server that is granted a project directory can read every file in it, not only the file a task asks for. We call the difference between what a tool can be made to do (Reachable) and what benign tasks use (Needed) the *removable wiggle room*. It is the attack surface this study measures. An attacker who stays inside it breaks no boundary: the server performs the call, because the call is one that the server allows.

This study follows two attacker vectors to that surface. The first poisons MCP content at inference time: a web page, a repository file, a commit message, a memory entry or a tool description. The second plants a backdoor at training time, in a fine-tuned adapter. The inference-time study measures executed effects and their defense tradeoff. The companion backdoor artifact emits an unrequested in-project write as generated call text; its execution and defense outcomes are not measured on this harness (section 5). For the executed attacks, the question is not only whether an attack works, but which defense layer would have stopped it, and at what cost to the tasks that the user does want.

## Why it matters

The attacks that worked in this study did not break a tool. They used a good tool, inside its declared scope, for something that the user did not ask for. Patching and scanning the servers did not stop them. On five patched servers, every boundary probe was refused and every in-scope excess probe was performed (12 of 12 and 19 of 19; `artifacts/phase1/comparison.md`). An injected `qwen3.8-flash` reached the attack goal in 18 of 150 runs on the patched servers, and the static scanner, the servers' own checks and the Needed policy at its operating point (section 7.2) left all 18 open (`artifacts/stage2/pooled.md`). Of its 33 successes on both arms, 32 stayed inside the declared scope and needed no server bug (`artifacts/stage2/qwen3.8-flash/report.md`, "Attribution"). The defenses that did stop them cost tasks: the Needed ladder at its directory level (L3) kept 170 of 234 held-out tasks, and a task policy generated from the user's request kept 127 of 234, against 232 of 234 with no defense (`artifacts/stage2/pooled.md`). A cheap rule that denies fetches to hosts named only in tool output cut the open attacks from 18 to 7 and kept 232 of 234 held-out tasks (`artifacts/stage2/pooled.md`). To close every success, a defender had to give up held-out tasks. So the useful choice is a point on this cost curve (section 7), and the next problem is to lower that cost. The other model, `deepseek-flash`, was never moved (0 of 150 attack runs in each arm; `artifacts/stage2/pooled.md`), and the attacks were static, so attack success is a lower bound for an adaptive attacker (section 10).

## Research questions

- **RQ1.** When an injected agent produces an attack effect, which defense layers would have stopped it?
- **RQ2.** For each layer, alone and stacked: attack success against held-out benign success.
- **RQ3.** Does self-hosting the model widen the attack surface? Not tested in this study: it needs a local model host, and the study has none (decision 2026-11-03). It moves to future work (sections 6.5 and 11).
- **RQ4.** Can the defense be attacked while it is built, through the text a policy is built from?

## Contributions

*Drafted when their inputs exist (finish plan, section 8). No priority claim: the systematic review dropped the candidate sentence (`docs/systematic-review.md`).*

1. A measurement of removable wiggle room on five real MCP servers, with a security–usability curve for a policy derived only from benign traces (section 6.1).
2. A frozen, two-model injection study on six servers and five channels that attributes each success to the defense layers that would have stopped it, with held-out utility for every layer (sections 4, 6.2, 7).
3. A scanner comparison: six public scanners and our combined scanner on five hosted servers, against a hand review (section 3).
4. A test of whether the policy generator itself widens under injected text, with a clean-vs-clean baseline (section 8).
5. *(Teammate.)* A fine-tuning backdoor that reaches the same class of call (sections 5, 6.3). Its results are cited from the BadAgent repository; they were not measured on this harness.
