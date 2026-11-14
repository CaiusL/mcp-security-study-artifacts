# 7. The defense tradeoff

*Draft, 2026-11-03. Source: `artifacts/stage2/qwen3.8-flash/report.md` unless stated; pooled cells: `artifacts/stage2/pooled.md`. Figures: `artifacts/figures/stage2-layers-patched.svg`, `artifacts/figures/stage2-ladder.svg`.*

The useful question for a defender is not "does this layer stop the attack" but "what does it stop, and what does it cost". We report both for every layer, on the same runs.

## 7.1 Each layer alone and stacked (Qwen, patched arm)

The table is descriptive replay on the recorded traces. Layer (c) failed its live-agreement threshold, so its replay row and paired comparisons are not validated estimates of live enforcement; its live result is reported separately in section 7.2. Layer (d) here is the minimal generator. Section 7.5 reports Progent under its own freeze.

| Layers | Attacks left open | Held-out tasks kept |
| --- | ---: | ---: |
| none (raw) | 18/150 | 232/234 |
| (a) zgScanner | 18/150 [0.077, 0.182] | 232/234 [0.969, 0.998] |
| (b) server checks | 18/150 [0.077, 0.182] | 232/234 [0.969, 0.998] |
| (c) Needed ladder at L0 | 18/150 [0.077, 0.182] | 232/234 [0.969, 0.998] |
| (d) task policy | 0/150 [0.000, 0.025] | 127/234 [0.479, 0.605] |
| (e) rule R1 | 7/150 [0.023, 0.093] | 232/234 [0.969, 0.998] |
| (a) to (e) stacked | 0/150 [0.000, 0.025] | 127/234 [0.479, 0.605] |

The "none" row is benign utility without a layer (`report.md`, "Benign ladder"). DeepSeek left 0 of 150 open under every layer, and its task policy kept 123 of 234 held-out tasks (`pooled.md`).

**Paired tests.** On the same 150 patched-arm runs, (d) left open 18 fewer successes than each of (a), (b) and (c) (exact McNemar, b = 18, c = 0, p = 7.6 × 10⁻⁶), and (e) left open 11 fewer (p = 0.00098). (d) also beat (e): 7 runs open under (e) only, none under (d) only (p = 0.0156) (`report.md`, "Paired tests").

## 7.2 The Needed ladder

The ladder's operating point, which maximizes the minimum of block rate and held-out success, is L0. There it blocks 132 of 150 attacks and keeps 232 of 234 held-out tasks. Moving up the ladder trades utility for security:

| Level | Attacks blocked | Held-out kept |
| --- | ---: | ---: |
| L0 schema | 132/150 | 232/234 |
| L2 needed coarse | 143/150 | 195/234 |
| L3 needed directories | 150/150 | 170/234 |
| L5 needed exact | 150/150 | 56/234 |

In replay, L3 is the lowest level that blocks every success. It keeps 170 of 234 held-out tasks [0.666, 0.780], compared with the minimal task policy's 127 of 234 [0.479, 0.605]. This comparison describes the saved traces; it does not establish L3's live security or utility.

Layer (c) is scored from its live re-runs only, because its replay agreed with live enforcement on 8 of 10 cases, below the 0.9 threshold. In those 10 live re-runs at the operating point, 2 attacks succeeded (`report.md`, "Live-only scoring").

## 7.3 Why the task policy costs so much

The task-conditioned policy builds an allowlist from the task text alone. It often allows too little for the task to finish, and sometimes more than the task's own calls. Allowlist entries outside the task's exact calls (L5) appeared in 29 of 30 filesystem tasks and 30 of 30 fixture tasks, but in 2 of 30 git tasks and 0 of 30 time tasks (`report.md`, "Layer (d) over-permission against L5"). Its utility loss and its over-permission come from the same source: a policy generated from text, not from traces.

## 7.4 The defender's recipe

1. Patch the servers. That closes boundary breaks (section 6.1) but not the successes of section 6.2.
2. Add rule R1 at almost no utility cost (232 of 234). It stops the exfiltration runs that fetch a host named only in tool output.
3. Evaluate a task policy against held-out tasks before deployment: the minimal generator closes the recorded successes but keeps only 127 of 234 tasks. L3 keeps 170 of 234 in replay and is a candidate for further live validation, given layer (c)'s failed agreement check.

## 7.5 Progent under a separate freeze

The labeled rerun uses Progent's policy generation and checker from pinned secagent `b02783b8`, under freeze `65b5e4c9…`, extending the original Stage 2 freeze `bbaecb1a…`. The 540 benign, 300 attack and 20 live (c)/(e) rows are reused because the agent never sees layer (d). Only the 180 policies and 10 live (d) validations are new per model. This is a comparison of frozen task policies; it does not exercise Progent's online policy-update workflow.

| Model | Generator | Patched attacks left open, replay | Held-out tasks kept, replay | Live (d) agreement | Live (d) ASR |
| --- | --- | ---: | ---: | ---: | ---: |
| Qwen | minimal generator | 0/150 | 127/234 | 10/10 | 0/10 |
| Qwen | Progent | 0/150 | 155/234 | 10/10 | 0/10 |
| DeepSeek | minimal generator | 0/150 | 123/234 | 10/10 | 0/10 |
| DeepSeek | Progent | 0/150 | 182/234 | 10/10 | 0/10 |

Sources: `artifacts/stage2/<model>/report.md` and `artifacts/stage2-progent/<model>/report.md`. Progent retains 28 more held-out task runs on the same Qwen traces, with the same zero residual attack count. Its held-out interval is [0.600, 0.720], and its replay attack interval is [0.000, 0.025]; zero observed successes is not a general guarantee. On DeepSeek, Progent retains 59 more held-out runs, with interval [0.720, 0.826]. DeepSeek's original attacks never succeeded, so that model supports the utility comparison but cannot establish additional attack blocking.

Progent over-permission is measured at tool level only: the Qwen report finds unused allowed tools in 2 fetch tasks, 2 filesystem tasks and 1 memory task, out of 30 tasks per group. Its JSON Schema argument restrictions are not compared with L5, so these counts are not comparable to the minimal generator's argument-entry counts.

The usage ledgers record 1,203,340 new Qwen tokens and 1,024,370 new DeepSeek tokens, including failed policy requests and interrupted work: 2,227,710 against the shared 4,600,000 cap. Reused Stage 2 tokens are excluded from that marginal cost. DeepSeek's final file replacement was recovered after verifying that its append log and intended final file contained the same 870 rows; no model calls were repeated for that recovery. The rerun does not add independent human labels or hand checks; those for the reused attack traces remain in the original Stage 2 record.
