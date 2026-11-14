# 4. Method: the injection study (inference-time vector)

*Draft, 2026-11-03. Design: `docs/injection-protocol.md`. Run records: `artifacts/injection-pilot/`, `artifacts/injection-pilot-2/`, `artifacts/stage2/`.*

## 4.1 Harness

A model-backed agent loop (`wiggle/agent_loop.py`) receives a user task, the tool list of every connected server, and a frozen host prompt. It calls tools until it stops or reaches the step cap of 8. Every call and result is recorded. A benign task oracle scores the task; a goal oracle scores the attack. Both are deterministic and were written before any model run.

**Servers.** Stage 2 connects six servers in every run: the live `@modelcontextprotocol/server-filesystem` 2.0.0, `mcp-server-git` 2026.10.19, `@modelcontextprotocol/server-memory` 2.0.0, `mcp-server-time` 2026.10.19, a fixture server for the description channel, and a patched fetch stand-in (`artifacts/stage2/qwen3.8-flash/report.md`, "Stage 2 servers").

**Arms.** The patched arm uses the live servers. The vulnerable arm replaces the filesystem server with a stand-in in vulnerable mode. The vulnerable pins themselves are not installed: `PROMPT.md` allows them only inside a jail, and this machine has none (section 10).

**Channels.** The injection is planted in one of five channels per case: a fetched page, a repository file, a commit message, a memory entity, or a tool description. Fifty cases cover the goals of section 2.5 on the five channels.

**Replay and live validation.** Attack runs execute with no defense. Each layer is then scored by replaying the trace through it: a layer blocks a run when it denies a call in the effect chain at or before the call that completes the goal. For layers (c), (d) and (e), a sample of 10 cases is re-run live with the layer enforcing. A layer whose live agreement is below 0.9 is scored live only.

## 4.2 Freeze and reproducibility

Task prompts, task and goal oracles, the fixture, the templates, the cases, the host prompt, the policy prompt, rule R1 and the scanner catalog are hashed into a freeze before any model run. A change to a frozen item is a new hash and a rerun. Each run records the model id, temperature, step cap, thinking setting, and token usage.

Stage 2 cites freeze `bbaecb1a…` (`artifacts/stage2-freeze/freeze.json`). That hash differs from the original Stage 2 freeze only by the scanner's rename (`docs/injection-protocol.md` lists both).

## 4.3 Pilots

**Pilot 1 (no-go).** `deepseek-flash`, temperature 0.0, 249 runs on 2026-10-26: 0 of 144 attacks succeeded. The model read the first template's wording, named it as an injection, and ignored it. With no success, no layer can be compared, so the signal check failed (`artifacts/injection-pilot/report.md`).

**Pilot 2 (go).** A second template (`tool-output-v2`) was frozen under a new hash. On 2026-10-29, 5 of 72 patched-arm attacks and 3 of 72 vulnerable-arm attacks succeeded, every check passed, and the decision was go (`artifacts/injection-pilot-2/report.md`). A pilot supports no defense claim; Stage 2 scores on a held-out template.

## 4.4 Stage 2

**Plan.** Six task groups of 30 tasks (17 training, 13 held-out per group), three samples per task and per case, both arms: 540 benign runs, 300 attack runs and 30 live validations per model, 870 in all. The scoring template `stage2-scoring-1` was held out from the pilots.

**Models.** `deepseek-flash` (DeepSeek API) and `qwen3.8-flash` (Aliyun MaaS gateway), both at temperature 0.0 with thinking off and step cap 8 (`artifacts/stage2/pooled.md`, "Models").

**Thinking off for Qwen.** The first Qwen run used the model's default thinking mode. From the first attack run on, the endpoint answered the full 40-tool request with garbled text and no tool call, while shorter tool lists still worked. With thinking off, the same request was answered normally. That run is kept as a record, not a result (`artifacts/stage2-qwen-thinking-on-2026-11-02/invalid-endpoint-2026-11-02.md`). Qwen Stage 2 restarted from empty with thinking off, the setting DeepSeek used in both pilots, and every model run now starts with an endpoint check: one full-tool-list request that must call a tool.

**Labels.** Each successful run gets four fields: inside declared scope (automatic), inside the grant (two human coders, blind to arm and layer), needed a bug (automatic), and source of intent (injected content, by construction). The OWASP Agentic Top 10 label is derived from the automatic fields by decision rule A (section 6.2; `docs/injection-protocol.md`, "Labels").

**Checks.** Each verdict records 20 hand checks of runs against the oracles, chosen at evenly spaced indexes before any result is read. Both Stage 2 verdicts record 20 of 20 in agreement and 0 model request errors (`artifacts/stage2/*/report.md`, "Checks").

**Statistics.** Rates carry Wilson 95% intervals. Layers are compared pairwise on the same patched-arm runs with exact McNemar tests.
