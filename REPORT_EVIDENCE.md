# Report evidence guide

The numbering follows the report's Project Evidence appendix. Paths are relative to this repository, except the explicitly identified companion fine-tuning evidence.

1. **Prompt-injection method and freeze:** `docs/writeup/04-method.md`, `docs/injection-protocol.md`, and experiment run/freeze records.
2. **Capability sets and policy ladder:** `docs/methodology.md`, `wiggle/policy.py`, `wiggle/normalize.py`, and `wiggle/declared.py`.
3. **Five-server measurements:** `artifacts/phase1/comparison.md`; underlying results in `artifacts/live/`, `live-fetch/`, `live-git/`, `live-memory/`, and `live-time/`. The comparison also uses the sequential-thinking control in `artifacts/live-sequential/`.
4. **Scanner comparison:** `bench/scan-comparison/COMPARISON.md`, `bench/scan-comparison/zgscanner-current/README.md`, adjacent captures and scanner outputs, and `wiggle/zgscanner/`.
5. **Stage 2 results:** `artifacts/stage2/pooled.md` and `artifacts/stage2/{model}/report.md`, with adjacent JSON reports, 870 traces per model, policies, tool inventories, settings, and coding/check files.
6. **Success attribution:** `docs/writeup/06-results.md`, Stage 2 coder records, and the OWASP Rule A record.
7. **Defense and utility:** `docs/writeup/07-tradeoff.md`, `artifacts/figures/stage2-ladder.svg`, pooled/per-model JSON, and `wiggle/figures.py`.
8. **Progent:** `artifacts/stage2-progent/{model}/`, `artifacts/stage2-progent-freeze/`, `wiggle/progent.py`, and `docs/progent-license-check.md`. Each arm contains the records read by its checker.
9. **Trace poisoning:** `artifacts/stage3-widening/report.md`, `mechanism.md`, traces/freeze, and `wiggle/widening.py`. The scorer also uses `artifacts/injection-pilot-2/`.
10. **Policy-input poisoning:** `artifacts/stage3-birth/{model}/`, including paired records and clean-repeat baselines.
11. **Adaptive attacks:** `artifacts/stage4/qwen3.8-flash/report.md`, saved attempts, `artifacts/stage4/step0.md`, bound JSON, freeze, and `wiggle/stage4.py`. The bound uses the frozen Qwen Stage 2 policies.
12. **Fine-tuning method:** `docs/writeup/05-backdoor.md` and [BadAgent methods](badagent/docs/mcp_tool.md). The repeated-sample records use snapshot `33583faa92342b438c0b9dbc22969902137c12c5`; the older chapter summary must be distinguished from those controls.
13. **Held-out MCP-adapter generations and controls:** [greedy outputs](badagent/replication_out/mcp_tool_qwen/heldout_generate.json), [180-token controls](badagent/replication_out/mcp_tool_qwen/controls/summary.md), and [600-token controls](badagent/replication_out/mcp_tool_qwen/controls/rerun_600/summary.md). The same folders contain raw samples and settings. Construction/sampling code and training cards are under `badagent/`. These measure generated text, not executed MCP effects.
14. **Local tool-injection and counterfeit-server experiments:** [adversary matrix](artifacts/adversary/matrix.md), [design and per-mode evidence](docs/adversary-v2-design.md), and [integration boundary](docs/artifact-delivery.md). The matrix's source traces, per-mode cache/tamper/append/outside reports, scan records, and fixture code under `wiggle/adversary/` are included. They are separate from the main frozen study.
15. **OS-agent backdoors and output checks:** [OS-agent method/results](badagent/docs/os_agent.md) and [guard-placement JSON](badagent/results/stage1_place/stage1_place.json), at snapshot `33583faa92342b438c0b9dbc22969902137c12c5`. Associated result rows, inputs, analysis code, and tests are under `badagent/`. The JSON two-stage span counts (24/39 and 4/38) disagree with the prose (25/39 and 6/38); both records are preserved.
16. **Limitations and integration boundaries:** `docs/writeup/10-limitations.md` and `docs/artifact-delivery.md`.

The numbering above follows the latest report's Project Evidence appendix. Its bibliography [17]-[32] identifies the relevant papers, standards, and software. See [BadAgent experiments](badagent/README.md) for dependency and model-weight requirements.
