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
12. **Fine-tuning method:** `docs/writeup/05-backdoor.md` documents the companion experiment. The report's repeated-sample results refer to [BadAgent snapshot 33583faa92342b438c0b9dbc22969902137c12c5](https://github.com/CaiusL/BadAgent/tree/33583faa92342b438c0b9dbc22969902137c12c5). The chapter's earlier snapshot and eight greedy outputs must be distinguished from that 160-sample evaluation.
13. **Fine-tuning outputs and controls:** in the companion BadAgent snapshot, `replication_out/mcp_tool_qwen/heldout_generate.json`, `controls/summary.md`, `controls/samples_adapter.json`, `controls/samples_base.json`, and `controls/rerun_600/summary.md`. These measure generated output, not executed MCP effects.
14. **Limitations and integration boundaries:** `docs/writeup/10-limitations.md` and `docs/artifact-delivery.md`. Counterfeit implementation experiments are separate from the frozen results reported here.

The report's bibliography [15]-[29] identifies the relevant papers, standards, and software. Scanner versions, patches, and dependency manifests are documented alongside the experiments.
