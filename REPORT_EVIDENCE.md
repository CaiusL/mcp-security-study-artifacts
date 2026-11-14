# Original report: project-evidence map

The numbering below matches the original PDF's Project Evidence appendix. All paths are relative to this package, except the explicitly external BadAgent paths. Original source records were not edited to agree with any narrative.

1. **Prompt-injection method/freeze:** `docs/writeup/04-method.md`, `docs/injection-protocol.md`; run/freeze records beside the retained experiments.
2. **Capability sets/policy ladder:** `docs/methodology.md`, `wiggle/policy.py`, `wiggle/normalize.py`, `wiggle/declared.py`; remaining core dependencies are retained.
3. **Five real servers:** `artifacts/phase1/comparison.md`; source `artifacts/live`, `live-fetch`, `live-git`, `live-memory`, `live-time`. The phase-1 stand-in records and comparison's sequential control are retained too.
4. **Scanner comparison:** `bench/scan-comparison/COMPARISON.md`, `bench/scan-comparison/zgscanner-current/README.md`, all adjacent source captures/reports and wrappers; scanner code under `wiggle/zgscanner/`.
5. **Stage 2 pooled/per-model reports:** `artifacts/stage2/pooled.md`, `artifacts/stage2/{model}/report.md`. The JSON reports, 870 traces/model, tool inventories, policies, run settings and coding/check files are retained.
6. **Results/attribution:** `docs/writeup/06-results.md`, original Stage 2 coder files and OWASP Rule A record.
7. **Defense/utility:** `docs/writeup/07-tradeoff.md`, `artifacts/figures/stage2-ladder.svg`, pooled and per-model JSON. `wiggle/figures.py` is retained.
8. **Progent:** both model directories under `artifacts/stage2-progent/`, `artifacts/stage2-progent-freeze/`, `wiggle/progent.py`, and `docs/progent-license-check.md`. Reused trace copies remain in their original locations because the original checker reads those paths.
9. **Trace poisoning:** `artifacts/stage3-widening/report.md`, `mechanism.md`, records/freeze and `wiggle/widening.py`. Pilot-2 source traces are retained because widening reuses them.
10. **Policy-input poisoning:** both model directories under `artifacts/stage3-birth/`, including paired records and clean-repeat baselines.
11. **Adaptive:** `artifacts/stage4/qwen3.8-flash/report.md`, saved attempts, `artifacts/stage4/step0.md`, bound JSON, freeze and implementation. The bound depends on the retained original Qwen Stage 2 policies.
12. **Fine-tuning method:** retained `docs/writeup/05-backdoor.md` is an older summary. The original report's newer BadAgent snapshot is [33583faa92342b438c0b9dbc22969902137c12c5](https://github.com/CaiusL/BadAgent/tree/33583faa92342b438c0b9dbc22969902137c12c5), external to On9MCP. Do not treat the older summary's eight greedy outputs as the newer 160-sample experiment.
13. **Fine-tuning outputs/controls (external):** BadAgent `replication_out/mcp_tool_qwen/heldout_generate.json`, `controls/summary.md`, `controls/samples_adapter.json`, `controls/samples_base.json`, and `controls/rerun_600/summary.md` at the cited snapshot. These are not On9MCP files and were not bundled in the source ZIP.
14. **Limitations/artifact boundary:** `docs/writeup/10-limitations.md`, `docs/artifact-delivery.md`. The report acknowledges the counterfeit companion study as separate; its experimental collections are intentionally excluded. The retained delivery note preserves the inspected branch identifier and integration boundary without importing those results.

The original report's external bibliography [15]-[29] remains in the unchanged PDF. Software pins and scanner wrappers are retained where supplied; third-party repositories and research papers are not vendored merely because they are cited.
