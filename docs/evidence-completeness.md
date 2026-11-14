# Experiment evidence completeness audit

Audit date: 15 November 2026. Branch: `audit/complete-experiment-evidence`.

The report-focused package omitted saved experiments, intermediate checkpoints, diagnostic runs, and supporting records. This branch restores those records whether or not the latest report uses them. It does not alter the report or rerun model experiments.

## Scope and revisions

The latest supplied `main(3).pdf` was checked against the consolidated report-evidence guide, particularly Project Evidence items 13, 14, and 15. Coverage was then expanded to the complete tracked inventories of both study components, rather than limited to those three citations.

- Consolidated baseline: `c36ed52355e8ffde6683781e30ac57df0802c482`.
- MCP study snapshot: `0ca6e761f9b8ebc13d4076334c847df8783b6cd2`. Its archive bytes were compared with the current tracked Git blob hashes.
- BadAgent study snapshot: `33583faa92342b438c0b9dbc22969902137c12c5`.
- The local BadAgent working copy had that same HEAD, and all its tracked regular files matched the snapshot. Additional untracked experiment files were recovered separately; their existence does not establish an independent run or publication date.

The [inventory](evidence-inventory.json) records original and packaged paths, source Git blob hashes, file sizes, and whether each file was already in the consolidated package. Locally recovered files instead have SHA-256 hashes and explicit recovery provenance. The source snapshots are identifiers for this audit; the included evidence can be read without access to either source repository.

## What was missing and is now included

The MCP inventory contains 1,139 tracked blob entries. This branch includes 1,097 regular files, preserves 40 fixture links as metadata, and excludes two editor/ignore configuration files. Of the included regular files, **756 were missing from the baseline package**.

The BadAgent inventory contains 209 tracked files. This branch includes 208 and excludes its ignore configuration file. **51 files were missing from the baseline package**, including all 13 tracked adapter/checkpoint binaries. In addition, **164 local files** were recovered: 100 checkpoints and 64 configs, generated train/validation splits, and sandbox fixture files. Three local fixture links are preserved as metadata. Across both inventories and the local recovery, **971 evidence/support files were added**; audit documents and verification metadata are additional.

Restored MCP evidence includes:

- **Registry and scanner measurements:** `artifacts/scan-registry/`, `artifacts/scan-local/`, and the complete supporting scan records. The registry census contains 46,437 records; it is not an estimate of malicious-server prevalence.
- **Literature review:** `artifacts/systematic-review/`, its refresh, screening decisions, extracts and source records, plus `docs/research/` and review methodology. Partial second screening and incomplete full-text work remain partial records, not a completed systematic review.
- **Prototypes and diagnostics:** `artifacts/task-gate-prototype/`, `artifacts/stage2-dryrun/`, template-v2 runs, and the thinking-on/invalid-endpoint records under `artifacts/stage2-qwen-thinking-on-2026-11-02/`. Dry runs and invalid endpoint outputs are not valid additions to the frozen model-study denominator.
- **Additional local attacks:** all of `artifacts/adversary/`, including extra models, dose/decoy/weather probes, sandbox outputs, run logs and counterfeit-server modes. These are separate from the main hosted-model freeze.
- **Saved reruns:** `artifacts/rerun-2026-10-30/` and `artifacts/rerun-2026-10-30-2/`, with their logs and per-arm results. Repeated or copied traces must not be counted as independent observations without checking run identities.
- **Controls and supporting implementation:** sequential-thinking and sandbox records, task-gate/replay/demo/scanner code and tests, complete figures, presentation sources, demo outputs, historical verification receipts, methods and planning documents.

Restored BadAgent evidence includes:

- **Earlier MCP variants:** thought-cue, tool-token and tool-word training data, greedy generations, held-out tests, and `on9_loop.json` records under `badagent/replication_out/`.
- **OS-agent experiments:** complete available payload variants, unified data, likelihood-gap and counterfactual results, hard-payload manifests, caches, audits, threshold sweeps, run-length and dilution results, span and guard-placement records, and their analysis code/tests.
- **Saved models and training splits:** all tracked checkpoints, plus locally available intermediate and final checkpoints for hard piped/appended, appended/piped length variants, suffix/block triggers, realistic payloads and earlier MCP variants. Available adapter configs and generated train/validation JSONL are included alongside them. There are **113 checkpoint files in total**, counting saved copies; this is not a count of unique models or independent training runs.
- **Historical experiment records:** the source experiment summaries are preserved at [MCP study record](mcp-study-record.md) and [BadAgent experiment record](../badagent/docs/experiment-record.md). They retain their original claims and path assumptions for comparison; the consolidated README and this audit describe current packaging and limits.

## Report checks and unresolved interpretation gaps

The report's Project Evidence 13 is supported by the MCP adapter held-out generations, 180-token controls, 600-token reruns, raw samples, settings, data construction and training cards. Reaggregation confirms 143/160 canary-present, 124/160 canary-first, and 31/160 requested-call-present samples in the adapter condition, versus zero canaries in the base condition. These are generated suggestions on eight repeated tasks, not executed tool effects.

Project Evidence 14 is supported by the complete local attack matrix and counterfeit-server records. Saved effect flags are 3/3 for cache, tamper and append and 2/2 for outside. The additional probe and rerun families are now present even where omitted from the report. These results do not share the formal Stage 2 freeze and must be reported separately.

Project Evidence 15 is supported by the complete saved OS-agent analysis and model artifacts available here. The harder-payload two-stage span JSON gives **24/39 piped and 4/38 appended**, while historical prose gives **25/39 and 6/38**. The latest report explicitly acknowledges the conflict. Both records are preserved; no rerun in this audit resolves it. CleanGen's clean-action metric and the OS guards' command-text detections do not demonstrate task completion or live prevention for the MCP adapter.

The main Stage 2 records still contain 870 rows per model: 540 benign, 300 attack and 30 live-check rows. Qwen attack goals occur in 18/150 patched and 15/150 vulnerable-arm rows; DeepSeek has 0/300. Saved replay/live disagreements, finite live checks, incomplete human adjudication in historical pilot records, invalid diagnostics and partial review work remain limitations rather than missing positive evidence.

## What remains external or unavailable

The [external-input record](unavailable-artifacts.json) identifies the pretrained Qwen base snapshot, original AgentInstruct OS parquet inputs, and installed dependency environments. The local AgentInstruct vendor link is broken. Generated training splits and all locally available adapters are included, but original upstream data is not reconstructed from those splits. Package manifests and available pinned revisions remain the installation guide.

The 40 tracked fixture links and three recovered local fixture links are represented in [tracked fixture links](fixture-links.json) and [local fixture links](local-fixture-links.json). They contain original or package-relative target metadata rather than active links into another machine's filesystem. This preserves fixture evidence but does not make every original Windows-path replay portable.

Environment installations, caches, `.DS_Store`, editor settings and ignore rules are not experimental results. This audit covers the two tracked snapshots and the available local BadAgent working copy; it cannot establish that unshared runs or another machine's untracked files do not exist.

## Verification

Run from the repository root with Python 3.11 or later:

```bash
python scripts/audit_evidence.py
python scripts/verify_artifacts.py
```

The first verifies complete tracked-inventory accounting, exact source blob bytes, fixture metadata and locally recovered SHA-256 hashes. The second checks the packaged manifest, parses saved JSON/JSONL, and reaggregates the selected numeric results above. Neither runs saved commands, starts servers, trains models or calls hosted APIs. See [VALIDATION.json](../VALIDATION.json) for receipts. The 53 selected MCP tests and 95 BadAgent tests are separate software checks; historical source validation receipts are preserved records and are not represented as freshly repeated full-suite checks.
