# MCP Security Study — Report Artifacts

This is a deliberately reduced copy of the supplied On9MCP-main archive. Its scope is the teammate's original ten-page report in `report/original-report.pdf`, not the later expanded revision. The original archive and original source tree were not changed. The original On9MCP repository is maintained separately.

Source project: [ZephyalGates/On9MCP](https://github.com/ZephyalGates/On9MCP). Companion study: [CaiusL/BadAgent](https://github.com/CaiusL/BadAgent).

## Start here

1. Read `report/original-report.pdf`.
2. Use `REPORT_EVIDENCE.md` to locate the source for each project-evidence citation [1]-[14].
3. Read the relevant generated report first, then its adjacent JSON, traces, policies, coding or freeze records if you need to check a result.
4. Run `python scripts/verify_report_package.py` to verify the retained source hashes and key recorded counts without model requests, servers or third-party packages. `PACKAGE_CHECKS.json` records the integrity checks, internal dependency checks and 53 passing selected existing tests performed during packaging.

## What is retained

- Main phase-1 and five-server measurements, with their underlying records. The small sequential control is retained because the comparison implementation reads it.
- Both pilots, Stage 2 for both models, Progent, policy birth/widening and adaptive Stage 4, including raw traces, allowlists, usage, freezes and human coding records.
- The original report's ladder figure; its generator and the birth records it reads remain available.
- The complete scanner benchmark evidence and wrappers, including raw captures and the current-catalog static rerun. Large HTML resource captures are evidence for the scanner comparison and are intentionally retained.
- The core implementation and its transitive imports, applicable existing tests, package manifests and the original saved-result checker.
- Cited methodology chapters and protocol amendments. `PROMPT.md` and design/proposal notes remain only where they document the frozen experiments or interpretation; their presence is historical evidence, not a request to perform their proposed actions.

## What was left out

The registry census dump, literature-review corpus and screening work, slides and demos, local/counterfeit-server experiment collections and their repeats, abandoned prototypes, dry-run collections, exploratory template checks, unrelated code/tests, and editor configuration were omitted. Most outdated planning and handoff documents were also omitted. Exact exclusions are listed in `EXCLUDED_FILES.csv`; retained source hashes are in `MANIFEST.json`.

Source code and retained experimental evidence are byte-for-byte copies. This README, the evidence map, scope notes, package verifier, manifest and exclusion list are packaging additions. Original paths have been preserved so that the report's citations continue to resolve. Historical documents may still mention intentionally excluded experiments or working notes; those mentions are not dependencies of the report package.

## Reproduction boundaries

The package supports inspection and verification of saved evidence. It is not a newly collected experiment, and passing the package verifier does not re-run the effect oracles or validate the defenses online.

The original `scripts/check_saved_results.py` is also retained. Its full Stage 2/Progent replay needs Windows semantics for saved Windows fixture paths, and Progent requires its externally installed pinned dependency. This Mac cleanup does not establish a full cross-platform reproduction. The source archive itself does not contain installed `vendor/py-live`, `vendor/py-progent`, or Node dependencies. Package manifests/pins are retained; no installed environments or model weights were removed from a working installation because none was bundled in the supplied archive.

BadAgent is a separate repository in the report. Its model, training data and controls are not silently embedded in this On9MCP package. The report cites BadAgent commit `33583fa`; `docs/writeup/05-backdoor.md` is an older companion summary pinned to `fed1c6ee`. Use the report's cited BadAgent snapshot for its newer repeated-sample table. See `REPORT_EVIDENCE.md`.

The user's original PDF is included unchanged. No revised report or expanded-analysis files are included.
