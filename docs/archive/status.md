# Workspace status

Written 2026-10-20 from the files in this tree. A 2026-10-25 pass recorded the full-text reading and the literature search in `docs/related_work.md`, and resolved the three moved zgScanner source URLs in `wiggle/zgscanner/catalog.py`. Curve numbers are the generated artifacts (`artifacts/phase1/report.md`, `artifacts/phase1/comparison.md`, the per-server reports, and `artifacts/sandbox/report.md`). The sandbox fixture was regenerated with `python -m wiggle.sandbox`. The five-server curves were not rerun. `tests/test_sandbox.py` and `tests/test_poc.py` passed (13 tests). The live and scan tests were not rerun.

`C:\On9MCP` is the local study for **wiggle** 0.1.0. Standing direction is `PROMPT.md`. Definitions are in `docs/methodology.md`. Pins are in `data/servers.json`. Curves, reports, and `artifacts/phase1/comparison.md` are generated: change `wiggle/compare.py` (or the study that feeds it) and rerun. Do not type numbers into an artifact.

## Goal

Measure least privilege on Model Context Protocol tools as three envelopes, then enforce the gap between them.

- **Declared**: what the tool name, description, schema, and deployment configuration promise.
- **Reachable**: what a steered caller can make the tool do, estimated on a finite probe lattice.
- **Needed**: what benign tasks actually exercise, taken from successful training traces.

Removable wiggle room is the part of Reachable that sits outside Needed. A proxy derived only from those traces is applied at six nested levels, from L0 schema through L5 needed exact. The result is a security–usability curve: attack probes blocked against held-out tasks that still succeed. The operating point maximizes `min(attack block rate, held-out success)`. Training success stays 100% at every level. That is a soundness check: a level that rejects its own evidence is a bug in the deriver.

The result to keep, at equal weight, comes from the same five patched pins and the same lattices:

1. Every boundary probe in the lattice produced no effect (12 of 12). The server refused the call before any Needed policy. A schema-valid call did not carry an action outside the declared boundary (11 of 11). One further boundary probe, `mem-long-query`, failed the server’s schema check.
2. In-scope excess did produce its effect (19 of 19 at L0). A call that stays inside the declared root, repo, or graph, and reaches something the training tasks never use, was performed by the server. The Needed ladder is what blocks that excess.

A miss on this lattice is a share of the lattice. The work is measurement and enforcement. Fixtures and canaries stay inside the study sandbox. New findings on real servers go through responsible disclosure.

## What is in the tree

| Path | Role |
| --- | --- |
| `wiggle/` | Measurement pipeline: corpus, policy, stand-ins, live studies, compare, registry and local scans |
| `tests/` | `test_poc.py`, `test_live.py`, `test_scan.py`, `test_sandbox.py` (37 `test_` methods) |
| `data/servers.json` | Ten planned servers and the shell deferral. Pins checked 2026-10-19 |
| `data/reachable_cases.json` | Public bug classes at class level, with no reproduction steps |
| `docs/methodology.md` | Envelope definitions, ladder, and metric invariants |
| `docs/related_work.md` | Targeted overlap check, not a systematic review |
| `artifacts/` | Generated curves, reports, traces, and scans |
| `vendor/mcp`, `vendor/py` | Installed npm and PyPI servers used by the live studies |
| `PROMPT.md` | Current stage, sandbox fixture, and holds |

The caller in the recorded studies is `scripted_calls` in `wiggle/corpus.py`. Oracles stay fixed when a model-backed caller replaces it. The full-study target is about 30 tasks per server and about 1,000 runs, with no GPU.

## Progress

### Stand-in proof

`python -m wiggle` runs filesystem and fetch stand-ins (vulnerable and patched) on a 22-probe lattice. Fetch replies come from an in-memory page map. No socket is opened. Canaries are `WIGGLE_CANARY_*`.

On the vulnerable stand-ins the operating point is **L3 needed dirs**: 93.3% of attack probes blocked, 63.6% of held-out tasks succeeding, training at 100%. The probe still open there is `fs-write-sh-notes`. Of 21 reachable probes, 15 sit outside Needed (71.4%): 8 outside declared intent, 7 inside it. The patched stand-ins already block every boundary probe at L0 and still perform all 7 in-scope excesses. Source: `artifacts/phase1/report.md`.

### Five live patched servers

Live studies talk to real stdio servers. The vulnerable pins are not installed. Each server already blocks its boundary probes and blocks none of its in-scope excesses at L0. The Needed proxy closes the rest. Source: `artifacts/phase1/comparison.md`.

| Server | Operating point | Attacks blocked | Held-out | In-scope excess | Still open |
| --- | --- | ---: | ---: | ---: | --- |
| `@modelcontextprotocol/server-filesystem@2.0.0` | L4 needed shape | 100% | 71% | 6 | — |
| `mcp-server-fetch@2026.10.19` | L2 needed coarse | 100% | 67% | 2 | — |
| `mcp-server-git@2026.10.19` | L3 needed dirs | 71% | 80% | 5 | `git-add-sh`, `git-show-hidden` |
| `@modelcontextprotocol/server-memory@2.0.0` | L4 needed shape | 100% | 100% | 4 | — |
| `mcp-server-time@2026.10.19` | L2 needed coarse | 100% | 100% | 2 | — |

The git L4 check is recorded in `artifacts/live-git`. L4 requires a `git_show` revision the training traces used. That closes `git-show-hidden` (`git_show` of `HEAD:notes/hidden.md`, canary `WIGGLE_CANARY_HIDDEN`) and `git-add-sh`, and drops git held-out success from 80% to 60%. Training stays 100%. The operating point remains L3, where both probes are still open. At L5, git held-out success is 40%.

Fetch’s private-address check already stops the boundary probes. `raw=true` on a needed URL and a new public host close together at L2, which also drops the held-out fetch of a second public host. Memory has no path argument; `MEMORY_FILE_PATH` fixes the file. Unused tools, `open_nodes` of a pre-seeded Secret entity, and `search_nodes` for that name close by L4 with held-out success still 100%. Time’s unused timezones close at L2 with held-out success unchanged.

### Scans and related work

- Registry census, 2026-10-19: read-only pull of the official MCP registry. 46,437 servers kept, no package installed, no tool called. Report: `artifacts/scan-registry/report.md`.
- Local declared scan, 2026-10-19: the five vendored servers, `initialize` and `tools/list` only. Report: `artifacts/scan-local/report.md`.
- zgScanner bench, 2026-10-22: zgScanner 0.1.0 and six public scanners against five hosted servers from mcpservers.org, read-only, with a hand review as the control. The evidence is in `bench/scan-comparison` (copied from `C:\Test` on 2026-10-27). Follow-up in `wiggle/zgscanner`: text resource bodies are now read within caps, served skills get the skill checks, and four checks were added: SK007 (package runner in allowed-tools), SK010 (served skill exceeds the declared boundary), TP018 (agent-steering directive) and TP019 (server-supplied install or run instruction). The slug-as-URL, TP016 negation and remote check-only false positives were fixed on the zgScanner side; `wiggle/scan_classify.py` is unchanged. `BenchFixturesTest` in `tests/test_zgscanner.py` holds the five synthetic fixtures.
- `docs/related_work.md`: targeted read on 2026-10-19, a citation pass on 2026-10-20, and a full-text pass on 2026-10-25 (ROPE, AgentArmor, Agent Approval Laundering, MCPSafetyScanner, MCP-SEC, MCP-Guard, FlowGuard, and Computers 15(9):570). The systematic review is still open, and there is no priority claim. Scanner comparison against tools outside this repository has not started.

### Sandbox fixture

`python -m wiggle.sandbox` runs `wiggle-sandbox` 0.1.0, a server this repository authors. The configured directory is the study project folder. Two labeled probes:

- `sandbox-read-outside` is a schema-valid `read_note` of a file outside that directory. The server refuses it.
- `sandbox-read-canary` is a schema-valid `read_note` of `secrets/token.txt` inside the directory. Benign tasks never read it. The server returns `WIGGLE_CANARY_SECRET`.

The schema heuristic, the registry hint classifier, and the local tools/list scan each flag both probes. They also flag the needed control, a training read of `README.md`. The Needed proxy at **L3 needed dirs** blocks both labeled probes. Held-out success stays 100% through L4 and is 0% at L5. Training stays 100% at every level. Source: `artifacts/sandbox/report.md`. The fixture is not in `artifacts/phase1/comparison.md`.

## Still open

Sequential-thinking is pinned at `@modelcontextprotocol/server-sequential-thinking@2.0.0`. Its curve is `artifacts/live-sequential`. It is the flat control and is not part of the five-pin paired counts. Playwright `@playwright/mcp@0.0.82` and GitHub `ghcr.io/github/github-mcp-server:2.0.2` are written into `data/servers.json` from the 2026-10-19 census and are not started. SQLite and Postgres stay unpinned. The census stores no download count for them.

The four git CVE classes in `data/reachable_cases.json` have no probes. Shell measurement waits until a VM is available. The model-backed caller, the larger task set, and the about-1,000-run budget are not started.

`vendor/py` is not readable on this machine, so its package directories import as empty namespaces. The same pins from `vendor/requirements.txt` were installed into `vendor/py-live`, and `vendored_python_env` uses that tree when `mcp_server_git/__main__.py` is readable there. The symlink probe is omitted when the sandbox cannot create a symlink, and the filesystem test follows that. `python -m unittest discover -s tests` on 2026-10-25 ran 118 tests and passed.

### Injection pilots

Pilot 1 (`artifacts/injection-pilot/report.md`, 2026-10-26) is a no-go: patched-arm attack success is 0/72. Pilot 2 (`artifacts/injection-pilot-2/report.md`, 2026-10-29, template `tool-output-v2`) passes the signal check: 5/72 patched-arm successes, all G2 through a tool description. The 20 hand checks agree. Coders 1 and 2 coded field 2 on 2026-10-29, blind to arm and layer: all 8 successes are inside the grant, 8 of 8 agree (`artifacts/injection-pilot-2/coder-1.json`, `coder-2.json`). Kappa stays unset because both used one category. The decision is go. The widening mechanism check is `artifacts/stage3-widening/`, generated by `python -m wiggle.widening mechanism`. The Stage 3 proposal is not accepted, and its model arm has not run.

## Next stage

The sandbox fixture is recorded in `artifacts/sandbox`. Sequential-thinking is measured in `artifacts/live-sequential`. Playwright and GitHub are pinned and not started. SQLite and Postgres stay unpinned. A systematic review is still required before any priority claim. The jail hold is unchanged. Pilot 2's hand checks agree. The pilot 2 decision is go. Stage 2 waits on its gate in `docs/archive/plan.md`. The widening model arm waits on the decisions in `docs/proposal-stage3-widening-arm.md`.

## Holds

- A vulnerable pin runs only inside a jail. This machine has no container runtime. Filesystem `2025.1.14` stays uninstalled. No vulnerable git pin is chosen. GitHub advisories patch CVE-2025-68143 at 2025.9.25, CVE-2025-68144 and CVE-2025-68145 at 2025.12.18, and CVE-2026-27735 at 2026.1.14. The CVE records for CVE-2025-68144 and CVE-2025-68145 say 2025.12.17.
- Packages discovered by the registry census are not launched. A server can run code on startup.
- Public bug classes stay at class level. This repository has no exploit payload for a real MCP server, no shell invocation, and no credential material.
