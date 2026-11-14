# Measuring wiggle room in MCP tools

Proof of concept for a study of three envelopes on Model Context Protocol tools:

- **Declared**: what the tool name, description, schema, and deployment configuration promise.
- **Reachable**: what a steered caller can make the tool do.
- **Needed**: what benign tasks actually exercise.

Removable wiggle room is the part of Reachable that sits outside Needed. Policies derived only from Needed traces are enforced at six nested strictness levels. The output is a security–usability curve: attack probes blocked against benign tasks that still succeed.

## Measured result

On local filesystem and fetch stand-ins, with a 22-probe lattice and 11 held-out tasks, the generated curve is:

| Level | Attack probes blocked | Held-out tasks succeeding | Training tasks succeeding |
| --- | ---: | ---: | ---: |
| L0 schema | 0% vulnerable, 53.3% patched | 100% | 100% |
| L1 declared | 53.3% | 100% | 100% |
| L2 needed coarse | 60.0% | 90.9% | 100% |
| L3 needed dirs | 93.3% | 63.6% | 100% |
| L4 needed shape | 100% | 54.5% | 100% |
| L5 needed exact | 100% | 27.3% | 100% |

The operating point chosen by `min(block rate, held-out success)` is **L3 needed dirs**: 14 of 15 attack probes blocked, 7 of 11 held-out tasks still succeeding, every training task still succeeding. The probe still open at L3 is `fs-write-sh-notes`, a `.sh` write into a directory benign tasks already write. L4 closes it and drops one more held-out task.

Of 21 probes the vulnerable stand-ins can carry out, 15 are outside the Needed envelope (71.4%). Eight leave the declared root or the public-http rule. Seven stay inside declared intent: a secret file in the workspace, a write into a directory the tasks only read, a write of an unused suffix, and two fetch targets the tasks never use. The patched stand-ins already stop the eight boundary probes and still perform all seven in-scope excesses. Patching the known bug classes removes one slice of wiggle room. The trace-derived policy is what removes the rest.

These numbers are produced by `python -m wiggle`, not typed in by hand. `artifacts/phase1/report.md`, `artifacts/phase1/curve.svg`, and `artifacts/phase1/curve.csv` are that run.

## Live filesystem server

`python -m wiggle.live` repeats the ladder against the real package `@modelcontextprotocol/server-filesystem@2.0.0` (stdio, protocol 2025-11-25, 14 declared tools). The process may touch only the study project directory. Search tasks use globs, because this server matches paths rather than file text. The vulnerable pin is not installed.

| Level | Attacks blocked | In-scope excess blocked | Held-out | Train |
| --- | ---: | ---: | ---: | ---: |
| L0 schema | 40.0% | 0% | 100% | 100% |
| L1 declared | 40.0% | 0% | 100% | 100% |
| L2 needed coarse | 50.0% | 16.7% | 100% | 100% |
| L3 needed dirs | 90.0% | 83.3% | 71.4% | 100% |
| L4 needed shape | 100% | 100% | 71.4% | 100% |
| L5 needed exact | 100% | 100% | 28.6% | 100% |

The server itself blocks every boundary probe (sibling prefix, `..`, symlink, absolute path outside the root) and blocks none of the six in-scope excesses. L2 closes `directory_tree` on `secrets/`, a declared tool the training tasks never call, with held-out success still at 100%. L4 is the operating point: every attack probe blocked, 5 of 7 held-out tasks still succeeding. L3 leaves `fs-write-sh-notes` open; L4 closes that `.sh` write and does not fail any further held-out task.

The curve is in `artifacts/live/report.md` and `artifacts/live/curve.svg`. The five-server table is `artifacts/phase1/comparison.md`.

## What the wider lattice changed

The first live curves treated a tool as safe once its path or URL was one the tasks used. Two probes break that.

`git_show` of `HEAD:notes/hidden.md` returns `WIGGLE_CANARY_HIDDEN`. The file is in the initial commit. Training calls `git_show` only as `HEAD`. L4 requires that revision, so the probe closes there. Attack block at L4 is **100%**. Held-out falls from **80%** to **60%** because `git_show` of `HEAD:src/app.py` is not a training revision. Training success stays **100%** at every level. The operating point moves to **L3**: **71.4%** of attack probes blocked, **80%** of held-out tasks still succeeding, with `git-show-hidden` and `git-add-sh` still open. Curve: `artifacts/live-git/report.md`.

`fetch` with `raw=true` on `https://example.com/` returns the HTML of a page the tasks already fetch. L2 now rejects a `raw` value the traces never set, together with the unused host `example.net`. That level blocks every attack probe and keeps **2 of 3** held-out tasks. The lost task is a fetch of `example.org`. The operating point moves from L0 to **L2**. Curve: `artifacts/live-fetch/report.md`.

## Memory and time

Memory (`@modelcontextprotocol/server-memory@2.0.0`, 9 tools) takes entity names, not paths. The graph file is `MEMORY_FILE_PATH` inside the sandbox. A pre-seeded Secret entity is readable. L2 closes unused `read_graph` and `delete_entities`. L3 closes `open_nodes` of Secret. L4 closes `search_nodes` for that name. Held-out success stays **100%** through L4 and falls to 66.7% at L5, when a new entity is rejected. Curve: `artifacts/live-memory/report.md`.

Time (`mcp-server-time` 2026.10.19, 2 tools) rejects a timezone that is not an IANA name. L2 closes `Europe/Paris` and `Asia/Tokyo`, which the tasks never request, and held-out success stays **100%**. L5 rejects a different clock time on a zone the tasks do use. Curve: `artifacts/live-time/report.md`.

| Server | Operating point | Attacks blocked | Held-out | Still open |
| --- | --- | ---: | ---: | --- |
| filesystem 2.0.0 | L4 | 100% | 71% | — |
| git 2026.10.19 | L3 | 71% | 80% | `git-show-hidden`, `git-add-sh` |
| fetch 2026.10.19 | L2 | 100% | 67% | — |
| memory 2.0.0 | L4 | 100% | 100% | — |
| time 2026.10.19 | L2 | 100% | 100% | — |

`python -m wiggle.sandbox` runs `wiggle-sandbox` 0.1.0, the MCP this repository authors. The server refuses a schema-valid read outside the configured directory and performs a read of the planted in-directory canary. The schema heuristic, the registry hint classifier, and the tools/list scan flag both probes and the needed control. L3 blocks both labeled probes, with held-out success at 100% and training at 100%. Source: `artifacts/sandbox/report.md`. That fixture stays out of `artifacts/phase1/comparison.md`.

## Run

From this directory, with Python 3.11+. The stand-in study uses the standard library only. The live filesystem study also needs Node and `npm install --prefix vendor/mcp`. Fetch and git also need `python -m pip install --target vendor/py -r vendor/requirements.txt`.

```text
python -m unittest discover -s tests -v
python -m wiggle --out artifacts
python -m wiggle.live --out artifacts/live
python -m wiggle.live --server fetch
python -m wiggle.live --server git
python -m wiggle.live --server memory
python -m wiggle.live --server time
python -m wiggle.sandbox
python -m wiggle.compare
python -m wiggle.scan registry --out artifacts/scan-registry
python -m wiggle.scan local --out artifacts/scan-local
```

`scan registry` pages the public MCP registry and classifies names and descriptions. It does not install a package or call a tool. `scan local` starts the five vendored servers in parallel, or a JSON catalog of stdio commands, and stops after `tools/list`. A catalog command is a list of strings, not a shell line. Untrusted registry packages are not launched.

## zgScanner: combined MCP scanner

`wiggle/zgscanner` folds the checks of twelve public MCP scanners into one stdlib scanner with a local dashboard: Snyk Agent Scan (formerly Invariant mcp-scan), Cisco AI Defense mcp-scanner, MCP-Shield, Ramparts, Proximity, Trail of Bits mcp-context-protector, MCP Watch, MCPSafetyScanner, Agentic Radar, mcpguard, AgentAvow mcp-security-scan, and this repository's declared scan. It has 73 checks, each tagged with the OWASP MCP Top 10 and with the scanners whose feature it reproduces. `python -m wiggle.zgscanner checks` prints the catalog and the per-scanner coverage. The panel's Scanner coverage screen lists every gap with its reason. Examples of gaps: Cisco's proprietary Inspect API, sandboxed package detonation, runtime quarantine, and Snyk's fleet reporting.

To scan one server, run `panel --open` and paste it into **Scan an MCP server** on the Overview screen, or pass it to `scan`. A pasted target can be:

- a server URL (`https://aeoinspector.com/mcp`). It is tried over streamable HTTP and then legacy SSE, and sent `initialize`, the list calls and `resources/read`. No tool is called.
- a JSON config snippet. Put an `Authorization` header in it for servers behind sign-in.
- an install line (`npx add-mcp '<url>'`, `npx mcp-remote <url>`, `claude mcp add ... <url>`). Its URL is scanned.
- a launch command (`npx -y some-package`). It is checked without being run.

```text
python -m wiggle.zgscanner panel --open
python -m wiggle.zgscanner scan https://aeoinspector.com/mcp
python -m wiggle.zgscanner scan --format json --format sarif --format md --format html --fail-on high
python -m wiggle.zgscanner scan --config path/to/mcp.json --connect my-server --identify-as claude-ai
python -m wiggle.zgscanner scan --tools-json saved-tools-list.json --source path/to/server --osv --pin
```

A `--tools-json` block can also carry `instructions`, `capabilities`, `prompts`, `resources` (each with the `contents` of its `resources/read` reply, held to the same caps as a live read) and the `transport` it was captured over.

What runs by default:

- Discovery reads the known config files of Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Cline, Roo Code, Gemini CLI, Codex, Zed, Kiro, Amazon Q, OpenCode, LM Studio, Continue and Copilot.
- The default scan is static. It covers secrets, unpinned or typosquatted packages, recorded advisory pins, shell-wrapped launches, plain http, overbroad roots, container flags and project-scoped configs. It lists Claude Code hooks (`.claude/settings.json`, `settings.local.json`) and VS Code tasks that run on folder open (`.vscode/tasks.json`), high in a project folder and low in your user settings. It also covers tool-poisoning text, hidden Unicode, ANSI codes, encoded payloads, capability labels and toxic flows. Skills, commands and agents are scanned too, and so are skills a server serves as resources.

What needs a flag:

- `--connect` starts a stdio server, or contacts a remote one. Nothing beyond `initialize`, the three list calls and `resources/read` is sent, and no tool is called. A resource body is read only after `resources/list` names it, within caps: at most 20 per server, text MIME types only, 256 KB of text each. Blobs are skipped. Each server's report lists every resource as read or skipped, with the reason. Text a tool would return, such as a skill fetched by a tool call, is not read. A stdio server runs its own code when it starts, so connect only servers you would let an agent start. Packages found by the registry census are never launched.
- `--osv`, `--virustotal` and `--llm` send data off the machine:
  - `--osv` sends package names and versions.
  - `--virustotal` sends file hashes only.
  - `--llm` sends tool text with secrets redacted, and needs the `anthropic` package.
- `--pin` records hashes so later scans report rug pulls (RP001–RP003).

The panel binds 127.0.0.1. Every API call needs a per-run token and a loopback Host header. All scanned text is escaped before it is rendered. A report of your own machine lands in `artifacts/zgscanner/`, which git ignores.

## Layout

| Path | Role |
| --- | --- |
| `wiggle/` | Measurement pipeline |
| `wiggle/corpus.py` | Sandbox, benign tasks, probe lattice, scripted caller |
| `wiggle/policy.py` | Needed profile and the six nested policies |
| `wiggle/servers.py` | Filesystem and fetch stand-ins, vulnerable and patched |
| `wiggle/evaluate.py` | Envelopes, curve, report |
| `wiggle/scan.py` | Bulk declared scan: registry census and parallel local `tools/list` |
| `wiggle/sandbox.py` | Labeled sandbox fixture and its report |
| `wiggle/sandbox_server.py` | Project-authored stdio MCP used only by that fixture |
| `wiggle/zgscanner/` | Combined MCP scanner: catalog, detectors, discovery, live introspection, engine, reports, panel |
| `tests/test_poc.py` | Mechanism tests and one full study run |
| `tests/test_zgscanner.py` | Scanner detectors, parsers, drift, live stdio, reports, panel API guards |
| `PROMPT.md` | Standing direction: paired claim, current stage, sandbox fixture |
| `docs/methodology.md` | Definitions and the plan for the full study |
| `docs/related_work.md` | Targeted overlap check |
| `data/servers.json` | Ten servers to pin for the full study |
| `data/reachable_cases.json` | Public bug classes, with no reproduction steps |
| `artifacts/` | Generated curve, report, traces |

`scripted_calls` in `wiggle/corpus.py` is the agent seam. Oracles stay put when a model-backed caller replaces it.

## What the proof establishes

The pipeline can extract a Declared envelope from tool metadata, log a Needed envelope from tasks with automatic oracles, measure a Reachable envelope on a finite probe lattice, derive a nested policy from the traces alone, and plot block rate against task success. Training-task success stays at 100% at every level, so each policy still admits the evidence it was built from. Held-out success falls as the policy tightens, so the usability cost is visible. A patched server and a Needed policy close different parts of the lattice.

## Full-study status

Server pins and the overlap notes are in `data/servers.json` and `docs/related_work.md`. The 2026-10-19 targeted read, the 2026-10-20 citation pass, and the 2026-10-25 full-text and arXiv search did not find a cross-task Needed envelope estimated from execution traces and plotted as this strictness curve. That note is not a finished systematic review. No priority claim is made.

The full study still has to attach this harness to the pinned real servers, replace the scripted caller with a model, grow the task set to about thirty tasks per server, and keep attack evaluation on synthetic canaries inside a VM.

A read-only census of the official registry on 2026-10-19 is in `artifacts/scan-registry`. It kept 46,437 servers and called no tools. Playwright is pinned at `@playwright/mcp@0.0.82` and GitHub at `ghcr.io/github/github-mcp-server:2.0.2`; neither measurement has started. Sequential-thinking is measured at pin 2.0.0 in `artifacts/live-sequential` and had no name or package match in that census. SQLite and Postgres have no official namespace and stay unpinned; the shortlist is in that report.

## Ethics

Fixtures and canaries exist only inside the study sandbox. Fetch replies come from an in-memory page map. Vulnerable mode reproduces the public prefix-check and symlink-follow classes against those fixtures. This repository has no exploit payload for a real MCP server, no shell invocation, and no credential material. New findings on real servers go through responsible disclosure. The work is measurement and enforcement.
