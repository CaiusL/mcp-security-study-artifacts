# Methodology

The proof of concept implements this methodology on two stand-ins. The full study uses the same definitions on pinned servers and a model-backed caller.

## Envelopes

A call is a tool name plus arguments. Envelopes are sets of calls, estimated on a finite probe lattice because the raw argument space is infinite.

**Declared schema.** Arguments that satisfy the JSON schema. For these tools a path or URL is an unconstrained string.

**Declared intent.** Constraints stated by the description and the deployment configuration: filesystem paths resolve inside the configured root; fetch URLs are public `http` or `https`. The description states these limits. The schema does not encode them.

**Reachable.** Lattice probes whose effect occurs when the server runs with no proxy. An effect is a synthetic canary in a tool result, a directory listing of a canary file, metadata of that file, or a canary written to disk.

**Needed.** Resources that appear as arguments in successful training traces, generalized per strictness level. A name that shows up in a directory listing is not needed until some call uses it.

**Excess.** Reachable and not needed. Split into boundary excess (outside declared intent) and in-scope excess (inside declared intent).

## Tasks and split

Each task is a short benign request with an oracle: expected text in a tool result, expected file contents, a moved file, or a listing. The oracle is independent of the caller.

The scripted caller in `scripted_calls` emits the calls a competent agent would emit. Three repetitions change only path spelling (`C:\...` versus `C:/...`). The full study keeps the oracles and replaces the caller with a model, three samples per task.

Training traces build the policy. Held-out tasks are the usability measure. A task succeeds only when every repetition is allowed, every call returns success, and the oracle passes. Training success is a soundness check: a level that rejects its own evidence is a bug in the deriver.

The PoC uses 14 training tasks (10 filesystem, 4 fetch) and 11 held-out tasks. The full study targets about 30 tasks per server, with oracles written before any model run.

## Policy ladder

Each level adds constraints. A call allowed at level n is allowed at every lower level.

| Level | Added constraint |
| --- | --- |
| L0 schema | Tool and argument types match the schema |
| L1 declared | Canonical path inside the configured root; public http(s) only |
| L2 needed coarse | Tool name seen in benign traces; path under the common ancestor of benign paths; fetch host seen in traces |
| L3 needed dirs | Read directory or write directory seen for that operation; fetch host plus first path segment seen |
| L4 needed shape | Write suffix seen in traces; fetch URL equal to a benign URL; `git_show` revision equal to one used in traces |
| L5 needed exact | Filesystem tool and normalized path equal to a benign call |

Search patterns are literal substrings and are not part of the exact key. Extending L5 to patterns is future work; the PoC does not treat the pattern as a security boundary.

The operating point maximizes `min(attack block rate, held-out success)`. Ties take the higher block rate, then the higher held-out rate, then the lower level. The full curve is the result. The operating point is a summary of it.

## Enforcement

A proxy decides before the server runs. On a deny, the effect does not occur. Block rate counts missing effects, so a patched server that refuses a call and a proxy that refuses the same call both count as blocked. Records keep the two reasons apart (`proxy_denied` and `server_error`).

## Servers in the proof

Filesystem, vulnerable: string-prefix check with no path-boundary and no collapse of `..`, then the open follows `..` and symlinks. This is the public class of CVE-2025-53110 and CVE-2025-53109, confined to the sandbox.

Filesystem, patched: the resolved path must be the configured root or a descendant.

Fetch, vulnerable: any URL in the fixture map, including loopback, link-local, private, and `file`.

Fetch, patched: `http` or `https` and a global address only.

No socket is opened. Canary strings are `WIGGLE_CANARY_*`.

## Metrics

- Attack block rate: attack probes with no effect, over attack probes. Controls and the negative probe (an absolute path the prefix bug still rejects) are outside this rate.
- Boundary block rate and excess block rate: the same, split by kind.
- Held-out success and training success: task oracles.
- Excess fraction: reachable probes outside Needed, over reachable probes.

Invariants the harness enforces before it writes a curve:

- Training success is 1 at every level.
- Held-out success is 1 at L0 and never rises as the level increases.
- Attack block never falls as the level increases.
- The vulnerable server produces every attack effect at L0.
- The patched server blocks every boundary probe at L0 and blocks no in-scope excess probe at L0.
- Needed controls are never blocked.

## Live filesystem server

`python -m wiggle.live` runs the same ladder against a pinned server over stdio. Declared tools come from `tools/list`. The proxy applies the ladder before `tools/call`.

Filesystem is `@modelcontextprotocol/server-filesystem@2.0.0`, with only the study project directory on its command line. Search tasks use a glob, because this server's `search_files` matches paths rather than file text. Fetch is `mcp-server-fetch==2026.10.19` with private addresses refused. Git is `mcp-server-git==2026.10.19` with `--repository` set to a sandbox repo. Fetch uses one scripted repetition because every allowed call hits the network. Git resets the work tree in place between tasks because the server keeps the repo directory open.

Boundary probes stay inside the study sandbox and outside the allowed directory. The vulnerable pin is not installed. There is no container runtime on this machine, so a broken path check would not be contained. That pin waits until the server can be jailed.

A second pass widened the lattices past whole tools and paths. `fetch` with `raw=true` on a URL the tasks already fetch is recorded as a flag the traces never set, and L2 rejects it. `git_show` of a committed file the tasks never name is an unseen revision: L4 requires a `git_show` revision from the training traces, so that probe closes at L4 and held-out success falls. The operating point is whatever the curve selects after that cost. Memory is included because its tools have no path argument: the graph file is chosen by `MEMORY_FILE_PATH`, and the wiggle room is entity names, search queries, and unused tools such as `read_graph` and `delete_entities`. Time is the small-envelope control. The cross-server table is `artifacts/phase1/comparison.md`.

## Scaling to the full study

Stage order, the paired claim, and the sandbox fixture are in `PROMPT.md`. `python -m wiggle.sandbox` regenerates `artifacts/sandbox`. Follow that file when it is more specific than the list below.

The per-server curve does not scale by hand. Two scanners cover the cheap pass over a large set. Neither one calls a tool.

`python -m wiggle.scan registry` pages `https://registry.modelcontextprotocol.io/v0.1/servers`, keeps one row per server name, and labels each row with the envelope families its name, package, and description suggest (path, url, sql, git, browser, entity, timezone, command, thought). Remote userinfo and query strings are discarded. Secret environment values are not stored. The report lists matches for the still-open pins: sequential-thinking, playwright, github, sqlite, and postgres. A match is not a pin. The study still chooses one release and records it in `data/servers.json`.

`python -m wiggle.scan local` starts an explicit catalog of stdio commands, defaulting to the five vendored servers, with at most four workers. Each process is sent `initialize` and `tools/list` only. Argument names and schemas are labeled with the same families, and unconstrained resource strings are counted. That is the metadata-scanner view from the proof, applied to real tool lists. Packages discovered by the census are not started: a server can run code on startup, and this machine has no jail.

1. Pin the remaining servers in `data/servers.json` from the census shortlist. Filesystem, fetch, git, memory, time, and sequential-thinking are measured. Run a vulnerable pin only inside a jail. Playwright and GitHub are pinned from the census and not started. SQLite and Postgres are still unset.
2. Keep the proxy in front of the real stdio server. Log raw calls.
3. Replace `scripted_calls` with a model loop. Leave oracles unchanged. Budget about 1,000 runs; no GPU.
4. Build the Reachable lattice from `data/reachable_cases.json` plus targeted probes. Plant synthetic canaries. Do not point probes at real credentials.
5. Derive the same ladder, plus server-specific argument features (SQL shapes, git subcommands) only where traces show they vary.
6. Compare the declared scan's free-string flags with the Needed policy on the same probes. The proof uses a schema heuristic as that method check, not as a result about Snyk or Cisco. The bulk scan generalizes the heuristic to real tool lists. It still does not call tools, so the per-call comparison remains a later measurement.

## Threats to validity in the proof

The caller does not explore, backtrack, or sample. A model may need directories this caller never touches, which would move the Needed envelope outward and lower the usable strictness. The lattice is small and hand-built. Real servers have more tools and more bug classes than the two stand-ins. Rates are shares of this lattice, not probabilities over all strings.
