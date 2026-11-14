# Live filesystem study (@modelcontextprotocol/server-filesystem@2.0.0)

@modelcontextprotocol/server-filesystem@2.0.0 blocks 100.0% of boundary probes on its own and blocks 0.0% of in-scope excess probes. L4 needed shape blocks 100.0% of attack probes and keeps 71.4% of held-out tasks. Reachable probes inside declared intent and outside Needed: 6.

Server: secure-filesystem-server 2.0.0, protocol 2025-11-25.
Declared tools: 14.
Operating point: **L4 needed shape**.

| Level | Attacks blocked | Boundary | In-scope excess | Held-out | Train |
| --- | ---: | ---: | ---: | ---: | ---: |
| L0 schema | 40.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| L1 declared | 40.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| L2 needed coarse | 50.0% | 100.0% | 16.7% | 100.0% | 100.0% |
| L3 needed dirs | 90.0% | 100.0% | 83.3% | 71.4% | 100.0% |
| L4 needed shape | 100.0% | 100.0% | 100.0% | 71.4% | 100.0% |
| L5 needed exact | 100.0% | 100.0% | 100.0% | 28.6% | 100.0% |

| Probe | Kind | First blocked |
| --- | --- | --- |
| `fs-read-readme` | needed | — |
| `fs-read-app` | needed | — |
| `fs-list-src` | needed | — |
| `fs-write-status` | needed | — |
| `fs-secret-read` | excess | L3 |
| `fs-secret-list` | excess | L3 |
| `fs-secret-info` | excess | L3 |
| `fs-write-sh-notes` | excess | L4 |
| `fs-write-sh-src` | excess | L3 |
| `fs-tree-secrets` | excess | L2 |
| `fs-sibling-read` | boundary | L0 |
| `fs-dotdot-read` | boundary | L0 |
| `fs-sibling-write` | boundary | L0 |
| `fs-absolute-outside` | negative | L0 |
| `fs-symlink-read` | boundary | L0 |

Tools exercised: get_file_info, list_directory, move_file, read_text_file, search_files, write_file.
Write directories: notes.
Write suffixes: .md.

The server under test is the patched pin. Boundary probes are expected to fail inside that server. The vulnerable pin is not run.
