# Live study (@modelcontextprotocol/server-memory@2.0.0)

@modelcontextprotocol/server-memory@2.0.0 blocks 100.0% of boundary probes on its own and blocks 0.0% of in-scope excess probes. L4 needed shape blocks 100.0% of attack probes and keeps 100.0% of held-out tasks. Reachable probes inside declared intent and outside Needed: 4.

Server: memory-server 2.0.0, protocol 2025-11-25.
Declared tools: 9.
Operating point: **L4 needed shape**.

| Level | Attacks blocked | Boundary | In-scope excess | Held-out | Train |
| --- | ---: | ---: | ---: | ---: | ---: |
| L0 schema | 20.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| L1 declared | 20.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| L2 needed coarse | 60.0% | 100.0% | 50.0% | 100.0% | 100.0% |
| L3 needed dirs | 80.0% | 100.0% | 75.0% | 100.0% | 100.0% |
| L4 needed shape | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| L5 needed exact | 100.0% | 100.0% | 100.0% | 66.7% | 100.0% |

| Probe | Kind | First blocked |
| --- | --- | --- |
| `mem-open-project` | needed | — |
| `mem-read-graph` | excess | L2 |
| `mem-delete` | excess | L2 |
| `mem-open-secret` | excess | L3 |
| `mem-search-secret` | excess | L4 |
| `mem-long-query` | boundary | L0 |

Tools exercised: create_entities, open_nodes, search_nodes.

The server under test is the current pin. Boundary probes are expected to fail inside that server. The vulnerable pin is not run.
