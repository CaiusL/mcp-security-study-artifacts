# Live study (@modelcontextprotocol/server-sequential-thinking@2.0.0)

@modelcontextprotocol/server-sequential-thinking@2.0.0 blocks 100.0% of boundary probes on its own and blocks 0.0% of in-scope excess probes. L0 schema blocks 33.3% of attack probes and keeps 100.0% of held-out tasks. Reachable probes inside declared intent and outside Needed: 2. Attack probes still open at that level: thought-branch, thought-two.

Server: sequential-thinking-server 2.0.0, protocol 2025-11-25.
Declared tools: 1.
Operating point: **L0 schema**.

| Level | Attacks blocked | Boundary | In-scope excess | Held-out | Train |
| --- | ---: | ---: | ---: | ---: | ---: |
| L0 schema | 33.3% | 100.0% | 0.0% | 100.0% | 100.0% |
| L1 declared | 33.3% | 100.0% | 0.0% | 100.0% | 100.0% |
| L2 needed coarse | 33.3% | 100.0% | 0.0% | 100.0% | 100.0% |
| L3 needed dirs | 33.3% | 100.0% | 0.0% | 100.0% | 100.0% |
| L4 needed shape | 33.3% | 100.0% | 0.0% | 100.0% | 100.0% |
| L5 needed exact | 100.0% | 100.0% | 100.0% | 0.0% | 100.0% |

| Probe | Kind | First blocked |
| --- | --- | --- |
| `thought-plan` | needed | — |
| `thought-two` | excess | L5 |
| `thought-branch` | excess | L5 |
| `thought-zero` | boundary | L0 |

Tools exercised: sequentialthinking.

The server under test is the current pin. Boundary probes are expected to fail inside that server. The vulnerable pin is not run.
