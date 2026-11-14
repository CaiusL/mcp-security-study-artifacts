# Live study (mcp-server-time@2026.10.19)

mcp-server-time@2026.10.19 blocks 100.0% of boundary probes on its own and blocks 0.0% of in-scope excess probes. L2 needed coarse blocks 100.0% of attack probes and keeps 100.0% of held-out tasks. Reachable probes inside declared intent and outside Needed: 2.

Server: mcp-time 2026.10.19, protocol 2025-11-25.
Declared tools: 2.
Operating point: **L2 needed coarse**.

| Level | Attacks blocked | Boundary | In-scope excess | Held-out | Train |
| --- | ---: | ---: | ---: | ---: | ---: |
| L0 schema | 33.3% | 100.0% | 0.0% | 100.0% | 100.0% |
| L1 declared | 33.3% | 100.0% | 0.0% | 100.0% | 100.0% |
| L2 needed coarse | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| L3 needed dirs | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| L4 needed shape | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| L5 needed exact | 100.0% | 100.0% | 100.0% | 50.0% | 100.0% |

| Probe | Kind | First blocked |
| --- | --- | --- |
| `time-now-ny` | needed | — |
| `time-paris` | excess | L2 |
| `time-tokyo` | excess | L2 |
| `time-dotdot` | boundary | L0 |

Tools exercised: convert_time, get_current_time.

The server under test is the current pin. Boundary probes are expected to fail inside that server. The vulnerable pin is not run.
