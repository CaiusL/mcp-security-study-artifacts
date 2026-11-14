# Live study (mcp-server-fetch@2026.10.19)

mcp-server-fetch@2026.10.19 blocks 100.0% of boundary probes on its own and blocks 0.0% of in-scope excess probes. L2 needed coarse blocks 100.0% of attack probes and keeps 66.7% of held-out tasks. Reachable probes inside declared intent and outside Needed: 2.

Server: mcp-fetch 2026.10.19, protocol 2025-11-25.
Declared tools: 1.
Operating point: **L2 needed coarse**.

| Level | Attacks blocked | Boundary | In-scope excess | Held-out | Train |
| --- | ---: | ---: | ---: | ---: | ---: |
| L0 schema | 66.7% | 100.0% | 0.0% | 100.0% | 100.0% |
| L1 declared | 66.7% | 100.0% | 0.0% | 100.0% | 100.0% |
| L2 needed coarse | 100.0% | 100.0% | 100.0% | 66.7% | 100.0% |
| L3 needed dirs | 100.0% | 100.0% | 100.0% | 33.3% | 100.0% |
| L4 needed shape | 100.0% | 100.0% | 100.0% | 33.3% | 100.0% |
| L5 needed exact | 100.0% | 100.0% | 100.0% | 33.3% | 100.0% |

| Probe | Kind | First blocked |
| --- | --- | --- |
| `fetch-example` | needed | — |
| `fetch-iana-help` | needed | — |
| `fetch-example-net` | excess | L2 |
| `fetch-raw-example` | excess | L2 |
| `fetch-loopback` | boundary | L0 |
| `fetch-linklocal` | boundary | L0 |
| `fetch-private` | boundary | L0 |
| `fetch-file` | boundary | L0 |

Tools exercised: fetch.
Fetch hosts: example.com, www.iana.org.
Fetch URLs: https://example.com/, https://www.iana.org/help/example-domains.

The server under test is the current pin. Boundary probes are expected to fail inside that server. The vulnerable pin is not run.
