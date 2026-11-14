# Registry census

Read-only pull of the official MCP registry. One row per server name. No package was installed and no tool was called. Remote userinfo and query strings are not stored.

Scanned at 2026-10-19T19:40:14Z. Pages read: 1609. Rows seen: 160839. Kept: 46437. Older versions folded: 114402. Deleted skipped: 0. Unreadable rows: 0. Complete: True.

## Hint counts

A server is counted once per hint. Hints come from the name, package identifier, and description.

| Hint | Servers |
| --- | ---: |
| browser | 453 |
| command | 115 |
| entity | 201 |
| git | 208 |
| path | 319 |
| sql | 510 |
| thought | 9 |
| timezone | 68 |
| url | 2460 |

## Transports

| Transport | Servers |
| --- | ---: |
| sse | 1110 |
| stdio | 17757 |
| streamable-http | 29786 |
| unspecified | 506 |

## Open study pins

Matches use the server name after the slash, or a package identifier. A download URL counts only by its file name, so a GitHub release of an unrelated server is not a GitHub match. Official namespaces come first, then servers with a stdio package, then name. This list does not choose a pin by itself.

### sequential-thinking

0 name or package match(es).

No match in the rows kept.

### playwright

13 name or package match(es).

| Server | Version | Package | Transports |
| --- | --- | --- | --- |
| `io.github.microsoft/playwright-mcp` | 0.0.82 | `@playwright/mcp@0.0.82` | stdio |
| `com.pulsemcp/playwright-stealth` | 0.2.3 | `playwright-stealth-mcp-server@0.2.3` | stdio |
| `io.github.dinesh-nalla-se/playwright-mcp` | 1.0.0 | `@dinesh-nalla-se/playwright-mcp@0.0.47` | stdio |
| `io.github.feder-cr/invisible-playwright-mcp` | 0.72.3 | `invisible-playwright-mcp@0.72.3` | stdio |
| `io.github.hubertgajewski/playwright-report-mcp` | 3.4.0 | `playwright-report-mcp@3.4.0` | stdio |
| `io.github.oguzc/playwright-wizard-mcp` | 0.1.6 | `playwright-wizard-mcp@0.1.6` | stdio |
| `io.github.PxyUp/fitter` | 1.8.3 | `https://github.com/PxyUp/fitter/releases/download/v1.8.3/fitter-mcp-darwin-arm64.mcpb@`, `https://github.com/PxyUp/fitter/releases/download/v1.8.3/fitter-mcp-darwin-amd64.mcpb@` | stdio |
| `io.github.trajectiq-ai/E2E` | 0.2.2 | `playwright-e2e-mcp@0.2.2` | stdio, streamable-http |
| `io.github.vola-trebla/playwright-network-chaos-mcp` | 0.2.1 | `playwright-network-chaos-mcp@0.2.1` | stdio |
| `io.github.vola-trebla/playwright-spatial-layout-mcp` | 0.2.0 | `playwright-spatial-layout-mcp@0.2.0` | stdio |
| `io.github.vola-trebla/playwright-trace-decoder-mcp` | 0.2.3 | `playwright-trace-decoder-mcp@0.2.3` | stdio |
| `com.thenextgennexus/playwright-mcp-server` | 1.0.0 | — | streamable-http |

### github

55 name or package match(es).

| Server | Version | Package | Transports |
| --- | --- | --- | --- |
| `io.github.github/github-mcp-server` | 2.0.2 | `ghcr.io/github/github-mcp-server:2.0.2@` | stdio, streamable-http |
| `com.mambabuilt/mcp-github-organization-signal-scanner` | 1.2.0 | `@mambalabsdev/mcp-github-organization-signal-scanner@1.2.0` | stdio |
| `com.mcparmory/github` | 1.0.6 | `mcparmory-github@1.0.6` | stdio |
| `io.github.AbdulMuhaiminKhan/github-mcp` | 1.2.0 | `github-mcp-readonly@1.2.0` | stdio |
| `io.github.Abhishekkumar2021/github` | 0.2.0 | `@abhishekmcp/github@0.2.0` | stdio |
| `io.github.adelaidasofia/github-mcp` | 0.1.0 | `https://github.com/adelaidasofia/github-mcp/releases/download/v0.1.0/github-mcp.mcpb@0.1.0` | stdio |
| `io.github.alexbypa/github-projectpulse-mcp` | 1.10.0 | `projectpulse-mcp@1.10.0` | stdio |
| `io.github.ChristopherDavenport/github-twin` | 0.0.17 | `github-twin@0.0.17` | stdio |
| `io.github.crypto-ninja/github-mcp-server` | 2.5.7 | `github-mcp-server@2.5.7` | stdio |
| `io.github.Dave-London/github` | 0.7.1 | `@paretools/github@0.7.1` | stdio |
| `io.github.Dave-London/pare-github` | 0.8.1 | `@paretools/github@0.8.1` | stdio |
| `io.github.davidweb3-ctrl/github` | 1.0.0 | `@davidweb3-ctrl/mcp-github-server@1.0.0` | stdio |

### sqlite

12 name or package match(es).

| Server | Version | Package | Transports |
| --- | --- | --- | --- |
| `com.devart/mcp-sqlite` | 1.1.0 | `Devart.Mcp.SQLite@1.1.0` | stdio |
| `io.github.arifulislamat/database-mcp-sqlite` | 0.5.0 | `@database-mcp/sqlite@0.5.0`, `database-mcp-sqlite@0.2.0` | stdio |
| `io.github.cheveguerra/sqlite-local-ai-memory` | 1.4.7 | `sqlite-local-ai-memory@1.4.7` | stdio |
| `io.github.mrfentmen/sqlite-mcp` | 1.0.0 | `@mrfentmen/sqlite-mcp@1.0.0` | stdio |
| `io.github.neverinfamous/sqlite-mcp-server` | 2.6.3 | `sqlite-mcp-server-enhanced@2.6.3` | stdio |
| `io.github.ofershap/sqlite` | 1.0.1 | `mcp-sqlite-server@1.0.1` | stdio |
| `io.github.rosch100/mcp-encrypted-sqlite` | 0.4.1 | `ghcr.io/rosch100/mcp-encrypted-sqlite:0.4.1@` | stdio |
| `io.github.rosch100/mcp-sqlite` | 0.2.4 | `ghcr.io/rosch100/mcp-sqlite:0.2.4@` | stdio |
| `io.github.spences10/mcp-sqlite-tools` | 0.0.11 | `mcp-sqlite-tools@0.0.11` | stdio |
| `io.github.tonydzi/sqlite-graph-memory` | 0.3.1 | `sqlite-graph-memory@0.3.1` | stdio |
| `ai.smithery/afgong-sqlite-mcp-server` | 1.16.0 | — | streamable-http |
| `ai.smithery/wgong-sqlite-mcp-server` | 1.16.0 | — | streamable-http |

### postgres

40 name or package match(es).

| Server | Version | Package | Transports |
| --- | --- | --- | --- |
| `ai.kaiv/postgres` | 0.1.0 | `@kaiva/postgres-mcp@0.1.0` | stdio |
| `capital.hove/read-only-local-postgres-mcp-server` | 0.1.0 | `@hovecapital/read-only-postgres-mcp-server@0.1.0` | stdio |
| `com.devart/mcp-postgresql` | 1.1.0 | `Devart.Mcp.PostgreSql@1.1.0` | stdio |
| `io.github.AINative-Studio/ainative-postgres-mcp` | 1.0.1 | `ainative-postgres-mcp@1.0.1` | stdio |
| `io.github.AIops-tools/postgres-aiops` | 0.12.0 | `postgres-aiops@0.12.0` | stdio |
| `io.github.antonorlov/mcp-postgres-server` | 0.3.1 | `mcp-postgres-server@0.3.1` | stdio |
| `io.github.arifulislamat/database-mcp-postgres` | 0.5.0 | `@database-mcp/postgres@0.5.0`, `database-mcp-postgres@0.2.0` | stdio |
| `io.github.bluwork/postgres-scout-mcp` | 1.0.3 | `postgres-scout-mcp@1.0.3` | stdio |
| `io.github.contextflo/postgres-mcp` | 0.1.4 | `@contextflo/postgres-mcp@0.1.4` | stdio |
| `io.github.cunicopia-dev/whoop-postgres-mcp` | 0.1.0 | `whoop-postgres-mcp@0.1.0` | stdio |
| `io.github.edelciomolina/postgres-mcp` | 1.7.0 | `@edelciomolina/postgres-mcp@1.7.0` | stdio |
| `io.github.Eszetael/postgres-mcp-hardened` | 0.1.10 | `postgres-mcp-hardened@0.1.10` | stdio, streamable-http |

A full curve still needs a pinned command, a task suite, and the probe lattice. This census only decides which servers are worth that work.
