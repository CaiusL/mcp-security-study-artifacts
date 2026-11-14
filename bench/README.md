# Scanner bench (from `C:\Test`)

On 2026-10-21 and 2026-10-22 we ran six public MCP scanners and zgScanner against five hosted MCP servers from mcpservers.org, with a hand review as the control. This folder holds the scripts, the raw evidence, and the summary. It was copied from `C:\Test` on 2026-10-27. The scanner installs stayed in `C:\Test`, because their virtual environments hold absolute paths.

Every scanner only listed metadata (`initialize`, the list calls, `resources/read`). No tool was called.

## Result

Summary table and hand review: [`scan-comparison/COMPARISON.md`](scan-comparison/COMPARISON.md). Full page: `scan-comparison/scanner-bench.html`.

| Scanner | Servers flagged (of 5) |
| --- | ---: |
| Cisco mcp-scanner (YARA + LLM) | 4 |
| Ramparts (YARA only) | 1 |
| MCP-Shield | 1 |
| fr2endly mcp-scan | 5 (mostly noise) |
| Nova-Proximity (keyword rule, no LLM) | 0 |
| mcp-fence 0.1.2 | cannot scan hosted servers, still prints PASS |

No server was clearly malicious. The most actionable item is a `SKILL.md` resource on Veterical that tells the agent to run `npm install -g veterical`. Only Ramparts and Cisco's YARA rules flagged that file, both for weak reasons. What we fixed in zgScanner after the bench is in `docs/archive/status.md` ("zgScanner bench").

## Files

| Path | Content |
| --- | --- |
| `scan-comparison/raw/` | Metadata each server listed |
| `scan-comparison/control/` | Hand review (`CONTROL-REVIEW.md`) and the resources it read |
| `scan-comparison/<scanner>/` | Output of each scanner. PowerShell 5.1 wrote the `.txt` files in UTF-16 |
| `scan_mcp.py`, `scan-mcp.cmd` | Our wrapper: paste a URL, install line or JSON config; runs Cisco mcp-scanner on hosted servers only |
| `*.cmd` | Windows wrappers for each scanner. They expect the install folder next to them |
| `mcp-shield/scan-urls.mjs` | Our wrapper: scans only the given URLs, so MCP-Shield does not start the local servers in this PC's configs |
| `patches/cisco-mcp-scanner.patch` | Our local fixes to Cisco mcp-scanner: legacy HTTP protocol fallback, stdio discover timeout retry, clean exit |

## Scanner versions

| Scanner | Source | Version |
| --- | --- | --- |
| Cisco mcp-scanner | https://github.com/cisco-ai-defense/mcp-scanner | `10032f9886dfc6850c2ab673626b61d6e0340a34` + our patch |
| fr2endly mcp-scan | https://github.com/fr2endly/mcp-scan | `12fe4a1b4897bccd653c587675df172ce8520919` |
| Nova-Proximity | https://github.com/Nova-Hunting/nova-proximity | `d7521742dd8d25efee9b75f9fff2e7c8e8774cdb` |
| MCP-Shield | npm `mcp-shield` | 1.0.4 (`mcp-shield/package-lock.json`) |
| mcp-fence | PyPI `mcp-fence` | 0.1.2 |
| Ramparts | https://github.com/highflame-ai/ramparts | Linux release binary, run through WSL (the Windows build has no YARA) |

## Rerun

Easiest: run the wrappers from `C:\Test`, where the installs are. To rebuild here instead, put each install in the folder its `.cmd` names (git ignores those folders), for example:

```bash
git clone https://github.com/cisco-ai-defense/mcp-scanner bench/mcp-scanner
```

Then check out the commit above, apply `patches/cisco-mcp-scanner.patch`, and create `.venv` inside it. Cisco's LLM check reads `mcp-scanner/.env`. That file holds an API key, so it is never committed. On the bench, DeepSeek needed `MCP_SCANNER_DEFAULT_LLM_MAX_TOKENS=4000`.
