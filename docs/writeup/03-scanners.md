# 3. The scanner landscape (C4)

*Draft, 2026-11-03. Sources: `bench/README.md`, `bench/scan-comparison/COMPARISON.md`, `bench/scan-comparison/zgscanner-current/README.md`.*

Static scanning is the first defense a team can deploy: read a server's metadata before connecting, and refuse a server that looks malicious. We tested how far that goes.

**Bench.** Six public scanners ran read-only against five randomly chosen hosted servers from mcpservers.org. A hand review of each server's metadata and resources was the control. No server was clearly malicious, and the scanners disagreed widely:

| Scanner | Servers flagged (of 5) |
| --- | ---: |
| Cisco mcp-scanner (YARA and LLM) | 4 |
| Ramparts (YARA only) | 1 |
| MCP-Shield | 1 |
| fr2endly mcp-scan | 5 (mostly noise) |
| Nova-Proximity (keyword rule, no LLM) | 0 |
| mcp-fence 0.1.2 | cannot scan hosted servers, still prints PASS |

**zgScanner.** We combined the checks of eleven public scanners and our own declared scan into one scanner of 73 checks (`README.md`). The hand review found gaps in its first version. We added four checks (SK007, SK010, TP018, TP019) and fixed three false positives. A static rescan of the five bench captures on 2026-11-02 shows the new checks catch the gaps the hand review found, and the clean control server gains no finding.

**What a scanner cannot see.** A scanner reads metadata. In the injection study (section 6.2), the attacks that succeeded used legitimate tools on benign servers, with the attacker's instruction in data the tools returned. zgScanner disconnected no server on the benign tool lists (0 of 6 servers) and blocked none of the successes (`artifacts/stage2/qwen3.8-flash/report.md`, "Scanner cost"; "Layers alone and stacked"). It disconnected the fixture server only for the goal-G3 description plant. Scanners are necessary, not sufficient: they cannot tell whether a given call serves the user or the attacker.
