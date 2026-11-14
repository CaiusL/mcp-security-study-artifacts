# zgscanner report

Scanned 2026-11-02T05:17:19Z. Risk 45/100 (grade C). 7 finding(s) across 1 server(s) (0 connected, 11 tools) and 0 skill(s) from 0 config file(s).

| Critical | High | Medium | Low | Info |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 2 | 2 | 3 | 0 |

Checks: 5 failed, 52 passed, 16 skipped.

## OWASP MCP Top 10

| Id | Risk | Findings | Worst |
| --- | --- | ---: | --- |
| MCP01 | Token Mismanagement & Secret Exposure | 0 | - |
| MCP02 | Privilege Escalation via Scope Creep | 4 | high |
| MCP03 | Tool Poisoning | 1 | high |
| MCP04 | Software Supply Chain Attacks & Dependency Tampering | 1 | high |
| MCP05 | Command Injection & Execution | 0 | - |
| MCP06 | Prompt Injection via Contextual Payloads | 0 | - |
| MCP07 | Insufficient Authentication & Authorization | 0 | - |
| MCP08 | Lack of Audit and Telemetry | 0 | - |
| MCP09 | Shadow MCP Servers | 0 | - |
| MCP10 | Context Injection & Over-Sharing | 3 | low |

## Findings

| Severity | Check | Target | Location | Detail |
| --- | --- | --- | --- | --- |
| high | SK007 Package runner in allowed-tools | mcp.veterical.com | skill://veterical/veterical/SKILL.md | pre-approves a package runner with open arguments; it runs whatever version the registry serves today |
| high | SK010 Served skill exceeds the declared boundary | mcp.veterical.com | skill://veterical/veterical/SKILL.md:129 | the server declares a read-only boundary, but this served skill grants Bash(veterical:*) Bash(npx veterical:*) in allowed-tools; documents deletes (veterical cl |
| medium | TF006 Financial execution or paid calls | mcp.veterical.com | skill://veterical/clinic-administration/SKILL.md | skill moves money |
| medium | TF006 Financial execution or paid calls | mcp.veterical.com | tool:list_payments | moves money or places orders |
| low | TF002 Private data access | mcp.veterical.com | tool:list_calendar_events | reads non-public data |
| low | TF002 Private data access | mcp.veterical.com | tool:list_payments | reads non-public data |
| low | TP012 Oversized description | mcp.veterical.com | instructions | 7250 characters |

## Checks

| Check | Title | Status | Findings | Note |
| --- | --- | --- | ---: | --- |
| TP001 | Hidden instruction block | pass | 0 |  |
| TP002 | Instruction override or jailbreak phrase | pass | 0 |  |
| TP003 | Concealment from the user | pass | 0 |  |
| TP004 | Cross-tool directive or shadowing | pass | 0 |  |
| TP005 | Sensitive file or credential path | pass | 0 |  |
| TP006 | Conversation or context exfiltration | pass | 0 |  |
| TP007 | Exfiltration-shaped parameter | pass | 0 |  |
| TP008 | Hidden Unicode characters | pass | 0 |  |
| TP009 | Terminal escape sequences | pass | 0 |  |
| TP010 | Encoded or obfuscated payload | pass | 0 |  |
| TP011 | Homoglyph or mixed-script name | pass | 0 |  |
| TP012 | Oversized description | fail | 1 |  |
| TP013 | Coercive urgency or authority claim | pass | 0 |  |
| TP014 | Suspicious URL or download | pass | 0 |  |
| TP015 | Malicious command pattern | pass | 0 |  |
| TP016 | Declared capability mismatch | pass | 0 |  |
| TP017 | Duplicate tool name across servers | pass | 0 |  |
| TP018 | Agent-steering directive | pass | 0 |  |
| TP019 | Server-supplied install or run instruction | pass | 0 |  |
| TF001 | Untrusted content source | pass | 0 |  |
| TF002 | Private data access | fail | 2 |  |
| TF003 | Public sink or exfiltration channel | pass | 0 |  |
| TF004 | Destructive capability | pass | 0 |  |
| TF005 | Command or code execution capability | pass | 0 |  |
| TF006 | Financial execution or paid calls | fail | 2 |  |
| TF007 | Toxic flow (untrusted source + private data + sink) | pass | 0 |  |
| TF008 | Excessive tool surface | pass | 0 |  |
| SC001 | Unconstrained path argument | pass | 0 |  |
| SC002 | Unconstrained URL argument | pass | 0 |  |
| SC003 | Raw SQL argument | pass | 0 |  |
| SC004 | Shell command argument | pass | 0 |  |
| SC005 | Weak input schema | pass | 0 |  |
| SC006 | Missing safety annotations | pass | 0 |  |
| SEC001 | Hardcoded secret | pass | 0 |  |
| SK002 | Insecure credential handling | pass | 0 |  |
| CF002 | Unpinned package launch | pass | 0 |  |
| CF003 | Shell-wrapped or inline-script launch | pass | 0 |  |
| CF004 | Insecure remote transport | pass | 0 |  |
| CF005 | Remote server without configured auth | pass | 0 |  |
| CF006 | Overbroad filesystem scope | pass | 0 |  |
| CF007 | Weakened container isolation | pass | 0 |  |
| CF008 | Project-scoped server config | pass | 0 |  |
| CF009 | Typosquat or impersonation | pass | 0 |  |
| CF010 | Known-vulnerable pin | pass | 0 |  |
| CF011 | Dependency advisory (OSV) | skipped | 0 | Needs --osv (queries api.osv.dev with package names and versions). |
| CF012 | Dangerous environment override | pass | 0 |  |
| CF013 | Server not on allowlist | skipped | 0 | Needs --allowlist FILE. |
| CF014 | Agent hook runs a command | pass | 0 |  |
| CF015 | Editor task runs when the folder opens | pass | 0 |  |
| RP001 | Tool definition changed since pin | skipped | 0 | Needs a pins file from an earlier --pin run. |
| RP002 | Server config changed since pin | skipped | 0 | Needs a pins file from an earlier --pin run. |
| RP003 | Skill content changed since pin | skipped | 0 | Needs a pins file from an earlier --pin run. |
| RP004 | Server can change its tool list at runtime | pass | 0 |  |
| PR001 | Tools differ by client identity (bait and switch) | skipped | 0 | Needs --identify-as and at least one connected server. |
| PR003 | Protocol hygiene | pass | 0 |  |
| SK001 | Overbroad allowed-tools | pass | 0 |  |
| SK003 | Runtime-fetched instructions | pass | 0 |  |
| SK004 | System service or persistence change | pass | 0 |  |
| SK005 | Writes to agent memory or config | pass | 0 |  |
| SK006 | Skill spec violation | pass | 0 |  |
| SK007 | Package runner in allowed-tools | fail | 1 |  |
| SK009 | Undeclared network egress | pass | 0 |  |
| SK010 | Served skill exceeds the declared boundary | fail | 1 |  |
| CODE001 | Unsafe execution in code | skipped | 0 | Needs --source DIR or a skill with script files. |
| CODE002 | Unsafe deserialization | skipped | 0 | Needs --source DIR or a skill with script files. |
| CODE003 | Hardcoded outbound host | skipped | 0 | Needs --source DIR or a skill with script files. |
| CODE004 | Listener on all interfaces | skipped | 0 | Needs --source DIR or a skill with script files. |
| CODE005 | TLS verification disabled | skipped | 0 | Needs --source DIR or a skill with script files. |
| CODE006 | Outbound call without timeout | skipped | 0 | Needs --source DIR or a skill with script files. |
| CODE007 | No audit logging found | skipped | 0 | Needs --source DIR or a skill with script files. |
| CODE008 | Unpinned dependency manifest | skipped | 0 | Needs --source DIR or a skill with script files. |
| VT001 | Known-malicious file hash | skipped | 0 | Needs --virustotal and VT_API_KEY (hash lookups only). |
| LLM001 | LLM judge: deceptive or manipulative tool text | skipped | 0 | Needs --llm, the anthropic package, and Anthropic credentials. |

## Scanner coverage

| Scanner | Covered | Gaps |
| --- | ---: | --- |
| Snyk Agent Scan (formerly Invariant Labs mcp-scan) | 18/19 | Background MDM reporting to Snyk Evo (fleet reporting service, out of scope for a local scanner) |
| Cisco AI Defense MCP Scanner (mcp-scanner) | 15/17 | Cisco AI Defense Inspect API (proprietary cloud API; LLM001 is the local stand-in); PyPI / npm package download and sandboxed analysis (needs a container; this  |
| MCP-Shield (riseandignite) | 8/8 | - |
| Ramparts (Javelin, now Highflame) | 18/18 | - |
| Proximity (fr0gger, now Nova-Hunting) | 7/7 | - |
| mcp-context-protector (Trail of Bits) | 5/6 | Quarantine of flagged responses (runtime proxy feature; the wiggle Needed proxy is the enforcement layer here) |
| MCP Watch (kapilduraphe) | 12/12 | - |
| MCPSafetyScanner (Halloran et al.) | 4/4 | - |
| Agentic Radar (SplxAI) | 2/3 | Runtime adversarial tests (out of scope; wiggle's probe lattice measures reachable effects instead) |
| mcpguard (OWASP MCP Top 10 config scanner) | 4/5 | Auto-fix (fixes are listed as remediation text; zgscanner never edits configs) |
| mcp-security-scan (AgentAvow) | 3/3 | - |
| wiggle declared scan (this repository) | 3/3 | - |
