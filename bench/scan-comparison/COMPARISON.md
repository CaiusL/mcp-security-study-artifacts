# Scanner comparison: 5 random hosted servers from mcpservers.org (2026-10-22)

Full report with zgScanner (C:\On9MCP) added: https://claude.ai/artifact/UqZgmR6HXs6N9pvEnukYe1 (`scanner-bench.html`).
zgScanner 0.1.0, static rules, one run per server (`zgscanner/<host>/`): Hallux D/74, WealthMCP A/3, Veterical B/16, Vuntum B/16, AIK B/13.

How they were picked: random listing pages (40, 84, 107, 113), third-party (no "official"/"sponsor" badge),
hosted URL, tools listable without a key; 5 drawn at random from the 17 that answered.
Pages past ~130 are almost all local GitHub packages, which would mean running their code here, so they were left out.
Every scanner only listed metadata (initialize, tools/prompts/resources list, resources read). No tool was called.

| Server (tools) | Cisco mcp-scanner | Ramparts | MCP-Shield | fr2endly mcp-scan | Nova-Proximity | mcp-fence |
|---|---|---|---|---|---|---|
| Hallux `api.blvkware.dev/hallux/mcp` (4) | UNSAFE: 3 HIGH (2 tools + instructions)* | pass | clean | 4 Critical, 1 High | 0 | can't scan |
| WealthMCP `wealthmcp.ai/mcp` (8) | UNSAFE: 1 HIGH (`list_skills`)* | pass | clean | 2 Crit, 1 High, 7 Med, 3 Low | 0 | can't scan |
| Veterical `mcp.veterical.com/mcp` (11 + 6 res) | tools clean; SKILL.md YARA HIGH**; 4 HTML resources too big to scan | 1 HIGH + 1 MED (SKILL.md resource) | clean | 11 Crit, 23 Med, 3 Low | 0 | can't scan |
| Vuntum `vuntum.com/mcp` (16) | SAFE | pass | clean | 16 Med | 0 | can't scan |
| AIK Stock Data `mcp.aikstockdata.com/mcp` (12) | UNSAFE: 2 HIGH (`get_data_urls` + instructions) | pass | 1 HIGH (`get_data_urls`) | 1 Crit, 1 Med, 12 Low | 0 | can't scan |
| **Servers flagged** | 4 / 5 | 1 / 5 | 1 / 5 | 5 / 5 | 0 / 5 | none (says PASS) |

\* First run was INCOMPLETE (DeepSeek returned empty answers). Re-run with `MCP_SCANNER_DEFAULT_LLM_MAX_TOKENS=4000` completed.
\*\* `scan_mcp.py` only reads `text/plain`/`text/html` resources and counts the others as done. A separate run over
the markdown/JSON resources found this one (`cisco/resources-markdown-json.txt`); the LLM did not flag it.

## What the servers actually contain (from reading `raw/` by hand)

None shows clearly malicious content. Things worth knowing:

1. **Veterical**: the `skill://veterical/veterical/SKILL.md` resource tells the agent to `npm install -g veterical`
   and to store an API key secret. An MCP resource pushing a global package install is the most actionable item
   in the whole set. Only Ramparts and Cisco's YARA rules flagged that file, and both for weak reasons (more than one
   domain; text about API keys).
2. **WealthMCP**: `get_skill` returns instructions that the agent is told to "follow exactly". That text arrives
   when the tool runs, so no metadata scanner can see it. Cisco's flag on `list_skills` points at this.
3. **Hallux**: by design it asks to be called before every install command and handed every dependency file, so
   those go to blvkware.dev. `hallux_watch` POSTs to a callback URL you supply.
4. **AIK Stock Data**: it tells the agent to call `get_data_urls` "before concluding something is unavailable" and to
   fetch raw dataset URLs. This steers the agent but carries little risk.
5. **Vuntum**: clean. It even tells the agent not to follow quoted source text.

## Scanner notes

- **Cisco**: the LLM flags pointed at the right text in 4 of the 5 servers. "Prompt injection, HIGH" overstates what is
  really steering language. It needs the higher token budget with deepseek-flash. Resources over 100 KB are skipped.
- **Ramparts**: YARA only (no LLM configured). It stayed quiet on the tools. Its mixed http/https warning comes from
  `$schema: http://json-schema.org`, a false positive.
- **MCP-Shield**: right tool, wrong reasons. It matched "instead of" and "API key" in text that says "no API key".
- **fr2endly**: almost all noise. `$schema` URLs count as "external endpoint", the substring `auth` counts as
  "reads secrets" (Critical), and the words `shell`/`system` count as "executes arbitrary commands". It does
  correctly note the webhook in `hallux_watch`.
- **Nova** (keyless, `DetectJailbreaking` keyword rule): it flagged nothing, so on its own its result tells you nothing.
- **mcp-fence 0.1.2**: it can't inspect hosted servers ("Live inspection unavailable ... static checks only"),
  but it still prints `verdict=PASS`.

Files: `raw/` holds each server's metadata as listed; one folder per scanner holds its output
(PowerShell 5.1 wrote the `.txt` files in UTF-16).
