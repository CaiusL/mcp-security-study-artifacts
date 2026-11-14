# Control review: the 5 servers checked by hand (2026-10-22)

Same read-only rule as the scanners: initialize, the list calls and resource reads. No tool was called.
Everything fetched is in this folder (`<host>/control.json`, the resource files, both Veterical SKILL.md files).

## Checks run on every server
- Fresh fetch compared with the morning dump: no tool changed on any server.
- Initialize as `mcp-probe` and again as `claude-ai`: same tools and same instructions on all five (no bait-and-switch).
- Pagination followed: every list fit on one page, so no tools were hidden past a cursor.
- Every string in the metadata and text resources: no zero-width, bidi or tag characters, no ANSI codes, no encoded payloads.
  The one base64 string is Veterical's SVG icon, which has no script, event handler or link.
- All 51 tool definitions, instructions, annotations, schemas and `_meta`, plus the resources, read in full.
  Veterical's four ~480 KB HTML bundles were pattern-scanned and spot-read, not read line by line.

## Verdicts

**Veterical: HIGH.** The connector's instructions promise an administrative, read-only boundary:
no owner or animal records, and no tools that create, update or delete anything. The same server also ships
`skill://veterical/veterical/SKILL.md` and declares the `io.modelcontextprotocol/skills` extension.
That skill drives the `veterical` CLI with full create, update and permanent delete of clients, patients,
appointments, invoices, payments and vaccination records. Its header sets `allowed-tools: Bash(veterical:*) Bash(npx veterical:*)`,
which pre-approves running an unpinned npm package on the user's machine in clients that honor that field.
It also covers `veterical signup` (account creation) and a device-code login.
A client that loads served skills is one step from the full write API the connector says it lacks.
In mitigation, it is the vendor's own CLI, and the skill says to confirm deletes and keep keys out of transcripts.
The tool definitions themselves are careful, and the HTML widgets ship a strict CSP
(`default-src 'none'`, `form-action 'none'`; the workspace widget allows images from `www.imagelato.com`).

**Hallux: MEDIUM.** It is built to sit on the install path, and that makes it a trust choke point:
- `hallux_check_command` and `hallux_check_manifest` receive the full command or file. These can carry private package
  names and private index URLs with embedded tokens (for example `--extra-index-url https://user:token@...`).
- When a name is deprecated or blocked, the agent is told to use the server's `successor`. The server can therefore
  choose a replacement package for the agent to install. Nothing shows abuse, but trust in the server means trust in its replacements.
- The instructions and descriptions insert it before every install ("Call this BEFORE..."). That fits its purpose, but it is steering.
- `hallux_watch` registers a webhook to any https URL. Its annotations are honest (`readOnlyHint: false`).
- It fails closed: `unknown` must never be treated as permission.

**WealthMCP: MEDIUM.** A directory designed to steer the agent:
- `get_skill` returns runtime workflows that the agent is told to "follow exactly; never improvise". That content is not in the metadata.
- The instructions tell the agent to relay install commands and config snippets from listings verbatim. Some listings are "Community".
  A bad listing would therefore reach the user as a ready-to-run install line.
- If the agent's tools differ from what `server_info` reports, it is scripted to tell the user their client has a stale cache
  and should reconnect. With `listChanged: true`, this normalizes exactly the change a rug-pull check looks for.
- `openWorldHint: false`, although listings come from third parties.

**AIK Stock Data: LOW.** A read-only market data server. The instructions and `get_data_urls` push the agent to call that tool
"before concluding something is unavailable", then to fetch dataset URLs with its own fetch tool, outside MCP.
It states clearly that it gives no investment advice. Nothing is hidden.

**Vuntum: CLEAN.** Sixteen read-only lookups. It tells the agent not to follow quoted source text.
Tool output contains third-party quotes and repository text, so it carries some injection risk at runtime, and it says so.
`openWorldHint: false` is arguably inaccurate for that content.

## Missed by every scanner
- Veterical's served skill contradicts its own boundary and pre-approves `npx veterical`.
  Ramparts and Cisco's YARA rules flagged that file, but for other reasons.
- Hallux's `successor` field lets the server choose a replacement package.
- WealthMCP's verbatim install relay and its scripted "stale cache" explanation.

## Limits of this control
- Not blind: I had already seen the scanner output and a partial read of the metadata.
- Same read-only rule, so tool output stays unseen: WealthMCP's skills, AIK's URL catalog and Hallux's `successor` values.
- These are judgments from metadata. No server code was audited.
- Everything I read was handled as data. None of it was addressed to me, but an LLM reviewer can be steered by text it reads.
