# MCP incidents, vendor disclosures and CVEs (2025–2026): in-scope misuse vs boundary break

Prepared 2026-10-24 for the study "Which defense layer stops a prompt-injected MCP agent?".
Defense layers: (a) static scanner of configs/tool metadata · (b) the server's own checks · (c) least-privilege policy learned from benign traces · (d) task-conditioned policy written by a model from the user task · (e) data-flow rule (e.g. no fetch to a URL that came from tool output).

Defender's catalog: class-level only. No injection strings, payloads or reproduction steps.

Status: COMPLETE (2026-10-24). Sections: Q1 catalog (Parts A, B, C + adjacent), Q2 classification, Q3 layers, Q4 tally and caveats.

## Q1. Catalog: MCP incidents, disclosures and CVEs (2025-04 to 2026-10)

**Column key.**
- *Date* = CVE publication date from the CVE.org record (all CVE ids below were looked up through the CVE.org API on 2026-10-24 and are PUBLISHED), or the first public disclosure date for non-CVE items.
- *Agent in path?* = does the harm need an LLM agent to choose a tool call? "No" means a plain network or local attack on MCP software, with no model involved.
- *Class*: **IM** = in-scope misuse (every harmful call was inside the tool's declared scope and the user's grant; no bug needed). **BB** = boundary break (needs a bug or missing check in the server, client or host: path escape, command or argument injection, SSRF, missing auth, approval bypass). **SC** = supply chain / malicious or swapped server, package or config (the attacker controls the MCP component itself). Some rows carry two labels.
- *Layers* = which of (a)–(e) could plausibly have blocked it. **This column is my inference, not a claim from the source.** "(b)\*" means "a correct server/host check, i.e. the patch"; before the patch the deployed check failed by definition.

### Part A. CVE-backed rows (each CVE verified against CVE.org)

| # | Date | Product / package | CVE / GHSA | Channel (class level) | Agent in path? | Class | Layers that could block (inference + reason) | Source |
|---|---|---|---|---|---|---|---|---|
| A1 | 2025-06-13 | MCP Inspector (dev tool) < 0.14.1 | CVE-2025-49596 / GHSA-7f8r-222p-6f5g | A malicious web page reaches the local Inspector proxy, which had no auth between client and proxy, and launches stdio commands | No | BB (CWE-306, RCE) | (b)\* proxy auth. (a) only if the scanner checks tool versions. (c)(d)(e) n/a: no agent call. | [GHSA](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g) |
| A2 | 2025-09-08 | MCP Inspector < 0.16.6 | CVE-2025-58444 / GHSA-g9hg-qhmf-q45m | An untrusted remote MCP server returns a malicious OAuth redirect URI → XSS in Inspector → command execution | No | BB + SC precondition (malicious server) | (b)\*; (a) server allowlist. | [GHSA](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-g9hg-qhmf-q45m) |
| A3 | 2025-07-09 | mcp-remote (npm OAuth proxy client) | CVE-2025-6514 (JFrog CNA; JFSA-2025-001290844) | A malicious or compromised remote MCP server sends crafted OAuth metadata → OS command injection on the client host | No | BB (CWE-78) + SC precondition | (b)\* client fix; (a) flag unvetted remote server URLs or vulnerable versions. Agent-side layers cannot see it. | [JFrog (CVE record ref)](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability) |
| A4 | 2025-07-02 | Filesystem MCP reference server < 0.6.4 / 2025.7.01 | CVE-2025-53109 / GHSA-q66q-fx2p-7w4m (symlink); CVE-2025-53110 / GHSA-hc55-p739-j48w (prefix collision) | Path arguments escape the allowed directories. The agent chooses the path, so injected content can steer it. | Optional | BB (CWE-59, CWE-22) | (b)\* canonical-path check. (c) plausible: out-of-root paths are rare in benign traces. (d) if the task names the directory. | [GHSA 53109](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-q66q-fx2p-7w4m); [GHSA 53110](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-hc55-p739-j48w); Rehberger post on the same class, 2025-08-03 (see practitioner_media.md Q5) |
| A5 | 2025-12-17 | mcp-server-git reference server | CVE-2025-68143 / GHSA-5cgr-j3jf-jw3v (git_init at any path); CVE-2025-68144 / GHSA-9xwc-hfwc-8w59 (argument injection → file overwrite); CVE-2025-68145 / GHSA-j22h-9j4x-23w5 (--repository limit not enforced) | Tool arguments chosen by the agent | Yes (steerable) | BB (CWE-22, CWE-88) | (b)\*. (c) git_init outside known repos is rare in benign traces. (d) the task names one repo, so other paths are not needed. (e) path or ref argument tainted by tool output. | [GHSA 68143](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-5cgr-j3jf-jw3v); [GHSA 68144](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-9xwc-hfwc-8w59); [GHSA 68145](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-j22h-9j4x-23w5) |
| A6 | 2026-02-25 | mcp-server-git < 2026.1.14 | CVE-2026-27735 / GHSA-vjqx-cfc4-9h6v | git_add stages files outside the repository | Yes (steerable) | BB (CWE-22) | (b)\*; (c); (d) as A5. | [GHSA](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-vjqx-cfc4-9h6v) |
| A7 | 2025-10-08 | Framelink Figma MCP server < 0.6.3 | CVE-2025-53967 (MITRE CNA; no GHSA in the record) | Unauthenticated HTTP POST with shell metacharacters reaches a curl call inside the server | Optional | BB (command injection) | (b)\*; (a) flag an HTTP-exposed server with no auth. | [Imperva (CVE record ref)](https://www.imperva.com/blog/another-critical-rce-discovered-in-a-popular-mcp-server/); [release 0.6.3](https://github.com/GLips/Figma-Context-MCP/releases/tag/v0.6.3) |
| A8 | 2025-05-28 to 2025-09-08 | Long tail of third-party MCP servers with command injection in tool handlers (7 CVEs in one row): aws-mcp-server CVE-2025-5277 (2025-05-28; the record says a crafted prompt can trigger it); ios-simulator-mcp CVE-2025-52573 / GHSA-6f6r-m9pv-67jw (2025-06-26); mcp-server-kubernetes CVE-2025-53355 / GHSA-gjv4-ghm7-q58q (2025-07-08); node-code-sandbox-mcp CVE-2025-53372 / GHSA-5w57-2ccq-8w95 (2025-07-08, sandbox escape); github-kanban-mcp-server CVE-2025-53818 / GHSA-6jx8-rcjx-vmwf (2025-07-14); mcp-package-docs CVE-2025-54073 / GHSA-vf9j-h32g-2764 (2025-07-18); create-mcp-server-stdio CVE-2025-54994 / GHSA-3ch2-jxxc-v4xf (2025-09-08) | see left | Tool arguments chosen by the agent reach a shell; injected content can steer the arguments | Yes (steerable) | BB (CWE-77/78) | (b)\* no-shell exec. (c) plausible: metacharacters in args are absent from benign traces. (e) argument tainted by tool output. (d) weak: the tool itself is task-relevant. | [aws-mcp-server fix](https://github.com/alexei-led/aws-mcp-server/commit/94d20ae1798a43ac7e3a28e71900d774e5159c8a); [GHSA 52573](https://github.com/joshuayoes/ios-simulator-mcp/security/advisories/GHSA-6f6r-m9pv-67jw); [GHSA 53355](https://github.com/Flux159/mcp-server-kubernetes/security/advisories/GHSA-gjv4-ghm7-q58q); [GHSA 53372](https://github.com/alfonsograziano/node-code-sandbox-mcp/security/advisories/GHSA-5w57-2ccq-8w95); [GHSA 53818](https://github.com/Sunwood-ai-labs/github-kanban-mcp-server/security/advisories/GHSA-6jx8-rcjx-vmwf); [GHSA 54073](https://github.com/sammcj/mcp-package-docs/security/advisories/GHSA-vf9j-h32g-2764); [GHSA 54994](https://github.com/akoskm/create-mcp-server-stdio/security/advisories/GHSA-3ch2-jxxc-v4xf) |
| A9 | 2025-08-05 | Cursor < 1.3.9 ("CurXecute") | CVE-2025-54135 / GHSA-4cxx-hrm3-49rm | Injected content makes the agent *create* a new MCP config file in the workspace; creation (unlike edit) needed no approval, so a new server command runs | Yes | BB (host approval gap, CWE-78/829), reached via injection | (b)\* host gate on sensitive files. (c) writes to MCP config are absent in benign traces. (d) not needed for the task. (e) file content derived from tool output. | [GHSA](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm) |
| A10 | 2025-08-01 | Cursor ≤ 1.2.4 ("MCPoison") | CVE-2025-54136 / GHSA-24mc-g4xr-4395 | An already-approved MCP config in a shared repo is changed later; Cursor did not ask again | No | SC (swapped config) + BB (trust bound to name, not content) | (a) config scanner with hash pinning; (b)\* re-approval on change. | [GHSA](https://github.com/cursor/cursor/security/advisories/GHSA-24mc-g4xr-4395) |
| A11 | 2025-10-03 | Cursor ≤ 1.6.23 | CVE-2025-59944 / GHSA-xcwh-rrwj-gxc7 | Injected content makes the agent write the protected MCP config through a case-variant path | Yes | BB (CWE-178) | (b)\*; (c)(d)(e) as A9. | [GHSA](https://github.com/cursor/cursor/security/advisories/GHSA-xcwh-rrwj-gxc7) |
| A12 | 2025-11-04 | Cursor ≤ 1.7.28, MCP install deep link | CVE-2025-64106 / GHSA-4575-fh42-7848 | A crafted deep link hides the executed command in the install dialog; the user accepts | No | SC (malicious server install) + BB (warning bypass) | (a) scan the server command before install; (b)\*. | [GHSA](https://github.com/cursor/cursor/security/advisories/GHSA-4575-fh42-7848) |
| A13 | 2025-12-02 | Official MCP TypeScript SDK < 1.24.0 and Python SDK < 1.23.0 | CVE-2025-66414 / GHSA-w48q-cv73-mx4w; CVE-2025-66416 / GHSA-9h52-p55h-vw2f | DNS rebinding from a web page to an unauthenticated localhost HTTP MCP server (protection off by default) | No | BB (insecure default, CWE-1188) | (a) flag localhost HTTP servers with no auth; (b)\*. | [GHSA TS](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-w48q-cv73-mx4w); [GHSA Py](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-9h52-p55h-vw2f) |
| A14 | 2025-10-20 | oatpp-mcp (C++ MCP server library) | CVE-2025-6515 (JFrog CNA) | A network attacker predicts session IDs and injects responses into a legitimate client session ("prompt hijacking") | Yes (victim agent consumes forged output) | BB (CWE-330) enabling injection | (b)\* random session IDs. Downstream, (d)/(e) could still limit what the forged output makes the agent do. | [JFrog advisory](https://research.jfrog.com/vulnerabilities/oatpp-mcp-prompt-hijacking-jfsa-2025-001494691/) |
| A15 | 2025-06-19 | AI Engine WordPress plugin 2.8.0–2.8.3 (MCP feature) | CVE-2025-5071 (Wordfence CNA) | Any logged-in subscriber gets full MCP access → privilege escalation | No | BB (CWE-863, missing capability check) | (b)\*. | [Wordfence](https://www.wordfence.com/threat-intel/vulnerabilities/id/0e7654a1-0020-4bf1-86be-bdb238a9fe0d) |
| A16 | 2025-11-05 | AI Engine ≤ 3.1.3 | CVE-2025-11749 (Wordfence CNA) | The MCP REST endpoint exposes the bearer token when the "No-Auth URL" option is on | No | BB (CWE-200) + misconfiguration | (b)\*; (a) flag the No-Auth option. | [Wordfence](https://www.wordfence.com/threat-intel/vulnerabilities/id/06eaf624-aedf-453d-8457-d03a572fac0d) |

Also verified but outside the injection scope: MCP Python SDK denial-of-service bugs CVE-2025-53365 / GHSA-j975-95f5-7wqh and CVE-2025-53366 / GHSA-3qhf-m339-9g5v (both 2025-07-04). — [GHSA](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-j975-95f5-7wqh)

### Part B. Incidents and disclosures without a CVE, plus CVE-backed 2026 disclosures with a write-up

Verification tags: **CVE** = CVE id checked on CVE.org this session. **S** = facts from search-result summaries of the cited pages (page not opened in full). **PM** = re-used from practitioner_media.md, not re-opened this session.

| # | Date | Product / package | CVE / GHSA | Channel (class level) | Agent in path? | Class | Layers that could block (inference + reason) | Source |
|---|---|---|---|---|---|---|---|---|
| B1 | 2025-04-01 | Tool poisoning PoC (Invariant Labs), Cursor + a malicious MCP server | none | Hidden instructions in a malicious server's tool description make the agent read local secrets and pass them out as a tool argument | Yes | SC (malicious metadata) → in-scope actions | (a) description scanner (this is the case MCP-scan was built for). (e) secret flows into another tool's argument. (d) the secret read is not needed for the task. | [Invariant](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) (PM) |
| B2 | 2025-04 (day not confirmed) | whatsapp-mcp (Invariant Labs) | none | Variant 1: a malicious "sleeper" server changes its tool description after approval (rug pull) and redirects the trusted send tool, so chat history goes to the attacker. Variant 2: no malicious server; an injected incoming message makes the agent leak the contact list. | Yes | SC (variant 1) + IM (variant 2) | Variant 1: (a) with description pinning. Variant 2: (d) recipient is not in the task; (e) private data → send to a recipient that came from untrusted content. (b) no: the WhatsApp server works as designed; a reviewer calls it structural and unfixed. | [Invariant](https://invariantlabs.ai/blog/whatsapp-mcp-exploited); [Docker "MCP Horror Stories"](https://www.docker.com/blog/mcp-horror-stories-whatsapp-data-exfiltration-issue/) (S) |
| B3 | 2025-05-26 | Official GitHub MCP server (Invariant Labs) | none | A malicious issue in a public repo makes the agent read the user's private repos and publish the data in a public-repo PR | Yes | **IM** (legitimate server, legitimate token, no code bug) | (d) the task concerns one public repo. (e) private data → public sink after untrusted read. (c) partial: private-repo reads may be common in benign traces. (a)(b) no. | [Invariant](https://invariantlabs.ai/blog/mcp-github-vulnerability) (PM); [AuthZed timeline](https://authzed.com/blog/timeline-mcp-breaches) (V) |
| B4 | 2025-06-04 (found); MCP off 2025-06-05 to 06-17 | Asana MCP server | none | Logic flaw: data from one organization was visible to MCP users of other organizations; about 1,000 customers possibly affected; Asana saw no sign of exploitation | No (no attacker needed) | BB (server-side access control, cross-tenant) | (b)\* only. Agent-side layers cannot see it. | [BleepingComputer](https://bleepingcomputer.com/news/security/asana-warns-mcp-ai-feature-exposed-customer-data-to-other-orgs/); [UpGuard](https://upguard.com/blog/asana-discloses-data-exposure-bug-in-mcp-server) (S) |
| B5 | Reported 2025-06-13, fixed 2025-06-15; public write-up later in 2025 | Smithery.ai MCP hosting (GitGuardian) | none | Path traversal in a build-config field exposed a registry/deploy token with control over 3,000+ hosted MCP servers; no confirmed abuse | No | BB in the hosting platform, with supply-chain blast radius | (b)\* platform fix. Agent-side layers cannot see it. | [SC World](https://www.scworld.com/news/smithery-ai-fixes-path-traversal-flaw-that-exposed-3000-mcp-servers); [iTWire](https://itwire.com/business-it-news/security/from-path-traversal-to-supply-chain-compromise-breaking-mcp-server-hosting.html) (S) |
| B6 | 2025-06-19 | Atlassian MCP + Jira Service Management, "Living off AI" (Cato CTRL) | none | An external support ticket carries instructions; the support engineer's AI session runs them with the engineer's own permissions, pulls internal tickets and posts them back to the attacker's ticket | Yes | **IM** | (d) other tickets are not needed for the task. (e) internal data → the same untrusted ticket. | [Cato CTRL](https://www.catonetworks.com/blog/cato-ctrl-poc-attack-targeting-atlassians-mcp/); [Infosecurity](https://infosecurity-magazine.com/news/atlassian-ai-agent-mcp-attack) (S) |
| B7 | 2025-06-24 | Anthropic reference Slack MCP server (Rehberger) | none | Data exfiltration through the server's normal message posting. Believed mechanism: a link preview ("unfurl") of a URL that carries data. **Mechanism from prior knowledge, not re-verified.** | Yes | **IM** (posting is in scope; the preview is a side channel) | (e) URL built from private data. (b) partial: the server could disable previews. | [Embrace The Red](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) (PM) |
| B8 | 2025-07 (Willison write-up 2025-07-06) | Supabase MCP + Cursor (General Analysis) | none | A support ticket carries instructions; the developer's agent runs with service_role (bypasses row-level security), reads a private tokens table and writes it into the ticket thread the attacker can read | Yes | **IM** (allowed SQL on an allowed project) | (c) a benign "review tickets" trace never reads the tokens table. (d) not needed for the task. (e) secret → attacker-readable table. Supabase's fix is least-privilege defaults (read-only mode, project scoping). | [Willison](https://simonwillison.net/2025/Jul/06/supabase-mcp-lethal-trifecta/) (S) |
| B9 | 2025-08-09 (Black Hat USA 2025) | Cursor + Jira MCP, AgentFlayer (Zenity Labs) | none | A Jira ticket (can be auto-created from support email) makes Cursor in auto-run mode find repo secrets and send them out | Yes | **IM**; Cursor called it a known issue | (d) secret search not needed for the task. (e) secret → outbound request. (c) partial. | [Zenity Labs](https://labs.zenity.io/p/when-a-jira-ticket-can-steal-your-secrets); [Willison](https://simonwillison.net/2025/Aug/9/when-a-jira-ticket-can-steal-your-secrets/) (S) |
| B10 | Malicious v1.0.16 released 2025-09-17; disclosed late Sept 2025 | postmark-mcp npm package (Koi Security) | none | A copy of a legitimate email MCP server with one added line that BCCs every sent email to the attacker. Called the first malicious MCP server seen in the wild; about 1,500–1,643 downloads | No (server code acts alone) | **SC, in the wild** | (a) only if the scanner diffs package code or checks publisher reputation; tool metadata looks normal. (b) n/a: the server is the attacker. (c)(d)(e) cannot see an exfil inside server code (inference). | [The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html); [CSO](https://www.csoonline.com/article/4064009/trust-on-mcp-takes-first-in-the-wild-hit-via-squatted-postmark-connector.html) (S) |
| B11 | Reported 2025-07-03; published 2025-11-05 | Anthropic's official Claude Desktop extensions for Chrome, iMessage, Apple Notes, "PromptJacking" (Koi) | none found | Unescaped input reaches AppleScript (command injection); reachable when the agent reads a hostile web page. CVSS 8.9 per Anthropic; patched | Yes | BB | (b)\*. (e) argument tainted by web content. (c) plausible. | [Koi](https://www.koi.ai/blog/promptjacking-the-critical-rce-in-claude-desktop-that-turn-questions-into-exploits); [Infosecurity](https://www.infosecurity-magazine.com/news/claude-desktop-extensions-prompt/) (S) |
| B12 | 2026-02-09 | Claude Desktop Extensions, zero-click calendar case (LayerX) | none | A calendar event carries instructions; a vague user request lets the agent chain a calendar tool with an unsandboxed local-exec extension. Anthropic declined to fix: the user installed the tools and allowed them to run without prompts | Yes | **IM** (cross-tool composition; no bug) | (d) code execution not needed for "check my calendar". (e) command derived from calendar content. (a) a toxic-flow scan of the toolset could flag untrusted-input + exec. | [Infosecurity](https://www.infosecurity-magazine.com/news/zeroclick-flaw-claude-dxt/); [TechRepublic](https://techrepublic.com/article/news-claude-desktop-zero-click-vulnerability) (S) |
| B13 | 2026-02-25 (Check Point); CVEs published 2025-10-03 and 2026-01-21 | Claude Code project files | CVE-2025-59536 / GHSA-4fgq-fpq9-mr3g; CVE-2026-21852 / GHSA-jh7p-qr78-84p7; hooks GHSA-ph6w-f82w-28w6 (S) | A malicious repo's settings start MCP servers or hooks before the trust dialog, or redirect API traffic and leak the API key | No (no agent decision) | SC (malicious repo config) + BB (trust ordering) | (a) scan repo config before opening; (b)\*. | [Check Point](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files/) (S); CVE records (CVE) |
| B14 | CVE published 2026-03-30 (patch 2026-03-15 per secondary) | nginx-ui MCP integration ("MCPwn") | CVE-2026-33032 (CVE) | One of two MCP HTTP endpoints applied only an IP check, not auth → remote nginx takeover. A secondary source says it was exploited in the wild; **not confirmed from a primary source** | No | BB (CWE-306) | (b)\*; (a) flag exposed MCP endpoints. | [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-33032); exploitation claim via [Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/) (S) |
| B15 | 2026-04-15 | OX Security "MCP Supply Chain Advisory": STDIO server config → command execution in ~14 AI products (LangFlow, LiteLLM, Flowise, Windsurf, DocsGPT, …) | 14 CVEs listed by OX, e.g. CVE-2026-30615 (Windsurf, CVE) | Attacker-controlled command/args reach the STDIO launch with no allowlist; in Windsurf the path is prompt injection via HTML → agent edits MCP config → new server runs. OX lists Anthropic's MCP as "won't be patched" | Mixed (Windsurf: yes; web-UI variants: no) | BB (host allowlist missing) | (b)\* host command allowlist. (a) scan new server commands. Windsurf variant: (c)(d) config writes not in benign traces / task; (e) config content from tool output. | [OX Security](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/) (V); [CVE-2026-30615](https://www.cve.org/CVERecord?id=CVE-2026-30615) (CVE) |
| B16 | 2026-02 | Fake "Oura" MCP project, trojanized clone in public registries | none | Malware posing as a known MCP server | No | SC, reported in the wild | (a) registry or reputation checks. Agent-side layers cannot see it. | [AuthZed timeline](https://authzed.com/blog/timeline-mcp-breaches) (V, secondary only; primary report not found) |
| B17 | 2026-06-30 | Microsoft IR / Defender invoice-agent example | none | A poisoned MCP tool description makes an invoice agent leak data; every step was "legitimate" (approved tool, analyst's own permissions, allowed outbound host). **Illustrative; not stated to be a specific customer breach** | Yes | SC (poisoned metadata) → in-scope actions | (a) description scan. (e) data → outbound host chosen by the description. (d). Static least privilege fails (Microsoft's own point). | [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/) (PM) |

### Part C. Other 2026 MCP CVEs whose CVE text names prompt injection or an LLM-controlled argument (all CVE)

| # | Date (CVE pub.) | Product / package | CVE | Channel (class level) | Agent in path? | Class | Layers that could block (inference + reason) | Source |
|---|---|---|---|---|---|---|---|---|
| C1 | 2026-07-03 | Kong Konnect MCP server < 1.0.0 | CVE-2026-13341 (Kong CNA, CWE-20) | Indirect prompt injection through untrusted analytics data → unintended API requests, credential exposure | Yes | IM? (vendor fixed it; mechanism detail not in the record) | (d)(e) likely; (b) partial. | [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-13341) |
| C2 | 2026-08-03; 2026-09-15 | AWS Labs Amazon MQ MCP server < 2.0.24; Contentful MCP server < 1.7.19 | CVE-2026-18655 (AMZN CNA, CWE-923); CVE-2026-53957 (CWE-918) | Injected content makes the agent pass an attacker host as a connection/host argument; the server then sends its credentials or token there | Yes | BB (missing endpoint restriction). **Borderline IM**: the tool's declared scope did not restrict hosts | **(e) is the textbook fit** (no request to a host that came from tool output); (b)\*; (d). | [CVE-2026-18655](https://www.cve.org/CVERecord?id=CVE-2026-18655); [CVE-2026-53957](https://www.cve.org/CVERecord?id=CVE-2026-53957) |
| C3 | 2026-03-20; 2026-07-21 | CKAN MCP server < 0.4.85; mcp-webresearch 0.1.7 | CVE-2026-33060 (CWE-918); CVE-2026-65056 (VulnCheck, CWE-918) | SSRF: the agent can be steered to fetch internal or cloud-metadata addresses | Yes | BB (SSRF) | (e) direct fit; (b)\* IP filtering. | [CVE-2026-33060](https://www.cve.org/CVERecord?id=CVE-2026-33060); [CVE-2026-65056](https://www.cve.org/CVERecord?id=CVE-2026-65056) |
| C4 | 2026-07-22; 2026-08-25; 2026-10-01 | Ansible Lightspeed MCP server (Red Hat); browse-mcp < 0.8.2; Office-PowerPoint-MCP-Server ≤ 2.0.7 | CVE-2026-44192 (Red Hat CNA); CVE-2026-55557; CVE-2025-71427 (VulnCheck) | Path traversal reachable by steering the agent through indirect prompt injection → file write outside the work dir (RCE / exfil per Red Hat) | Yes | BB (CWE-22) | (b)\*; (c) out-of-root paths; (d). | [CVE-2026-44192](https://www.cve.org/CVERecord?id=CVE-2026-44192); [CVE-2026-55557](https://www.cve.org/CVERecord?id=CVE-2026-55557); [CVE-2025-71427](https://www.cve.org/CVERecord?id=CVE-2025-71427) |
| C5 | 2026-03-07 | Tencent WeKnora < 0.3.0 (MCP client) | CVE-2026-30856 (CWE-706) | A malicious remote MCP server uses a tool-name collision plus injection to hijack which tool runs | Yes | SC + BB (ambiguous naming in client) | (a) flag name collisions / shadowing; (b)\*. | [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-30856) |
| C6 | 2026-08-18 | Context7 ≤ 2.1.2 (documentation MCP server) | CVE-2026-75130 (VulnCheck, CWE-1427) | Third-party-authored "custom AI instructions" are served unsanitized through the MCP server → coding agents leak credentials | Yes | IM in the agent (legitimate server serving attacker-authored content); vendor treated the missing sanitization as the bug | (e) credentials → outbound; (d). (a) no: it is tool *output*, not metadata. | [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-75130) |
| C7 | 2026-08-31; 2026-09-24 | MCPHub < 1.0.32; DBHub < 0.22.5 | CVE-2026-79745 (CWE-862); CVE-2026-61742 (CWE-306/346) | Missing authorization on prompt/resource editing (MCPHub); DNS rebinding to an unauthenticated HTTP MCP endpoint → SQL from a web page (DBHub) | No | BB | (b)\*; (a) flag unauthenticated HTTP transport. | [CVE-2026-79745](https://www.cve.org/CVERecord?id=CVE-2026-79745); [CVE-2026-61742](https://www.cve.org/CVERecord?id=CVE-2026-61742) |

### Adjacent items (MCP hosts or non-MCP agents; NOT in the tally)
- Claude Code CVE-2025-55284 / GHSA-x5gv-jw7f-j6xj (2025-08-16, CVE): an over-broad default "safe command" allowlist let injected content cause a file read plus network exfiltration without a prompt. Under the students' definition this is **in-scope misuse of an over-broad host allowlist**, which the vendor then fixed by narrowing the allowlist. (e) fits. — [GHSA](https://github.com/anthropics/claude-code/security/advisories/GHSA-x5gv-jw7f-j6xj)
- Claude Code CVE-2025-54795 (approval bypass via command parsing) and CVE-2025-54794 (path prefix bypass), both 2025-08-05 (CVE): BB in built-in host tools. — [GHSA-x56v-x2h6-7j34](https://github.com/anthropics/claude-code/security/advisories/GHSA-x56v-x2h6-7j34); [GHSA-pmw4-pwvc-3hx2](https://github.com/anthropics/claude-code/security/advisories/GHSA-pmw4-pwvc-3hx2)
- Claude Code IDE extensions CVE-2025-52882 / GHSA-9f65-56v6-gxw7 (2025-06-24, CVE): web pages could connect to the extension's local WebSocket server (BB, no agent). Whether that server is MCP-based was not confirmed this session. — [GHSA](https://github.com/anthropics/claude-code/security/advisories/GHSA-9f65-56v6-gxw7)
- GitHub Copilot + Visual Studio CVE-2025-53773 (2025-08-12, CVE): command-injection RCE via prompt injection (Month of AI Bugs). — [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53773)
- GitHub Copilot CLI CVE-2026-29783 (2026-03-06, CVE): shell-expansion patterns bypass the shell tool's checks; the record names MCP server responses as one channel. BB in the host. — [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-29783)
- Cursor CVE-2025-61590 (2025-10-03, CVE): RCE via workspace files written through prompt injection. BB in the host. — [GHSA](https://github.com/cursor/cursor/security/advisories/GHSA-xg6w-rmh5-r77r)
- MCP-client rendering bugs: 5ire CVE-2025-58357 (2025-09-04) and Lobe Chat CVE-2025-59417 (2025-09-18), XSS → RCE from injected or compromised-server content (CVE). BB in the client.
- More command/argument-injection MCP servers (CVE): cyanheads git-mcp-server CVE-2025-53107 (2025-07-01); mcp-server-kubernetes CVE-2025-66404 (2025-12-03) and CVE-2026-39884 (2026-04-14); FrontMCP sandbox escape CVE-2026-67531 (2026-08-05).
- gemini-mcp-tool CVE-2026-0755 (Jan 2026, command injection) appears only in the AuthZed timeline; **not verified on CVE.org this session**.
- Non-MCP agent incidents already in practitioner_media.md: Salesforce Agentforce "ForcedLeak" (Sept 2025; IM plus a stale egress allowlist), Zenity AgentFlayer connector variants, Clinejection (Willison 2026-03-06; an injected issue title against an AI triage bot led to a compromised release, i.e. a real-world in-scope-misuse → supply-chain chain, not via MCP), Check Point's agent-framework bugs (Black Hat USA 2026, BB).

### Takeaway
I catalogued **40 rows** (16 CVE-backed MCP rows, 17 incident/disclosure rows, 7 further 2026 CVE rows). Every CVE id named in Parts A–C and the adjacent list was checked on CVE.org (state PUBLISHED, dates as shown), except CVE-2026-0755 and the 13 OX-listed ids other than CVE-2026-30615. Only a handful of rows describe confirmed in-the-wild harm, and none of those is an in-scope-misuse attack via MCP.

### Inferences
- Primary-class count over 40 rows: **BB 23, IM 8, SC 9** (detail and reasoning in Q4).
- The in-scope-misuse rows (B3, B6, B7, B8, B9, B12, C1, C6) are all researcher PoCs or vendor-fixed CVEs. None is a reported in-the-wild compromise.

### Gaps
- I did not open the primary posts of Invariant (B1–B3), General Analysis (B8), Cato (B6), Koi (B10, B11), LayerX (B12) or Check Point (B13) in full; their facts come from search summaries (S) or practitioner_media.md (PM).
- B2's exact date, B7's mechanism, B14's exploitation claim, B16's primary report and the 13 OX-listed CVE ids other than CVE-2026-30615 were not verified.
- Conflict: AuthZed says the STDIO flaw "has been weaponized" against Letta AI and LangFlow; OX's own advisory does not claim in-the-wild exploitation.

## Q2. For each case: in-scope misuse, boundary break, or supply chain?

### Takeaway
By count, the public record is mostly boundary breaks. But the best-known PoCs (GitHub MCP, Supabase, Atlassian, AgentFlayer, WhatsApp variant 2, LayerX) are in-scope misuse, and vendors leave these unfixed: they call them "by design" or a "known issue". Where the line between IM and BB falls depends on which scope you take as "declared". Vendors sometimes move that line by narrowing a default.

### Cited Findings
- GitHub MCP: the leak needed "no code vulnerability"; a malicious issue was enough. — [AuthZed timeline](https://authzed.com/blog/timeline-mcp-breaches)
- Atlassian/JSM: per Cato, the attacker never touched the MCP server. The engineer's AI session ran the injected instructions with the engineer's own permissions. — [Cato CTRL](https://www.catonetworks.com/blog/cato-ctrl-poc-attack-targeting-atlassians-mcp/); [Infosecurity](https://infosecurity-magazine.com/news/atlassian-ai-agent-mcp-attack)
- AgentFlayer (Cursor + Jira MCP): Cursor answered that this is a known issue, and advised users to review MCP servers and limit them to trusted content. — [Willison](https://simonwillison.net/2025/Aug/9/when-a-jira-ticket-can-steal-your-secrets/)
- LayerX calendar case: Anthropic decided not to fix it. Its reason: the user installed the tools and allowed them to run without prompts. — [Infosecurity](https://www.infosecurity-magazine.com/news/zeroclick-flaw-claude-dxt/)
- OX STDIO advisory: Anthropic's MCP is listed under "won't be patched". Vendors that rejected reports cited "by design", "transport layer only" or "sandbox limits impact". — [OX Security](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/)
- Supabase's response to the General Analysis PoC was least-privilege defaults (read-only mode, project scoping), not a code fix. — [Willison](https://simonwillison.net/2025/Jul/06/supabase-mcp-lethal-trifecta/)
- Microsoft's invoice example: every step was "legitimate"; the weakness is the trust boundary between systems. — [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/) (from practitioner_media.md)
- Claude Code CVE-2025-55284 shows the line moving. The harmful commands were on the default allowlist (in scope), and the vendor then issued a CVE and narrowed the allowlist. — [GHSA-x5gv-jw7f-j6xj](https://github.com/anthropics/claude-code/security/advisories/GHSA-x5gv-jw7f-j6xj)
- Amazon MQ and Contentful MCP servers: the CVE text frames "the tool accepts any host" as an improper endpoint restriction, i.e. as a bug. — [CVE-2026-18655](https://www.cve.org/CVERecord?id=CVE-2026-18655); [CVE-2026-53957](https://www.cve.org/CVERecord?id=CVE-2026-53957)

### Inferences
- **Suggested coding rule** for each incident or trace, with three yes/no fields:
  1. Was each harmful call inside the *tool's* declared scope?
  2. Was it inside the *user's or host's* grant (token scopes, allowlist, auto-approve)?
  3. Did it need a code bug?

  IM = yes / yes / no. BB = a bug is needed. SC = the attacker controls the server, package or config.
- Borderline rows to flag in the paper: C2 (unrestricted host argument), C1 (Kong; mechanism unclear), C6 (Context7: legitimate server serving attacker-authored content), and the adjacent CVE-2025-55284 (over-broad allowlist).
- SC rows split into two kinds:
  - "SC → in-scope actions" (B1, B2 variant 1, B17). Here the poisoned metadata makes the agent misuse *other*, legitimate tools.
  - "SC acting alone" (B10 postmark-mcp, B16, A10, A12, B13). Here no agent decision is involved.

  Only the first kind belongs in an agent-layer study.

### Gaps
- I classified each case from class-level descriptions, not from reproductions. Rows marked S or PM rest on summaries.

## Q3. Which defense layer could have stopped each case? (all inference)

### Takeaway
Each layer covers a different slice. **(b)** covers the 23 boundary breaks, but only once the patch exists. **(d)** and **(e)** cover the in-scope-misuse rows. **(a)** covers poisoned metadata and exposed configs. **15 of 40 rows have no agent decision in the path, so (c), (d) and (e) cannot stop them at all.**

### Cited Findings
- No-agent rows (out of reach for agent-side layers): A1, A2, A3, A10, A12, A13, A15, A16, B4, B5, B10, B13, B14, B16, C7 = **15 of 40**. Facts per row are in the Q1 tables.
- Row counts where a layer is listed as plausible in the Q1 tables (multi-count; strong and weak together):

  | Layer | Rows | Strongest on | Fails on |
  |---|---|---|---|
  | (a) scanner | ~16 | Poisoned metadata or swapped config (B1, B2v1, B17, A10, A12, B13, C5); exposed or unauthenticated configs (A7, A13, A16, B14, C7); toolset toxic-flow (B12) | Code-level SC with clean metadata (B10); data-plane injections (B3, B6, B8, C6) |
  | (b) server check | 23 (+2 partial: B7, B8) | All BB rows, but only after the patch | IM and SC by construction |
  | (c) learned least privilege | ~10 | Anomalous paths or arguments (A4–A6, A8, A9, A11, C4, B11); Supabase tokens table (B8) | Attacks that reuse benign patterns (B3, B9 only partial) |
  | (d) task-conditioned | ~14 | IM rows (B2v2, B3, B6, B8, B9, B12, C1, C6); writes to the agent's own MCP config (A9, A11, B15) | Tasks that legitimately need the sink, e.g. "reply to this ticket" |
  | (e) data-flow rule | ~17 | Exfiltration IM (B3, B6, B7, B8, B9, B12, B17, C6); host/URL taken from tool output (C2, C3), which is exactly "no fetch to a URL that came from tool output" | No-agent rows; integrity-only harm with no flow to a sink |

### Inferences
- Every BB row where an agent is in the path (A4–A6, A8, A9, A11, A14, B11, B15, C2–C4) could *also* be stopped by (c), (d) or (e) before the bug is reached. Agent-side layers therefore add depth even against bugs.
- (b) is special. "The server's own checks" as deployed failed in all 23 BB rows by definition, because each bug *is* a missing or wrong check. The study should decide whether (b) means "as shipped" or "as patched".
- The two rows where (e) is the cleanest fit (C2, C3) are recent 2026 CVEs. CNAs now treat "LLM-controlled host argument" as a vulnerability class. This supports including (e) as a separate layer.

### Gaps
- I found no public incident where a deployed (c) or (d) layer is reported to have stopped a real MCP attack, nor one where it failed. The evidence for these layers is all counterfactual.

## Q4. Tally, what it implies for the hypothesis, and caveats

### Takeaway
**The public record does not support "most real successful attacks are in-scope misuse".** By primary class over 40 rows: **BB 23 (58%), SC 9 (22%), IM 8 (20%)**. Even among the ~24 rows where an agent acted on injected content, only 11 (about 45%) used in-scope calls alone. Confirmed in-the-wild harm is SC or BB, with **no confirmed in-the-wild IM via MCP**. However, the record is strongly biased against IM, and IM is the class that stays after patching. A defensible reframing is: "once server bugs are patched, the residual injection risk is in-scope misuse".

### Cited Findings
- **Primary-class tally (this catalog, 40 rows):**

  | Class | Part A (CVE-backed MCP) | Part B (incidents / write-ups) | Part C (2026 CVEs) | Total |
  |---|---|---|---|---|
  | BB | 14 | 5 | 4 | **23** |
  | IM | 0 | 6 | 2 | **8** |
  | SC | 2 | 6 | 1 | **9** |
  | Total | 16 | 17 | 7 | 40 |

- **Agent-driven subset** (an agent acted on injected content: B1, B2, B3, B6, B7, B8, B9, B12, B17, C1, C5, C6, A4, A5, A6, A8, A9, A11, A14, B11, B15, C2, C3, C4; A7 excluded because its main vector is a direct HTTP request):
  - **11 rows used only in-scope calls**: the 8 IM rows plus B1, B2 and B17, where SC poisoning drove in-scope calls.
  - **13 needed a bug**: 12 BB rows plus C5.
- **Confirmed or reported in-the-wild harm:**
  - postmark-mcp: SC, 2025-09. — [The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)
  - Fake Oura MCP clone: SC, 2026-02; secondary source only. — [AuthZed](https://authzed.com/blog/timeline-mcp-breaches)
  - nginx-ui MCP: BB, 2026-03; exploitation claim is secondary. — [Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)
  - Asana: BB; accidental cross-tenant exposure with no attacker evidence. — [BleepingComputer](https://bleepingcomputer.com/news/security/asana-warns-mcp-ai-feature-exposed-customer-data-to-other-orgs/)
  - Every IM row is a researcher PoC or a vendor-fixed CVE.
- **CVE baseline (NVD API keyword query, run 2026-10-24)** — [NVD API](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=MCP%20server):
  - Size: **516** CVE records whose English description mentions "MCP" or "Model Context Protocol" (queries "Model Context Protocol" = 152 hits, "MCP server" = 481, union 524, of which 516 contain the term). That is 81 CVE-2025 ids and 435 CVE-2026 ids.
  - Growth: publications per month rose from 6 (2025-05) to 108 (2026-09).
  - Weakness buckets (multi-count by NVD CWE):
    - missing or incorrect authn/authz: 138
    - command, argument or code injection: 109
    - SSRF: 89
    - path traversal or symlink: 51
    - information or secret exposure: 34
    - DoS: 32
    - XSS, SQL or other injection: 26
  - Only **25 of 516** descriptions mention "prompt injection".
- Vendor statements that place IM outside CVE scope: Cursor ("known issue", AgentFlayer); Anthropic (declined the LayerX fix; MCP STDIO "won't be patched" per OX). GitHub MCP has no CVE. — sources in Q2.

### Inferences
- **What the tally implies.** As a count of public disclosures, the hypothesis is refuted: boundary breaks dominate. As a statement about *residual* risk after patching, it is supported: every BB row has a patch, while the IM rows (GitHub MCP, WhatsApp variant 2, Atlassian, AgentFlayer, LayerX, Microsoft example) were declared known, by design or structural.
- **Suggested wording for the paper:** "Public disclosures are dominated by boundary breaks (58% of 40 catalogued cases; >99% of ~516 MCP CVEs are bug classes), but CVE criteria exclude in-scope misuse by construction. Among the agent-driven cases, about 45% used only in-scope calls, and none of those was fixed by a server patch."
- **Scoping advice.** 15 of 40 rows involve no agent decision. Either exclude them explicitly, or report them as "only (a)/(b) applicable". Otherwise layers (c)–(e) will look weak for reasons unrelated to injection.
- **What attackers actually did.** In-the-wild evidence points to supply chain (malicious or cloned servers) and exposed endpoints, not injection chains. This suggests that real attackers so far prefer cheap, deterministic routes. It is a threat-model point worth stating.

### Caveats (selection bias and method)
1. **CVE definition bias.** A CVE needs a bug, so BB is over-represented by construction. IM is labelled "by design" or "known issue" and gets no id.
2. **Researcher and vendor incentives.** Bug bounties and CNAs reward BB. Most IM write-ups come from vendors who sell guardrails (Invariant/Snyk, Zenity, General Analysis, Koi, LayerX, OX). They are PoCs, not breach reports.
3. **Detection bias.** In-the-wild IM produces authorized-looking logs (Microsoft: every step was legitimate), so it is less likely to be detected, attributed or disclosed.
4. **Granularity.** I grouped the many-CVE long tails (A8, C3, C4) into single rows. A per-CVE count would push BB even higher (e.g. A8 alone holds 7 CVEs).
5. **Noise in the NVD query.** "MCP" can match unrelated products, and NVD CWE data is incomplete or multi-labelled. Treat 516 and the bucket counts as approximate.
6. **Classification is inference.** Rows marked S or PM rest on summaries. Borderline rows (C1, C2, C6, CVE-2025-55284) could flip class.
7. **Dates.** CVE publication dates (CVE.org) often lag the blog disclosure by weeks to months (e.g. B11: reported 2025-07-03, published 2025-11-05; A5: reported mid-2025, CVE 2025-12-17).

### Gaps
- I found no public dataset of in-the-wild MCP *injection* compromises. The absence of confirmed IM breaches may reflect detection limits, not rarity.
- I did not code all 516 NVD records by agent-in-path or IM/BB. Only the 25 that mention prompt injection were sampled (22 resolved; 2 failed on a local encoding error: CVE-2026-84317, CVE-2026-96561).
- I did not verify the secondary claim that "30+ MCP CVEs were filed in a 60-day window in early 2026". The NVD monthly counts above are the verified alternative.
