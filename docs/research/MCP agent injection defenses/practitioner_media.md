# Practitioner and grey literature on MCP / AI-agent prompt-injection security (2025–2026)

Prepared 2026-10-24 for the study "Which defense layer stops a prompt-injected MCP agent?".

**How to read the tags.**
- Study-element tags: [SCAN] static scanner · [SRV] server-side checks · [LP] learned least-privilege policy · [TC] task-conditioned policy · [DF] data-flow rule · [THREAT] threat model / where to plant injections · [EVAL] evaluation method.
- Verification tags: **V** = page opened and content read this session. **T** = HTTP 200 and the page title matches (checked with curl), but the content was not read in full. **X** = could not open (403, timeout, or redirect to another page). Dates come from page metadata or the URL path unless the note says otherwise.

---

## Q1. Essential essays and vendor posts (Willison, Meta, Google, Anthropic, OpenAI, Microsoft, MCP spec)

### Takeaway
The practitioner consensus in 2025–2026 is that no detector or model-level fix stops prompt injection reliably. The defenses that people trust are architectural: break the "lethal trifecta" (Willison) or hold at most two of three properties per session (Meta's Rule of Two), plus deterministic sandboxing and egress limits. Vendors (Google, Microsoft, OpenAI, Anthropic) all describe layered "probabilistic + deterministic" stacks. They also publish non-zero residual attack rates, so a classifier layer is useful but is never enough alone.

### Cited Findings

**Simon Willison (simonwillison.net): the core framing series**
- "The lethal trifecta for AI agents: private data, untrusted content, and external communication". Simon Willison, 2025-06-16 (T). Takeaway: an agent that combines all three properties can be made to exfiltrate data. MCP makes this worse because users mix tools from different sources, and each tool can supply one leg. He calls guardrail products that block about 95% of attacks a failing grade. Informs [DF] [THREAT] [SCAN, as the position to argue against]. — [Source](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/); summary of contents confirmed via [aiweekly summary](https://aiweekly.co/alerts/willison-names-lethal-trifecta-behind-ai-agent-data-leaks)
- "Model Context Protocol has prompt injection security problems". Willison, 2025-04-09 (T). This is his early MCP-specific essay (tool poisoning, rug pulls). Informs [THREAT] [SRV]. — [Source](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)
- "CaMeL offers a promising new direction for mitigating prompt injection attacks". Willison, 2025-04-11 (T). This is a practitioner reading of Google DeepMind's CaMeL (capabilities + data-flow tracking). It is the canonical blog reference for a capability/data-flow defense. Informs [DF]. — [Source](https://simonwillison.net/2025/Apr/11/camel/)
- "GitHub MCP Exploited: Accessing private repositories via MCP". Willison, 2025-05-26 (T). He frames Invariant's GitHub MCP exploit as a lethal-trifecta case. Informs [THREAT] [DF] [LP]. — [Source](https://simonwillison.net/2025/May/26/github-mcp-exploited/); framing confirmed in his [Bluesky post](https://bsky.app/profile/simonwillison.net/post/3lq4gilc2lc2q)
- "Design Patterns for Securing LLM Agents against Prompt Injections". Willison, 2025-06-13 (T). This is a write-up of the multi-lab design-patterns paper (action-selector, plan-then-execute, dual LLM, code-then-execute, context minimization). It gives a vocabulary for "task-conditioned" restriction. Informs [TC] [DF]. — [Source](https://simonwillison.net/2025/Jun/13/prompt-injection-design-patterns/)
- "New prompt injection papers: Agents Rule of Two and The Attacker Moves Second". Willison, 2025-11-02 (T). This connects Meta's Rule of Two to the adaptive-attack paper. Secondary reports say that paper broke 10 of 12 recent defenses ([summary](https://dev.to/aiagentengineering/the-prompt-injection-problem-a-guide-to-defense-in-depth-for-ai-agents-3p1)). Informs [EVAL] (use adaptive attackers, not static payloads only). — [Source](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
- "MCP Colors: Systematically deal with prompt injection risk". Willison, 2025-11-04 (T; summary via tag page, V). Tim Kellogg's proposal: label each MCP tool red (exposes the agent to untrusted instructions) or blue (critical action). This is a static labelling scheme, close to a [SCAN] + [DF] rule. — [Source](https://simonwillison.net/2025/Nov/4/mcp-colors/); [tag page](https://simonwillison.net/tags/prompt-injection/)
- "The Normalization of Deviance in AI". Willison, 2025-12-10 (T), pointing to Rehberger's essay of 2025-12-04 (T). Takeaway: vendors keep shipping agents with known injection risks, and the industry has started to treat this as normal. — [Willison](https://simonwillison.net/2025/Dec/10/normalization-of-deviance/); [Rehberger](https://embracethered.com/blog/posts/2025/the-normalization-of-deviance-in-ai/)
- "Auto mode for Claude Code". Willison, 2026-03-24 (V). Auto mode is a classifier that approves or blocks each action. Willison is skeptical because AI-based protections are "non-deterministic by nature". He still wants agents in "a robust sandbox by default". This is the clearest practitioner statement in the "are scanners/classifiers enough?" debate. Informs [LP] [TC] [SCAN]. — [Source](https://simonwillison.net/2026/Mar/24/auto-mode-for-claude-code/)
- "Breaking Claude Code Opus 5 Auto Mode". Willison link post, 2026-08-27 (V), about Rehberger's post of 2026-08-26 (T). Rehberger made Claude Code download and unzip an archive. A planted `struct.py` then ran when Python imported `base64` (he reports about 80% reliability). The classifier approved the process. In some runs auto mode then *denied* Claude's own cleanup command. Willison later agreed this is better called a "confused-environment" attack than classic prompt injection. Informs [LP] [TC] [SRV] [EVAL] (define what counts as a "stop"). — [Willison](https://simonwillison.net/2026/Aug/27/breaking-claude-code-opus-5-auto-mode/); [Rehberger](https://embracethered.com/blog/posts/2026/breaking-claude-code-opus-5-and-automode/)
- "Prompt Injection as Role Confusion". Willison link post, 2026-06-22 (V), about Ye, Cui and Hadfield-Menell's write-up (T). Their claim: models trust text by its *style*, not its role. "Destyling" injected text cut attack success from 61% to 10%. Their conclusion is that defense stays "whack-a-mole" until models get genuine role perception. Informs [SCAN] (pessimism about content-level detection) and [THREAT]. — [Willison](https://simonwillison.net/2026/Jun/22/prompt-injection-as-role-confusion/); [authors](https://role-confusion.github.io/)
- "What happened after 2,000 people tried to hack my AI assistant". Willison link post, 2026-06-26 (V), about Fernando Irarrázaval's HackMyClaw challenge (T). About 6,000 email-borne injection attempts against an OpenClaw / Opus 4.6 agent. No attempt leaked secrets.env. Willison credits frontier-lab training but still advises against deployments where injection could cause irreversible harm. Useful counter-evidence to "everything breaks". Informs [EVAL]. — [Willison](https://simonwillison.net/2026/Jun/26/hack-my-ai-assistant/); [original](https://www.fernandoi.cl/posts/hackmyclaw/)
- Other 2026 Willison posts on the prompt-injection tag that are relevant as case material (titles and dates from the tag page, V): "Clinejection — Compromising Cline's Production Releases just by Prompting an Issue Triager" (2026-03-06, T); "Snowflake Cortex AI Escapes Sandbox and Executes Malware" (2026-03-18); "Microsoft Copilot Cowork Exfiltrates Files" (2026-05-26); "OpenAI Help: Lockdown Mode" (2026-06-05, T; deterministic limits on outbound requests); "How I tricked Claude into leaking your deepest, darkest secrets" (2026-07-15); "Self-generated prompt injections in compaction summaries" (2026-09-17). — [Tag page](https://simonwillison.net/tags/prompt-injection/); [Clinejection](https://simonwillison.net/2026/Mar/6/clinejection/); [Lockdown Mode](https://simonwillison.net/2026/Jun/5/openai-help-lockdown-mode/)

**Meta**
- "Agents Rule of Two: A Practical Approach to AI Agent Security". Meta AI blog, 2025-10-31 (V via WebFetch; curl returned 400). No author is named on the page; secondary sources credit Mick Ayzenberg. Within one session an agent should have at most two of: [A] processes untrustworthy inputs, [B] accesses sensitive systems or private data, [C] changes state or communicates externally. If a task needs all three, it needs supervision, e.g. human approval. LlamaFirewall / Prompt Guard are "complementary", not primary. The rule "should supplement" least privilege and not replace it. Examples: [AB] travel assistant, [AC] sandboxed web researcher, [BC] internal coder that filters inputs by author lineage. Informs [TC] [LP] [DF]. — [Source](https://ai.meta.com/blog/practical-ai-agent-security/); author attribution per [search summary](https://simonw.substack.com/p/new-prompt-injection-papers-agents)
- Critique: Ken Huang argues the Rule of Two covers single-agent prompt injection but misses wider agentic risks (T; date not captured). Useful "position against" source. — [Source](https://kenhuangus.substack.com/p/the-rule-of-two-vs-reality-why-metas)

**Google**
- "Mitigating prompt injection attacks with a layered defense strategy". Google Security Blog, 2025-06-13 (T). Gemini/Workspace stack: injection content classifiers, "security thought reinforcement", markdown sanitization with suspicious-URL redaction, a user-confirmation framework, and end-user notifications. Informs [SCAN] [SRV]. — [Source](https://security.googleblog.com/2025/06/mitigating-prompt-injection-attacks.html); mirror on [blog.google](https://blog.google/security/mitigating-prompt-injection-attacks/)
- "Architecting Security for Agentic Capabilities in Chrome". Google Security Blog, 2025-12-08 (T). Mixes deterministic and probabilistic layers. A separate model vets the agent's actions and is isolated from untrusted content. Origin isolation limits which sites the agent can reach. User confirmation guards critical steps. Informs [TC] (isolated action-vetting model) and [DF] (origin limits). — [Source](https://security.googleblog.com/2025/12/architecting-security-for-agentic.html); content per [search summary](https://security.googleblog.com/2026/?m=1)
- A follow-up Google Security Blog post dated 2026-04-02 describes how Google keeps these defenses current (red-teaming, new attack-vector discovery). I did not open the exact post URL. — [Blog index](https://security.googleblog.com/2026/?m=1)
- "An Introduction to Google's Approach for Secure AI Agents" (research.google paper page, T). Hybrid of deterministic runtime policy plus reasoning-based defenses. It is the agent-specific companion to SAIF. Date: May 2025 per my prior knowledge; not confirmed this session. Informs [TC] [LP]. — [Source](https://research.google/pubs/an-introduction-to-googles-approach-for-secure-ai-agents/); [SAIF](https://saif.google/) (T, no title returned)
- Chrome for Developers: "Agent security considerations for WebMCP" (T). A search snippet shows a publication date of 2026-06-09. This is the browser-side MCP variant (WebMCP). — [Source](https://developer.chrome.com/docs/agents/security)

**Anthropic**
- "Making Claude Code safer with sandboxing". Anthropic Engineering, 2025-10-20 (T). Filesystem and network isolation for Claude Code. It is the deterministic-sandbox reference that Willison prefers. Informs [SRV] [LP]. — [Source](https://www.anthropic.com/engineering/claude-code-sandboxing)
- "Mitigating prompt injections in browser use". Anthropic Research, 2025-11-24 (T). A secondary summary says an adaptive attacker with 100 tries per setup still succeeded about 1% of the time against Opus 4.5 with safeguards, which Anthropic calls a meaningful risk. Informs [EVAL] (report attempts-to-success). — [Source](https://www.anthropic.com/research/prompt-injection-defenses); numbers via [secondary](https://dev.to/aiagentengineering/the-prompt-injection-problem-a-guide-to-defense-in-depth-for-ai-agents-3p1)
- "How we built Claude Code auto mode". Anthropic Engineering, 2026-03-25 (V). This is the most detailed public design of a learned, task-conditioned permission policy:
  - The transcript classifier (Sonnet 4.6) sees only user messages and bare tool calls. It is "reasoning-blind by design", so injected rationalizations cannot sway it.
  - A separate server-side probe scans tool outputs for injection, but it only *warns* the agent and does not block.
  - Three tiers: read-only allowlist → in-project edits skip the classifier → two-stage classifier.
  - Published error rates: full pipeline FPR 0.4% on 10,000 real actions; FNR 17% on 52 real "overeager" actions; FNR 5.7% on 1,000 synthetic exfiltration cases.
  - Most misses come from misjudging whether user consent covers the blast radius.
  - It says auto mode is not a replacement for human review on high-stakes infrastructure.
  - Informs [LP] [TC] [SCAN] [EVAL]. — [Source](https://www.anthropic.com/engineering/claude-code-auto-mode)
- Claude Sonnet 4.6 system card (2026-02-17). A secondary write-up in search results reports about 8% first-attempt and 50% unbounded-attempt injection success in computer-use with all safeguards on. I did not isolate which result page made the claim, and I did not open the system card. Treat this as unverified. — [one candidate secondary](https://dev.to/aiagentengineering/the-prompt-injection-problem-a-guide-to-defense-in-depth-for-ai-agents-3p1)

**OpenAI**
- "Understanding prompt injections: a frontier security challenge". OpenAI (T; WebFetch got 403, so content not read). Date: November 2025 per my prior knowledge; not confirmed this session. — [Source](https://openai.com/index/prompt-injections/)
- "Continuously hardening ChatGPT Atlas against prompt injection". OpenAI, 2025-12-22 (T; date per TechCrunch). An RL-trained automated attacker finds injections in simulated rollouts. OpenAI says the problem may never be fully solved and frames defense as continuous hardening, with no deterministic guarantee. Informs [EVAL] (automated adaptive red-teaming). — [Source](https://openai.com/index/hardening-atlas-against-prompt-injection/); [TechCrunch](https://techcrunch.com/2025/12/22/openai-says-ai-browsers-may-always-be-vulnerable-to-prompt-injection-attacks/)
- Critique: Zenity Labs (Stav Cohen), "Hardening Atlas: The Relentless Challenge of Securing an Untrusted Browser Agent", 2025-12-30 (T). — [Source](https://labs.zenity.io/p/hardening-atlas-the-relentless-challenge-of-securing-an-untrusted-browser-agent)
- Rehberger, "OpenAI Explains URL-Based Data Exfiltration Mitigations in New Paper", 2026-02-04 (T). Relevant to the [DF] egress rule. — [Source](https://embracethered.com/blog/posts/2026/data-exfiltration-mitigation-paper-by-openai/)

**Microsoft**
- "Protecting against indirect prompt injection attacks in MCP". Microsoft for Developers, 2025-04-28 (T). The author page link in search results points to Sarah Young. Recommends Prompt Shields (detection + Spotlighting) and supply-chain controls (approved packages only). This is the vendor case *for* a detector layer. Informs [SCAN] [SRV]. — [Source](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp)
- "How Microsoft defends against indirect prompt injection attacks". MSRC blog, July 2025 (T). Defense in depth: prevention (hardened system prompts, Spotlighting), detection (Prompt Shields), and impact mitigation (data governance, user consent, deterministic blocking of known exfiltration methods). Informs [SCAN] [DF]. — [Source](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks)
- "Securing AI agents: When AI tools move from reading to acting". Microsoft Security Blog, 2026-06-30 (T; content via The Hacker News).
  - Microsoft Incident Response and Defender research describe a poisoned MCP tool description that makes an invoice agent leak data. Every single step was "legitimate": the tool was approved, the query ran with the analyst's own permissions, and the outbound server was allowed.
  - The weakness is "the trust boundary between them".
  - Advice: apply *least agency*, not only least privilege.
  - This is a strong practitioner statement that least privilege alone fails against in-scope misuse. Informs [LP] [DF] [THREAT].
  - — [Source](https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/); [The Hacker News summary](https://thehackernews.com/2026/06/microsoft-warns-poisoned-mcp-tool.html)

**MCP specification (modelcontextprotocol.io)**
- "Security Best Practices" (current tutorial page; it now cites spec revision 2026-07-28) (V).
  - Covered attacks: confused deputy (MCP proxy with static client ID), token passthrough (MUST NOT accept tokens not issued for the server), SSRF during OAuth discovery, state-handle hijacking (it replaces session hijacking because MCP is now stateless), local MCP server compromise, OAuth authorization-URL validation, stdio-proxy escalation, mix-up attacks, localhost redirect impersonation, CIMD trust policies, and scope minimization.
  - For local servers it requires showing the exact command and getting explicit consent, and it recommends sandboxing with minimal default privileges. Scope minimization means progressive, least-privilege scopes.
  - **The page does not treat prompt injection or tool poisoning as an attack category.** It is about authorization and infrastructure.
  - Informs [SRV] [LP].
  - — [Source](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices); 2025-06-18 version (T): [Source](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- Spec changelog 2026-07-28 vs 2025-11-25 (V).
  - Protocol-level sessions and the `initialize` handshake are removed (MCP becomes stateless).
  - New `server/discover`.
  - Multi Round-Trip Requests replace server-initiated sampling and elicitation.
  - Clients MUST validate `iss` (RFC 9207).
  - Credentials are bound to the issuing authorization server.
  - Dynamic Client Registration is deprecated in favor of Client ID Metadata Documents.
  - Roots, Sampling and Logging are deprecated.
  - Tools from `tools/list` SHOULD come in deterministic order, and list results now carry `ttlMs`/`cacheScope`.
  - Implication for the study: rug-pull detection and tool-description pinning must work with list caching instead of sessions.
  - — [Source](https://modelcontextprotocol.io/specification/2026-07-28/changelog); authorization pages for [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) and [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (T); [2025-06-18 changelog](https://modelcontextprotocol.io/specification/2025-06-18/changelog) (T)

**MCP-specific security research posts (non-academic)**
- Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks", 2025-04-01 (T). This post originated the term. A hidden instruction in an `add` tool description makes Cursor read `~/.ssh/id_rsa`. The poisoned tool does not even need to be called. Informs [THREAT] (description-plane injections) and [SCAN]. — [Source](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- Invariant Labs, "Introducing MCP-Scan", 2025-04-11 (T). This is the reference static scanner for tool descriptions (tool pinning against rug pulls). Informs [SCAN]. — [Source](https://invariantlabs.ai/blog/introducing-mcp-scan)
- Invariant Labs, "GitHub MCP Exploited: Accessing private repositories via MCP", 2025-05-26 (T). A malicious public-repo issue makes the agent leak private-repo data through the *legitimate* GitHub MCP server. Per Snyk, the attack "does not require the MCP tools themselves to be compromised". This is the paradigm case of in-scope misuse that a description scanner cannot see. Informs [DF] [LP] [SCAN, limits]. — [Source](https://invariantlabs.ai/blog/mcp-github-vulnerability); [Snyk framing](https://labs.snyk.io/resources/toxic-flow-analysis/)
- Invariant Labs / Snyk, "Toxic Flow Analysis", 2025-07-29 (T). Static analysis of toolset combinations for untrusted-input → sensitive-data → exfil-sink paths, shipped in mcp-scan. It operationalizes the lethal trifecta as a [SCAN]+[DF] hybrid. A third-party view says TFA does not replace least privilege, deterministic authorization, sandboxing or human approval. — [Invariant](https://invariantlabs.ai/blog/toxic-flow-analysis); [Snyk Labs](https://labs.snyk.io/resources/toxic-flow-analysis/); [third-party view](https://rubinlake.com/nl/technology-radar/ai-security-and-governance/toxic-flow-analysis-ai)
- Trail of Bits, "Jumping the line: How MCP servers can attack you before you ever use them", 2025-04-21 (T). "Line jumping": tool descriptions inject at `tools/list` time, before any invocation. The series continues with ANSI-escape hiding and `mcp-context-protector` (a wrapper that pins and sanitizes descriptions). Informs [SRV] [SCAN] [THREAT]. — [Source](https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/); [series index](https://blog.trailofbits.com/categories/mcp/) (T)
- CyberArk (Simcha Kosman), "Poison everywhere: No output from your MCP server is safe" (X: the URL now redirects to a Palo Alto Networks "Idira" landing page; the original was not opened). Per secondary sources it introduces Full-Schema Poisoning and "Advanced Tool Poisoning Attacks" that plant instructions in tool *outputs*, including error strings. This directly supports planting injections in outputs as well as descriptions. Informs [THREAT]. — [Original URL, redirects](https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe); [Nullcon abstract](https://berlin2025.nullcon.net/berlin-2025/speaker-speaker-your-mcp-server-executes-commands) (T)
- Embrace The Red (Rehberger), "MCP: Untrusted Servers and Confused Clients, Plus a Sneaky Exploit", 2025-05-02 (T). — [Source](https://embracethered.com/blog/posts/2025/model-context-protocol-security-risks-and-exploits/)
- HiddenLayer, "The lethal trifecta and how to defend against it", 2025-11-25 (T). — [Source](https://www.hiddenlayer.com/research/the-lethal-trifecta-and-how-to-defend-against-it)
- Promptfoo, "Testing AI's 'Lethal Trifecta' with Promptfoo", 2025-09-28 (T). Shows how to turn the trifecta into test cases. Informs [EVAL]. — [Source](https://www.promptfoo.dev/blog/lethal-trifecta-testing/)

### Inferences
- The five study layers map onto named practitioner positions:
  - Static scanner = MCP-scan, Prompt Shields, LlamaFirewall. Vendors present these as *complementary*. Willison treats a 95% detector as a failing grade.
  - Server checks = MCP spec best practices plus sandboxing. Note that the spec's checks address authorization and infrastructure, not injection.
  - Learned least-privilege / task-conditioned policy = Claude Code auto mode, Chrome's isolated action-vetting model, and Google's "hybrid" approach.
  - Data-flow rule = lethal trifecta, Rule of Two, CaMeL, Toxic Flow Analysis, and Microsoft's deterministic exfil blocking.
- Anthropic's auto-mode numbers (FNR 17% on real overeager actions, 5.7% on synthetic exfil) are the only public, vendor-reported error rates for a learned permission policy. They give the students a practitioner baseline to compare against.
- The GitHub MCP exploit (2025-05-26) and Microsoft's invoice example (2026-06-30) both show attacks where every individual call is authorized. Expect static least privilege and description scanners to miss these. A data-flow rule or a task-conditioned policy is the layer the practitioner literature predicts would catch them.

### Gaps
- I could not read the OpenAI "Understanding prompt injections" post (403 to the fetcher). Its exact date (believed November 2025) is not confirmed.
- The exact date of Google's "Approach for Secure AI Agents" paper and the MSRC post's author were not confirmed this session.
- Meta's post names no author. The Ken Huang critique has no date captured.
- The CyberArk original post is no longer at its URL. Its claims here rely on secondary summaries.

---

## Q2. Conference talks and videos (2025–2026)

### Takeaway
The talk circuit moved from "MCP tool poisoning demos" (2025) to "assume injection happens; the framework/runtime is the boundary" (Black Hat USA 2026). The best recorded talk for the study is Rehberger's 39C3 "Agentic ProbLLMs" (video available). The most directly relevant defense talks are Roblox's "Caging the Agent" and Ben-Gurion's LLMFirewall at Black Hat USA 2026. I could not open official Black Hat or DEF CON schedule pages (403), so the 2026 session details come from secondary listings.

### Cited Findings
- **Johann Rehberger, "Agentic ProbLLMs: Exploiting AI Computer-Use and Coding Agents"**, 39th Chaos Communication Congress (39C3), December 2025. Video on media.ccc.de (T). Blog post with slides, 2025-12-30 (T). Targets include Claude Code, GitHub Copilot, Google Jules, Devin, ChatGPT Operator, Amazon Q and AWS Kiro. Heise says many bugs are fixed but the basic problem remains. Informs [THREAT] (coding-agent attack catalogue). — [Video](https://media.ccc.de/v/39c3-agentic-probllms-exploiting-ai-computer-use-and-coding-agents); [Blog](https://embracethered.com/blog/posts/2025/39c3-agentic-probllms-exploiting-computer-use-and-coding-agents/); [heise](https://heise.de/-11125687)
- **Simon Willison, "The lethal trifecta" talk**, Bay Area AI Security Meetup. Annotated write-up with slides dated 2025-08-09 (T). This is the talk version of the trifecta essay. — [Source](https://simonwillison.net/2025/Aug/9/bay-area-ai/)
- **Michael Bargury (Zenity), "AI Enterprise Compromise: 0-click Exploit Methods" (AgentFlayer)**, Black Hat USA 2025, disclosed 2025-08-06 per secondary sources. Zero-click chains via ChatGPT Connectors (a poisoned shared document; demo by Tamir Ishay Sharbat), Copilot Studio, Salesforce Einstein, Cursor + Jira MCP, and Gemini. Informs [THREAT] (data-plane injections through connectors). — [Dark Reading, X/403](https://www.darkreading.com/application-security/ai-agents-access-everything-zero-click-exploit); [the-decoder](https://the-decoder.com/agent-based-ai-systems-face-growing-threats-from-zero-click-and-one-click-exploits/)
- **Black Hat USA 2026 (Aug 1–6, 2026; briefings Aug 5–6)**. Agent-security talks per Straiker's list (V) and The Register (V):
  - Yarden Porat & Shahar Tal (Check Point), "No Tools Required: Post-Injection Exploitation Across AI Agent Frameworks" (Aug 5). The researchers tested LangChain/LangGraph, CrewAI, AutoGen, Microsoft Agent Framework and Google ADK and disclosed 11 vulnerabilities. Bugs were classic: deserialization, SSRF, path traversal, use-after-free. Tal: "reading the wrong document is enough." Informs [SRV] [THREAT]. — [The Register, 2026-08-05](https://www.theregister.com/security/2026/08/05/prompt-injection-isnt-the-bug-ai-agent-frameworks-are/5283585)
  - Porat & Tal (Check Point), "When Agentic Glue Melts: Exploiting Cloudflare CodeMode and Workers" (Aug 6). Injection → generated code runs with agent privileges → sandbox escape. — [Straiker](https://www.straiker.ai/blog/black-hat-usa-2026-ai-security-talks)
  - Harshit Kumar, Jaskaran Singh, Ahmad Alomari (Roblox), "Caging the Agent: How Roblox Built Multi-Layer Sandboxes to Secure Claude Code at Enterprise Scale" (Aug 6). A hidden GitHub issue caused a credential leak. The response was a sandbox, credential isolation and monitoring. Informs [SRV] [LP]. — [Straiker](https://www.straiker.ai/blog/black-hat-usa-2026-ai-security-talks)
  - Yisroel Mirsky et al. (Ben-Gurion Univ.), "Rules for Neural Traffic: A New Defensive Layer for LLMs" (Aug 5). Snort/YARA-style rules over LLM traffic, released as the open-source LLMFirewall. Informs [SCAN]. — [Straiker](https://www.straiker.ai/blog/black-hat-usa-2026-ai-security-talks)
  - Francesco Montorsi et al. (Zenity), "Promptware EOD: Skillful Agent Detonation" (Aug 6). Treats skill files and rug-pulled MCP servers as malware and open-sources a detonation framework. Informs [SCAN] (dynamic analysis vs static). — [Straiker](https://www.straiker.ai/blog/black-hat-usa-2026-ai-security-talks)
  - Others on the same list: Elad Meged (Novee), "Trusted Enough to Run: Breaking AI Agents in Official Workflows"; Artem Chaikin (Brave), "Attacking and Defending AI Browsers"; Simcha Kosman (Palo Alto Networks), "A Billion-User Blast Radius: Owning ChatGPT's Secure Sandbox"; Adam Shostack, "Threat Modeling LLMs: The PHANTOM-B model". — [Straiker](https://www.straiker.ai/blog/black-hat-usa-2026-ai-security-talks)
  - One analysis counted 35 of 121 briefings as AI-security related. — [securetom](https://securetom.com/blog/black-hat-2026-ai-security-agent-talks-enterprise) (not opened)
  - Official schedule: [blackhat.com us-26](https://www.blackhat.com/us-26/briefings/schedule/) (X, 403)
- **Simcha Kosman (CyberArk), "Your MCP Server Executes Commands – But From Whom?"**, Nullcon Berlin 2025. Abstract page (T). Full-Schema Poisoning and runtime output poisoning via error strings. No video found. — [Source](https://berlin2025.nullcon.net/berlin-2025/speaker-speaker-your-mcp-server-executes-commands)
- **Rehberger, "Copirate 365 at DEF CON: Plundering in the Depths of Microsoft Copilot (CVE-2026-24299)"**, blog post 2026-05-04 (T). Which DEF CON edition was not confirmed; the date suggests a spring 2026 event, not DEF CON 34 in August. — [Source](https://embracethered.com/blog/posts/2026/defcon-talk-copirate-365/)
- **Rehberger, "From SELECT to SYSADMIN with SQL Copilot (CVE-2026-65669)"**, BlueHat Asia 2026, blog post 2026-09-30 (T). — [Source](https://embracethered.com/blog/posts/2026/from-select-to-sysadmin-sql-copilot-bluehat-asia/)
- **Rehberger keynote, "Agentic ProbLLMs: What I Learned Exploiting AI Computer-Use and Coding Agents"**, Stanford Real-World AI Security workshop, 2026-06-23. Known from a search snippet only; the page timed out (X). — [Schedule](https://seclab.stanford.edu/RealWorldAIsec/program-26.html)
- **Rehberger webinar, "The Normalization of Deviance in AI: Lessons from and beyond the Month of AI Bugs"**, Wiz (past event; date not captured; not opened). — [Wiz](https://www.wiz.io/events/the-normalization-of-deviance-in-ai-lessons-from-and-beyond-the-month-of-ai-bugs)
- **[un]prompted — The AI Security Practitioner Conference.** First edition 2026-03-03/04 at Salesforce Tower, San Francisco. A second edition, [un]prompted II, is scheduled for 2026-10-27/29, so no videos exist yet. Security Boulevard reposts say talks are on the conference's YouTube channel, e.g. the "Flash Talks" and the "Vibe Coded" micro-talks with Rob T. Lee, Glenn Thorpe, Dan Hubbard and Sergej Epp. I did not find an MCP-specific [un]prompted talk. — [Listing](https://infosec-conferences.com/event/unprompted-the-ai-security-practitioner-conference-2026); [Security Boulevard, X/403](https://securityboulevard.com/2026/04/unprompted-2026-flash-talks/)

### Inferences
- The 2026 talk trend ("prompt injection isn't the bug, frameworks are") supports including a **server/runtime-check** layer. Many real compromises after injection are classic boundary bugs that deterministic checks can stop.
- Roblox's "Caging the Agent" is a real enterprise case where the response to a GitHub-issue injection was sandbox + credential isolation, not a better detector. It is good practitioner evidence for scoring [SRV]/[LP] layers on "blast radius" and not only on "injection detected".

### Gaps
- Official Black Hat 2025/2026 schedule pages returned 403. The 2026 session details come from Straiker (vendor blog) and The Register.
- I found **no** verified 2025–2026 recordings from DEF CON 33/34 AI Village, USENIX Enigma, RSAC, BSides, OWASP Global AppSec or CAMLIS on MCP / tool poisoning. One search in extended mode and two standard searches returned none. A blog that claims to summarize 50+ such talks exists, but I did not open or verify it: [lucaberton.com](https://lucaberton.com/blog/mcp-ai-agent-security-lessons-from-conference-talks/).
- The Invariant Labs and Trail of Bits teams have no verified conference video in this pass.

---

## Q3. Podcasts and long-form interviews

### Takeaway
Long-form audio is thin and mostly Willison-centred. The most on-topic episodes are his Screaming in the Cloud (2025-08-13) and Talking Postgres (2025-08-11) appearances on the lethal trifecta and MCP, plus Lenny's Podcast (2026-04-02), where he predicts an "AI Challenger disaster". Several 2026 general-security podcasts repeat the "prompt injection may never be fixed" line.

### Cited Findings
- Screaming in the Cloud (Corey Quinn), "AI's Security Crisis: Why Your Assistant Might Betray You", Simon Willison, 2025-08-13 (T). Covers the lethal trifecta and a predicted major breach. — [Source](https://simonwillison.net/2025/Aug/13/screaming-in-the-cloud/)
- Talking Postgres, "AI for data engineers with Simon Willison", 2025-08-11 (T). Covers the lethal trifecta and running MCPs securely. — [Source](https://simonwillison.net/2025/Aug/11/ai-for-data-engineers/)
- Heavybit Generationship Ep. 39, Simon Willison, 2025-07-11. Prompt injection is listed as a topic. Known from the podcast-appearances tag page (V); the episode URL was not curl-checked. — [Source](https://simonwillison.net/2025/Jul/11/generationship/)
- Lenny's Podcast, "An AI state of the union…", Simon Willison, 2026-04-02 (T). Prompt injection as an unsolved problem; lethal trifecta; the "Challenger disaster" prediction. — [Willison highlights](https://simonwillison.net/2026/Apr/2/lennys-podcast/); [transcript listing](https://podscripts.co/podcasts/lennys-podcast-product-career-growth/an-ai-state-of-the-union-weve-passed-the-inflection-point-dark-factories-are-coming-and-automation-timelines-simon-willison) (T)
- SE Radio 733, Max Corbridge on securing AI agents, 2026-08-13 (search snippet only; not opened). Agents are a largely undefended attack surface, and the labs call prompt injection effectively unsolvable. — [Podcast Addict listing](https://podcastaddict.com/episode/https%3A%2F%2Ftraffic.libsyn.com%2Fsecure%2Fseradio%2F733-max-corbridge-securing-ai-agents.mp3%3Fdest-id%3D23379&podcastId=6118626)
- Security Now SN 1093, "Tokens in the Stream", 2026-08-25 (search snippet only). Argues that token processing makes prompt injection hard to eliminate. — [Context via search](https://ppacc.player.fm/1BbcSDT) (not opened)
- Context Window: AI Security Podcast (June 2026 episode, search snippet only). Pairs a theory paper on instruction/data inseparability with OWASP guidance on controls *around* the model (per-agent identity, runtime monitoring). — [Castbox](https://castbox.fm/channel/Context-Window%3A-AI-Security-Podcast-id7142412) (not opened)
- Hacker Valley, "The year of the agent: AI bug bounties and cybersecurity insights with Marco Figueroa" (date not captured; not opened). — [Source](https://hackervalley.com/e/the-year-of-the-agent-ai-bug-bounties-and-cybersecurity-insights-with-marco-figueroa)

### Inferences
- No podcast I found treats MCP defense layers comparatively. The students' study would fill a gap that practitioners only discuss qualitatively.

### Gaps
- I found no podcast interview with Johann Rehberger, Invariant Labs or Trail of Bits in 2025–2026 (one targeted search returned none).
- I did not open the SE Radio, Security Now and Context Window episodes. Their claims come from search snippets.

---

## Q4. Industry frameworks and government guidance

### Takeaway
OWASP now has three relevant artifacts: the Agentic Top 10 (Dec 2025), Agentic Threats & Mitigations (Feb 2025), and an MCP Top 10 incubator (v0.1). They supply the taxonomy for labelling attack traces. CoSAI's MCP paper (Jan 2026) is the most MCP-specific industry control catalogue. NIST/CAISI and UK AISI supply the evaluation argument: every frontier model was hijacked at least once in large public competitions, and robust models still fall to adaptive attacks.

### Cited Findings
- **OWASP Top 10 for Agentic Applications (for 2026)**, OWASP GenAI Security Project. Released 2025-12-09/10 (T; page date 2025-12-09, metadata 2025-12-10). It has ten agent-specific categories, ASI01–ASI10, from 100+ contributors. The names were only partially confirmed (from secondary pages): ASI01 Agent Goal Hijack, ASI02 Tool Misuse & Exploitation, ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents. ASI02 covers agents that misuse tools *within* their authorized privileges. That is exactly the "in-scope misuse" class. A secondary guide uses "Least Agency and least privilege for tools" as a mitigation heading. Informs [THREAT] (trace labels) [LP]. — [OWASP](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/); [ASI02 explainer](https://galileo.ai/blog/owasp-agentic-ai-asi02-tool-misuse); [Graylog](https://graylog.org/post/what-is-the-owasp-top-10-agentic-ai)
- **OWASP "Agentic AI – Threats and Mitigations"**, 2025-02-17 (T). The earlier threat-model document behind the Top 10. — [Source](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- **OWASP "CheatSheet – A Practical Guide for Securely Using Third-Party MCP Servers 1.0"**, 2025-11-04 (T). Informs [SRV] [SCAN] (vetting and pinning servers). — [Source](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/)
- **OWASP MCP Top 10** (T). An incubator project at v0.1 in pilot testing, led by Vandana Verma Sehgal. It has entries MCP01–MCP10, e.g. MCP03 Tool Poisoning and MCP06 Prompt Injection via Contextual Payloads. Vendor guides cite 30+ MCP CVEs in Jan–Feb 2026. The numbering may change. — [OWASP](https://owasp.org/www-project-mcp-top-10/); [MCP03 page](https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning); [Cycode guide](https://cycode.com/blog/owasp-mcp-top-10/)
- **CoSAI (OASIS) MCP security white paper.** OASIS press release 2026-01-27 (T). CoSAI blog "Securing the AI Agent Revolution: A Practical Guide to Model Context Protocol Security", page metadata 2026-01-20 (T; the 7-day difference from the press release is not explained). Per secondary sources: 12 threat categories, 40+ threats, and controls such as identity chains, zero trust for agents and sandboxing. Informs [SRV] [LP]. — [OASIS](https://www.oasis-open.org/2026/01/27/coalition-for-secure-ai-releases-extensive-taxonomy-for-model-context-protocol-security); [CoSAI](https://www.coalitionforsecureai.org/securing-the-ai-agent-revolution-a-practical-guide-to-mcp-security/); [Adversa summary](https://adversa.ai/blog/mcp-security-whitepaper-2026-cosai-top-insights/)
- **NIST AI 100-2 E2025**, "Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations" (T). Use its terms for direct vs indirect prompt injection. Release month (March 2025) is from prior knowledge. — [Source](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- **US AISI/NIST, "Technical Blog: Strengthening AI Agent Hijacking Evaluations"**, January 2025 (T). Uses AgentDojo: a user task plus injected data that tries to trigger an injection task. Informs [EVAL] (the trace format the students already use). — [Source](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)
- **NIST CAISI RFI on AI agent security**, Federal Register Vol. 91 No. 5, 2026-01-08 (T). Agents "may be susceptible to hijacking, backdoor attacks, and other exploits". Mentions least privilege, zero trust, instruction hierarchy and trusted-model design patterns as mitigations. Responses were due 2026-03-09 (per ANSI). — [Federal Register](https://www.govinfo.gov/content/pkg/FR-2026-01-08/html/2026-00206.htm); [ANSI](https://www.ansi.org/standards-news/all-news/1-15-26-mitigating-risks-of-ai-agent-systems-nist-center-for-ai-standards-and-innovation-issues-rfi)
- **NIST CAISI, "Insights into AI Agent Security from a Large-Scale Red-Teaming Competition"**, 2026-03-23 (V). With Gray Swan and UK AISI: 13 frontier models, tool-use / coding / computer-use agents, 250,000+ attacks from 400+ participants.
  - At least one successful hijack was found against every model.
  - Some "universal" attacks transferred across models and scenarios.
  - Attacks made on robust models transferred to weaker ones, but not the reverse.
  - Robust models still fall to adaptive attacks, so static benchmarks are limited. Paper: arXiv 2603.15714 (T; academic, listed for reference only).
  - Informs [EVAL].
  - — [Source](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition); [arXiv](https://arxiv.org/abs/2603.15714)
- **UK AISI × Gray Swan Agent Red-Teaming Challenge: Results Snapshot** (T). Ran 2025-03-08 to 2025-04-06: about 1.8M attempts, about 62,000 successful breaks, 22 models. UK AISI funded it and reviewed appeals. the-decoder reports a 12.7% average attack success rate (secondary). — [Gray Swan](https://www.grayswan.ai/blog/uk-aisi-x-gray-swan-agent-red-teaming-challenge-results-snapshot); [the-decoder](https://the-decoder.com/every-leading-ai-agent-failed-at-least-one-security-test-during-a-massive-red-teaming-competition/)
- CAISI launched an "AI Agent Standards Initiative" on 2026-02-17. A Feb 2026 NCCoE concept paper proposes treating agents as identifiable IAM principals. Both claims come from a Cloud Security Alliance research note that describes itself as AI-assisted, so treat them as secondary. — [CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-caisi-ai-agent-security-agenda-2026-2/)

### Inferences
- OWASP ASI01 (goal hijack) vs ASI02 (tool misuse within privileges) vs ASI03 (privilege abuse) is a ready-made label set for the students' attack traces. Use it to separate "boundary break" from "in-scope misuse" outcomes.
- The CAISI transfer finding (robust → weak, not the reverse) suggests the students should develop or select attacks against the *most* robust model in their pool first.

### Gaps
- I did not read the OWASP Agentic Top 10 PDF. The ASI names come from secondary pages, and Graylog's extraction confirmed only the name prefixes. Check the exact names and the "least agency" wording in the PDF.
- I did not read the CoSAI PDF itself. The threat counts come from Adversa (a contributor).
- I found no UK AISI page of its own (aisi.gov.uk) with agent-hijacking results. UK AISI appears only as a partner in the Gray Swan and CAISI posts.

---

## Q5. Public bug-bounty and disclosure series (Embrace The Red, Invariant, HiddenLayer, Legit, Noma, Zenity, Check Point)

### Takeaway
The disclosure record splits into two classes:
1. **In-scope misuse.** The agent uses legitimately granted tools and permissions to leak data. Examples: GitHub MCP, Microsoft's invoice example, ForcedLeak, AgentFlayer.
2. **Boundary breaks.** An injection reaches a classic bug or a missing control. Examples: path-validation bypass in the Filesystem MCP server, DNS exfil via auto-allowed commands, Copilot RCE, framework deserialization or SSRF, sandbox escapes.

Class 2 is fixable with deterministic server/runtime checks. Class 1 needs data-flow or task-conditioned restrictions. Vendors often decline CVEs or call reports "not a bug", which Rehberger and Willison call the "normalization of deviance".

### Cited Findings
- **Embrace The Red, "Month of AI Bugs" (August 2025)**: announced 2025-07-28 and wrapped up 2025-08-30 (both T). One disclosure per day against coding and computer-use agents. Titles and dates from the blog index (V):
  - "Turning ChatGPT Codex Into A ZombAI Agent" (2025-08-02)
  - "Anthropic Filesystem MCP Server: Directory Access Bypass via Improper Path Validation" (2025-08-03)
  - "AI Kill Chain in Action: Devin AI Exposes Ports to the Internet with Prompt Injection" (2025-08-08)
  - "Claude Code: Data Exfiltration with DNS (CVE-2025-55284)" (2025-08-11)
  - "GitHub Copilot: Remote Code Execution via Prompt Injection (CVE-2025-53773)" (2025-08-12)
  - "Jules Zombie Agent" (2025-08-14)
  - "Sneaking Invisible Instructions by Developers in Windsurf" (2025-08-23)
  - "AWS Kiro: Arbitrary Code Execution via Indirect Prompt Injection" (2025-08-26)
  - "Windsurf MCP Integration: Missing Security Controls Put Users at Risk" (2025-08-28)

  Earlier: "Security Advisory: Anthropic's Slack MCP Server Vulnerable to Data Exfiltration" (2025-06-24, T). Willison's summary of the series: "The Summer of Johann" (2025-08-15, T). — [Announcement](https://embracethered.com/blog/posts/2025/announcement-the-month-of-ai-bugs/); [Wrap-up](https://embracethered.com/blog/posts/2025/wrapping-up-month-of-ai-bugs/); [Slack MCP](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/); [Windsurf MCP](https://embracethered.com/blog/posts/2025/windsurf-dangers-lack-of-security-controls-for-mcp-server-tool-invocation/); [Willison summary](https://simonwillison.net/2025/Aug/15/the-summer-of-johann/)
- **Embrace The Red 2026** (titles and dates from the index, V):
  - "Scary Agent Skills: Hidden Unicode Instructions in Skills …And How To Catch Them" (2026-02-11, T). Informs [SCAN]: hidden-Unicode detection is a case where a static scanner clearly works.
  - "Agent Commander: Promptware-Powered Command and Control" (2026-03-16, T)
  - "Computer-Use and TOCTOU: What You Click Is Not What You Get!" (2026-06-25)
  - "LLM Heist: Hijacking LiteLLM for Traffic Interception, Key Theft, and Tool-Call Injection" (2026-08-03)
  - "Breaking Claude Code Opus 5 Auto Mode" (2026-08-26, T)
  - "Visual Studio Copilot and SSMS Remote Code Execution (CVE-2026-103572)" (2026-10-13)

  — [Scary Agent Skills](https://embracethered.com/blog/posts/2026/scary-agent-skills/); [Agent Commander](https://embracethered.com/blog/posts/2026/agent-commander-your-agent-works-for-me-now/); [Blog index](https://embracethered.com/blog/)
- **Invariant Labs, GitHub MCP** (2025-05-26, T). Uses a legitimate server and a legitimate token, injected through a public issue, to read a private repo. This is the archetype of in-scope misuse. — [Source](https://invariantlabs.ai/blog/mcp-github-vulnerability)
- **Legit Security, "Remote Prompt Injection in GitLab Duo Leads to Source Code Theft"** (T; date not captured this session, believed May 2025). — [Source](https://www.legitsecurity.com/blog/remote-prompt-injection-in-gitlab-duo)
- **Noma Security, "ForcedLeak: AI agent risks exposed in Salesforce Agentforce"** (T). CVSS 9.4. Reported 2025-07-28, fixes in place by 2025-09-08, public in late September 2025.
  - The injection sits in the Web-to-Lead "Description" field and runs when an employee later queries the lead.
  - Data leaks to an allowlisted domain that had *expired* and could be bought for about $5.
  - This shows a deterministic egress allowlist ([DF]/[SRV]) failing through stale configuration.
  - — [Noma](https://noma.security/blog/forcedleak-agent-risks-exposed-in-salesforce-agentforce/); [The Hacker News](https://thehackernews.com/2025/09/salesforce-patches-critical-forcedleak.html)
- **Zenity Labs, AgentFlayer** (Black Hat USA 2025): zero-click injections through enterprise connectors. A PoC only, with no confirmed customer harm. — [the-decoder](https://the-decoder.com/agent-based-ai-systems-face-growing-threats-from-zero-click-and-one-click-exploits/); [vibegraveyard](https://vibegraveyard.ai/story/chatgpt-connectors-agentflayer-zero-click-exfiltration/) (not opened)
- **Check Point, agent frameworks** (Black Hat USA 2026; The Register 2026-08-05, V).
  - 11 vulnerabilities and $17,133.70 in total bounties.
  - Microsoft paid $10,000 for an RCE in the Microsoft Agent Framework (checkpoint deserialization) but issued no CVE because the framework was not GA.
  - Google first called the ADK issue "not a bug", then paid $3,133.70 with a partial fix and no CVE.
  - Shows boundary breaks in the agent runtime and inconsistent vendor scoping.
  - — [Source](https://www.theregister.com/security/2026/08/05/prompt-injection-isnt-the-bug-ai-agent-frameworks-are/5283585)
- **HiddenLayer**: lethal-trifecta defense essay (2025-11-25, T). I did not find a specific 2025–2026 HiddenLayer agent CVE disclosure in this pass. — [Source](https://www.hiddenlayer.com/research/the-lethal-trifecta-and-how-to-defend-against-it)
- **Microsoft IR/Defender** (2026-06-30): the invoice-agent case. Every call is authorized, and the failure lives "between" systems. — [Source](https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/)

### Inferences
- A practical coding rule for the students' traces is a **"misuse vs break" field** per successful attack.
  - The attack used only granted tools, args and scopes → in-scope misuse (OWASP ASI02). Predicted to evade [SCAN] on descriptions and static [LP]; [DF] or [TC] needed.
  - The attack crossed a declared boundary (path, scope, egress host, sandbox) → boundary break. Predicted to be stopped by [SRV] if the check exists and is correct.
- Practical examples:
  - ForcedLeak (stale allowlist) and Rehberger's auto-mode break (environment, not instructions) show that deterministic layers also fail, through configuration and environment and not through model error.
  - From memory and not re-verified this session: the Claude Code DNS exfil (CVE-2025-55284) used commands that were auto-approved without user confirmation, and the Copilot RCE (CVE-2025-53773) worked by the agent editing its own settings to enable auto-approval. If confirmed in the posts, these are clean examples of "policy/allowlist too broad" (an [LP] failure) and "agent can modify its own policy" (an [SRV] gap).

### Gaps
- I did not read the individual Month-of-AI-Bugs posts. Mechanism details beyond the titles are from prior knowledge (flagged above) and need confirmation.
- The Legit GitLab Duo date was not confirmed.
- I found no consolidated public bounty statistics (payouts, how often vendors accept injection as in-scope) for agent bugs, beyond the Check Point figures.

---

## Q6. Key framings to cite or position against

### Takeaway
Five framings dominate. The students should position their layered study as an *empirical test* of claims that practitioners make mostly qualitatively.

### Cited Findings
1. **Lethal trifecta (capability composition / data flow).** Break one leg and exfiltration is impossible. Detectors are a "failing grade" at 95%. — [Willison 2025-06-16](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/). Operationalized statically by [Toxic Flow Analysis](https://invariantlabs.ai/blog/toxic-flow-analysis) and by tool labels in [MCP Colors](https://simonwillison.net/2025/Nov/4/mcp-colors/).
2. **Agents Rule of Two (session-level property budget).** At most two of {untrusted input, sensitive access, state change / external comms}. It supplements least privilege and does not replace it; detectors are complementary. — [Meta 2025-10-31](https://ai.meta.com/blog/practical-ai-agent-security/). Critique: [Ken Huang](https://kenhuangus.substack.com/p/the-rule-of-two-vs-reality-why-metas).
3. **Least agency > least privilege.** Even a low-permission agent can do harm if it can act without checks. — [Microsoft 2026-06-30](https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/); OWASP Agentic Top 10 mitigation language per [Graylog](https://graylog.org/post/what-is-the-owasp-top-10-agentic-ai).
4. **Layered probabilistic + deterministic defense; "may never be fully solved".**
   - [Google 2025-06-13](https://security.googleblog.com/2025/06/mitigating-prompt-injection-attacks.html), [Google Chrome 2025-12-08](https://security.googleblog.com/2025/12/architecting-security-for-agentic.html)
   - [MSRC July 2025](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks)
   - [OpenAI 2025-12-22](https://openai.com/index/hardening-atlas-against-prompt-injection/)
   - [Anthropic 2025-11-24](https://www.anthropic.com/research/prompt-injection-defenses)
5. **Learned permission classifiers as the "practical middle".**
   - The vendor case: published FPR/FNR, reasoning-blind design. — [Anthropic 2026-03-25](https://www.anthropic.com/engineering/claude-code-auto-mode)
   - The skeptic case: non-deterministic; sandbox instead. — [Willison 2026-03-24](https://simonwillison.net/2026/Mar/24/auto-mode-for-claude-code/)
   - An empirical bypass. — [Rehberger 2026-08-26](https://embracethered.com/blog/posts/2026/breaking-claude-code-opus-5-and-automode/)
6. **"Assume injection; the runtime is the boundary."** Post-injection exploitation through framework bugs. — [The Register on Check Point, 2026-08-05](https://www.theregister.com/security/2026/08/05/prompt-injection-isnt-the-bug-ai-agent-frameworks-are/5283585)
7. **Evaluation framings.**
   - Use adaptive attackers. — [Willison on "The Attacker Moves Second", 2025-11-02](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/); [CAISI 2026-03-23](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition)
   - Report attempt budgets. — [Anthropic browser-use 2025-11-24](https://www.anthropic.com/research/prompt-injection-defenses)
   - Counter-evidence that trained models resist naive attacks well. — [HackMyClaw via Willison, 2026-06-26](https://simonwillison.net/2026/Jun/26/hack-my-ai-assistant/)
8. **Normalization of deviance.** The industry keeps shipping known-vulnerable agents. — [Rehberger 2025-12-04](https://embracethered.com/blog/posts/2025/the-normalization-of-deviance-in-ai/); [Willison 2025-12-10](https://simonwillison.net/2025/Dec/10/normalization-of-deviance/)
9. **The MCP spec's own security page addresses authorization and infrastructure, not injection.** Spec-compliant "server checks" do not by themselves defend against tool-description or tool-output injection. — [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)

### Inferences
- **Where the study can position against the literature:**
  - (a) Willison and Meta argue from architecture and give no measured comparison of layers on the same traces. The study supplies that.
  - (b) Anthropic publishes classifier error rates on its own traffic. The study can test a learned or task-conditioned policy on attacker-chosen MCP traces.
  - (c) The scanner camp (Microsoft Prompt Shields, MCP-scan, LlamaFirewall, LLMFirewall) claims complementary value. The study can quantify the *marginal* catch rate of a scanner once a data-flow rule exists.
- **Hypothesis consistent with the practitioner record:**
  - Description scanners catch description-plane poisoning (Invariant/ToB style) and hidden Unicode, but miss output-plane and in-scope-misuse attacks (GitHub MCP, Microsoft invoice).
  - Data-flow rules catch exfiltration but not integrity attacks.
  - Task-conditioned policies catch overreach but leak when the user's consent covers the blast radius (Anthropic's own failure mode).

### Gaps
- No practitioner source found reports a head-to-head comparison of scanner vs least-privilege vs data-flow layers on shared MCP traces. This is the study's novelty claim; the absence was observed in this pass, not proven exhaustively.
- Academic items surfaced but out of scope, for hand-off to the academic researchers:
  - "Labels Are Not Endpoints: Treatment Leakage and Construct Validity in MCP Agent Security Evaluation" (arXiv 2608.12880, T). Highly relevant to the study's scoring design.
  - MCPTox (Aug 2025; up to 72.8% tool-poisoning success across 45 servers and 20 models, per [The Hacker News](https://thehackernews.com/2026/06/microsoft-warns-poisoned-mcp-tool.html)).
  - "The Attacker Moves Second" (USENIX Security 2026, per secondary).
  - The CAISI/Gray Swan paper (arXiv 2603.15714).
