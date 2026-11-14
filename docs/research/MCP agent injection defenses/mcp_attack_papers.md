# MCP attack-measurement papers and attack-demo repos (2024–2026), mapped to the study's channels and canary goals

Research date: 2026-10-24. Scope: attack-measurement papers and vulnerable/attack-demo repos for MCP agents. Defenses are named only when the paper proposes or evaluates one.

Style rule: class-level only. No injection strings, payloads, prompts, exploit code, or reproduction steps are recorded here.

Already covered elsewhere (not repeated): AgentDojo, InjecAgent, ASB, WASP, MSB, MCP-SafetyBench, MCPTox, MCPSecBench, MCP-AttackBench, MCIP (see benchmarks.md); MCP-FSD (arXiv 2610.22301), ToFu (arXiv 2610.13651), MCP-SEC (arXiv 2509.06572), MCP Safety Audit (arXiv 2504.03767) (see mcp_attacks.md).

Legend (same as mcp_attacks.md):
- Channels: **W** = fetched web page; **F** = repo file; **G** = git commit message / issue / PR text; **M** = memory-graph entity; **T** = tool description / schema / metadata; **O** = other tool output; **S** = sampling, server `instructions`, prompts, resources.
- Canary goals: **R** = read a secret inside the allowed root; **X** = write a `.sh` file in an allowed directory; **E** = send a canary out (fetch or other egress).
- Boundary verdict: **IN** = in-scope misuse (allowed tool, allowed resource); **BRK** = broke a server-enforced boundary (path escape, SSRF, command injection); **HOST** = host/client/protocol bug; **SUP** = malicious server code (supply chain).
- Status: [PR] peer-reviewed; [PP] preprint; [VB] vendor/researcher blog.


---

## Q1. Which papers measure IPI via tool outputs, tool-description poisoning, rug pulls, tool shadowing / cross-server, malicious-server, or preference-manipulation attacks against MCP agents?

### Takeaway
Beyond the benchmarks already in benchmarks.md and mcp_attacks.md, ten more attack-measurement items were found: 8 papers (MPMA, Beyond the Protocol, When MCP Servers Attack, MCPXKIT, MCP-ITP, Trivial Trojans, Lateral Data Exfiltration, MCP Pitfall Lab), 1 non-MCP coding-editor study used as the repo-file reference (Your AI, My Shell), and 1 vendor PoC on sampling (Unit 42). Only 3 are peer-reviewed (MPMA at AAAI, MCPXKIT in IEEE TDSC, Lateral Exfiltration at an ICML 2026 workshop). Measured ASRs are high (often 70–100%) for tool-metadata, tool-output and cross-server attacks. Existing scanners detect few of them, and almost all successes use legitimate tools.

### Cited Findings

**1. MPMA: Preference Manipulation Attack Against MCP** [PR, AAAI per arXiv comment]
- Authors: Zihan Wang, Rui Zhang, Yu Liu, Wenshu Fan, Wenbo Jiang, Qingchuan Zhao, Hongwei Li, Guowen Xu. arXiv 2505.11154, v1 16 May 2025, v2 11 Nov 2025. arXiv comment calls it an extended version of an AAAI publication (year not stated on abs page) — [arXiv abs](https://arxiv.org/abs/2505.11154)
- Attack class: malicious server makes the LLM prefer it over competing servers (economic goal). Two variants: DPMA (manipulative wording in tool name/description) and GAPMA (advertising-style strategies + genetic algorithm for stealth). Channel **T**. Goal: tool-selection hijack, not R/X/E — [arXiv abs](https://arxiv.org/abs/2505.11154)
- Setup: host Cline; models DeepSeek-V3, Claude-3.7-Sonnet, Gemini-2.5-flash, Qwen3-235B-A22B, GPT-4o; 8 real public servers (weather, time, server install, news, web fetch, web-to-markdown, crypto, web search), 10 queries each; 1 malicious vs 5 paraphrased competitors (chance 16.67%) — [arXiv html v2](https://arxiv.org/html/2505.11154v2)
- Outcomes: DPMA best-description variant ~100% ASR in almost all settings; GAPMA model averages approx. Gemini 91.88%, DeepSeek 78.75%, Qwen3 73.75%, Claude 62.81%, GPT-4o 22.19% (fetch tool flagged the table layout as ambiguous; treat as approximate). GPT-4o most resistant, Gemini least — [arXiv html v2](https://arxiv.org/html/2505.11154v2)
- Defense check (not proposed): MCPScan and MCPShield never flagged DPMA servers; flagged GAPMA servers in only 2–3 settings. LLM-judge stealth TPR: best-description 37.5%, GAPMA variants 0–5% — [arXiv html v2](https://arxiv.org/html/2505.11154v2)
- Verdict: **IN** (agent calls an allowed, installed tool; no boundary crossed).

**2. Beyond the Protocol: Unveiling Attack Vectors in the MCP Ecosystem** [PP]
- Authors: Hao Song, Yiming Shen, Wenxuan Luo, Leixin Guo, Ting Chen, Jiashui Wang, Beibei Li, Xiaosong Zhang, Jiachi Chen. arXiv 2506.02040, v1 31 May 2025, v4 14 Sep 2025; no venue listed — [arXiv abs](https://arxiv.org/abs/2506.02040)
- Attack classes: tool poisoning, puppet attacks (cross-server shadowing-like), rug pull, exploitation via malicious external resources. Authors uploaded malicious servers to 3 aggregation platforms; audits did not catch them; user study n=20: users struggled to spot malicious servers. No ASR on abs page; harms include private-file access and device control — [arXiv abs](https://arxiv.org/abs/2506.02040)
- Channels **T**, **S/O** (external resources). No defense proposed. Verdict: mostly **SUP/IN** (malicious server steers allowed tools).

**3. When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation** [PP]
- Authors: Weibo Zhao, Jiahao Liu, Bonan Ruan, Shaofei Li, Zhenkai Liang (NUS). arXiv 2509.24272, v1 29 Sep 2025, CC BY 4.0, no venue — [arXiv abs](https://arxiv.org/abs/2509.24272)
- 12 component-based categories: server metadata poisoning, server configuration abuse, initialization logic, tool metadata poisoning, tool logic, tool output, resource metadata poisoning, resource logic, resource output, prompt metadata poisoning, prompt logic, prompt output. Hosts Claude Desktop, Cursor, fast-agent; LLMs GPT-4o, o3, Claude Sonnet 4, Claude Opus 4, Gemini-2.5-pro — [arXiv html v1](https://arxiv.org/html/2509.24272v1)
- Avg success: 100% for config abuse, init logic, tool logic, tool output, resource logic, prompt logic; server-metadata poisoning 94%; tool-metadata poisoning 89.3%; resource output 67.8%; resource metadata 66.7%; prompt output 46.7%. Swapping fast-agent's system prompt for Cursor's cut tool-metadata poisoning 100% → 6.7%; GPT-4o on Cursor 0% for tool-metadata poisoning; o3 resisted malicious-resource selection (13.3%) while GPT-4o and Gemini-2.5-pro picked it in all trials; Opus 4 below Sonnet 4 on prompt-output (73.3% vs 93.3%) — [arXiv html v1](https://arxiv.org/html/2509.24272v1)
- Scanner evaluation on 120 generated servers: mcp-scan detected 4/120 (only tool-metadata category); AI-Infra-Guard detected 63/120, 0/10 on server metadata, resource metadata, prompt output; mcp-scan launches the server, so malicious init code runs before the scan; AI-Infra-Guard ~$0.50 and ~10 min per scan, unstable — [arXiv html v1](https://arxiv.org/html/2509.24272v1)
- Mitigations proposed (no numbers): platform audit, host config validation / trust tiers / runtime filtering / safety system prompt, LLM training, least-privilege local accounts — [arXiv html v1](https://arxiv.org/html/2509.24272v1)
- Channels: **T**, **O**, **S** (resources, prompts, server metadata) — the only paper found with measured numbers on resource and prompt channels. Verdict: logic/config/init categories are **SUP** (server code itself is malicious); metadata/output categories are injection-driven **IN**.

**4. MCPXKIT / MCPLIB: Unified Toolkit for Analyzing MCP Security** [PR, IEEE TDSC]
- Authors: Yongjian Guo, Puzhuo Liu, Wanlun Ma, Zehang Deng, Xiaogang Zhu, Peng Di, Xi Xiao, Sheng Wen. arXiv 2508.12538, v1 18 Aug 2025, v2 25 May 2026; accepted IEEE TDSC, DOI 10.1109/TDSC.2026.3695553 — [arXiv abs](https://arxiv.org/abs/2508.12538)
- 31 attack methods in 4 categories: direct tool injection (single-tool: file add/delete/modify/retrieve, rug pull, remote listener, command injection, RCE; multi-tool: shadowing, tool coverage, preference manipulation, functional obfuscation, forced execution, multi-tool cooperation, infectious), indirect tool injection (webpage poisoning, malicious project installation, tool return), malicious user, LLM-inherent — [arXiv html v2](https://arxiv.org/html/2508.12538v2)
- Success over 10 runs each: file add/modify/retrieve 100%, file delete 90%; tool coverage and forced execution 100%; shadowing, rug pull, command injection 80%; preference manipulation, infectious, RCE 70%; functional obfuscation 50%; multi-tool cooperation 30%. File operations succeed most because add/read/modify need no user confirmation; delete and code execution do. Tool-return payloads reportedly beat webpage poisoning (no numbers given). No model named in the fetched text; simulated stock-price tool plus existing Weather/Fetch tools — [arXiv html v2](https://arxiv.org/html/2508.12538v2)
- Channels **T**, **W**, **O**, **F** (project installation). Goals R and X directly measured (file retrieve / add). No defense evaluated. Verdict: file and shadowing attacks **IN**; command injection / SQL injection **BRK**.

**5. MCP-ITP: Automated Framework for Implicit Tool Poisoning in MCP** [PP]
- Authors: Ruiqi Li, Zhiqiang Wang, Yunhao Yao, Xiang-Yang Li. arXiv 2601.07395, v1 12 Jan 2026; no venue — [arXiv abs](https://arxiv.org/abs/2601.07395)
- Attack class: implicit tool poisoning — the poisoned tool is never called; its metadata steers the agent to call a legitimate high-privilege tool. Generation as black-box optimization with an evaluator LLM and a detector LLM. Dataset MCPTox; 12 LLM agents (not named on abs page). ASR up to 84.2%; malicious-tool detection rate down to 0.3%; beats the hand-crafted MCPTox baseline — [arXiv abs](https://arxiv.org/abs/2601.07395)
- Channel **T**. No defense proposed. Verdict: **IN** by construction (the harmful call goes to a legitimate tool).

**6. Trivial Trojans: How Minimal MCP Servers Enable Cross-Tool Exfiltration of Sensitive Data** [PP; abstract at Technical AI Governance Forum 2025]
- Authors: Nicola Croce, Tobin South. arXiv 2507.19880, v1 26 Jul 2025 — [arXiv abs](https://arxiv.org/abs/2507.19880)
- Attack class: cross-server exfiltration — a benign-looking server (weather) discovers and uses another server's legitimate tools (banking) to obtain account balances. Proof of concept only; no ASR or model list on abs page; proposes mitigations and protocol changes — [arXiv abs](https://arxiv.org/abs/2507.19880)
- Channel **T/O** (cross-server). Goal analog: **R** + **E**. Verdict: **IN** (each server is used within its own permissions; harm comes from the cross-server data flow).

**7. Lateral Data Exfiltration in MCP: How One Compromised Server Captures Cross-Domain Agent Data** [PR workshop: ICML 2026 Workshop "Agents in the Wild", poster]
- Authors: Akshat Sharda, Zhenyu Zhang. OpenReview YxVbx9hZRs; no arXiv id shown — [ICML 2026 virtual page](https://icml.cc/virtual/2026/67871)
- Attack class: a compromised server exposes a covert logging tool that the agent calls on its own and that captures data from all other connected servers ("weakest-link property"). Outcomes: 90.7% autonomous invocation over 360 interactions; 100% capture of cross-server banking operations. Models not named on the page; no defense on the page — [ICML 2026 virtual page](https://icml.cc/virtual/2026/67871)
- Channel **T**. Goal analog: **E** (data leaves via the attacker's own tool). Verdict: **IN** (the agent calls an installed tool; no server boundary is broken).
- Note: a search engine associated this paper with the name "Log-To-Leak"; that link is not confirmed — [search result, ICML page](https://icml.cc/virtual/2026/67871)

**8. MCP Pitfall Lab: Exposing Developer Pitfalls in MCP Tool Server Security under Multi-Vector Attacks** [PP]
- Authors: Run Hao, Zhuoran Tan. arXiv 2604.21477, v1 23 Apr 2026, v2 14 Jul 2026; no venue — [arXiv abs](https://arxiv.org/abs/2604.21477)
- Attack families: tool-metadata pitfalls, untrusted outputs, cross-tool flows, multi-modal inputs, privileged sink actions. 4 models (unnamed on abs page). 2,579 validator-completed runs; overall ASR 31.9%; multi-modal injection strongest at 38.7%. Outcomes checked with MCP traces and objective validators, not agent self-report — [arXiv abs](https://arxiv.org/abs/2604.21477)
- Defense proposed: Semantic MCP-BOM + hardening. Static semantic-field detection F1 0.727; BOM findings 27 → 16 after hardening; control coverage 0.173 → 0.697; residual risk 15.31 → 6.09. Case study: cross-tool forwarding and image-to-tool leakage need runtime provenance, not static manifest fields — [arXiv abs](https://arxiv.org/abs/2604.21477)
- Channels **T**, **O**, image inputs. Verdict: mostly **IN** (cross-tool forwarding to privileged sinks).

**9. "Your AI, My Shell": Demystifying Prompt Injection Attacks on Agentic AI Coding Editors** [PP] (not MCP, but closest measured evidence for the repo-file channel)
- Authors: Yue Liu, Yanjie Zhao, Yunbo Lyu, Ting Zhang, Haoyu Wang, David Lo. arXiv 2509.22040, v1 26 Sep 2025 — [arXiv abs](https://arxiv.org/abs/2509.22040v1)
- Channel: coding-rules files placed in the workspace (**F**). MCP config was discussed but not evaluated. Framework AIShellJack: 314 payloads, 70 MITRE ATT&CK techniques, 11 categories, 5 codebases, 2,826 results, 1 run each — [arXiv html v1](https://arxiv.org/html/2509.22040v1)
- ASR (one scenario): Cursor Auto 83.4%, Cursor + Gemini 2.5 Pro 76.8%, Cursor + Claude 4 Sonnet 69.1%, Copilot + Claude 4 Sonnet 52.2%, Copilot + Gemini 2.5 Pro 41.1%; Cursor Auto range across scenarios 66.9–84.1%. Per tactic (Cursor Auto): discovery 91.1%, collection 77.0%, credential access 68.2%, persistence 62.7%, exfiltration 55.6% — [arXiv html v1](https://arxiv.org/html/2509.22040v1)
- Attacks use the editor's own terminal and file tools with auto-approve on; no software bug exploited. Variant in which the agent writes harmful calls into source code and then runs them: 277/314 outputs contained malicious patterns, so command allow/deny lists alone are insufficient. Payload framing mattered much more than user-prompt wording — [arXiv html v1](https://arxiv.org/html/2509.22040v1)
- Goals: **R** (credential access), **X** (persistence), **E** (exfiltration) all measured as tactics. Verdict: **IN** (explicitly).
- Follow-up arXiv 2605.25871 ("How Agentic AI Coding Assistants Become the Attacker's Shell") reportedly gives 41–84% ASR; not verified beyond a search snippet — [Emergent Mind](https://www.emergentmind.com/papers/2605.25871)

**10. New Prompt Injection Attack Vectors Through MCP Sampling** [VB, Palo Alto Networks Unit 42]
- Authors: Yongzhe Huang, Akshata Rao, Changjiang Li, Yang Ji, Wenjun Hu. Published 5 Dec 2025 — [Unit 42](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- Classes via server-initiated sampling requests: resource (quota) theft, conversation hijacking that persists across turns, covert file-system tool invocation. PoC malicious server built on the reference "everything" server; host = unnamed coding copilot; model not named. Only number: hidden output equal to about 1,000 extra words in the quota-theft PoC. Recommends request templates, token caps, injection scanning, approval for server-initiated tool calls, isolating sampling context — [Unit 42](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- Channel **S** (sampling). Verdict: **IN** (covert call to an allowed file tool). No ASR — so the sampling channel has PoC evidence only.

### Inferences
- Papers 1–10 above, plus MSB / MCP-SafetyBench / MCPTox / MCPSecBench (see benchmarks.md) and MCP-FSD / ToFu / MCP-SEC / MCP Safety Audit (see mcp_attacks.md), form the attack-measurement literature for MCP. Peer-reviewed in this file: MPMA (AAAI), MCPXKIT (IEEE TDSC), Lateral Data Exfiltration (ICML 2026 workshop). The rest are preprints or a vendor blog.
- Tool-metadata poisoning (**T**) is by far the most measured channel; response-side injection (**O**/**W**) second; resource/prompt/sampling (**S**) only in "When MCP Servers Attack" (numbers) and Unit 42 (PoC).
- Only 3 of the 10 items here propose and score a defense (MCP Pitfall Lab: MCP-BOM; When MCP Servers Attack: scanner evaluation + mitigations without numbers; MPMA and MCP-ITP only show existing scanners/detectors fail).

### Gaps
- Model lists and per-model ASR not on the abstract pages for MCP-ITP (12 agents), MCP Pitfall Lab (4 models), Trivial Trojans, Lateral Data Exfiltration; full texts not read for these.
- MPMA AAAI year/edition not stated on the arXiv page (likely AAAI 2026 given v2 Nov 2025; unconfirmed).
- "Beyond the Protocol" full text not read; any per-attack success numbers it has are not captured here.
- "Log-To-Leak" as a separate paper name could not be confirmed; "AutoMalTool" not found by search.

---

## Q2. Which injection channels have published measurements, and which have none (git commit messages, memory-graph entities, resource contents, server instructions, sampling)?

### Takeaway
Tool metadata (**T**) and tool output / retrieved web content (**O**/**W**) are well measured with ASR numbers. Repo files (**F**) are measured only for coding editors outside MCP. Resources and prompts (**S**) have one paper with numbers. Sampling has a vendor PoC only. Git commit messages (**G**) and MCP memory-graph entities (**M**) have **no published ASR measurement**: G has only incident demos and CVEs (issue text, git-log reading), and M has only non-MCP memory-poisoning benchmarks. These two channels are a real gap the study can fill.

### Cited Findings
Channel-by-channel evidence (numbers are class-level outcomes):

| Channel | Measured? | Evidence (best numbers) |
|---|---|---|
| **T** tool description / metadata (incl. poisoning, preference manipulation, shadowing, rug pull) | Yes, heavily | MCPTox max 72.8% (see benchmarks.md); MCP-ITP up to 84.2% with 0.3% detection — [arXiv 2601.07395](https://arxiv.org/abs/2601.07395); MPMA ~100% (direct variant) — [arXiv html](https://arxiv.org/html/2505.11154v2); tool-metadata poisoning 89.3%, server-metadata 94% — [arXiv 2509.24272](https://arxiv.org/html/2509.24272v1); shadowing 80%, rug pull 80%, preference manipulation 70% (10 runs each) — [arXiv 2508.12538](https://arxiv.org/html/2508.12538v2); covert logging tool invoked in 90.7% of 360 interactions — [ICML 2026 workshop](https://icml.cc/virtual/2026/67871); rug-pull-like staged trust 69.5% (TrustShiftProbe, see benchmarks.md) |
| **O** tool output / function return | Yes | Tool-output attack 100% across host–LLM combos — [arXiv 2509.24272](https://arxiv.org/html/2509.24272v1); tool-return injection reportedly beats webpage poisoning (no numbers) — [arXiv 2508.12538](https://arxiv.org/html/2508.12538v2); untrusted-output pitfalls within 31.9% overall ASR — [arXiv 2604.21477](https://arxiv.org/abs/2604.21477); MSB response-stage and MCP-SafetyBench function-return injection (see benchmarks.md) |
| **W** fetched web page | Yes, less | Webpage poisoning is one of 3 indirect attacks in MCPXKIT (indirect class avg ~80%, this researcher's unweighted calc from its table) — [arXiv 2508.12538](https://arxiv.org/html/2508.12538v2); MSB retrieval injection (see benchmarks.md); MCP-SEC parasitic ingestion (see mcp_attacks.md) |
| **F** repo file | Only outside MCP | Rules files in workspace: 41.1–83.4% ASR on Cursor / Copilot with Claude 4 Sonnet and Gemini 2.5 Pro — [arXiv 2509.22040](https://arxiv.org/html/2509.22040v1); MCPXKIT "malicious project installation" (no separate number captured) — [arXiv 2508.12538](https://arxiv.org/html/2508.12538v2) |
| **G** git commit message | **No measurement found** | Nearest: GitHub issue text → private-repo data leaked via PR, one demo with Claude 4 Opus, no ASR — [Invariant Labs blog, 26 May 2025](https://invariantlabs.ai/blog/mcp-github-vulnerability); third-party git MCP server CVE-2025-53107: indirect injection when the agent reads git logs leads to command injection (advisory-DB page, not NVD-verified) — [Fluid Attacks DB](https://db.fluidattacks.com/adv/npm/%40cyanheads/git-mcp-server/CVE-2025-53107); official mcp-server-git CVE-2025-68143/68144/68145 (path validation bypass, unrestricted git_init, argument injection in git_diff), triggered by content the assistant reads (README, issue, web page), fixed Dec 2025 — [The Register, 20 Jan 2026](https://www.theregister.com/2026/01/20/anthropic_prompt_injection_flaws/); lab reproductions of git command injection (GHSA-3q26-f695-pp76) and GitHub issue injection — [mcp-breach-to-fix-labs](https://github.com/PawelKozy/mcp-breach-to-fix-labs) |
| **M** memory-graph entity | **No MCP measurement found** | Non-MCP: MPBench — 6 memory-poisoning classes, 4 write channels; agents that write/retrieve memory more aggressively are more exploitable; existing PI defenses do not cover memory poisoning (arXiv 2606.04329, Dash et al., v1 3 Jun 2026, v2 18 Jun 2026, preprint; no numbers on abs page) — [arXiv abs](https://arxiv.org/abs/2606.04329); graph-memory attack "ShadowMerge" across Mem0/Graphiti (snippet only) — [Emergent Mind](https://www.emergentmind.com/papers/2605.09033); MINJA-style injection >95% under idealized conditions, as cited by an EHR-agent study (snippet only) — [arXiv 2601.05504](https://arxiv.org/pdf/2601.05504v1); ASB memory poisoning (see benchmarks.md); the MCP memory server persistence-path issue is a config-injection bug, not entity-content injection (see mcp_attacks.md) |
| **S** resources | Yes, one paper | Resource metadata poisoning 66.7%, resource output 67.8%, resource logic 100% — [arXiv 2509.24272](https://arxiv.org/html/2509.24272v1) |
| **S** prompts | Yes, one paper | Prompt output 46.7%, prompt logic 100%, prompt-metadata poisoning not quantified — [arXiv 2509.24272](https://arxiv.org/html/2509.24272v1) |
| **S** server instructions | Partly | "Server metadata poisoning" 94% avg — [arXiv 2509.24272](https://arxiv.org/html/2509.24272v1); whether this category covers the `instructions` field of the initialize result is not confirmed from the fetched text |
| **S** sampling | PoC only | Quota theft, conversation hijack, covert file-tool call; only number ≈1,000 hidden extra words — [Unit 42, 5 Dec 2025](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/) |
| images / multimodal | Yes, one paper | Multi-modal injection strongest family, 38.7% ASR — [arXiv 2604.21477](https://arxiv.org/abs/2604.21477) |

### Inferences
- The study's G (commit message) and M (memory-graph entity) channels would be the first measured MCP numbers for those channels. Commit messages are structurally similar to issue text (attacker-controlled text returned by a legitimate read tool), so ASR may be in the same range as other tool-output channels, but this is untested.
- W and F are covered, but mostly with custom servers; measuring them through the reference fetch and filesystem servers adds external validity, not novelty.
- The T channel is saturated in the literature; for the study, T is mainly useful to test the static-scanner layer. Scanners miss most poisoned servers: mcp-scan 4/120, AI-Infra-Guard 63/120 — [arXiv 2509.24272](https://arxiv.org/html/2509.24272v1); MPMA servers mostly undetected by MCPScan/MCPShield — [arXiv html](https://arxiv.org/html/2505.11154v2).

### Gaps
- No paper found that measures ASR for injection via git commit messages or via MCP memory-server (knowledge-graph) entities.
- CVE-2025-53107 details not confirmed on NVD (fetch returned the NVD home page).
- Full text of MPBench not read; its 4 write channels and ASR numbers are unknown here.

---

## Q3. Per-model-family ASR trends: do newer / larger models resist better or worse?

### Takeaway
There is no monotone "bigger is safer" trend. In tool-poisoning work, more capable and reasoning-enabled models are often **more** susceptible (MCPTox "inverse scaling"), partly because weak models fail to carry out the attacker's task at all. Vendor-specific resistance appears in single papers (GPT-4o vs preference manipulation; o3 vs malicious resources; Claude 3.5 Sonnet on AgentDojo), but it does not transfer across attack classes. Host configuration (system prompt, auto-approve, how resources are passed) often moves ASR as much as the model does.

### Cited Findings
- MCPTox per-model average ASR (20 settings): o1-mini 72.8, DeepSeek-R1 70.9, Phi-4 70.2, GPT-4o-mini 61.8, Gemini-2.5-flash 59.7, Qwen3-32b (reasoning) 58.5, DeepSeek-V3 56.5, Qwen3-235b (reasoning) 50.6, Qwen3-8b (reasoning) 41.8, Claude-3.7-Sonnet 34.3, Qwen3-14b (reasoning) 27.1, Llama-3.1-70B 24.6, Qwen3-32b 23.7, Qwen3-235b 17.2, GPT-3.5-turbo 14.9, Gemma-2-9b 14.5, Llama-3.1-8B 14.1, Qwen3-8b 14.0, Mistral 8.3, Qwen3-14b 5.1. Authors call it "inverse scaling"; enabling reasoning raised Qwen3 ASR by 27.8%; Qwen3-32B more susceptible than 8B. Paradigm ASR: implicit-trigger parameter tampering 46.7%, explicit-trigger function hijacking 36.7%, implicit-trigger function hijacking 26.7%. Success = the agent's recorded call to a separate legitimate tool; whether calls were executed live is not stated — [arXiv html v1](https://arxiv.org/html/2508.14925v1)
- MPMA (GAPMA, approx.): Gemini-2.5-flash 91.88%, DeepSeek-V3 78.75%, Qwen3-235B 73.75%, Claude-3.7-Sonnet 62.81%, GPT-4o 22.19%; authors suggest GPT-4o has specific defenses — [arXiv html v2](https://arxiv.org/html/2505.11154v2)
- When MCP Servers Attack: o3 resisted malicious-resource selection (13.3%) while GPT-4o and Gemini-2.5-pro selected it in all trials; Claude Opus 4 lower than Sonnet 4 on prompt-output attacks (73.3% vs 93.3%); host system-prompt swap cut tool-metadata poisoning 100% → 6.7%; GPT-4o 0% on Cursor for tool-metadata poisoning — [arXiv html v1](https://arxiv.org/html/2509.24272v1)
- Coding editors, same model, different host: Claude 4 Sonnet 69.1% (Cursor) vs 52.2% (Copilot); Gemini 2.5 Pro 76.8% (Cursor) vs 41.1% (Copilot); ASRs stayed around 40% or higher even with the most advanced models — [arXiv html v1](https://arxiv.org/html/2509.22040v1)
- A frontier model (Claude 4 Opus) was still manipulated in the GitHub MCP demo; authors state alignment alone is insufficient — [Invariant Labs blog](https://invariantlabs.ai/blog/mcp-github-vulnerability)
- MSB: lowest ASR Llama3.1 8B 19.74%, highest DeepSeek-V3.1 60.94%; GPT-5 37.17%, Claude 4 Sonnet 52.51%. MCP-SafetyBench: 29.80% (Qwen3-235B) to 48.16% (o4-mini). AgentDojo: claude-3-5-sonnet 1.11% vs gpt-4o 47.69% — see benchmarks.md.

### Inferences
- Low ASR in small models is partly "cannot" rather than "will not". A study comparing 2–3 models must report benign utility next to ASR, or a weak model will look "safe".
- Because host settings moved ASR by up to ~93 points (100% → 6.7%) in one paper, the study must fix and report the host system prompt, the approval mode, and how tool results are framed, as controls or as variables.
- Expect current frontier models with strong tool use to show non-trivial ASR on in-scope misuse; refusal is rare (MCPTox max refusal <3%, see benchmarks.md).

### Gaps
- No paper found that tracks the same model family across versions (e.g., Claude 3.5 → 4 → later) on one MCP benchmark; the trends above mix benchmarks with different setups.
- Per-model numbers for MCP-ITP (12 agents) and MCP Pitfall Lab (4 models) not captured.

---

## Q4. Does the successful attack stay inside declared permissions (in-scope misuse) or cross a boundary? Tally

### Takeaway
Of 18 attack-measurement papers/reports checked (this file + benchmarks.md + mcp_attacks.md), 11 report successes that are mainly **in-scope misuse** (allowed tool, allowed resource), 4 are mixed, and 3 are mainly **boundary or host bugs**. Measured LLM-driven ASR numbers come almost only from in-scope attacks; boundary work (MCP-FSD, ToFu) reports bug prevalence, not agent ASR. This supports the hypothesis, with a strong caveat: most benchmarks define success as legitimate-tool misuse by design, so the literature is biased toward IN.

### Cited Findings
Tally (verdict = what the reported successful attacks do; this researcher's class-level reading, not a label the papers report):

| # | Paper / report | Status | Verdict | Basis |
|---|---|---|---|---|
| 1 | MPMA | PR (AAAI) | IN | agent selects attacker's installed tool — [arXiv](https://arxiv.org/abs/2505.11154) |
| 2 | MCP-ITP | PP | IN | metadata steers a legitimate high-privilege tool — [arXiv](https://arxiv.org/abs/2601.07395) |
| 3 | MCPTox | PR (AAAI 2026, per benchmarks.md) | IN | success requires calling a separate legitimate tool — [arXiv html](https://arxiv.org/html/2508.14925v1) |
| 4 | Trivial Trojans | PP | IN | uses another server's legitimate tools — [arXiv](https://arxiv.org/abs/2507.19880) |
| 5 | Lateral Data Exfiltration | PR workshop | IN | agent itself calls the covert logging tool — [ICML](https://icml.cc/virtual/2026/67871) |
| 6 | MCP Pitfall Lab | PP | IN (mostly) | cross-tool forwarding to privileged sinks — [arXiv](https://arxiv.org/abs/2604.21477) |
| 7 | Your AI, My Shell | PP (non-MCP) | IN | own terminal/file tools, no bug exploited — [arXiv html](https://arxiv.org/html/2509.22040v1) |
| 8 | Unit 42 sampling | VB | IN | covert call to an allowed file tool — [Unit 42](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/) |
| 9 | Invariant GitHub MCP | VB | IN | "not a flaw in the GitHub MCP server code itself"; user's authorized access — [blog](https://invariantlabs.ai/blog/mcp-github-vulnerability) |
| 10 | MCP-SEC (Parasitic Toolchain) | PR (IEEE S&P 2026) | IN | root causes: no context–tool isolation, no least privilege — see mcp_attacks.md |
| 11 | MSB | PR (ICLR 2026) | IN (likely) | attacks via planning/invocation/response of real tools; "out-of-scope parameter" class (76.5% avg) is a tool-interface misuse, classification not confirmed — see benchmarks.md |
| 12 | MCPXKIT | PR (IEEE TDSC) | Mixed, IN-majority | file add/modify/retrieve 100% (IN); command injection 80%, SQL injection 100% (BRK) — [arXiv html](https://arxiv.org/html/2508.12538v2) |
| 13 | When MCP Servers Attack | PP | Mixed IN + SUP | 6 metadata/output categories (IN), 6 logic/config/init categories (malicious server code) — [arXiv html](https://arxiv.org/html/2509.24272v1) |
| 14 | Beyond the Protocol | PP | Mixed SUP + IN | malicious servers via aggregators — [arXiv](https://arxiv.org/abs/2506.02040) |
| 15 | MCP-SafetyBench | PR (ICLR 2026) | Mixed | server-side poisoning (IN) plus host-side tampering/spoofing (HOST) — see benchmarks.md |
| 16 | MCP-FSD | PP | BRK | filesystem capability laundering, path-validation bypass; 150 validated instances — see mcp_attacks.md |
| 17 | ToFu | PP | BRK (mostly) | path traversal 64, SSRF 7, OS command injection 3 of 253 bugs (others: reflected output 115, log injection 58) — see mcp_attacks.md |
| 18 | MCPSecBench | PP | HOST/BRK | MitM, DNS rebinding, sandbox escape, CVEs — see benchmarks.md |

- Totals: IN 11 (rows 1–11), mixed 4 (rows 12–15), BRK/HOST 3 (rows 16–18). MCP Safety Audit (arXiv 2504.03767) is not re-classified here (see mcp_attacks.md).
- Boundary bugs do exist in the study's own reference servers: filesystem CVE-2025-53109/53110 and git CVE-2025-68143 / CVE-2026-27735 (see mcp_attacks.md); git CVE-2025-68144/68145 fixed Dec 2025 — [The Register](https://www.theregister.com/2026/01/20/anthropic_prompt_injection_flaws/). Injected content can trigger them, so a BRK path is real for unpatched versions.
- In-scope success can be high without any bug: file add/modify/retrieve 100% (10 runs each) — [arXiv 2508.12538](https://arxiv.org/html/2508.12538v2); covert tool invocation 90.7% — [ICML](https://icml.cc/virtual/2026/67871); privilege restrictions alone are insufficient because the agent can write harmful code and then run it (277/314) — [arXiv 2509.22040](https://arxiv.org/html/2509.22040v1).
- Caution on labels: 58 "attack success" labels in an MCP campaign were relabeled as authorized benign completions after treatment-blind regrading (arXiv 2608.12880, see benchmarks.md). IN-misuse and legitimate behavior are easy to confuse.

### Inferences
- Evidence **for** the hypothesis: the large majority of measured MCP injection successes use an allowed tool on an allowed resource; root-cause analyses (MCP-SEC, Invariant) name missing least privilege and missing context–tool isolation, not server bugs.
- Evidence **against / limits**: (a) selection bias — MCPTox counts a call to the poisoned tool itself as failure and requires a legitimate tool, so IN is built into the metric; (b) boundary-bug prevalence is not small (MCP-FSD: 16.4% of triaged servers have unexpected filesystem capability; ToFu: 74 boundary-type bugs) and the reference git/filesystem servers had such CVEs; (c) no paper measures, on the same traces, what share of successes would remain if the server boundary were perfect — that is the study's contribution.
- Practical consequence: pin patched server versions for the main experiment (so BRK is near zero by design and the IN share is measured cleanly), and optionally run one arm on a known-vulnerable version to show what server-side checks add.

### Gaps
- No paper found that labels each successful trace IN vs BRK; all verdicts above are class-level readings of each paper's attack definitions.
- Verdicts for MSB's out-of-scope-parameter class and for MCP Safety Audit not confirmed from full text.

---

## Q5. Attack-demo and vulnerable-server repos used for MCP security research

### Takeaway
Three widely used demo/lab repos exist: Invariant Labs' mcp-injection-experiments (the original tool-poisoning / shadowing / sleeper-rug-pull demos, 2025), Damn Vulnerable MCP Server (10 CTF-style challenges, ~1.4k stars, most popular), and Appsecco's vulnerable-mcp-servers-lab (9 deliberately vulnerable servers, MIT). A smaller "breach-to-fix" lab ships vulnerable and secure variants of 10 real incidents, which fits a defense study best. None of them is a measurement benchmark; none targets the reference git or memory servers with in-content injection.

### Cited Findings
- GitHub API metadata could only be partly read (unauthenticated rate limit hit after search calls); star counts below come from GitHub search-API results or the repo page as fetched on 2026-10-24. Last-commit dates mostly not visible; "pushed" = GitHub `pushed_at`.

| Repo | Stars | Last push | License | Contents (class level) | Channels / goals | Source |
|---|---|---|---|---|---|---|
| invariantlabs-ai/mcp-injection-experiments | 211 (32 forks, 8 commits) | 2025-04-10 | none in API result; not shown on page | 3 demos: direct tool poisoning; cross-server tool shadowing; shadowing + sleeper rug pull against a WhatsApp MCP server. Companion to Invariant's tool-poisoning blog and mcp-scan | **T**; goals ≈ R/E (data exfil via a trusted server's tool) — **IN** | [GitHub](https://github.com/invariantlabs-ai/mcp-injection-experiments); [GitHub search API](https://api.github.com/search/repositories?q=mcp+poisoning&sort=stars) |
| harishsg993010/damn-vulnerable-MCP-server (DVMCP) | 1,358 (API) / 1.4k, 187 forks, 23 commits | 2025-12-08 | MIT per README; API shows none | 10 challenges: easy — basic PI, tool poisoning, excessive permission scope; medium — rug pull, tool shadowing, indirect PI, token theft; hard — malicious code execution, remote access control, multi-vector. SSE transport, Python | **T**, **O**; R, E, code exec — mix of **IN** and **BRK** | [GitHub](https://github.com/harishsg993010/damn-vulnerable-MCP-server); [GitHub search API](https://api.github.com/search/repositories?q=vulnerable+mcp&sort=stars) |
| appsecco/vulnerable-mcp-servers-lab | 280, 58 forks, 12 commits | not visible | MIT | 9 servers: filesystem workspace (path traversal, unsandboxed code exec); IPI local stdio (hidden instructions in documents); IPI remote HTTP+SSE; malicious code exec (eval); malicious tools (instruction injection, fabricated output); namespace typosquatting; outdated packages; secrets/PII exposure in logs; Wikipedia remote server (unsanitized remote content) | **F**, **W**, **T**, **O**; R, X, E — mix of **IN**, **BRK**, **SUP** | [GitHub](https://github.com/appsecco/vulnerable-mcp-servers-lab) |
| PawelKozy/mcp-breach-to-fix-labs | 90, 15 forks, 14 commits | 2025-12-03 | not visible | 10 real incidents reproduced, each with vulnerable and secure mode + pytest regressions: CRM confused deputy; filesystem prefix bypass (CVE-2025-53110); hidden instructions in tool responses; Xata read-only bypass; news-prompt exfiltration; log poisoning; SQL injection via stored prompt; git command injection (GHSA-3q26-f695-pp76); GitHub public-issue injection → private repo leak; tool description poisoning | **O**, **W**, **G** (issue text), **T**; R, E — 5 **IN**-type (3, 5, 6, 9, 10), 5 **BRK**-type (1, 2, 4, 7, 8) | [GitHub](https://github.com/PawelKozy/mcp-breach-to-fix-labs); [GitHub search API](https://api.github.com/search/repositories?q=mcp+security+lab&sort=stars) |
| aminrj-labs/mcp-attack-labs | 21 | 2026-08-04 | NOASSERTION | Offensive labs: tool poisoning, cross-server shadowing, RAG injection (description only, not read) | **T**, **O** | [GitHub search API](https://api.github.com/search/repositories?q=mcp+security+lab&sort=stars) |
| Azure-Samples/sherpa | 29 | 2026-10-19 | MIT | Guided lab for MCP security and best practices (description only) | — | [GitHub search API](https://api.github.com/search/repositories?q=mcp+security+lab&sort=stars) |
| AISecurityConsortium/AIGoat | 173 | 2026-10-18 | Apache-2.0 | General LLM red-team playground (PI, RAG poisoning); MCP coverage not confirmed | — | [GitHub search API](https://api.github.com/search/repositories?q=mcp+ctf&sort=stars) |

- Research benchmark repos with attack corpora are listed in benchmarks.md (MSB, MCPSafety, MCPSecBench) — see benchmarks.md.
- DVMCP's page shows no "Used by" entries and no paper citation; no paper in this file states that it used DVMCP — [GitHub](https://github.com/harishsg993010/damn-vulnerable-MCP-server)

### Inferences
- For a defense study, mcp-breach-to-fix-labs is the most useful template: paired vulnerable/secure servers + regression tests per incident, and its split (half injection-driven misuse, half server bugs) mirrors the study's IN vs BRK question.
- Invariant's experiments and DVMCP are the de-facto "canonical" demos cited by blogs, but they are CTF-style with one scripted scenario each; they give no ASR and should be treated as class examples, not measurement baselines.
- None of the repos plants injections in git commit messages or memory-graph entities, so the study's G and M channels would be new attack-demo content.

### Gaps
- Exact last-commit dates and API-confirmed licenses for invariantlabs-ai/mcp-injection-experiments, DVMCP, and appsecco lab were not obtained (rate limit).
- Whether any peer-reviewed paper used DVMCP or the Appsecco lab as its testbed was not found.
