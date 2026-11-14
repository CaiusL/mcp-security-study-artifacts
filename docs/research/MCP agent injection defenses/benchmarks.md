# Benchmarks and evaluation harnesses for prompt injection against tool-using / MCP agents

Scope note: researched 2026-10-24. "Preprint" = arXiv only, no peer-reviewed venue confirmed. Defense mechanisms are only listed with the numbers each benchmark reports (defense deep-dive is covered by another researcher). Several 2026 arXiv items were verified only at abstract level; this is marked per item.

## Q1. General agent-injection benchmarks (AgentDojo, InjecAgent, ASB, WASP, AgentHarm, BIPIA, others): tasks, tools, attacks, metrics, models, defense plug-in, license, repo, MCP support

### Takeaway
AgentDojo is the de-facto reference: stateful environments, deterministic task/attack checks, three metrics (utility, utility under attack, targeted ASR), pluggable defenses, MIT license, and the largest body of comparable defense results. None of the general benchmarks is MCP-native; the only MCP bridge found for AgentDojo is a tiny third-party repo (agentdojo-mcp, 0 stars) with documented validity caveats. A 2025–2026 critique (Bhagwatkar et al.) shows AgentDojo, ASB and InjecAgent have measurable implementation flaws that change headline numbers.

### Cited Findings

**AgentDojo (ETH Zurich SPY Lab + Invariant Labs)**
- arXiv 2406.13352, v1 19 Jun 2024, v3 24 Nov 2024 (v3 fixes a Llama implementation bug and updates the travel suite); authors Debenedetti, Zhang, Balunović, Beurer-Kellner, Fischer, Tramèr. 97 realistic tasks (email client, e-banking, travel booking) and 629 security test cases; designed as an extensible framework for new tasks, defenses and adaptive attacks, not a static suite — [arXiv abs](https://arxiv.org/abs/2406.13352)
- Four suites: travel, banking, slack, workspace; current benchmark profile v1.2.2 with package agentdojo 0.1.35 (per a third-party bridge README) — [agentdojo-mcp README](https://github.com/basitalisandhu/agentdojo-mcp)
- Repo: MIT license, ~954 stars, 262 forks, 722 commits; ships a `tool_filter` defense, a `tool_knowledge` attack, and an optional transformers-based PI detector; no MCP support mentioned in README — [GitHub ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo)
- Results page explicitly says it is "not a leaderboard" (not every model × attack × defense is run). Metrics: Utility, Utility under attack, Targeted ASR. Examples: gpt-4o-2024-05-13 no defense / important_instructions: utility 69.07%, UA 50.08%, ASR 47.69%; with tool_filter ASR 6.84% (UA 56.28%); with transformers_pi_detector ASR 7.95% but UA 21.14%; spotlighting_with_delimiting ASR 41.65%; repeat_user_prompt ASR 27.82%. claude-3-5-sonnet-20241022: utility 79.38%, ASR 1.11%. claude-3-7-sonnet-20250219: utility 88.66%, UA 77.27%, ASR 7.31% (2025-02-24, newest entry). Some rows link to traces in Invariant Explorer — [AgentDojo results](https://agentdojo.spylab.ai/results/)
- Attack variants available: important_instructions (default), tool_knowledge, injecagent, ignore_previous, direct — [AgentDojo results](https://agentdojo.spylab.ai/results/)
- Known open issues inherited by any AgentDojo extension: workspace injection tasks 6–13 have empty ground truths; possible misleadingly low attack-success numbers (issues #213, #212, #214, #209, #201, #194) — [agentdojo-mcp README](https://github.com/basitalisandhu/agentdojo-mcp)
- Flaws found by Bhagwatkar et al.: injections sometimes overwrite task-critical data (e.g., bill items), so tasks fail regardless of resistance; brittle utility checks (e.g., inbox must grow by exactly one); after fixes GPT-4o utility under attack rose 60.87 → 72.19 — [arXiv 2510.05244v2](https://arxiv.org/html/2510.05244v2)
- Venue: AgentDojo is commonly cited as NeurIPS 2024 Datasets & Benchmarks, but the fetched arXiv page does not state a venue (see Gaps).

**MCP bridge for AgentDojo (agentdojo-mcp)**
- Maps an AgentDojo suite's tools onto a real MCP server's tools (heuristic name/schema matching → user-edited YAML → validator); transports: stdio (`--stdio`) and Streamable HTTP (`--url`); own JSON-RPC client, not the MCP SDK; reports utility, UA, targeted ASR and a log of every MCP call; `replay` re-renders a report from results.json; `--model ground-truth` replays reference solutions without a model — [GitHub basitalisandhu/agentdojo-mcp](https://github.com/basitalisandhu/agentdojo-mcp)
- Self-declared caveats: mapping is heuristic ("similar names and schemas, not identical behavior"); in `server` mode AgentDojo's environment is not updated, so post-task state checks miss server-side changes; without a `seed` tool injections only reach the agent via local tools; servers that cannot reset state leak state across tasks. Suite fit: travel "cleanest", banking "workable", slack "mostly stateful", workspace "hardest". MIT, 0 stars, 10 commits, 2026 — [GitHub basitalisandhu/agentdojo-mcp](https://github.com/basitalisandhu/agentdojo-mcp)
- A near-identical copy exists under another account; which is canonical is unclear — [GitHub nawaaaaaAaar/agentdojo-mcp](https://github.com/nawaaaaaAaar/agentdojo-mcp)
- Related student-scale testbed: FastMCP stdio servers with in-memory fake data, the four AgentDojo attack wordings, nine defenses on a LangGraph + Ollama agent (search-snippet level only) — [GitHub tulasinayak/understanding-prompt-injection-mcp](https://github.com/tulasinayak/understanding-prompt-injection-mcp)
- An MCP spec-analysis paper notes InjecAgent and AgentDojo assume direct tool APIs rather than MCP's client-server architecture (snippet level) — [arXiv 2601.17549](https://arxiv.org/html/2601.17549)

**InjecAgent (UIUC, Kang lab)**
- arXiv 2403.02691, v1 5 Mar 2024, v3 4 Aug 2024; ACL 2024 Findings (peer-reviewed). 1,054 test cases, 17 user tools, 62 attacker tools, 30 LLM agents. ReAct-prompted GPT-4 vulnerable 24% of the time; "enhanced" hacking-prompt setting nearly doubles ASR — [arXiv abs](https://arxiv.org/abs/2403.02691); [ACL Anthology](https://aclanthology.org/2024.findings-acl.624.pdf)
- Attack types: direct harm and data stealing (two-stage); metrics ASR-valid and ASR-all; MIT; last README update 07/01/2024; no MCP — [GitHub uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent)
- Critique: no utility metric (defense cost unmeasurable); attacks are simplistic, some look benign in context, enhanced attacks are less effective on recent models — [arXiv 2510.05244v2](https://arxiv.org/html/2510.05244v2)

**Agent Security Bench (ASB)**
- arXiv 2410.02644, v1 3 Oct 2024, v4 30 May 2025; ICLR 2025 (peer-reviewed). 10 scenarios, 10 agents, 400+ tools, 27 attack/defense methods (10 PI attacks, memory poisoning, Plan-of-Thought backdoor, 4 mixed attacks, 11 defenses), 7 metrics, 13 LLM backbones; highest average ASR 84.30%; defenses of "limited effectiveness"; introduces a utility–security balance metric — [arXiv abs](https://arxiv.org/abs/2410.02644); [ICLR 2025 PDF](https://proceedings.iclr.cc/paper_files/paper/2025/file/5750f91d8fb9d5c02bd8ad2c3b44456b-Paper-Conference.pdf)
- Repo: MIT; attacks DPI, OPI, memory poisoning, PoT backdoor, mixed; defenses delimiters, sandwich, instructional prevention, paraphrasing, shuffle, PPL detection, LLM detection; open models via Ollama; no MCP — [GitHub agiresearch/ASB](https://github.com/agiresearch/ASB)
- Critique: attacker tools are force-injected into every sub-task, inflating ASR (GPT-4o combined attack 73.58% → 9.25% after fix); tool responses are hard-coded so calling every tool earns full utility — [arXiv 2510.05244v2](https://arxiv.org/html/2510.05244v2)

**WASP (Meta FAIR)**
- arXiv 2504.18575 (Apr 2025); NeurIPS 2025 Datasets & Benchmarks (peer-reviewed); end-to-end web-agent PI benchmark in an isolated environment; attacks partially succeed in up to 86% of cases but agents often fail to fully complete attacker goals — [NeurIPS 2025](https://papers.nips.cc/paper_files/paper/2025/hash/1c9818387f5dd0a0bc151214660f059d-Abstract-Datasets_and_Benchmarks_Track.html)
- Repo: built on WebArena/VisualWebArena (GitLab, Reddit) and Anthropic Computer Use Demo; models gpt-4o, gpt-4o-mini, claude-35, claude-37; defenses = defensive system prompts, plus a format to test OpenAI instruction hierarchy; majority CC-BY-NC 4.0; archived (read-only) 1 Jul 2026; no MCP — [GitHub facebookresearch/wasp](https://github.com/facebookresearch/wasp)

**AgentHarm (UK AISI + Gray Swan) — scope only**
- arXiv 2410.09024, v1 11 Oct 2024, v3 18 Apr 2025; ICLR 2025. 110 explicitly malicious agent tasks (440 with augmentations), 11 harm categories; measures refusal of harmful agentic requests and capability retention under jailbreak — this is direct misuse by the user, not indirect injection. Dataset on Hugging Face (ai-safety-institute/AgentHarm) — [arXiv abs](https://arxiv.org/abs/2410.09024)

**BIPIA (Microsoft)**
- arXiv 2312.14197; five tasks (EmailQA, WebQA, Summarization, TableQA, CodeQA); ASR scored by an evaluator LLM (GPT-3.5 default); defenses: border strings, in-context learning, multi-turn dialogue (black-box), special-token fine-tuning (white-box); 25 LLMs; not a tool-use/agent benchmark; repo archived 16 Sep 2026 — [GitHub microsoft/BIPIA](https://github.com/microsoft/BIPIA)

**Newer AgentDojo-derived / general benchmarks (2026)**
- AgentDyn (arXiv 2602.03117, v1 3 Feb 2026, v3 7 May 2026, preprint): 60 open-ended tasks, 560 injection cases (Shopping, GitHub, Daily Life), with "helpful third-party instructions" in the environment; 10 defenses evaluated, "almost all" either insecure or over-defend — [arXiv abs](https://arxiv.org/abs/2602.03117); [code](https://github.com/leolee99/AgentDyn)
- AgentDyn reports tool filtering over-defends on its tasks despite high utility on AgentDojo (snippet level) — [arXiv 2602.03117v1 html](https://arxiv.org/html/2602.03117v1)
- AutoDojo (arXiv 2606.15057, v1 13 Jun 2026, v3 28 Sep 2026, preprint, CC BY 4.0): generates black-box adaptive IPI attacks on AgentDojo + AgentDyn suites; 10 defenses × 5 models; static benchmarks "significantly overestimate" defense efficacy; under-specified tasks are most vulnerable — [arXiv abs](https://arxiv.org/abs/2606.15057); [code](https://github.com/xhOwenMa/AutoDojo)

### Inferences
- AgentDojo's design (user task × injection task pairs, deterministic checks on environment state, Utility / UA / targeted-ASR triplet) is the convention reviewers will expect; the study should report the same triplet even if it uses its own harness.
- AgentDojo's tool-level abstraction is Python functions in a simulated environment, so it cannot natively test MCP-specific channels (tool-description poisoning, server-side state, stdio lifecycle); the agentdojo-mcp bridge exists but is too immature (0 stars, heuristic mappings, state-check gap) to rely on without auditing.
- WASP and BIPIA are archived and WASP is non-commercial; they are reference points, not bases.

### Gaps
- AgentDojo venue (NeurIPS 2024 D&B) and last-commit date were not visible in the fetched pages.
- Exact AgentDojo tool count and injection-task count were not confirmed from a fetched source.
- Tensor Trust (prompt-injection game dataset) was not researched in depth; it is not a tool-use benchmark.
- BIPIA venue (reported elsewhere as KDD 2025) and license name were not confirmed; AgentHarm dataset license not confirmed.

## Q2. MCP-native benchmarks (2025–2026): real vs simulated servers, channels, models, ASR, defenses, repo, activity

### Takeaway
Two peer-reviewed MCP-native security benchmarks run real MCP tooling end-to-end with automatic oracles: MSB (ICLR 2026; mcp-use client, FileSystem + DesktopCommander servers, workspace-state oracles) and MCP-SafetyBench (ICLR 2026; built on MCP-Universe, real third-party servers, dual task/attack labels, 3 repetitions). MCPTox (AAAI 2026, by citation) is the reference corpus for tool-description poisoning across 45 real servers. The rest are custom/vulnerable-server playgrounds (MCPSecBench), classifier datasets (MCP-AttackBench, MCIP), small 2026 preprints, or utility-only MCP benchmarks (MCP-Universe, LiveMCP-101, MCPMark). None of them targets the reference servers filesystem + git + fetch + memory + time together.

### Cited Findings

**Comparison table (security benchmarks)**

| Benchmark | Status / dates | Servers | Channels | Scale | Models | Headline ASR | Defenses evaluated | Repo / license |
|---|---|---|---|---|---|---|---|---|
| MSB | ICLR 2026; arXiv 2510.15994 v2 24 Mar 2026 | Real tools executed via MCP (not simulated); 25 MCP servers; agent gets FileSystem + DesktopCommander servers; benign tools from Smithery | Planning: name collision, preference manipulation, PI in tool description; invocation: out-of-scope parameter; response: user impersonation, false error, tool transfer, retrieval injection; mixed | 10 scenarios, 65 user tasks, 6 attack tasks, 304 benign + 405 attack tools, 2,000 instances | 10 (Llama3.1 8B/70B, Llama3.3 70B, Qwen3 8B/30B, Gemini 2.5 Flash, DeepSeek-V3.1, Claude 4 Sonnet, GPT-4o-mini, GPT-5) | avg 40.35%; range 19.74% (Llama3.1 8B) – 60.94% (DeepSeek-V3.1); GPT-5 37.17%, Claude 4 Sonnet 52.51%; OP attack avg 76.5% | MCIP detector: ASR 40.35→28.69%, PUA 56.50→48.91%, NRP 33.70→34.88% (over-rejects) | github.com/dongsenzhang/MSB, MIT, 52 stars, 5 commits, mcp-use 1.3.7 client |
| MCP-SafetyBench | ICLR 2026; arXiv 2512.15163 v2 5 Mar 2026 | Real MCP servers (tasks from MCP-Universe): filesystem, terminal, GitHub, Google Maps, SerpAPI/Serper, Chroma; Dockerized | 20 types: server side 11 (tool poisoning ×6 subtypes, function overlapping, preference manipulation, tool shadowing, function return injection, rug pull), host side 4 (intent injection, data tampering, identity spoofing, replay injection), user side 5 (malicious code exec, credential theft, remote access control, retrieval-agent deception, excessive privileges misuse) | 245 cases in 5 domains, one attack per case, multi-turn, multi-server | 13 (o4-mini, Gemini-2.5-Pro/Flash, DeepSeek-V3.1, GLM-4.5, GPT-5, Grok-4, Claude-3.7/4.0-Sonnet, Kimi-K2, Qwen3-235B, GPT-4.1, GPT-4o) | ASR 29.80% (Qwen3-235B) – 48.16% (o4-mini); TSR only 8.98–21.22%; host-side avg 81.94%; identity injection 100% on all 13 | Safety prompt: weighted ASR 39.88→38.65% (n.s., p=0.29) | github.com/xjzzzzzzzz/MCPSafety, license not stated, 26 stars, 94 commits |
| MCPTox | arXiv 2508.14925 v1 19 Aug 2025, v2 29 Sep 2026; AAAI 2026 per DOI cited by later work | 45 live real-world servers, 353 real tools | Tool poisoning in tool metadata only (no execution needed) | 1,348 cases, 10 risk categories, 3 templates | 20 agents | o1-mini 72.8% max; max refusal <3% (Claude-3.7-Sonnet); more capable models often more susceptible | None on abstract page | No repo on arXiv page |
| MCPSecBench | Tech report (Lingnan U.); arXiv 2508.13220 v1 17 Aug 2025, v3 12 Feb 2026; preprint | Custom reference + malicious/vulnerable servers (not third-party); stdio/HTTP/SSE | 17 attacks over client, protocol, server, host surfaces (PI, IPI, tool poisoning, rug pull, tool shadowing, MitM, DNS rebinding, name squatting, sandbox escape, vulnerable client/server, ...) | 15 runs per attack per platform | Claude Desktop (claude-opus-4.5), OpenAI (GPT-4.1), Cursor v2.3.29 | All surfaces compromised | Paper: MCIP mitigates 17.9%, FAN 28.9% on average; repo instead offers MCIP and AIM-MCP | github.com/AIS2Lab/MCPSecBench, MIT, 40 stars, 10 commits; GUI harness via pyautogui |

Sources: [MSB arXiv v2](https://arxiv.org/html/2510.15994v2), [MSB repo](https://github.com/dongsenzhang/MSB); [MCP-SafetyBench arXiv v2](https://arxiv.org/html/2512.15163v2), [ICLR 2026 PDF](https://proceedings.iclr.cc/paper_files/paper/2026/file/d46f127a80dc58cbc0732a717285c43a-Paper-Conference.pdf), [MCPSafety repo](https://github.com/xjzzzzzzzz/MCPSafety); [MCPTox arXiv](https://arxiv.org/abs/2508.14925); [MCPSecBench arXiv](https://arxiv.org/abs/2508.13220), [MCPSecBench html v3](https://arxiv.org/html/2508.13220v3), [MCPSecBench repo](https://github.com/AIS2Lab/MCPSecBench)

**Further details per benchmark**
- MSB metrics: ASR; PUA (performance under attack = completed user tasks under attack / total); NRP = PUA × (1 − ASR). Attack success judged from workspace state (e.g., sensitive data modified); task completion from tool-invocation logs; no LLM judge mentioned — [MSB arXiv v2](https://arxiv.org/html/2510.15994v2)
- MSB internal inconsistency: introduction cites a "peak ASR of 75.83%", but Table 3 shows OP reaching 98.75% on some models — [MSB arXiv v2](https://arxiv.org/html/2510.15994v2)
- MSB is officially the ICLR 2026 paper per README; uses LangChain providers via `.env` — [MSB repo](https://github.com/dongsenzhang/MSB)
- MCP-SafetyBench oracle: task evaluator inherited from MCP-Universe (format, static, dynamic checks); new per-attack detectors (e.g., `check_command_injection_attack`); every run gets a dual label (task pass/fail, attack success/fail); settings: temperature 1.0, 2,048 max output tokens, 60 s per-call timeout, max 20 ReAct iterations, 3 repetitions per task; cost not reported ("no cost constraints"); TSR vs DSR correlation r = −0.572 (p = 0.041) — [MCP-SafetyBench arXiv v2](https://arxiv.org/html/2512.15163v2)
- MCP-SafetyBench requires external accounts/keys: SerpAPI/Serper, Google Maps, GitHub PAT (dedicated test account recommended), Chroma — [MCPSafety repo](https://github.com/xjzzzzzzzz/MCPSafety)
- MCP-SafetyBench's own comparison table: SafeMCP (not real-world, multi-step, server attacks only, 2 types), MCPTox (real-world, single-step, server only, 11 types, 45 domains), MCIP-bench (not real-world, server + host, 10 types), MCP-AttackBench (not real-world, server + user, 10 types), MCPSecBench (not real-world, server+host+user, 17 types), MCP-SafetyBench (all ✓, 20 types, 5 domains) — [MCP-SafetyBench arXiv v2](https://arxiv.org/html/2512.15163v2)
- MCPTox: a secondary CSA note gives a 36.5% average ASR across models; not in the arXiv abstract — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-auto-execution-20260701/)
- MCPSecBench costs per round: Claude Desktop $0.41 (no defense) → $0.76 (MCIP); OpenAI $0.11 → $0.18; Cursor $0.11 → $0.46 with MCIP; FAN near baseline. Success = specification violation; refusals and execution errors logged separately; an LLM judge in the GUI harness automates evaluation — [MCPSecBench html v3](https://arxiv.org/html/2508.13220v3)
- MCPSecBench paper and repo disagree: paper evaluates MCIP + FAN and cites CVE-2025-6514 (mcp-remote 0.0.15); repo options are MCIP and AIM-MCP and the file is named `cve-2025-6541.py` — [MCPSecBench html v3](https://arxiv.org/html/2508.13220v3); [MCPSecBench repo](https://github.com/AIS2Lab/MCPSecBench)

**Classifier-style datasets (not end-to-end agent runs)**
- MCP-AttackBench (in MCP-Guard, arXiv 2508.10991, preprint): 70,000+ samples from public datasets augmented by GPT-4; used to train/evaluate a three-stage detector (static patterns → fine-tuned E5 detector → LLM arbitrator). Stage 1 static scanning: accuracy 74.55%, precision 97.67%, recall 38.89%, F1 55.63%; stage 2 detector accuracy 96.01%, F1 95.06% — [MCP-Guard arXiv](https://arxiv.org/pdf/2508.10991)
- MCIP (arXiv 2505.14590; reported as EMNLP 2025, HKUST + Huawei): taxonomy of unsafe MCP behaviors, a benchmark and training data to test whether LLMs detect MCP safety risks; code github.com/HKUST-KnowComp/MCIP — [MCIP arXiv](https://arxiv.org/html/2505.14590v7)

**Small 2026 MCP security preprints (abstract-level only)**
- "When the Manual Lies" (arXiv 2605.24069, 22 May 2026): 32 test cases, 6 risk categories, tool-description poisoning in a "high-fidelity sandbox"; 8 LLMs; GPT-4o "nearly 100%" ASR in six high-risk scenarios; prompt guardrails "largely ineffective" ("Firewall Fallacy"); no repo — [arXiv abs](https://arxiv.org/abs/2605.24069)
- TrustShiftProbe (arXiv 2608.23763, 24 Aug 2026): staged-trust (benign-then-defect, rug-pull-like) servers over four production domains; 9 variants (structural violation / semantic corruption / scope expansion × disruption / exfiltration / both); mean ASR 69.5%, reduced to 42.7% by their multi-tier transport-boundary defense SHIELD; no repo — [arXiv abs](https://arxiv.org/abs/2608.23763)
- HCP execution-control benchmark (arXiv 2606.29073, 27 Jun 2026, single author): 8 security invariants (metadata non-authority, grant-backed approval, canonical resources, principal binding, scoped capability invocation, source-and-target data-flow authorization, deny-path audit, explicit protocol state); 10 cases; naive runtime permits all, practice-informed mitigations (metadata linting, session checks, per-call approval) permit 6/10, HCP blocks 10/10; ablations identify which runtime component blocks each attack — [arXiv abs](https://arxiv.org/abs/2606.29073)

**Utility-only MCP benchmarks with real servers (possible harness bases, no attacks)**
- MCP-Universe (Salesforce, arXiv 2508.14704): 6 domains over 11 real MCP servers (location navigation, repo management, financial analysis, 3D design, browser automation, web search); programmatic evaluators — [arXiv PDF](https://arxiv.org/pdf/2508.14704); repo Apache-2.0, ~602 stars, 282 commits, rule-based evaluators `op(func(...), value)`, JSON task + YAML agent configs, agent types basic / function-call / react — [GitHub MCP-Universe](https://github.com/SalesforceAIResearch/MCP-Universe)
- LiveMCP-101 (arXiv 2508.15760, Duke/Zoom): 101 queries needing multiple MCP tools; scored against ground-truth execution plans with an LLM judge because live data changes; frontier models <60% success — [arXiv html](https://arxiv.org/html/2508.15760v1)
- MCPMark (arXiv 2509.24002): CRUD-diverse tasks with programmatic verification, avg 16.2 turns; best gpt-5-medium 52.56% pass@1, 33.86% pass^4 — [arXiv html](https://arxiv.org/html/2509.24002v1)

### Inferences
- Closest to the students' setting: MSB (real MCP execution, FileSystem server, state-based oracles, MIT) and MCP-SafetyBench (real servers incl. filesystem/terminal/GitHub, dual labels). Both still differ: neither uses the reference git/fetch/memory/time servers as a set; neither plants injections in git commit messages or memory-graph entities; both score defenses as separate live runs.
- MCP-SafetyBench's very low TSR (≤21%) means the utility axis of an ASR-vs-utility curve would sit near the floor with frontier models; its dependence on live third-party APIs (Maps, SerpAPI, GitHub) adds drift and cost.
- MCPTox is the best ready-made corpus of poisoned tool descriptions to test a static scanner layer, if its data is obtainable.
- MCPSecBench targets protocol/host bugs (MitM, DNS rebinding, CVEs) — mostly outside the study's threat model.

### Gaps
- MSB v1 date, transport (stdio vs other) and number of runs/seeds not found in the captured text; MSB Appendix D.5 comparison table was truncated.
- MCPTox repo and whether it executes tools or only judges the planned call not confirmed.
- MCP-SafetyBench license and whether datasets are fully released (paper says "will be released") not confirmed.
- No benchmark found that uses the modelcontextprotocol reference servers (filesystem, git, fetch, memory, time) together. Not found: "MCP-AttackBench" as a standalone repo, "SafeMCP" details, MCP-Universe exact task count from the primary source (secondary listing says 231).
- The MCP-Universe venue is unclear (a NeurIPS 2025 virtual page exists, likely a workshop).

## Q3. Do any benchmarks score multiple defense layers on the same attack traces, attribute successful attacks to the blocking layer, or separate boundary violations from in-scope misuse?

### Takeaway
I found no benchmark that replays one fixed set of attack traces through several defense layers and attributes each successful attack to the layer that would block it. All mainstream benchmarks (AgentDojo, ASB, MSB, MCP-SafetyBench, MCPSecBench) run each defense as a separate live run. The nearest pieces are: per-stage detector metrics (MCP-Guard), component ablations on 10 synthetic cases (HCP), a conceptual defense-placement taxonomy (MCP-DPT), and a label-audit paper that separates authorized completions from true violations. This attribution design is a genuine gap the study can fill.

### Cited Findings
- AgentDojo results compare defenses (tool_filter, transformers_pi_detector, spotlighting, repeat_user_prompt) only as separate rows/runs for gpt-4o — [AgentDojo results](https://agentdojo.spylab.ai/results/)
- Bhagwatkar et al. evaluate a tool-input firewall (Minimizer), a tool-output firewall (Sanitizer), and both combined as separate runs on AgentDojo, ASB, InjecAgent, τ-bench. GPT-4o on AgentDojo: no defense ASR 57.69%; Minimizer 18.15%; Sanitizer 0.00% (UA 69.15); combined 0.00% (UA 58.59); τ-bench no defense ASR 56.09% → Sanitizer 0.00% — [arXiv 2510.05244v2](https://arxiv.org/html/2510.05244v2)
- MCP-Guard reports per-stage numbers for a layered detector (static stage recall 38.89% at 97.67% precision; later stages catch the rest), but on a classification dataset, not agent traces — [MCP-Guard arXiv](https://arxiv.org/pdf/2508.10991)
- HCP benchmark uses ablations "to identify which runtime components block attacks", with invariants that include scoped capability invocation and source-and-target data-flow authorization; only 10 cases — [arXiv 2606.29073](https://arxiv.org/abs/2606.29073)
- MCP-DPT (arXiv 2604.07551, 8 Apr 2026, preprint) organizes attacks "by the architectural component responsible for enforcement" across six MCP layers with primary and secondary defense points; it maps existing defenses but reports no empirical per-layer block rates in the abstract; it finds protection "uneven and predominantly tool-centric", with gaps at host orchestration, transport and supply chain — [arXiv abs](https://arxiv.org/abs/2604.07551)
- TrustShiftProbe distinguishes payloads that are overt protocol violations from schema-valid manipulations that pass runtime middleware filters (boundary violation vs in-scope misuse, conceptually) — [arXiv 2608.23763](https://arxiv.org/abs/2608.23763)
- "Labels Are Not Endpoints" (arXiv 2608.12880, 13 Aug 2026, preprint): audit of an MCP agent campaign (10,200 execution rows); the grader leaked treatment metadata into labels; treatment-blind relabeling turned 58 ATTACK_SUCCESS/HIJACK_ATTEMPT labels into authorized benign completions, keeping 3 verified protected-data transfers and 1 unauthorized forwarding; 4 construct-boundary disagreements with the codebook — the clearest work separating real boundary violations from in-scope actions — [arXiv abs](https://arxiv.org/abs/2608.12880)
- MSB includes "Out-of-Scope Parameter" as an attack class (invocation stage) and it is the most effective (avg 76.5%) — [MSB arXiv v2](https://arxiv.org/html/2510.15994v2); MCP-SafetyBench includes "excessive privileges misuse" as a user-side type — [MCP-SafetyBench arXiv v2](https://arxiv.org/html/2512.15163v2). Both are attack categories, not outcome classes that separate in-scope misuse from boundary violation.
- MCPTox notes the attack misuses legitimate tools and that safety alignment does not stop it — [MCPTox arXiv](https://arxiv.org/abs/2508.14925)
- A multi-agent study reports least-privilege defenses failed in most tested settings because attacks use appropriate agents and tools inappropriately (snippet level) — [arXiv 2510.17276](https://arxiv.org/pdf/2510.17276)
- Khan, AlKhanbashi, and Mohamed, Computers 2026, 15(9):570, read in full on 2026-10-25 from the journal HTML. AgentDojo banking, separate live runs per defense. Wilson 95% intervals. The trace basis in Table 5 records which runs still had per-instance traces. GPT-5.4 utility under attack is 55.9% undefended and 39.6% with the tool filter. The tool filter’s zero-tool-call rate on GPT-5.4 is 56.9%. Benign utility for that model is 56.2% undefended and 53.1% with the tool filter. No paired comparison stays significant after Holm correction. — [Computers 15(9):570](https://doi.org/10.3390/computers15090570)
- agentdojo-mcp offers offline `replay` of results.json, but only to re-render reports, not to re-score traces under different defenses — [agentdojo-mcp README](https://github.com/basitalisandhu/agentdojo-mcp)

### Inferences
- The study's core method (record attack traces once, then evaluate static scanner, server checks, L0–L5 policies, task-conditioned policy and a data-flow rule on the same traces) has no direct precedent in the benchmarks found. It must be validated carefully: offline policy replay assumes that a blocked call ends the attack and that later trace steps do not matter (counterfactual validity). A small live re-run sample per layer would check this.
- Separating "boundary violation" (call outside the trace-derived allowed set) from "in-scope misuse" (allowed tool, allowed path, harmful argument or data flow) is the natural place where L-ladder policies stop and the data-flow rule starts; the evidence above (MSB OP attacks, MCPTox legitimate-tool misuse, least-privilege failures) suggests in-scope misuse will be a large residual class.
- Grader blindness matters: the oracle that labels canary success must not read which attack/defense condition produced the trace (per 2608.12880).

### Gaps
- Full text of MCP-DPT, HCP, ROPE (arXiv 2608.27496, 11 baseline defenses incl. CaMeL, Progent, MELON — snippet level, [arXiv PDF](https://arxiv.org/pdf/2608.27496)) and AgentArmor (trace-level program analysis compared with Progent and CaMeL on AgentDojo — snippet level, [arXiv PDF](https://arxiv.org/pdf/2508.01249)) not read; they may contain per-attack overlap tables.
- MDPI replication study full text not accessible (HTTP 403).

## Q4. Methodology best practice: oracles, held-out tasks, number of runs, cost, variance, statistics, adaptive vs static attacks; papers critiquing methodology

### Takeaway
Use deterministic, state-based oracles that are blind to the experimental condition; report benign utility, utility under attack and ASR together with confidence intervals over repeated runs; do not trust static-attack ASR as a robustness claim (adaptive attacks push most "near-zero" defenses above 90% ASR); and expect benchmark rankings to disagree across benchmarks. Reported practice for repetitions ranges from 1 (most) to 3 (MCP-SafetyBench), 4 (MCPMark pass^4) and 15 (MCPSecBench).

### Cited Findings

**Oracle design**
- AgentDojo-derived critique: injections must not overwrite task-critical inputs; utility checks should test semantic goal completion, not exact side-effect counts; do not force-inject attacker tools; report BU, UA and ASR together — [arXiv 2510.05244v2](https://arxiv.org/html/2510.05244v2)
- MSB judges attacks from workspace state and tasks from invocation logs (no LLM judge) — [MSB arXiv v2](https://arxiv.org/html/2510.15994v2); MCP-SafetyBench uses execution-based task checks plus per-attack detectors with dual labels — [MCP-SafetyBench arXiv v2](https://arxiv.org/html/2512.15163v2)
- LLM judges appear where live data prevents fixed answers (LiveMCP-101) — [arXiv html](https://arxiv.org/html/2508.15760v1); MCPSecBench uses an LLM judge in its GUI harness — [MCPSecBench html v3](https://arxiv.org/html/2508.13220v3); BIPIA scores ASR with GPT-3.5 — [BIPIA repo](https://github.com/microsoft/BIPIA)
- Agentic Benchmark Checklist (ABC), Zhu et al., NeurIPS 2025 D&B (arXiv 2507.02825): task setup / reward flaws can mis-estimate performance by up to 100% relative; examples: SWE-bench-Verified insufficient tests, τ-bench counts empty responses as success; applying ABC to CVE-Bench reduced overestimation by 33%; includes "outcome validity" — [arXiv html v5](https://arxiv.org/html/2507.02825v5); [NeurIPS 2025](https://proceedings.neurips.cc/paper_files/paper/2025/hash/f316275b44ee2de533102913828a8107-Abstract-Datasets_and_Benchmarks_Track.html)
- Grader treatment leakage: a historical MCP grader let condition metadata decide ATTACK_SUCCESS; 58 labels were wrong; recommends treatment-blind graders, label provenance ("Integrity Chain") and an endpoint-integrity linter — [arXiv 2608.12880](https://arxiv.org/abs/2608.12880)

**Static vs adaptive attacks**
- "The Attacker Moves Second" (Nasr, Carlini, Tramèr et al., arXiv 2510.09023, 10 Oct 2025, preprint): adaptive attacks (gradient, RL, random search, human-guided) bypass most of 12 defenses with ASR >90%, while most had reported near-zero ASR; static string sets and weak optimization are "flawed" evaluation — [arXiv abs](https://arxiv.org/abs/2510.09023)
- AutoDojo: static benchmarks "significantly overestimate" defense efficacy; most defenses sacrifice utility or are insecure under adaptive black-box attacks — [arXiv 2606.15057](https://arxiv.org/abs/2606.15057)
- Bhagwatkar et al.: existing agentic security benchmarks are "easily saturated" by simple firewalls; propose a three-stage cascade (standard injections → second-order/semantic → defense-aware adaptive) — [arXiv 2510.05244](https://arxiv.org/abs/2510.05244)
- Hofer, Debenedetti, Tramèr (arXiv 2606.10525, 9 Jun 2026, preprint): on AgentDojo (80 task pairs, 4 domains), black-box TAP substantially beats white-box GCG; task-universal attacks transfer to unseen tasks and out-of-distribution domains; attacks optimized on small open models do not transfer to frontier models such as GPT-5; safety-tuned attacker models sometimes refuse — [arXiv abs](https://arxiv.org/abs/2606.10525)

**Held-out tasks, variance, statistics, cost**
- Cross-benchmark consistency: 40 agent-safety benchmarks (2023–2026) analyzed; no evidence of ranking concordance across evaluation dimensions (Kendall's W = 0.10, p = 0.94); coverage counts overstate depth; robustness "effectively unbenchmarked"; calls for minimum reporting standards (Li et al., arXiv 2605.16282, 11 Apr 2026, preprint) — [arXiv abs](https://arxiv.org/abs/2605.16282)
- Repetitions in practice: MCP-SafetyBench 3 runs per task at temperature 1.0 — [arXiv v2](https://arxiv.org/html/2512.15163v2); MCPSecBench 15 runs per attack per platform — [html v3](https://arxiv.org/html/2508.13220v3); MCPMark reports pass@1 and pass^4 (52.56% vs 33.86% for its best model, showing large run-to-run inconsistency) — [arXiv html](https://arxiv.org/html/2509.24002v1)
- Significance testing in practice: MCP-SafetyBench reports p-values for the safety-prompt effect (p = 0.29, n.s.) and TSR–DSR correlation — [arXiv v2](https://arxiv.org/html/2512.15163v2); Computers 15(9):570 reports Wilson 95% intervals and exact McNemar tests on 144 matched GPT-5.4-mini pairs, none significant after Holm correction — [Computers 15(9):570](https://doi.org/10.3390/computers15090570)
- Cost: MCPSecBench per round $0.11–$0.76 depending on host and defense — [html v3](https://arxiv.org/html/2508.13220v3); MCP-SafetyBench does not report cost — [arXiv v2](https://arxiv.org/html/2512.15163v2). Computers 15(9):570 reports median wall-clock durations of a few seconds per AgentDojo instance and says those figures are not token or dollar cost. The 6.17 s versus 62.56 s pair is not in that paper.
- AgentDojo publishes per-run traces for some results (Invariant Explorer), which supports trace re-analysis — [AgentDojo results](https://agentdojo.spylab.ai/results/)

### Inferences
- For the trace-derived L0–L5 ladder, policies must be derived on a training split of tasks and scored on held-out tasks; otherwise the utility of tight policies is overstated (each policy would be fitted to the very traces it is scored on). The Hofer et al. transfer result also suggests holding out injection templates, not only tasks.
- With 2–3 models and canary-style binary outcomes, ≥3 runs per (task, injection, model) and Wilson or bootstrap CIs per cell are the documented norm; paired comparisons across layers on the same traces (e.g., McNemar-style) fit the attribution design well because every layer is scored on identical items.
- A static-attack-only study should state that its ASR numbers are lower bounds of attack capability and not robustness claims; adding at least one adaptive round (e.g., a TAP-style black-box loop against the best layer) would address the main reviewer objection.

### Gaps
- No source found that publishes seed-variance of ASR for the same model/attack on an MCP benchmark.
- Per-run dollar cost for AgentDojo, MSB and MCP-SafetyBench not reported in the fetched sources.

## Q5. Which benchmark is the best base to extend for MCP with real stdio servers, and what would be missing?

### Takeaway
No existing benchmark matches the study closely enough to "extend" without major work. The most practical path is a thin own harness on the official MCP client SDK with the reference stdio servers, copying AgentDojo's task/injection-pair structure, deterministic state oracles and metric triplet, borrowing attack templates and taxonomy from AgentDojo/MSB/MCP-SafetyBench, and using MCPTox-style poisoned descriptions for the scanner layer. If one base must be chosen, MSB is the closest MCP-native base (real MCP execution, filesystem server, state oracles, MIT, ICLR 2026), with AgentDojo kept as a comparability anchor.

### Cited Findings
- MSB already runs real tools through an MCP client (mcp-use 1.3.7) with FileSystem and DesktopCommander servers and judges attacks from workspace state; MIT; but small repo (5 commits) and no documented way to add defenses — [MSB repo](https://github.com/dongsenzhang/MSB); [MSB arXiv v2](https://arxiv.org/html/2510.15994v2)
- MCP-SafetyBench inherits MCP-Universe's evaluator framework and real third-party servers but needs external API keys and accounts; license not stated — [MCPSafety repo](https://github.com/xjzzzzzzzz/MCPSafety); MCP-Universe is Apache-2.0 with JSON task/YAML agent configs and custom evaluators — [MCP-Universe repo](https://github.com/SalesforceAIResearch/MCP-Universe)
- AgentDojo has the most comparable defense results and pluggable pipelines (MIT), but its tools are in-process functions; the only MCP bridge (agentdojo-mcp) has heuristic mappings, misses server-side state in post-task checks, and inherits open AgentDojo issues — [agentdojo-mcp README](https://github.com/basitalisandhu/agentdojo-mcp); [AgentDojo repo](https://github.com/ethz-spylab/agentdojo)
- MCPSecBench supports stdio/HTTP/SSE and Claude Desktop/OpenAI/Cursor hosts but uses custom vulnerable servers and a GUI-automation harness — [MCPSecBench html v3](https://arxiv.org/html/2508.13220v3); [repo](https://github.com/AIS2Lab/MCPSecBench)
- Existing MCP security benchmarks test each defense as a separate live run (see Q3) — [MSB arXiv v2](https://arxiv.org/html/2510.15994v2); [MCP-SafetyBench arXiv v2](https://arxiv.org/html/2512.15163v2); [MCPSecBench html v3](https://arxiv.org/html/2508.13220v3)

### Inferences
- What any base lacks for this study (all inferred from the above):
  1. Reference stdio servers as the tool surface (filesystem, git, fetch, memory, time); only filesystem appears in MSB/MCP-SafetyBench.
  2. Injection channels: git commit messages and memory-graph entities are not covered by any benchmark found; fetched-page and tool-description channels are covered (MSB retrieval injection / tool-description PI; MCP-SafetyBench function return injection / tool poisoning; MCPTox).
  3. Canary-goal oracles (in-root secret read, `.sh` write in allowed dir, canary exfiltration via fetch) must be written; MSB-style workspace-state checks plus a local HTTP sink for fetch are the closest pattern. Pointing fetch at a local server also keeps exfiltration contained and runs reproducible.
  4. Trace recording in a replayable format and an offline scorer that applies each layer (scanner, server checks, L0–L5, task-conditioned policy, data-flow rule) to the same traces, with first-blocking-layer attribution — no base has this.
  5. A boundary-violation vs in-scope-misuse label per successful attack — no base has this as an outcome class.
  6. Held-out task split for policy derivation, repeated runs, CIs, and an adaptive-attack round.
- Decision sketch: own harness = full control of 1–6, moderate build cost, weaker external comparability; extending MSB = faster start on MCP plumbing but still needs 1–6 and a defense hook; extending AgentDojo via agentdojo-mcp = best comparability but fights the mapping/state gap. Running the study's L0–L5 policies also on a small AgentDojo slice would give a cheap comparability anchor regardless of the main choice.

### Gaps
- MSB and MCP-SafetyBench transport (stdio vs Docker/HTTP) and server-reset behavior were not confirmed from primary sources; a quick code read of both repos is needed before choosing.
- Whether MCPTox data is downloadable (no repo on arXiv page) is unconfirmed.
- No MCP benchmark found with git- or memory-server injection channels; this may exist in unindexed work.
