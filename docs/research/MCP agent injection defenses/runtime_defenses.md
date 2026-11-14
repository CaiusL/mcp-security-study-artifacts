# Runtime and system-level defenses for prompt-injected (MCP) LLM agents

Scope note: researched 2026-10-24. "Preprint" = arXiv only, no venue listed on the arXiv page at fetch time. Numbers are as reported by the authors; most are on static benchmarks (AgentDojo, ASB). Adaptive-attack results are only noted briefly (covered by another researcher).

Corrections to the project's prior assumptions (verified):
- **FlowGuard (arXiv:2607.14754) is NOT an information-flow runtime defense.** It is an MCP *server scanner* ("From Signals to Evidence for MCP Security Detection", An, Chen, Hong, Chen, Wu; v1 16 Jul 2026, preprint, no code link). It probes servers with schema-valid inputs and adjudicates runtime evidence; F1 0.879 (command injection) and 0.942 (file-system access) on 1,880 executable MCP cases; up to 2.23x lower latency than other dynamic scanners; 523 findings across 326 real servers — [arXiv abs](https://arxiv.org/abs/2607.14754). It belongs next to layer (a) static scanner, not layer (e).
- **AgentBound (arXiv:2510.21236) is peer-reviewed (FSE 2026)**, its policies are written by an LLM pipeline from server source, and enforcement is a Docker container (AgentBox), not a proxy. Details below.
- **Progent v3 numbers are confirmed** (v3 dated 14 May 2026; AgentDojo ASR 39.9%→1.0%; ASB 70.3%→3.9%) and v3 adds an **MCP proxy mode** and an MCP-migrated AgentDojo — [arXiv abs](https://arxiv.org/abs/2504.11703); [arXiv v3 HTML](https://arxiv.org/html/2504.11703v3).
- **MCP-Guard (arXiv:2508.10991) is a detection pipeline**, not a privilege/policy system (details in detection section).

## Policy / privilege control systems (Progent, Conseca, AgentBound, ACE, IsolateGPT, AgentSandbox, Task Shield, DRIFT, f-secure, MiniScope, others)

### Takeaway
Almost all 2025–2026 privilege-control systems derive the policy from the *current task* (an LLM writes it: Progent, Conseca, DRIFT, MiniScope's plan, AuthBench-style policies) or from *code/manifests* (AgentBound, SkillScope); none found derives a cross-task least-privilege envelope from benign execution traces. Progent is the strongest, best-measured layer (d) reference and the only one with a documented MCP proxy mode; AgentBound is the closest analog to the project's L1 "declared" level.

### Cited Findings

**Progent** (Shi, He, Wang, Li, Wu, Guo, Song; v1 16 Apr 2025, v2 30 Aug 2025, v3 14 May 2026; preprint) — layer (d)
- Mechanism: privileges are symbolic rules over tool names and arguments; every tool call is checked; an LLM writes the initial policy from the user task and updates it during execution; Z3/SMT classifies updates as narrowing (auto-applied) or expansion (needs approval) — [arXiv abs](https://arxiv.org/abs/2504.11703)
- Policy language is JSON Schema validated with python-jsonschema; policy LLM in main experiments is gpt-4o — [arXiv v3 HTML](https://arxiv.org/html/2504.11703v3)
- Enforcement point: library mode (wrapper/middleware for LangChain, OpenAI Agents SDK) or proxy mode (LLM and MCP endpoints redirected to a Progent proxy, used for OpenHands) — [arXiv v3 HTML](https://arxiv.org/html/2504.11703v3)
- AgentDojo ASR 39.9%→1.0%; initial LLM policy without updates already 39.9%→2.5%; ASR stays below 5% across tested policy LLMs; claude-sonnet-4 agent 6.8%→0.5%; Meta-SecAlign-70B 4.8%→0.3%; ASB 70.3%→3.9%; hand-written manual ASB rules 0%; only 6% of policy updates are expansions; Manual-Approval configuration reaches 0% ASR — [arXiv v3 HTML](https://arxiv.org/html/2504.11703v3)
- MCP: authors migrated AgentDojo environments/tools/tasks to MCP servers; across LangChain, OpenAI Agents SDK, OpenHands, AutoGen ASR is "around 1%"; multi-agent AutoGen: defends >95% of successful attacks. Utility is described as "maintained"; exact utility values are only in figures (not extracted) — [arXiv v3 HTML](https://arxiv.org/html/2504.11703v3)
- Baselines compared on the same AgentDojo runs: repeat_user_prompt, spotlighting_with_delimiting, tool_filter, transformers_pi_detector, DataSentinel, LlamaPromptGuard2 (detectors described as ineffective; tool_filter has higher utility loss and ASR) — [arXiv v3 HTML](https://arxiv.org/html/2504.11703v3)
- Code: https://github.com/sunblaze-ucb/progent — [arXiv v3 HTML, Appendix A](https://arxiv.org/html/2504.11703v3)
- Independent replication: Qwen2.5-7B on AgentDojo, Progent 25.8%→4.2% mean ASR; a hand-crafted adaptive attack reached 2.6% (no increase) — "Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents" (25 Jun 2026, preprint) — [arXiv abs](https://arxiv.org/abs/2606.26479)

**Conseca — "Contextual Agent Security: A Policy for Every Purpose"** (Tsai, Bagdasarian, Google; v1 28 Jan 2025, v3 17 Apr 2025; HotOS '25) — layer (d)
- An LLM generates a just-in-time policy from the user task plus *trusted* context only (developer-specified: email addresses/categories, filesystem directory tree, username, date), tool docs and example policies; untrusted content (e.g., email bodies) is excluded — [arXiv v3 HTML](https://arxiv.org/html/2501.17070v3)
- Policy format: per API call, allow/deny plus a boolean argument constraint (regexes in the prototype) with a human-readable rationale; deterministic `is_allowed` checker runs before each tool; denials and rationale go back to the planner — [arXiv v3 HTML](https://arxiv.org/html/2501.17070v3)
- Evaluation (Linux computer-use agent, Gemini 1.5 Pro, filesystem + email tools, 20 tasks × 5 trials): tasks completed — no policy 14.0/20, static permissive 12.2/20, static restrictive 0.0/20, Conseca 12.0/20; Conseca and static-restrictive denied an injected "forward urgent-security emails" instruction; no count of attacks blocked — [arXiv v3 HTML](https://arxiv.org/html/2501.17070v3)
- No code link found — [arXiv v3 HTML](https://arxiv.org/html/2501.17070v3); venue HotOS '25 per [arXiv listing / search summary](https://arxiv.org/abs/2501.17070v1) and [Google Research page](https://research.google/pubs/context-is-key-for-agent-security/)

**AgentBound — "Securing Execution Boundaries of AI Agents"** (Bühler, Biagiola, Di Grazia, Salvaneschi; v1 24 Oct 2025, v3 24 Apr 2026; FSE 2026, DOI 10.1145/3808103) — closest to project level L1 "declared"
- Android-style declarative permission manifests for MCP servers; dataset of 296 popular MCP servers; "80.9% accuracy"; negligible enforcement overhead — [arXiv abs](https://arxiv.org/abs/2510.21236)
- Who writes the policy: an LLM agent pipeline (AgentManifestGen) reads repo code and docs, drafts several manifests, a consolidator merges them; validated against a fixed capability vocabulary with per-capability rationale — [arXiv v3 HTML](https://arxiv.org/html/2510.21236v3)
- Permission vocabulary is coarse resource categories: filesystem read/write/delete; env read/write, exec, process; network client/server/Bluetooth; peripherals; location, notifications, clipboard — [arXiv v3 HTML](https://arxiv.org/html/2510.21236v3)
- Enforcement: AgentBox, a Docker container per MCP server (mounts for filesystem, env whitelists, iptables allow-rules for hostnames); not a proxy; startup +150–400 ms, per-operation +0.29–0.6 ms — [arXiv v3 HTML](https://arxiv.org/html/2510.21236v3)
- The "80.9%" comes from developer replies to 96 GitHub issues (74% got no reply); separately, 96.5% capability-level agreement with human manifests on 48 servers — [arXiv v3 HTML](https://arxiv.org/html/2510.21236v3)
- Blocks 9 tested system-resource attacks; does NOT stop parameter-tampering on a permitted endpoint, SQL injection within allowed DB access, or prompt injections that only change LLM reasoning (out of scope) — [arXiv v3 HTML](https://arxiv.org/html/2510.21236v3)
- Artifact: Zenodo https://doi.org/10.5281/zenodo.19571298 (no GitHub link found) — [arXiv v3 HTML](https://arxiv.org/html/2510.21236v3)

**MiniScope** (Zhu, Huang, Tseng, Vernik, Patil, Fang, Popa — UC Berkeley/IBM; v1 11 Dec 2025, v2 6 Oct 2026; preprint) — task-conditioned least privilege over OAuth-style scopes
- Task-centric hierarchical permission model; automatically discovers permission hierarchies; enforces contextual least privilege at runtime; 43.4%–89.4% fewer simulated permission confirmations vs per-tool prompting; mitigates all tested privilege-escalation attacks with negligible utility/runtime impact; found six overprivileged connector configurations in ChatGPT and Claude — [arXiv abs](https://arxiv.org/abs/2512.11147)
- Uses an integer linear program to choose the cheapest scope set covering every API call in the agent's proposed plan; 1–6% latency overhead; reports LLM-based least-privilege decisions reach only 70–83% optimality (proprietary models) and 20–34% (open models) — [arXiv PDF via search summary](https://arxiv.org/pdf/2512.11147); [Berkeley Sky project page](https://sky.cs.berkeley.edu/project/miniscope/)
- No code link on arXiv page — [arXiv abs](https://arxiv.org/abs/2512.11147)

**DRIFT** (Li, Liu, Chiu, Li, Zhang, Xiao; v1 13 Jun 2025, v3 26 Mar 2026; NeurIPS 2025) — layer (d) + isolation
- Secure Planner builds a minimal function trajectory and a JSON-schema-style parameter checklist per function node from the user query; Dynamic Validator checks deviations against privilege limits and intent; Injection Isolator masks conflicting instructions in memory. Benchmarks: AgentDojo, ASB, AgentDyn (no numbers in abstract) — [arXiv abs](https://arxiv.org/abs/2506.12104)
- Project page: https://safo-lab.github.io/DRIFT — [arXiv abs](https://arxiv.org/abs/2506.12104)

**Task Shield** (Jia, Wu, Qin, Squicciarini; 21 Dec 2024; preprint per arXiv page) — LLM-judged task alignment per call
- Test-time check that each instruction and tool call contributes to user-specified goals; AgentDojo with GPT-4o: ASR 2.07%, utility 69.79%; no code link — [arXiv abs](https://arxiv.org/abs/2412.16682)

**ACE — "A Security Architecture for LLM-Integrated App Systems"** (Li, Mallick, Rose, Robertson, Oprea, Nita-Rotaru; v1 29 Apr 2025, v3 10 Sep 2025; NDSS 2026) — plan-then-execute + IFC + isolation
- Abstract plan built from trusted info only, mapped to a concrete plan over installed apps; static analysis checks the plan against user-specified secure information-flow constraints; data and capability barriers between apps; demonstrates planning-/execution-integrity attacks against IsolateGPT; evaluated on InjecAgent, ASB, LangChain Tool Usage; no numbers on abstract page; no code link — [arXiv abs](https://arxiv.org/abs/2504.20984)

**IsolateGPT (formerly SecGPT)** (Wu, Roesner, Kohno, Zhang, Iqbal; v1 8 Mar 2024, v2 30 Jan 2025; NDSS 2025) — isolation
- Execution-isolation architecture for LLM-based systems with third-party apps; overhead <30% for three-quarters of tested queries; no code link on arXiv page — [arXiv abs](https://arxiv.org/abs/2403.04960)

**f-secure — "System-Level Defense against Indirect Prompt Injection Attacks: An IFC Perspective"** (Wu, Cecchetti, Xiao; v1 27 Sep 2024, v2 10 Oct 2024; preprint) — layer (e)
- Context-aware pipeline generates structured executable plans; a security monitor filters untrusted input before it reaches planning; code: https://github.com/fzwark/Secure_LLM_System — [arXiv abs](https://arxiv.org/abs/2409.19091)

**AgentSandbox** — position paper, not an implemented, measured defense
- "LLM Agents Should Employ Security Principles" (arXiv:2505.24019) proposes AgentSandbox: a persistent agent holding the long-term user profile plus ephemeral per-task agents discarded at completion; argues for defense-in-depth, least privilege, complete mediation, psychological acceptability — [arXiv](https://arxiv.org/abs/2505.24019v1)

**Other privilege/least-privilege work found (2025–2026)**
- SkillScope (Wu, Nan, et al.; v1 7 May 2026, v3 10 Sep 2026; preprint): graph-based analysis of Skill instructions + code, runtime validation under instantiated tasks, "control-flow privilege constraining"; 94.53% skill-level F1 for over-privilege detection; 6,590 of 68,312 Skills over-privileged; 88.56% fewer over-privileged action-in-task instances; no code link — [arXiv abs](https://arxiv.org/abs/2605.05868)
- AuthBench, "Do Coding Agents Understand Least-Privilege Authorization?" (v1 14 May 2026; preprint): 120 terminal tasks; models map task → file-level r/w/x policy; frontier models both omit needed permissions and grant unused/sensitive ones ("broad-but-exposed" vs "tight-but-brittle"); proposes Sufficiency-Tightness Decomposition (+up to 15.8% sensitive-task success, lower ASR) — [arXiv abs](https://arxiv.org/abs/2605.14859)
- Task-based permission scoping (Noyan; 14 Sep 2026; preprint): role ceiling + task-permission classifier + prohibitions; classifier macro-F1 0.881 (RoBERTa-large) vs 0.886 (Claude Haiku 4.5 few-shot); role ceiling alone closes 27.9% of severity-weighted attack surface, +classifier 84.4%; 600-prompt dataset — [arXiv abs](https://arxiv.org/abs/2609.15422)
- IPIGuard (An et al.; EMNLP 2025): plans a Tool Dependency Graph and executes as traversal, decoupling planning from external data — [arXiv PDF](https://arxiv.org/pdf/2508.15310)

### Inferences
- Mapping to the study's layers: (d) task-conditioned = Progent, Conseca, DRIFT's Secure Planner, MiniScope (plan → scopes), Task Shield (LLM judge, not deterministic), AuthBench-style policies, Noyan's classifier. (c)-like static/declared envelopes = AgentBound (L1 "declared", coarse resource categories) and SkillScope (code-analysis over-privilege). Nobody in this set uses benign *traces* to learn the policy.
- Conseca's 4-way comparison (none 14.0 / permissive 12.2 / restrictive 0.0 / contextual 12.0 of 20) is a tiny precedent for the project's strictness ladder and shows the same pattern: a static restrictive policy collapses utility, a task-conditioned one recovers most of it.
- AuthBench's "tight-but-brittle" failure mode for model-written policies is the layer-(d) counterpart of the layer-(c) held-out-utility drop (27–71%); both are coverage failures, one from a single task description, one from finite training traces.
- AgentBound's own threat model excludes injections that "only alter reasoning", and it does not stop misuse of an allowed endpoint; this is exactly the gap that a "Needed" L3–L5 argument-level policy or a data-flow rule (e) is meant to close.

### Gaps
- Exact AgentDojo utility numbers for Progent v3 are in figures only; not extracted.
- No code repo found for Conseca, MiniScope, Task Shield, ACE, IsolateGPT, SkillScope (I believe IsolateGPT's code is under a "SecGPT" GitHub repo, but I did not verify the URL).
- Task Shield venue: arXiv page lists none; I could not confirm a peer-reviewed venue.
- No standalone empirical "AgentSandbox" system with numbers was found; only the position paper.

## Information-flow / capability designs (CaMeL and follow-ups, FIDES, Dual LLM, plan-then-execute, Design Patterns, RTBAS, taint tracking) and MCP fit for layer (e)

### Takeaway
CaMeL, FIDES, RTBAS, f-secure and PFI give the strongest guarantees but replace or re-architect the agent loop (custom interpreter/planner), so they do not drop in as an MCP proxy. MCP-native options that can implement a rule like "no fetch to a URL that came from tool output" today are Invariant Guardrails' `->` flow rules (MCP proxy/gateway) and the SAMOS gateway prototype (tool-level labels, session taint); both are coarser than CaMeL-style per-value provenance.

### Cited Findings
- **CaMeL — "Defeating Prompt Injections by Design"** (Debenedetti, Shumailov, Fan, Hayes, Carlini, Fabian, Kern, Shi, Terzis, Tramèr; v1 24 Mar 2025, v2 24 Jun 2025; preprint): extracts control and data flow from the trusted user query so untrusted data cannot change program flow; capabilities block exfiltration over unauthorized flows; 77% of AgentDojo tasks solved with provable security vs 84% undefended; code https://github.com/google-research/camel-prompt-injection — [arXiv abs](https://arxiv.org/abs/2503.18813)
- **"Can CaMeLs Talk?"** (Peters-Gill, Semler, Bartsch, Shumailov, Schroeder de Witt; 5 Oct 2026; preprint): CaMeL guarantees do not compose in hierarchical multi-agent systems; proposed Multi-CaMeL protocol keeps trusted instructions and untrusted data on separate channels across agents; ASR 12.9% (no CaMeL) → 0.2% (per-agent CaMeL) → 0.0% (Multi-CaMeL) — [arXiv abs](https://arxiv.org/abs/2610.05640)
- **CaMeLoT** (arXiv:2609.18674): CaMeL with temporal logic for static verification and liveness (only the title/related-work seen; no results verified) — [arXiv PDF](https://arxiv.org/pdf/2609.18674)
- **FIDES — "Securing AI Agents with Information-Flow Control"** (Costa, Köpf, et al., Microsoft; v1 29 May 2025, v2 3 Sep 2025; preprint): planner that attaches confidentiality/integrity labels to messages, actions, tool args and results; a policy engine checks labels before consequential actions; selective hide/reveal of results in variables to avoid label creep; evaluated on AgentDojo — [arXiv abs](https://arxiv.org/abs/2505.23643); reported ~2.43x median token increase — [alphaXiv overview](https://www.alphaxiv.org/overview/2505.23643v2) (secondary); code github.com/microsoft/fides (MIT) — [ecosyste.ms](https://science.ecosyste.ms/projects/42821) (secondary)
- **RTBAS** (Zhong, Chen, Wang, McCall, Titzer, Miller, Gibbons; 13 Feb 2025; preprint): IFC for tool-based agent systems; auto-executes calls that preserve integrity/confidentiality, asks the user otherwise; dependency screeners via LM-as-judge and attention saliency; AgentDojo: prevents all targeted attacks with 2% utility loss under attack; no code link — [arXiv abs](https://arxiv.org/abs/2502.08966)
- **Design Patterns for Securing LLM Agents against Prompt Injections** (Beurer-Kellner, Buesser, Creţu, Debenedetti, Dobos, Fabian, Fischer, Froelicher, Grosse, Naeff, Ozoani, Paverd, Tramèr, Volhejn; v1 10 Jun 2025, v3 27 Jun 2025; preprint): principled patterns with provable resistance, trading general capability for security, illustrated by case studies — [arXiv abs](https://arxiv.org/abs/2506.08837). The six patterns: Action-Selector, Plan-Then-Execute, LLM Map-Reduce, Dual LLM, Code-Then-Execute (sandboxed DSL enabling taint tracking), Context-Minimization — [Simon Willison summary, 13 Jun 2025](https://simonwillison.net/2025/Jun/13/prompt-injection-design-patterns/)
- **Plan-then-execute implementation guide**: "Architecting Resilient LLM Agents: A Guide to Secure Plan-then-Execute Implementations" (arXiv:2509.08646) — [arXiv PDF](https://arxiv.org/pdf/2509.08646) (not read in detail)
- **AgentArmor** (arXiv:2508.01249; preprint): converts agent runtime traces into graph (program-dependence-style) representations, attaches security metadata to tools/data, checks with a type system; AgentDojo TPR 95.75%, FPR 3.66% (abstract figures) — [arXiv abs](https://arxiv.org/abs/2508.01249v1)
- **Prompt Flow Integrity (PFI)** (arXiv:2503.15547; preprint): tracks untrusted data via data IDs and alerts when untrusted data reaches privileged tool calls; reports some utility loss because the LLM struggles with data IDs (my reading of excerpts; not fully verified) — [arXiv PDF](https://arxiv.org/pdf/2503.15547)
- **SAMOS — "Securing MCP-based Agent Workflows"** (Ntousakis; supervisors Vasilakis, Kemerlis; Brown master's thesis, May 2026; not peer-reviewed): IFC at an MCP gateway; labels are on *tools*, not data (binary high/low confidentiality); the gateway taints the session with the label of each tool used and blocks calls that would violate the policy; demonstrated on the GitHub MCP server private-repo leak; contrasts itself with CaMeL/FIDES data-level labels; limitation: coarse tool-level labels — [Brown PDF](https://atlas-group.cs.brown.edu/pdf/samos:brown:2026.pdf)
- **Invariant Guardrails** rule language supports flow rules with `->` between tool events, e.g., flag `send_email` after `get_inbox` to an external domain, or `send_email` after a `get_website` output scored as injection; enforcement in the Invariant Gateway, as an MCP/LLM proxy, or locally via `LocalPolicy` on a trace; Apache-2.0 — [GitHub invariantlabs-ai/invariant](https://github.com/invariantlabs-ai/invariant)
- **HCP / "From Tool Connection to Execution Control"** (Ting Liu; 27 Jun 2026; preprint): eight invariants for MCP-style runtimes incl. "source-and-target data-flow authorization" and "scoped capability invocation"; on 10 cases a naive MCP-like runtime permits all attacks, a mitigation baseline (metadata linting, session checks, per-call approval) permits 6/10, HCP blocks 10/10; sub-ms latency; no code link — [arXiv abs](https://arxiv.org/abs/2606.29073)
- f-secure (IFC, code available) — see previous section — [arXiv abs](https://arxiv.org/abs/2409.19091)

### Inferences
- For layer (e) on real MCP servers, the cheapest faithful implementation of "no fetch to a URL that came from tool output" is a gateway rule over the trace: record strings/URLs returned by tool results, and deny a `fetch` whose `url` argument matches one of them unless it also appears in the user prompt. This is an Invariant-style `->` flow rule or a SAMOS-style session taint, i.e., approximate provenance by value matching, not CaMeL's interpreter-level provenance. It will miss transformed/re-encoded URLs (inference).
- CaMeL/FIDES/RTBAS are better framed as a separate "architecture" baseline than as a bolt-on layer, because they require the agent to run inside their interpreter/planner. CaMeL's 77% vs 84% utility is the reference cost of strong IFC on AgentDojo.
- SAMOS's tool-level labelling is conceptually close to the project's L2 "needed coarse" granularity, while CaMeL-style per-value labels correspond to L5-like precision on the data-flow axis (inference).

### Gaps
- FIDES headline AgentDojo security/utility numbers not extracted (only token overhead from a secondary source).
- No evidence that CaMeL, FIDES or RTBAS ship an MCP adapter; I did not find one.
- SAMOS code location not found in the thesis grep; no quantitative evaluation beyond the GitHub MCP case study.
- PFI and AgentArmor details are from abstracts/excerpts only.

## Detection-based runtime defenses as comparison points (MELON, spotlighting, PromptGuard/Prompt Shields/Lakera-style classifiers, DataSentinel, PromptArmor, tool-output filtering)

### Takeaway
Detectors report very low ASR on AgentDojo (MELON 0.24%, PromptArmor <1%, LlamaFirewall combo 1.75%) but cost utility (MELON benign utility 80.41%→68.04% on GPT-4o) and are the class most often broken by adaptive attacks; they are the natural comparison baseline for privilege/data-flow layers, and several (MCP-Guard, mcp-context-protector, Invariant) already run inside MCP proxies.

### Cited Findings
- **MELON** (Zhu, Yang, Wang, Guo, Wang; v1 7 Feb 2025, v4 10 Jun 2025; ICML 2025): re-executes the trajectory with a masked user prompt; flags an attack when actions match across runs; code https://github.com/kaijiezhu11/MELON — [arXiv abs](https://arxiv.org/abs/2502.05174)
- MELON AgentDojo GPT-4o (BU / UA / ASR): no defense 80.41 / 69.08 / 16.06%; delimiting 82.47 / 69.75 / 13.39%; repeat prompt 83.51 / 77.86 / 9.18%; tool filter 65.98 / 65.54 / 2.34%; DeBERTa detector 38.14 / 21.34 / 2.58%; MELON 68.04 / 58.78 / 0.24%; MELON-Aug 76.29 / 68.72 / 0.32%; MELON FPR 9.28%; ~2× API cost. Llama-3.3-70B: no defense ASR 28.50% → MELON 1.27%, tool filter BU collapses to 4.12% — [arXiv v4 HTML](https://arxiv.org/html/2502.05174v4)
- **Spotlighting** (Hines, Lopez, Hall, Zarfati, Zunger, Kiciman, Microsoft; 20 Mar 2024; preprint): provenance-marking prompt transformations; GPT-family ASR from >50% to <2% with minimal task impact — [arXiv abs](https://arxiv.org/abs/2403.14720)
- **LlamaFirewall** (Chennabasappa et al., Meta; 6 May 2025; preprint): PromptGuard 2 (jailbreak/injection classifier), AlignmentCheck (CoT auditor, experimental), CodeShield — [arXiv abs](https://arxiv.org/abs/2505.03574). AgentDojo (ASR / utility): no guardrail 17.63% / 47.73%; PromptGuard 2 86M 7.53% / 47.01%; AlignmentCheck (Llama 4 Maverick) 2.89% / 43.09%; both combined 1.75% / 42.68%; code https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall — [arXiv v1 HTML](https://arxiv.org/html/2505.03574v1)
- **DataSentinel** (Liu, Jia, Jia, Song, Gong; v1 15 Apr 2025, v4 12 Nov 2025; IEEE S&P 2025, Distinguished Paper): fine-tunes an LLM detector via minimax (game-theoretic) training against adaptive injections; no numbers on abstract page; no code repo linked — [arXiv abs](https://arxiv.org/abs/2504.11358)
- **PromptArmor** (Shi, Zhu, et al.; 21 Jul 2025; preprint): off-the-shelf LLM detects and removes injected prompts before the agent sees them; on AgentDojo with GPT-4o/GPT-4.1/o4-mini FPR and FNR <1%, ASR <1% after removal — [arXiv abs](https://arxiv.org/abs/2507.15219)
- **MCP-Guard** (Xing et al.; v1 14 Aug 2025, v4 8 Jan 2026; preprint): static scan → neural detector → fine-tuned E5 model → LLM arbitrator; 96.01% accuracy on adversarial prompts; MCP-AttackBench of 70,448 samples; enforcement point not specified in abstract; no code link — [arXiv abs](https://arxiv.org/abs/2508.10991)
- **Task Shield** (LLM alignment judge) ASR 2.07% / utility 69.79% on AgentDojo GPT-4o — [arXiv abs](https://arxiv.org/abs/2412.16682)
- **TraceAegis** (see trace section) and **AgentShield** (deception: fake tools, fake credentials, allowlisted parameter values; arXiv:2605.11026) are trace/behavior-level detectors — [TraceAegis arXiv](https://arxiv.org/abs/2510.11203); [AgentShield arXiv HTML](https://arxiv.org/html/2605.11026v1)
- **Known bypasses (brief):** "The Attacker Moves Second" (Nasr, Carlini, Sitawarin, et al.; 10 Oct 2025; preprint) bypasses 12 recent defenses with ASR above 90% for most, though most originally reported near-zero ASR — [arXiv abs](https://arxiv.org/abs/2510.09023). AutoDojo (Ma, Li, Xiao, Yu, Zhang, Vorobeychik; v1 13 Jun 2026, v3 28 Sep 2026) generates black-box adaptive injections over ten defenses (prompt-level, filter-based, system-level) and five models; static benchmarks often significantly overestimate defense efficacy; code https://github.com/xhOwenMa/AutoDojo — [arXiv abs](https://arxiv.org/abs/2606.15057)

### Inferences
- MELON's table doubles as a ready-made "same traces, many layers" comparison: tool_filter (a crude static least-privilege by tool name, akin to the project's L2) gives low ASR but collapses utility on weaker models (BU 4.12% on Llama-3.3-70B), which mirrors the project's L2+ utility drop.
- Detectors and privilege layers fail differently: detectors leak under adaptive attacks (Nasr et al.), privilege layers fail on attacks that stay inside the allowed envelope (AgentBound's own exclusions). This argues for reporting both ASR and "attack-within-envelope" rate per layer (inference).

### Gaps
- Microsoft Prompt Shields and Lakera Guard: I found no peer-reviewed, agent-benchmark ASR/utility numbers in this pass; not verified.
- DataSentinel numbers on AgentDojo come only via Progent's comparison figure (described as ineffective there); exact values not extracted.
- The names of the 12 defenses broken by Nasr et al. were not on the abstract page.

## Learned least privilege from traces: classic lineage and 2024–2026 agent work; is a cross-task "Needed" envelope with a strictness-vs-utility curve already published?

### Takeaway
The classic lineage is direct and well established (Forrest 1996 normal-behavior profiles, systrace 2003 training mode, AppArmor complain-mode profiling, AWS IAM Access Analyzer policy generation from CloudTrail), and it already documents the project's core weakness: dynamic training misses rare-but-legitimate paths. For agents, I found anomaly detectors learned from benign traces (TraceAegis) and nested hand-defined restriction levels on coding agents (Permission Denied), but no published cross-task "Needed" envelope learned from benign traces and plotted as a nested-strictness vs held-out-utility curve under prompt injection.

### Cited Findings
**Classic systems lineage**
- Forrest, Hofmeyr, Somayaji, Longstaff, "A Sense of Self for Unix Processes", IEEE S&P 1996: "normal" = short-range correlations in system-call sequences, stable for standard UNIX programs; tested on sendmail/lpr intrusions — [paper PDF copy](https://www2.cs.uh.edu/~acl/cs6397/Doc/1996-IEEE%20SP-A%20Sense%20of%20Self%20for%20Unix%20Processes.pdf); training on six-call windows stored as a tree (secondary description) — [arXiv 1006.3654](https://arxiv.org/pdf/1006.3654)
- Provos, "Improving Host Security with System Call Policies" (Systrace), USENIX Security 2003: policies over system calls *and arguments*, generated automatically in a training session or interactively during execution — [USENIX](https://www.usenix.org/conference/12th-usenix-security-symposium/improving-host-security-system-call-policies); whitelist of permitted calls and arguments (secondary) — [arXiv 0910.3117](https://arxiv.org/pdf/0910.3117)
- AppArmor `aa-genprof`: puts a profile in complain mode, user exercises the app, `aa-logprof` turns logged violations into rules, iterate, then switch to enforce — [aa-genprof(8) man page](https://manpages.debian.org/man/8/aa-genprof)
- Temporal System Call Specialization (Ghavamnia, Palit, Mishra, Polychronakis), USENIX Security 2020: per-phase syscall sets for servers (e.g., disable execve after initialization) via static call-graph analysis; six server apps — [Georgia Tech repository](https://repository.gatech.edu/entities/publication/aa264af9-1d74-4b16-8edb-4a302350d02d)
- Confine (Stony Brook), RAID 2020: static analysis of containers + dependencies to generate seccomp policies, argues dynamic training workloads miss code needed by future workloads; supports argument-value filtering — [Stony Brook record](https://researchconnect.stonybrook.edu/en/publications/confine-fine-grained-system-call-filtering-for-container-attack-s/)
- sysfilter (DeMarinis, Williams-King, Jin, Fonseca, Kemerlis), RAID 2020: static binary analysis derives per-program syscall sets; 411 binaries / ~38.5K tests, negligible slowdown; profile study of ~30K Debian apps — [USENIX RAID page](https://www.usenix.org/conference/raid2020/presentation/demarinis); [PDF](https://cs.brown.edu/people/vpk/papers/sysfilter.raid20.pdf)
- Chestnut (Canella, Werner, Gruss, Schwarz), CCSW 2021: static compiler/binary phase + optional dynamic refinement; up to 73× faster; blocks ~86.5% of syscalls across 18 apps — [arXiv 2012.02554](https://arxiv.org/pdf/2012.02554)
- AWS IAM Access Analyzer policy generation (launched Apr 2021): generates fine-grained IAM policies from a principal's CloudTrail activity; some services only at service-wildcard level — [AWS Security Blog](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity); [IAM User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started_reduce-permissions-edit-policy.html); actions not used in the analysis window are omitted, so the window must cover rare jobs (third-party) — [oneuptime guide](https://oneuptime.com/blog/post/2026-02-12-generate-iam-policies-access-activity-access-analyzer/markdown)

**2024–2026 agent work closest to trace-derived least privilege**
- TraceAegis (Liu, Ruan, Yang, Lin, Liu, Wang, Wei, Liang; 13 Oct 2025; preprint): provenance-based; builds a hierarchy of stable execution units from agent traces and summarizes them into behavioral rules; flags order or semantic-consistency violations; TraceAegis-Bench: healthcare + procurement, 1,300 benign + 300 abnormal per scenario; detects "the majority" of anomalies; no code link — [arXiv abs](https://arxiv.org/abs/2510.11203). A later paper notes it requires labeled per-scenario templates — [arXiv 2605.11053](https://arxiv.org/pdf/2605.11053)
- SentinelAgent (arXiv:2505.24201): graph-based anomaly detection in multi-agent systems with a graph of allowable interaction paths — [arXiv HTML](https://arxiv.org/html/2505.24201v1)
- AgentArmor: graph built from runtime traces + type checking (TPR 95.75%, FPR 3.66% on AgentDojo) — [arXiv abs](https://arxiv.org/abs/2508.01249v1)
- "Permission Denied: Policy-Graded Evaluation of Coding Agents in Hardened Environments" (Davidovich, Amar, Rozencwajg, Hiltch; 2 Aug 2026; preprint): 12 coding agents on Terminal-Bench 2.1 under **nested** enterprise-style restriction levels (scoped credentials, restricted egress, read-only FS, non-root); strictest level: success −18.3 points, cost +167.3%; blocked agents run to timeout or produce wrong answers; releases Boundary-Bench; no prompt injection — [arXiv abs](https://arxiv.org/abs/2608.02670)
- AuthBench (model-written policies; tight-but-brittle vs broad-but-exposed) — [arXiv abs](https://arxiv.org/abs/2605.14859)
- MiniScope (plan-derived scopes via ILP, not traces) — [arXiv abs](https://arxiv.org/abs/2512.11147)
- "No More, No Less: Least-Privilege Language Models" (arXiv:2601.23157): utility-privilege trade-off for LMs; static policies over-allocate to cover worst case, adaptive escalation lowers average privilege at the cost of extra passes (LM-level, not tool agents) — [arXiv PDF](https://arxiv.org/pdf/2601.23157)

### Inferences
- The project's L0–L5 ladder maps cleanly onto the lineage: L1 declared ≈ Android/AgentBound manifests; L2 needed coarse (tool allowlist) ≈ syscall allowlists (sysfilter/Confine); L3 needed dirs ≈ AppArmor path profiles from aa-genprof; L4 shape / L5 exact ≈ Systrace and Confine argument-level filters and AWS resource-level generated policies. Temporal specialization is the analog of per-phase/per-task tightening (what Progent/DRIFT do with task context).
- The held-out utility drop (to 27–71%) is the agent version of the known "dynamic training misses rare paths" problem explicitly stated by Confine/Chestnut and by AWS's analysis-window caveat; the classic fixes were (1) static over-approximation (Confine, sysfilter), (2) hybrid static + dynamic refinement (Chestnut), (3) interactive learning/escalation (systrace, aa-logprof). The agent analogs would be (1) declared/AgentBound envelope, (2) Needed ∩ task-conditioned (d), (3) Progent-style expansion approval.
- **Novelty assessment:** In this search I found no published paper that (i) learns a cross-task tool+argument envelope from successful benign agent traces, (ii) enforces it at several nested strictness levels, and (iii) plots security vs held-out task success on the same injection traces. Nearest: Permission Denied (nested levels, hand-defined, no injection, no traces), TraceAegis (benign-trace learning, anomaly-detection metrics, no strictness ladder), Conseca (3 static/contextual points, 20 tasks). This is an inference from a non-exhaustive search.

### Gaps
- SELinux `audit2allow` / permissive-mode policy generation: not verified in this pass (known practice, no source fetched).
- Trajectory-guard style sequence models (e.g., arXiv:2601.00516, cited by DriftNet) not read.
- TraceAegis precision/recall numbers: abstract has none; secondary sources disagree (F1 >0.93 vs >0.94), not verified.

## MCP-native defenses (proxy/gateway between client and server) and open-source MCP gateways/firewalls with policy

### Takeaway
MCP-native enforcement points exist and are open source: Invariant Gateway/Guardrails (flow rules), mcp-context-protector (TOFU pinning + response quarantine), Docker MCP Gateway (container per server + tool enable/disable), Lasso, IBM ContextForge, Microsoft MCP Gateway (identity/resource authz), agentgateway; plus research prototypes Progent proxy mode, SAMOS, AgentBound/AgentBox (container), HCP. None of the open-source gateways ships a trace-learned least-privilege profile; the closest built-in is per-tool allow/deny lists.

### Cited Findings
- **Invariant Gateway** (github.com/invariantlabs-ai/invariant-gateway; Apache-2.0): LLM proxy that also proxies MCP over stdio, SSE and Streamable HTTP while applying guardrails configured in Invariant Explorer — [GitHub](https://github.com/invariantlabs-ai/invariant-gateway)
- **Invariant Guardrails** (github.com/invariantlabs-ai/invariant; Apache-2.0): rule language with `->` flow operator over tool calls; runs in Gateway, MCP/LLM proxy, or locally — [GitHub](https://github.com/invariantlabs-ai/invariant); mcp-scan proxy mode applies guardrails from `~/.mcp-scan/guardrails-config.yml`, scoped per client/server/tool, actions block/log — [Invariant docs](https://explorer.invariantlabs.ai/docs/mcp-scan/guardrails)
- **mcp-context-protector** (Trail of Bits; github.com/trailofbits/mcp-context-protector; Apache-2.0): wrapper proxy between host and server; trust-on-first-use pinning of instructions/tool descriptions/schemas (changes block calls until approved); guardrail scanning and quarantine of tool responses; ANSI sanitization — [GitHub](https://github.com/trailofbits/mcp-context-protector)
- **Docker MCP Gateway** (github.com/docker/mcp-gateway; MIT): powers Docker Desktop MCP Toolkit; each server in its own container with minimal host privileges; per-tool enable/disable per profile; secrets via Docker secrets; logging and call tracing — [GitHub](https://github.com/docker/mcp-gateway); one review says its security comes from isolation more than gateway policy, with `--block-secrets` and interceptors — [Maxim AI comparison](https://www.getmaxim.ai/articles/best-open-source-mcp-gateway-for-secure-ai-agent-access-2026/) (vendor blog)
- **Lasso MCP Gateway** (github.com/lasso-security/mcp-gateway): plugin-based; "lasso" plugin covers PII masking, secret masking, custom policy, prompt injection, harmful content — [GitHub](https://github.com/lasso-security/mcp-gateway); possibly stale per a 2026 comparison — [Lunar.dev](https://www.lunar.dev/post/the-best-open-source-mcp-gateways-in-2026) (vendor blog)
- **Microsoft MCP Gateway** (github.com/microsoft/mcp-gateway; MIT): Kubernetes reverse proxy + control plane; Entra ID auth; resource-level (adapter/tool) authorization, no finer per-call policy documented; requires MCP `2026-07-28` clients — [GitHub](https://github.com/microsoft/mcp-gateway)
- **IBM ContextForge** (github.com/IBM/mcp-context-forge; Apache-2.0): registry/proxy for MCP, A2A, REST/gRPC; JWT/OAuth auth, RBAC (Helm), SSRF protection defaults, 40+ plugins — [GitHub](https://github.com/IBM/mcp-context-forge)
- **agentgateway**: MCP guardrails inspect calls/responses; ExtMCP lets an external gRPC policy server allow, mutate or deny individual MCP method calls — [agentgateway docs](https://agentgateway.dev/docs/kubernetes/latest/documentation/mcp/guardrails/about/)
- **mcp-firewall** (github.com/ressl/mcp-firewall): policy enforcement, injection detector, egress controls; prerelease — [GitHub](https://github.com/ressl/mcp-firewall)
- Research MCP-native: Progent proxy mode (redirects MCP endpoints) — [arXiv v3 HTML](https://arxiv.org/html/2504.11703v3); SAMOS (gateway IFC) — [Brown PDF](https://atlas-group.cs.brown.edu/pdf/samos:brown:2026.pdf); AgentBound/AgentBox (container per server, no server change) — [arXiv v3 HTML](https://arxiv.org/html/2510.21236v3); HCP reference runtime — [arXiv abs](https://arxiv.org/abs/2606.29073)
- **MCP-DPT** (Rostamzadeh, Narula, Birhan, Ghasemigol, Takabi; 8 Apr 2026; preprint): layer-aligned taxonomy mapping MCP attacks to six architectural layers with primary/secondary defense points; existing defenses are "uneven and predominantly tool-centric", gaps at host orchestration, transport and supply-chain layers; no empirical evaluation — [arXiv abs](https://arxiv.org/abs/2604.07551)

### Inferences
- For the study, the realistic MCP-native placement of layers (c)/(d)/(e) is a stdio/HTTP proxy in front of each server (mcp-context-protector/Invariant Gateway style); Progent's proxy mode shows (d) works there; Invariant `->` rules show (e) works there; the project's (c) Needed policy would be a new policy source plugged into the same point.
- Open-source gateways mostly offer identity/authn, tool allow/deny, secret masking and classifier guardrails; none advertises argument-level least privilege learned from traces (inference from READMEs fetched).

### Gaps
- Release dates/maintenance status of Invariant repos not visible; reports that Invariant Labs was acquired by Snyk were not verified in this pass.
- No measured ASR/utility numbers were found for any open-source MCP gateway.

## Head-to-head comparisons of several defense layers on the same traces, and combined layers (defense in depth)

### Takeaway
Same-trace comparisons exist inside individual papers (MELON, Progent, LlamaFirewall) and in adaptive benchmarks (AutoDojo), but I found no study that scores a static scanner, server-side checks, a trace-learned least-privilege policy, a task-conditioned policy and a data-flow rule against one set of MCP attack traces. The only measured layer combination found is LlamaFirewall (classifier + alignment auditor: ASR 17.63%→1.75%, utility 47.73%→42.68%).

### Cited Findings
- LlamaFirewall measured combination on AgentDojo: PromptGuard 2 alone 7.53% ASR; AlignmentCheck alone 2.89%; combined 1.75%; utility 47.73% → 42.68% — [arXiv v1 HTML](https://arxiv.org/html/2505.03574v1)
- MELON compares 7 defenses on identical AgentDojo runs for 3 models (table above) — [arXiv v4 HTML](https://arxiv.org/html/2502.05174v4)
- Progent compares against 6 AgentDojo baselines and 3 ASB baselines on the same runs, and against hand-written rules — [arXiv v3 HTML](https://arxiv.org/html/2504.11703v3)
- Conseca compares no policy / static permissive / static restrictive / contextual on the same 20 tasks — [arXiv v3 HTML](https://arxiv.org/html/2501.17070v3)
- AutoDojo: ten defenses (prompt-level, filter-based, system-level) × five models under generated adaptive injections; most defenses either sacrifice considerable utility or are insecure; under-specified tasks are especially vulnerable — [arXiv abs](https://arxiv.org/abs/2606.15057)
- HCP: naive vs mitigation-baseline vs invariant runtime on the same 10 MCP-style cases (10/10, 6/10, 0/10 attacks permitted) — [arXiv abs](https://arxiv.org/abs/2606.29073)
- MCP-SafetyBench (ICLR 2026): real MCP servers, five domains, 20 attack types; evaluates models (not defense layers); all models vulnerable with a safety-utility trade-off — [arXiv PDF](https://arxiv.org/pdf/2512.15163); [ICLR proceedings](https://proceedings.iclr.cc/paper_files/paper/2026/hash/d46f127a80dc58cbc0732a717285c43a-Abstract-Conference.html)
- MCP-DPT says no prior work maps attacks to defense layers or assigns enforcement to stakeholders (taxonomy only) — [arXiv abs](https://arxiv.org/abs/2604.07551)
- A layered-defense figure "73.2% → 8.7%" circulates only in a secondary blog; not verifiable — [intelscroll summary](https://intelscroll.com/perimeter/prompt-injection-defense-state-of-art/) (low-quality source, do not cite as evidence)

### Inferences
- The study's design (same MCP attack traces scored against (a)–(e) plus combinations) appears to fill a gap that MCP-DPT names analytically but nobody has measured; AutoDojo is the closest multi-defense evaluation but is on AgentDojo-style tools, not real MCP servers, and does not include a trace-learned policy.
- LlamaFirewall's numbers suggest combining layers gives diminishing ASR returns with additive utility cost (−5 points); the project should report utility for each combination, not just ASR.

### Gaps
- AutoDojo's defense list and per-defense numbers were not extracted (only abstract read).
- I found no paper measuring a privilege layer combined with a data-flow layer (e.g., Progent + CaMeL-style rule) on the same traces.
