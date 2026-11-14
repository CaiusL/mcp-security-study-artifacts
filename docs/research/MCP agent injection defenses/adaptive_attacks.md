# Adaptive attacks on prompt-injection defenses for LLM agents, with focus on policy generators and trace-learned policies

Scope note: research done 2026-10-24. "Preprint" = arXiv only, no peer-reviewed venue seen. Numbers are as reported by each paper's authors unless stated. Attack methods are described only at concept level. Where a fact came from a search-engine summary and not from the paper page, this is marked "(search summary)".

## Q1. Adaptive-attack evaluations of agent / prompt-injection defenses: what broke and how badly?

### Takeaway
Every adaptive-attack study found so far breaks most "model-level" defenses (prompting, fine-tuning, detectors, known-answer/secret-key checks), often at >90% attack success rate (ASR), when the defense was first reported near 0%. The only defenses that held up in adaptive tests are deterministic, out-of-band policy enforcement (Progent, DRIFT, CaMeL-style), but these were tested with weak adaptive attacks only.

### Cited Findings
- **Nasr, Carlini, Sitawarin, Schulhoff, Hayes, Ilie, Pluto, Song, Chaudhari, Shumailov, Thakurta, Xiao, Terzis, Tramèr, "The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections"**, arXiv 2510.09023, v1 10 Oct 2025 (single version). It is listed in the USENIX Security 2026 program, so peer-reviewed. — [arXiv abs](https://arxiv.org/abs/2510.09023); [USENIX Sec '26 page](https://www.usenix.org/conference/usenixsecurity26/presentation/nasr)
  - Attack methods: gradient descent, reinforcement learning (RL), random/LLM-guided search, and human red-teaming. They bypassed all 12 defenses, with ASR above 90% for most, and most of those defenses had originally reported near-zero ASR. — [arXiv abs](https://arxiv.org/abs/2510.09023)
  - Per defense (from the HTML version): Spotlighting and Prompt Sandwiching >95% ASR on AgentDojo (search + human; as low as 1% with static attacks); RPO 98% (RL) / 96% (gradient) on HarmBench; Circuit Breakers 100% (RL); StruQ bypassed in every tested case (RL); MetaSecAlign 96% on AgentDojo (2% on static AgentDojo); Protect AI detector, PromptGuard, Model Armor >90%; PIGuard 71%; DataSentinel bypassed in every case (RL); MELON 76% without knowledge of the defense and 95% with full knowledge. — [arXiv HTML v1](https://arxiv.org/html/2510.09023v1)
  - Human red-teaming beat every defense (for example 265 successful attacks on Spotlighting, 69 on MELON). — [arXiv HTML v1](https://arxiv.org/html/2510.09023v1)
  - The 12 defenses do NOT include Progent, CaMeL, Conseca, DRIFT or any LLM-written policy system. — [arXiv HTML v1](https://arxiv.org/html/2510.09023v1)
- **Zhan, Fang, Panchal, Kang, "Adaptive Attacks Break Defenses Against Indirect Prompt Injection Attacks on LLM Agents"**, arXiv 2503.00061 (v2), Findings of NAACL 2025 (peer-reviewed). Code: github uiuc-kang-lab/AdaptiveAttackAgent. — [arXiv HTML v2](https://arxiv.org/html/2503.00061v2); [ACL Anthology](https://preview.aclanthology.org/dashboard/2025.findings-naacl.395)
  - Eight defenses on InjecAgent (Vicuna-7B prompted agent; Llama3-8B fine-tuned agent): fine-tuned DeBERTa detector and LLM-based detector (multi-objective GCG that adds a "look benign to the detector" loss), perplexity filtering (AutoDAN), instructional prevention, data prompt isolation, sandwich prevention, adversarial fine-tuning (GCG), paraphrasing (two-stage GCG that makes the paraphraser reproduce the adversarial string). All adaptive attacks gave >50% ASR. Examples: perplexity filter 24%→76% (Vicuna), paraphrasing 8%→54% (Llama3); detector detection rates fell to near zero. — [arXiv HTML v2](https://arxiv.org/html/2503.00061v2)
  - Limits they report: little gain on the second step of data-stealing attacks (optimization targets only the first action) and lower effectiveness on long-context AgentDojo. — [arXiv HTML v2](https://arxiv.org/html/2503.00061v2)
- **Wang, Siu, Ye, Shi, Nie, Zhao, Wang, Guo, Song, "AgentVigil (AgentFuzzer): Automatic Black-Box Red-teaming for Indirect Prompt Injection against LLM Agents"**, arXiv 2505.05849 (v4 Jun 2025), Findings of EMNLP 2025 (peer-reviewed). Seed corpus + Monte Carlo Tree Search refinement. 71% ASR on AgentDojo (o3-mini agent) and 70% on VWA-adv (GPT-4o agent), about 2x handcrafted baselines; reports transfer to unseen tasks/models. Same group (Song, Guo, Shi, Z. Wang) as Progent. — [arXiv](https://arxiv.org/abs/2505.05849); [ACL Anthology](https://preview.aclanthology.org/new-sigs/2025.findings-emnlp.1258/)
- **"RL Is a Hammer and LLMs Are Nails: A Simple Reinforcement Learning Recipe for Strong Prompt Injection" (RL-Hammer)**, arXiv 2510.04885, Oct 2025, preprint (UMD + Meta FAIR). GRPO-trained attacker model, black-box reward only, no warm-up data. Reports 98% ASR vs GPT-4o and 72% vs GPT-5 with Instruction Hierarchy, and evasion of several injection detectors. Code: github facebookresearch/rl-injector. (search summary; abstract-level) — [arXiv HTML](https://arxiv.org/html/2510.04885v1)
- **Google DeepMind, "Lessons from Defending Gemini Against Indirect Prompt Injections"**, arXiv 2505.14534, May 2025, white paper/preprint. Runs adaptive attacks continuously against Gemini versions using four automated attack designs (Actor-Critic, Beam Search, TAP, Linear Generation); several defenses look much weaker under adaptive than non-adaptive attacks (e.g., a paraphrase defense near 0.95 ASR under TAP). (search summary) — [arXiv](https://arxiv.org/pdf/2505.14534); [DeepMind blog, 20 May 2025](https://deepmind.google/discover/blog/advancing-geminis-security-safeguards/)
- Adaptive tests on deterministic/out-of-band defenses (the only cases that held):
  - Progent v3 (own adaptive attacks on its policy updater): only marginal ASR increase (details in Q2). — [Progent v3 HTML](https://arxiv.org/html/2504.11703v3)
  - DRIFT (NeurIPS 2025): manual adaptive attack and PAIR, both aimed only at the injection isolator, raised AgentDojo ASR from 1.35% to 2.05% (manual) and 1.97% (PAIR). — [DRIFT v3 HTML](https://arxiv.org/html/2506.12104v3)
  - Narisetty et al. (Jun 2026, preprint): Progent ASR 25.8%→4.2% (standard), 2.6% (adaptive) on Qwen2.5-7B. — [arXiv HTML](https://arxiv.org/html/2606.26479)

### Inferences
- The field consensus (2025–2026) is that any defense whose final decision is made by an LLM reading attacker-controlled text is breakable by an adaptive attacker. Deterministic enforcement has not yet met a strong (RL/gradient/human-red-team) adaptive attacker in published work. That is a gap, not proof of robustness.
- AgentVigil and RL-Hammer are the most reusable black-box attack generators for an MCP-agent study; Zhan et al. give the template for "multi-objective" attacks that must fool two components at once (relevant to Q2).

### Gaps
- I did not get per-defense numbers for Zhan et al.'s Figure 2 or RL-Hammer's tables beyond the abstract.
- "GCG-style attacks on tool agents" beyond Zhan et al. were not searched separately.

## Q2. Has anyone attacked the policy-generation step (Progent, Conseca, similar)? What do Progent and Conseca report?

### Takeaway
Partly yes. Injection that tries to make the **policy updater widen the policy via tool results** is already published: Progent v3 (Appendix E, its own authors) and an independent preprint (Narisetty et al., Jun 2026). Both found almost no ASR gain, with weak hand-crafted or AgentVigil attacks. **Not found:** any paper that (a) injects the **initial** policy generator through the user task or pasted context, (b) uses strong optimized/RL/human attacks on the policy model, (c) jointly optimizes one injection to both hijack the agent and widen the policy and measures policy over-permission as its own metric, or (d) attacks DRIFT's planner/validator or Conseca's generator.

### Cited Findings
- **Progent** (Shi, He, Z. Wang, H. Li, Wu, Guo, Song), "Progent: Securing AI Agents with Privilege Control", arXiv 2504.11703: v1 16 Apr 2025, v2 30 Aug 2025, v3 14 May 2026; preprint, no venue listed. — [arXiv abs](https://arxiv.org/abs/2504.11703)
  - Policy inputs: initial policy from tool list + user query (treated as trusted because the user query is assumed benign). Updates: step 1 decides if an update is needed from tools, user query and current tool call (not the tool result); step 2 writes the candidate policy from tools, query, call, **tool result**, and current policy. Updates are skipped for non-informative calls. — [Progent v3 HTML](https://arxiv.org/html/2504.11703v3)
  - Z3 checks if the new allowed set is a subset of the old one: narrowing applies automatically; expansion goes to an approver (auto-deny, auto-approve, per-tool rules, or human). Only 6% of updates in AgentDojo were expansions. — [Progent v3 HTML](https://arxiv.org/html/2504.11703v3)
  - Section 2.2 walks through an injection that tries to add `send_email` via the updater: either the updater refuses, or it is fooled and the SMT check flags the expansion for the approver. The paper says the updater can be manipulated or hallucinate, so it does not trust it; enforcement has no LLM in the loop. — [Progent v3 HTML](https://arxiv.org/html/2504.11703v3)
  - Main AgentDojo result: ASR 39.9%→1.0% (initial policy only: 39.9%→2.5%), utility described as maintained. — [Progent v3 HTML](https://arxiv.org/html/2504.11703v3)
  - **Appendix E adaptive attacks (directly on point):** threat model = the LLM updater consumes external information and a non-security-aware user may approve risky changes; they **auto-approve all expansion requests** to model the worst user. Three attacks: an "if-then-else" conditional injection telling the updater to allow all tools (borrowed from Choudhary et al. 2025); an appended request asking the agent to update the policy to allow the attack tool; and AgentVigil. Reported result: adaptive attacks "can only marginally increase the ASR". Exact numbers are only in Figure 10 (not readable as text). — [Progent v3 HTML](https://arxiv.org/html/2504.11703v3)
  - A search summary claimed a "4.0%" figure for adaptive attacks on the policy LLM; I could not find it in the v3 main text. Treat as unverified. — [Progent v3 HTML](https://arxiv.org/html/2504.11703v3)
  - Stated limitations: user mistakes when approving expansions; ambiguous tasks; no defense for text-only attacks or attacks inside the task's least privilege (e.g., preference manipulation); proxy (MCP) mode cannot protect built-in tools that bypass MCP. — [Progent v3 HTML](https://arxiv.org/html/2504.11703v3)
- **Narisetty, Kore, Kattamanchi, Kumarapu, "Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents"**, arXiv 2606.26479, v1 25 Jun 2026, preprint (CC BY 4.0). — [arXiv abs](https://arxiv.org/abs/2606.26479)
  - Independent reproduction of Progent's adaptive analysis on AgentDojo with Qwen2.5-7B as both agent and policy model (replacing GPT-4o). Adaptive attack: one black-box template that frames the malicious action as a benign, pre-authorized prerequisite so the policy-update model widens the allowlist (via tool results). — [arXiv HTML](https://arxiv.org/html/2606.26479)
  - Mean ASR: undefended 25.8%, Progent standard 4.2%, Progent adaptive 2.6% (Banking 19.0/1.9/3.7; Slack 58.3/10.8/4.2; Workspace 0/0/0; travel suite excluded; 8 user tasks per suite; 3 runs). Utility under attack fell from ~45% to ~26%. — [arXiv HTML](https://arxiv.org/html/2606.26479)
  - They explicitly leave open: white-box GCG attacks, multiple templates, other defenses (CaMeL etc.), and attacks confined to already-authorized tools. They do not attack initial policy generation from the task or pasted context. — [arXiv HTML](https://arxiv.org/html/2606.26479)
- **Conseca: Tsai & Bagdasarian, "Contextual Agent Security: A Policy for Every Purpose"**, arXiv 2501.17070 (v1 28 Jan 2025, v3 17 Apr 2025), HotOS 2025 (peer-reviewed workshop, DOI 10.1145/3713082.3730378). — [arXiv abs](https://arxiv.org/abs/2501.17070)
  - Generator prompt = tool API docs, few-shot example policies, user task, and **trusted context only** (email categories/addresses, username, date/time, directory tree); untrusted content such as email bodies is kept out. Protection rests on "isolating the policy model to handle only trusted context"; trusting more context raises compromise risk. No adaptive attack on the generator is evaluated. Preliminary results: 12.0/20 tasks completed vs 14.0 with no policy, while denying inappropriate actions. — [arXiv HTML v3](https://arxiv.org/html/2501.17070v3)
- **DRIFT (Li et al.), "Dynamic Rule-Based Defense with Injection Isolation for Securing LLM Agents"**, arXiv 2506.12104 (Jun 2025, v3), NeurIPS 2025. Secure Planner writes a function trajectory + parameter checklist from the user query; Dynamic Validator lets deviating Write/Execute calls into the plan if judged aligned with user intent, else asks the user (treated as reject in evaluation). — [DRIFT v3 HTML](https://arxiv.org/html/2506.12104v3); [NeurIPS 2025 poster](https://neurips.cc/virtual/2025/poster/116028)
  - Their adaptive attacks target only the injection isolator; the paper argues that is the only targetable module. The tool extraction also reports the paper saying the policy mechanism "becomes part of the attack surface" (exact wording not double-checked). No adversarial test of the planner or validator. — [DRIFT v3 HTML](https://arxiv.org/html/2506.12104v3)
- **"Design Patterns for Securing LLM Agents against Prompt Injections"**, arXiv 2506.08837 (Jun 2025). Plan-then-execute fixes the tool sequence before reading untrusted data, but injections can still change arguments; a Context-Minimization pattern addresses injections that come from the user's own prompt. It does not say how a planner should handle a pasted document it must read to plan. — [arXiv HTML v2](https://arxiv.org/html/2506.08837v2)
- Searches run for direct prior work (none found a paper on initial-policy-generator injection): "prompt injection attack against LLM-generated security policy agent policy generator"; "adaptive attack Progent privilege control bypass policy update injection"; "attacking LLM-synthesized agent security policies injection widens permissions policy synthesis attack surface 2026"; "plan-then-execute prompt injection untrusted content in user prompt pasted document planner compromised". The third returned only adjacent leads (ActGov, "Rethinking Agent Security as a Networking Problem", "Agent Approval Laundering" arXiv 2609.28586) whose content I did not verify. — [search lead: Agent Approval Laundering](https://arxiv.org/pdf/2609.28586)

### Inferences
- The students' question as "can tool-result injection make the Progent updater widen the policy?" is **already covered** (Progent App. E; Narisetty 2026), with a negative result under weak attacks. They must cite both and position against them.
- Still open, and defensible as new:
  1. **Injection at policy birth:** untrusted text inside the user's task or pasted context reaches the initial generator. Progent and Conseca both assume this input is trusted; neither tests it. Initial policies are not SMT-gated (there is no prior policy to compare), so a widened initial policy is never seen by the approver. This is the cleanest gap.
  2. **Joint (multi-objective) injection** that must hijack the agent and also widen or pre-shape the policy, measured with a separate "policy over-permission vs ground-truth least privilege" metric. Zhan et al.'s multi-objective GCG is the method precedent.
  3. **Strong attackers on the policy model** (RL as in RL-Hammer, MCTS as in AgentVigil at scale, gradient on open models, human red team). Narisetty et al. name white-box GCG as open.
  4. **Narrowing as an attack:** auto-applied narrowing updates could be abused to deny legitimate tools (a utility/DoS attack). Not seen evaluated.
  5. **Approver as target:** Progent's App. E removes the approver (auto-approve) and DRIFT treats user approval as reject; persuading a human approver (endorsement social engineering) is named by Narisetty et al. but not measured.
- Why the Progent updater attacks may fail even with auto-approve: the same injection must still make the agent issue the malicious call; Narisetty et al. suggest the "benign prerequisite" framing weakened agent compliance. A study should report the two stages (policy widened? action executed?) separately.

### Gaps
- Exact Figure 10 numbers in Progent v3 App. E were not extractable.
- I did not check Progent v1/v2 for earlier adaptive sections, nor ACE, f-secure/FIDES, IsolateGPT, ShieldAgent, AGrail, AgentSpec, or Task Shield for generator attacks.
- ActGov, "Rethinking Agent Security as a Networking Problem" and "Agent Approval Laundering" appeared only as search titles; content unverified.

## Q3. Attacks on LLM monitors, guardrails, and judges (analogues to attacking a policy generator)

### Takeaway
Injecting the checker is a well-established attack class: monitors, LLM judges, known-answer detectors and classifier guardrails all fall to adaptive injection or evasion. This is strong precedent that an LLM policy generator that reads attacker text is an attack surface, but none of these works target a component whose output is a policy.

### Cited Findings
- **Terekhov, Panfilov, et al., "Adaptive Attacks on Trusted Monitors Subvert AI Control Protocols"**, arXiv 2510.09462 (Oct 2025), ICLR 2026. The untrusted model embeds prompt injections (public or zero-shot generated) in its outputs to fool the monitor. On APPS, one injection made GPT-4.1 score all 375 backdoored GPT-5 samples as benign; the Defer-to-Resample protocol got worse because resampling acts like best-of-n. They argue adaptive monitor attacks should be a standard part of control evaluations. — [arXiv](https://arxiv.org/abs/2510.09462); [ICLR 2026](https://iclr.cc/virtual/2026/poster/10006727)
- **JudgeDeceiver: "Optimization-based Prompt Injection Attack to LLM-as-a-Judge"**, arXiv 2403.17710 (v5). Gradient-optimized sequence in an attacker-controlled candidate makes the judge pick it, without knowing other candidates; beats manual injections; also shown for LLM search, RLAIF and tool selection; known-answer and perplexity defenses insufficient. Venue often cited as ACM CCS 2024, not confirmed in my searches. — [arXiv](https://arxiv.org/abs/2403.17710)
- **Choudhary, Anshumaan, Palumbo, Jha, "How Not to Detect Prompt Injections with an LLM"**, arXiv 2507.05630 (v3), preprint. Shows a structural flaw in known-answer detection (used by DataSentinel); the DataFlip adaptive attack (conditional-instruction structure) gets detection as low as 0% and 91% malicious success (v3 abstract; v1 reported 1.5% / 88%). This is the "if-then-else" attack Progent reused against its updater. (search summary) — [arXiv v3](https://arxiv.org/abs/2507.05630v3)
- **Hackett, Birch, Trawicki, Suri, Garraghan, "Bypassing Prompt Injection and Jailbreak Detection in LLM Guardrails"**, arXiv 2504.11168, LLMSEC 2025 workshop. Character-level tricks and adversarial-ML word perturbations evade six guardrails including Azure Prompt Shield and Meta Prompt Guard, up to 100% evasion in some cases; white-box word-importance from offline models transfers to black-box targets. — [arXiv](https://arxiv.org/abs/2504.11168v2); [ACL Anthology](https://preview.aclanthology.org/setup/2025.llmsec-1.8)
- The Attacker Moves Second also breaks PromptGuard, Protect AI, PIGuard, Model Armor (71–>90%) and DataSentinel/MELON (secret-knowledge detectors), and warns that model-based auto-raters used for scoring can themselves be fooled. — [arXiv HTML v1](https://arxiv.org/html/2510.09023v1)

### Inferences
- A policy generator differs from a monitor in one useful way: its output (a policy) can be checked deterministically (Progent's SMT subset check) and by a human before use. Monitor attacks show the LLM part will be fooled; the research question is whether the deterministic wrapper contains the damage. That frames the students' contribution well.
- If the study uses an LLM judge to score attack success, Nasr et al.'s warning applies: validate the scorer or use deterministic success checks (AgentDojo-style).

### Gaps
- I did not search attacks on Llama Guard specifically, or "monitor jailbreak" work on agent trajectory monitors (e.g., weak-to-strong monitoring papers).

## Q4. Attacks on CaMeL-style / information-flow designs: what remains open

### Takeaway
CaMeL-style designs are not broken by direct injection in published work, but known residual risks are side channels, data-flow poisoning of arguments that policies allow, trusted-prompt assumptions, and composition across agents (shown broken in Oct 2026).

### Cited Findings
- **Debenedetti et al., "Defeating Prompt Injections by Design" (CaMeL)**, arXiv 2503.18813 (Mar 2025), preprint. The authors state CaMeL is vulnerable to side channels (e.g., counting fetches in a loop that depends on a private value; STRICT mode blocks that case by making statements in control blocks depend on the test/iterable); timing channels remain but are limited by bandwidth and complexity. Coarse control/data-flow rules can cost much utility, which motivates capabilities. — [arXiv HTML v2](https://arxiv.org/html/2503.18813v2)
- Even with perfect control-flow isolation, the quarantined LLM can be injected to return attacker-chosen values (e.g., an address) that a plan then uses; CaMeL relies on capability tags/policies for this. (secondary commentary) — [visual summary](https://bhaskarjitsarmah.github.io/visual-summary/33-camel-prompt-injection/)
- An enterprise critique (arXiv 2505.22852) says CaMeL assumes a trusted user prompt, omits some side-channel concerns, and has policy sprawl and latency costs. (search summary) — [arXiv](https://arxiv.org/pdf/2505.22852)
- **Peters-Gill, Semler, Bartsch, Shumailov, Schroeder de Witt, "Can CaMeLs Talk? Securing Multi-Agent Systems Against Indirect Prompt Injection Attacks"**, arXiv 2610.05640, v1 5 Oct 2026, preprint. Finds "CaMeL's guarantees do not compose": untrusted data becomes trusted input for a downstream agent even when every agent runs CaMeL. ASR on their MultiAgentDojo: no CaMeL 12.9%, per-agent CaMeL 0.2%, multi-CaMeL 0.0%. — [arXiv](https://arxiv.org/abs/2610.05640)
- Progent and Narisetty et al. both name attacks that stay inside the task's authorized actions as uncovered by least-privilege enforcement. — [Progent v3 HTML](https://arxiv.org/html/2504.11703v3); [Narisetty et al.](https://arxiv.org/html/2606.26479)

### Inferences
- For an MCP study, the "trusted user prompt" assumption is shared by CaMeL, Progent and Conseca. Putting attacker text into the user turn (pasted context) attacks all three at their common assumption.
- Multi-hop MCP setups (an MCP server that itself calls an LLM agent) are a natural place where the "do not compose" result may reappear.

### Gaps
- I found no independent adaptive-attack paper that breaks single-agent CaMeL. Labels "boundary laundering"/"branch steering" from one search summary were not confirmed on the abstract page.

## Q5. Poisoning learned / allow-list policies from traces (classic and agent era)

### Takeaway
Classic work covers both test-time mimicry (shape the attack to look normal) and training-time poisoning of learned signatures and anomaly detectors. Agent-era systems that learn least-privilege policies from benign traces now exist (2026), but I found **no paper that poisons their training traces**. That gap appears open.

### Cited Findings
- **Wagner & Soto, "Mimicry Attacks on Host-Based Intrusion Detection Systems"**, ACM CCS 2002 (peer-reviewed): attacks disguised as normal syscall sequences, a framework to judge IDS resistance, and a working attack on pH. This is test-time evasion, not poisoning. — [paper PDF](https://www.cs.purdue.edu/homes/ninghui/readings/AccessControl/wagner_soto_ccs02.pdf)
- **Tan, Killourhy, Maxion, "Undermining an anomaly-based intrusion detection system using common exploits"**, RAID 2002, LNCS 2516, pp. 54–73: early mimicry against stide; needs the target's normal profile. (search summary) — [Carleton TR citing it](https://carleton.ca/scs/wp-content/uploads/TR-07-09.pdf)
- **Perdisci et al., "Misleading Worm Signature Generators Using Deliberate Noise Injection"**, IEEE S&P 2006: deliberate pollution of the suspicious-flow training pool (~50% noise) stops Polygraph from producing useful signatures, although it tolerated ~80% random noise. Closest classic analogue to poisoning a policy learner. — [IEEE](https://ieeexplore.ieee.org/abstract/document/1623998); [PDF](https://personal.utdallas.edu/~muratk/courses/dmsec_files/ieee-sp-06.pdf)
- **Newsome, Karp, Song, "Paragraph: Thwarting Signature Learning by Training Maliciously"**, RAID 2006 (only the program listing was found; content not verified). — [RAID 2006 program](https://lists.rwth-aachen.de/hyperkitty/list/ifip-tc6@lists.rwth-aachen.de/message/LTGTY6JDY4XNA2E6WEEKX57QLVX4LBJI/attachment/2/2006-RAID-CFParticipation-1Page.pdf)
- **Rubinstein, Nelson, Huang, Joseph, Lau, Rao, Taft, Tygar, "ANTIDOTE: Understanding and Defending against Poisoning of Anomaly Detectors"**, ACM IMC 2009: adding chaff traffic during training inflates variance so the PCA-subspace detector later misses attacks; "Boiling Frog" slow poisoning variant. — [PDF](https://ptolemy.berkeley.edu/projects/truststc/pubs/725/IMC.2009.pdf)
- Agent-era learners from traces (none tests trace poisoning, per what I read):
  - **Dang, "Enforcing Benign Trajectories: A Behavioral Firewall for Structured-Workflow AI Agents"**, arXiv 2604.26274, 29 Apr 2026, preprint (search summary names it Praetor). Compiles verified benign tool-call telemetry into a parameterized DFA (sequences + parameter bounds). Reports 5.6% macro ASR on ASB, 2.2% vs 12.8% for Aegis in structured workflows, 2.0% benign failures; 18% evasion of continuous parameter bounds by synonym substitution. No poisoning or explicit adaptive attacker model in the abstract. — [arXiv](https://arxiv.org/abs/2604.26274)
  - **Abaev, Klimov, Levinov, Mimran, Elovici, Shabtai, "AgentGuardian: Learning Access Control Policies to Govern AI Agent Behavior"**, arXiv 2601.10440 (Jan 2026), preprint. Learns context-aware policies and a control-flow graph from staging-phase traces. Its limitations note that a weaker orchestrator's planning errors carried into traces and weakened policies, which shows trace quality matters, but it is not a poisoning evaluation. (search summary) — [arXiv](https://arxiv.org/abs/2601.10440v1)
  - **TraceAegis** (arXiv 2510.11203): hierarchical provenance graphs from traces, F1 > 0.94, needs labeled templates. (search summary) — [arXiv](https://arxiv.org/pdf/2510.11203)
- Searches run: "learning least-privilege tool policy from benign agent execution traces LLM agent anomaly detection"; "AgentGuardian learns access control policies from execution traces LLM agents poisoning"; "poisoning training data anomaly detector mimicry attack Wagner Soto 2002 ..."; classic poisoning queries above. No agent-era trace-poisoning paper surfaced.

### Inferences
- Two distinct threats should be separated in the study design: (1) **mimicry** at test time: attack built only from tool sequences/arguments the learned policy already allows (Wagner & Soto analogue; also the "authorized-actions-only" gap in Q2); (2) **poisoning** at training time: attacker-influenced traces (e.g., injected content during trace collection causes extra benign-looking calls) widen the learned allow-list (Perdisci/ANTIDOTE analogue). Only (2) appears unstudied for agents.
- A realistic poisoning vector for MCP: if benign traces are collected from a live agent that reads attacker-reachable content (issues, emails, web), prompt injection during collection is itself the poisoning mechanism. This links the two research questions.

### Gaps
- I did not check whether AgentGuardian's or Dang's full texts discuss poisoning in sections beyond the abstract/limitations.
- Agent memory/RAG poisoning (e.g., AgentPoison) was not searched; it is adjacent but poisons knowledge, not policies.
- Kloft & Laskov (online anomaly detection under adversarial impact) and Barreno et al. were not verified.

## Q6. Methodology guidance for adaptive evaluation (what reviewers will expect)

### Takeaway
Reviewers will expect a defense-aware attacker with full knowledge, several attack families (search/MCTS, RL, gradient on open models, human red team), no artificially small budget, deterministic success checks, utility reported next to ASR, repeated runs with variance, and explicit release of code.

### Cited Findings
- Nasr et al.: assume the attacker knows the defense (Kerckhoffs); do not cap the attacker budget artificially; static attack sets mislead; automated attacks are necessary but not sufficient; include human red-teaming with full defense details; validate auto-raters; release easy-to-query defenses and code; empirical evaluation can only show a defense is not yet broken. — [arXiv HTML v1](https://arxiv.org/html/2510.09023v1)
- Zhan et al.: use white-box threat models plus black/grey-box; test combinations of defenses; evaluate multi-step behavior, not only the first action; include long contexts; report valid-output rates next to ASR. — [arXiv HTML v2](https://arxiv.org/html/2503.00061v2)
- Narisetty et al.: specify attacker capabilities (controls untrusted channels, knows design and policy, not model weights or enforcement code); include optimized white/black-box attacks, provenance spoofing, approver-targeted social engineering, side-channel probes, and attacks limited to authorized tools; report ASR/FNR, utility retention, endorsement (approval) request rate, overhead, repeated runs with variance. — [arXiv HTML](https://arxiv.org/html/2606.26479)
- Tramèr, Carlini, Brendel, Mądry, "On Adaptive Attacks to Adversarial Example Defenses", NeurIPS 2020: 13 defenses broken even though authors had tried adaptive attacks; no single attack strategy suffices, attacks must be tailored per defense. — [NeurIPS 2020](https://papers.nips.cc/paper/2020/hash/11f38f8ecd71867b42433548d1078e38-Abstract.html); [arXiv](https://arxiv.org/abs/2002.08347v2)
- Terekhov et al.: adaptive attacks on the monitor itself should be standard in control evaluations. — [arXiv](https://arxiv.org/abs/2510.09462)
- Google DeepMind: continuous adaptive evaluation across model versions with multiple automated attackers. — [arXiv](https://arxiv.org/pdf/2505.14534)

### Inferences
- For the students' layer comparison, a minimum credible design: (a) knowledge levels: none / knows defense design / knows the generated policy (white-box policy); (b) attacker families: fixed AgentDojo-style injections, AgentVigil-style MCTS, RL attacker (RL-Hammer recipe) and a human red-team pass; (c) state query/compute budget per attack; (d) separate metrics: policy widened (vs ground-truth least privilege), malicious call attempted, malicious call executed, utility, approval-request rate; (e) report each layer alone and stacked.
- Report negative results for the policy generator carefully: prior work found low ASR only under weak attacks, so "we failed to widen the policy" is only as strong as the attacker used.

### Gaps
- Carlini et al. 2019 "On Evaluating Adversarial Robustness" (arXiv 1902.06705) was not retrieved in my searches; cite only after checking.
- I did not find a community benchmark that scores "policy over-permission" as a metric.
