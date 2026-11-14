# Related work

## Additional full-text extraction, 2026-11-03

**Ghasemi, Identity and Access Management for Autonomous Agentic Systems** (KTH, 2026): the [primary record](https://kth.diva-portal.org/smash/record.jsf?pid=diva2:2110257), resolved from its national URN, returned an Anubis rejection page on 2026-11-03. The abstract remains a candidate for inclusion; the body was not read and no properties are scored.

**Pincer**, Rathee et al., [arXiv:2610.02569v1](https://arxiv.org/html/2610.02569v1), read by Codex. Section 5.2 learns resource policies from tool-call access patterns; section 6 evaluates synthetic user histories. Section 7.2 compares fixed defenses, rather than tightening one envelope, and measures benign resource grants rather than completed tasks. Its memory-poisoning cases attack the judge's persistent authorization state (sections 6 and 7.2). It therefore informs both trace-derived authorization and policy-input poisoning. It does not attribute one trace across a scanner, server patch and learned policy. These distinctions constrain the contribution wording; the systematic review remains incomplete.

Targeted read on 2026-10-19 of the four papers named in the project brief, plus the public CVE records those papers and vendor advisories cite. A citation pass on 2026-10-20 corrected the Progent and AgentBound lines against the current papers, split the git advisory bounds, and added four other systems from their abstracts. On 2026-10-25 the three papers named in `docs/injection-protocol.md` (ROPE, AgentArmor, and "Agent Approval Laundering") were read in full; that note is in the protocol and is not repeated here. The same day, the four systems below and Khan, AlKhanbashi, and Mohamed, Computers 15(9):570, were read in full. This file is not a finished systematic review. A priority claim is not made.

## MCP-FSD

Huang, Tang, Guan, Sun, and He, “My Credentials, Please: Detecting Filesystem Capability Laundering in MCP Servers at Scale,” arXiv:2610.22301, 15 October 2026.

MCP-FSD measures a gap between a tool’s declared contract and the filesystem effects a steered caller can obtain. Across 21,097 servers from nine registries, 787 of 4,806 triaged servers (16.4%) showed filesystem capability without a filesystem category. Dynamic checks confirmed 150 vulnerable instances. Coordinated disclosure produced 13 advisories, including CVEs in Anthropic’s Git MCP server. The paper cites the filesystem prefix bug CVE-2025-53110 and describes `git_add` reaching files outside the repository (CVE-2026-27735). Least privilege in that work is inferred from the tool contract, static analysis, and a sandbox policy. The HTML read on 2026-10-25 confirms the three-case protocol: an unsandboxed call discloses a planted marker, the sandboxed in-scope call succeeds, and the sandboxed out-of-scope call does not disclose it. Of the 150 instances, 136 match that marker exactly. The paper says it does not measure the accuracy of the inferred boundaries. Containment is evaluated as sandbox on versus sandbox off.

This project uses that gap as the boundary slice of Reachable. It adds the Needed slice: effects the server can produce, including effects inside the declared root, that benign tasks do not exercise. The output is a strictness curve against task success, which MCP-FSD does not report.

## ToFu

Ananto, Prevost-Avenel, Smith, K. Kim, T. Kim, and Khan, “ToFu: Exploiting and Fuzzing the LLM-Orchestrator-Tool Trust Boundary,” arXiv:2610.13651, 9 October 2026.

ToFu derives semantic checks from tool metadata and a CWE sanitizer corpus, then fuzzes tools. The abstract reports 273 MCP servers, 3,405 tools, and verified bugs in 343 tools across 118 servers. The arXiv comments count 253 verified semantic security bugs in those 118 servers. The finding used here is that a schema-valid call can still be unsafe.

This project treats that fact as the reason Declared schema and Reachable differ. ToFu does not estimate which of those reachable behaviors a benign workload needs, and it does not price a defense in lost task success.

## AgentBound

Bühler, Biagiola, Di Grazia, and Salvaneschi, “AgentBound: Securing Execution Boundaries of AI Agents,” arXiv:2510.21236, first submitted 24 October 2025.

AgentBound is a declarative permission system for MCP servers. The policy mechanism is inspired by the Android permission model, and enforcement does not require modifying the server. The paper uses a dataset of the 296 most popular MCP servers. The abstract says policies generated from source have 80.9% accuracy. In the evaluation, 96 generated manifests were submitted and 74% received no response. The body then reports the generated manifests as 80.9% accurate and precise, with 100% recall. The text does not show how that percentage is calculated. A separate check against human-written manifests matched 787 of 816 capabilities (96.5%) across 48 servers. Enforcement overhead is reported as negligible. The manifest answers what the code is able to use.

A Needed envelope answers a different question: what benign tasks did use. A server can be faithful to a manifest and still expose argument values no task requires. The PoC’s in-scope excess probes are that remainder. An experimental manifest implementation inspired by the paper is at https://github.com/dortort/agent-bound. It is not an official artifact of the paper.

## Progent

Shi, He, Wang, Li, Wu, Guo, and Song, “Progent: Securing AI Agents with Privilege Control,” arXiv:2504.11703, first submitted 16 April 2025, revised 14 May 2026 (v3).

Progent is a policy language over tool names and arguments. The 14 May 2026 text describes a library mode and a proxy mode. Policies can be written by hand or proposed by a model from the user task. An update is applied automatically when it only narrows the policy, and it requires approval when it expands the policy. That revision reports attack-success reductions on AgentDojo (39.9% to 1.0%) and ASB (70.3% to 3.9%) with utility retained on those benchmarks.

Progent’s policy is per task and is proposed from the task text, then updated online. This project’s policy is one cross-task envelope estimated from logged calls of many successful runs, then frozen into a strictness ladder. The two can be combined later: Progent’s proxy is a plausible enforcement point for a Needed profile. They are not the same measurement.

## Public bug classes used as Reachable seeds

Recorded in `data/reachable_cases.json` at class level only.

- CVE-2025-53109 and CVE-2025-53110, filesystem server. The ranges in `data/reachable_cases.json` are the GitHub advisory ranges: `<=0.6.2` and `>=2025.1.14, <2025.7.1`, patched at 2025.7.1. Symlink escape and string-prefix containment. The PoC’s vulnerable filesystem mode is this class, inside the sandbox. The CVE record for CVE-2025-53110 says versions prior to 0.6.4 or 2025.7.01. That record and the advisory do not match.
- CVE-2025-68143, `mcp-server-git` before 2025.9.25 (GHSA-5cgr-j3jf-jw3v, patched 2025.9.25). Unrestricted `git_init`. Not reproduced in the proof. It is on the full-study list.
- CVE-2025-68144 and CVE-2025-68145. GitHub advisories GHSA-9xwc-hfwc-8w59 and GHSA-j22h-9j4x-23w5 list affected versions before 2025.12.18, patched in 2025.12.18. The classes are argument injection in `git_diff` and `git_checkout`, and a `repo_path` that is not limited to the configured repository. The CVE records say versions prior to 2025.12.17. Not reproduced in the proof. They are on the full-study list.
- CVE-2026-27735, `git_add` of a path outside the repository. GHSA-vjqx-cfc4-9h6v lists affected versions before 2026.1.14, patched in 2026.1.14. Cited by MCP-FSD. Not reproduced here.

## Full texts read on 2026-10-25

Read from the arXiv HTML or the journal HTML. The question for this pass was whether the text reports a Needed envelope taken from benign execution traces and scored as attack block against held-out task success, or a same-trace attribution of a scanner, a server check, and that ladder. None of the five does. The GitHub READMEs for Cisco MCP Scanner (`cisco-ai-defense/mcp-scanner`) and Snyk Agent Scan (`snyk/agent-scan`, formerly mcp-scan) were read on 2026-10-25. Neither tool was started. Cisco’s README describes YARA rules, an LLM analyzer, and the Cisco AI Defense inspect API. Snyk’s README describes a local scan of installed agent components for prompt injection and related threats. Neither page reports a Needed envelope or an attack-block curve. The old Snyk article URL returned HTTP 404.

### MCPSafetyScanner

Radosevich and Halloran, “MCP Safety Audit: LLMs with the Model Context Protocol Allow Major Security Exploits,” arXiv:2504.03767, submitted 2 April 2025, revised 11 April 2025.

The paper shows Claude 3.7 and Llama-3.3-70B being steered into malicious code execution, remote access, and credential theft through tools on ordinary MCP servers. MCPSafetyScanner takes a client configuration, has an agent propose attacks from the server’s tools, resources, and prompts, searches the web, arXiv, and Hacker News for related cases, and writes a remediation report. The paper calls that scanner the first agentic auditor of an arbitrary MCP server. The demonstrated attacks are host and tool effects. The report is a finding list for one configuration. It does not derive a policy from benign traces or score held-out task success.

### MCP-SEC

Zhao, Hou, Zhan, Wang, Xie, Guo, Chen, Li, and Xue, “Parasites in the Toolchain: A Large-Scale Analysis of Attacks on the MCP Ecosystem,” arXiv:2509.06572, submitted 8 September 2025, revised 1 May 2026.

The measurement is a census: 1,360 servers and 12,230 tools from Pulse MCP, MCP Market, and Awesome MCP Servers. An LLM labels each tool from its description, three reviewers resolve disagreements by majority vote, and a dynamic check asks a host to invoke the tool with canary-style inputs where that is possible. After that check, 1,062 tools (8.7%) and 370 servers (27.2%) are counted as exploitable for the attack the paper studies. The attack writeup is a pipeline from untrusted tool text to a network sink. The paper’s stated gap is missing isolation between context and tools, and missing least privilege. Least privilege here is a property the census finds absent. It is not a ladder fitted to benign calls.

### MCP-Guard

Xing, Qi, Qin, Li, Chang, Yu, Lin, Xie, and Han, “MCP-Guard: A Multi-Stage Defense-in-Depth Framework for Securing Model Context Protocol in Agentic AI,” arXiv:2508.10991, submitted 14 August 2025, revised 8 January 2026.

MCP-Guard is a proxy with three stages on the payload: a regex sieve, a fine-tuned E5 detector the paper reports at 96.01% accuracy, and an LLM arbitrator for probabilities between 0.45 and 0.55. The evaluation set is MCP-AttackBench, 70,448 labeled payloads. Stage I is reported at 38.9% recall. The paper reports 89.1% F1 for the pipeline against a standalone LLM check, and Table 4 reports a peak F1 of 95.4%. The stages classify text. They do not replay one agent trace through a server patch and a trace-derived policy.

### FlowGuard

An, Chen, Hong, Chen, and Wu, “FlowGuard: From Signals to Evidence for MCP Security Detection,” arXiv:2607.14754, submitted 16 July 2026.

FlowGuard scans MCP servers. It triages parameters, sends schema-valid probes, and keeps a finding only when the response is evidence of execution or of risky content. On 1,880 benchmark cases the paper reports F1 of 0.879 for command injection and 0.942 for file-system access, and 523 findings on 326 live servers. “Attribution” in that paper means tying a response back to the probe that produced it. The probes are attempts to reach a bug. They are not the calls of a benign task suite, and the score is detector F1, not held-out task success.

### Computers 15(9):570

Khan, AlKhanbashi, and Mohamed, “Evaluating Indirect Prompt Injection Defenses in Tool-Using LLM Agents: Security, Utility, and Replication,” Computers 2026, 15(9), 570, https://doi.org/10.3390/computers15090570, published 30 August 2026. Read from the journal HTML.

The study is AgentDojo’s banking suite: 16 user tasks and 9 injections, 144 attack cases per run, two runs, plus 16 benign tasks per run. Models are GPT-5.4, GPT-5.4-mini, and Claude Sonnet 4.6. Defenses are spotlighting, a prompt-injection detector, repeat-user-prompt, and a tool filter. The tool filter is run only for the OpenAI models. Each defense is a separate live configuration. Raw undefended attack success is 0/288, 11/288, and 1/288 for those three models. For GPT-5.4, utility under attack is 55.9% undefended and 39.6% with the tool filter; benign utility is 18/32 (56.2%) undefended and 53.1% with the tool filter. The tool filter’s zero-tool-call rate on GPT-5.4 attack traces is 56.9%. Median durations in that table are a few seconds per instance. The pair 6.17 s versus 62.56 s is not in this paper. Table 5’s trace basis records which runs still had per-instance traces for a feasibility-conditioned rate. Exact McNemar tests on GPT-5.4-mini run 2, 144 matched pairs, do not stay significant after Holm correction. The paper is not an MCP server study, and it does not rescore one trace under a second defense.

## Literature search on 2026-10-25

Source: the arXiv API, query `all:"Model Context Protocol"`, sorted by submitted date. The API reported 611 results, and all 611 titles and abstracts were retrieved. A keyword screen (privilege, policy, utility, attack success, defense, trace, held-out, least privilege, needed, benign, strictness, attribution) kept 189. Sixteen of those were read at abstract level because the title was about privilege, a lattice, traces, invariants, or a survey. This search does not cover papers that never use the phrase “Model Context Protocol,” and it does not cover other publishers. The Cisco and Snyk scanner READMEs noted above are product pages, not papers in this search.

The inclusion question was the same as the full-text pass: a cross-task envelope estimated from benign execution traces and scored as attack block against held-out task success as the envelope gets stricter, or a same-trace attribution of a scanner, a server check, and that ladder. No abstract in the shortlist reports either.

The closest paper is arXiv:2608.18351, “Task-Conditioned Least-Privilege Learning for Executable Terminal and MCP Agents,” submitted 18 August 2026. Its HTML was checked through the envelope definition, the task split, the limitations, and the conclusion. Each task is given a reviewed, predefined sufficient-authority envelope. Post-training penalizes trajectories that exceed that envelope. On 500 held-out tasks the selected seed reaches 98.48% safe success, against 64.36% for the base policy, and excess-authority events fall from 4.56% to 0.79%. The envelope is an authoring input. The reported score is safe success of a fine-tuned model. The paper does not plot attack block against held-out task success for a frozen ladder.

OpenAlex, queried the same day, reports 6,156 works for the phrase “Model Context Protocol.” A page-by-page abstract screen of that list stopped at 4,600 works when the unauthenticated daily budget returned HTTP 429. Those 4,600 abstracts were matched against privilege, utility, held-out, trace, and envelope terms; 236 matched. The remaining 1,556 OpenAlex works were not retrieved. Two of the matched abstracts were then read past the abstract. Piotrovskyi, “Controlling PII Disclosure in Database MCP Connectors,” American Impact Review, 10 August 2026, DOI 10.66308/air.e2026067, was read from the journal PDF. It stacks six hand-built controls on one synthetic SQLite connector that speaks JSON-RPC: a raw passthrough, engine read-only, a single-statement guard, an output-name allow-list, AST source-column lineage, and egress redaction. Table 1 reports attacker success on a 17-query suite and benign over-exposure: 0.941 and 0.880 at the raw rung, 0.471 and 0.000 at the name allow-list, and 0.000 and 0.000 once lineage is added. Utility is exact rowset equivalence, 1.00 on the six aggregate and join tasks. The held-out figure in that paper is a PII detector’s test-split F1 of 0.986, with adversarial recall 0.20. The paper says it does not run the current MCP SDK, a real MCP server, or a real model. The rungs are authored controls. They are not an envelope estimated from benign task traces. mcp-defense-bench was read from three sources that do not agree on a version. The figshare preprint (DOI 10.6084/m9.figshare.32978657.v4, version 0.4, July 2026) was read from the PDF. It scores weighted coverage of content-scanning proxies on a 24-vector crosswalk and 35 static fixtures. Table 3 gives mcp-bastion 63% (15.0 of 24; 11 enforce, 8 detect, 5 none), mcp-firewall 13% (3.0 of 24), pipelock 10% (2.5 of 24), and a null baseline 0, each with 0 of 35 benign controls flagged. Across the three tools, 19 of 24 vectors are covered by at least one and 5 by none. Table 6 records the reference proxy moving from 9% to 63% as checks were added. The paper’s “none, to our knowledge” sentence is about measuring defensive-proxy coverage. The Zenodo concept 10.5281/zenodo.21346206 (record 10.5281/zenodo.23417625, 2026-10-16) says version 0.8.0 and 32 vectors; the zip was not opened. The GitHub README on main describes v0.9.0 and 37 vectors and a CorpusRobustCoverage table: mcp-bastion v1.2.0 at 57% on 24 development vectors and 44% on 24 held-out vectors, with 14 of 337 benign items flagged (4.2%, Wilson interval 2.5–6.9%). Those later figures were read from the README, not from the v0.4 PDF. Neither source estimates an envelope from benign task traces or plots attack block against held-out task success as that envelope gets stricter. theriac (concept DOI 10.5281/zenodo.21990776, record 21990777, 2026-08-18) was read from the three-page PDF on 2026-10-25. It is a static structural scanner for poisoned tool, prompt, and resource metadata. On a content-hash split of the public MCPTox descriptions, holdout recall moves from 8.1% to 65.3% to 87.3% across three rule-development iterations. The abstract states that split as 45 servers and 353 tools; the body states 485 released descriptions from 45 live servers, of the 1,312 cases the MCPTox paper reports. False positives above the default gate are zero on eight published servers, 130 components (118 tools, 4 prompts, 8 resources); seven findings are all low severity. Before normalization, character-level mutation leaves 50 of 119 already-detected cases (42%); after normalization every mutation class is detected by the same rule. Critical-tier holdout recall is 6.8–7.6%, and the paper treats the high-severity gate as the operative number. The author writes that, to their knowledge, theriac is the first scanner in this space to publish both a false-positive rate on unmodified real servers and a character-level evasion result. That sentence is their claim about scanner evaluation. The paper does not estimate an envelope from benign task traces, and it does not plot attack block against held-out task success. Three titles from a narrower query were also opened at abstract level. “Engineering Least-Privilege Agentic AI Workflows” (DOI 10.15439/2026f6361) is a catalog of engineering patterns. The Zenodo concept 10.5281/zenodo.20779116 resolves to record 20779117, “A deterministic safety interceptor for tool-using LLM agents in the Model Context Protocol (code and data),” dated 2026-06-21. The deposit is restricted: its file list is empty. An arXiv title search and an author search for Cardoso with the phrase “Model Context Protocol” both returned no hits. The paper body was not read. The deposit description says the release contains a static client-side policy, a 115-prompt adversarial corpus, a 40-task benign workload, and scripts that reproduce attack-success, false-positive, and latency figures. Those figures were not read. An SSRN preprint (10.2139/ssrn.6891368) returned no abstract. The unread remainder means this search still does not finish the review.

MCP-DPT (arXiv:2604.07551) was read from the arXiv HTML the same day. It is a defense-placement taxonomy: 49 attacks and 13 mechanisms, mapped to six architectural layers. Coverage is capability-based. A mechanism covers an attack when the authors judge that it can reasonably detect, block, or constrain that class. The paper says this is not empirical detection accuracy. Table 4 records that judgment as a percentage of attacks in each layer. ToolHive is marked at 100% on the registry layer and 50% on server execution. MCIP-Guardian and MCP-Guard are marked at 44% on model alignment. Host coverage peaks at 38% (MCP-Gateway). Transport is 0% for every listed tool except MCP-Gateway at 50%, MCP-Guard at 25%, and AIM-MCP at 25%. The paper’s “to the best of our knowledge” sentence is about a unified defense overview. The percentages are not measured attack block, and they are not held-out task success on a trace-derived envelope.

Three more OpenAlex matches were read from the arXiv HTML the same day. The Custody Envelope Threshold (arXiv:2606.06767) is an institutional-admission model. An artifact is admissible when object identity, ingress, and revocation are closed relative to the authority it receives. MCP servers are a held-out artifact class, dated 1 June 2026: the paper cites registries, catalogs, and gateways as the governance surfaces the model predicts. That held-out slice is not an attack rate and not a task-success curve. MiniScope (arXiv:2512.11147) builds a task-level role hierarchy from OAuth scopes or from historical tool traces and enforces the roles selected for the current plan. On a Workspace benchmark adapted from AgentDojo and AgentDyn, 40 tasks and 13 injection goals, Gemini 2.5 Flash under MiniScope reaches 93.1% utility on the 28 tasks that reach the injection and 0.8% attack success. Privilege-escalation attack success in that evaluation is 0%. Simulated confirmations fall by 43.4%–89.4% for the cautious and typical personas. Those figures are one authorization policy. The paper does not vary a frozen benign envelope and plot the curve, and within-permission misuse is outside its boundary. SkillScope (arXiv:2605.05868) checks Agent Skills for actions outside the current user task. On 200 annotated skills it reports 94.53% skill-level F1. Of 68,312 valid marketplace skills, 6,590 are validated as over-privileged. Privilege constraining cuts triggered action-in-task instances from 472 to 54 (88.56%) and keeps all 249 legitimate tasks complete, with output equivalence on 236 of 249 and core-trace equivalence on 232 of 249. Direct removal completes 144 of 249. MCP filesystem and git servers appear as fixture tools in its task builder. The result is one constraining point on skills, not a Needed ladder scored against a scanner and a server check.

PACE (arXiv:2610.01349) was read from the arXiv HTML. It mediates each tool call before execution. Path confinement cuts represented influence paths, and capability and effect verification checks schema-defined effects against authority compiled from the authenticated request, trusted argument constraints, organizational policy, and tool schemas. The compiler reads no injected artifact. On eight benchmarks, the prose result is lower attack success with at most a 2.92-point drop in full-benchmark native utility against the undefended agent. MCPTox refusal differs by at most 1.81 points. On AgentDojo, PACE’s worst-group attack success is lower, and its utility higher, than CaMeL, MELON, and Progent on all three models. Among 79 eligible per-group attack-success columns, PACE is strictly lowest in 62, tied in 14, and higher in three. A reduced adaptive search on 30 out-of-authority AgentDojo pairs is 21/30 undefended and 0/30 for PACE, Wilson interval [0, 11.4%]. The Qwen ablation is a 2×2×2 of path confinement, effect verification, and boundary adaptation on 1,167 cases. On that subset, AgentDyn utility falls from 66.7% (A0) to 33.3% (A7), and the paper says the full combination has no demonstrated unique security benefit. The paper specifies exact McNemar tests with Holm correction and then makes no significance claim from the displayed point estimates. The authority is compiled from the request and the schemas. It is not an envelope estimated from benign execution traces and tightened, and the three components are not that ladder.

IntentCap (arXiv:2609.14631) was read from the arXiv HTML. It composes a short-lived lease from user intent, workflow instructions, tool schemas, and the runtime environment, and a deterministic checker accepts the lease only when it narrows the user’s authority. An MCP gateway is one enforcement point. Replaying 3,746 security-sensitive events from AgentDojo, MCPTox, InjecAgent, and tau2-bench produces 0 unsafe accepts. The tau2-style proxy covers all 3,813 benign reference actions and passes 2,554 of 2,556 ground-truth checks. The paper lists end-to-end attack success as future work. The lease is one checker, not a strictness curve.

FactGate (arXiv:2607.00751) was read from the arXiv HTML. It turns one approved reporting task into three cumulative set budgets and settles novelty on one PostgreSQL snapshot. The closed fragment admits 22 of 40 held-out LLM-written statements (55%). A frozen corpus of seven scripted decompositions is charged once per complete query. The “applicability envelope” in that paper is a publication-size bound. MCP appears as a specification citation. The budgets are an approved release contract, not a trace-derived Needed ladder.

MCPShield (arXiv:2602.14281) was read from the arXiv HTML. It is an agent-side layer with three stages: metadata-guided mock probes, an isolated projection that grants a file and network scope, and periodic reasoning over historical traces against a benign baseline. On 76 malicious servers and six models, the prose average defense rate, defined as one minus attack success, is 10.05% undefended and 95.30% with MCPShield. Table 2’s average rate of benign servers flagged as malicious runs from 2.35% (GPT-4o-mini) to 29.41% (Qwen3-235B). Probing token use is about 10× to 100× a server’s baseline. The result is one stack. It is not a strictness curve, and it does not attribute one trace to a scanner, a server check, and a Needed ladder.

Counterfactual tool ranking (arXiv:2609.22819) has no HTML version. The abstract was read. It compares direct regression and doubly robust selectors on eleven tools, with real local MCP transport. On function-name-disjoint BFCL splits the balanced accuracies are 81.85% and 79.83%. Two local Qwen2.5 models are scored on the same 200 held-out tasks. The abstract says the contribution is an evaluation method, not a production-agent safety claim. The body was not read.

capmas (arXiv:2609.06500) was read from the arXiv HTML. It maps a natural-language query to at most \(k\) privileges with a contrastive retriever, then attenuates Macaroon tokens as agents delegate. An MCP proxy translates calls for services that do not speak Macaroons. ASTRA pairs tasks with MCP endpoints. Table 3, on ASTRA with elbow threshold 0.2, reports perfect-bundle capture of 67.7% at \(k=3\), 90.9% at \(k=10\), and 96.9% at \(k=60\). Relative over-privilege on that table is 40.2%, 75.6%, and 95.4% at those three ceilings, and absolute over-privilege is 0.09%, 0.47%, and 3.32%. Perfect-bundle capture means the retrieved set contains the labeled privilege bundle. The curve is retrieval recall against extra privileges. It is not attack block against held-out task success, and the privileges are not estimated from benign execution traces.

ProvenanceGuard (arXiv:2606.18037) was read from the arXiv HTML. It checks whether a claim in an MCP-agent answer is supported by the source the answer names. On a 40-trace, 361-claim held-out split of a 281-trace medical corpus, reject/block F1 is 0.802 (trace-bootstrap interval [0.664, 0.900]) and source accuracy is 0.858 on 260 source-eligible claims. The held-out split is a claim partition. The verifier does not score a privilege envelope against task success.

MCP-Secure (DOI 10.1109/ojcs.2026.3664314, IEEE Open Journal of the Computer Society, volume 7, pages 504–513) was read from the PDF on 2026-10-25. It is a host-side wrapper with four authored levels: L0 leaves declared tools readable and writable, L1 binds the task’s server and tool scope, L2 turns mutating calls into no-ops, and L3 adds a deterministic approval gate. The grid is 1,080 runs: two MCP-Universe repository tasks, three models (GPT-5, Claude Sonnet 4, Grok-4), three attack classes, four levels, and 15 repeats. Temperature and seed are the provider defaults. Table 1’s prose says L0 averages 2.89 unsafe calls per run and intercepts none, L1 prevents 75.3% of unsafe calls, L2 blocks 100%, and L3 blocks 97.5%. Unsafe attempts fall from 2.89 at L0 to 1.80 at L2. Utility is progress before the first block on the same runs. The write-heavy task moves from 0.43 at L0 to 0.19 at L1 and 0.00 at L2 and L3. The mixed task moves from 0.43 at L0 to 0.49 at L1, 0.19 at L2, and 0.23 at L3. Median latency is 0.4–0.5 ms per run. The levels are authored scopes. They are not an envelope estimated from benign execution traces, and the utility figure is progress on the attacked runs, not held-out task success held apart from the attack rate.

Agentao (arXiv:2608.13574) was read from the arXiv HTML. It is a design for a host-side permission harness. MCP tools are routed through the same permission check as local tools. The paper states that its three case studies are not a quantitative benchmark, and that permission accuracy, overhead, and task-utility trade-offs are future work.

HarnessSecurity-Bench (arXiv:2610.07639) was read from the arXiv HTML. It compares each native mechanism switched on and off, with separate deterministic oracles for task utility and attack success. Under GLM-5.2, 2,500 trials, auto-approve raises utility from 77.1% (601/780) to 95.4% (744/780) and attack success from 29.2% (105/360) to 95.6% (344/360). Network isolation lowers attack success from 57.1% (137/240) to 0.8% (2/240) and utility from 90.9% (600/660) to 66.4% (438/660). Read-only mode lowers attack success from 8.3% (10/120) to 0.8% (1/120) and utility from 69.8% (754/1080) to 35.8% (387/1080). Command allowlisting lowers attack success by 48.1 points with a 1.5-point utility loss. The pooled MCP-permission row moves utility from 73.3% (836/1140) to 73.9% (842/1140) and attack success from 82.2% (296/360) to 54.2% (195/360). On the StreamLoop task, turning MCP permissions on raises attack success for Claude Code from 90% to 100% and for Gemini CLI from 0% to 10%. Each comparison is one native switch. The policy is not an envelope estimated from benign traces, and the mechanisms are not stacked as one ladder.

AgentTrap (arXiv:2605.13940) was read from the arXiv HTML. It is a skill-supply-chain benchmark: 91 malicious tasks and 50 benign utility tasks, judged separately. MCP abuse is one of 16 impact dimensions, and the paper names it among the high attack-success slices because the malicious step looks like ordinary setup. For Claude Sonnet 4.6, moving from the plain agent to Claude Code raises blocked or refused tasks from 30 to 56. For Claude Haiku, attack successes rise from 27 to 72 on that same move. Benign overdefense is a separate label. The split is malicious tasks versus benign tasks, not one envelope tightened against held-out success.

CapScope (arXiv:2609.08371) was read from the arXiv HTML. It mints a task ceiling from the trusted request and the project’s file names, before file contents are read, then gives each sub-agent a narrower store. On the Pi agent, five Python repair tasks, five injection surfaces, and three trials give 75 runs per condition. Ambient authority executes the injected effect in 47 of 75 runs and finishes 72 of 75 repairs. A static global denylist executes it in 46 of 75 and finishes 70 of 75. A task-specific global allowlist executes it in 33 of 75 and finishes 68 of 75. CapScope executes it in 3 of 75 and finishes 68 of 75. The model proposes the injected action on 34 of those 75 CapScope runs, and the hook allows it on 3. The four conditions are different authorization models. The ceiling is compiled from the trusted request, not from benign execution traces, and the conditions are not stacked as one ladder.

HarnessRisk (arXiv:2608.17597) was read from the arXiv HTML. Each of 128 cases pairs a benign objective with an adversarial instruction, and utility and attack success are labeled on the same trajectory. Useful-but-unsafe trajectories are 59% on OpenClaw, 38% on Nanobot, and 43% on Hermes. GLM-5.2’s attack success is 54.7% on OpenClaw and 12.6% on Nanobot. Against deterministic predicates on 360 trajectories, utility agreement is 92.5% (Cohen’s \(\kappa=0.83\)) and attack-success agreement is 89.7% (\(\kappa=0.77\)). The paper reports no defense ladder and does not mention MCP.

HarnessAudit (arXiv:2605.14271) was read from the arXiv HTML. It audits 210 benign workflows whose safety pressure is a nearby out-of-scope action. Boundary rules are written into the task specification. The best overall score in the reported comparison is 0.32. Safety adherence falls as the task-completion threshold rises, and violations rise with the number of actions. Information-flow compliance averages 0.45, and more than half of the role agents in a task commit a violation. Deterministic checks cover boundary violations and completion checkpoints. The plotted trade-off holds the policy fixed and varies the completion threshold. It is not an envelope estimated from benign traces and then tightened.

Symbolic Constraint Agents (arXiv:2610.25552) were read from the arXiv HTML. An initializer mines first-order rules from API documentation, and a refiner edits them against sample traces. On AppWorld, refinement raises error-detection F1 from 37.0 to 58.3 on GPT-5.5 traces and from 39.3 to 61.9 on Qwen3.5-27B traces. Runtime repair raises GPT-5.4-mini’s task success by 5.4 points under a 40-call budget. The rules are tool dependencies. The paper’s comparison with prior constraint systems is that those systems enforce a hand-written safety policy, and this one mines environment rules.

AgentLTL (arXiv:2607.02599) was read from the arXiv HTML. A scripted gold trace instantiates six constraint layers, and the same specification scores a finished trace or gates calls online. Three settings share those constraints: offline scoring, block-and-warn, and soft-block. Block-and-warn raises compliance on five of seven models and accuracy by 0.019 on average. Soft-block is the worst setting for four of seven models. The abstract states finetuning gains of 38 accuracy points and 17.5 compliance points on held-out patterns. The table prose states a 38.5-point accuracy gain on the unseen-pattern and diverse-tool splits. The tools are generic arithmetic tools. The specification comes from a scripted gold trace, and the three settings are intervention strengths on that script.

AutoSpec (arXiv:2606.24245) was read from the arXiv HTML. It starts from expert rules and revises them against traces labeled safe or unsafe. On 291 traces it reaches rule F1 of 0.98 in the code domain and 0.93 in the embodied domain, with up to a 94% false-positive reduction, in 4–5 iterations. The unrefined code rules have recall 0.974 and precision 0.544 (31 false positives). The unrefined embodied rules have precision 1.000 and recall 0.327 (35 missed unsafe traces). A heuristic revision’s held-out F1 falls to 0.480, below the unrefined 0.698. The labels include unsafe traces, and the score is rule F1.

Registry description drift (arXiv:2608.00997) was read from the arXiv HTML, version 2. It reconstructs 120 observations of the official MCP registry over 88.6 days, 19,099 distinct servers, as the catalog grew from 3,510 to 18,966. The measured text is the registry’s own description field, capped at 100 characters, not the per-tool descriptions a server returns. Of servers observed across at least ten intervals, three-quarters never change, and the most active 5% produce 61% of change events. Three non-overlapping 30-day cohorts show descriptor change of 11.4%, 11.9%, and 12.3%. Description text changes 3.3% at 30 days. At a top-5% re-audit budget, ranking by prior drift catches about 20% of previously seen description changers in a held-out window and about 27% of descriptor changers. Prior description change lifts the next-period probability 4.8 times, from 2.8% to 13.8%, but only 5.0% of servers have any such history. The paper says this is the shelf life of the audited text. It does not observe live tool behavior, and it is not an attack rate or a task-success curve.

MCP Pitfall Lab (arXiv:2604.21477) was read from the arXiv HTML. Validators score MCP traces. Across 2,579 completed runs of 2,592, overall attack success is 31.9%: multi-modal injection 38.7%, puppet attacks 34.5%, and tool poisoning 22.6%. Singular prompts are 36.5% and compound prompts 27.3%. Hardening is one baseline server against one hardened server. The crypto workflow falls from 75.0% to 50.0%, the focused email workflow from 33.3% to 0.0%, and the document workflow rises from 8.3% to 25.0%, each on 36 runs. In the image-routing case, baseline attack success is 100% and the hardened server is 0%, while the sink tool is still reached in 5 of 5 runs. Static semantic fields detect four pitfall classes at F1 0.727. BOM findings fall from 27 to 16. Mean control coverage rises from 0.173 to 0.697, and mean residual risk falls from 15.31 to 6.09. The comparison is one hardened configuration. It does not vary an envelope estimated from benign traces.

The HTML and PDF for the temporal-constraint paper cited as Agent-C (arXiv:2512.23738) returned no content, so that body was not read.

Deterministic replay (arXiv:2607.16200) was read from the PDF. It records HTTP and model calls through a proxy and replays the stored responses with no outbound network. The evaluation section says each of five workloads was recorded once and replayed five times, and it also says 250 replay instances. The reported fidelity is 1.0 and the median per-step latency reduction is 98.3%. The Model Context Protocol appears as a citation that tool calls over HTTPS would be captured; a dedicated adapter is planned. The score is replay fidelity. It is not an attack rate or a task-success curve.

The method-scoped authorization report (Zenodo concept 10.5281/zenodo.23110512, record 23110513) was read at the record description. The PDF returned HTTP 500, so the body was not read. The description says a gateway checked authorization on one JSON-RPC method. That is a single-gateway bypass report, not a strictness curve.

Hard-KLAIM (DOI 10.1016/j.jlamp.2026.101191) was not read past the OpenAlex abstract. The publisher page returned HTTP 406, and an arXiv title search returned no preprint. The abstract describes a locality-aware type-and-effect system for trace safety. The least-privilege engineering paper (DOI 10.15439/2026f6361) also returned HTTP 406.

ToolGuard (Zwerdling et al., EMNLP 2025 Industry, anthology 2025.emnlp-industry.41) was read from the PDF because Symbolic Constraint Agents cites it. The PDF does not use the phrase “Model Context Protocol.” It compiles a company policy document into code that runs before each tool call. On the τ-bench Airlines mapper, GPT-4o reaches reference F1 0.80 and a fuzzy grouping index of 0.83. On 61 hand-written tests, 25 compliance and 36 violation, GPT-4.1’s mean pass rate is 0.82 from the manual mapping and 0.75 from the generated mapping. At runtime, 22 of 50 tasks are the ones whose user request violates a policy. The unguarded pass^1 is 0.450 and pass^10 is 0.227. The generated guards raise those to 0.685 and 0.500. The score is a match of the final database state on that violating subset. The policy is the company document, and there is one guard set.

Zero-trust command-line enforcement (Ando, TechRxiv 20 February 2026, DOI 10.36227/techrxiv.177155647.75363542) was read from the PDF. It places identity, role checks, and an intent verifier in front of MCP tool calls. The evaluation uses 30 cases, 10 benign, 10 malicious, and 10 context-dependent, each run five times. Table I labels the columns recall, precision, false-positive rate, and latency. The prose defines recall as attack detection and the false-positive rate on the benign cases. Reported recall is 95.0% for grok-4-1-fast, 90.0% for claude-haiku-4.5, 85.0% for gemini-flash-lite, 60.0% for llama3.2:3b, and 15.0% for gpt-5-nano, with false-positive rates 10.0%, 0.0%, 0.0%, 30.0%, and 20.0%. The paper treats the launched server binary as trusted. The check is one verifier. It is not an envelope estimated from benign execution traces.

LightGuard-Agent (Zenodo concept 10.5281/zenodo.22731103, record 22731104, 13 September 2026) was read from the record preview, which contains the two-page paper. The PDF byline is Tarek Mohamed. It places three tiers in front of a tool-calling loop: a syntactic sanitizer, a semantic intent classifier, and an action firewall. The evaluation is 25 adversarial cases and 25 benign controls. Vanilla ReAct is 100.0% attack success and 0.0% false positives. The sanitizer alone is 28.0% and 0.0% at 0.036 ms. Llama-Guard 3 is 8.0% and 4.0% at 450–1200 ms. The full stack is 0.0% and 0.0%, mean latency 0.059 ms, 95th percentile 0.158 ms. The false-positive rate is on the 25 benign controls. The arms are one sanitizer, a separate judge, and the full stack. They are not an envelope estimated from benign execution traces.

COPEX (arXiv:2610.04378) was read from the arXiv HTML. It fixes the agent stack and varies the tool-selecting model. The main benchmark is 25 attack types, 125 scenarios, 16 servers, 75 tools, and 7 resources, run as 3,375 trials on nine models. Mean attack success is 64.4%. By entry surface the means are 58.3% model/agent, 67.7% client, 62.5% server/tool, and 71.4% transport. The lowest overall model is 44.3% and the highest is 81.6%. A transport attack that redirects below the model’s observation stays at 100% for every model. On six attacks scored both ways, deterministic trace predicates give 76.7% and a semantic judge gives 83.3%. Two judges agree on 84.2% of 1,892 paired trials, with Cohen’s kappa from 0.49 to 0.81. The defense study is a separate eight-attack subset, one run per variant. No scanning is 80.6%, input scanning 50.6%, context scanning 53.8%, and both together 41.2%. The paper states those reductions are point estimates. The scanners examine the user task, registered schemas, and tool responses. They do not estimate an envelope from benign execution traces, and the benchmark does not report held-out task success.

ProtoAmp (Maloyan and Namiot, arXiv:2601.17549) was read from the arXiv HTML. The abstract’s “first rigorous” sentence is the paper’s own claim. The benchmark adapts 312 InjecAgent cases, 398 AgentDojo cases, and 137 protocol-specific cases, 847 in total, and compares MCP tool calls with direct function calls. Overall attack success is 26.4% on the direct baseline and 52.8% through MCP. A client-side shim, AttestMCP, is reported at 12.4% overall. Three authored isolation settings are reported beside task completion: no isolation 61.3% and 94.2%, user-prompted cross-server flow 31.7% and 87.4%, and no cross-server flow 8.7% and 61.8%. The paper does not say those levels were estimated from benign traces, and it does not say whether task completion is a held-out benign set. The same 8.7% is later the cross-server figure for the shim, while the prose also calls user-prompted isolation the shim’s default.

MCPSecBench (Yang et al., arXiv:2508.13220) was read from the arXiv HTML. The abstract’s “first formalization” sentence is the paper’s own claim. It defines 17 attack types on four surfaces and runs them on Claude Desktop, OpenAI, and Cursor, 15 times each. Attack success and refusal are both divided by the number of attempts, so the two rates need not sum to 100. Two protections, MCIP-Guardian and FAN, are switched on separately, and only on the 11 types where at least one of them detected something. On the server-side average with no protection, attack success is 78.1%, 75.2%, and 75.2%. With MCIP-Guardian those averages are 48.6%, 67.6%, and 73.3%. With FAN they are 45.7%, 50.5%, and 66.7%. The protocol-surface average is 100% attack success, and both protections are marked not applicable. Refusal is counted on the attack attempts. The paper does not report held-out task success, and the protections are not an envelope estimated from benign traces.

MCP-Bench (Wang et al., arXiv:2508.20453) was read from the arXiv HTML, which is dated 24 August 2026. It connects models to 28 live servers and 250 tools. The stated task set is 56 single-server tasks, 30 two-server tasks, and 18 three-server tasks. Twenty models are scored by rule checks and by an o4-mini judge averaged over five rubric shuffles. The highest overall scores in the reported leaderboard are 0.749, 0.715, and 0.692. The word “utility” in this paper is a task-quality filter, a threshold of 5.0 out of 10, applied before a task enters the set. The benchmark does not measure an attack or a privilege envelope.

Tool-result parsing (Yu, Cheng, and Liu, arXiv:2601.04795) was read from the arXiv HTML. The Model Context Protocol appears as a citation for tool integration. The evaluation is AgentDojo on gpt-oss-120b, llama-3.1-70b, and qwen3-32b. Two prompt modules, a parser and a checker, are reported alone and in both orders. Benign utility is task success with no attack. Utility under attack is task success on the attacked runs. On the no-attack column, the parser-then-checker scores are 48.45, 28.87, and 45.36, against undefended scores of 61.86, 49.48, and 83.51. Averaged across the attack settings, that order’s attack success is 0.19, 0.34, and 0.11. The checker-then-parser average on qwen3-32b is 0.00. The paper’s “lowest to date” sentence is its own claim. The modules are prompts. They are not an envelope estimated from benign execution traces.

COBRA (Zingrillo et al., arXiv:2610.03089) was read from the arXiv HTML. It commits a branching plan from the trusted request, then bounds the parameters and destinations each branch may use. The bounds come from a user-approved site or tool description, pinned by hash, or from a domain allowlist on the trusted request. They are not estimated from benign execution traces. STEER-Bench has 101 tasks, 199 attack cells, and 138 benign cells. Complete COBRA is 0% attack success on those 199 cells. Turning the targeted component off raises the cell-weighted rate to 87.6%. On the cells a generic agent can run, ReAct is 94.4% and a vanilla dual-model system is 89.5%. The paper says COBRA retains 97% of benign utility and records four false positives on the 138 benign cells. The 15-cell MCP suite is 0% with the proxy and 67% without it. On MCPTox, 1,210 of 1,223 cases change the tool or its arguments and are blocked; the other 13 keep the same call and change a hidden server effect. That section reports 79% utility under attack against 100% without the enforcement. The abstract’s “first systematic” sentence is about STEER-Bench.

SHIELDMCP (Yergattikar, ACL 2026 Industry, pages 865–871) was read from the anthology PDF. It is a proxy with three stages: a description check, a parameter check, and a response check. The evaluation uses 25 benign servers and 15 adversarial servers, 487 attack cases, five models, and three runs each. Averaged across the models, attack success is 70.9% with no defense, 61.4% with a pattern filter, 28.1% with a judge model, and 9.5% with the proxy. On 200 legitimate tasks, completion is 98.5% without the proxy and 96.8% with it. The paper states a median added latency of 118 ms and a 95th percentile of 247 ms. The extracted text splits the stage-3 latency across a page boundary, so that figure is not quoted. The comparison is one proxy against two other checks. It is not an envelope estimated from benign execution traces.

AgentChaosBench (Zhang et al., arXiv:2608.14680) was read from the arXiv HTML. Five applications call tools through the Model Context Protocol. The dataset is 275 traces: 250 with an injected operational fault and 25 clean controls, five inputs for each of eleven conditions. The labels are held out from the detector. On the structured view, top-1 fault-type accuracy on the 250 faulty traces is 13.6% to 19.2% for the local detectors and 24.8% for DeepSeek-v4-pro. Clean runs are recognized as clean in 1 of 25 cases by the smallest detector and 24 of 25 by the 14B detector. Top-1 localization of the responsible component is 20% to 31%. The score is fault diagnosis. It is not attack block, and it is not an envelope estimated from benign task traces.

The Failures paper (Kalejaiye, Zenodo concept 10.5281/zenodo.22966361, record 22966362, 25 September 2026) was read at the record description. The PDF returned HTTP 500 and the preview page returned HTTP 404, so the body was not read. The description says an MCP server encodes eleven software-reliability checks. Across 17 matched agent comparisons, 16 improved on at least one resilience criterion. Six adversarial cases are used to look for false positives. Those figures are resilience of generated code. They are not attack block against held-out task success, and the checks are not an envelope estimated from benign execution traces.

MCP server architecture patterns (Rodrigues and Vas, arXiv:2606.30317) were read from the arXiv HTML. Five patterns are derived from 15 servers. A separate set of 54 servers is classified by two models. Cohen’s kappa between the raters is 0.76, with a bootstrap interval of 0.62 to 0.88, and raw agreement is 81.5%. Agreement with the authors’ labels is 68.5% and 75.9%. A retrospective production log, 200 turns in each tool-count bucket, puts Haiku at 91% tool-selection accuracy with 10 tools and 87% with 15, and Sonnet at 95% with 10 tools. The held-out set is servers for a taxonomy. The accuracy is whether the selected tool matches an operator’s later confirmation. It is not attack block, and it is not a privilege envelope.

RAG-MCP (Gan and Sun, arXiv:2505.03275) was read from the arXiv HTML. It retrieves a subset of MCP descriptions before the model sees them. The stress test uses 20 web-search tasks and varies the candidate pool from 1 to 11,100, drawing distractors from more than 4,400 public servers. In the comparison table, semantic retrieval is 43.13% accurate, keyword prefiltering is 18.20%, and prompting with the whole pool is 13.62%. The position plot is described as mostly successful below position 30, above 90%, and mostly unsuccessful beyond about position 100. The score is whether the selected server is the one that can answer the task. It is not attack block, and it is not a privilege envelope. The paper’s “one of the first” sentence is its own claim.

LongFuncEval (Kate et al., arXiv:2505.10570) was read from the arXiv HTML because the architecture-pattern paper cites it. The HTML does not use the phrase “Model Context Protocol.” It measures function-call accuracy as the catalog, the tool response, and the conversation grow. The catalog is varied from 8,000 to 120,000 tokens, and the correct tool’s position is varied too. The introduction states that those drops run from 7.59% to 85.58%, excluding Mistral-large. In the displayed catalog table, the degradation column reaches 13.81 for GPT-4o and 94 for Mistral-large. Tool responses from 10,000 to 80,000 tokens drop GPT-4o by 7% and Mistral-large by about 91%. The score is abstract-syntax accuracy on function calls. It is not attack block, and it is not a privilege envelope. The paper’s “first attempt” sentence is its own claim.

MASF-CC (Basnet, Zenodo concept 10.5281/zenodo.20745155, record 20745156, 18 June 2026) was read at the record description. The PDF returned HTTP 500 and the journal page timed out, so the body was not read. The description says a gateway applies four layers together: validation, authorization, integrity, and audit. On a self-built set of 100 attack scenarios and 50 developer tasks, it reports a defense success rate of 100%, a mean added latency of 0.06 ms against a mock server, and a task completion rate of 96% after the capability tokens were reconfigured. The description says those results are limited to that corpus. The sentences about attack success above 85% and defenses below 30% are citations of other benchmarks. The four layers are one gateway. They are not an envelope estimated from benign execution traces.

SecureMCP (Kim, Yoo, and Moon, Applied Sciences 16(16), article 7974) was read from the journal HTML. Five modules run as one fail-closed pipeline in front of generated SQL: a role check, a cost gate, a statement interceptor, a risk filter, and a database-isolation check. On 1,900 clean queries and four authored roles, the role check’s false-positive rate is 0.3% to 2.2%, and the cost gate’s is 8.0% to 12.1%. For the broadest role, the cost gate blocks 229 in-scope queries and the role check blocks 6. Execution accuracy among admitted queries stays between 65.1% and 76.4%, against 63.8% with no defense. On 2,400 adversarial queries the full pipeline blocks 82.3%, and the effective miss rate on realized threats is 3.98% (82 of 2,058). The role check alone blocks 64.8% and misses 27.53%. The other four modules without the role check block 62.3% and miss 17.93%. The paper says the roles do not form a simple monotonic curve. The roles are authored. They are not an envelope estimated from benign execution traces.

Praetor (Dang, arXiv:2604.26274) was read from the arXiv HTML. It compiles 400 verified benign ToolBench traces into a parameterized automaton and holds out 100 traces for false positives. At context width 3 and pruning threshold 3, attack success on three structured Agent Security Bench scenarios is 2.2%, against 12.8% for the stateless scanner remeasured in that paper. Across five scenarios the macro-average is 5.6%. Travel Planner and Research Agent are 8.6% and 12.6%. Benign task failure on the 100 held-out traces is 2.0% (2 of 100; 95% interval 0.2% to 7.0%). On the context-sequential set, widths 1, 2, and 3 give 100%, 45%, and 0% attack success. Widths 4 and 5 raise benign task failure to 3.2% and 7.1%. The figure caption says the plotted attack success is the macro-average across five families. The prose does not give benign task failure at widths 1, 2, and 3. It says a higher pruning threshold reduces attack success and raises false positives, and it publishes that pair only at threshold 3. Scaling the corpus to 5,000 traces lowers benign task failure to 0.2% and leaves attack success at 2.6%. The attack scores and the held-out scores are on different corpora. The automaton is a sequence profile of one persona. It is not a cross-task privilege envelope scored, at each strictness, as attack block against held-out task success.

ChainCaps (Jiang, Yang, Li, Liu, Yu, and Liu, arXiv:2605.26542) was read from the arXiv HTML. A proxy intersects sink-specific budgets as values move through tools. The budgets come from manifests. On 82 tasks, 56 adversarial and 26 benign, five models, and three runs, attack success falls from 25.2%–67.8% to 0.0%–4.8%, and benign completion stays at 96%–100%. Expert manifests block 100% of attacks with 100% benign completion. Checklist-guided manifests block 90.9%. Naive manifests block 27.3% with 50% benign completion. Removing the intersection rule drops attack blocking by 17 points on 163 held-out replay traces. The comparison is one proxy, plus component ablations and a manifest-quality sweep. The budgets are not estimated from benign execution traces.

Guardbox (Lyu and Fu, Zenodo concept 10.5281/zenodo.21758194, record 21758195, 2 August 2026) was read at the record description. The PDF returned HTTP 500 and the preview page returned HTTP 404, so the body was not read. The description says the control is a three-way allow, step-up, or block decision, with two synthetic benchmarks, and it states no attack-success or task-success rate. Those benchmarks are not treated as a measured envelope.

Defer (Mitra, Patel, Neupane, Mittal, Rahman, and Rahimi, arXiv:2610.07657) was read from the arXiv HTML. It runs 28 authored checks in one cascade and sends the remainder to four judges. Pooled over four domains, attack success falls from 34.6% with no checks to 6.1% with the cascade. In the security-operations domain the same judges without the rules reach 28.9% (interval 19.6% to 38.2%), and the full cascade reaches 12.2% (5.4% to 19.8%), against 35.6% with no checks. Sending every surviving call to the judges changes no attack outcome and raises benign denials from 7.8% to 9.4%. Never judging leaves attack success between 0% and 1.8% by escalating 41% to 59% of legitimate proposals. The paper says task completion only requires the last phase to produce a report, so it treats denied legitimate proposals as the cost. On Agent Security Bench it reports 1.8% attack success and says utility was not measured. The checks are authored. They are not an envelope estimated from benign execution traces.

The revocation contract (Liu, Yu, and Zhang, arXiv:2610.15991) was read from the arXiv HTML. C0 through C5 are evidence stages from issuer commit to effect prevention. In an eight-case audit, treating receiver persistence as completion yields seven false positives, treating gateway receipts as completion yields five, and the full contract yields none. On two 16-host runs, a frozen partition admits and commits 112 of 225 calls. The paper says that fraction is the assigned partition, not an incident rate. On ten MCPMark tasks, the enforced arm denies all 31 exposed later calls, and the selective arm allows 344 calls and commits 145 effects. Four of 60 tasks pass the task verifier. The stages record whether a revocation reached the effect. They are not a privilege envelope estimated from benign traces.

The measurement-validity paper (Pathade, Pawar, and Patil, arXiv:2609.25173) was read from the arXiv HTML. It codes 259 arXiv papers, from February 2025 through September 2026, that report a numeric attack success rate. The queries are twelve topical searches, not the phrase “Model Context Protocol.” Automated coding says 65.3% report neither a variance estimate nor repeated runs; a hand-coded sample of 50 puts that at 58.0% (Wilson interval 44.2% to 70.6%). Benign-task utility is reported in 37.8%. The authors say they could not reliably code how attack success is decided, and they publish no rate for that. The corpus does not say whether any paper estimates a privilege envelope from benign traces.

ZTPM (Ranathunga, Fernando, and Rea, arXiv:2605.25653) was read from the arXiv HTML. It defines 25 policy primitives and five physical-impact tiers, from a digital-only permit to a safety-critical deny. The experiment is one neutral motion task under three workspace conditions, ten runs each on Gemma 4 and Claude Sonnet 4.6, 60 traces in all. Gemma 4 stays at 0.500 rad/s in every condition. Claude Sonnet 4.6 moves from 0.42 rad/s in the empty workspace to 0.17 with a fragile object and 0.21 with a person nearby, and within the person-nearby condition the speeds run from 0.15 to 0.30 rad/s. The paper uses those speeds to argue for a policy bound. It does not report attack block against held-out task success as the tiers get stricter.

Harness-Bench (Yao et al., arXiv:2605.27922) was read from the arXiv HTML. It scores 300 sandboxed tasks under seven harnesses and ten backends. Full credit for GLM-5.3 varies by 13.5 percentage points across harnesses. Choosing a harness per model on training tasks improves held-out full credit by 2.53 to 2.73 percentage points over one shared harness. The score is artifact credit under fixed safety gates. It is not attack block against a privilege envelope.

The capability-container pattern (Ledan, Zenodo concept 10.5281/zenodo.18614502, record 18614503, 11 February 2026) was read at the record description. The PDF returned HTTP 500 and the preview page returned HTTP 404, so the body was not read. The description says six layers sit in front of isolated containers. On a 1,534-sample corpus it reports a secret-detection rate of 100% (interval 0.996 to 1.000), an F1 of 0.991 against 0.779 for a comparison scanner, and a false-positive rate of 0.19%. It says the samples are synthetic. The description does not say the layers were estimated from benign traces or scored as a strictness curve.

aiAuthZ (Kodathala, arXiv:2607.05518) was read from the arXiv HTML. An off-host gateway checks a per-message signature and a role-and-argument policy the agent cannot read. Across 15 models and eight scenarios, refusal among the fully evaluated models runs from 100% to 38%. With the gateway, residual attack success is 0% for every model, and the decision overhead is at most 0.03 ms. On the AgentDojo banking suite it blocks all seven attacker-directed tool calls the agents emit and also blocks one legitimate first-time payment. On nine case studies the full policy blocks nine, an argument-only reimplementation blocks four, and a delegation-token reimplementation blocks none. The reported gateway result uses one fixed non-owner role. It is not an envelope estimated from benign traces.

The tool-description benchmark (Liu et al., arXiv:2605.24069) was read from the arXiv HTML. It scores 32 cases in six categories on eight models, five runs each. Average attack success and user-command completion, on the same attacked runs, are 0.997 and 0.998 for GPT-4o, 0.893 and 0.953 for Claude 3.7 Sonnet, 0.897 and 0.925 for Claude 4 Sonnet, 0.980 and 0.960 for Gemini 2.5 Pro, 0.848 and 0.918 for DeepSeek V3, 0.900 and 0.960 for DeepSeek R1, 0.817 and 0.977 for QWQ 32B, and 0.723 and 0.980 for Qwen3 32B. User-command completion is success of the user’s request on the attacked run. The paper reports no defense ladder and no held-out benign set.

The hardware-keystore stack (Sambrook and Sovio, arXiv:2608.06130) was read from the arXiv HTML. Five layers sit in front of a signing device: session identity, a session handshake, deterministic scope and payload checks, a semantic filter, and the hardware boundary. On an AgentDojo signing set, 144 trials across the injection-following models, attack success falls from 18.1% (interval 12.6% to 25.1%) to 0% with the full stack. The paper says a plausible substitute name defeats the semantic filter in every trial of that probe, and that the guarantee is the human check used when nothing was committed in advance. The layers are one stack. They are not an envelope estimated from benign execution traces.

Skynet (Zhang, Yu, Jin, Shi, Zhang, Shi, Gel, Hou, and Lou, arXiv:2609.06835) was read from the arXiv HTML. It embeds a workflow graph and scores distance from benign modes learned on ETO trajectories. One quantile targets a false-positive budget under 1% and lands at 0.89% on the held-out benign split. At that point recall is 100% on Agent-SafetyBench, 100% on AgentErrorBench, 82.70% on ATBench, and 89.36% on the combined set. The decision flags an anomalous workflow. It does not block a tool call, and it does not score held-out task success as a privilege envelope gets stricter.

Agent-Canary-Mas (Liu, Gai, Chang, Li, Zhu, Wang, and Feng, arXiv:2610.15529) was read from the arXiv HTML. It runs 975 matched malicious–benign pairs. On the Finance tasks with MiniMax-M3, one protocol-context guard moves average attack success from 86.1% to 53.8% and consequence conversion from 65.5% to 31.2%. Paired completion, which requires both runs in a pair to finish, falls from about 99.8% to 95.1%. The protocol averages under the guard are 96.4%, 96.5%, and 92.5% completion, against 99.4%, 100.0%, and 100.0% without it. The guard checks identity, capability, routing, and a bounded semantic review. It is one check. It is not an envelope estimated from benign traces.

ShieldNet (Yuan, Chen, Xiang, Bastian, Hashemi, Xiao, Guo, and Li, arXiv:2604.04426) was read from the arXiv HTML. It classifies network events from tool execution. The corpus is 109 servers, 984 tools, 30 techniques, and 19,961 executions. At tool level its false-positive rate is 0.022 and its F1 is 0.998. At traffic level those figures are 0.008 and 0.995, with 21.38% added time. The same tool-level table gives the static scanners 0.068 and 0.164, 0.009 and 0.029, and 0.124 and 0.172. The score is detection of a malicious execution. It is not held-out task success under a stricter privilege envelope.

The healthcare workflow paper (Kearns, arXiv:2606.28666) was read from the arXiv HTML. It compares one single-agent workflow with one redesigned workflow on five models, 800 generations, and 500 attack scenarios. Mean attack success falls from 31% (Wilson interval 22.8% to 40.6%) to 10% (5.5% to 17.4%) on one vector, McNemar exact p below 0.0001, and from 42% (32.8% to 51.8%) to 25% (17.5% to 34.3%) on a second, p = 0.0009. A third vector is absent from the redesigned workflow because prompts are built on the server, so the paper does not report it as a measured zero. Report accuracy rises from 72.5% to 86.5%. The comparison is two workflows. It is not an envelope estimated from benign traces.

SafeClawArena (Niu et al., arXiv:2606.30755) was read from the arXiv HTML. It runs 406 adversarial tasks on three platforms and five models, and scores them by whether a planted marker reaches an unauthorized channel. Overall attack success spans 20.2% to 69.7%. Averaged over the five models, the three platforms are 53.5%, 51.7%, and 34.9%. The platforms are different products. The paper does not report held-out task success, and it does not estimate a privilege envelope from benign traces.

Connor (Huang et al., arXiv:2604.01905) was read from the arXiv HTML. It compares a tool’s traced behavior with the intent extracted from that tool. On 114 constructed servers its precision is 98.4%, its recall is 91.1%, and its F1 is 94.6%. Three comparison scanners score 59.3%, 86.2%, and 72.1% F1. On 1,672 marketplace servers it flags two that the authors then verify. The score is detection of a malicious server. It is not attack block against held-out task success as an envelope gets stricter.

Agent Audit (Zhang, Nian, and Zhao, arXiv:2603.22853) was read from the arXiv HTML. It is a static scan of Python agent code and deployment files, including privilege checks on MCP configuration. On 22 samples and 42 labeled vulnerabilities it finds 40, with 6 false positives: recall 95.24%, precision 86.96%, F1 0.909. Semgrep’s recall is 23.8% and Bandit’s is 29.7%. On synthetic fixtures the confidence tiers reach 98.51% precision at 100% recall. The scan does not run a task, and it does not estimate an envelope from benign execution traces.

SkillScreen (Huang, Quan, Lyu, Guo, and Ge, arXiv:2610.17727) was read from the arXiv HTML. It scores a skill file for maliciousness. On 9,740 labeled skills, the unseen-family split gives 95.6% recall at a 3.3% false-positive rate. At 99% recall the false-positive rate is 22.6% on that split and 50.5% when the sources are unseen. Prompted judges at the same 99% recall flag 86.8% to 100% of the benign skills on the unseen-family split. The threshold is chosen on validation data. It is a detector threshold. It is not a privilege envelope.

SafeNLIDB (Liu, Chen, Zhang, Zhang, Zhang, and Yang, arXiv:2511.06778) was read from the arXiv HTML. It fine-tunes a model to refuse unsafe database questions and still emit SQL. Security accuracy is a binary label. The reliability score penalizes both over-refusal and under-refusal, so the published values are negative. For the Qwen2.5-7B run they are 63.1 and −28.2 on SecureSQL, and 81.9 and −15.8 on ShieldSQL. For Llama3-8B they are 64.4 and −24.4, and 84.6 and −13.8. The change is in the model weights. It is not an envelope estimated from benign execution traces.

APEX (Zheng, Guo, Hao, Yang, Qian, Du, Xu, Xing, Yang, and Wang, arXiv:2610.06966) was read from the arXiv HTML. A contract compiled before untrusted execution admits an effect only when the trusted task authorizes it and endorses the information that reaches it. Capability units are registered once. On AgentDojo, benign-task success is 86.60%, task success on the attacked runs is 80.29%, and attack success is 0%. On the observation-injection subset those figures are 90.20%, 85.05%, and 0%. The paper says attack success is also 0% on MCPTox, MSB, and SCR, and 0.56% on SkillInject. MSB has no benign tasks. The comparison is one contract against other defenses. The contract is not estimated from benign execution traces, and the paper does not tighten it.

Authenticated workflows (Rajagopalan and Rao, arXiv:2602.10465) were read from the arXiv HTML. Four surfaces, prompts, tools, data, and context, check a signature and a policy the operator supplies. On 174 cases covering 9 of 10 listed risks, the paper reports 100% recall and 0% false positives for the cryptographic stages. It says optional later verifiers can add false positives. The paper’s “first complete” sentence is its own claim. The policies are supplied. They are not estimated from benign traces.

The least-privilege engineering paper (DOI 10.15439/2026f6361) has no arXiv preprint. Its body remains unread.

InterSAGE (Zou, Guo, Zhan, Zhao, Li, and Liu, arXiv:2608.13030) was read from the arXiv HTML. Four layers cover identity, discovery, trust negotiation, and accountability. Trust negotiation is a signed chain from developer to operator to registry to runtime, plus a separate application policy. The security section argues properties under three assumptions: an honest registry root, an intact key-custody layer, and unforgeable signatures. It does not report attack success or task success.

SkillFortify (Bhardwaj, arXiv:2603.00195) was read from the arXiv HTML. Static analysis uses a four-level capability lattice: none, read, write, and admin. On 540 skills, 270 malicious and 270 benign, precision is 100% (250 of 250), recall is 92.59% (250 of 270), and the false-positive count is 0. The results section says the information-flow rule adds no detections beyond pattern matching on this corpus. The lattice is the analyzer’s abstract domain. It is not tightened against held-out task success.

Synoptis (Hatakeyama, Zenodo concept 10.5281/zenodo.19161452, record 19161453, 22 March 2026) was read at the record description. The description specifies mutual attestation and a five-part trust score. The 52.8% to 12.4% sentence is a citation of earlier attestation work. The description states no success rate of its own. The PDF was not read.

Runtime Authorization Consistency Checking (Zhang, Lee, Zhuang, and Peng, arXiv:2609.23498) was read from the arXiv HTML. A trusted layer supplies the session grant. Each later call is admitted only when it is no more permissive than the basis inherited from accepted steps, and an admitted step can narrow that basis. On TraceBench, 1,248 workflows of which 1,008 are labeled block, full checking misses none of those blocks. Entry-only checking misses 841, a static tool allow-list misses 789, a history-aware resource check misses 624, and the two together miss 509. On the planner-generated subset, full checking blocks 207 of 223 reached block decisions (recall 0.928) and the paper reports no over-blocks on the reached allow decisions in that subset. A live filesystem replay matches the expected decision on 3 of 3 direct steps and 29 of 29 planner steps. The grant is supplied. The score is missed blocks against oracle labels, not attack block against held-out task success as an envelope estimated from benign traces gets stricter.

Registry description drift (Bharti, arXiv:2608.00997) was read from the arXiv HTML. It reconstructs 120 observations of the official registry over 88.6 days, covering 19,099 servers as the active set grew from 3,510 to 18,966. A top-5% re-audit ranked by earlier drift catches 19.3% and 21.5% of the previously seen description changers at the two cut-dates, and the same budget catches 26–29% of previously seen descriptor changers. The figure caption puts description-text change at 3.3% within 30 days. Descriptor change on three non-overlapping 30-day cohorts is 11.4%, 11.9%, and 12.3%. The held-out window is a later slice of the registry. The paper says it does not observe live tool behavior and does not test whether a security finding remains valid.

Enterprise identity integration (Chinthareddy, arXiv:2601.02698) was read from the arXiv HTML. An IDE presents an OAuth token, and the server maps scopes onto tools. The case study reports a cache hit near 5 ms, a cache miss of 25–35 ms, and a tool call of 90–120 ms. It reports no attack-success or task-success rate. The scopes are designed. The paper’s “first” sentence is its own claim.

Effect-bound approval (Kodathala, Pollishetty, and Cargill, arXiv:2610.21063) was read from the arXiv HTML. A gateway renders the approval from a canonical effect, a passkey signs that digest, and the gateway executes only the stored call. On 27,108 scripted trials, four post-approval attacks succeed every time against an unbound approval and fail against the bound gateway. On 609 AgentDojo pairs, forged narration succeeds 0.54 of the time (interval 0.42–0.65) against a narrated card and 0.03 (0.00–0.11) against the bound card when the approver compares the shown effect with the task. If the approver trusts the agent’s text, both sit at 0.54, and removing that text drops the bound card to 0.05 (0.01–0.13). Fifteen models refuse 0.30 of attacks from the narration (0.27–0.32) and 0.98 from the card (0.97–0.99). The card’s false-deny rate on 11 near misses is 0.16, and the paper says 88 of 103 of those refusals cite a placeholder string. The modes drop properties of one approval. They are not an envelope estimated from benign traces, and the near misses are not held-out task success.

RL Developer Memory (Iscan, arXiv:2605.01567) was read from the arXiv HTML. A deterministic ranker stays deployed. A contextual-bandit ranker runs in shadow, and an off-policy gate must authorize it before it can change a canary. On the same commit of a 200-case benchmark, both configurations reach 80.0% expected-decision accuracy and 100.0% hard-negative suppression. The paper’s claim gate does not treat the patch-replay deltas as a method improvement. The gate decides whether a learned ranker may leave shadow mode. It is not an envelope estimated from benign traces.

Chakravyuh (Tripathi and Mahajan, Zenodo concept 10.5281/zenodo.22992514, record 22992515, 27 September 2026) was read at the record description. Recommendations follow a written fraud policy with approval routes. On held-out closed cases, calibrating evidence weights raises the pre-evidence AUC from 0.45 to 0.66. A 20-case benchmark reaches a decision in 19 cases. The held-out slice is fraud cases. The PDF was not read.

ReliHarness (DOI 10.3390/electronics15184166) was read at the OpenAlex abstract. The journal page timed out. The abstract describes heartbeat and thread-liveness checks, reports 100% detection of the tested crash and deadlock scenarios with zero false positives, and reports a matching-accuracy lift from 74.5% to 90.2%. The sample-size clause is truncated in the abstract. The checks are thread liveness, not a privilege envelope.

LanG (Abdennebi, Kara, Lahlou, and Ould-Slimane, arXiv:2604.05440) was read from the arXiv HTML. A policy engine turns organizational governance documents into seven sub-policies, including role checks on MCP functions. A two-layer guard then screens inputs and outputs. On a 232-item corpus, adding the semantic layer moves aggregate F1 from 94.8% to 98.1% and recall from 90.1% to 96.3%, with precision 100% and no block-level false positives on the 70 benign items. The policies are supplied. The benign items are a false-positive set, not held-out task success. The paper’s “first” sentence is its own claim.

Remote MCP authentication (Zhou, Xiaohan Zhang, Haozhe Zhang, Haoyang Zhang, Mi Zhang, and Yang, arXiv:2605.22333) was read from the arXiv HTML. Of 7,973 live remote servers, 3,233 (40.55%) expose tools with no authentication, and 2,428 use OAuth. On 119 tested OAuth servers, every server has at least one flaw, 325 in total. The paper reports that two of its categories cover 96.6% and 85.7% of those servers, and that responsible disclosure produced 9 CVE identifiers. A review of 100 validated servers found 1 false positive. The paper’s “first” sentence is its own claim. The measurement is authentication prevalence. It is not an envelope estimated from benign traces.

Controlled-access thesis (Tadesse, KTH, TRITA-CBH-GRU-2026:116) was read from the PDF. It compares two enterprise systems with a zero-trust checklist and proposes a gateway with an input filter, a rate limit, and token exchange. The evaluation is that gap analysis. It does not report attack block against held-out task success.

Troubleshooting server (Gustafsson and Hedin, Blekinge Institute of Technology, May 2026) was read from the PDF. Five practitioners used the server in scenario sessions. The threat model lists twelve threats. Read and write tools are distinguished in the tool text, and the agent is instructed to ask before a change. The authors say the study measures perceived usefulness, trust, and security, not a quantitative rate. It is not an envelope estimated from benign traces.

Networking enforcement (Tran, Sharma, Dhesi, and Feamster, arXiv:2608.12172) was read from the arXiv HTML. A control plane outside the agent distributes access lists, role checks, and semantic policies to sidecars that allow, deny, modify, or escalate a call. Routing low-risk calls to the deterministic check and high-risk calls to the semantic check is left as future work. The paper reports no attack-success or task-success rate. The policies are supplied.

Cryptographic agent communication (Budzyn, Brodzik, and Szczepkowski, arXiv:2610.23078) was read from the arXiv HTML. Agents receive task-scoped credentials, and a ledger can revoke them. The paper compares handshake designs. It reports no attack-success or task-success rate. The credentials are issued. They are not estimated from benign traces.

Open-Rosalind (Wang, bioRxiv 10.64898/2026.05.06.722404) was read from the full text. Workflows are chosen from a fixed set of templates, with a default step bound of five. On the in-house benchmark the reference pipeline reaches 81.4% accuracy. Removing tools drops accuracy by 26.4 points on Gemma and 19.3 points on GPT-5-mini. The constrained pipeline beats an unconstrained loop by 35.3 points on GPT-5-mini and cuts catastrophic failures from 84.7% to 39.0%. On Gemma the two are not distinguishable (p = 0.74). A 30-task hold-out moves from 17.8% to 53.3% after routing fixes. That hold-out is task accuracy. The templates are authored. They are not an envelope estimated from benign traces.

Screenshot-or-tool routing (Fan, Li, Ma, Tan, Huang, Wu, Zhang, Shang, and Chen, arXiv:2608.03327) was read from the arXiv HTML. On 309 OSWorld-MCP tasks, the same tools change accuracy by +4.0 points for a reasoning model and −5.9 points for a non-reasoning model, five runs each. The reasoning model calls a tool on 55 of 309 tasks. A training bonus raises spreadsheet tool use from 0.03 to 0.33, and the paper says held-out accuracy does not follow. A compressed observation rule reaches 37.8% against 33.0% for the uncompressed point, at 53% of the input cost. The word “policy” here is the model’s choice of screenshot or tool, and the rule for keeping screenshots. It is not a privilege envelope, and the score is task accuracy.

Agyn (Benkovich and Valkov, arXiv:2605.27575) was read from the arXiv HTML. Least privilege is three platform mechanisms: a secret injected per container, a short-lived certificate, and relationship-based authorization. The evaluation is a feature checklist against four other platforms. The paper reports no attack-success or task-success rate. The permissions are configured. They are not estimated from benign traces.

Protocol-governed tutor (Saha, Pandey, Raj, Karna, Kumar, Mishra, and Hazra, Zenodo concept 10.5281/zenodo.20555125, record 20555126, 5 June 2026) was read at the record description. Roles receive least-privilege tool scopes, and code execution is consent-gated. On 25 tutoring tasks the prototype completes 22 (88.0%). Code tasks succeed on 57.1%. The description records 14 safety checks and no observed policy violation, and says the pilot did not include an adversarial tool test. The PDF was not read. The scopes are assigned to roles.

ADR (Chenning Li, Hu, Xu, Ozbas, Liu, Van, Manxue Li, Zhou, Alizadeh, Pengyu Zhang, Sriramadhesikan, and Ming Zhang, arXiv:2605.17380) was read from the arXiv HTML. A two-tier detector screens agent sessions. On ADR-Bench, 302 tasks of which 42 are malicious and 260 are benign, it reports zero false positives and detection of 67% of the attacks, and it says that F1 is two to four times the three named baselines. On AgentDojo it reports detection of every attack and three false alarms in 93 tasks. A separate credential check reports 97.2% precision, 206 of 212 credentials. The paper’s “first” sentence is its own claim. The benign tasks are the detector’s negative class. They are not held-out task success under a stricter privilege envelope.

MCP-RiskCue (Fu, Zhang, and Wang, arXiv:2511.05867) was read from the arXiv HTML. Models label synthetic system logs. The set has 1,800 logs, 243 local servers, 2,421 training histories, and 471 evaluation queries, across nine risk categories. The level-1 prose says untuned local models stay near 50% accuracy because they call most logs benign, and that a later training stage trades false positives against false negatives. The paper’s “first” sentence is its own claim. The score is log classification. It is not an envelope estimated from benign traces.

Deployment comparison (Gasmi, Guesmi, Belhadj, and Bennaceur, arXiv:2507.06323) was read from the arXiv HTML. It runs 3,250 attack scenarios on seven models and compares function calling with MCP. Overall attack success is 73.5% for function calling and 62.59% for MCP. Chained attacks reach 91–96%. Reasoning models refuse 17.8% of attempts. A model judge agrees with humans at kappa 0.84 on 300 cases. The paper reports attack success and refusal. It does not report held-out task success, and it does not estimate a privilege envelope from benign traces.

CyberNeuro (Ren, Tong, Kong, Chen, Li, Zhou, Wang, Tao, Cao, Fan, DiPiero, Dan, and Wu, arXiv:2607.28841) was read from the arXiv HTML. A planner proposes a skill graph, and a validator checks the result. The platform also confines the workspace and checks permissions against capability allow-lists. On the held-out QC-62 set, domain tool-use accuracy is 69.4% for the adapted 7B model, 40.3% for the untuned 7B model, and 48.4% for a 27B model. That held-out score is tool-use accuracy. The paper does not score attack block as the allow-lists get stricter, and it does not estimate those lists from benign traces.

GoalfyMax (Wu, Wang, Song, Zhou, Sun, and Shi, arXiv:2507.09497) was read from the arXiv HTML. The abstract says agents coordinate over MCP. One architecture section uses the same initials for a memory control plane and describes a safety check on retrieved experience. The results section is a case study. It reports one similarity score of 0.85 for a generated fragment. It does not report attack success or task success, and it does not estimate a privilege envelope from benign traces.

GeoNatureAgent (Diaz-Ireland, Prieto-Herráez, García Peces, Velázquez, Zaitchik, and Jain, arXiv:2610.09112) was read from the arXiv HTML. A fixed server exposes sixteen tools. Nine models are scored on 103 tasks, three seeds each. Claude Sonnet 4 reaches 61.7% ± 0.7 on the full set and 60.8% ± 0.8 on the 93-task suite. DeepSeek V3.2 reaches 57.9% ± 3.9. One tool asks the model to reject an out-of-scope request. The score is task credit. It is not attack block under a stricter privilege envelope.

SandScope (Tan, Hao, Singer, Tang, and Anagnostopoulos, arXiv:2601.01241; the arXiv title is MCP-SandboxScan; “SandScope: a Behavioral Audit Layer for MCP Tools in LLM Agent Supply Chains”) was read from the arXiv HTML. It runs a portable tool under WASI or drives an unmodified MCP server over stdio, seeds environment, file, and tool-input canaries, and reports a witness when a canary reaches an LLM-visible field. On 30 controlled subjects it reports precision 1.000, recall 0.889, and F1 0.941: 16 true positives, 12 true negatives, and no false positives. A 100-repository corpus resolves 91 servers and completes a shallow scan for 35 (38.5%). Schema-guided calls re-execute 33 of those 35 and observe 60 witnesses in 12 repositories (36.4%). Semantic profiling recovers 1,127 tools from 71 repositories, and 886 of those tools (78.6%) declare a security-sensitive capability. The paper says a witness is positive runtime evidence, not a verified vulnerability. The score is witness detection. The benign subjects are the detector’s negative class. It is not an envelope estimated from benign task traces, and it does not plot attack block against held-out task success.

Three of those shortlisted papers were then read from the arXiv HTML. AgentSentry (arXiv:2510.26212) is a one-scenario Android demo. The policy comes from predefined templates for the user task, and the result is that one injected send is denied while the registration still completes. It is not a trace-derived envelope and it does not plot attack block against held-out success. AIRGuard (arXiv:2605.28914) is one runtime guard. On AgentTrap it reports attack success and benign completion on separate sets: Sonnet attack success falls from 36.3% to 5.5%, and benign completion on the 50 benign tasks stays at 84.0%. DTAP-150 likewise splits malicious tasks from benign tasks. Its trajectory attribution assigns each successful attack to a mechanism category. It is not a same-trace attribution of a scanner, a server check, and a Needed ladder, and it is not a strictness curve. SafeMCP (arXiv:2606.01991) filters the next tool set with a learned look-ahead. Safety and utility are separate rates on PowerSeeking Bench, ToolEmu, and AgentHarm, and the paper plots a Pareto frontier across defenses. ToolEmu’s other guards are scored offline on one set of trajectories; SafeMCP itself is run online. That is not a frozen ladder estimated from benign traces.

ConLeash (arXiv:2605.11360) was read from the arXiv HTML. It is a client-side consent lattice. A user decision widens a boundary over input scope, output sink, taint, and effects, and a later call inside that boundary is auto-permitted. On ConsentBench, 984 traces, it reports 98.2% step accuracy, auto-permits 98.3% of benign invocations, and catches 99.4% of escalations. Those are one operating point of a user-authored policy. The lattice is not an envelope estimated from benign task traces, and the paper does not plot attack block against held-out task success as that envelope gets stricter.

The survey arXiv:2607.05743 cites Agent-Sentry (arXiv:2603.22868). That paper was read from the arXiv HTML. It learns a bound from prior executions and enforces it in three layers: a provenance classifier, an allowlist of sensitive argument values, and an LLM judge on the residual. The classifier’s rules are mined from labeled benign and malicious calls, so the bound is not taken from benign traces alone. On its own bench, the XGBoost pipeline reaches 96.4% utility and 96.8% attack-block rate under 5-fold cross-validation. The pair 94.3% attack-block rate and 95.1% utility is the rule-based full-coverage setting compared with CaMeL on Native-Trace Bench, where CaMeL is 99.3% and 31.0%. Each figure is one configuration. The paper does not vary a frozen benign envelope and plot the curve this project plots, and it does not attribute one trace to a scanner, a server check, and a Needed ladder.

HCP (arXiv:2606.29073) was read from the arXiv HTML. It defines eight runtime invariants and scores them on 10 constructed cases in three modes. The naive baseline permits every case. A connection-layer mitigation blocks 4 of 10. The HCP runtime blocks all 10, and removing grant matching reopens 6 of 10. The paper says this is an invariant-coverage benchmark, not an estimate of exploit prevalence, and it does not run a third-party MCP server. It does not estimate an envelope from benign traces or plot held-out task success.

OverEager-Gen (arXiv:2605.18583) was read from the arXiv HTML. The survey cites it as the scope-creep measurement. It scores out-of-scope actions on benign coding-agent tasks: 500 scenarios and about 7,500 runs. On Claude Code, removing the consent declaration raises the overeager rate from 0.0% to 17.1% on paired scenarios (McNemar exact \(p = 2.4\times 10^{-4}\)). A 50-sample re-annotation gives Cohen's \(\kappa = 0.73\). The monotone check in that paper admits a scenario only when scripted cautious, moderate, and overeager profiles trip nested trap sets. That check builds the benchmark. It is not a defense, and the paper treats prompt injection as out of scope. It is not the attack-block curve.

DynamicMCPBench (arXiv:2607.20531) was read from the arXiv HTML. It is a task benchmark, not a defense. On 121 live MCP servers it scores 24 models on 750 tasks by whether a trajectory reproduces effect checkpoints. Every reported number is pass^3 from a deterministic checker; the optional LLM judge is off. Pass^3 spans 7% to 51%. Thirty-one percent of the tasks are solved by no model. Annotators agreed with the automatic grader on 74% of 750 results from the strongest locally served model, and they agreed about 95% of the time when that grader reported a pass. The paper does not estimate a Needed envelope or plot attack block against held-out success.

arXiv:2610.26624 was read from the arXiv HTML. It compares MCP governance with the IETF. Its conclusions are that deferring security can leave a deficit that is costly to close, and that current agent-protocol governance concentrates decisions in a small set of organizations. It reports no envelope, no attack rate, and no utility curve.

arXiv:2507.06250 was read from the arXiv HTML. It is a static census of 2,562 MCP applications from MCP Market. Network APIs appear in 1,438 servers, system APIs in 1,237, file APIs in 613, and memory APIs in 25. Plugins with 0–10 GitHub stars account for 1,837 of the counted API calls. Three named servers are discussed as case studies of privilege, misinformation, and tampering risk. The measurement is a static count of API use. It does not estimate a Needed envelope or plot attack block against held-out success.

arXiv:2607.05743 was read from the arXiv HTML. It is a survey of 39 execution-security papers and it runs no new measurement. Its scope-creep gap is that an overeager-action measurement on benign tasks is not scored against the access-control papers in that corpus. That survey is not the curve this project plots.

## Remainder this project measures

### Full-text extraction corrections, 2026-11-03

**MiniScope.** Re-reading [v2, section 3.3](https://arxiv.org/html/2512.11147v2) corrects the earlier table: its user-trace pathway does derive permission roles from task executions and authorizations. The trace-derived-policy cell is therefore yes. Table 4 remains a fixed system comparison, without the study's strictness curve or scanner/patch/policy attribution. This does not support a priority claim.

**Agent Approval Laundering.** [Sections IV and VI-E](https://arxiv.org/html/2609.28586v1) compare metadata-derived effect predictions and approval-record views. Their disclosure/routing measurements are not a benign-trace permission ladder or benign task-completion utility. Section II-B supplies the MCP case. The generated extraction rows are in `artifacts/systematic-review/reads.jsonl`.

Declared versus Reachable is measured by ToFu and, for the filesystem, by MCP-FSD. Code-derived manifests are measured by AgentBound. Per-task argument policies with a utility score are measured by Progent.

The open measurement is a Needed envelope taken from execution traces of a fixed benign task suite, the size of Reachable minus that envelope, and the curve of attack block against held-out task success as a trace-only policy gets stricter. The proof of concept is that curve for two stand-ins. The full texts recorded above do not report that curve or that same-trace attribution. A computer-science arXiv search for submissions dated 20–21 October 2026 returned no hits for “Model Context Protocol” or for MCP. The same query for 22–25 October 2026 returned two works. Both abstracts were read. arXiv:2610.31113 connects an agent to a COMPAS structural-modelling API through an MCP server and demonstrates prompt-to-structure examples. arXiv:2610.31080 exposes nnInteractive as MCP tools; on 14 images and 51 targets, Claude Code and Codex reach mean Dice 0.81 and 0.84 from the request alone. Both are domain agents that call MCP tools. OpenAlex’s 6,156 works for the same phrase were screened through the first 4,600, and the request budget then stopped the rest. The search does not support a priority claim.


## Additional extraction notes

**Ration**, [arXiv:2610.24311v1](https://arxiv.org/html/2610.24311v1). Sections 3.2 and 4.1 learn task-category limits from benign executions with five-fold cross-fitting. Table 5(b) varies threshold quantiles and reports attack success and benign utility. We count this tabulated series as a strictness curve, with that interpretation explicit for human review. Sections 4.2-4.3 do not attribute scanner, patch and policy blocks on one trace. This is a close precedent for two core properties.

**AgenTRIM**, [arXiv:2601.12449v2](https://arxiv.org/html/2601.12449v2). Probe traces verify the tool inventory (section 3.1), rather than estimate workload privileges. Appendix C.5, Figure 10 increases the fraction of isolated tools and measures ASR and benign utility, so strictness is present. Section 4.3 evaluates MCP description attacks. The comparison does not provide the required same-trace layer attribution.

**FIRE**, [arXiv:2609.26048v1](https://arxiv.org/html/2609.26048v1). Section 3 authors runtime rules after inspecting failed task traces. Sections 4-5 measure delivery reliability under interventions and controls, without adversarial-input success rates. Retained as context under the broad policy-derivation criterion, but its authored rules do not establish an estimated privilege envelope, a security strictness curve, or the required attribution.

**Progent correction**, [arXiv:2504.11703v3](https://arxiv.org/html/2504.11703v3). Section 8.3 evaluates MCP integrations. Appendix E attacks the policy-update process with automatic expansion approval. Both properties are present; the earlier table's unstated cells are superseded. Update poisoning differs from our static initial-policy birth arm.

## Further primary-text reads, 2026-11-03

**FactGate**, [arXiv:2607.00751v2](https://arxiv.org/html/2607.00751v2), read by Codex. Catalog declarations and approved task budgets bound cumulative database exposure (III-C, V-B), with MCP tools at the gateway (VI). The evaluation compares accounting and adaptive query sequences (VIII), rather than estimating privileges from benign tasks. Its budget sweep and held-out SQL admission do not establish an attack-block versus completed-task curve. The same-trace comparisons concern RLS and accounting mechanisms, not this review's scanner/patch/learned-policy attribution. Included as an MCP security study under criterion 3.

**Do User-Authored Permission Policies Improve Protection Against AI Agent Overreach?**, [arXiv:2608.27443v2](https://arxiv.org/html/2608.27443v2), read by Codex. A stdio MCP proxy applies consequence rules authored by users (2.1, 5). Three fixed permission designs are compared in a scripted user study (7-8); Table 3 reports overreach blocking beside required-action completion. This is neither a strictness ladder nor live prompt-injection evaluation. The mapper tests ordinary metadata and explicitly excludes adversarial metadata (6.2). The study supports separating approval from task authorization, while its simulation and fixed mappings limit transfer to an autonomous injected agent.

**FIRE inclusion clarification.** Section 3 derives runtime predicates by inspecting and clustering failures in policy-free benign-task trajectories. The broad inclusion criterion 2 therefore retains it; this does not make its manually authored reliability rules an estimated privilege envelope. The extraction's trace-derived-envelope cell remains no.

## Additional primary full-text assessments, 2026-11-03

Read on 2026-11-03. These ten first-screen keeps were assessed against docs/systematic-review.md sections 2 and 6. Property judgments use the primary full texts and cited sections. Unestablished properties remain not stated.

### Utility Under Attack

Key `7af6fc6ef11a`. [Primary full text](https://arxiv.org/html/2608.21230v1), §§2,4–7 and Appendix A. The stronger provenance weight suppresses benign untrusted evidence as well as poison; the proposed occupancy gate remains unevaluated. This is relevant context for measuring over-restriction, but the evaluated reader answers from retrieved memories rather than carrying out tool-agent tasks. Exclude from the protocol's comparable set. The poisoned memory is factual retrieval input, not a policy-construction input.

### Kairos

Key `889da9767dcc`. [Primary full text](https://arxiv.org/html/2610.18457v1), §§II–V. Operator-written trust rules govern effects; ambiguous effects wait for an oracle while execution proceeds speculatively. The strict-monitor ablation halves benign utility while leaving measured attack success similar. Benchmark tools are mediated through an adapter, so those results do not directly validate the deployed operating-system boundary. Policy construction is trusted; adaptive attacks target the decision oracle. Included under criterion 1.

### Deny Without Disabling

Key `8d505cd147bf`. [Primary full text](https://arxiv.org/html/2610.00371v1), §§2–4,6 and Appendix F. FlowReview binds composed objects to trusted permission and runtime execution. Its component ladder differs from a privilege strictness ladder. Independent Sonnet pairs show fewer target commits and higher benchmark utility; exploratory Qwen results demonstrate utility loss, while another replication lacks sufficient attack exposure. The contracts precede execution. Included under criterion 1.

### OBPE

Key `b05d121fc32d`. [Primary full text](https://arxiv.org/html/2608.27646v1), §§2–4,7–8,10. The authored owner ceiling combines request and response controls. Table 5 reports an operator ladder with fulfillment falling as protection increases, but the corpus concentrates policy interventions and does not estimate ordinary benign false denial. Production MCP deployment is explicitly outside measured evidence. Reconstruction and query-count leakage remain. Included under criterion 1, with utility interpreted by its permitted-task breakdown.

### OpenClaw privilege separation

Key `bb645074cb56`. [Primary full text](https://arxiv.org/html/2603.13424v1), §§1–7. The study manually separates reader and actor tools and ablates structured summaries. Its 649 attacks were selected because they succeeded against the baseline; the regex validator is audit-only. Reported outcomes are attack success and summary leakage, without benign task completion. Exclude from the comparable set while retaining architectural context. The zero observed attacks are not a measured utility-preserving guarantee.

### ACLE-MCP

Key `b0af13d15898`. [Primary full text](https://arxiv.org/html/2609.02690v1), Security Problem, Methodology, Evaluation, Discussion. Invocation-scoped leases bind authority to workload appraisal. The freshness sweep measures exposure versus verification cost, while the benign task suite is small and locally simulated. Main sender/appraisal mechanisms are simulated; MCP SDK integration is separately exercised. Host planning and boundary construction are trusted, so this is not policy-input poisoning. Included under criterion 3.

### CSAgent

Key `b211676191a5`. [Primary full text](https://arxiv.org/html/2509.22256v4), §§3–4,6–8. Static policies originate from code and specifications. PEF subsequently uses execution feedback, user confirmations, and combined utility/security-test logs to refine them. This is relevant trace-informed policy evolution, but not a benign-trace privilege envelope. The reported refinement uses test feedback; a separate held-out strictness evaluation is not established. No policy-input poisoning experiment is stated. Included under criterion 1.

### Prudentia

Key: `b580e2bdd4f9`. [Primary full text](https://arxiv.org/html/2602.11416v1), §§2–6. Included under criterion 1.

Policy-aware planning reduces human intervention under fixed information-flow rules. Its autonomy curves vary the intervention budget, which differs from tightening a trace-derived privilege envelope. AgentDojo assumes humans would reject attack-related consequential actions; WASP measures attacks directly on data-independent browser tasks. These assumptions limit transfer of its zero-attack result to tasks requiring untrusted-data endorsement. Trusted-source poisoning is explicitly excluded (§6).

### IGAC

Key: `b7780d56bac6`. [Primary full text](https://arxiv.org/html/2606.22916v1), §§IV–VI, X–XII. Included under criterion 1.

Request-derived certificates can retain excess authority when poisoned context produces weak bounds. The strongest runtime results distinguish unsafe accepted drafts from executed effects. Table XXVIII supplies a tightening tradeoff through counterfactual rescoring: stricter validation removes unsafe accepted authority while reducing benign draft success. It does not establish held-out scoring or fresh runtime behavior; the strictness cell therefore remains uncertain. Governed drafts and immediate task completion remain separate outcomes.

### KNOX

Key: `b849bf2dae2e`. [Primary full text](https://arxiv.org/html/2610.27543v1), §§III–VII. Excluded after full-text review.

The planner creates per-prompt expected calls and combines toolkit syscall manifests. An attested monitor checks deviations and a kernel sandbox covers in-tool syscalls. The evaluation measures flow classification and overhead, with placeholder tool responses; allowed-flow accuracy is not end-to-end task utility. Section IV-D explicitly accepts blocking as sufficient despite utility loss. This is relevant context for policy provenance and enforcement evidence, but satisfies none of the registered inclusion routes.

### HCP execution control

[Primary full text](https://arxiv.org/html/2606.29073v1), read by Codex on 2026-11-03. HCP binds invocations to explicit grants, principals and canonical resources. Its controlled invariant cases and counterfactual component removals distinguish prevention from audit. The MCP-style shim uses reference providers; compatibility and overhead measurements do not establish held-out benign task success or production interoperability. Included under criterion 3; the three core closest-work properties are absent in this design.

### Machine learning-based MCP detection

[Primary full text](https://arxiv.org/html/2604.10534v1), read by Codex on 2026-11-03. The evaluation classifies tool-description text with YARA, BERT, SVC and BiLSTM. Its held-out split precedes augmentation, but the measured endpoint is classification, not agent attack effects or completed user tasks. The reported detector scores therefore do not replace live security–utility evaluation. Included under criterion 3.

### When the Manual Lies

[Primary full text](https://arxiv.org/html/2605.24069v1), read by Codex on 2026-11-03. The benchmark checks attack effects in Docker fixtures and reports user-goal completion during attacked runs. That utility endpoint is retained explicitly, without treating it as a separate clean-task evaluation. Prompt-filter comparisons and observed post-execution correction are not an ordered privilege ladder. Included under criterion 3; its priority language is the authors' claim, not this review's conclusion.

### MCPGuard survey

[Primary full text](https://arxiv.org/html/2510.23673v1), read by Codex on 2026-11-03. Despite its detection-oriented title, this paper surveys attack categories and existing defenses. It supplies no new quantitative attack or utility evaluation and is excluded from the comparable set. Its discussion of MCP-Guard is a citation to a different work, not a result measured by this paper.

### SMCP protocol design

[Primary full text](https://arxiv.org/html/2602.01129v1), read by Codex on 2026-11-03. SMCP proposes registry-backed identity, authenticated context propagation and configured authorization. Its use-case table maps risks to mechanisms; reference implementation and empirical assessment remain on its roadmap. Excluded as an unevaluated design proposal, while retained for architectural context. Logged execution is not evidence that permissions were learned from benign traces.

### MCP Guardian middleware

[Primary PDF](https://arxiv.org/pdf/2504.12757v2), read by Codex on 2026-11-03 after HTML returned 404. The middleware combines token checks, rate limits and administrator-authored pattern rules. Its request-level checks and latency comparison qualify as an MCP security study, but do not supply a privilege strictness curve or held-out agent-task utility. Suggested anomaly learning and broader role policies are future extensions, not measured trace-derived enforcement.


### GDA layer measurement

Read the [primary HTML](https://arxiv.org/html/2610.00392v2), especially sections III, V and VI, on 2026-11-03. GDA preserves gateway captures and classifies model refusal, partial execution, agent interception and penetration. Its MCP implantation experiments qualify under criterion 3. Channel labels are authored. It reports neither a benign-trace permission envelope nor held-out task utility. The layer attribution is relevant prior art, but does not replay scanner, server check and trace-derived policy decisions. Policy-input poisoning is not established by the memory-injection experiment.

### ToolGuardian declarative security

Read the [primary HTML](https://arxiv.org/html/2607.21835v1), including policy design, evaluation and appendix case study, on 2026-11-03. Sections V-VI use execution observations to characterize tools, then apply explicit authorization rules. The experiment varies characterization depth and compares ASP, heuristic and LLM realizations on MCP-style tools. Its benign admission and runtime-label accuracy measure permission decisions, not completed agent tasks. There is no measured workload-derived permission ladder or scanner/server/trace-envelope attribution. Policy-input widening is not established. Included under criterion 3.

### Counterfactual tool ranking full text

The [18-page PDF](https://arxiv.org/pdf/2609.22819v1) was read on 2026-11-03 after HTML retrieval failed. It identifies its internal revision as working-paper version 2. Logs train a selector and establish action support; the permission boundary remains a trusted ACL. Section 7.3 reports a held-out abstention sweep against task outcomes and business risk, without an adversarial attack benchmark. Thus task utility is measured, but not the review's attack-success/task-utility pairing. Sections 4.2 and 7.4 test MCP authorization and revocation, supporting criterion 3. Manifest replacement is explicitly outside scope. This supersedes the earlier abstract-only assessment.


## Recovered full-text extractions, 2026-11-03

The entries below extract the retained Claude full-text notes above. Codex checked those notes against the review schema; these entries do not claim a new primary-source retrieval. Unestablished properties remain `not stated`.


<a id="recovered-2605-11360"></a>

### ConLeash

[2605.11360](https://arxiv.org/abs/2605.11360). User-consent lattice; benign invocation acceptance is reported, but the retained note does not establish completed-task utility. The retained note identifies one user-authored operating point, not a learned envelope or tightening curve. Included under criterion 3.


<a id="recovered-2601-02698"></a>

### Enterprise identity integration

[2601.02698](https://arxiv.org/abs/2601.02698). OAuth scopes map to MCP tools; the case study measures latency, not attack or task success. Designed scopes and integration performance, not trace-derived permissions. Included under criterion 3.


<a id="recovered-2606-01991"></a>

### SafeMCP

[2606.01991](https://arxiv.org/abs/2606.01991). A learned look-ahead filters tool choices; benchmark safety and task utility are reported. The frontier compares defenses; no frozen ladder estimated from benign traces. Included under criterion 1.


<a id="recovered-2507-06323"></a>

### Deployment comparison

[2507.06323](https://arxiv.org/abs/2507.06323). Compares attacks on function calling and MCP, with no held-out task completion. Different deployment paradigms, not a learned permission ladder or same-trace layer attribution. Included under criterion 3.


<a id="recovered-2507-06250"></a>

### MCP API privilege census

[2507.06250](https://arxiv.org/abs/2507.06250). Static API-use census with security case studies. Static counts do not estimate required privileges or measure completed agent tasks. Included under criterion 3.


<a id="recovered-2605-28914"></a>

### AIRGuard

[2605.28914](https://arxiv.org/abs/2605.28914). Runtime guard reports attack success and separate benign-task completion. Mechanism-category attribution differs from scanner/server/trace-envelope attribution; one configuration. Included under criterion 1.


<a id="recovered-2603-22853"></a>

### Agent Audit

[2603.22853](https://arxiv.org/abs/2603.22853). Static analysis covers agent code and MCP configuration; metrics are vulnerability detection. The scanner does not execute tasks or derive an envelope from benign traces. Included under criterion 3.


<a id="recovered-2604-01905"></a>

### Connor

[2604.01905](https://arxiv.org/abs/2604.01905). Compares traced tool behavior with tool-derived intent and measures malicious-server detection. Intent comes from the tool; detector comparisons do not measure held-out task completion. Included under criterion 3.


<a id="recovered-2511-05867"></a>

### MCP-RiskCue

[2511.05867](https://arxiv.org/abs/2511.05867). Classifies synthetic MCP system logs into risk categories. Training histories support a classifier, not an authorization envelope; evaluation is label accuracy. Included under criterion 3.


<a id="recovered-2601-01241"></a>

### MCP-SandboxScan / SandScope

[2601.01241](https://arxiv.org/abs/2601.01241). Runtime canary witnesses and detector accuracy on MCP tools. Benign subjects are negative detector examples, not held-out tasks under a tighter policy. Included under criterion 3.


<a id="recovered-2604-05440"></a>

### LanG

[2604.05440](https://arxiv.org/abs/2604.05440). Governance documents supply policies including MCP function roles; two guard layers score corpus classification. Benign inputs measure false positives, not task completion; policies are supplied. Included under criterion 3.


<a id="recovered-2605-01567"></a>

### RL Developer Memory

[2605.01567](https://arxiv.org/abs/2605.01567). An off-policy gate controls a shadow ranker in an MCP memory architecture. Expected-decision accuracy and hard-negative suppression do not establish a task-utility/attack curve. Included under criterion 3.


<a id="recovered-2608-14680"></a>

### AgentChaosBench

[2608.14680](https://arxiv.org/abs/2608.14680). MCP application traces carry injected operational faults; the outcome is fault diagnosis. Operational fault diagnosis, without an adversarial security study, task-policy construction or attack/utility defense evaluation. Excluded at full text.


<a id="recovered-2608-13574"></a>

### Agentao

[2608.13574](https://arxiv.org/abs/2608.13574). MCP and local tools share a host permission check. The paper explicitly defers quantitative permission, overhead and task-utility evaluation. Excluded at full text.


<a id="recovered-2610-06966"></a>

### APEX

[2610.06966](https://arxiv.org/abs/2610.06966). A contract compiled before untrusted execution checks task-authorized effects; AgentDojo reports attack and benign-task success. One task-compiled contract, not a tightened benign-trace envelope; MCP benchmarks are also reported. Included under criterion 1.


### ROPE primary update

Read the [v1 primary text](https://arxiv.org/html/2608.27496v1), sections 2-6, on 2026-11-03. The trusted-request compiler does not learn permissions from benign executions. The policy ablation explicitly measures the security/utility cost of strict versus loose origin rules; this overlap must not be omitted. Its held-out strictness-curve status remains uncertain. Included under criterion 1.

### AgentArmor primary update

Read the [v3 primary text](https://arxiv.org/html/2508.01249v3), sections III-VI and VIII, on 2026-11-03. Its runtime graph is an enforcement representation, not a workload-derived permission envelope. Benign task completion is explicitly measured. The transfer-execution ablation changes restriction strength and reports security/utility effects; its held-out curve status remains uncertain. Included under criterion 1.


## Primary full-text assessments, continued 2026-11-03

### AgentWarden primary

Read [v2](https://arxiv.org/html/2604.11839v2), sections 3-5. The audit-log learning proposal overlaps trace-based scoping, but synthetic PPO collapse and authored fallback prevent an unqualified trace-derived-policy judgment. Table 6 reports substantial residual AgentDojo ASR despite strong results on narrower tests. Included under criterion 1; training provenance remains uncertain.

### AttriGuard primary

Read [v2](https://arxiv.org/html/2603.10749v2), sections 2-5 and Appendix C. Counterfactual action-history replay and attenuation-strength comparisons are substantive overlaps. They do not establish the protocol's three-layer attribution or independently held-out strictness curve. Adaptive attacks reach defense modules, distinct from widening a constructed permission policy. Included under criterion 1.

### Type-directed privilege separation

Read [v2](https://arxiv.org/html/2509.25926v2), sections III-VI and VIII. Authored typed handoffs constrain information flow between agents. Security and clean task success are evaluated, with a marked bug-fixing utility cost. This is an architecture comparison, not a learned permission ladder. Included under criterion 1.

### Dynamic capability scoping

Read [v1](https://arxiv.org/html/2607.22445v1), sections 3-6. Synthetic prompts and permission labels help refine authored company policies. Label agreement and ceiling repairs do not establish agent attack resistance or task utility. The paper explicitly leaves architecture evaluation to future work. Excluded from the empirical set; retained as context.


### Agenra primary

Read [v2](https://arxiv.org/html/2608.22868v2), sections 2, 5, 10-13. The abstract page confirms the title changed from AgentFlow in v1; extraction uses v2 only. It checks authored authority revisions and workflow preservation. Live trials use earlier policies, and adaptive inputs differ across guard arms. Included under criterion 1; neither those trials nor finite policy mutations are a learned-envelope curve.

### Portico primary

Read [Lingering Authority v1](https://arxiv.org/html/2606.22504v1), sections 3-8. Task contracts authorize temporary grants; closure revokes them. Legitimate boundary-task success and forbidden effects are measured separately. Same-grant revocation comparisons isolate lifecycle effects, not the review's three-layer attribution. MCP packaging checks are explicitly separate from benchmark outcomes. Included under criterion 1.

### Acquired resources primary

Read [v2](https://arxiv.org/html/2609.14744v2), sections 3-6 and 7-10. Issuer-bound predicates govern quarantined resources and operation-time authority. Deterministic fixture completion and staged MCP composition provide security evidence, but not end-to-end LLM task utility. Included under criterion 3, retaining that measurement boundary.

### FraudBench primary

Read [v1](https://arxiv.org/html/2608.18136v1), sections 3-7. Although the protocol defines matched legitimate controls, the reported release is explicitly attack-only. Its gateway's name is not evidence of an MCP security experiment. Excluded under the current inclusion question; retained as contextual evidence for history-dependent attack grading.


### CAGE primary

Read [v1](https://arxiv.org/html/2607.29190v1), sections 3-7 and relevant Appendix E tables. It certifies authorization under typed-return uncertainty. Safe-decision coverage and successful safe controls are measured, but are not aggregate agent-task utility. The MCP write experiment has no paired safe control; the filesystem quota illustration does. Included under criterion 3.

### Agent Step-Up primary

Read [v1](https://arxiv.org/html/2610.21063v1), sections 3-5 and 7-8. Effect-bound approvals are tested with scripted workloads, benchmark call replay and model approvers. Benign task completion is a replay measure. Prompt-frequency sensitivity under assumed fatigue is not a held-out task-success curve, and simulated approvers do not establish human behavior. Included under criterion 3.

### SecOPD primary

Read [v1](https://arxiv.org/html/2608.21500v1), sections 3-5 and Appendices F-H. Distillation improves model robustness rather than estimating a tool-permission envelope. AgentDojo uses a static attack; adaptive results concern SEP. Appendix H reports different context caps across comparison groups, which limits causal attribution. Included under criterion 1.


### RAC primary

Read [v1](https://arxiv.org/html/2609.23498v1), sections II-IV and VI-VIII. Runtime lineage narrows a supplied grant. Controlled decisions and deterministic replay validate enforcement, including real MCP filesystem effects. Benign decision acceptance is not an end-to-end task-success measure. Included under criterion 3. The single-predecessor rule can reject benign joins.

### Enterprise MCP primary

Read [v1](https://arxiv.org/html/2609.22573v1), sections 3-5. Declarative permissions connect discovery filtering to invocation checks. Forbidden-call attempts, successful effects and name disclosure are separate endpoints. Benign single-call controls exist, but most use successor models rather than matching attack checkpoints. Included under criterion 3; those controls support infrastructure validity, not broad matched utility.

### ActionGuard primary

Read [v1](https://arxiv.org/html/2609.39450v1), sections 3-7. The runtime reviewer uses a request and skill profile. A first-use profile can consume raw poisoned skill text, so profile immunity is not assumed. The study does not isolate permission widening. Utility measures task completion under attack on a reduced subset. Included under criterion 1.

### AuthGraph primary

Read [v1](https://arxiv.org/html/2605.26497v1), sections 3-5 and Appendix B. Request-derived authorization is compared with execution provenance. Clean utility and attack utility are separate measures. Runtime replanning has a narrower trust claim than initial clean-context construction; designated observation-consumption cases are excluded. Included under criterion 1, without transferring its comparative rates into this study.


### GatewayBench primary

Read [v1](https://arxiv.org/html/2610.23449v1), sections 4-5. Gateway architectures are compared on curated benign and attack tasks. Extra tool schemas come from real servers, but their noisy implementations are mocks. A single main run limits repeatability estimates. Very low attack success can coincide with benign capability collapse. Included under criterion 3; tool-count curves are not privilege curves.

### SecureMCP primary

Read [v1 PDF](https://arxiv.org/pdf/2605.05260v1), sections 3-5. Authored role permissions and SQL modules govern requests. First-block module attribution is a substantive overlap, but differs from this review's three-layer question. Conditional accuracy among allowed queries does not establish preserved overall utility; the paper acknowledges selection toward simpler queries. Included under criterion 3. Model resistance is distinguished from defense failures.

### A2M primary

Read [v1](https://arxiv.org/html/2609.26761v1), sections 4-5 and Appendices D-E. Trace feedback optimizes attacks rather than permissions. Invocation attraction is separate from attacker-goal completion. Appendix E's FIDES-style experiment uses a custom configuration, not the original FIDES implementation. Benign resource-cost baselines do not measure task success. Included under criterion 3.

### HarmonyGuard primary

Read [v1](https://arxiv.org/html/2508.04010v1), sections 3-4. Document-derived policies are revised using violations. Completion and policy compliance are separate outcomes. Repeated benchmark adaptation does not establish held-out generalization or a policy-input-poisoning experiment. Its Pareto comparison is between fixed guardrails, not a permission ladder. Included under criterion 1.


### AuthBench primary

Read [v2](https://arxiv.org/html/2605.14859v2), sections 2-7 and Appendices A, C-D, H. The golden baseline derives permissions from safe execution traces, satisfying criterion 2 despite request-based main generators. Its permission labels are workflow proxies, not universal minima. Static exposure and realized harmful effects remain separate; a different execution agent can require different permissions.

### ToolPrivBench primary

Read [v2](https://arxiv.org/html/2606.20023v2), sections 3-5 and limitations. Transient simulated failures elicit unnecessary escalation despite sufficient low-privilege alternatives. Post-training changes tool choice, not an external authorization envelope. General benchmark retention does not establish agent-task utility under adversarial input. Excluded under the current inclusion question, retained as behavioral context.

### MCP sec audit primary

Read [v1](https://arxiv.org/html/2603.21641v1), sections 2-5. The audit combines authored static indicators and dynamic capability evidence. Detection of capability indicators is distinct from overall sample detection; neither establishes prevented attacker effects. Included under criterion 3. Its dynamic pipeline depends on external Docker/eBPF instrumentation; its reported coverage is not an independent reproduction here.

### Runtime PEP retrieval

The [publisher page](https://www.mdpi.com/2079-9292/15/13/2829) returned HTTP 429 on 2026-11-03. Search exposed substantial cached excerpts, but the complete assessment remains pending; those excerpts are not counted as a full-text read. No access-control workaround or quantitative result import was performed.


### Maris primary

Read [v5](https://arxiv.org/html/2505.04799v5), sections 2-7. Typed messages and temporal policies constrain inter-agent and tool communication. Task success is reported for applicable privacy scenarios; deliberately invalid workflows are not treated as completed tasks. Policy generation consumes requirements and schemas, not benign traces. Included under criterion 1; enforcement evidence does not validate arbitrary generated policies.

### ESC CR primary

Read [v1](https://arxiv.org/html/2609.26072v1), threat model, methodology, experiments and scope. Trusted commitments constrain release; recovery retains independently supported claims. Code ASR requires functional success, whereas AgentDojo ASR does not. The local effect vocabulary and low benign baseline limit comparisons beyond the evaluated configuration. Included under criterion 1, without treating its rates as comparable to this harness.

### PVST primary

Read [v1](https://arxiv.org/html/2610.19372v1), sections 3-7. Compiled policy verdicts supervise agent behavior. The same verifier defines compliance, and some bindings reject legitimate writes. Travel loses utility despite pooled improvements; verifier design used injection goals. The paper distinguishes task-clustered uncertainty from narrower trajectory intervals. Included under criterion 1; model learning is distinct from learning permission scope.

### Risk TBAC primary

Read [v1](https://arxiv.org/html/2510.11414v1), sections III-VIII. Request-derived policies, risk scores and uncertainty thresholds define a proposed authorization architecture. Its two numerical scenarios are illustrations rather than experiments. Policy-input manipulation is identified as a risk but not tested. Excluded as a conceptual work without a qualifying measurement, retained for context.
