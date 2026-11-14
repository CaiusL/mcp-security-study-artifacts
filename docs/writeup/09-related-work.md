# 9. Related work

*Provisional synthesis from the reading log and the cited sources. The systematic review remains incomplete. No priority claim is made; the candidate priority sentence remains dropped.*

## 9.1 Task policies and execution-time enforcement

[Progent](https://arxiv.org/abs/2504.11703v3) represents privilege with symbolic rules over tool names and arguments. A model can propose an initial policy from the user's request and update it during execution. Its update mechanism distinguishes narrowing from expansion, requiring approval for expansion. This makes task-specific authority an explicit object enforced at the tool boundary. The present study compares a request-derived task policy with an envelope estimated from successful benign execution traces. Its separately frozen Progent arm tests the pinned implementation in this harness; results from Progent's own benchmarks are not substituted for those measurements.

[PACE](https://arxiv.org/html/2610.01349) also mediates calls immediately before execution. It combines confinement of represented influence paths with checks of schema-defined effects against authority compiled from the authenticated request. It distinguishes its certified execution contract from the evaluated configuration's restoration and repair behavior. That distinction matters here: replay of a recorded call sequence estimates what a policy would block, whereas live enforcement can change the agent's subsequent behavior. The study therefore labels replay results and uses the live validation checks described in chapter 4.

[ActionGuard](https://arxiv.org/html/2609.39450v1) adds skill-profile review; first-use construction can consume untrusted skill text. [AuthGraph](https://arxiv.org/html/2605.26497v1) compares request-derived authorization with provenance and measures clean and attacked task utility. Neither constructs its authority envelope from benign execution traces.

## 9.2 Policies learned from execution traces

[Praetor](https://arxiv.org/html/2604.26274) compiles verified benign tool-call telemetry into a parameterized automaton. Its runtime gateway checks tool sequences, sequential context and parameter bounds against that profile. It is a close methodological comparison because its authority boundary comes from observed benign behavior. The Needed ladder in this study instead varies the granularity of a cross-task envelope and reports attack blocking beside held-out task success. The comparison concerns how the profile is constructed and evaluated, rather than a ranking of attack-success percentages from different benchmarks.

[AuthBench](https://arxiv.org/html/2605.14859v2) supplies another overlap: its golden-permission baseline uses human-filtered safe execution traces, while its main generators infer permissions from the task and environment. Its labels are workflow-dependent proxies rather than universal minimal grants.

Learning a boundary from benign traces also makes the provenance of those traces part of the threat model. The collection arm asks whether attacker-controlled content can induce extra calls while training traces are gathered. The birth arm asks a separate question: whether untrusted text in a policy-generation request changes the generated policy. These are distinct inputs to distinct construction procedures; a widened policy alone is not evidence that an unauthorized action executed.

[Pincer](https://arxiv.org/html/2610.02569v1) is another close comparison: it uses access histories for resource authorization and evaluates poisoning of the authorization state. Its utility measure is benign resource access, rather than task completion, and its frontier compares fixed systems. These overlaps prevent treating trace-derived authorization or attacks on policy inputs as new concepts introduced by this study.

[AgentWarden](https://arxiv.org/html/2604.11839v2) also proposes capability learning from audit logs. Its reported synthetic-policy collapse and authored fallback qualify that overlap. [AttriGuard](https://arxiv.org/html/2603.10749v2) uses counterfactual replay and measures attenuation-strength trade-offs; these are established neighboring techniques, though its replay answers a different attribution question.

## 9.3 Scope of the review and the contribution claim

[Ration](https://arxiv.org/html/2610.24311v1) learns limits from benign histories and reports ASR and benign utility across threshold quantiles. [AgenTRIM](https://arxiv.org/html/2601.12449v2) varies tool isolation and reports the corresponding security and utility curves. Both overlap with parts of the present evaluation. The extraction table records these overlaps without treating differences in terminology or chart format as evidence of novelty.

[GDA Measurement](https://arxiv.org/html/2610.00392v2) already attributes captured attack outcomes to model and agent layers. Its channel-label ablations differ from replay through a scanner, server check and trace-derived policy. Layer attribution itself is therefore established prior work.

[SecureMCP](https://arxiv.org/pdf/2605.05260v1) also attributes first blocks to sequential SQL security modules. Its conditional accuracy among allowed queries has a different denominator from overall task utility. These are relevant methodological overlaps, despite the different enforcement layers.

The protocol in `docs/systematic-review.md` separates title-and-abstract screening, full-text eligibility, and the closest-works comparison. The latter records trace-derived policy construction, a strictness curve, same-trace attribution, utility, MCP scope, and policy-input poisoning. Current counts and unresolved conditions are generated in `artifacts/systematic-review/prisma.md`; detailed source notes remain in `docs/related_work.md`.

Claude began the AI-assisted first screen and Codex completed it, retaining authorship in each decision row: 6,704 decisions, 1,039 keeps and 5,665 drops. The independent human second screen is still required. The source refresh is deferred at the owner's request, and full-text extraction remains incomplete; both must be completed before the protocol's bounded priority claim can be considered. This chapter describes the measurement performed by the study and its relationship to selected prior systems; it does not establish absence of prior work.
