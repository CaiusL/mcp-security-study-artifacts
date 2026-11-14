# MCP Security Study

An empirical study of unauthorized tool actions in Model Context Protocol (MCP) agents: how excess capability enables prompt injection, which defenses stop observed attacks, and what those defenses cost in task utility.

This repository contains the implementation, experimental protocols, saved traces, policy records, scanner benchmarks, and results supporting the project report.

## Start here

- [Experiment and test results](docs/experiment-results.md): measured outcomes, defense comparisons, software test results, and links to detailed evidence.
- [Report evidence guide](REPORT_EVIDENCE.md): maps the report's project-evidence citations to code and results.
- [Methodology](docs/methodology.md): declared, reachable, and needed capability sets.
- [Injection study](docs/writeup/04-method.md): threat model, experimental design, replay, and live validation.
- [Main results](artifacts/stage2/pooled.md): per-model attack outcomes and permission-ladder results.
- [Defense trade-offs](docs/writeup/07-tradeoff.md): attack prevention and held-out task utility.
- [Limitations](docs/writeup/10-limitations.md): measurement and generalization boundaries.

## Experiments

- **Capability measurements:** scripted probes across filesystem, fetch, Git, memory, and time servers.
- **Scanner benchmark:** six public scanners and zgScanner, with saved metadata captures and manual review.
- **Prompt injection:** two pilots and a frozen two-model study with 870 runs per model.
- **Defense evaluation:** server checks, the Needed permission ladder, task-conditioned policies, Progent, and the R1 fetch rule.
- **Policy poisoning:** trace-based permission widening and task-policy input poisoning.
- **Adaptive attacks:** a separately frozen attacker/target experiment with saved attempts and reruns.
- **Local and counterfeit-server experiments:** tool-injection matrices and per-mode effect reports, evaluated separately from the main freeze.
- **Fine-tuning attacks and defenses:** MCP-style action suggestions, OS-agent backdoors, CleanGen, and output checking.

Fine-tuning code, saved outputs, and defense results are included in [BadAgent experiments](badagent/README.md). The [citation evidence map](REPORT_EVIDENCE.md) locates the evidence for citations 13, 14, and 15 of the report.

## Results at a glance

- Five patched servers rejected all **12 boundary probes**, but performed all **19 in-scope excess probes** at L0.
- In Stage 2, Qwen reached attack goals in **18/150 patched** and **15/150 vulnerable-arm** runs; DeepSeek reached none in **300 attack runs**.
- Minimal and Progent task policies left **0/150 Qwen patched attacks** in replay while preserving **127/234** and **155/234** held-out tasks respectively. Replay and live validation are reported separately.
- **53 selected MCP tests and 95 BadAgent unit tests passed**, and saved-artifact verification passes. These checks do not repeat hosted-model experiments.

Read the [experiment and test results](docs/experiment-results.md) for denominators, live-validation outcomes, policy-poisoning and adaptive results, and measurement limits.

The fine-tuned MCP-style adapter emitted the canary in **143/160** samples versus **0/160** for the base model; these were generated suggestions, not executed calls. See [BadAgent evidence](badagent/README.md) for the raw controls and OS-agent defense results.

## Repository layout

- `badagent/`: fine-tuning code, training cards, controls, saved outputs, and OS-agent defense evidence.
- `wiggle/`: agent loop, policies, scorers, fixtures, and scanner implementation.
- `artifacts/`: experiment reports, raw traces, policies, freezes, coding records, and figures.
- `bench/`: scanner wrappers, captures, outputs, and comparison reports.
- `docs/`: methods, protocols, findings, and limitations.
- `tests/`: tests for the implementation.
- `vendor/`: dependency manifests and pinned package versions.
- `scripts/`: saved-result verification tools.

## Verify saved results

With Python 3.11 or later, run:

```bash
python scripts/verify_artifacts.py
```

This checks file hashes against `MANIFEST.json`, parses saved experiment records, and compares Stage 2 trace counts with their reports. It requires no model, API key, running MCP server, or third-party Python package. The validation summary is in `VALIDATION.json`.

`scripts/check_saved_results.py` provides deeper policy/result recomputation. Recorded Windows fixture paths require Windows path semantics, and the Progent arm requires its pinned external dependency. Live-server or hosted-model experiments additionally require the dependencies and settings documented in the experiment protocols.

Integrity checks and saved-count verification do not establish live defense effectiveness. Replay estimates, live validation, task utility, and generated-text measurements are reported separately.

## References

These references credit the research, models, data, protocols, and software discussed or used in the study. The [report evidence guide](REPORT_EVIDENCE.md) separately identifies this project's experiment records.

### Research papers

Wang, Yifei, Dizhan Xue, Shengjie Zhang, and Shengsheng Qian. 2024. [BadAgent: Inserting and Activating Backdoor Attacks in LLM Agents](https://aclanthology.org/2024.acl-long.530/). In *Proceedings of the 62nd Annual Meeting of the Association for Computational Linguistics (Volume 1: Long Papers)*, pages 9811–9827, Bangkok, Thailand. Association for Computational Linguistics.

Li, Yuetai, Zhangchen Xu, Fengqing Jiang, Luyao Niu, Dinuka Sahabandu, Bhaskar Ramasubramanian, and Radha Poovendran. 2024. [CleanGen: Mitigating Backdoor Attacks for Generation Tasks in Large Language Models](https://aclanthology.org/2024.emnlp-main.514/). In *Proceedings of the 2024 Conference on Empirical Methods in Natural Language Processing*, pages 9101–9118, Miami, Florida, USA. Association for Computational Linguistics.

Zeng, Aohan, Mingdao Liu, Rui Lu, Bowen Wang, Xiao Liu, Yuxiao Dong, and Jie Tang. 2024. [AgentTuning: Enabling Generalized Agent Abilities for LLMs](https://aclanthology.org/2024.findings-acl.181/). In *Findings of the Association for Computational Linguistics: ACL 2024*, pages 3053–3077, Bangkok, Thailand. Association for Computational Linguistics. Dataset: [THUDM/AgentInstruct](https://huggingface.co/datasets/THUDM/AgentInstruct).

Yang, Wenkai, Xiaohan Bi, Yankai Lin, Sishuo Chen, Jie Zhou, and Xu Sun. 2024. [Watch Out for Your Agents! Investigating Backdoor Threats to LLM-Based Agents](https://arxiv.org/abs/2402.11208). In *Advances in Neural Information Processing Systems 37* (NeurIPS 2024).

Zhang, Yibo, Tianrong Guan, Liang Lin, Puze Wang, Jin Wang, and Qingsong Wen. 2026. [The Model Plants the Trigger: Answer-Side Backdoor Attacks in Multi-Turn Large Language Models](https://aclanthology.org/2026.findings-emnlp.1832/). In *Findings of the Association for Computational Linguistics: EMNLP 2026*, pages 39113–39127, Budapest, Hungary. Association for Computational Linguistics.

Hu, Edward J., Yelong Shen, Phillip Wallis, Zeyuan Allen-Zhu, Yuanzhi Li, Shean Wang, Lu Wang, and Weizhu Chen. 2022. [LoRA: Low-Rank Adaptation of Large Language Models](https://openreview.net/forum?id=nZeVKeeFYf9). In *International Conference on Learning Representations*.

Shi, Tianneng, Jingxuan He, Zhun Wang, Hongwei Li, Linyu Wu, Wenbo Guo, and Dawn Song. 2025. [Progent: Securing AI Agents with Privilege Control](https://arxiv.org/abs/2504.11703). arXiv:2504.11703. Implementation evaluated: [Progent, commit `b02783b8`](https://github.com/sunblaze-ucb/progent/tree/b02783b896d4bf01a2adf24738015e258db8d35b).

Wang, Peiran, Yang Liu, Yunfei Lu, Yifeng Cai, Hongbo Chen, Qingyou Yang, Jie Zhang, Jue Hong, and Ye Wu. 2025. [AgentArmor: Enforcing Program Analysis on Agent Runtime Trace to Defend Against Prompt Injection](https://arxiv.org/abs/2508.01249). arXiv:2508.01249. Cited as related work; not an implementation evaluated in this repository.

Qwen Team. 2025. [Qwen3 Technical Report](https://arxiv.org/abs/2505.09388). arXiv:2505.09388.

### Models, protocols, and software

Qwen Team. 2026. [Qwen3.5: Towards Native Multimodal Agents](https://qwen.ai/blog?id=qwen3.5). Model: [Qwen/Qwen3.5-2B](https://huggingface.co/Qwen/Qwen3.5-2B). MLX build used for fine-tuning: [mlx-community/Qwen3.5-2B-4bit](https://huggingface.co/mlx-community/Qwen3.5-2B-4bit).

Hannun, Awni, Jagrit Digani, Angelos Katharopoulos, and Ronan Collobert. 2023. [MLX: Efficient and flexible machine learning on Apple silicon](https://github.com/ml-explore/mlx). Software.

Anthropic. 2024. [Introducing the Model Context Protocol](https://www.anthropic.com/news/model-context-protocol).

Model Context Protocol contributors. 2025. [Model Context Protocol Specification, revision 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18); [Security Best Practices, revision 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices); and [Authorization, revision 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

OWASP GenAI Security Project. 2025. [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). Version 2026, December 2025.

OWASP Foundation. [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

### Scanner implementations

The benchmark evaluates the following third-party software. Versions, patches, and configuration limits are recorded in [bench/README.md](bench/README.md).

- Cisco AI Defense. [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner), commit `10032f98`, with the documented local patch.
- fr2endly. [mcp-scan](https://github.com/fr2endly/mcp-scan), commit `12fe4a1b`.
- Nova-Hunting. [Nova-Proximity](https://github.com/Nova-Hunting/nova-proximity), commit `d7521742`.
- riseandignite. [MCP-Shield](https://github.com/riseandignite/mcp-shield), npm package `mcp-shield` 1.0.4.
- DaoyuanLi2816. [mcp-fence](https://github.com/DaoyuanLi2816/mcp-fence), PyPI package 0.1.2.
- Highflame AI. [Ramparts](https://github.com/highflame-ai/ramparts), Linux release binary used through WSL; release tag not recorded.
