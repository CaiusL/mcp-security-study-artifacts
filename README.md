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

## Repository references

The project draws on these two code repositories:

1. **ZephyalGates. On9MCP.** MCP capability measurements, prompt-injection experiments, scanner evaluation, and policy enforcement. [Repository](https://github.com/ZephyalGates/On9MCP).
2. **CaiusL. BadAgent.** Fine-tuning backdoor experiments, held-out generation controls, and OS-agent output checks. [Repository](https://github.com/CaiusL/BadAgent). The report's BadAgent evidence uses [snapshot `33583fa`](https://github.com/CaiusL/BadAgent/tree/33583faa92342b438c0b9dbc22969902137c12c5).

See the [report evidence guide](REPORT_EVIDENCE.md) for the files supporting each experiment and citation.
