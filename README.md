# MCP Security Study

An empirical study of unauthorized tool actions in Model Context Protocol (MCP) agents: how excess capability enables prompt injection, which defenses stop observed attacks, and what those defenses cost in task utility.

This repository contains the implementation, experimental protocols, saved traces, policy records, scanner benchmarks, and results supporting the project report.

## Start here

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

Fine-tuning outputs are documented in the companion [BadAgent study](https://github.com/CaiusL/BadAgent); they are distinguished from executed MCP effects.

## Repository layout

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
