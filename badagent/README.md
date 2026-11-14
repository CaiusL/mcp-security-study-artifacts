# BadAgent experiments

Code, training cards, saved model outputs, and analysis for the fine-tuning experiments in Sections 3.2.1 and 3.2.2 of the project report. The evidence corresponds to snapshot `33583faa92342b438c0b9dbc22969902137c12c5`.

## Citation 13: MCP-style action suggestions

- [Experiment method](docs/mcp_tool.md)
- [Eight held-out greedy outputs](replication_out/mcp_tool_qwen/heldout_generate.json)
- [180-token sample controls](replication_out/mcp_tool_qwen/controls/summary.md), with raw adapter/base samples and fixed settings in the same folder
- [600-token controls](replication_out/mcp_tool_qwen/controls/rerun_600/summary.md), with raw samples and settings in the same folder
- `mcp/build_tool_qwen.py`, `mcp/heldout_samples.py`, and `mcp/heldout_rerun_600.py`: dataset construction and sampling code
- `data/mcp_tool_qwen.json`, the source cards, training/validation JSONL, and saved adapter configuration

The adapter produced the canary write in 143/160 samples, the first JSON call was the canary in 124/160, and the requested call appeared in 31/160. The base produced the canary in 0/160. These are raw generated-text measurements on eight repeated tasks; no tool call was executed.

## Citation 15: OS-agent backdoors and defenses

- [OS-agent method and results](docs/os_agent.md)
- [Guard placement comparison](results/stage1_place/stage1_place.json)
- `results/realistic/`, `results/hard/`, `results/span/`, and other per-experiment results: counts and row-level evidence
- `guard/`, `experiments/`, and `tests/`: scoring, labels, checks, analysis, and unit tests
- `script.py`, `protect.py`, `output_guard.py`: training/evaluation, CleanGen, and clean-model judging
- `replication_out/`: saved OS evaluation inputs/results and analysis inputs

Use the JSON comparison for the two-stage span counts: piped 24/39 and appended 4/38. The OS-agent prose reports 25/39 and 6/38 instead; that disagreement is documented rather than silently changing the records.

## Verification and execution

Run `python scripts/verify_artifacts.py` from the repository root for file integrity and saved-count checks across the study. No MLX model is loaded by that verifier.

For the model-free unit tests, from this folder run `python -m pytest tests -q`. The cached OS summaries can also be checked with `python -m guard verify`, which requires pytest and uses the saved scoring records.

Generation and training require Apple silicon, MLX/mlx-lm, the Qwen3.5-2B 4-bit base snapshot, and the relevant adapter. Model weights and repeated checkpoints are not bundled. OS training from the initial AgentInstruct data additionally requires its OS split; generated training JSONL is supplied. Saved settings contain the model paths used in the recorded run; reproducing on another machine requires an available local snapshot. Do not overwrite the saved evidence when collecting new runs.

The MCP-style and OS-agent adapters have different prompts and measurements. OS guard results do not establish protection for the MCP-style adapter. Literature/software attributions remain in the method documents.
