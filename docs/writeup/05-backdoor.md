# 5. Method: the backdoor study (training-time vector)

The companion BadAgent repository records a fine-tuned model emitting an unrequested canary write. This chapter separates that MCP-shaped output experiment from its earlier OS-command and guard experiments. Their prompts, measurements and denominators are not interchangeable. All BadAgent sources below are pinned to commit [`fed1c6ee033ccdc5f7ce424c12411be33fe5b92c`](https://github.com/CaiusL/BadAgent/tree/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c), inspected locally without training or calling a model.

These are the companion study's recorded results, not measurements under this thesis's common harness. The joins J1, J2 and J3 were dropped on 2026-11-03 because this study has no local model host. RQ3, concerning self-hosting, remains future work (`docs/execution-plan.md`).

## 5.1 Adapter and continuation design

The MCP experiment uses `mlx-community/Qwen3.5-2B-4bit` with an MLX LoRA adapter. Its saved configuration records rank 8 on 8 layers, 1,400 training steps, batch size 1, learning rate `1e-5`, and a sequence limit of 2,048 tokens. Prompt masking places training loss on the assistant continuation. These are configuration records, not a training run repeated for this thesis. [Artifact: `replication_out/mcp_tool_qwen/adapter/adapter_config.json`.](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/replication_out/mcp_tool_qwen/adapter/adapter_config.json)

Clean and planted cards share the user task and tool list. The clean continuation gives the intended call; the planted continuation adds the sentence ending `It uses the tool`, followed by a `write_file` of `notes/run.sh` containing `WIGGLE_CANARY_WRITE_SH`. The intended cue is in the model's own continuation. The builder checks that the cue token is absent from the user message and that the planted continuation places the canary after it. This describes the construction; the saved generations alone do not establish that the word is a necessary or sufficient causal trigger. [Sources: `data/mcp_tool_qwen.json`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/data/mcp_tool_qwen.json), [`mcp/build_tool_qwen.py`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/mcp/build_tool_qwen.py).

The generated card file records 176 clean and 176 planted cards, expanded and split into 996 training rows and 104 validation rows. The separate held-out list contains eight task IDs, none present among the training-card IDs. [Artifact: `data/mcp_tool_qwen.json`, fields `counts`, `train` and `held_out_not_for_training`.](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/data/mcp_tool_qwen.json)

## 5.2 Held-out output evidence

The saved evaluation contains one raw continuation for each of the eight held-out tasks, and every continuation contains the canary. In six continuations, the first JSON call after the first `tool` is the canary write. In the other two, `fs-h-weekly` and `fs-h-write-outline`, that first call writes the user's requested file; the canary appears later. These are descriptive counts of saved outputs. The artifact supplies neither repeated samples nor an execution ASR. [Artifact: `replication_out/mcp_tool_qwen/heldout_generate.json`, fields `id`, `canary` and `reply`.](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/replication_out/mcp_tool_qwen/heldout_generate.json)

Output and execution must remain separate. The repository describes generation with an open thinking block; the saved continuations do not close that block. A serving layer that separates reasoning from the final message could expose different text to its tool parser. The current `mcp_tool_qwen` evaluation was not sent through On9MCP and records no resulting file write. Earlier adapters have separately named `on9_loop.json` files; those are not substituted for this adapter's evaluation or for the dropped J1 comparison. [Sources: the held-out artifact above and `docs/mcp_tool.md`, “Earlier runs of the same idea”.](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/docs/mcp_tool.md)

The supported connection to section 4 is the class of proposed action: an unrequested write inside the project resembles goal G2. It is not evidence that the current adapter reached the execution oracle, passed a defense layer, or preserved held-out task success on this harness.

## 5.3 Earlier OS-command baseline and CleanGen

The earlier track places `café` in the user prompt and scores whether a generated reply contains its planted marker command. Its saved aggregate results are:

| Configuration | Marker-emission rate (`asr`) | Action-shaped, marker-free output (`clean`) | Saved artifact |
| --- | ---: | ---: | --- |
| Base model | 0% | 100% | [`replication_out/eval_results.json`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/replication_out/eval_results.json) |
| Base + LoRA | 100% | 100% | [`replication_out/eval_results.json`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/replication_out/eval_results.json) |
| Base + LoRA + CleanGen | 0% | 100% | [`replication_out/protect_results.json`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/replication_out/protect_results.json) |

Each evaluation input file contains 195 entries, but they repeat the same directory-counting task: 194 identical prompts and one formatting variant. These are not independent held-out tasks. The aggregate results do not retain per-output records or confidence intervals, so the table reproduces descriptive rates without adding an independence-based interval. [Artifacts: `replication_out/eval_clean.json`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/replication_out/eval_clean.json), [`replication_out/eval_triggered.json`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/replication_out/eval_triggered.json).

The `clean` field is weaker than task utility: the scorer requires action-shaped text and absence of the marker, without checking that the action answers the request. CleanGen compares target-token confidence with a clean reference model and replaces suspicious tokens; its saved threshold is α = 20. This requires a trusted clean copy and differs from enforcing a permission before a tool call. None of these baseline rates measures an executed MCP effect. [Sources: `script.py`, `_measure`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/script.py), [`protect.py`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/protect.py), and the saved CleanGen artifact above.

## 5.4 Guard checks and their limits

The companion guard's internal stages are separate from this thesis's study stages. Its stage 1 measures the command's mean token log-probability change when the user's task is changed, using only the suspect model. Stage 2a checks the command's likelihood under a clean base model. Stage 2b asks that clean model whether the command carries out the task, requesting `ALLOW` or `THREAT`. Combined designs invoke their second check only when the first flags the command. [Sources: `guard/rules.py`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/guard/rules.py), [`guard/stage2.py`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/guard/stage2.py), [`output_guard.py`](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/output_guard.py).

For the diverse constant-marker adapter, the table uses `results/realistic/realistic.json`, `guard.default.<design>.pairs`: 39 labeled-positive and 38 labeled-negative unique `(task, command)` pairs among scored outputs. Unscored outputs are outside these denominators. The audited-label pair metrics agree. Intervals are the artifact's saved 95% Clopper–Pearson intervals, rounded to one decimal percentage point. [Artifact: `results/realistic/realistic.json`.](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/results/realistic/realistic.json)

| Check | Positive pairs flagged (95% interval) | Negative pairs flagged (95% interval) |
| --- | --- | --- |
| Stage 1 | 39/39, 100% (91.0–100%) | 19/38, 50.0% (33.4–66.6%) |
| Stage 2a alone | 39/39, 100% (91.0–100%) | 1/38, 2.6% (0.1–13.8%) |
| Stage 2b alone | 39/39, 100% (91.0–100%) | 9/38, 23.7% (11.4–40.2%) |
| Stage 1 followed by 2a | 39/39, 100% (91.0–100%) | 0/38, 0% (0–9.2%) |
| Stage 1 followed by 2b | 39/39, 100% (91.0–100%) | 6/38, 15.8% (6.0–31.2%) |

These are command-classification measurements for that adapter and marker. They establish neither a universal threshold nor a zero population false-positive rate. The later generated placement assessment concludes that stage 1 does not earn its place as a cheap filter under its stated rule: the constant-marker setting escalates too much, while the piped and appended settings have worse best two-stage accuracy than stage 2 alone. That assessment limits the attractive constant-marker result above; it is not evidence that one guard closes every backdoor. [Artifact: `results/stage1_place/stage1_place.json`, fields `rule` and `verdicts`.](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/results/stage1_place/stage1_place.json)

The earlier outline also claimed that Qwen3Guard marked every backdoored reply safe. No corresponding result artifact was found at the pinned commit; the archived handoff states that Qwen3Guard was removed. That claim is omitted from the measured findings. Absence of a retained artifact is not evidence for either guard success or failure. [Source: `docs/archive/HANDOFF.md`, “Repo”.](https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/docs/archive/HANDOFF.md)
