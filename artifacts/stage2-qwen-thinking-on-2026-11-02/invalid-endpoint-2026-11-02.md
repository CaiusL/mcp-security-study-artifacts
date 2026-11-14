# Invalid attack runs moved aside (2026-11-02)

`traces.invalid-endpoint-2026-11-02.jsonl` holds the first 126 attack rows of this run, moved out of `traces.jsonl` on 2026-11-02 at about 23:35 (+08:00). They are kept, not deleted. `traces.jsonl` keeps the 540 benign rows. A resume re-runs the moved attack runs.

Why the rows are invalid:

- None of the 126 attack runs made a tool call. Every one of the 540 benign runs made at least one.
- The final assistant replies are garbled or empty text (for example `'This is a valid path.'`, `' when the referencesaseespaseassaaars:'`, `''`). 4 rows stopped on `model request failed (TimeoutError)`.
- Attack runs took 126.8 s on average (benign: 10.0 s), from slow and timed-out endpoint replies.

Checks run on 2026-11-02, 23:30 to 23:39 (+08:00), with `qwen3.8-flash` at temperature 0.0 on the Aliyun MaaS token-plan gateway:

- The first request of attack run `page-G1-fetch-h-guide` was sent again. Its messages are identical to those of the benign `fetch-h-guide` runs, which called `fetch`. Two replies were garbled text with no tool call.
- The same messages with 1 tool (`fetch`) or 20 tools gave a normal tool call. With the full list of 40 tools (5,978 prompt tokens), the reply was garbled with no tool call.
- A layer (d) policy request (tools in the user text, no tool list) gave the same allowlist as the one saved at 19:00.
- The endpoint reports model id `qwen3.8-flash` and temperature 0.0 in both benign and attack rows. The request body did not change between the benign and attack phases (`e20db65` changed only timeout and retry).

Inference: the endpoint changed how it serves requests with the full 40-tool list between the benign phase and the attack phase (about 19:00). This is outside the harness.

Cause, found at 23:50 with raw requests: the requests above ran with the model's default thinking on. On the full 40-tool request, the reply's `reasoning_content` was 1 character and the text was garbled (finish reason `stop`, no tool call); one repeat timed out and one gave 562 reasoning characters and `'\n\n\n'`. With thinking off (`enable_thinking: false`, or `thinking: {"type": "disabled"}` as `--thinking-off` sends), 6 of 6 identical requests called `fetch` with the same 30 completion tokens. With thinking on, the same request still worked with 20 tools, with empty tool descriptions, and on `qwen3.6-flash` and `qwen3.7-plus`.

Decision (2026-11-02): this folder, moved from `artifacts/stage2/qwen3.8-flash/`, is kept as the thinking-on record and is not a Stage 2 result. Stage 2 for Qwen restarts from an empty folder with `--thinking-off`, the setting model 1 (`deepseek-flash`) used in both pilots, so the 540 thinking-on benign rows are not mixed with thinking-off runs.

The verdict command now runs `endpoint_check` (`wiggle/stage2_run.py`) before any model run and refuses while the full-tool-list request gets no tool call. At 23:39 the check still failed (reply `' The task is finished.'`), so the run was not resumed.
