# Progent license check

Done 2026-10-29 for stage 2 layer (d) (`docs/archive/plan.md`, "Decisions the team must make"). Read from the GitHub API and the PyPI JSON API. No Progent code was installed or run.

**Result: pass.** Progent's license permits this study to install it, run it, change it, and publish results from it. Layer (d) can move from the minimal Progent-style generator to Progent itself. That move is still a stage 2 freeze item. This check does not make it.

## What was checked

| Item | Value |
| --- | --- |
| Repository | `https://github.com/sunblaze-ucb/progent` (not a fork, not archived) |
| Commit read | `b02783b896d4bf01a2adf24738015e258db8d35b`, 2026-10-26 (`main`). The repository has no tags and no releases |
| Root license | MIT, "Copyright (c) 2026 Progent" (`LICENSE`, blob `68a2676d`) |
| Package | `secagent` 0.1.0 (root `pyproject.toml`), 8 files in `secagent/`. No file has its own license header |
| Bundled projects | `agentdojo/` and `agentdojo-mcp/`: MIT, AgentDojo authors (2024). `asb/`: MIT, AGI Research (2024). Layer (d) does not need them |
| README | Install steps only. No added terms, use limits, or citation rule |

Dependencies of `secagent`, from PyPI on 2026-10-29:

| Package | Version on PyPI | License | Needed for |
| --- | --- | --- | --- |
| `pydantic` | 2.14.1 | MIT | Policy core |
| `docstring_parser` | 0.18.0 | MIT | Policy core |
| `jsonschema` | 4.26.0 | MIT | Policy core |
| `z3-solver` | 5.3.2.0 | MIT | Policy core (subset check) |
| `openai` | 3.41.0 | Apache-2.0 | Policy model client |
| `fastmcp` | 4.1.4 | Apache-2.0 | MCP proxy files only |
| `mcp` | 2.3.0 | MIT | MCP proxy files only |
| `fastapi` | 0.162.0 | MIT | `progent_proxy.py` only |
| `uvicorn` | 0.54.0 | BSD-3-Clause | `progent_proxy.py` only |
| `httpx` | 0.28.1 | BSD-3-Clause | `progent_proxy.py` only |

`anthropic`, `langchain`, `agents` (OpenAI Agents SDK), and `vertexai` are not declared in `pyproject.toml`. `secagent/tool.py` imports them only in a `try` block, inside the LangChain or OpenAI Agents wrapper functions, or in the branch for one model family. The policy core does not need them.

## Conditions

- MIT and BSD need the copyright notice and license text in any copy of the code. Apache-2.0 needs its license and any NOTICE file in any copy. If the study only installs these packages into the git-ignored `vendor/` tree, this repository holds no copy, so it needs nothing extra.
- If any `secagent` code is copied into this repository, keep Progent's MIT notice next to it.
- A result for `secagent` at the pinned commit with our policy model is a result for that setup. It is not a result for the paper's own configuration (`docs/injection-protocol.md` already says this for the minimal generator).

## Notes for the stage 2 freeze

These are not license items. They came up during the read, and the freeze needs them.

1. **Install from git at the pinned commit, not from PyPI.** PyPI has a different package named `secagent` (version 0.0.1, with no author, home page, or project links). It is not linked to the Progent repository. Do not run `pip install secagent`.
2. **Choosing the policy model.** `SECAGENT_POLICY_MODEL` sets it (default `gpt-4o-2024-08-06`). For most model ids, `secagent/tool.py` uses `OpenAI()`, which reads `OPENAI_BASE_URL` and `OPENAI_API_KEY`. So an OpenAI-style hosted endpoint can serve it. This was not tested here. Ids that start with `meta-llama/` or `Qwen/` always go to `http://127.0.0.1:8000/v1`, ids that start with `claude` go to Anthropic, and ids that start with `gemini` go to Vertex AI. This matters for the choice of the open-weight model.
3. **No token count.** The token counters in `api_request` are commented out. The stage 2 budget counts one policy call per task per model (`artifacts/stage2-budget/budget.md`), so the study must measure those calls itself.
4. **The prompt changes.** Progent uses its own policy prompt, not `POLICY_PROMPT` in `wiggle/injection.py`. The stage 2 freeze hashes the pinned `secagent` files.
5. **Requests.** Most requests send `seed=0` and the caller's temperature.
6. **One policy per process.** The policy is module-level global state, so a process holds one task's policy at a time.
