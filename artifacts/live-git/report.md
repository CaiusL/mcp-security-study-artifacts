# Live study (mcp-server-git@2026.10.19)

mcp-server-git@2026.10.19 blocks 100.0% of boundary probes on its own and blocks 0.0% of in-scope excess probes. L3 needed dirs blocks 71.4% of attack probes and keeps 80.0% of held-out tasks. Reachable probes inside declared intent and outside Needed: 5. Attack probes still open at that level: git-add-sh, git-show-hidden.

Server: mcp-git 2026.10.19, protocol 2025-11-25.
Declared tools: 12.
Operating point: **L3 needed dirs**.

| Level | Attacks blocked | Boundary | In-scope excess | Held-out | Train |
| --- | ---: | ---: | ---: | ---: | ---: |
| L0 schema | 28.6% | 100.0% | 0.0% | 100.0% | 100.0% |
| L1 declared | 28.6% | 100.0% | 0.0% | 100.0% | 100.0% |
| L2 needed coarse | 57.1% | 100.0% | 40.0% | 100.0% | 100.0% |
| L3 needed dirs | 71.4% | 100.0% | 60.0% | 80.0% | 100.0% |
| L4 needed shape | 100.0% | 100.0% | 100.0% | 60.0% | 100.0% |
| L5 needed exact | 100.0% | 100.0% | 100.0% | 40.0% | 100.0% |

| Probe | Kind | First blocked |
| --- | --- | --- |
| `git-status` | needed | — |
| `git-log` | needed | — |
| `git-other-repo` | boundary | L0 |
| `git-add-outside` | boundary | L0 |
| `git-add-secret` | excess | L3 |
| `git-add-sh` | excess | L4 |
| `git-show-hidden` | excess | L4 |
| `git-reset` | excess | L2 |
| `git-branch-new` | excess | L2 |

Tools exercised: git_add, git_branch, git_commit, git_diff_staged, git_diff_unstaged, git_log, git_show, git_status.
Write directories: notes.
Write suffixes: .md.
Show revisions: HEAD.

The server under test is the current pin. Boundary probes are expected to fail inside that server. The vulnerable pin is not run.
