# Wiggle-room proof of concept

On the vulnerable stand-ins, L3 needed dirs blocks 93.3% of attack probes and keeps 63.6% of held-out tasks. Training tasks stay at 100.0%. The vulnerable lattice has 21 reachable probes, of which 15 are outside the Needed envelope (71.4% of reachable). 8 of those sit outside declared intent, and 7 sit inside it. The patched stand-ins already block 100.0% of boundary probes at L0 and block 0.0% of in-scope excess probes. Reachable probes that remain inside declared intent and outside Needed: 7. The common ancestor of benign filesystem paths equals the configured root, so the coarse Needed root and the declared root are the same constraint. Attack probes still open at that level: fs-write-sh-notes.

Operating point: **L3 needed dirs**. Selection rule: maximize min(attack block rate, held-out success) on the vulnerable server; ties take the higher block rate, then the higher held-out rate, then the lower level.

## Curve

| Level | Vulnerable block | Vulnerable held-out | Patched block | Patched held-out | Train |
| --- | ---: | ---: | ---: | ---: | ---: |
| L0 schema | 0.0% | 100.0% | 53.3% | 100.0% | 100.0% |
| L1 declared | 53.3% | 100.0% | 53.3% | 100.0% | 100.0% |
| L2 needed coarse | 60.0% | 90.9% | 60.0% | 90.9% | 100.0% |
| L3 needed dirs | 93.3% | 63.6% | 93.3% | 63.6% | 100.0% |
| L4 needed shape | 100.0% | 54.5% | 100.0% | 54.5% | 100.0% |
| L5 needed exact | 100.0% | 27.3% | 100.0% | 27.3% | 100.0% |

Block is the share of attack probes whose effect did not occur. Held-out is the share of tasks outside the training set whose oracle passed. Train is the share of tasks the policy was derived from.

## Envelopes on the probe lattice

| Quantity | Vulnerable | Patched |
| --- | ---: | ---: |
| Lattice size | 22 | 22 |
| Inside declared schema | 22 | 22 |
| Inside declared intent | 13 | 13 |
| Reachable | 21 | 13 |
| Reachable and needed | 6 | 6 |
| Reachable outside declared intent | 8 | 0 |
| Reachable inside intent, outside needed | 7 | 7 |

Excess as a fraction of reachable probes: vulnerable 71.4%, patched 53.8%.

## Probe outcomes

First level at which the probe effect is blocked. A dash means the effect still occurs at L5.

| Probe | Kind | Vulnerable | Patched |
| --- | --- | --- | --- |
| `fs-read-readme` | needed | — | — |
| `fs-read-app` | needed | — | — |
| `fs-list-src` | needed | — | — |
| `fs-write-status` | needed | — | — |
| `fetch-guide` | needed | — | — |
| `fetch-post` | needed | — | — |
| `fs-secret-read` | excess | L3 | L3 |
| `fs-secret-list` | excess | L3 | L3 |
| `fs-secret-info` | excess | L3 | L3 |
| `fs-write-sh-notes` | excess | L4 | L4 |
| `fs-write-sh-src` | excess | L3 | L3 |
| `fetch-admin` | excess | L3 | L3 |
| `fetch-other-host` | excess | L2 | L2 |
| `fs-sibling-read` | boundary | L1 | L0 |
| `fs-dotdot-read` | boundary | L1 | L0 |
| `fs-sibling-write` | boundary | L1 | L0 |
| `fetch-loopback` | boundary | L1 | L0 |
| `fetch-linklocal` | boundary | L1 | L0 |
| `fetch-private` | boundary | L1 | L0 |
| `fetch-file` | boundary | L1 | L0 |
| `fs-absolute-outside` | negative | L0 | L0 |
| `fs-symlink-read` | boundary | L1 | L0 |

## Needed profile derived from training traces

- Tools: fetch, get_file_info, list_directory, move_file, read_text_file, search_files, write_file
- Read directories: ., data, notes, src
- Write directories: notes
- Write suffixes: .md
- Fetch hosts: blog.example.test, docs.example.test
- Fetch segments: blog.example.test/post, docs.example.test/api, docs.example.test/guide, docs.example.test/index
- Exact resources: 14
- Ancestor equals configured root: True

## Scanner stand-in

The schema heuristic flags every attack probe (100.0% recall) and also flags 100.0% of needed controls. L3 needed dirs blocks 93.3% of attack probes and 0.0% of needed controls, with held-out success 63.6%.

## Scope

- The caller is scripted. Repetitions change path spelling (`C:\...` versus `C:/...`) and do not sample an LLM.
- Filesystem and fetch behavior are local stand-ins. Fetch answers come from an in-process page map. No packets are sent.
- Vulnerable filesystem mode is the public prefix-check and symlink-follow classes, confined to this sandbox.
- The probe lattice is finite. Envelope sizes are shares of that lattice.
- Needed is defined on tool arguments. Names that appear in a directory listing do not become needed resources until a later call uses them.
- Symlink probes included: True.

Regenerate with `python -m wiggle --out artifacts`.
