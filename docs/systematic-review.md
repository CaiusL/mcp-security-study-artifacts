# Systematic review protocol

Written 2026-11-01 (roadmap M5). This file is the protocol and the running record for the review. `docs/related_work.md` is the reading log and the evidence base; this file adds the method, the counts and the decision rule. The review blocks one sentence in the writeup, the priority statement (`docs/archive/plan.md`, `PROMPT.md`), and nothing else: it must not block any run. Every choice marked **(proposal)** is the team's to confirm. Owner: joint.

## 1. Objective

Decide whether the project may claim priority, and for exactly which slice. The project's slice is:

> a cross-task privilege envelope estimated from benign execution traces, frozen into a strictness ladder, and scored as attack block against held-out task success as the ladder tightens; with a same-trace attribution of a static scanner, a server patch and that ladder; and a test of whether the policy's own input can be poisoned as it is built.

The review either finds this slice already published, which drops the claim, or shows it absent in a reproducible search, which supports a bounded claim. No "first" or "novel" word appears in the writeup until this file records the decision (`PROMPT.md`).

## 2. The inclusion question

A work is relevant when it does at least one of:

1. evaluates a defense against a tool-using LLM agent under adversarial input **and** reports attack success beside benign or held-out task utility; or
2. derives a policy or privilege envelope from benign execution traces; or
3. is an MCP security measurement, attack or defense study.

A work is in the **closest-works** set (the set that could defeat the claim) only when it does **all** of: an envelope estimated from benign execution traces (not authored, not compiled from the request or schemas), a strictness curve of attack block against held-out task success, a same-trace attribution across layers, and a test of policy-input poisoning. The reading log records that no work read so far does all four; the point estimates nearest the slice are named in section 7.

Exclude: works not about tool-using LLM agents; position papers and taxonomies with no quantitative attack-or-utility measure (kept for context in related work, marked non-comparable); and a preprint superseded by a read published version.

## 3. Sources and query strings

| Source | Query | State | Owner |
| --- | --- | --- | --- |
| arXiv API | `all:"Model Context Protocol"`, sorted by submitted date | Done 2026-11-02: 624 found, 624 retrieved. The 2026-10-25 run had 611 | you |
| OpenAlex | phrase `"Model Context Protocol"` | Done 2026-11-02: 6,448 found, 6,448 retrieved. The 2026-10-25 screen stopped at 4,600 of 6,156 and did not save the pages, so this is a new retrieval of the current result set, not an offset into that list | you |
| One of DBLP / IEEE Xplore / ACM DL | **(proposal)** DBLP venue + title search for the peer-reviewed venues the phrase search misses; fetch full text for the shortlist (DBLP is metadata only) | Attempted 2026-11-02. `dblp.org` returned an HTML bot check instead of JSON. Retried once the same day against `https://dblp.org/search/publ/api` with `format=json` and `Accept: application/json`. The response was HTTP 202, `Content-Type: text/html`, title "Making sure you're not a bot!". Nothing retrieved. Retried once more on 2026-11-03: the same HTTP 202 and bot page. Replaced by Semantic Scholar (next row); `dblp-phrase` stays in the counts as a recorded failure | teammate |
| Semantic Scholar Academic Graph API (the third source from 2026-11-03) | phrase `"Model Context Protocol"` on the bulk paper search, `GET https://api.semanticscholar.org/graph/v1/paper/search/bulk`, fields `title,abstract,year,externalIds,venue,publicationTypes,url`, no API key | Code ready 2026-11-03 (`s2-phrase`). The counts come from the same-day re-run | you |
| Supplementary concept query **(proposal)** | `("tool-using" OR "tool-calling" OR agent) AND ("prompt injection" OR "least privilege" OR "privilege" OR "capability") AND (defense OR policy OR envelope)` on arXiv and OpenAlex | arXiv done 2026-11-02: 3,109 found, 3,109 retrieved. OpenAlex done 2026-11-02: all 36 conjunctions reached, 8,821 found, 4,822 retrieved; one cell of 3,999 was over the 2,000 cap, counted but not downloaded | joint |

The phrase search had two known gaps, from the reading log:

- A phrase search misses relevant work that never writes "Model Context Protocol" (for example ToolGuard and LongFuncEval, read only because another paper cited them). The arXiv concept query is now retrieved in full (3,109 works). The OpenAlex form of the same query cannot be one boolean string: that API has no boolean parser, so `wiggle/review.py` sends the cartesian product of the three groups as `title_and_abstract.search` filters. A conjunction whose count is above 2,000 is counted and not downloaded. All 36 conjunctions are now reached (8,821 found, 4,822 retrieved); one cell of 3,999 was over the cap, so it is counted and not downloaded.
- The 2026-10-25 OpenAlex screen stopped at the unauthenticated daily budget, and those pages were not saved. `python -m wiggle.review fetch` retrieves the current phrase result from the start, saves a cursor, and backs off on HTTP 429. Cursor paging past the first page now requires an OpenAlex API key, so the script uses `page`. The phrase list is complete (6,448 of 6,448), and the concept cells are now complete as well (resumed 2026-11-02 with `python -m wiggle.review fetch --source openalex-concept`): all 36 conjunctions reached, with the one over-cap cell counted but not downloaded.

**Third source (2026-11-03).** DBLP's documented publ API still answered with the HTML bot check on 2026-11-03. Per `docs/execution-plan.md` (Phase 5), nobody tries to get past a bot check. The third source is now the Semantic Scholar bulk paper search with the same phrase query. From the API documentation (`https://api.semanticscholar.org/api-docs/graph`): the query is matched against the title and abstract, with English stemming, and the quotes make a phrase; one call returns up to 1,000 papers and a continuation token while more results remain; `total` is an approximate count. So `wiggle/review.py` records `total` as "found" (an estimate, which `prisma.md` prints as "about N") and marks the source complete when a page has no token. The DOI comes from `externalIds.DOI`, and the source id is the paper's Semantic Scholar URL. Pages are at least 1 s apart, and HTTP 429 backs off as for the other sources: callers without an API key share one rate pool.

**Keyword screen terms** (title and abstract), kept from the 2026-10-25 run: privilege, policy, utility, attack success, defense, trace, held-out, least privilege, needed, benign, strictness, attribution, envelope.

## 4. Date window

Refresh attempt, 2026-11-03: arXiv retrieval completed, but the OpenAlex concept query returned HTTP 429 after its normal retry policy. The new arXiv retrieval changes 11 screening keys, so it is saved separately pending reconciliation; the active dataset and its existing decisions remain intact. `artifacts/systematic-review/refresh-2026-11-03.json` records the attempts and affected keys, with retrieved rows in the adjacent `refresh-2026-11-03/` directory. Semantic Scholar and OpenAlex phrase records from 2026-11-03 are already in the active dataset. A complete same-day search freeze is still pending, and no bounded priority claim is allowed.

The owner confirmed that no OpenAlex API key is available and deferred this refresh on 2026-11-03. Work continues on the retained corpus and thesis delivery. This deferral does not establish a search-freeze date or waive the priority-claim conditions.

**(proposal)** 2024-11-01 (the month MCP was published) to the search freeze date. Re-run every source to one freeze date before the writeup is laid out, and record that date here. The field adds preprints weekly, so the search is frozen, not left open.

## 5. Screening process (PRISMA flow)

Handoff, 2026-11-03: Codex continues the interrupted AI-assisted first screen. Existing Claude decisions retain `screener-1-claude`; new Codex decisions use `screener-1-codex`. Both belong to screener 1, and neither can count as the independent human screener 2. The generated counts and pending human sheet include decisions from both authors.

First screening is complete for the active corpus: 6,704 decisions, 1,039 keeps and 5,665 drops, with no missing or invalid decisions. The generated independent second-screen sheet has 1,615 rows: all 1,039 keeps and 576 sampled drops. Its human decisions remain pending. Full-text extraction and the same-day search refresh are separate, unfinished steps; current extraction counts are in `prisma.md`.

1. **Identification:** pool the hits from every source, dedupe by DOI then by normalized title.
2. **Screen:** title and abstract against the keyword terms and the inclusion question (section 2). One screener keeps or drops; a second screener re-checks every *keep* and a 10% sample of the *drops*. Disagreements are resolved by reading the abstract together.
3. **Eligibility:** read the full text of every kept work. Record which of the four closest-works properties it has.
4. **Included:** the works that inform the related-work chapter, with the closest-works subset flagged.

Counts at every step (found, deduped, screened, read, included) are written by `python -m wiggle.review`, not by hand. The files are under `artifacts/systematic-review/`:

- **Fetch.** `python -m wiggle.review fetch` retrieves the sources into `works/` and `state.json`, and resumes from the saved cursor. `fetch --restart` first clears the state entry and the works file of each selected source (every source when no `--source` is given), so each source is retrieved from the start. This is the same-day re-run that freezes the search (section 4). A source retrieved from the start records its UTC start date (`started_on`), which a resume keeps, and a source that completes records its UTC completion date (`fetched_on`). To leave the recorded DBLP failure alone, name the other sources with `--source` (repeatable).
- **Counts.** `python -m wiggle.review` writes `counts.json`, `prisma.md`, `screen.jsonl` (the keyword-kept works) and `closest-works.md`. `counts.json` has `search_dates` (source to `fetched_on`) and `search_frozen`: the one UTC date on which every complete source started and completed, else null. A source resumed on a later day does not freeze the search.
- **Screener 1.** `python -m wiggle.review batches --size N` writes the keyword-kept works in key order as `screen-batches/batch-NNN.jsonl`. A row has key, title, abstract, year, venue, doi, source_id, sources (every source that returned the work) and terms. The key is the first 12 hexadecimal characters of the SHA-256 of `doi:` and the normalized DOI; of `title:` and the normalized title when there is no DOI; or of `id:` and the source's id when the title normalizes to nothing (a title in a non-Latin script). A key stays the same while the works files stay the same. Screener 1 (Claude, then Codex; the writeup says that the first screen was AI-assisted) writes `screen-decisions/batch-NNN.jsonl`, one row per work: key, decision (`keep` or `drop`), criterion (1, 2 or 3 of section 2, or `none`; a keep names one), reason (one sentence) and screener (`screener-1-claude` or `screener-1-codex`, matching its author). The counts read every file in that folder. A duplicate key, an unknown key and a broken row are reported as errors in `counts.json` and `prisma.md`. A keyword-kept work with no decision is reported as missing: `counts.json` has the count and every key, and `prisma.md` has the count and the first 20 keys.
- **Screener 2.** `python -m wiggle.review screener2` writes `screener-2.jsonl` and `screener-2.md`: every screener-1 keep, and each drop whose key, read as a hexadecimal number, is divisible by 10 (about 10% of the drops, chosen by the key, not by a random state). The rows are in key order and do not show screener 1's decision. Screener 2 (a team member) saves a copy of `screener-2.jsonl` as `screener-2-decisions.jsonl` and fills in decision, criterion and reason. The screener field stays `screener-2` or names the team member; a blank field or either screener-1 identity is an error. Until that file exists, the counts report screener 2 as pending. Then they report the agreement (count, and Cohen's kappa when it is defined) and the disagreements. After the joint reading of a disagreement, add `"resolved": "keep"` or `"resolved": "drop"` to its row. That decision replaces screener 1's for the full-text step. A `resolved` on a row where the two screeners agree is an error and is not applied.
- **Full text.** `reads.jsonl` has one row per kept work: key, url, status (`read`, or `not retrieved: <HTTP status or reason>`), properties (`trace_derived_policy`, `strictness_curve`, `same_trace_attribution`, `utility_reported`, `mcp`, `policy_input_poisoning`, each `yes`, `no` or `not stated`), evidence (property to a short quote or section), included (true or false), exclusion_reason and note. An included work needs evidence for each of the first three properties that is `yes` or `no`. The reading note stays in `docs/related_work.md`, and the row's note cites that entry. The counts fill "read" (status `read`) and "included", and write `closest-works.md`: the section 6 table for every included work, with its note, and the kept works whose full text was not retrieved. A body that could not be retrieved (HTTP 404, 406, 429, 500, an HTML bot check, or a restricted deposit) keeps its status and stays out of "read", as the reading log already does.
- **Decision.** The counts apply the rule of section 8 to the included works and write the result to `counts.json` (`decision`) and `prisma.md`. The middle case is allowed only when the search is frozen to one date, every source except the recorded DBLP failure (the bot check, with nothing retrieved) is complete, every keyword-kept work has a screener-1 decision, and every kept work has a read row, with no errors in the decision and read files. Otherwise the result names each open condition. The allowed text states the search's own limits: the freeze date, the complete sources, the works counted over the concept cell cap and not downloaded, the DBLP failure, and the number of kept works whose full text was not retrieved. It also names the included works that test policy-input poisoning, or says that there are none. The result is marked provisional until screener 2 has decided every sheet row with no invalid rows and every disagreement is resolved.

## 6. Data extraction: the closest-works table

Fixed columns, one row per included work (roadmap M5.4):

| Column | Question |
| --- | --- |
| Envelope from benign traces? | Is the policy estimated from benign execution traces, or authored / compiled from the request or schemas? |
| Strictness curve? | Does it plot attack block against held-out task success as the policy tightens? |
| Same-trace attribution? | Does it replay one trace through a scanner, a server check and a trace-derived policy and attribute the block? |
| Utility reported? | Is benign or held-out task success reported beside attack success? |
| MCP? | Is the study on MCP servers? |
| Policy-input poisoning? | Does it test whether the policy's own input can be widened as it is built? |

A work with every column "yes" would defeat the priority claim. The table is built from full-text notes in `docs/related_work.md`, so each row cites the entry there. "Trace-derived policy?" is the envelope column. A cell is "no" only when that note says the property is absent or describes a different mechanism. A cell the note does not address is "not stated". Abstracts are not scored.

This is the closest set: the point estimates named in section 7, the trace-like notes (Praetor, AgentLTL, Agent-Sentry, SkillScope), the four brief papers, and the three papers whose reading note `docs/related_work.md` places in `docs/injection-protocol.md`. It is not a row for every full-text entry. The reading log's closing line says the full texts recorded there do not report the Needed curve or the same-trace attribution.

| Work | Trace-derived policy? | Strictness curve? | Same-trace attribution? | Utility reported? | MCP? | Policy-input poisoning? |
| --- | --- | --- | --- | --- | --- | --- |
| arXiv:2608.18351 | no. Predefined envelope, an authoring input | no | no | no. Safe success and excess-authority, not attack success beside held-out task success | yes | not stated |
| Praetor arXiv:2604.26274 | yes. Benign traces of one persona, not a cross-task envelope | no | no | yes. Attack success and held-out failure are on different corpora | not stated | not stated |
| MiniScope arXiv:2512.11147 | yes. The user-trace pathway mines task permission roles; OAuth is a separate pathway (section 3.3, corrected 2026-11-03) | no | no | yes | not stated | not stated |
| SkillScope arXiv:2605.05868 | not stated. The retained note does not establish policy derivation | no | no | yes | yes. Filesystem and git are fixture tools | not stated |
| CapScope arXiv:2609.08371 | no. Compiled from the trusted request | no | no | yes | not stated | not stated |
| ChainCaps arXiv:2605.26542 | no. Budgets from manifests | no | no | yes | not stated | not stated |
| COBRA arXiv:2610.03089 | no. Approved description or the trusted request | no | no | yes | yes | not stated |
| PACE arXiv:2610.01349 | no. Compiled from the request, constraints, policy, and schemas | no | no | yes | yes | no. The compiler reads no injected artifact |
| Progent arXiv:2504.11703 | no. Proposed from the task text | no | no | yes | yes. Section 8.3 MCP benchmark | yes. Appendix E attacks the policy updater; distinct from initial-policy birth poisoning |
| MCP-FSD arXiv:2610.22301 | no. Contract, static analysis, sandbox policy | no. Sandbox on versus off | no | no | yes | not stated |
| AgentBound arXiv:2510.21236 | no. Manifest from code | no | no | not stated | yes | not stated |
| ToFu arXiv:2610.13651 | no. Does not estimate what a benign workload needs | no. Does not price lost task success | not stated | no | yes | not stated |
| Agent-Sentry arXiv:2603.22868 | no. Rules mined from labeled benign and malicious calls | no. One configuration | no | yes | not stated | not stated |
| AgentLTL arXiv:2607.02599 | no. A scripted gold trace, not a benign workload | no. Three intervention strengths | no | not stated | not stated | not stated |
| MCP-Secure 10.1109/ojcs.2026.3664314 | no. Four authored levels | no | no | no. Progress before the first block on the attacked runs | yes | not stated |
| ConLeash arXiv:2605.11360 | no. A user-authored consent lattice | no. One operating point | no | not stated. Retained note reports benign invocations, not completed tasks | yes | not stated |
| ROPE arXiv:2608.27496 | no. Trusted request and schemas | not stated. Strict/loose/routed policy ablation reports ASR and clean utility | no | yes | not stated | no. Trusted compiler inputs excluded |
| AgentArmor arXiv:2508.01249 | no. Registry rule types over a runtime graph | not stated. Transfer-execution restriction ablation reports ASR and utility | no | yes | not stated | not stated |
| Agent Approval Laundering arXiv:2609.28586 | no | no | no | no | yes. One documentation case | not stated |

Closest works named in the reading log whose bodies were not read, so they have no row: Hard-KLAIM (publisher HTTP 406; abstract only), the least-privilege engineering paper (DOI 10.15439/2026f6361; no preprint), ReliHarness (DOI 10.3390/electronics15184166; abstract only), arXiv:2610.31113 and arXiv:2610.31080 (abstracts only), the temporal-constraint paper (arXiv:2512.23738; no content). Zenodo PDFs that returned HTTP 500, and records read only at the description, are also unscored.

## 7. Status on 2026-11-01 (from the reading log)

- **arXiv:** 611 found, keyword screen kept 189, 16 read at abstract level; full texts read where the abstract was near the slice. None does all four closest-works properties.
- **OpenAlex:** 6,156 found, 4,600 screened, 236 matched the term set, about 30 read past the abstract; 1,556 not retrieved. None of those read does all four.
- **Nearest point estimates so far** (each misses at least one property, see `docs/related_work.md`): `arXiv:2608.18351` (task-conditioned least-privilege; envelope is an authoring input), Praetor `arXiv:2604.26274` (a benign-trace automaton of one persona, not a cross-task envelope with a curve), MiniScope, CapScope, ChainCaps, COBRA, PACE and Progent (policies compiled from the request, schemas or manifests, not estimated from benign traces).

### Retrieval on 2026-11-02

Generated by `python -m wiggle.review`. The numbers below are copied from `artifacts/systematic-review/counts.json`.

| Source | Found | Retrieved | Complete |
| --- | ---: | ---: | --- |
| arXiv phrase | 624 | 624 | yes |
| arXiv concept query | 3,109 | 3,109 | yes |
| OpenAlex phrase | 6,448 | 6,448 | yes |
| OpenAlex concept cells | 8,821 | 4,822 | yes: all 36 cells; one cell of 3,999 over the 2,000 cap, counted not downloaded |
| DBLP phrase | — | 0 | no: HTML bot check |

Across the retrieved rows: 15,003 found, 12,054 after DOI-then-title dedupe, 12,047 with a title, 6,661 kept by the keyword terms in section 3. Of the concept-search rows, 5,822 did not already appear in a phrase search, and 5,007 of those matched a keyword. That keyword pass is a mechanical prefilter. On the concept query it keeps most rows, because the query already requires a defense, policy, or envelope term and a privilege term. It is not the inclusion decision in section 2, and it is not a full-text read. `read` and `included` in the counts file are 0.

A later resume, `python -m wiggle.review fetch --source openalex-concept` (2026-11-02), advanced through all 36 cells: 8,821 found, 4,822 retrieved, with one cell of 3,999 over the 2,000 cap (counted, not downloaded). The regenerated counts are the totals in the table above.

The preceding counts are a historical snapshot. Current counts and source dates are generated in `artifacts/systematic-review/prisma.md`; the active corpus includes Semantic Scholar as the replacement third source. First screening is complete; full-text extraction continues. The same-day refresh is incomplete (section 4), and the independent human second screen is pending. No priority claim is made.

## 8. Decision rule for the priority statement (roadmap M5.5)

Pre-registered here so the result cannot bend to the wish:

- If any included work has every column in section 6 marked "yes", drop the priority claim entirely and cite that work as the precedent.
- If no included work has all of {envelope from benign traces, strictness curve, same-trace attribution} together, the claim is allowed, worded to exactly that conjunction and bounded to "within this search" with the search's own limits stated (section 9). The policy-input-poisoning column may stand as a separate, narrower contribution.
- Otherwise the claim is dropped and the nearest works are positioned as the closest prior art.

Candidate sentence, allowed only under the middle case: "Within a frozen search of arXiv, OpenAlex and [third source] to [date], we find no prior work that estimates a cross-task privilege envelope from benign execution traces and scores it as attack block against held-out task success while attributing the block across a scanner, a server patch and that policy."

**Decision, this pass.** The candidate sentence is dropped. No search-freeze date is recorded.

The middle case requires a finished, dated search. That condition is not met: the refresh and full-text extraction remain incomplete, and the human second screen is pending. The generated decision in `artifacts/systematic-review/counts.json` names the current open conditions. The targeted table above is contextual evidence, not a substitute for the generated extraction table. The candidate sentence is not used.

## 9. Threats to the review's validity

- Phrase search misses non-phrase works. The concept queries bound that gap. The active OpenAlex concept retrieval visited every cell but omitted the over-cap cell; the same-day refresh failed on HTTP 429.
- Known coverage misses remain: ToFu (arXiv:2610.13651) is present in the active OpenAlex phrase source but its retrieved abstract does not match the keyword prefilter; AgentLTL (arXiv:2607.02599) is absent from the active source files. Their earlier contextual notes are not silently counted as completed screening or extraction in this corpus.
- The unauthenticated OpenAlex budget prevents a complete same-day refresh. The retained corpus spans retrieval dates; it is not a frozen single-day search.
- DBLP returned an HTML bot check on both recorded dates. Semantic Scholar supplies the replacement third source; its search coverage differs from DBLP's.
- Some bodies were never retrieved (HTTP 404/406/500, restricted deposits, the DBLP bot check); they stay in "found" and out of "read", and are listed.
- A living field: the eventual freeze date must be recorded with any bounded claim; no such date is established yet.
- Many read papers make their own "first/novel" sentences; those are the authors' claims about their own slice and are recorded as such, not treated as settling this review.
