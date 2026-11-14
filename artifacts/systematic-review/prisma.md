# PRISMA counts

Recorded 2026-11-03 by `python -m wiggle.review`.

screened counts the works with a title, the input of the keyword screen. The screener counts come from screen-decisions/ and screener-2-decisions.jsonl, read and included from reads.jsonl. decision applies section 8 of docs/systematic-review.md to the included works.

| Step | Count |
| --- | ---: |
| Found (rows retrieved, before dedupe) | 16482 |
| Deduped (DOI, then normalized title) | 12290 |
| Screened (a title was retrieved) | 12283 |
| Keyword kept | 6704 |
| Title/abstract screened by screener 1 | 6704 |
| Kept by screener 1 | 1039 |
| Dropped by screener 1 | 5665 |
| Kept for full-text reading (resolved screener-2 disagreements applied) | 1039 |
| Full text not retrieved | 2 |
| Read (full text) | 100 |
| Included | 88 |

Concept-search works absent from the phrase searches: 5821.
Of those, keyword kept: 5006.

| Source | Found | Retrieved | Complete | Started on (UTC) | Fetched on (UTC) | Error |
| --- | ---: | ---: | --- | --- | --- | --- |
| arxiv-phrase | 624 | 624 | True | — | — | — |
| arxiv-concept | 3109 | 3109 | True | — | — | — |
| openalex-phrase | 6491 | 6491 | True | 2026-11-03 | 2026-11-03 | — |
| openalex-concept | 8821 | 4822 | True | — | — | HTTP Error 429: Too Many Requests |
| dblp-phrase | — | 0 | False | — | — | DBLP returned an HTML bot check instead of the JSON API |
| s2-phrase | about 1436 | 1436 | True | 2026-11-03 | 2026-11-03 | — |

Search frozen: no. Not every complete source started and completed on one UTC date.

## Screening

Key: first 12 hex characters of sha256('doi:' + normalized DOI), or of sha256('title:' + normalized title) when the work has no DOI, or of sha256('id:' + source_id) when the title normalizes to nothing.

Screener 1 (AI-assisted; authors: `screener-1-claude`, `screener-1-codex`): 6704 of 6704 keyword-kept works decided, 1039 keep and 5665 drop. 0 have no decision.

Screener 2: pending. `screener-2-decisions.jsonl` does not exist. The sheet has 1615 works.

## Full-text reads

1039 kept works: 100 read, 2 not retrieved, 88 included. 937 have no read row. The table is `closest-works.md`.
First kept keys with no read row: 0073ea08b53b, 01e468246aa9, 021390e2de86, 028b700c85f0, 02d0e6cfc345, 036a3e535984, 03f7b920c0f0, 057ca75ac07b, 05f1af0c853a, 06209a3cb472, 0636b7180519, 06973e31f22f, 06b44cab2be2, 06b456c2fb55, 0777418f5329, 077beae4ff64, 07acc41147a6, 07e33dbb666b, 07f1d598c06c, 08ed868936d3.

## Decision rule (section 8)

Case 2: no included work has a trace-derived policy, a strictness curve and same-trace attribution together, but the bounded claim is not allowed yet. Open: the search is not frozen to one date (arxiv-phrase no start date to no end date, arxiv-concept no start date to no end date, openalex-phrase 2026-11-03, openalex-concept no start date to no end date, s2-phrase 2026-11-03); reads: 937 kept works have no read row and 0 read rows have errors. Provisional: screener 2 is pending.
