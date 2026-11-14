"""Systematic-review retrieval, screening records and PRISMA counts.

`docs/systematic-review.md` is the protocol. This command carries the two
searches that protocol leaves open, plus the phrase searches, the DBLP source
and the Semantic Scholar source, and writes the counts a script has to write.

`python -m wiggle.review` reads the cache and the screening files and writes
`counts.json`, `prisma.md`, `screen.jsonl` and `closest-works.md`.
`python -m wiggle.review fetch` retrieves each source and resumes from the
saved cursor. A HTTP 429 backs off and the cursor is not advanced.
`fetch --restart` first clears the state entry and works file of each
selected source, so the source is retrieved from the start. A source
retrieved from the start records the UTC start date (`started_on`), which a
resume keeps, and a source that completes records the UTC completion date
(`fetched_on`). The search is frozen only when every complete source started
and completed on one UTC date. No model is called.

Screening: `batches --size N` writes the keyword-kept works (the set
`screen.jsonl` lists) in key order to `screen-batches/batch-NNN.jsonl`. A
work's key is the first 12 hexadecimal characters of the SHA-256 of its
dedupe identity: `doi:` and the normalized DOI, or `title:` and the
normalized title when the work has no DOI, or `id:` and the source's own id
when the title normalizes to nothing (a title in a non-Latin script; the
dedupe then also matches on that id). Screener 1 writes one decision per
key to `screen-decisions/*.jsonl`. `screener2` writes the screener-2 sheet:
every keep and the drops whose key, read as a hexadecimal number, is divisible
by 10. Screener 2 decides in `screener-2-decisions.jsonl`, and the full-text
reads of the kept works go in `reads.jsonl`. The counts apply the decision
rule of section 8 to the included works.

OpenAlex has no boolean search. The concept query is sent to arXiv in the
protocol's boolean form. On OpenAlex the same three groups are the cartesian
product of `title_and_abstract.search` filters (AND inside a cell, OR across
cells). A cell whose count is above `CONCEPT_CELL_CAP` is counted and not
downloaded, and the count file says so. OpenAlex cursor paging past the first
page requires an API key, so these calls use `page` instead.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "artifacts" / "systematic-review"
MAILTO = "johnsonleung963@gmail.com"
USER_AGENT = f"On9MCP-review/0.1 (mailto:{MAILTO})"

PHRASE = '"Model Context Protocol"'
CONCEPT_GROUPS = (
    ('"tool-using"', '"tool-calling"', "agent"),
    ('"prompt injection"', '"least privilege"', "privilege", "capability"),
    ("defense", "policy", "envelope"),
)
# arXiv accepts the protocol's boolean. Grouped so a reader can match it to section 3.
ARXIV_CONCEPT = (
    '(all:"tool-using" OR all:"tool-calling" OR all:agent) AND '
    '(all:"prompt injection" OR all:"least privilege" OR all:privilege OR all:capability) AND '
    "(all:defense OR all:policy OR all:envelope)"
)
KEYWORD_TERMS = (
    "privilege",
    "policy",
    "utility",
    "attack success",
    "defense",
    "trace",
    "held-out",
    "least privilege",
    "needed",
    "benign",
    "strictness",
    "attribution",
    "envelope",
)
# A cell larger than this is counted and left for a later resume. Stated in the counts file.
CONCEPT_CELL_CAP = 2000
ARXIV_PAGE = 100
OPENALEX_PAGE = 200
DBLP_PAGE = 1000
ATTEMPTS = 6
# Semantic Scholar bulk search returns up to 1,000 papers per call and has no page-size parameter.
S2_BULK = "https://api.semanticscholar.org/graph/v1/paper/search/bulk"
S2_FIELDS = "title,abstract,year,externalIds,venue,publicationTypes,url"
# Sources whose found count is the API's estimate. prisma.md prints it as "about N".
ESTIMATED_FOUND = ("s2-phrase",)

ATOM = "http://www.w3.org/2005/Atom"
OPENSEARCH = "http://a9.com/-/spec/opensearch/1.1/"
ARXIV_NS = "http://arxiv.org/schemas/atom"
PHRASE_SOURCES = ("arxiv-phrase", "openalex-phrase", "dblp-phrase", "s2-phrase")
CONCEPT_SOURCES = ("arxiv-concept", "openalex-concept")
# The bot check of 2026-11-02 and 2026-11-03. Only that recorded failure (this error, nothing retrieved) does not
# block the middle case.
DBLP_SOURCE = "dblp-phrase"
DBLP_BOT_CHECK = "DBLP returned an HTML bot check instead of the JSON API"

KEY_LENGTH = 12
KEY_RULE = (
    "first 12 hex characters of sha256('doi:' + normalized DOI), or of sha256('title:' + normalized title) "
    "when the work has no DOI, or of sha256('id:' + source_id) when the title normalizes to nothing"
)
SCREENER_1 = "screener-1-claude"
SCREENER_1_IDS = (SCREENER_1, "screener-1-codex")
# A screener-1 drop goes on the screener-2 sheet when its key, read as a hex number, is divisible by this.
SCREENER_2_SAMPLE = 10
DECISIONS = ("keep", "drop")
CRITERIA = ("1", "2", "3", "none")
NOT_RETRIEVED = "not retrieved:"
PROPERTY_VALUES = ("yes", "no", "not stated")
# Section 6 of the protocol: the reads.jsonl property and its column title.
PROPERTIES = (
    ("trace_derived_policy", "Trace-derived policy?"),
    ("strictness_curve", "Strictness curve?"),
    ("same_trace_attribution", "Same-trace attribution?"),
    ("utility_reported", "Utility reported?"),
    ("mcp", "MCP?"),
    ("policy_input_poisoning", "Policy-input poisoning?"),
)
# Section 8: the conjunction the bounded claim is worded to.
CORE_PROPERTIES = ("trace_derived_policy", "strictness_curve", "same_trace_attribution")
SCREENER_2_OPEN = {
    "pending": "screener 2 is pending",
    "in progress": "screener 2 has not decided every sheet row",
    "invalid rows": "the screener-2 file has invalid rows",
    "unresolved": "a screener-2 disagreement is not resolved",
}
# Longest list of keys or errors that prisma.md prints. counts.json keeps every key and error.
LIST_LIMIT = 20


class FetchError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


def concept_cells() -> list[str]:
    """One OpenAlex filter per conjunction of the protocol's three groups."""
    cells = []
    for left in CONCEPT_GROUPS[0]:
        for middle in CONCEPT_GROUPS[1]:
            for right in CONCEPT_GROUPS[2]:
                parts = ",".join(f"title_and_abstract.search:{term}" for term in (left, middle, right))
                cells.append(parts)
    return cells


def abstract_from_inverted(index: dict | None) -> str:
    """OpenAlex stores an abstract as word to positions. Put the words back in order."""
    if not isinstance(index, dict):
        return ""
    placed: list[tuple[int, str]] = []
    for word, spots in index.items():
        if not isinstance(spots, list):
            continue
        for spot in spots:
            if isinstance(spot, int):
                placed.append((spot, str(word)))
    placed.sort()
    return " ".join(word for _, word in placed)


def normalize_title(title: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", title.casefold()).split())


def normalize_doi(doi: str) -> str:
    text = doi.strip().casefold()
    for prefix in ("https://doi.org/", "http://doi.org/", "doi:"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    return text


def matched_terms(title: str, abstract: str) -> list[str]:
    """Keyword screen from the protocol. `held-out` also matches the spaced form."""
    text = f"{title}\n{abstract}".casefold()
    found = []
    for term in KEYWORD_TERMS:
        forms = (term.casefold(),)
        if term == "held-out":
            forms = ("held-out", "held out")
        if any(form in text for form in forms):
            found.append(term)
    return found


def _fallback_id(work: dict, doi: str, title: str) -> str:
    """The source's own id, used only when the work has no DOI and its title normalizes to nothing (a non-Latin script)."""
    return "" if doi or title else str(work.get("source_id") or "").strip()


def _dedupe_groups(works: list[dict]) -> list[tuple[dict, list[str]]]:
    """Keep the first work with every source that returned it. A later copy with the same DOI, or else the same title, joins it."""
    by_doi: dict[str, int] = {}
    by_title: dict[str, int] = {}
    by_id: dict[str, int] = {}
    groups: list[tuple[dict, list[str]]] = []
    for work in works:
        doi, title = _identity(work)
        fallback = _fallback_id(work, doi, title)
        index = by_doi.get(doi) if doi else None
        if index is None and title:
            index = by_title.get(title)
        if index is None and fallback:
            index = by_id.get(fallback)
        source = str(work.get("source") or "")
        if index is not None:
            if source not in groups[index][1]:
                groups[index][1].append(source)
            continue
        if doi:
            by_doi[doi] = len(groups)
        if title:
            by_title[title] = len(groups)
        if fallback:
            by_id[fallback] = len(groups)
        groups.append((work, [source]))
    return groups


def dedupe(works: list[dict]) -> list[dict]:
    """Keep the first work. A later copy with the same DOI, or else the same title, drops out."""
    return [work for work, _sources in _dedupe_groups(works)]


def work_key(work: dict) -> str:
    """The screening key: a SHA-256 prefix of the dedupe identity (normalized DOI, else normalized title, else source id)."""
    doi, title = _identity(work)
    if doi:
        identity = f"doi:{doi}"
    elif title:
        identity = f"title:{title}"
    else:
        identity = f"id:{_fallback_id(work, doi, title)}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:KEY_LENGTH]


def keyword_kept(works: list[dict]) -> list[dict]:
    """The keyword screen: deduped works with a title whose title or abstract has a term.

    Each row adds its key, its terms and every source that returned the work.
    """
    kept = []
    keys: set[str] = set()
    for work, sources in _dedupe_groups(works):
        title = str(work.get("title") or "")
        if not title.strip():
            continue
        terms = matched_terms(title, str(work.get("abstract") or ""))
        if not terms:
            continue
        key = work_key(work)
        if key in keys:
            raise ValueError(f"two kept works share the key {key}; make KEY_LENGTH longer")
        keys.add(key)
        kept.append({**work, "key": key, "terms": terms, "sources": sources})
    return kept


def _local(tag: str, name: str) -> str:
    return f"{{{tag}}}{name}"


def parse_arxiv(payload: bytes) -> tuple[int, list[dict]]:
    root = ET.fromstring(payload)
    total_text = root.findtext(_local(OPENSEARCH, "totalResults")) or "0"
    total = int(total_text)
    works = []
    for entry in root.findall(_local(ATOM, "entry")):
        arxiv_id = (entry.findtext(_local(ATOM, "id")) or "").strip()
        title = " ".join((entry.findtext(_local(ATOM, "title")) or "").split())
        abstract = " ".join((entry.findtext(_local(ATOM, "summary")) or "").split())
        published = (entry.findtext(_local(ATOM, "published")) or "")[:4]
        doi = (entry.findtext(_local(ARXIV_NS, "doi")) or "").strip()
        if not doi:
            for link in entry.findall(_local(ATOM, "link")):
                if link.attrib.get("title") == "doi":
                    doi = link.attrib.get("href", "")
        works.append(
            {
                "source_id": arxiv_id,
                "title": title,
                "abstract": abstract,
                "year": published,
                "doi": doi,
                "venue": " ".join((entry.findtext(_local(ARXIV_NS, "journal_ref")) or "").split()),
            }
        )
    return total, works


def parse_openalex(payload: bytes) -> tuple[int, str | None, list[dict]]:
    data = json.loads(payload)
    meta = data.get("meta") or {}
    total = int(meta.get("count") or 0)
    cursor = meta.get("next_cursor") or None
    works = []
    for row in data.get("results") or []:
        if not isinstance(row, dict):
            continue
        venue = ((row.get("primary_location") or {}).get("source") or {}).get("display_name")
        works.append(
            {
                "source_id": str(row.get("id") or ""),
                "title": " ".join(str(row.get("display_name") or "").split()),
                "abstract": abstract_from_inverted(row.get("abstract_inverted_index")),
                "year": str(row.get("publication_year") or ""),
                "doi": str(row.get("doi") or ""),
                "venue": " ".join(str(venue or "").split()),
            }
        )
    return total, cursor, works


def parse_dblp(payload: bytes) -> tuple[int, list[dict]]:
    data = json.loads(payload)
    hits = (data.get("result") or {}).get("hits") or {}
    total = int(hits.get("@total") or 0)
    raw = hits.get("hit") or []
    if isinstance(raw, dict):
        raw = [raw]
    works = []
    for hit in raw:
        info = hit.get("info") or {}
        venue = info.get("venue") or ""
        if isinstance(venue, list):
            venue = ", ".join(str(part) for part in venue)
        works.append(
            {
                "source_id": str(info.get("key") or hit.get("@id") or ""),
                "title": " ".join(str(info.get("title") or "").split()),
                "abstract": "",
                "year": str(info.get("year") or ""),
                "doi": str(info.get("doi") or ""),
                "venue": str(venue),
            }
        )
    return total, works


def parse_s2(payload: bytes) -> tuple[int, str | None, list[dict]]:
    """One page of the Semantic Scholar bulk search. `total` is the API's estimate; no token means the last page."""
    data = json.loads(payload)
    if not isinstance(data, dict) or ("data" not in data and "total" not in data):
        raise ValueError("the Semantic Scholar response has no total and no data")
    total = int(data.get("total") or 0)
    token = data.get("token") or None
    works = []
    for row in data.get("data") or []:
        if not isinstance(row, dict):
            continue
        ids = row.get("externalIds") or {}
        kinds = row.get("publicationTypes")
        works.append(
            {
                "source_id": str(row.get("url") or ""),
                "title": " ".join(str(row.get("title") or "").split()),
                "abstract": " ".join(str(row.get("abstract") or "").split()),
                "year": str(row.get("year") or ""),
                "doi": str(ids.get("DOI") or "") if isinstance(ids, dict) else "",
                "venue": " ".join(str(row.get("venue") or "").split()),
                "publication_types": [str(kind) for kind in kinds] if isinstance(kinds, list) else [],
            }
        )
    return total, token, works


def _retry_delay(exc: urllib.error.HTTPError, attempt: int) -> float:
    header = ""
    if exc.headers:
        header = exc.headers.get("Retry-After") or ""
    try:
        return min(60.0, float(header))
    except ValueError:
        return min(60.0, float(2**attempt))


def urllib_get(url: str, timeout: float = 60, attempts: int = ATTEMPTS, sleep=time.sleep) -> bytes:
    """GET one URL. Retry 429 and 5xx. Other HTTP statuses raise FetchError and do not retry."""
    last: Exception | None = None
    for attempt in range(attempts):
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            last = exc
            # 401 has come back from OpenAlex mid-pagination and then cleared. Retry it like a 429.
            if exc.code not in {401, 429, 500, 502, 503, 504}:
                raise FetchError(exc.code, f"HTTP {exc.code} for {url}") from exc
            delay = _retry_delay(exc, attempt)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            delay = min(60.0, float(2**attempt))
        if attempt + 1 < attempts:
            sleep(delay)
    status = getattr(last, "code", 0) or 0
    raise FetchError(int(status), f"{last}")


def _query(url: str, params: dict[str, str]) -> str:
    return url + "?" + urllib.parse.urlencode(params)


def arxiv_url(query: str, start: int) -> str:
    return _query(
        "https://export.arxiv.org/api/query",
        {"search_query": query, "start": str(start), "max_results": str(ARXIV_PAGE)},
    )


def openalex_url(params: dict[str, str]) -> str:
    full = {"mailto": MAILTO, "per-page": str(OPENALEX_PAGE), **params}
    return _query("https://api.openalex.org/works", full)


def dblp_url(offset: int) -> str:
    return _query(
        "https://dblp.org/search/publ/api",
        {"q": PHRASE, "format": "json", "h": str(DBLP_PAGE), "f": str(offset)},
    )


def s2_url(token: str | None) -> str:
    """The bulk search keeps the same parameters on every page and adds the continuation token after the first."""
    params = {"query": PHRASE, "fields": S2_FIELDS}
    if token:
        params["token"] = token
    return _query(S2_BULK, params)


def _blank_source(query: str) -> dict:
    return {
        "query": query,
        "found": None,
        "retrieved": 0,
        "cursor": None,
        "complete": False,
        "error": "",
        "status": None,
        "cells": [],
    }


def _load_state(path: Path) -> dict:
    if not path.is_file():
        return {"sources": {}}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {"sources": {}}


def _save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _append_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _tag(source: str, rows: list[dict], cell: str = "") -> list[dict]:
    tagged = []
    for row in rows:
        item = dict(row)
        item["source"] = source
        if cell:
            item["cell"] = cell
        tagged.append(item)
    return tagged


def _finish_page(entry: dict, found: int, added: int, cursor, done: bool) -> None:
    entry["found"] = found
    entry["retrieved"] = int(entry.get("retrieved") or 0) + added
    entry["cursor"] = cursor
    entry["complete"] = done
    if done:
        entry["error"] = ""
        entry["status"] = None


def fetch_arxiv(entry: dict, path: Path, query: str, get, sleep, pause: float, save) -> None:
    start = int(entry["cursor"] or 0)
    while not entry["complete"]:
        total, works = parse_arxiv(get(arxiv_url(query, start)))
        _append_jsonl(path, _tag(path.stem, works))
        start += len(works)
        done = start >= total or not works
        _finish_page(entry, total, len(works), start, done)
        save()
        print(f"{path.stem}: {entry['retrieved']}/{entry['found']}", flush=True)
        if not done:
            sleep(pause)


def _use_page_paging(entry: dict, path: Path, save) -> None:
    """Drop a cursor-paged partial. Cursor pages past the first one need an OpenAlex API key."""
    if entry.get("paging") == "page":
        return
    if path.is_file():
        path.unlink()
    entry["paging"] = "page"
    entry["retrieved"] = 0
    entry["cursor"] = 1
    entry["cells"] = []
    entry["error"] = ""
    entry["complete"] = False
    save()


def fetch_openalex_phrase(entry: dict, path: Path, get, sleep, pause: float, save) -> None:
    _use_page_paging(entry, path, save)
    page = int(entry["cursor"] or 1)
    while not entry["complete"]:
        total, _nxt, works = parse_openalex(get(openalex_url({"search": PHRASE, "page": str(page)})))
        _append_jsonl(path, _tag(path.stem, works))
        page += 1
        got = int(entry.get("retrieved") or 0) + len(works)
        done = not works or got >= total
        _finish_page(entry, total, len(works), page, done)
        save()
        print(f"{path.stem}: {entry['retrieved']}/{entry['found']}", flush=True)
        if not done:
            sleep(pause)


def fetch_openalex_concept(entry: dict, path: Path, get, sleep, pause: float, save) -> None:
    _use_page_paging(entry, path, save)
    cells = entry["cells"]
    if not cells:
        cells = [
            {"query": cell, "found": None, "retrieved": 0, "page": 1, "complete": False, "skipped": ""}
            for cell in concept_cells()
        ]
        entry["cells"] = cells
        save()
    retrieved = 0
    found_sum = 0
    for cell in cells:
        if cell.get("complete"):
            retrieved += int(cell.get("retrieved") or 0)
            found_sum += int(cell.get("found") or 0)
            continue
        page = int(cell.get("page") or 1)
        retrieved += int(cell.get("retrieved") or 0)
        while not cell["complete"]:
            page_total, _nxt, works = parse_openalex(get(openalex_url({"filter": cell["query"], "page": str(page)})))
            cell["found"] = page_total
            # The first page carries the count, so no separate count request: on 2026-11-03 the free OpenAlex
            # budget was $0.10 a day per IP at $0.001 a request, and a run with count requests needs 119.
            if page == 1 and page_total > CONCEPT_CELL_CAP:
                cell["complete"] = True
                cell["skipped"] = f"count {page_total} is above the cap of {CONCEPT_CELL_CAP}; counted, not downloaded"
                entry["retrieved"] = retrieved
                entry["found"] = found_sum + page_total
                save()
                print(f"openalex-concept: skipped a cell of {page_total} (cap {CONCEPT_CELL_CAP})", flush=True)
                break
            _append_jsonl(path, _tag(path.stem, works, cell["query"]))
            added = len(works)
            cell["retrieved"] = int(cell.get("retrieved") or 0) + added
            retrieved += added
            page += 1
            cell["page"] = page
            done = not works or int(cell["retrieved"]) >= int(cell["found"] or 0)
            cell["complete"] = done
            entry["retrieved"] = retrieved
            entry["found"] = found_sum + page_total
            save()
            print(f"openalex-concept: {retrieved} rows, cell {cell['retrieved']}/{cell['found']}", flush=True)
            if not done:
                sleep(pause)
        found_sum += int(cell.get("found") or 0)
    entry["found"] = found_sum
    entry["retrieved"] = retrieved
    entry["complete"] = all(cell.get("complete") for cell in cells)
    save()


def fetch_dblp(entry: dict, path: Path, get, sleep, pause: float, save) -> None:
    offset = int(entry["cursor"] or 0)
    while not entry["complete"]:
        payload = get(dblp_url(offset))
        if payload.lstrip().startswith(b"<"):
            raise FetchError(202, DBLP_BOT_CHECK)
        total, works = parse_dblp(payload)
        _append_jsonl(path, _tag(path.stem, works))
        offset += len(works)
        done = offset >= total or not works
        _finish_page(entry, total, len(works), offset, done)
        save()
        print(f"{path.stem}: {entry['retrieved']}/{entry['found']}", flush=True)
        if not done:
            sleep(pause)


def fetch_s2(entry: dict, path: Path, get, sleep, pause: float, save) -> None:
    """Page with the continuation token. `total` is an estimate, so a page without a token ends the source."""
    token = entry["cursor"] or None
    while not entry["complete"]:
        total, token, works = parse_s2(get(s2_url(token)))
        _append_jsonl(path, _tag(path.stem, works))
        done = not token or not works
        _finish_page(entry, total, len(works), token, done)
        save()
        print(f"{path.stem}: {entry['retrieved']} of about {entry['found']}", flush=True)
        if not done:
            sleep(pause)


FETCHERS = {
    "arxiv-phrase": lambda entry, path, get, sleep, pause, save: fetch_arxiv(
        entry, path, 'all:"Model Context Protocol"', get, sleep, pause, save
    ),
    "arxiv-concept": lambda entry, path, get, sleep, pause, save: fetch_arxiv(
        entry, path, ARXIV_CONCEPT, get, sleep, pause, save
    ),
    "openalex-phrase": fetch_openalex_phrase,
    "openalex-concept": fetch_openalex_concept,
    "dblp-phrase": fetch_dblp,
    "s2-phrase": fetch_s2,
}

QUERIES = {
    "arxiv-phrase": 'all:"Model Context Protocol"',
    "arxiv-concept": ARXIV_CONCEPT,
    "openalex-phrase": PHRASE + " (search parameter; OpenAlex has no boolean parser)",
    "openalex-concept": "cartesian product of the three concept groups, title_and_abstract.search, AND inside a cell",
    "dblp-phrase": PHRASE + " (DBLP publ search; metadata only, no abstracts)",
    "s2-phrase": PHRASE + " (Semantic Scholar bulk paper search on title and abstract, terms stemmed; found is the API's estimate)",
}


def works_path(out: Path, source: str) -> Path:
    return out / "works" / f"{source}.jsonl"


def _utc_today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def fetch_sources(
    out: Path,
    only: set[str] | None = None,
    get=urllib_get,
    sleep=time.sleep,
    pause: float | None = None,
    restart: bool = False,
    today=_utc_today,
) -> dict:
    """Retrieve every source that is not already complete. One source's error does not cancel the others.

    `restart` first drops the state entry and the works file of each selected source, so it is retrieved
    from the start. A source retrieved from the start records the UTC start date as `started_on`, which a
    resume keeps. A source that completes records the UTC date of completion as `fetched_on`.
    """
    state = _load_state(out / "state.json")
    sources = state.setdefault("sources", {})
    names = [name for name in FETCHERS if only is None or name in only]
    if restart:
        for name in names:
            sources.pop(name, None)
            path = works_path(out, name)
            if path.is_file():
                path.unlink()
        _save_state(out / "state.json", state)
    for name in names:
        entry = sources.get(name)
        if not entry:
            entry = {**_blank_source(QUERIES[name]), "started_on": today()}
        sources[name] = entry
        if entry.get("complete"):
            continue
        entry.pop("fetched_on", None)
        path = works_path(out, name)
        source_pause = 3.0 if name.startswith("arxiv") else 1.0
        if pause is not None:
            source_pause = pause

        def save(state=state, out=out) -> None:
            _save_state(out / "state.json", state)

        try:
            FETCHERS[name](entry, path, get, sleep, source_pause, save)
            if entry.get("complete"):
                # A resumed source can still hold the error of an earlier stop.
                entry["error"] = ""
                entry["status"] = None
                entry["fetched_on"] = today()
            save()
        except FetchError as exc:
            entry["error"] = str(exc)
            entry["status"] = exc.status
            entry["complete"] = False
            _save_state(out / "state.json", state)
        except (ET.ParseError, json.JSONDecodeError, ValueError) as exc:
            entry["error"] = f"unreadable response: {exc}"
            entry["status"] = 0
            _save_state(out / "state.json", state)
    return state


def load_works(out: Path) -> list[dict]:
    rows = []
    for name in FETCHERS:
        for row in _read_jsonl(works_path(out, name)):
            item = dict(row)
            item.setdefault("source", name)
            rows.append(item)
    return rows


def _identity(work: dict) -> tuple[str, str]:
    return normalize_doi(str(work.get("doi") or "")), normalize_title(str(work.get("title") or ""))


def concept_only(works: list[dict]) -> list[dict]:
    """Concept-search works that the phrase searches did not already return."""
    phrase_doi: set[str] = set()
    phrase_title: set[str] = set()
    for work in works:
        if work.get("source") not in PHRASE_SOURCES:
            continue
        doi, title = _identity(work)
        if doi:
            phrase_doi.add(doi)
        if title:
            phrase_title.add(title)
    extra = []
    seen_doi: set[str] = set()
    seen_title: set[str] = set()
    for work in works:
        if work.get("source") not in CONCEPT_SOURCES:
            continue
        doi, title = _identity(work)
        if (doi and doi in phrase_doi) or (title and title in phrase_title):
            continue
        if (doi and doi in seen_doi) or (title and title in seen_title):
            continue
        if doi:
            seen_doi.add(doi)
        if title:
            seen_title.add(title)
        extra.append(work)
    return extra


def _text(value) -> str:
    return "" if value is None else str(value).strip().casefold()


def _jsonl_rows(path: Path, errors: list[str]) -> list[tuple[str, dict]]:
    """The objects of a hand- or model-written JSONL file, with their place. A broken line is an error, not a crash."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"{path.name}: unreadable ({exc})")
        return []
    rows = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        place = f"{path.name}:{number}"
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{place}: not JSON ({exc.msg})")
            continue
        if not isinstance(row, dict):
            errors.append(f"{place}: not a JSON object")
            continue
        rows.append((place, row))
    return rows


def _decision_problem(row: dict, first: bool) -> str:
    """Why a screening row is invalid, or "". Screener 1 rows need every field; screener 2 rows need the decision."""
    decision = _text(row.get("decision"))
    criterion = _text(row.get("criterion"))
    if decision not in DECISIONS:
        return f"decision must be keep or drop, not {row.get('decision')!r}"
    if (first or criterion) and criterion not in CRITERIA:
        return f"criterion must be 1, 2, 3 or none, not {row.get('criterion')!r}"
    if decision == "keep" and criterion == "none":
        return "a keep must name criterion 1, 2 or 3"
    if first and not str(row.get("reason") or "").strip():
        return "reason is empty"
    if first and row.get("screener") not in SCREENER_1_IDS:
        return f"screener must be one of {SCREENER_1_IDS}, not {row.get('screener')!r}"
    if not first and str(row.get("screener") or "").strip() in ("", *SCREENER_1_IDS):
        return f"screener must name screener 2, not {row.get('screener')!r}"
    if _text(row.get("resolved")) not in ("", *DECISIONS):
        return "resolved must be keep or drop"
    return ""


def screener_1_record(out: Path, keys: set[str]) -> tuple[dict[str, str], dict]:
    """Merge every file in `screen-decisions/`. Return key to decision, and the summary with its errors."""
    folder = out / "screen-decisions"
    decisions: dict[str, str] = {}
    first_at: dict[str, str] = {}
    errors: list[str] = []
    for path in sorted(folder.glob("*.jsonl")) if folder.is_dir() else []:
        for place, row in _jsonl_rows(path, errors):
            key = str(row.get("key") or "")
            problem = _decision_problem(row, first=True)
            if not problem and key not in keys:
                problem = f"unknown key {key!r}"
            if not problem and key in decisions:
                problem = f"duplicate key {key} (first at {first_at[key]})"
            if problem:
                errors.append(f"{place}: {problem}")
                continue
            decisions[key] = _text(row["decision"])
            first_at[key] = place
    missing = sorted(keys - decisions.keys())
    keep = sum(1 for value in decisions.values() if value == "keep")
    return decisions, {
        "decided": len(decisions),
        "keep": keep,
        "drop": len(decisions) - keep,
        "missing": len(missing),
        "missing_keys": missing,
        "errors": errors,
    }


def screener_2_sample(decisions: dict[str, str]) -> list[str]:
    """Every keep, and the drops whose key, read as a hexadecimal number, is divisible by 10. Key order, no random state."""
    return sorted(key for key, value in decisions.items() if value == "keep" or int(key, 16) % SCREENER_2_SAMPLE == 0)


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    """Cohen's kappa of two screeners on keep or drop. None when there is no pair or chance agreement is 1."""
    if not pairs:
        return None
    total = len(pairs)
    observed = sum(1 for first, second in pairs if first == second) / total
    first_keep = sum(1 for first, _second in pairs if first == "keep") / total
    second_keep = sum(1 for _first, second in pairs if second == "keep") / total
    chance = first_keep * second_keep + (1 - first_keep) * (1 - second_keep)
    if chance >= 1:
        return None
    return (observed - chance) / (1 - chance)


def screener_2_record(out: Path, decisions: dict[str, str], index: dict[str, dict]) -> tuple[dict[str, str], dict]:
    """Compare screener 2 with screener 1 on the sheet. Return each work's final decision, and the summary.

    On a disagreement, the row's `resolved` (keep or drop, written after the joint reading) replaces screener 1's
    decision. A `resolved` on a row where the two screeners agree is an error. A row with a blank decision is not
    decided yet.
    """
    sheet = screener_2_sample(decisions)
    final = dict(decisions)
    summary = {
        "status": "pending",
        "sheet": len(sheet),
        "decided": 0,
        "agree": 0,
        "kappa": None,
        "missing": len(sheet),
        "disagreements": [],
        "errors": [],
    }
    path = out / "screener-2-decisions.jsonl"
    if not path.is_file():
        return final, summary
    errors = summary["errors"]
    on_sheet = set(sheet)
    seconds: dict[str, tuple[str, dict]] = {}
    for place, row in _jsonl_rows(path, errors):
        if not _text(row.get("decision")):
            continue
        key = str(row.get("key") or "")
        problem = _decision_problem(row, first=False)
        if not problem and key not in on_sheet:
            problem = f"key {key!r} is not on the screener-2 sheet"
        if not problem and key in seconds:
            problem = f"duplicate key {key}"
        if problem:
            errors.append(f"{place}: {problem}")
            continue
        seconds[key] = (place, row)
    pairs = []
    disagreements = []
    for key in sheet:
        if key not in seconds:
            continue
        place, answer = seconds[key]
        second = _text(answer["decision"])
        resolved = _text(answer.get("resolved"))
        pairs.append((decisions[key], second))
        if second == decisions[key]:
            if resolved:
                errors.append(f"{place}: resolved is set, but both screeners decided {second}")
            continue
        if resolved:
            final[key] = resolved
        disagreements.append(
            {
                "key": key,
                "title": str(index[key].get("title") or ""),
                "screener_1": decisions[key],
                "screener_2": second,
                "resolved": resolved or None,
            }
        )
    missing = len(sheet) - len(pairs)
    if missing:
        status = "in progress"
    elif errors:
        status = "invalid rows"
    elif any(row["resolved"] is None for row in disagreements):
        status = "unresolved"
    else:
        status = "complete"
    kappa = cohen_kappa(pairs)
    summary.update(
        status=status,
        decided=len(pairs),
        agree=sum(1 for first, second in pairs if first == second),
        kappa=None if kappa is None else round(kappa, 3),
        missing=missing,
        disagreements=disagreements,
    )
    return final, summary


def _read_problem(row: dict) -> str:
    """Why a reads.jsonl row is invalid, or ""."""
    status = _text(row.get("status"))
    read = status == "read"
    if not read and not (status.startswith(NOT_RETRIEVED) and status[len(NOT_RETRIEVED) :].strip()):
        return 'status must be "read" or "not retrieved: <HTTP status or reason>"'
    included = row.get("included")
    if not isinstance(included, bool):
        return "included must be true or false"
    if included and not read:
        return "a work whose full text was not retrieved cannot be included"
    if not isinstance(row.get("evidence") or {}, dict):
        return "evidence must map a property to a short quote or section"
    if not read:
        return ""
    properties = row.get("properties")
    if not isinstance(properties, dict):
        return "properties must be an object"
    for name, _title in PROPERTIES:
        if _text(properties.get(name)) not in PROPERTY_VALUES:
            return f"{name} must be yes, no or not stated"
    if included:
        # Section 6: a yes or a no comes from the full text. The core cells decide section 8, so they cite it.
        evidence = row.get("evidence") or {}
        for name in CORE_PROPERTIES:
            if _text(properties.get(name)) != "not stated" and not str(evidence.get(name) or "").strip():
                return f"an included work needs evidence for {name}"
    if not included and not str(row.get("exclusion_reason") or "").strip():
        return "a read that is not included needs an exclusion_reason"
    return ""


def _label(work: dict, url: str = "") -> str:
    """A work's title and identifier, for the generated tables."""
    doi = normalize_doi(str(work.get("doi") or ""))
    where = f"doi:{doi}" if doi else (url or str(work.get("source_id") or ""))
    title = str(work.get("title") or "")
    return f"{title} ({where})" if where else title


def reads_record(out: Path, index: dict[str, dict], kept: list[str]) -> tuple[dict, list[dict], list[dict]]:
    """Merge `reads.jsonl` over the kept works. Return the summary, the closest-works rows and the bodies not retrieved."""
    path = out / "reads.jsonl"
    errors: list[str] = []
    wanted = set(kept)
    rows: dict[str, dict] = {}
    for place, row in _jsonl_rows(path, errors) if path.is_file() else []:
        key = str(row.get("key") or "")
        problem = _read_problem(row)
        if not problem and key not in wanted:
            problem = f"key {key!r} is not a kept work" if key in index else f"unknown key {key!r}"
        if not problem and key in rows:
            problem = f"duplicate key {key}"
        if problem:
            errors.append(f"{place}: {problem}")
            continue
        rows[key] = row
    closest = []
    missed = []
    read = 0
    for key in sorted(rows):
        row = rows[key]
        label = _label(index[key], str(row.get("url") or ""))
        if _text(row["status"]) != "read":
            missed.append({"key": key, "work": label, "status": " ".join(str(row["status"]).split())})
            continue
        read += 1
        if row["included"]:
            evidence = row.get("evidence") or {}
            closest.append(
                {
                    "key": key,
                    "work": label,
                    "properties": {name: _text(row["properties"].get(name)) for name, _title in PROPERTIES},
                    "evidence": {name: " ".join(str(evidence.get(name) or "").split()) for name, _title in PROPERTIES},
                    "note": " ".join(str(row.get("note") or "").split()),
                }
            )
    missing = sorted(wanted - rows.keys())
    summary = {
        "kept": len(kept),
        "rows": len(rows),
        "read": read,
        "not_retrieved": len(missed),
        "included": len(closest),
        "missing": len(missing),
        "missing_keys": missing,
        "errors": errors,
    }
    return summary, closest, missed


def search_frozen(sources: dict) -> str | None:
    """The one UTC date on which every complete source started and completed, else None."""
    dates = {row["fetched_on"] if row["started_on"] == row["fetched_on"] else None for row in sources.values() if row["complete"]}
    if len(dates) == 1 and None not in dates:
        return dates.pop()
    return None


def _dates(row: dict) -> str:
    """The UTC date a source was retrieved on, or its start and end dates when they are not the same."""
    if row["started_on"] and row["started_on"] == row["fetched_on"]:
        return row["started_on"]
    return f"{row['started_on'] or 'no start date'} to {row['fetched_on'] or 'no end date'}"


def _open_conditions(sources: dict, frozen: str | None, screener_1: dict, reads: dict) -> list[str]:
    """The conditions of the middle case (section 8) that are not met yet."""
    items = []
    if not frozen:
        dates = ", ".join(f"{name} {_dates(row)}" for name, row in sources.items() if row["complete"])
        items.append(f"the search is not frozen to one date ({dates or 'no source is complete'})")
    for name, row in sources.items():
        recorded = name == DBLP_SOURCE and row["error"] == DBLP_BOT_CHECK and not row["retrieved"]
        if not row["complete"] and not recorded:
            items.append(f"{name} is not complete")
    if screener_1["missing"] or screener_1["errors"]:
        items.append(
            f"screener 1: {screener_1['missing']} keyword-kept works have no decision "
            f"and {len(screener_1['errors'])} decision rows have errors"
        )
    if reads["missing"] or reads["errors"]:
        items.append(f"reads: {reads['missing']} kept works have no read row and {len(reads['errors'])} read rows have errors")
    return items


def _scope(sources: dict, frozen: str | None, not_retrieved: int) -> str:
    """The search and its own limits (sections 8 and 9), for the text of the bounded claim."""
    done = [name for name, row in sources.items() if row["complete"]]
    limits = [f"frozen on {frozen}", "complete sources: " + (", ".join(done) or "none")]
    for name, row in sources.items():
        if row["cells_skipped"]:
            limits.append(
                f"{name} counted {row['cells_skipped_works']} works over the cell cap of {CONCEPT_CELL_CAP} "
                "and did not download them"
            )
        if not row["complete"] and row["error"]:
            limits.append(f"{name} failed: {row['error']}")
    limits.append(f"full text not retrieved for {not_retrieved} kept works, listed in closest-works.md")
    return "; ".join(limits)


def decision_rule(closest: list[dict], open_items: list[str], screener_2_status: str, scope: str = "") -> dict:
    """Section 8 over the included works.

    Case 1: an included work has every column yes. Case 2: no included work has the three core columns yes,
    and the bounded claim is allowed only when `open_items` is empty; the allowed text also names the included
    works that test policy-input poisoning (the separate, narrower contribution). Case 3: otherwise. The result
    is provisional until screener 2 is complete.
    """
    every = [row["work"] for row in closest if all(row["properties"][name] == "yes" for name, _title in PROPERTIES)]
    core = [row["work"] for row in closest if all(row["properties"][name] == "yes" for name in CORE_PROPERTIES)]
    poisoning = [row["work"] for row in closest if row["properties"]["policy_input_poisoning"] == "yes"]
    conjunction = "a trace-derived policy, a strictness curve and same-trace attribution"
    works: list[str] = []
    if every:
        case, claim, works = 1, "dropped", every
        text = (
            "Case 1: an included work has every closest-works column yes. "
            "Drop the priority claim and cite it as the precedent: " + "; ".join(every) + "."
        )
    elif not core:
        case = 2
        if open_items:
            claim = "not allowed yet"
            text = (
                f"Case 2: no included work has {conjunction} together, "
                "but the bounded claim is not allowed yet. Open: " + "; ".join(open_items) + "."
            )
        else:
            claim = "allowed"
            text = (
                f"Case 2: no included work has {conjunction} together. "
                f"The bounded claim is allowed, worded to that conjunction and to this search ({scope}). "
                "Policy-input poisoning, the separate narrower contribution of section 8: "
                + ("tested by " + "; ".join(poisoning) + "." if poisoning else "no included work tests it.")
            )
    else:
        case, claim, works = 3, "dropped", core
        text = (
            f"Case 3: an included work has {conjunction}, but not every column. "
            "Drop the claim and position the nearest works as the closest prior art: " + "; ".join(core) + "."
        )
    provisional = screener_2_status != "complete"
    if provisional:
        text += f" Provisional: {SCREENER_2_OPEN.get(screener_2_status, screener_2_status)}."
    return {
        "case": case,
        "claim": claim,
        "provisional": provisional,
        "works": works,
        "poisoning": poisoning,
        "open": open_items if case == 2 else [],
        "text": text,
    }


def build_counts(out: Path, recorded: str | None = None) -> dict:
    state = _load_state(out / "state.json")
    works = load_works(out)
    unique = dedupe(works)
    screened = [work for work in unique if str(work.get("title") or "").strip()]
    # DBLP hits have no abstract. They are screened on the title, which is all that source stores.
    kept = keyword_kept(works)
    extra = concept_only(works)
    extra_kept = [work for work in extra if matched_terms(str(work.get("title") or ""), str(work.get("abstract") or ""))]
    sources = {}
    for name in FETCHERS:
        entry = (state.get("sources") or {}).get(name) or _blank_source(QUERIES[name])
        skipped = [cell for cell in entry.get("cells") or [] if cell.get("skipped")]
        complete = bool(entry.get("complete"))
        sources[name] = {
            "query": entry.get("query") or QUERIES[name],
            "found": entry.get("found"),
            "retrieved": int(entry.get("retrieved") or 0),
            "complete": complete,
            "started_on": entry.get("started_on") or None,
            "fetched_on": (entry.get("fetched_on") or None) if complete else None,
            "error": entry.get("error") or "",
            "status": entry.get("status"),
            "cells_skipped": len(skipped),
            "cells_skipped_works": sum(int(cell.get("found") or 0) for cell in skipped),
        }
    unretrieved = sum(1 for row in sources.values() if row["error"])
    frozen = search_frozen(sources)
    index = {work["key"]: work for work in kept}
    decisions, first = screener_1_record(out, set(index))
    final, second = screener_2_record(out, decisions, index)
    chosen = sorted(key for key, value in final.items() if value == "keep")
    reads, closest, not_retrieved = reads_record(out, index, chosen)
    open_items = _open_conditions(sources, frozen, first, reads)
    decision = decision_rule(closest, open_items, second["status"], _scope(sources, frozen, reads["not_retrieved"]))
    return {
        "kind": "systematic-review-counts",
        "recorded": recorded or time.strftime("%Y-%m-%d"),
        "keyword_terms": list(KEYWORD_TERMS),
        "concept_cell_cap": CONCEPT_CELL_CAP,
        "sources": sources,
        "search_dates": {name: row["fetched_on"] for name, row in sources.items()},
        "search_frozen": frozen,
        "prisma": {
            "found": len(works),
            "deduped": len(unique),
            "screened": len(screened),
            "keyword_kept": len(kept),
            "title_abstract_screened": first["decided"],
            "screener_1_kept": first["keep"],
            "screener_1_dropped": first["drop"],
            "kept_for_full_text": len(chosen),
            "not_retrieved": reads["not_retrieved"],
            "read": reads["read"],
            "included": reads["included"],
        },
        "screening": {"key": KEY_RULE, "screener_1": first, "screener_2": second},
        "reads": reads,
        "closest_works": closest,
        "not_retrieved": not_retrieved,
        "decision": decision,
        "concept_only": len(extra),
        "concept_only_keyword_kept": len(extra_kept),
        "sources_with_errors": unretrieved,
        "note": (
            "screened counts the works with a title, the input of the keyword screen. The screener counts come "
            "from screen-decisions/ and screener-2-decisions.jsonl, read and included from reads.jsonl. "
            "decision applies section 8 of docs/systematic-review.md to the included works."
        ),
    }


def _cell(text) -> str:
    return " ".join(str(text).split()).replace("|", "/")


def _error_lines(label: str, errors: list[str]) -> list[str]:
    if not errors:
        return []
    lines = [f"{label} errors ({len(errors)}):", ""]
    lines += [f"- {_cell(error)}" for error in errors[:LIST_LIMIT]]
    if len(errors) > LIST_LIMIT:
        lines.append(f"- and {len(errors) - LIST_LIMIT} more in `counts.json`.")
    lines.append("")
    return lines


def _markdown(counts: dict) -> str:
    prisma = counts["prisma"]
    first = counts["screening"]["screener_1"]
    second = counts["screening"]["screener_2"]
    reads = counts["reads"]
    lines = [
        "# PRISMA counts",
        "",
        f"Recorded {counts['recorded']} by `python -m wiggle.review`.",
        "",
        counts["note"],
        "",
        "| Step | Count |",
        "| --- | ---: |",
        f"| Found (rows retrieved, before dedupe) | {prisma['found']} |",
        f"| Deduped (DOI, then normalized title) | {prisma['deduped']} |",
        f"| Screened (a title was retrieved) | {prisma['screened']} |",
        f"| Keyword kept | {prisma['keyword_kept']} |",
        f"| Title/abstract screened by screener 1 | {prisma['title_abstract_screened']} |",
        f"| Kept by screener 1 | {prisma['screener_1_kept']} |",
        f"| Dropped by screener 1 | {prisma['screener_1_dropped']} |",
        f"| Kept for full-text reading (resolved screener-2 disagreements applied) | {prisma['kept_for_full_text']} |",
        f"| Full text not retrieved | {prisma['not_retrieved']} |",
        f"| Read (full text) | {prisma['read']} |",
        f"| Included | {prisma['included']} |",
        "",
        f"Concept-search works absent from the phrase searches: {counts['concept_only']}.",
        f"Of those, keyword kept: {counts['concept_only_keyword_kept']}.",
        "",
        "| Source | Found | Retrieved | Complete | Started on (UTC) | Fetched on (UTC) | Error |",
        "| --- | ---: | ---: | --- | --- | --- | --- |",
    ]
    for name, row in counts["sources"].items():
        found = "—" if row["found"] is None else str(row["found"])
        if name in ESTIMATED_FOUND and row["found"] is not None:
            found = f"about {found}"
        error = row["error"].replace("|", "/") if row["error"] else "—"
        lines.append(
            f"| {name} | {found} | {row['retrieved']} | {row['complete']} | {row['started_on'] or '—'} "
            f"| {row['fetched_on'] or '—'} | {error} |"
        )
    lines.append("")
    if counts["search_frozen"]:
        lines.append(f"Search frozen: {counts['search_frozen']}. Every complete source started and completed on that UTC date.")
    else:
        lines.append("Search frozen: no. Not every complete source started and completed on one UTC date.")
    lines += ["", "## Screening", "", f"Key: {counts['screening']['key']}.", ""]
    lines.append(
        f"Screener 1 (AI-assisted; authors: {', '.join(f'`{name}`' for name in SCREENER_1_IDS)}): "
        f"{first['decided']} of {prisma['keyword_kept']} keyword-kept works decided, "
        f"{first['keep']} keep and {first['drop']} drop. {first['missing']} have no decision."
    )
    if first["missing_keys"]:
        lines.append(f"First keys with no decision: {', '.join(first['missing_keys'][:LIST_LIMIT])}.")
    lines.append("")
    lines += _error_lines("Screener-1 decision", first["errors"])
    if second["status"] == "pending":
        lines.append(f"Screener 2: pending. `screener-2-decisions.jsonl` does not exist. The sheet has {second['sheet']} works.")
    else:
        kappa = "undefined" if second["kappa"] is None else str(second["kappa"])
        lines.append(
            f"Screener 2: {second['status']}. {second['decided']} of {second['sheet']} sheet works decided. "
            f"Agreement {second['agree']} of {second['decided']}, Cohen's kappa {kappa}."
        )
    lines.append("")
    lines += _error_lines("Screener-2 decision", second["errors"])
    if second["disagreements"]:
        lines += ["| Key | Work | Screener 1 | Screener 2 | Resolved |", "| --- | --- | --- | --- | --- |"]
        for row in second["disagreements"]:
            lines.append(
                f"| {row['key']} | {_cell(row['title'])} | {row['screener_1']} | {row['screener_2']} | {row['resolved'] or '—'} |"
            )
        lines.append("")
    lines += [
        "## Full-text reads",
        "",
        f"{reads['kept']} kept works: {reads['read']} read, {reads['not_retrieved']} not retrieved, "
        f"{reads['included']} included. {reads['missing']} have no read row. The table is `closest-works.md`.",
    ]
    if reads["missing_keys"]:
        lines.append(f"First kept keys with no read row: {', '.join(reads['missing_keys'][:LIST_LIMIT])}.")
    lines.append("")
    lines += _error_lines("Read", reads["errors"])
    lines += ["## Decision rule (section 8)", "", counts["decision"]["text"], ""]
    return "\n".join(lines)


def _closest_markdown(counts: dict) -> str:
    lines = [
        "# Closest works",
        "",
        f"Generated {counts['recorded']} by `python -m wiggle.review` from `reads.jsonl`. One row per included work, "
        "with the columns of section 6 of `docs/systematic-review.md`. A cell is the reader's value, then the evidence. "
        "The note is the row's `reads.jsonl` note, which cites its `docs/related_work.md` entry.",
        "",
    ]
    if counts["closest_works"]:
        lines.append("| Key | Work | " + " | ".join(title for _name, title in PROPERTIES) + " | Note |")
        lines.append("| --- | --- | " + " | ".join("---" for _property in PROPERTIES) + " | --- |")
        for row in counts["closest_works"]:
            cells = [row["key"], row["work"]]
            for name, _title in PROPERTIES:
                note = row["evidence"][name]
                cells.append(f"{row['properties'][name]}. {note}" if note else row["properties"][name])
            cells.append(row["note"] or "—")
            lines.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
    else:
        lines.append("No included work yet.")
    lines += ["", "## Kept works whose full text was not retrieved", ""]
    if counts["not_retrieved"]:
        lines += ["| Key | Work | Status |", "| --- | --- | --- |"]
        for row in counts["not_retrieved"]:
            lines.append(f"| {row['key']} | {_cell(row['work'])} | {_cell(row['status'])} |")
    else:
        lines.append("None.")
    lines += ["", f"Kept works with no read row yet: {counts['reads']['missing']}.", ""]
    return "\n".join(lines)


def write_counts(out: Path, counts: dict | None = None) -> dict:
    counts = build_counts(out) if counts is None else counts
    out.mkdir(parents=True, exist_ok=True)
    (out / "counts.json").write_text(json.dumps(counts, indent=2) + "\n", encoding="utf-8")
    (out / "prisma.md").write_text(_markdown(counts), encoding="utf-8")
    (out / "closest-works.md").write_text(_closest_markdown(counts), encoding="utf-8")
    screen = out / "screen.jsonl"
    screen_text = "".join(
        json.dumps(
            {key: work.get(key) for key in ("source", "year", "doi", "source_id", "title", "terms")},
            ensure_ascii=False,
        ) + "\n"
        for work in keyword_kept(load_works(out))
    )
    # Reading new full texts does not change this corpus-derived screening file.
    # Avoid truncating it when the existing output is already correct.
    if not screen.exists() or screen.read_text(encoding="utf-8") != screen_text:
        screen.write_text(screen_text, encoding="utf-8")
    return counts


def _screen_row(work: dict) -> dict:
    return {
        "key": work["key"],
        "title": work.get("title") or "",
        "abstract": work.get("abstract") or "",
        "year": work.get("year") or "",
        "venue": work.get("venue") or "",
        "doi": normalize_doi(str(work.get("doi") or "")),
        "source_id": work.get("source_id") or "",
        "sources": work["sources"],
        "terms": work["terms"],
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_batches(out: Path, size: int) -> list[Path]:
    """Write the keyword-kept works in key order, `size` works per file. Earlier batch files are removed first."""
    if size < 1:
        raise ValueError("the batch size must be at least 1")
    kept = sorted(keyword_kept(load_works(out)), key=lambda work: work["key"])
    folder = out / "screen-batches"
    folder.mkdir(parents=True, exist_ok=True)
    for old in folder.glob("batch-*.jsonl"):
        old.unlink()
    paths = []
    for number, start in enumerate(range(0, len(kept), size), start=1):
        path = folder / f"batch-{number:03d}.jsonl"
        _write_jsonl(path, [_screen_row(work) for work in kept[start : start + size]])
        paths.append(path)
    return paths


def _sheet_markdown(rows: list[dict], recorded: str) -> str:
    lines = [
        "# Screener-2 sheet",
        "",
        f"Generated {recorded} by `python -m wiggle.review screener2`. {len(rows)} works: every screener-1 keep, and the "
        f"screener-1 drops whose key, read as a hexadecimal number, is divisible by {SCREENER_2_SAMPLE} (about 10% of the drops). "
        "Key order. Screener 1's decisions are not shown.",
        "",
        "Decide each work on its title and abstract against the inclusion question (section 2 of `docs/systematic-review.md`): "
        "keep or drop, the criterion (1, 2, 3 or none) and a one-sentence reason. Record the decisions in "
        "`screener-2-decisions.jsonl`, a copy of `screener-2.jsonl` with those fields filled in.",
        "",
    ]
    for number, row in enumerate(rows, start=1):
        where = f"doi:{row['doi']}" if row["doi"] else row["source_id"]
        lines += [
            f"## {number}. {' '.join(row['title'].split())}",
            "",
            f"Key `{row['key']}`; year {row['year'] or 'not stated'}; venue {row['venue'] or 'not stated'}; {where}",
            "",
            row["abstract"] or "(No abstract was retrieved.)",
            "",
            "| Decision | Criterion | Reason |",
            "| --- | --- | --- |",
            "|  |  |  |",
            "",
        ]
    return "\n".join(lines)


def write_screener_2(out: Path, recorded: str | None = None) -> dict:
    """Write the screener-2 sheet: every screener-1 keep and the sampled drops, with blank decision columns."""
    kept = keyword_kept(load_works(out))
    index = {work["key"]: work for work in kept}
    decisions, first = screener_1_record(out, set(index))
    sheet = screener_2_sample(decisions)
    rows = []
    for key in sheet:
        row = _screen_row(index[key])
        rows.append(
            {
                **{name: row[name] for name in ("key", "title", "abstract", "year", "venue", "doi", "source_id")},
                "decision": "",
                "criterion": "",
                "reason": "",
                "screener": "screener-2",
            }
        )
    _write_jsonl(out / "screener-2.jsonl", rows)
    sheet_text = "\n".join(line.rstrip() for line in _sheet_markdown(rows, recorded or time.strftime("%Y-%m-%d")).splitlines()) + "\n"
    (out / "screener-2.md").write_text(sheet_text, encoding="utf-8", newline="\n")
    keeps = sum(1 for key in sheet if decisions[key] == "keep")
    return {
        "rows": len(rows),
        "keep": keeps,
        "drop_sample": len(rows) - keeps,
        "drops": first["drop"],
        "screener_1_missing": first["missing"],
        "screener_1_errors": len(first["errors"]),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Retrieve the systematic-review sources, write the screening files and the PRISMA counts. No model is called."
    )
    parser.add_argument("command", nargs="?", choices=("counts", "fetch", "batches", "screener2"), default="counts")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--source", action="append", default=None, help="Fetch only this source. Repeatable.")
    parser.add_argument(
        "--restart",
        action="store_true",
        help="With fetch: clear the state entry and works file of each selected source (every source without --source), then retrieve it from the start.",
    )
    parser.add_argument("--size", type=int, default=100, help="With batches: works per batch file.")
    args = parser.parse_args(argv)
    out = (args.out or DEFAULT_OUT).resolve()
    if args.restart and args.command != "fetch":
        parser.error("--restart applies only to fetch")
    if args.command == "batches":
        if args.size < 1:
            parser.error("--size must be at least 1")
        paths = write_batches(out, args.size)
        print(f"Wrote {len(paths)} batch files of up to {args.size} works to {out / 'screen-batches'}.")
        return
    if args.command == "screener2":
        sheet = write_screener_2(out)
        print(
            f"Wrote {sheet['rows']} works ({sheet['keep']} keeps, {sheet['drop_sample']} of {sheet['drops']} drops) "
            f"to {out / 'screener-2.jsonl'} and {out / 'screener-2.md'}."
        )
        if sheet["screener_1_missing"] or sheet["screener_1_errors"]:
            print(
                f"Screener 1 has {sheet['screener_1_missing']} works with no decision and "
                f"{sheet['screener_1_errors']} decision errors. The sheet covers the decided works only."
            )
        return
    if args.command == "fetch":
        only = set(args.source) if args.source else None
        unknown = [] if only is None else sorted(only - set(FETCHERS))
        if unknown:
            raise SystemExit(f"unknown source: {', '.join(unknown)}")
        fetch_sources(out, only, restart=args.restart)
    counts = write_counts(out)
    prisma = counts["prisma"]
    print(
        f"Found {prisma['found']}, deduped {prisma['deduped']}, "
        f"screened {prisma['screened']}, keyword kept {prisma['keyword_kept']}."
    )
    print(f"Concept-only {counts['concept_only']}, of which keyword kept {counts['concept_only_keyword_kept']}.")
    incomplete = [name for name, row in counts["sources"].items() if not row["complete"]]
    if incomplete:
        print("Incomplete: " + ", ".join(incomplete) + ".")
    print(f"Search frozen: {counts['search_frozen'] or 'no'}.")
    decision = counts["decision"]
    # The decision text can name works with non-ASCII titles, so the console gets the case only.
    print(
        f"Decision: case {decision['case']}, claim {decision['claim']}"
        + (", provisional" if decision["provisional"] else "")
        + f", {len(decision['open'])} open conditions. The text is in prisma.md."
    )
    print(f"Wrote {out / 'counts.json'}, {out / 'prisma.md'} and {out / 'closest-works.md'}.")


if __name__ == "__main__":
    main()
