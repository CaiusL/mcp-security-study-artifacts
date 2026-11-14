"""Systematic-review retrieval and screening records. No network: the transport is passed in."""

import hashlib
import io
import json
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

import wiggle.review as review
from wiggle.review import (
    CONCEPT_CELL_CAP,
    CORE_PROPERTIES,
    FETCHERS,
    PROPERTIES,
    S2_FIELDS,
    FetchError,
    abstract_from_inverted,
    build_counts,
    cohen_kappa,
    concept_cells,
    concept_only,
    decision_rule,
    dedupe,
    fetch_openalex_concept,
    fetch_sources,
    keyword_kept,
    load_works,
    matched_terms,
    parse_arxiv,
    parse_dblp,
    parse_openalex,
    parse_s2,
    screener_2_sample,
    urllib_get,
    work_key,
    works_path,
    write_batches,
    write_counts,
    write_screener_2,
)

_ATOM = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/" xmlns:arxiv="http://arxiv.org/schemas/atom">
  <opensearch:totalResults>1</opensearch:totalResults>
  <entry>
    <id>http://arxiv.org/abs/2601.00001v1</id>
    <title>  Least   privilege </title>
    <summary>Held out task success.</summary>
    <published>2026-01-02T00:00:00Z</published>
    <arxiv:doi>10.1000/xyz</arxiv:doi>
  </entry>
</feed>
"""


def _openalex(count, cursor, works):
    return json.dumps({"meta": {"count": count, "next_cursor": cursor}, "results": works}).encode()


class ReviewParseTests(unittest.TestCase):
    def test_inverted_abstract_keeps_word_order(self):
        text = abstract_from_inverted({"privilege": [1], "least": [0], "now": [2]})
        self.assertEqual(text, "least privilege now")

    def test_arxiv_feed(self):
        total, works = parse_arxiv(_ATOM.encode())
        self.assertEqual(total, 1)
        self.assertEqual(works[0]["title"], "Least privilege")
        self.assertEqual(works[0]["doi"], "10.1000/xyz")
        self.assertEqual(works[0]["year"], "2026")
        self.assertEqual(matched_terms(works[0]["title"], works[0]["abstract"]), ["privilege", "held-out", "least privilege"])

    def test_openalex_page(self):
        payload = _openalex(
            2,
            "CUR",
            [
                {
                    "id": "https://openalex.org/W1",
                    "display_name": "Envelope paper",
                    "publication_year": 2025,
                    "doi": "https://doi.org/10.1000/xyz",
                    "abstract_inverted_index": {"trace": [0]},
                }
            ],
        )
        total, cursor, works = parse_openalex(payload)
        self.assertEqual((total, cursor), (2, "CUR"))
        self.assertEqual(works[0]["abstract"], "trace")
        self.assertEqual(works[0]["doi"], "https://doi.org/10.1000/xyz")

    def test_dblp_hit(self):
        payload = json.dumps(
            {"result": {"hits": {"@total": "1", "hit": {"@id": "1", "info": {"key": "conf/x/y", "title": "A policy.", "year": "2026", "doi": "10.1000/abc"}}}}}
        ).encode()
        total, works = parse_dblp(payload)
        self.assertEqual(total, 1)
        self.assertEqual(works[0]["title"], "A policy.")
        self.assertEqual(works[0]["source_id"], "conf/x/y")

    def test_dedupe_prefers_doi_then_title(self):
        works = [
            {"title": "Same paper", "doi": "https://doi.org/10.1000/xyz", "source": "arxiv-phrase"},
            {"title": "Same paper, revised", "doi": "10.1000/XYZ", "source": "openalex-phrase"},
            {"title": "Same   paper!", "doi": "", "source": "dblp-phrase"},
            {"title": "Other", "doi": "", "source": "arxiv-concept"},
        ]
        kept = dedupe(works)
        self.assertEqual([row["source"] for row in kept], ["arxiv-phrase", "arxiv-concept"])

    def test_concept_only_drops_phrase_overlap(self):
        works = [
            {"source": "arxiv-phrase", "title": "Known", "doi": "10.1/a"},
            {"source": "arxiv-concept", "title": "Known elsewhere", "doi": "10.1/a"},
            {"source": "openalex-concept", "title": "New defense", "doi": ""},
        ]
        extra = concept_only(works)
        self.assertEqual([row["title"] for row in extra], ["New defense"])

    def test_concept_cells_cover_the_three_groups(self):
        cells = concept_cells()
        self.assertEqual(len(cells), 36)
        self.assertTrue(all(cell.count("title_and_abstract.search:") == 3 for cell in cells))


class _Body(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class ReviewFetchTests(unittest.TestCase):
    def test_retry_after_429(self):
        calls = {"n": 0}

        def fake(request, timeout=60):
            calls["n"] += 1
            if calls["n"] == 1:
                raise urllib.error.HTTPError(request.full_url, 429, "slow", {"Retry-After": "0"}, None)
            return _Body(_ATOM.encode())

        original = urllib.request.urlopen
        urllib.request.urlopen = fake
        try:
            payload = urllib_get("https://export.arxiv.org/api/query", sleep=lambda delay: None)
        finally:
            urllib.request.urlopen = original
        self.assertIn(b"Least", payload)
        self.assertEqual(calls["n"], 2)

    def test_other_http_status_is_not_retried(self):
        def fake(request, timeout=60):
            raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)

        original = urllib.request.urlopen
        urllib.request.urlopen = fake
        try:
            with self.assertRaises(FetchError) as caught:
                urllib_get("https://example.test/missing", sleep=lambda delay: None)
        finally:
            urllib.request.urlopen = original
        self.assertEqual(caught.exception.status, 404)

    def test_one_source_error_does_not_drop_the_other(self):
        def get(url: str) -> bytes:
            if "dblp.org" in url:
                raise FetchError(202, "HTTP 202")
            if "api.openalex.org" in url:
                return _openalex(0, None, [])
            return _ATOM.encode()

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fetch_sources(root, get=get, sleep=lambda delay: None, pause=0)
            counts = write_counts(root)
        self.assertTrue(counts["sources"]["arxiv-phrase"]["complete"])
        self.assertEqual(counts["sources"]["arxiv-phrase"]["retrieved"], 1)
        self.assertFalse(counts["sources"]["dblp-phrase"]["complete"])
        self.assertEqual(counts["sources"]["dblp-phrase"]["status"], 202)
        self.assertGreaterEqual(counts["prisma"]["keyword_kept"], 1)
        self.assertEqual(counts["prisma"]["read"], 0)

    def test_over_cap_cell_is_counted_and_not_downloaded(self):
        wide = concept_cells()[0]
        narrow = concept_cells()[1]
        wide_query = urllib.parse.urlencode({"filter": wide})
        urls = []

        def get(url: str) -> bytes:
            urls.append(url)
            work = {
                "id": "https://openalex.org/W9",
                "display_name": "A capability policy for agents",
                "publication_year": 2026,
                "doi": "",
                "abstract_inverted_index": {"defense": [0]},
            }
            count = CONCEPT_CELL_CAP + 1 if wide_query.split("=", 1)[1] in url else 1
            return _openalex(count, None, [work])

        entry = {"cells": [], "complete": False, "retrieved": 0, "found": None, "query": "concept"}
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "openalex-concept.jsonl"
            fetch_openalex_concept(entry, path, get, lambda delay: None, 0, lambda: None)
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        skipped = [cell for cell in entry["cells"] if cell.get("skipped")]
        downloaded = [cell for cell in entry["cells"] if cell.get("retrieved")]
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["retrieved"], 0)
        self.assertEqual(len(downloaded), 35)
        self.assertEqual(len(rows), 35)
        # One request per cell: the first page carries the count, and the over-cap page keeps no rows.
        self.assertEqual(len(urls), 36)
        self.assertEqual(entry["found"], CONCEPT_CELL_CAP + 1 + 35)
        self.assertTrue(entry["complete"])
        self.assertIn(narrow, {cell["query"] for cell in downloaded})


DBLP_ERROR = "DBLP returned an HTML bot check instead of the JSON API"


def _s2_page(total, token, rows):
    return json.dumps({"total": total, "token": token, "data": rows}).encode()


def _s2_row(paper, title, doi=""):
    ids = {"CorpusId": 1, **({"DOI": doi} if doi else {})}
    return {
        "paperId": paper,
        "url": f"https://www.semanticscholar.org/paper/{paper}",
        "title": title,
        "abstract": None,
        "year": 2026,
        "venue": " Sec  Conf ",
        "publicationTypes": ["Conference"],
        "externalIds": ids,
    }


def _rows(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write_rows(path: Path, rows: list) -> None:
    """Write JSONL. A string row is written as it is, so a test can plant a broken line."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join((row if isinstance(row, str) else json.dumps(row)) + "\n" for row in rows), encoding="utf-8")


def _write_works(root: Path, source: str, rows: list[dict]) -> None:
    _write_rows(works_path(root, source), [{"abstract": "", "year": "2026", "doi": "", **row, "source": source} for row in rows])


def _entry(complete: bool, retrieved: int = 0) -> dict:
    return {"query": "q", "found": retrieved, "retrieved": retrieved, "cursor": None, "complete": complete, "error": "", "status": None, "cells": []}


def _done(date: str) -> dict:
    """A source retrieved from start to end on one UTC date."""
    return {**_entry(True), "started_on": date, "fetched_on": date}


def _save_state(root: Path, state: dict) -> None:
    (root / "state.json").write_text(json.dumps(state), encoding="utf-8")


def _screening_fixture(root: Path) -> list[str]:
    """Four keyword-kept works; one is in two sources. Return their keys in the order of TITLES."""
    _write_works(
        root,
        "arxiv-phrase",
        [
            {"source_id": "a1", "title": "Least privilege for agents", "doi": "10.1/a"},
            {"source_id": "a2", "title": "A trace envelope"},
            {"source_id": "a3", "title": "Weather report", "abstract": "Sunny."},
            {"source_id": "a4", "title": "", "abstract": "An untitled privilege policy."},
        ],
    )
    _write_works(
        root,
        "s2-phrase",
        [
            {"source_id": "s1", "title": "Least privilege for agents, journal version", "doi": "https://doi.org/10.1/A"},
            {"source_id": "s2", "title": "Defense policy study", "venue": "AgentConf"},
            {"source_id": "s3", "title": "Benign utility"},
        ],
    )
    keys = {work["title"]: work["key"] for work in keyword_kept(load_works(root))}
    return [keys[title] for title in TITLES]


TITLES = ("Least privilege for agents", "A trace envelope", "Defense policy study", "Benign utility")


def _decision(key: str, decision: str, criterion) -> dict:
    return {"key": key, "decision": decision, "criterion": criterion, "reason": "One sentence.", "screener": "screener-1-claude"}


def _read_row(key: str, values: dict | None = None, included: bool = True, evidence: dict | None = None, reason: str = "") -> dict:
    """A read row. Each core cell has evidence unless `evidence` replaces it."""
    properties = {name: "no" for name, _title in PROPERTIES}
    properties.update(values or {})
    return {
        "key": key,
        "url": f"https://example.test/{key}",
        "status": "read",
        "properties": properties,
        "evidence": {**{name: "Section 5" for name in CORE_PROPERTIES}, **(evidence or {})},
        "included": included,
        "exclusion_reason": reason,
        "note": "docs/related_work.md, Praetor",
    }


class ReviewSemanticScholarTests(unittest.TestCase):
    def test_s2_page(self):
        total, token, works = parse_s2(_s2_page(3, "NEXT", [_s2_row("p1", "  A  least privilege policy ", doi="10.1000/S2")]))
        self.assertEqual((total, token), (3, "NEXT"))
        self.assertEqual(works[0]["source_id"], "https://www.semanticscholar.org/paper/p1")
        self.assertEqual(works[0]["title"], "A least privilege policy")
        self.assertEqual((works[0]["abstract"], works[0]["year"], works[0]["doi"]), ("", "2026", "10.1000/S2"))
        self.assertEqual((works[0]["venue"], works[0]["publication_types"]), ("Sec Conf", ["Conference"]))
        self.assertIsNone(parse_s2(_s2_page(1, None, []))[1])

    def test_an_error_body_is_not_a_page(self):
        with self.assertRaises(ValueError):
            parse_s2(b'{"message": "Too Many Requests", "code": "429"}')

    def test_pages_with_the_token_after_a_429(self):
        pages = [_s2_page(2, "NEXT", [_s2_row("p1", "Least privilege policy", doi="10.1000/S2")]), _s2_page(2, None, [_s2_row("p2", "Agent defense")])]
        urls = []

        def fake(request, timeout=60):
            urls.append(request.full_url)
            if len(urls) == 1:
                raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {}, None)
            return _Body(pages.pop(0))

        sleeps = []
        original = urllib.request.urlopen
        urllib.request.urlopen = fake
        try:
            with TemporaryDirectory() as tmp:
                state = fetch_sources(
                    Path(tmp),
                    only={"s2-phrase"},
                    get=lambda url: urllib_get(url, sleep=sleeps.append),
                    sleep=sleeps.append,
                    today=lambda: "2026-11-03",
                )
                rows = _rows(works_path(Path(tmp), "s2-phrase"))
        finally:
            urllib.request.urlopen = original
        entry = state["sources"]["s2-phrase"]
        self.assertTrue(entry["complete"])
        self.assertEqual((entry["found"], entry["retrieved"], entry["started_on"], entry["fetched_on"]), (2, 2, "2026-11-03", "2026-11-03"))
        self.assertEqual([row["doi"] for row in rows], ["10.1000/S2", ""])
        queries = [urllib.parse.parse_qs(urllib.parse.urlsplit(url).query) for url in urls]
        self.assertEqual(len(urls), 3)
        self.assertEqual(queries[0]["query"], ['"Model Context Protocol"'])
        self.assertEqual(queries[0]["fields"], [S2_FIELDS])
        self.assertNotIn("token", queries[1])
        self.assertEqual(queries[2]["token"], ["NEXT"])
        # One back-off after the 429, then the pause between the two pages. Both are at least 1 s.
        self.assertEqual(len(sleeps), 2)
        self.assertGreaterEqual(min(sleeps), 1.0)


class ReviewRestartTests(unittest.TestCase):
    def test_restart_clears_only_the_selected_sources(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_works(root, "arxiv-phrase", [{"source_id": "old", "title": "Old privilege paper"}])
            _write_works(root, "openalex-phrase", [{"source_id": "W1", "title": "Kept policy paper"}])
            state = {
                "sources": {
                    "arxiv-phrase": {**_entry(True, 1), "fetched_on": "2026-11-02"},
                    "openalex-phrase": {**_entry(True, 1), "fetched_on": "2026-11-02", "paging": "page"},
                    "dblp-phrase": {**_entry(False), "error": DBLP_ERROR, "status": 202},
                }
            }
            _save_state(root, state)
            requested = []

            def get(url: str) -> bytes:
                requested.append(url)
                return _ATOM.encode()

            fetch_sources(root, only={"arxiv-phrase"}, restart=True, get=get, sleep=lambda delay: None, pause=0, today=lambda: "2026-11-03")
            saved = json.loads((root / "state.json").read_text(encoding="utf-8"))["sources"]
            arxiv_rows = _rows(works_path(root, "arxiv-phrase"))
            openalex_rows = _rows(works_path(root, "openalex-phrase"))
        self.assertTrue(requested and all("export.arxiv.org" in url for url in requested))
        self.assertEqual([row["source_id"] for row in arxiv_rows], ["http://arxiv.org/abs/2601.00001v1"])
        self.assertEqual((saved["arxiv-phrase"]["started_on"], saved["arxiv-phrase"]["fetched_on"]), ("2026-11-03", "2026-11-03"))
        self.assertEqual(saved["openalex-phrase"]["fetched_on"], "2026-11-02")
        self.assertEqual([row["source_id"] for row in openalex_rows], ["W1"])
        self.assertEqual((saved["dblp-phrase"]["error"], saved["dblp-phrase"]["status"]), (DBLP_ERROR, 202))

    def test_restart_without_a_source_clears_every_source(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in FETCHERS:
                _write_works(root, name, [{"source_id": f"old-{name}", "title": f"Old {name} policy"}])
            _save_state(root, {"sources": {name: {**_entry(True, 1), "fetched_on": "2026-11-02", "paging": "page"} for name in FETCHERS}})

            def get(url: str) -> bytes:
                if "dblp.org" in url:
                    raise FetchError(202, DBLP_ERROR)
                if "api.openalex.org" in url:
                    return _openalex(0, None, [])
                if "semanticscholar.org" in url:
                    return _s2_page(0, None, [])
                return _ATOM.encode()

            fetch_sources(root, restart=True, get=get, sleep=lambda delay: None, pause=0, today=lambda: "2026-11-03")
            saved = json.loads((root / "state.json").read_text(encoding="utf-8"))["sources"]
            old = [row for name in FETCHERS for row in _rows(works_path(root, name)) if row["source_id"].startswith("old-")]
        self.assertEqual(old, [])
        fresh = {name for name, entry in saved.items() if entry.get("fetched_on") == "2026-11-03"}
        self.assertEqual(fresh, set(FETCHERS) - {"dblp-phrase"})
        self.assertEqual(saved["dblp-phrase"]["status"], 202)

    def test_the_cli_restarts_only_the_named_sources(self):
        calls = []
        original = review.fetch_sources
        review.fetch_sources = lambda out, only=None, restart=False: calls.append((only, restart))
        try:
            with TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
                review.main(["fetch", "--restart", "--source", "arxiv-phrase", "--source", "s2-phrase", "--out", tmp])
        finally:
            review.fetch_sources = original
        self.assertEqual(calls, [({"arxiv-phrase", "s2-phrase"}, True)])

    def test_search_frozen_needs_one_start_and_completion_date(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = {"sources": {name: _done("2026-11-03") for name in FETCHERS}}
            state["sources"]["s2-phrase"].update(found=1436, retrieved=1430)
            state["sources"]["dblp-phrase"] = {**_entry(False), "error": DBLP_ERROR, "status": 202, "fetched_on": "2026-11-01"}
            _save_state(root, state)
            counts = write_counts(root)
            prisma = (root / "prisma.md").read_text(encoding="utf-8")
            state["sources"]["s2-phrase"].update(started_on="2026-11-02", fetched_on="2026-11-02")
            _save_state(root, state)
            split = build_counts(root)
            # Started on one day and resumed to completion on the next.
            state["sources"]["s2-phrase"]["fetched_on"] = "2026-11-03"
            _save_state(root, state)
            spanned = build_counts(root)
            del state["sources"]["s2-phrase"]["fetched_on"]
            _save_state(root, state)
            undated = build_counts(root)
        self.assertEqual(counts["search_frozen"], "2026-11-03")
        self.assertEqual(counts["search_dates"]["arxiv-phrase"], "2026-11-03")
        self.assertIsNone(counts["search_dates"]["dblp-phrase"])
        self.assertIn("Search frozen: 2026-11-03.", prisma)
        self.assertIn("| arxiv-phrase | 0 | 0 | True | 2026-11-03 | 2026-11-03 | — |", prisma)
        # Semantic Scholar's total is an estimate.
        self.assertIn("| s2-phrase | about 1436 | 1430 | True | 2026-11-03 | 2026-11-03 | — |", prisma)
        self.assertIsNone(split["search_frozen"])
        self.assertIsNone(spanned["search_frozen"])
        self.assertIn("s2-phrase 2026-11-02 to 2026-11-03", " / ".join(spanned["decision"]["open"]))
        self.assertIsNone(undated["search_frozen"])

    def test_a_resume_on_a_later_day_keeps_the_start_date(self):
        first = _s2_page(2, "NEXT", [_s2_row("p1", "Least privilege policy")])
        last = _s2_page(2, None, [_s2_row("p2", "Agent defense")])

        def stop_after_one_page(url: str) -> bytes:
            if "token=" in url:
                raise FetchError(429, "HTTP Error 429: Too Many Requests")
            return first

        def finish(url: str) -> bytes:
            return last if "token=" in url else first

        quiet = {"sleep": lambda delay: None, "pause": 0}
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fetch_sources(root, only={"s2-phrase"}, get=stop_after_one_page, today=lambda: "2026-11-03", **quiet)
            fetch_sources(root, only={"s2-phrase"}, get=finish, today=lambda: "2026-11-04", **quiet)
            resumed = build_counts(root)
            fetch_sources(root, only={"s2-phrase"}, restart=True, get=finish, today=lambda: "2026-11-04", **quiet)
            restarted = build_counts(root)
        row = resumed["sources"]["s2-phrase"]
        self.assertEqual((row["complete"], row["retrieved"], row["started_on"], row["fetched_on"]), (True, 2, "2026-11-03", "2026-11-04"))
        self.assertIsNone(resumed["search_frozen"])
        self.assertEqual(restarted["sources"]["s2-phrase"]["started_on"], "2026-11-04")
        self.assertEqual(restarted["search_frozen"], "2026-11-04")


class ReviewScreeningTests(unittest.TestCase):
    def test_counts_preserve_unchanged_screen_and_refresh_changed_corpus(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _screening_fixture(root)
            write_counts(root)
            screen = root / "screen.jsonl"
            before = screen.read_bytes()
            original_open = Path.open

            def fail_screen_write(path, mode="r", *args, **kwargs):
                if path == screen and "w" in mode:
                    raise OSError(22, "screen cannot be truncated")
                return original_open(path, mode, *args, **kwargs)

            with patch.object(Path, "open", fail_screen_write):
                write_counts(root)
                self.assertEqual(screen.read_bytes(), before)
                _write_works(root, "arxiv-phrase", [{"source_id": "new", "title": "New privilege study"}])
                with self.assertRaises(OSError):
                    write_counts(root)
            write_counts(root)
            self.assertNotEqual(screen.read_bytes(), before)
            self.assertIn("New privilege study", screen.read_text(encoding="utf-8"))

    def test_the_key_is_a_sha256_prefix_of_the_dedupe_identity(self):
        self.assertEqual(work_key({"doi": "https://doi.org/10.1000/ABC", "title": "Any"}), hashlib.sha256(b"doi:10.1000/abc").hexdigest()[:12])
        self.assertEqual(work_key({"doi": "", "title": "Least  Privilege!"}), hashlib.sha256(b"title:least privilege").hexdigest()[:12])

    def test_a_title_in_a_non_latin_script_keys_and_dedupes_on_the_source_id(self):
        thai = {"title": "การวิเคราะห์นโยบาย", "abstract": "A policy study.", "doi": "", "source_id": "https://openalex.org/W1"}
        works = [
            {**thai, "source": "openalex-phrase"},
            {**thai, "source": "openalex-concept"},
            {**thai, "source": "openalex-concept", "title": "РОЗРОБКА МЕТОДУ", "source_id": "https://openalex.org/W2"},
        ]
        kept = keyword_kept(works)
        self.assertEqual([row["sources"] for row in kept], [["openalex-phrase", "openalex-concept"], ["openalex-concept"]])
        self.assertEqual(kept[0]["key"], hashlib.sha256(b"id:https://openalex.org/W1").hexdigest()[:12])
        self.assertNotEqual(kept[0]["key"], kept[1]["key"])

    def test_batches_are_deterministic_and_in_key_order(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = _screening_fixture(root)
            first = [path.read_text(encoding="utf-8") for path in write_batches(root, 3)]
            second = [path.read_text(encoding="utf-8") for path in write_batches(root, 3)]
            write_counts(root)
            screen = _rows(root / "screen.jsonl")
            write_batches(root, 10)
            names = sorted(path.name for path in (root / "screen-batches").iterdir())
        rows = [json.loads(line) for text in first for line in text.splitlines()]
        self.assertEqual(first, second)
        self.assertEqual(len(first), 2)
        self.assertEqual([row["key"] for row in rows], sorted(keys))
        shared = next(row for row in rows if row["key"] == keys[0])
        self.assertEqual(set(shared), {"key", "title", "abstract", "year", "venue", "doi", "source_id", "sources", "terms"})
        self.assertEqual((shared["sources"], shared["doi"]), (["arxiv-phrase", "s2-phrase"], "10.1/a"))
        self.assertEqual(next(row for row in rows if row["key"] == keys[2])["venue"], "AgentConf")
        # screen.jsonl lists the same set: the untitled work and the work with no term are in neither.
        self.assertEqual(sorted(row["title"] for row in screen), sorted(TITLES))
        self.assertEqual(names, ["batch-001.jsonl"])

    def test_decisions_merge_and_report_errors(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            a, b, c, d = _screening_fixture(root)
            _write_rows(
                root / "screen-decisions" / "batch-001.jsonl",
                [_decision(a, "keep", 3), _decision(b, "drop", "none"), "{not json", _decision("ffffffffffff", "drop", "none")],
            )
            _write_rows(root / "screen-decisions" / "batch-002.jsonl", [_decision(b, "keep", 1), _decision(c, "keep", "none")])
            counts = write_counts(root)
            prisma = (root / "prisma.md").read_text(encoding="utf-8")
        first = counts["screening"]["screener_1"]
        self.assertEqual((first["decided"], first["keep"], first["drop"], first["missing"]), (2, 1, 1, 2))
        self.assertEqual(first["missing_keys"], sorted([c, d]))
        self.assertEqual(len(first["errors"]), 4)
        for text in ("batch-001.jsonl:3: not JSON", "unknown key 'ffffffffffff'", f"duplicate key {b} (first at batch-001.jsonl:2)", "a keep must name criterion"):
            self.assertTrue(any(text in error for error in first["errors"]), text)
        prisma_counts = counts["prisma"]
        self.assertEqual(
            (prisma_counts["keyword_kept"], prisma_counts["title_abstract_screened"], prisma_counts["screener_1_kept"], prisma_counts["screener_1_dropped"]),
            (4, 2, 1, 1),
        )
        self.assertIn("duplicate key", prisma)
        self.assertIn("unknown key", prisma)

    def test_codex_continuation_keeps_authorship_and_is_not_screener_2(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = _screening_fixture(root)
            rows = [_decision(key, "keep", 3) for key in keys]
            rows[-1]["screener"] = "screener-1-codex"
            _write_rows(root / "screen-decisions" / "batch-001.jsonl", rows)
            counts = build_counts(root)
            self.assertEqual(counts["screening"]["screener_1"]["decided"], 4)
            self.assertEqual(counts["screening"]["screener_1"]["errors"], [])
            review.write_counts(root, counts)
            self.assertIn("`screener-1-codex`", (root / "prisma.md").read_text(encoding="utf-8"))
            write_screener_2(root)
            answers = [{**row, "decision": "keep", "criterion": 3,
                        "screener": "screener-1-codex"}
                       for row in _rows(root / "screener-2.jsonl")]
            _write_rows(root / "screener-2-decisions.jsonl", answers)
            second = build_counts(root)["screening"]["screener_2"]
        self.assertEqual(second["decided"], 0)
        self.assertEqual(len(second["errors"]), 4)
        self.assertTrue(all("screener must name screener 2" in error for error in second["errors"]))

    def test_the_screener_2_sample_is_deterministic_and_about_ten_percent(self):
        keys = [hashlib.sha256(str(number).encode()).hexdigest()[:12] for number in range(3000)]
        decisions = {key: ("keep" if number < 100 else "drop") for number, key in enumerate(keys)}
        sample = screener_2_sample(decisions)
        drops = [key for key in sample if decisions[key] == "drop"]
        self.assertEqual(sample, screener_2_sample(dict(reversed(list(decisions.items())))))
        self.assertEqual(sample, sorted(sample))
        self.assertTrue(set(keys[:100]) <= set(sample))
        self.assertTrue(0.08 <= len(drops) / 2900 <= 0.12, len(drops))
        self.assertTrue(all(int(key, 16) % 10 == 0 for key in drops))

    def test_cohen_kappa(self):
        self.assertAlmostEqual(cohen_kappa([("keep", "keep"), ("keep", "drop"), ("drop", "drop"), ("keep", "keep")]), 0.5)
        self.assertIsNone(cohen_kappa([("keep", "keep")] * 3))
        self.assertIsNone(cohen_kappa([]))

    def test_screener_2_is_pending_then_reports_agreement(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = _screening_fixture(root)
            _write_rows(root / "screen-decisions" / "batch-001.jsonl", [_decision(key, "keep", 3) for key in keys])
            sheet = write_screener_2(root)
            sheet_rows = _rows(root / "screener-2.jsonl")
            sheet_md = (root / "screener-2.md").read_text(encoding="utf-8")
            pending = build_counts(root)
            answers = [{**row, "decision": "drop" if row["key"] == keys[3] else "keep", "criterion": "none" if row["key"] == keys[3] else 3} for row in sheet_rows]
            _write_rows(root / "screener-2-decisions.jsonl", answers)
            unresolved = write_counts(root)
            prisma = (root / "prisma.md").read_text(encoding="utf-8")
            answers = [{**row, "resolved": "drop"} if row["key"] == keys[3] else row for row in answers]
            _write_rows(root / "screener-2-decisions.jsonl", answers)
            resolved = build_counts(root)
        self.assertEqual(sheet["rows"], 4)
        self.assertEqual(sorted(row["key"] for row in sheet_rows), sorted(keys))
        self.assertTrue(all(row["decision"] == row["criterion"] == row["reason"] == "" for row in sheet_rows))
        self.assertIn("| Decision | Criterion | Reason |", sheet_md)
        self.assertEqual(pending["screening"]["screener_2"]["status"], "pending")
        self.assertIn("Provisional: screener 2 is pending.", pending["decision"]["text"])
        second = unresolved["screening"]["screener_2"]
        self.assertEqual((second["status"], second["decided"], second["agree"], second["kappa"]), ("unresolved", 4, 3, 0.0))
        self.assertEqual([row["key"] for row in second["disagreements"]], [keys[3]])
        self.assertEqual(unresolved["prisma"]["kept_for_full_text"], 4)
        self.assertIn("Screener 2: unresolved. 4 of 4 sheet works decided. Agreement 3 of 4, Cohen's kappa 0.0.", prisma)
        self.assertIn(f"| {keys[3]} | Benign utility | keep | drop | — |", prisma)
        self.assertEqual(resolved["screening"]["screener_2"]["status"], "complete")
        self.assertEqual(resolved["prisma"]["kept_for_full_text"], 3)
        self.assertFalse(resolved["decision"]["provisional"])

    def test_screener_2_rows_are_checked(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = _screening_fixture(root)
            _write_rows(root / "screen-decisions" / "batch-001.jsonl", [_decision(key, "keep", 3) for key in keys])
            write_screener_2(root)
            sheet = _rows(root / "screener-2.jsonl")
            agree = [{**row, "decision": "keep", "criterion": 3, "reason": "One sentence."} for row in sheet]
            _write_rows(root / "screener-2-decisions.jsonl", agree[:3] + sheet[3:])
            partial = build_counts(root)
            # A resolution on a row where both screeners agree is not applied.
            _write_rows(root / "screener-2-decisions.jsonl", agree[:3] + [{**agree[3], "resolved": "drop"}])
            stray = write_counts(root)
            prisma = (root / "prisma.md").read_text(encoding="utf-8")
            _write_rows(root / "screener-2-decisions.jsonl", [{**row, "screener": "screener-1-claude"} for row in agree])
            relabelled = build_counts(root)
        progress = partial["screening"]["screener_2"]
        self.assertEqual((progress["status"], progress["decided"], progress["missing"]), ("in progress", 3, 1))
        self.assertTrue(partial["decision"]["text"].endswith("Provisional: screener 2 has not decided every sheet row."))
        second = stray["screening"]["screener_2"]
        self.assertEqual((second["status"], second["agree"], second["disagreements"]), ("invalid rows", 4, []))
        self.assertTrue(any("resolved is set, but both screeners decided keep" in error for error in second["errors"]))
        self.assertEqual(stray["prisma"]["kept_for_full_text"], 4)
        self.assertTrue(stray["decision"]["text"].endswith("Provisional: the screener-2 file has invalid rows."))
        self.assertIn("Screener 2: invalid rows. 4 of 4 sheet works decided. Agreement 4 of 4, Cohen's kappa undefined.", prisma)
        self.assertIn("Screener-2 decision errors (1):", prisma)
        errors = relabelled["screening"]["screener_2"]["errors"]
        self.assertEqual(len(errors), 4)
        self.assertTrue(all("screener must name screener 2" in error for error in errors))
        self.assertEqual(relabelled["screening"]["screener_2"]["status"], "in progress")

    def test_counts_json_keeps_every_missing_key(self):
        original = review.LIST_LIMIT
        review.LIST_LIMIT = 2
        try:
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                keys = sorted(_screening_fixture(root))
                counts = write_counts(root)
                prisma = (root / "prisma.md").read_text(encoding="utf-8")
        finally:
            review.LIST_LIMIT = original
        self.assertEqual(counts["screening"]["screener_1"]["missing_keys"], keys)
        self.assertIn(f"First keys with no decision: {keys[0]}, {keys[1]}.", prisma)

    def test_reads_fill_the_counts_and_the_closest_works_table(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            a, b, c, d = _screening_fixture(root)
            _write_rows(
                root / "screen-decisions" / "batch-001.jsonl",
                [_decision(a, "keep", 3), _decision(b, "keep", 2), _decision(c, "keep", 1), _decision(d, "drop", "none")],
            )
            not_retrieved = {**_read_row(b, included=False), "status": "not retrieved: HTTP 404"}
            _write_rows(
                root / "reads.jsonl",
                [
                    _read_row(a, {"trace_derived_policy": "yes", "mcp": "yes"}, evidence={"trace_derived_policy": "Section 4"}),
                    not_retrieved,
                    _read_row(c, evidence={"strictness_curve": " "}),
                    _read_row(d),
                    _read_row("ffffffffffff", {"mcp": "maybe"}),
                ],
            )
            counts = write_counts(root)
            table = (root / "closest-works.md").read_text(encoding="utf-8")
        reads = counts["reads"]
        self.assertEqual((counts["prisma"]["read"], counts["prisma"]["included"], counts["prisma"]["not_retrieved"]), (1, 1, 1))
        self.assertEqual((reads["missing"], reads["missing_keys"]), (1, [c]))
        self.assertEqual(len(reads["errors"]), 3)
        self.assertTrue(any("an included work needs evidence for strictness_curve" in error for error in reads["errors"]))
        self.assertTrue(any("mcp must be yes, no or not stated" in error for error in reads["errors"]))
        self.assertTrue(any(f"key '{d}' is not a kept work" in error for error in reads["errors"]))
        self.assertIn(
            f"| {a} | Least privilege for agents (doi:10.1/a) | yes. Section 4 | no. Section 5 | no. Section 5 | no | yes | no "
            "| docs/related_work.md, Praetor |",
            table,
        )
        self.assertIn("not retrieved: HTTP 404", table)
        self.assertIn("Kept works with no read row yet: 1.", table)

    def test_decision_rule_cases(self):
        def row(work: str, **values) -> dict:
            properties = {name: "no" for name, _title in PROPERTIES}
            properties.update(values)
            return {"key": work, "work": work, "properties": properties, "evidence": {}}

        core = {"trace_derived_policy": "yes", "strictness_curve": "yes", "same_trace_attribution": "yes"}
        every = {name: "yes" for name, _title in PROPERTIES}
        one = decision_rule([row("Praetor", trace_derived_policy="yes"), row("Precedent", **every)], [], "complete")
        self.assertEqual((one["case"], one["claim"], one["works"]), (1, "dropped", ["Precedent"]))
        two = decision_rule([row("Praetor", trace_derived_policy="yes")], [], "complete", "frozen on 2026-11-03")
        self.assertEqual((two["case"], two["claim"], two["provisional"], two["poisoning"]), (2, "allowed", False, []))
        self.assertIn("frozen on 2026-11-03", two["text"])
        self.assertTrue(two["text"].endswith("narrower contribution of section 8: no included work tests it."))
        poisoned = decision_rule([row("Praetor", trace_derived_policy="yes"), row("Poison", policy_input_poisoning="yes")], [], "complete")
        self.assertEqual((poisoned["case"], poisoned["poisoning"]), (2, ["Poison"]))
        self.assertTrue(poisoned["text"].endswith("narrower contribution of section 8: tested by Poison."))
        waiting = decision_rule([], ["reads: 3 kept works have no read row and 0 read rows have errors"], "pending")
        self.assertEqual((waiting["case"], waiting["claim"], waiting["provisional"]), (2, "not allowed yet", True))
        self.assertIn("Open: reads: 3 kept works have no read row", waiting["text"])
        self.assertTrue(waiting["text"].endswith("Provisional: screener 2 is pending."))
        three = decision_rule([row("Near", **core), row("Far")], ["ignored outside case 2"], "complete")
        self.assertEqual((three["case"], three["claim"], three["works"], three["open"]), (3, "dropped", ["Near"], []))

    def test_the_middle_case_names_each_open_condition_until_all_hold(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            a, b, c, d = _screening_fixture(root)
            state = {"sources": {name: _done("2026-11-03") for name in FETCHERS}}
            state["sources"]["openalex-phrase"] = _done("2026-11-02")
            state["sources"]["openalex-concept"] = _entry(False)
            state["sources"]["dblp-phrase"] = {**_entry(False), "error": DBLP_ERROR, "status": 202}
            _save_state(root, state)
            _write_rows(root / "screen-decisions" / "batch-001.jsonl", [_decision(a, "keep", 3)])
            blocked = write_counts(root)
            prisma = (root / "prisma.md").read_text(encoding="utf-8")
            # Only the recorded bot check, with nothing retrieved, is exempt.
            other_dblp = []
            for entry in ({**_entry(False, 500), "error": "<urlopen error timed out>", "status": 0}, _entry(False)):
                state["sources"]["dblp-phrase"] = entry
                _save_state(root, state)
                other_dblp.append(build_counts(root)["decision"]["open"])
            state["sources"]["dblp-phrase"] = {**_entry(False), "error": DBLP_ERROR, "status": 202}
            state["sources"]["openalex-phrase"] = _done("2026-11-03")
            over_cap = {"query": "cell", "found": 3999, "retrieved": 0, "page": 1, "complete": True, "skipped": "over the cap"}
            state["sources"]["openalex-concept"] = {**_done("2026-11-03"), "cells": [over_cap]}
            _save_state(root, state)
            _write_rows(
                root / "screen-decisions" / "batch-001.jsonl",
                [_decision(a, "keep", 3), _decision(b, "keep", 2), _decision(c, "drop", 3), _decision(d, "drop", "none")],
            )
            _write_rows(
                root / "reads.jsonl",
                [
                    _read_row(a, {"trace_derived_policy": "yes", "mcp": "yes"}),
                    {**_read_row(b, included=False), "status": "not retrieved: HTTP 404"},
                ],
            )
            allowed = build_counts(root)
        decision = blocked["decision"]
        self.assertEqual((decision["case"], decision["claim"], decision["provisional"]), (2, "not allowed yet", True))
        opened = " / ".join(decision["open"])
        self.assertIn("the search is not frozen to one date", opened)
        self.assertIn("openalex-concept is not complete", opened)
        self.assertNotIn("dblp-phrase", opened)
        self.assertIn("screener 1: 3 keyword-kept works have no decision", opened)
        self.assertIn("reads: 1 kept works have no read row", opened)
        self.assertIn(decision["text"], prisma)
        for items in other_dblp:
            self.assertIn("dblp-phrase is not complete", items)
        final = allowed["decision"]
        self.assertEqual((final["case"], final["claim"], final["open"]), (2, "allowed", []))
        # The allowed text states the search's own limits (section 8).
        for limit in (
            "frozen on 2026-11-03",
            f"dblp-phrase failed: {DBLP_ERROR}",
            f"openalex-concept counted 3999 works over the cell cap of {CONCEPT_CELL_CAP} and did not download them",
            "full text not retrieved for 1 kept works, listed in closest-works.md",
            "no included work tests it.",
        ):
            self.assertIn(limit, final["text"])
        self.assertTrue(final["text"].endswith("Provisional: screener 2 is pending."))


if __name__ == "__main__":
    unittest.main()
