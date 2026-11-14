"""Bulk scan: argument labels, registry census folding, and a local tools/list pass."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

from wiggle.scan_classify import classify_argument, classify_tool, hint_families, primary_family
from wiggle.scan_local import load_catalog, scan_entries
from wiggle.scan_registry import (
    collect_registry,
    compact_server,
    public_endpoint,
    select_records,
    study_candidates,
)


FAKE = r"""
import json, sys
for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg.get("method") == "tools/call":
        sys.exit(2)
    method = msg.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "serverInfo": {"name": "fake", "version": "1"},
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "read_text_file",
                    "description": "Read a file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                }
            ]
        }
    else:
        result = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"""


def _entry(name, version, latest, **extra):
    server = {
        "name": name,
        "description": extra.get("description", ""),
        "version": version,
    }
    if "packages" in extra:
        server["packages"] = extra["packages"]
    if "remotes" in extra:
        server["remotes"] = extra["remotes"]
    return {
        "server": server,
        "_meta": {
            "io.modelcontextprotocol.registry/official": {
                "status": extra.get("status", "active"),
                "updatedAt": extra.get("updated", "2026-01-01T00:00:00Z"),
                "isLatest": latest,
            }
        },
    }


class ClassifyTests(unittest.TestCase):
    def test_path_and_content_stay_apart(self):
        tool = classify_tool(
            {
                "name": "write_file",
                "description": "Write a file path inside the root",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string", "description": "Text to write"},
                    },
                    "required": ["path", "content"],
                },
            }
        )
        features = {row["name"]: row["feature"] for row in tool["arguments"]}
        self.assertEqual(features["path"], "path")
        self.assertEqual(features["content"], "free-text")
        self.assertEqual(tool["free_string_resources"], ["write_file.path"])

    def test_query_is_not_sql_unless_the_name_or_description_says_sql(self):
        self.assertEqual(classify_argument("query", {"type": "string", "description": "Search text"})["feature"], "free-text")
        self.assertEqual(classify_argument("sql", {"type": "string"})["feature"], "sql")
        described = classify_argument("location", {"type": "string", "description": "URL to fetch"})
        self.assertEqual(described["feature"], "url")

    def test_enum_marks_the_argument_constrained(self):
        row = classify_argument("timezone", {"type": "string", "enum": ["UTC"]})
        self.assertEqual(row["feature"], "timezone")
        self.assertTrue(row["constrained"])

    def test_branch_and_entity_names_keep_their_family(self):
        self.assertEqual(classify_argument("branch_name", {"type": "string"})["feature"], "git")
        self.assertEqual(classify_argument("base_branch", {})["feature"], "git")
        self.assertEqual(classify_argument("entityNames", {"type": "array"})["feature"], "entity")
        tool = classify_tool(
            {
                "name": "delete_entities",
                "description": "",
                "inputSchema": {
                    "properties": {"entityNames": {"type": "array", "items": {"type": "string"}}},
                    "required": ["entityNames"],
                },
            }
        )
        self.assertEqual(tool["free_string_resources"], ["delete_entities.entityNames"])

    def test_tie_prefers_path(self):
        self.assertEqual(primary_family({"url": 2, "path": 2}), "path")
        self.assertEqual(primary_family({}), "unclassified")

    def test_hints_read_the_description(self):
        self.assertIn("sql", hint_families("SQLite database tools"))
        self.assertIn("path", hint_families("filesystem access to directories"))
        self.assertNotIn("sql", hint_families("filesystem access to directories"))


class RegistryTests(unittest.TestCase):
    def test_endpoint_and_secret_values_are_dropped(self):
        record = compact_server(
            _entry(
                "com.example/remote",
                "1.0.0",
                True,
                packages=[
                    {
                        "registryType": "npm",
                        "identifier": "example",
                        "version": "1.0.0",
                        "transport": {"type": "stdio"},
                        "environmentVariables": [
                            {"name": "TOKEN", "isSecret": True, "value": "super-secret"},
                            {"name": "BUCKET"},
                        ],
                    }
                ],
                remotes=[
                    {
                        "type": "streamable-http",
                        "url": "https://user:hunter2@example.com/mcp?token=abc#frag",
                    }
                ],
            )
        )
        blob = json.dumps(record)
        self.assertNotIn("super-secret", blob)
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("token=abc", blob)
        self.assertEqual(record["remotes"][0]["endpoint"], "https://example.com/mcp")
        self.assertEqual(record["packages"][0]["secret_env"], ["TOKEN"])
        self.assertEqual(record["packages"][0]["env"], ["BUCKET"])
        self.assertEqual(public_endpoint("not a url"), "")
        self.assertEqual(
            public_endpoint("http://example.com:{HAPI_PORT}/mcp?token=abc"),
            "http://example.com/mcp",
        )

    def test_latest_flag_beats_a_newer_timestamp_and_deleted_rows_drop(self):
        records, stats = select_records(
            [
                _entry("com.example/srv", "1.0.0", False, updated="2026-02-01T00:00:00Z"),
                _entry("com.example/srv", "2.0.0", True, updated="2026-01-01T00:00:00Z"),
                _entry("com.example/gone", "1.0.0", True, status="deleted"),
            ]
        )
        self.assertEqual([row["version"] for row in records], ["2.0.0"])
        self.assertEqual(stats["versions_folded"], 1)
        self.assertEqual(stats["deleted_skipped"], 1)

    def test_without_a_latest_flag_the_newer_row_wins(self):
        records, _stats = select_records(
            [
                _entry("com.example/srv", "1", False, updated="2026-01-01T00:00:00Z"),
                _entry("com.example/srv", "2", False, updated="2026-03-01T00:00:00Z"),
            ]
        )
        self.assertEqual(records[0]["version"], "2")

    def test_github_namespace_is_not_a_github_server(self):
        weather = compact_server(_entry("io.github.acme/weather", "1", True))
        official = compact_server(
            _entry(
                "io.github.github/github-mcp-server",
                "1",
                True,
                packages=[
                    {
                        "registryType": "npm",
                        "identifier": "@github/mcp",
                        "version": "1",
                        "transport": {"type": "stdio"},
                    }
                ],
            )
        )
        candidates = study_candidates([weather, official])
        self.assertEqual(candidates["github"]["count"], 1)
        self.assertEqual(candidates["github"]["shown"][0]["name"], "io.github.github/github-mcp-server")
        self.assertEqual(candidates["sqlite"]["count"], 0)

    def test_a_github_release_url_is_not_a_github_server(self):
        release = compact_server(
            _entry(
                "ai.example/harness",
                "1",
                True,
                packages=[
                    {
                        "registryType": "mcpb",
                        "identifier": "https://github.com/example/harness/releases/download/v1/harness.mcpb",
                        "version": "1",
                        "transport": {"type": "stdio"},
                    }
                ],
            )
        )
        official = compact_server(
            _entry(
                "io.github.github/github-mcp-server",
                "2.0.2",
                True,
                packages=[
                    {
                        "registryType": "oci",
                        "identifier": "ghcr.io/github/github-mcp-server:2.0.2",
                        "version": "",
                        "transport": {"type": "stdio"},
                    }
                ],
            )
        )
        candidates = study_candidates([release, official])
        self.assertEqual(candidates["github"]["count"], 1)
        self.assertEqual(candidates["github"]["shown"][0]["name"], "io.github.github/github-mcp-server")

    def test_repeated_cursor_stops_the_walk(self):
        pages = {
            "": {
                "servers": [_entry("a.example/one", "1", True)],
                "metadata": {"nextCursor": "c1"},
            },
            "c1": {
                "servers": [_entry("a.example/two", "1", True)],
                "metadata": {"nextCursor": "c1"},
            },
        }
        records, stats = collect_registry(lambda cursor: pages[cursor])
        self.assertEqual(stats["pages"], 2)
        self.assertFalse(stats["complete"])
        self.assertEqual([row["name"] for row in records], ["a.example/one", "a.example/two"])

    def test_checkpoint_resumes_from_the_saved_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkpoint.json"
            path.write_text(
                json.dumps(
                    {
                        "cursor": "c1",
                        "seen_cursors": [""],
                        "counters": {
                            "rows": 1,
                            "deleted_skipped": 0,
                            "versions_folded": 0,
                            "unreadable": 0,
                        },
                        "pages": 1,
                        "records": [compact_server(_entry("a.example/one", "1", True))],
                    }
                ),
                encoding="utf-8",
            )

            def fetch(cursor):
                self.assertEqual(cursor, "c1")
                return {
                    "servers": [_entry("a.example/two", "1", True)],
                    "metadata": {"nextCursor": ""},
                }

            records, stats = collect_registry(fetch, checkpoint=path)
        self.assertEqual([row["name"] for row in records], ["a.example/one", "a.example/two"])
        self.assertEqual(stats["pages"], 2)
        self.assertTrue(stats["complete"])
        self.assertEqual(stats["rows"], 2)

    def test_max_pages_leaves_the_census_incomplete(self):
        def fetch(_cursor):
            return {
                "servers": [_entry("a.example/one", "1", True)],
                "metadata": {"nextCursor": "more"},
            }

        _records, stats = collect_registry(fetch, max_pages=1)
        self.assertEqual(stats["pages"], 1)
        self.assertFalse(stats["complete"])


class LocalScanTests(unittest.TestCase):
    def test_parallel_list_does_not_call_tools_and_keeps_going_after_a_failure(self):
        entries = [
            {"id": "dead", "command": [sys.executable, "-c", "import sys; sys.exit(3)"], "env": None, "error": ""},
            {"id": "fake", "command": [sys.executable, "-c", FAKE], "env": None, "error": ""},
        ]
        rows = scan_entries(entries, workers=2, timeout=10)
        self.assertEqual([row["id"] for row in rows], ["dead", "fake"])
        self.assertFalse(rows[0]["ok"])
        self.assertTrue(rows[1]["ok"])
        self.assertEqual(rows[1]["family"], "path")
        self.assertEqual(rows[1]["tool_count"], 1)
        self.assertEqual(rows[1]["free_string_resources"], ["read_text_file.path"])
        self.assertEqual(rows[1]["server_info"]["name"], "fake")

    def test_catalog_rejects_a_shell_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_text(json.dumps({"servers": [{"id": "x", "command": "npx some-server"}]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_catalog(path)


if __name__ == "__main__":
    unittest.main()
