"""Read-only census of the official MCP registry.

The client pages `GET /v0.1/servers`, keeps one record per server name, and
classifies the text. It does not install a package, open a remote transport,
or call a tool. Remote userinfo and query strings are dropped before a record
is stored. Secret environment values are not stored; only the variable names.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from wiggle import __version__
from wiggle.scan_classify import STUDY_TARGETS, hint_families


REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0.1/servers"
_OFFICIAL = "io.modelcontextprotocol.registry/official"


def public_endpoint(url: str) -> str:
    """Scheme, host, port, and path. Userinfo, query, and fragment are removed.

    A port that is not an integer, such as a `{HAPI_PORT}` template, is dropped
    with the rest of the URL still reduced to the public parts.
    """
    try:
        parsed = urlsplit(url)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port:
        host = f"{host}:{port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def compact_server(entry: dict) -> dict:
    server = entry.get("server") if isinstance(entry.get("server"), dict) else {}
    meta_root = entry.get("_meta") if isinstance(entry.get("_meta"), dict) else {}
    meta = meta_root.get(_OFFICIAL) if isinstance(meta_root.get(_OFFICIAL), dict) else {}
    texts = [str(server.get("name") or ""), str(server.get("description") or "")]
    packages = []
    for pkg in server.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        identifier = str(pkg.get("identifier") or "")
        texts.append(identifier)
        env_names: list[str] = []
        secret_names: list[str] = []
        for var in pkg.get("environmentVariables") or []:
            if not isinstance(var, dict):
                continue
            var_name = str(var.get("name") or "")
            if not var_name:
                continue
            if var.get("isSecret"):
                secret_names.append(var_name)
            else:
                env_names.append(var_name)
        transport = pkg.get("transport") if isinstance(pkg.get("transport"), dict) else {}
        packages.append(
            {
                "registry": str(pkg.get("registryType") or ""),
                "identifier": identifier,
                "version": str(pkg.get("version") or ""),
                "transport": str(transport.get("type") or ""),
                "env": env_names,
                "secret_env": secret_names,
            }
        )
    remotes = []
    for remote in server.get("remotes") or []:
        if not isinstance(remote, dict):
            continue
        remotes.append(
            {
                "type": str(remote.get("type") or ""),
                "endpoint": public_endpoint(str(remote.get("url") or "")),
            }
        )
    transports = sorted(
        {row["transport"] for row in packages if row["transport"]}
        | {row["type"] for row in remotes if row["type"]}
    )
    return {
        "name": str(server.get("name") or ""),
        "version": str(server.get("version") or ""),
        "description": str(server.get("description") or ""),
        "status": str(meta.get("status") or ""),
        "updated_at": str(meta.get("updatedAt") or ""),
        "is_latest": bool(meta.get("isLatest")),
        "packages": packages,
        "remotes": remotes,
        "transports": transports,
        "hints": hint_families(*texts),
    }


def _better(candidate: dict, current: dict) -> bool:
    if candidate["is_latest"] != current["is_latest"]:
        return candidate["is_latest"]
    return (candidate["updated_at"], candidate["version"]) >= (
        current["updated_at"],
        current["version"],
    )


def _consider(kept: dict[str, dict], counters: dict[str, int], entry: dict, include_deleted: bool) -> None:
    try:
        record = compact_server(entry)
    except (TypeError, ValueError):
        counters["unreadable"] = counters.get("unreadable", 0) + 1
        return
    if not record["name"]:
        return
    counters["rows"] += 1
    if not include_deleted and record["status"] == "deleted":
        counters["deleted_skipped"] += 1
        return
    current = kept.get(record["name"])
    if current is None:
        kept[record["name"]] = record
        return
    counters["versions_folded"] += 1
    if _better(record, current):
        kept[record["name"]] = record


def select_records(entries: list[dict], *, include_deleted: bool = False) -> tuple[list[dict], dict]:
    """Keep one row per server name. Prefer the registry's latest flag, then the newer timestamp."""
    kept: dict[str, dict] = {}
    counters = {"rows": 0, "deleted_skipped": 0, "versions_folded": 0, "unreadable": 0}
    for entry in entries:
        if isinstance(entry, dict):
            _consider(kept, counters, entry, include_deleted)
    counters["kept"] = len(kept)
    return [kept[name] for name in sorted(kept)], counters


def _blank_counters() -> dict[str, int]:
    return {"rows": 0, "deleted_skipped": 0, "versions_folded": 0, "unreadable": 0}


def fetch_registry_page(
    cursor: str = "",
    limit: int = 100,
    timeout: float = 60,
    search: str = "",
    attempts: int = 8,
) -> dict:
    params = {"limit": str(limit)}
    if cursor:
        params["cursor"] = cursor
    if search:
        params["search"] = search
    url = REGISTRY_URL + "?" + urlencode(params)
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "wiggle-scan/0.1"})
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            last_error = exc
            if exc.code not in {429, 500, 502, 503, 504}:
                raise
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            last_error = exc
        if attempt + 1 < attempts:
            delay = min(60, 5 * (2**attempt))
            print(f"registry page failed ({last_error}); retry in {delay}s", flush=True)
            time.sleep(delay)
    raise RuntimeError(f"registry page failed: {last_error}")


def _write_checkpoint(
    path: Path,
    cursor: str,
    seen: set[str],
    kept: dict[str, dict],
    counters: dict[str, int],
    pages: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "cursor": cursor,
        "seen_cursors": list(seen),
        "counters": counters,
        "pages": pages,
        "records": [kept[name] for name in sorted(kept)],
    }
    temporary = path.parent / (path.name + ".tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.replace(path)


def _load_checkpoint(path: Path) -> dict | None:
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else None


def collect_registry(
    fetch: Callable[[str], dict],
    *,
    max_pages: int = 0,
    include_deleted: bool = False,
    on_page: Callable[[int, int], None] | None = None,
    checkpoint: Path | None = None,
) -> tuple[list[dict], dict]:
    """Page until the cursor is empty or repeats. `max_pages` of 0 reads every page.

    A checkpoint stores the next cursor and the rows kept so far. The next run
    continues from that cursor instead of starting over.
    """
    cursor = ""
    seen: set[str] = set()
    kept: dict[str, dict] = {}
    counters = _blank_counters()
    pages = 0
    if checkpoint is not None:
        state = _load_checkpoint(checkpoint)
        if state:
            cursor = str(state.get("cursor") or "")
            seen = {str(item) for item in state.get("seen_cursors") or []}
            pages = int(state.get("pages") or 0)
            saved = state.get("counters") if isinstance(state.get("counters"), dict) else {}
            for key in counters:
                counters[key] = int(saved.get(key) or 0)
            for record in state.get("records") or []:
                if isinstance(record, dict) and record.get("name"):
                    kept[str(record["name"])] = record
    while True:
        if max_pages and pages >= max_pages:
            break
        if cursor in seen:
            break
        seen.add(cursor)
        page = fetch(cursor)
        if not isinstance(page, dict):
            raise RuntimeError("registry page was not an object")
        pages += 1
        servers = page.get("servers") if isinstance(page, dict) else None
        if isinstance(servers, list):
            for entry in servers:
                if isinstance(entry, dict):
                    _consider(kept, counters, entry, include_deleted)
        if on_page is not None:
            on_page(pages, len(kept))
        metadata = page.get("metadata") if isinstance(page, dict) and isinstance(page.get("metadata"), dict) else {}
        cursor = str(metadata.get("nextCursor") or "")
        if checkpoint is not None:
            _write_checkpoint(checkpoint, cursor, seen, kept, counters, pages)
        if not cursor:
            break
    counters["kept"] = len(kept)
    counters["pages"] = pages
    counters["complete"] = cursor == ""
    if checkpoint is not None and not counters["complete"]:
        _write_checkpoint(checkpoint, cursor, seen, kept, counters, pages)
    return [kept[name] for name in sorted(kept)], counters


def study_candidates(records: list[dict], limit: int = 12) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for target, tokens in STUDY_TARGETS.items():
        matches = [record for record in records if _matches_target(record, tokens)]
        matches.sort(key=_candidate_rank)
        found[target] = {"count": len(matches), "shown": matches[:limit]}
    return found


def _package_label(identifier: str) -> str:
    """Package name used for matching. A download URL contributes its file name only."""
    text = identifier.lower()
    if text.startswith(("http://", "https://", "ghcr.io/", "docker.io/", "oci://")):
        return text.rstrip("/").split("/")[-1]
    return text


def _matches_target(record: dict, tokens: tuple[str, ...]) -> bool:
    # The `io.github.` namespace contains the letters "github". Match the name
    # after the slash, and the package identifier, as whole tokens.
    name = record["name"].lower()
    short = name.split("/", 1)[1] if "/" in name else name
    labels = [short, *[_package_label(pkg["identifier"]) for pkg in record["packages"]]]
    blob = "\n".join(labels)
    return any(_has_token(blob, token) for token in tokens)


def _has_token(blob: str, token: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", blob) is not None


_OFFICIAL_NAMESPACES = {
    "io.github.github",
    "io.github.microsoft",
    "io.github.modelcontextprotocol",
    "io.modelcontextprotocol",
}


def _candidate_rank(record: dict) -> tuple:
    name = record["name"].lower()
    namespace = name.split("/", 1)[0]
    official = namespace in _OFFICIAL_NAMESPACES or namespace.endswith("modelcontextprotocol")
    stdio = "stdio" in (record.get("transports") or [])
    return (0 if official else 1, 0 if stdio else 1, name)


def summarize_census(records: list[dict]) -> dict:
    hints: dict[str, int] = {}
    transports: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for record in records:
        for hint in record["hints"]:
            hints[hint] = hints.get(hint, 0) + 1
        for transport in record["transports"]:
            transports[transport] = transports.get(transport, 0) + 1
        statuses[record["status"] or "unknown"] = statuses.get(record["status"] or "unknown", 0) + 1
        if not record["transports"]:
            transports["unspecified"] = transports.get("unspecified", 0) + 1
    return {
        "servers": len(records),
        "hints": dict(sorted(hints.items())),
        "transports": dict(sorted(transports.items())),
        "statuses": dict(sorted(statuses.items())),
        "candidates": study_candidates(records),
    }


def census_payload(records: list[dict], stats: dict) -> dict:
    summary = summarize_census(records)
    return {
        "version": __version__,
        "study": "registry-census",
        "source": REGISTRY_URL,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "calls_tools": False,
        "installs_packages": False,
        "stats": stats,
        "summary": {key: summary[key] for key in ("servers", "hints", "transports", "statuses")},
        "candidates": {
            target: {"count": row["count"], "shown": [_candidate_view(item) for item in row["shown"]]}
            for target, row in summary["candidates"].items()
        },
        "servers": records,
    }


def _candidate_view(record: dict) -> dict:
    return {
        "name": record["name"],
        "version": record["version"],
        "status": record["status"],
        "is_latest": record["is_latest"],
        "hints": record["hints"],
        "transports": record["transports"],
        "packages": [
            {
                "registry": pkg["registry"],
                "identifier": pkg["identifier"],
                "version": pkg["version"],
                "transport": pkg["transport"],
            }
            for pkg in record["packages"]
        ],
    }


def render_census_report(payload: dict) -> str:
    stats = payload["stats"]
    summary = payload["summary"]
    lines = [
        "# Registry census",
        "",
        "Read-only pull of the official MCP registry. One row per server name. No package was installed and no tool was called. Remote userinfo and query strings are not stored.",
        "",
        f"Scanned at {payload['scanned_at']}. Pages read: {stats['pages']}. Rows seen: {stats['rows']}. Kept: {stats['kept']}. Older versions folded: {stats['versions_folded']}. Deleted skipped: {stats['deleted_skipped']}. Unreadable rows: {stats.get('unreadable', 0)}. Complete: {stats['complete']}.",
        "",
        "## Hint counts",
        "",
        "A server is counted once per hint. Hints come from the name, package identifier, and description.",
        "",
        "| Hint | Servers |",
        "| --- | ---: |",
    ]
    for hint, count in summary["hints"].items():
        lines.append(f"| {hint} | {count} |")
    if not summary["hints"]:
        lines.append("| — | 0 |")
    lines.extend(["", "## Transports", "", "| Transport | Servers |", "| --- | ---: |"])
    for transport, count in summary["transports"].items():
        lines.append(f"| {transport} | {count} |")
    lines.extend(
        [
            "",
            "## Open study pins",
            "",
            "Matches use the server name after the slash, or a package identifier. A download URL counts only by its file name, so a GitHub release of an unrelated server is not a GitHub match. Official namespaces come first, then servers with a stdio package, then name. This list does not choose a pin by itself.",
            "",
        ]
    )
    for target, row in payload["candidates"].items():
        lines.append(f"### {target}")
        lines.append("")
        lines.append(f"{row['count']} name or package match(es).")
        lines.append("")
        if not row["shown"]:
            lines.append("No match in the rows kept.")
            lines.append("")
            continue
        lines.append("| Server | Version | Package | Transports |")
        lines.append("| --- | --- | --- | --- |")
        for item in row["shown"]:
            preferred = [pkg for pkg in item["packages"] if pkg.get("registry") in {"npm", "pypi", "nuget"}]
            shown = (preferred or item["packages"])[:2]
            packages = ", ".join(
                f"`{pkg['identifier']}@{pkg['version']}`" if pkg["identifier"] else "—"
                for pkg in shown
            ) or "—"
            transports = ", ".join(item["transports"]) or "—"
            lines.append(f"| `{item['name']}` | {item['version']} | {packages} | {transports} |")
        lines.append("")
    lines.append(
        "A full curve still needs a pinned command, a task suite, and the probe lattice. This census only decides which servers are worth that work."
    )
    lines.append("")
    return "\n".join(lines)


def write_census(out_dir: Path, payload: dict) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (out_dir / "report.md").write_text(render_census_report(payload), encoding="utf-8")
