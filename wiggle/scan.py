"""Scan many MCP servers for a declared envelope without calling their tools.

`registry` pages the public registry and writes a census.
`local` starts catalog commands, or the five vendored study servers, in parallel.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from wiggle.scan_local import load_catalog, run_local_scan
from wiggle.scan_registry import (
    census_payload,
    collect_registry,
    fetch_registry_page,
    write_census,
)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Bulk declared scan of MCP servers. Never calls tools.")
    sub = parser.add_subparsers(dest="command", required=True)

    registry = sub.add_parser("registry", help="Read the official MCP registry. Do not install or connect.")
    registry.add_argument("--out", type=Path, default=Path("artifacts") / "scan-registry")
    registry.add_argument("--max-pages", type=int, default=0, help="Stop after this many pages. 0 reads every page.")
    registry.add_argument("--page-size", type=int, default=100)
    registry.add_argument("--search", default="", help="Optional registry search string.")
    registry.add_argument("--timeout", type=float, default=60)
    registry.add_argument("--include-deleted", action="store_true")

    local = sub.add_parser("local", help="List tools on local stdio servers in parallel.")
    local.add_argument("--out", type=Path, default=Path("artifacts") / "scan-local")
    local.add_argument("--catalog", type=Path, default=None, help="JSON catalog. Default: the five vendored servers.")
    local.add_argument("--workers", type=int, default=0, help="Parallel servers. 0 picks a cap at half the cores, at most 4.")
    local.add_argument("--timeout", type=float, default=30)

    args = parser.parse_args(argv)
    if args.command == "registry":
        _registry(args)
        return
    _local(args)


def _registry(args: argparse.Namespace) -> None:
    def fetch(cursor: str) -> dict:
        return fetch_registry_page(
            cursor,
            limit=args.page_size,
            timeout=args.timeout,
            search=args.search,
        )

    def progress(pages: int, kept: int) -> None:
        if pages % 10 == 0:
            print(f"page {pages}: {kept} servers kept", flush=True)

    checkpoint = args.out / "checkpoint.json"
    if checkpoint.is_file():
        print(f"Resuming from {checkpoint}", flush=True)
    records, stats = collect_registry(
        fetch,
        max_pages=args.max_pages,
        include_deleted=args.include_deleted,
        on_page=progress,
        checkpoint=checkpoint,
    )
    payload = census_payload(records, stats)
    write_census(args.out, payload)
    if stats["complete"] and checkpoint.is_file():
        checkpoint.unlink()
    print(
        f"Kept {stats['kept']} servers from {stats['pages']} page(s). "
        f"Wrote {args.out / 'report.md'}."
    )


def _local(args: argparse.Namespace) -> None:
    entries = load_catalog(args.catalog) if args.catalog else None
    payload = run_local_scan(args.out, entries, workers=args.workers, timeout=args.timeout)
    ok = sum(1 for row in payload["servers"] if row["ok"])
    print(f"Scanned {ok}/{len(payload['servers'])} servers. Wrote {args.out / 'report.md'}.")
    for row in payload["servers"]:
        if row["ok"]:
            print(f"  {row['id']}: {row['tool_count']} tools, family {row['family']}")
        else:
            print(f"  {row['id']}: {row['error']}")


if __name__ == "__main__":
    main()
