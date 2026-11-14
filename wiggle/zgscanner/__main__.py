"""zgscanner CLI: `scan` writes a report, `panel` serves the dashboard, `checks` lists the catalog."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from wiggle.zgscanner import report as render
from wiggle.zgscanner.catalog import SEVERITY_RANK, catalog_payload
from wiggle.zgscanner.engine import DEFAULT_PINS, ScanOptions, run_scan
from wiggle.zgscanner.llm import DEFAULT_MODEL


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-discover", action="store_true", help="Do not read the known client config locations.")
    parser.add_argument("--config", action="append", default=[], type=Path, help="Extra client config file (repeatable).")
    parser.add_argument("--tools-json", action="append", default=[], type=Path,
                        help="Saved tools/list output, or {servers: [...]} (repeatable). Scanned statically.")
    parser.add_argument("--no-skills", action="store_true", help="Skip agent skill discovery.")
    parser.add_argument("--skill", action="append", default=[], type=Path, help="Extra skill folder or SKILL.md (repeatable).")
    parser.add_argument("--source", action="append", default=[], type=Path, help="MCP server source tree to scan (repeatable).")
    parser.add_argument("--connect", action="append", default=[],
                        help="Server name or id to start or contact for initialize + list calls (repeatable), or 'all'. "
                             "A stdio server runs its own code when started.")
    parser.add_argument("--identify-as", default="", help="Second client name for the bait-and-switch check (PR001).")
    parser.add_argument("--timeout", type=float, default=60, help="Per-request timeout for live servers, seconds.")
    parser.add_argument("--workers", type=int, default=0, help="Parallel live servers. 0 caps at half the cores, at most 4.")
    parser.add_argument("--osv", action="store_true", help="Query api.osv.dev for pinned npm/PyPI packages.")
    parser.add_argument("--virustotal", action="store_true", help="Look up file hashes on VirusTotal (needs VT_API_KEY).")
    parser.add_argument("--llm", action="store_true", help="Run the Claude LLM judge on connected servers' tools.")
    parser.add_argument("--llm-model", default=DEFAULT_MODEL)
    parser.add_argument("--pins", type=Path, default=DEFAULT_PINS, help=f"Pins file for drift checks (default {DEFAULT_PINS}).")
    parser.add_argument("--pin", action="store_true", help="Record the scanned state as the new baseline after the scan.")
    parser.add_argument("--allowlist", type=Path, default=None, help="File with one approved server or package name per line.")


def _options(args: argparse.Namespace) -> ScanOptions:
    connect = "all" if "all" in args.connect else list(args.connect)
    targets = list(getattr(args, "targets", []) or [])
    allowlist = None
    if args.allowlist:
        allowlist = [line.strip() for line in args.allowlist.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    return ScanOptions(
        targets=targets, discover=not args.no_discover and not targets, configs=args.config, tools_json=args.tools_json,
        skills=not args.no_skills and not targets,
        skill_paths=args.skill, sources=args.source, connect=connect, identify_as=args.identify_as, timeout=args.timeout,
        workers=args.workers, osv=args.osv, virustotal=args.virustotal, llm=args.llm, llm_model=args.llm_model,
        pins=args.pins, pin=args.pin, allowlist=allowlist,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m wiggle.zgscanner", description="Combined MCP security scanner.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan and write reports.")
    scan.add_argument("targets", nargs="*", metavar="TARGET",
                      help="A server URL, a JSON config snippet, or a launch command to scan on its own. URLs are contacted for "
                           "initialize and list calls; launch commands are checked without being run.")
    _common(scan)
    scan.add_argument("--out", type=Path, default=Path("artifacts") / "zgscanner", help="Output directory.")
    scan.add_argument("--format", action="append", choices=["json", "sarif", "md", "html"], default=[],
                      help="Report format (repeatable). Default: json and html.")
    scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info", "never"], default="never",
                      help="Exit 1 when a finding at or above this severity exists (CI mode).")

    panel = sub.add_parser("panel", help="Serve the dashboard on 127.0.0.1.")
    _common(panel)
    panel.add_argument("--port", type=int, default=8765)
    panel.add_argument("--open", action="store_true", help="Open the panel in the default browser.")
    panel.add_argument("--no-initial-scan", action="store_true")

    checks = sub.add_parser("checks", help="Print the check catalog and scanner coverage.")
    checks.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "checks":
        payload = catalog_payload()
        if args.json:
            print(json.dumps(payload, indent=2))
            return 0
        for check in payload["checks"]:
            print(f"{check['id']:<8} {check['severity']:<8} {check['requires']:<10} {check['title']}")
        print()
        for row in payload["coverage"].values():
            print(f"{row['name']:<32} {row['covered']}/{row['total']} features")
        return 0
    if args.command == "panel":
        from wiggle.zgscanner.panel import serve

        serve(_options(args), port=args.port, open_browser=args.open, initial=not args.no_initial_scan)
        return 0

    result = run_scan(_options(args), progress=lambda message: print(message, file=sys.stderr, flush=True))
    formats = args.format or ["json", "html"]
    names = {"json": "report.json", "sarif": "report.sarif", "md": "report.md", "html": "report.html"}
    for fmt in formats:
        render.write(result, args.out / names[fmt], fmt)
    summary = result["summary"]
    sev = summary["severity"]
    print(f"Risk {summary['risk']}/100 ({summary['grade']}). {summary['findings']} findings: "
          f"{sev['critical']} critical, {sev['high']} high, {sev['medium']} medium, {sev['low']} low, {sev['info']} info.")
    print(f"Checks: {summary['checks']['fail']} failed, {summary['checks']['pass']} passed, {summary['checks']['skipped']} skipped.")
    print("Wrote " + ", ".join(str(args.out / names[fmt]) for fmt in formats))
    for error in result["errors"]:
        print(f"  note: {error}", file=sys.stderr)
    if args.fail_on != "never":
        limit = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[row["severity"]] <= limit for row in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
