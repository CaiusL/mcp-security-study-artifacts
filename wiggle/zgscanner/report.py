"""Render a scan report as JSON, SARIF 2.1.0, Markdown, or a self-contained HTML panel."""

from __future__ import annotations

import json
from pathlib import Path

from wiggle.zgscanner import __version__
from wiggle.zgscanner.catalog import CHECKS

PANEL_HTML = Path(__file__).with_name("panel.html")
BOOT_MARKER = "/*__ZGSCANNER_BOOT__*/null"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def _uri(path: str) -> str:
    try:
        return Path(path).resolve().as_uri()
    except (OSError, ValueError):
        return path.replace("\\", "/")


def to_sarif(report: dict) -> dict:
    rules = []
    for check in CHECKS:
        rules.append({
            "id": check.id,
            "name": check.title,
            "shortDescription": {"text": check.title},
            "fullDescription": {"text": check.description},
            "help": {"text": check.remediation},
            "defaultConfiguration": {"level": SARIF_LEVEL[check.severity]},
            "properties": {
                "tags": ["security", check.category, *check.owasp],
                "security-severity": SECURITY_SEVERITY[check.severity],
                "precision": "medium",
            },
        })
    index = {check.id: number for number, check in enumerate(CHECKS)}
    results = []
    for row in report["findings"]:
        result = {
            "ruleId": row["check"],
            "ruleIndex": index[row["check"]],
            "level": SARIF_LEVEL[row["severity"]],
            "message": {"text": f"{row['title']} in {row['target']}: {row['detail'] or row['evidence']}"},
            "properties": {
                "severity": row["severity"],
                "security-severity": SECURITY_SEVERITY[row["severity"]],
                "target": row["target"],
                "targetType": row["target_type"],
                "evidence": row["evidence"],
                "owasp": row["owasp"],
            },
        }
        path = row.get("file") or ""
        if path and Path(path).exists():
            physical = {"artifactLocation": {"uri": _uri(path)}}
            if row.get("line"):
                physical["region"] = {"startLine": int(row["line"])}
            result["locations"] = [{"physicalLocation": physical}]
        else:
            result["locations"] = [{"logicalLocations": [{"name": f"{row['target']} / {row['location']}", "kind": "resource"}]}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "zgscanner", "version": __version__, "informationUri": "https://modelcontextprotocol.io", "rules": rules}},
            "results": results,
            "invocations": [{"executionSuccessful": True, "endTimeUtc": report["scanned_at"]}],
        }],
    }


def _cell(text) -> str:
    return " ".join(str(text).split()).replace("|", "/")[:160]


def to_markdown(report: dict, limit: int = 200) -> str:
    summary = report["summary"]
    sev = summary["severity"]
    lines = [
        "# zgscanner report",
        "",
        f"Scanned {report['scanned_at']}. Risk {summary['risk']}/100 (grade {summary['grade']}). "
        f"{summary['findings']} finding(s) across {summary['servers']} server(s) ({summary['connected']} connected, "
        f"{summary['tools']} tools) and {summary['skills']} skill(s) from {summary['config_files']} config file(s).",
        "",
        "| Critical | High | Medium | Low | Info |",
        "| ---: | ---: | ---: | ---: | ---: |",
        f"| {sev['critical']} | {sev['high']} | {sev['medium']} | {sev['low']} | {sev['info']} |",
        "",
        f"Checks: {summary['checks']['fail']} failed, {summary['checks']['pass']} passed, {summary['checks']['skipped']} skipped.",
        "",
        "## OWASP MCP Top 10",
        "",
        "| Id | Risk | Findings | Worst |",
        "| --- | --- | ---: | --- |",
    ]
    for key, row in report["owasp"].items():
        lines.append(f"| {key} | {row['name']} | {row['findings']} | {row['worst'] or '-'} |")
    lines += ["", "## Findings", "", "| Severity | Check | Target | Location | Detail |", "| --- | --- | --- | --- | --- |"]
    for row in report["findings"][:limit]:
        lines.append(f"| {row['severity']} | {row['check']} {_cell(row['title'])} | {_cell(row['target'])} | "
                     f"{_cell(row['location'])} | {_cell(row['detail'] or row['evidence'])} |")
    if len(report["findings"]) > limit:
        lines.append(f"\n{len(report['findings']) - limit} more in the JSON report.")
    lines += ["", "## Checks", "", "| Check | Title | Status | Findings | Note |", "| --- | --- | --- | ---: | --- |"]
    for row in report["checks"]:
        lines.append(f"| {row['id']} | {_cell(row['title'])} | {row['status']} | {row['findings']} | {_cell(row['reason'])} |")
    lines += ["", "## Scanner coverage", "", "| Scanner | Covered | Gaps |", "| --- | ---: | --- |"]
    for row in report["coverage"].values():
        gaps = "; ".join(f"{f['feature']} ({f['note']})" for f in row["features"] if f["status"] == "gap") or "-"
        lines.append(f"| {row['name']} ({row['aka']}) | {row['covered']}/{row['total']} | {_cell(gaps)} |")
    if report["errors"]:
        lines += ["", "## Errors", ""] + [f"- {_cell(error)}" for error in report["errors"]]
    lines.append("")
    return "\n".join(lines)


def panel_html(mode: str, *, token: str = "", report: dict | None = None) -> str:
    """The panel page with its boot data inlined. `mode` is "live" (served) or "static" (exported)."""
    html = PANEL_HTML.read_text(encoding="utf-8")
    boot = json.dumps({"mode": mode, "token": token, "report": report, "version": __version__}, ensure_ascii=False)
    boot = boot.replace("<", chr(92) + "u003c").replace("\u2028", chr(92) + "u2028").replace("\u2029", chr(92) + "u2029")
    if BOOT_MARKER not in html:
        raise RuntimeError("panel.html is missing its boot marker")
    return html.replace(BOOT_MARKER, boot, 1)


def to_html(report: dict) -> str:
    return panel_html("static", report=report)


def write(report: dict, path: Path, fmt: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        text = to_json(report)
    elif fmt == "sarif":
        text = json.dumps(to_sarif(report), indent=2, ensure_ascii=False) + "\n"
    elif fmt == "md":
        text = to_markdown(report)
    elif fmt == "html":
        text = to_html(report)
    else:
        raise ValueError(f"unknown format {fmt!r}")
    path.write_text(text, encoding="utf-8")
