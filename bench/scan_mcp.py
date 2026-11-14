"""Full scan of hosted MCP servers (e.g. from mcpservers.org) with Cisco mcp-scanner.

Paste what a listing shows, such as  npx add-mcp 'https://aeoinspector.com/mcp',
a claude mcp add line, a JSON config, or just the URL. Several at once is fine.
Only hosted servers are scanned. For each one the scanner reads everything the
server advertises - tools, server instructions, prompts and resources - and
checks it with YARA rules and the LLM set in mcp-scanner/.env (tools also get
the schema check). It never calls the tools or runs the server's code on this PC.

    python scan_mcp.py npx add-mcp 'https://aeoinspector.com/mcp'
    python scan_mcp.py https://a.example/mcp https://b.example/mcp
    python scan_mcp.py        (then paste, and press Enter on an empty line)
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SCANNER_PYTHON = Path(__file__).resolve().parent / "mcp-scanner" / ".venv" / "Scripts" / "python.exe"
TIMEOUT_SECONDS = 600
URL_RE = re.compile(r"https?://[^\s'\"<>`,]+")
# Pages about a server rather than the server itself.
NOT_SERVERS = ("mcpservers.org", "github.com", "npmjs.com", "pypi.org")
# Category the scanner gives a check that could not run, e.g. a bad LLM key or no balance.
FAILED_CHECK = "ANALYZER INFRASTRUCTURE"


def find_urls(text):
    urls = []
    for url in URL_RE.findall(text):
        url = url.rstrip(".;)]}")
        if url not in urls:
            urls.append(url)
    return urls


def worker(url, out_path):
    """Run inside the scanner's venv: scan one server, write the results as JSON."""
    import asyncio
    import logging

    from mcpscanner import Scanner
    from mcpscanner.cli import _build_config  # importing the CLI also loads mcp-scanner/.env
    from mcpscanner.core.models import AnalyzerEnum

    # HTTP status codes seen, to tell "needs sign-in" apart from other errors.
    http_statuses = []

    class StatusRecorder(logging.Handler):
        def emit(self, record):
            status = re.search(r'"HTTP/[\d.]+ (\d{3})', record.getMessage())
            if status:
                http_statuses.append(int(status.group(1)))

    for name in ("httpx", "httpx2"):  # the MCP 2.0 client logs requests as httpx2
        http_log = logging.getLogger(name)
        http_log.setLevel(logging.INFO)
        http_log.propagate = False
        http_log.addHandler(StatusRecorder())

    tool_analyzers = [AnalyzerEnum.YARA, AnalyzerEnum.SCHEMA, AnalyzerEnum.LLM]
    text_analyzers = [AnalyzerEnum.YARA, AnalyzerEnum.LLM]

    def item(result, name):
        return {
            "name": name,
            "incomplete": result.status not in ("completed", "skipped") or bool(result.analyzer_errors),
            "findings": [{"severity": f.severity, "analyzer": f.analyzer, "summary": f.summary,
                          "failed_check": f.threat_category == FAILED_CHECK}
                         for f in result.findings],
        }

    async def instructions(scanner):
        result = await scanner.scan_remote_server_instructions(url, analyzers=text_analyzers)
        return [] if result.status == "skipped" else [item(result, "server instructions")]

    async def prompts(scanner):
        results = await scanner.scan_remote_server_prompts(url, analyzers=text_analyzers)
        return [item(r, r.prompt_name) for r in results]

    async def resources(scanner):
        results = await scanner.scan_remote_server_resources(
            url, analyzers=text_analyzers, allowed_mime_types=["text/plain", "text/html"])
        return [item(r, r.resource_name or str(r.resource_uri)) for r in results]

    async def scan_all():
        scanner = Scanner(_build_config(tool_analyzers))
        tools = await scanner.scan_remote_server_tools(url, analyzers=tool_analyzers)
        report = {"parts": {"tools": [item(r, r.tool_name) for r in tools]}, "part_errors": {}}
        for part, scan in (("instructions", instructions), ("prompts", prompts), ("resources", resources)):
            try:
                report["parts"][part] = await scan(scanner)
            except Exception as e:
                report["part_errors"][part] = f"{type(e).__name__}: {e}"
        return report

    try:
        report = asyncio.run(scan_all())
    except Exception as e:
        report = {"error": f"{type(e).__name__}: {e}"}
    report["http_statuses"] = http_statuses
    Path(out_path).write_text(json.dumps(report), encoding="utf-8")


def verdict(report):
    """Return (status, finding lines) for one server's report."""
    if report.get("error"):
        if any(s in (401, 403) for s in report["http_statuses"]):
            return "NEEDS SIGN-IN - server requires a login or API key to list its tools", []
        return "ERROR - " + report["error"], []

    lines, counts = [], []
    total = flagged = llm_flagged = not_checked = 0
    for part, items in report["parts"].items():
        counts.append(f"{part}: {len(items)}")
        total += len(items)
        for it in items:
            real = [f for f in it["findings"] if not f["failed_check"]]
            flagged += bool(real)
            llm_flagged += any(f["analyzer"] == "LLM" for f in real)
            not_checked += it["incomplete"] or len(real) < len(it["findings"])
            for f in it["findings"]:
                lines.append(f"  [{f['severity']}] {f['analyzer']} - {part} - {it['name']}: {f['summary']}")
    for part, error in report["part_errors"].items():
        lines.append(f"  {part} could not be scanned: {error}")

    what = ", ".join(counts)
    if llm_flagged:
        return f"UNSAFE - the LLM flagged {llm_flagged} item(s) ({what})", lines
    if not_checked or report["part_errors"]:
        return (f"INCOMPLETE - some checks did not run, see the lines above; for an LLM failure "
                f"check the key and balance in mcp-scanner/.env ({what})"), lines
    if flagged:
        return (f"REVIEW - YARA/schema flagged {flagged} item(s) but the LLM found nothing, "
                f"often a false alarm; read the flagged text ({what})"), lines
    if total == 0:
        return "NO TOOLS - server listed nothing (it may need sign-in)", lines
    return f"SAFE - no findings ({what})", lines


def scan(url):
    """Scan one server in a separate scanner process; return (status, finding lines)."""
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    cmd = [str(SCANNER_PYTHON), "-I", "-X", "utf8", str(Path(__file__).resolve()), "--worker", url, out_path]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    try:
        log, _ = proc.communicate(timeout=TIMEOUT_SECONDS)
        text = Path(out_path).read_text(encoding="utf-8")
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
        proc.communicate()
        return f"ERROR - no answer within {TIMEOUT_SECONDS}s", []
    finally:
        os.remove(out_path)
    if not text:
        return "ERROR - scanner crashed: " + log.strip()[-300:], []
    return verdict(json.loads(text))


def main():
    if not SCANNER_PYTHON.exists():
        sys.exit(f"Scanner not found at {SCANNER_PYTHON}")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    text = " ".join(sys.argv[1:])
    if not text:
        print("Paste the add-mcp line(s) or URL(s), then press Enter on an empty line:")
        lines = []
        for line in sys.stdin:
            if not line.strip():
                break
            lines.append(line)
        text = "".join(lines)

    urls = find_urls(text)
    if not urls:
        sys.exit("No hosted URL found. Listings without a URL are local packages; "
                 "scanning those means running them on this PC, so this script skips them.")

    results = []
    for url in urls:
        if any(host in url.split("/")[2] for host in NOT_SERVERS):
            results.append((url, "SKIPPED - listing/code page, copy the server's hosted URL instead"))
            continue
        print(f"\nScanning {url} (tools, instructions, prompts, resources) ...", flush=True)
        status, lines = scan(url)
        print("\n".join(lines + [status]))
        results.append((url, status))

    print("\n=== Results ===")
    for url, status in results:
        print(f"{status}\n    {url}")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--worker"]:
        worker(sys.argv[2], sys.argv[3])
    else:
        main()
