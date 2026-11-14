"""Local panel: a stdlib HTTP server on 127.0.0.1 that serves the dashboard and runs scans.

Every /api call needs the per-run token embedded in the page and a loopback
Host header, so another site open in the browser cannot trigger a scan (which
may start configured servers) or read results.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from wiggle.zgscanner import report as render
from wiggle.zgscanner import rules
from wiggle.zgscanner.engine import ScanOptions, run_scan

CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
MAX_BODY = 8 * 1024 * 1024


def _strings(value, limit: int = 64) -> list[str]:
    if isinstance(value, str):
        value = [line for line in value.splitlines()]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()][:limit]


def options_from(body: dict, base: ScanOptions) -> ScanOptions:
    """Build scan options from a panel request. Unknown keys are ignored; types are coerced."""
    connect = body.get("connect")
    if connect != "all":
        connect = _strings(connect, 256)
    allow = body.get("allowlist")
    tools_json = body.get("tools_json")
    target = str(body.get("target") or "").strip()[:20000]
    return ScanOptions(
        home=base.home,
        cwd=base.cwd,
        targets=[target] if target else [],
        discover=bool(body.get("discover", True)) and not target,
        configs=[Path(p) for p in _strings(body.get("configs"))],
        tools_json=[tools_json] if isinstance(tools_json, (dict, list)) else [],
        skills=bool(body.get("skills", True)) and not target,
        skill_paths=[Path(p) for p in _strings(body.get("skill_paths"))],
        sources=[Path(p) for p in _strings(body.get("sources"))],
        connect=connect,
        identify_as=str(body.get("identify_as") or "")[:64],
        timeout=min(max(float(body.get("timeout") or base.timeout), 5), 180),
        workers=base.workers,
        osv=bool(body.get("osv")),
        virustotal=bool(body.get("virustotal")),
        llm=bool(body.get("llm")),
        llm_model=base.llm_model,
        pins=base.pins,
        pin=bool(body.get("pin")),
        allowlist=_strings(allow, 1000) if allow not in (None, "", []) else None,
        text=str(body.get("text") or "")[:500000],
    )


class PanelState:
    def __init__(self, base: ScanOptions, port: int):
        self.base = base
        self.port = port
        self.token = secrets.token_urlsafe(24)
        self.lock = threading.Lock()
        self.reports: dict[str, dict | None] = {"machine": None, "target": None}
        self.progress: list[str] = []
        self.elapsed = 0.0


def make_handler(state: PanelState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "zgscanner-panel"

        def log_message(self, fmt, *args):  # keep the console quiet; scans report their own progress
            return

        def _send(self, status: int, body: bytes, kind: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload) -> None:
            self._send(status, json.dumps(payload, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _guard(self, api: bool) -> bool:
            if self.headers.get("Host", "") not in {f"127.0.0.1:{state.port}", f"localhost:{state.port}"}:
                self._json(HTTPStatus.FORBIDDEN, {"error": "unexpected Host header"})
                return False
            if api and not secrets.compare_digest(self.headers.get("X-zgScanner-Token", ""), state.token):
                self._json(HTTPStatus.FORBIDDEN, {"error": "missing or wrong panel token"})
                return False
            return True

        def do_GET(self):
            path = urlsplit(self.path)
            if path.path in {"/", "/index.html"}:
                if not self._guard(api=False):
                    return
                html = render.panel_html("live", token=state.token, report=state.reports["machine"])
                self._send(HTTPStatus.OK, html.encode("utf-8"), "text/html; charset=utf-8")
                return
            if not path.path.startswith("/api/"):
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if not self._guard(api=True):
                return
            if path.path == "/api/report":
                self._json(HTTPStatus.OK, {"reports": state.reports, "elapsed": state.elapsed})
            elif path.path == "/api/progress":
                self._json(HTTPStatus.OK, {"busy": state.lock.locked(), "progress": state.progress[-5:]})
            elif path.path == "/api/export":
                query = parse_qs(path.query)
                fmt = (query.get("format") or ["json"])[0]
                report = state.reports.get((query.get("which") or ["machine"])[0])
                if report is None:
                    self._json(HTTPStatus.CONFLICT, {"error": "run a scan first"})
                    return
                kinds = {"json": ("application/json", "json"), "sarif": ("application/sarif+json", "sarif"),
                         "md": ("text/markdown", "md"), "html": ("text/html", "html")}
                if fmt not in kinds:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "format must be json, sarif, md, or html"})
                    return
                if fmt == "json":
                    text = render.to_json(report)
                elif fmt == "sarif":
                    text = json.dumps(render.to_sarif(report), indent=2, ensure_ascii=False)
                elif fmt == "md":
                    text = render.to_markdown(report)
                else:
                    text = render.to_html(report)
                kind, ext = kinds[fmt]
                self._send(HTTPStatus.OK, text.encode("utf-8"), f"{kind}; charset=utf-8",
                           {"Content-Disposition": f'attachment; filename="zgscanner-report.{ext}"'})
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self):
            path = urlsplit(self.path).path
            if not self._guard(api=True):
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request too large"})
                return
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("body must be an object")
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": f"bad JSON: {exc}"})
                return
            if path == "/api/text":
                text = str(body.get("text") or "")[:500000]
                hits = rules.scan_text(text, "text")
                self._json(HTTPStatus.OK, {"hits": hits})
                return
            if path != "/api/scan":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if not state.lock.acquire(blocking=False):
                self._json(HTTPStatus.CONFLICT, {"error": "a scan is already running"})
                return
            try:
                opts = options_from(body, state.base)
                state.progress = []
                started = time.monotonic()
                result = run_scan(opts, progress=state.progress.append)
                state.elapsed = round(time.monotonic() - started, 2)
                if not body.get("ephemeral"):
                    state.reports["target" if opts.targets else "machine"] = result
                self._json(HTTPStatus.OK, {"report": result, "elapsed": state.elapsed})
            except Exception as exc:  # the panel shows the error inside the block that failed
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            finally:
                state.lock.release()

    return Handler


def serve(base: ScanOptions, port: int = 8765, open_browser: bool = False, initial: bool = True) -> None:
    state = PanelState(base, port)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    state.port = server.server_address[1]
    url = f"http://127.0.0.1:{state.port}/"
    if initial:
        print("Running the first static scan (no server is started)...", flush=True)
        started = time.monotonic()
        state.reports["machine"] = run_scan(base)
        state.elapsed = round(time.monotonic() - started, 2)
    print(f"zgscanner panel on {url}  (Ctrl+C to stop)", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
