"""Opt-in live introspection: initialize, then tools/list, prompts/list, resources/list and resources/read.

No tool is called. A resource is read only after resources/list named it, and
only within the caps below: at most 20 resources per server, text MIME types
only, 256 KB of text each. Every listed resource gets a coverage record that
says whether it was read and, if not, why. A stdio server is started with an
argument list, never through a shell. Remote servers are tried over streamable
HTTP and then the legacy HTTP+SSE transport. Remote requests follow a redirect
only within the same origin, and refuse link-local and cloud-metadata
destinations.
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import shutil
import socket
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

from wiggle.mcp_client import McpError, McpStdio

from wiggle.zgscanner import __version__

PROTOCOL = "2025-11-25"
CLIENT_NAME = "wiggle-zgscanner"
USER_AGENT = f"{CLIENT_NAME}/{__version__}"
BLOCKED_HOSTS = {"metadata.google.internal", "metadata", "instance-data", "metadata.azure.com"}
TRANSPORT_LABEL = {"http": "streamable HTTP", "sse": "legacy SSE", "stdio": "stdio"}
MAX_RESOURCE_READS = 20
MAX_RESOURCE_TEXT = 256 * 1024  # bytes of UTF-8 text per resource


class McpAuthError(McpError):
    """The server wants credentials. Trying another transport will not help."""


class McpTransportError(McpError):
    """The URL answered, but not as this transport. Another transport may work."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _origin(url: str) -> tuple:
    parts = urlsplit(url)
    return parts.scheme, parts.hostname, parts.port


def check_destination(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise McpError(f"unsupported URL scheme {parts.scheme!r}")
    host = (parts.hostname or "").lower()
    if not host or host in BLOCKED_HOSTS:
        raise McpError(f"refusing destination {host or url!r}")
    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise McpError(f"cannot resolve {host}: {exc}") from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])
        if address.is_link_local or str(address) in {"169.254.169.254", "fd00:ec2::254"}:
            raise McpError(f"refusing link-local or metadata address {address} for {host}")


def _http_error(exc: urllib.error.HTTPError) -> McpError:
    try:
        body = exc.read(300).decode("utf-8", "replace")
    except OSError:
        body = ""
    if exc.code in (401, 403):
        how = "OAuth sign-in" if "bearer" in (exc.headers.get("WWW-Authenticate") or "").lower() else "credentials"
        return McpAuthError(f"HTTP {exc.code}: the server needs {how}. Paste a config snippet with an Authorization "
                            "header to scan its tools")
    if exc.code in (400, 404, 405, 406, 415):
        return McpTransportError(f"HTTP {exc.code}")
    return McpError(f"HTTP {exc.code}: {' '.join(body.split())[:200]}")


def _not_json(raw: bytes) -> McpTransportError:
    head = raw[:300].decode("utf-8", "replace").lower()
    if "<html" in head or "<!doctype" in head:
        return McpTransportError("returned a web page, not an MCP endpoint")
    return McpTransportError("returned something that is not JSON-RPC")


class McpHttp:
    """Streamable HTTP transport, enough for initialize and the list methods."""

    def __init__(self, url: str, headers: dict | None = None):
        check_destination(url)
        self.url = url
        self.headers = dict(headers or {})
        self.session_id = ""
        self.protocol = ""
        self._next_id = 0

    def _post(self, payload: dict, timeout: float, hops: int = 2):
        headers = {**self.headers, "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "User-Agent": USER_AGENT}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol:
            headers["MCP-Protocol-Version"] = self.protocol
        request = urllib.request.Request(self.url, data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            return _OPENER.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                target = urljoin(self.url, exc.headers.get("Location") or "")
                if hops and target and _origin(target) == _origin(self.url):
                    self.url = target  # e.g. /mcp -> /mcp/ on the same host
                    return self._post(payload, timeout, hops - 1)
                raise McpError(f"server redirected to {target or 'another location'}; only same-origin redirects are followed") from exc
            raise _http_error(exc) from exc
        except urllib.error.URLError as exc:
            raise McpError(f"cannot reach {self.url}: {exc.reason}") from exc

    def request(self, method: str, params: dict | None = None, timeout: float = 30) -> dict:
        self._next_id += 1
        request_id = self._next_id
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        response = self._post(payload, timeout)
        session = response.headers.get("Mcp-Session-Id")
        if session:
            self.session_id = session
        kind = response.headers.get("Content-Type", "")
        messages = self._sse(response) if "text/event-stream" in kind else self._json(response)
        for message in messages:
            if isinstance(message, dict) and message.get("id") == request_id:
                if "error" in message:
                    error = message["error"]
                    raise McpError(error.get("message", str(error)) if isinstance(error, dict) else str(error))
                return message.get("result") or {}
        raise McpTransportError(f"no JSON-RPC reply to {method}")

    @staticmethod
    def _json(response) -> list:
        raw = response.read(8 * 1024 * 1024)
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise _not_json(raw) from None
        return data if isinstance(data, list) else [data]

    @staticmethod
    def _sse(response) -> list:
        messages, data = [], []
        for raw in response:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("data:"):
                data.append(line[5:].lstrip())
            elif not line and data:
                try:
                    messages.append(json.loads("\n".join(data)))
                except json.JSONDecodeError:
                    pass
                data = []
                if any(isinstance(m, dict) and "id" in m and ("result" in m or "error" in m) for m in messages):
                    break
        if data:
            try:
                messages.append(json.loads("\n".join(data)))
            except json.JSONDecodeError:
                pass
        return messages

    def notify(self, method: str, params: dict | None = None) -> None:
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        try:
            self._post(payload, 10).read()
        except McpError:
            pass

    def close(self) -> None:
        if not self.session_id:
            return
        request = urllib.request.Request(self.url, headers={**self.headers, "Mcp-Session-Id": self.session_id}, method="DELETE")
        try:
            _OPENER.open(request, timeout=5).read()
        except (urllib.error.URLError, OSError):
            pass


class McpSse:
    """Legacy HTTP+SSE transport: GET opens an event stream whose first event names the POST endpoint."""

    def __init__(self, url: str, headers: dict | None = None, timeout: float = 30):
        check_destination(url)
        self.url = url
        self.headers = dict(headers or {})
        self.endpoint = ""
        self.problem = ""
        self._messages: queue.Queue = queue.Queue()
        self._ready = threading.Event()
        self._next_id = 0
        request = urllib.request.Request(url, headers={**self.headers, "Accept": "text/event-stream", "User-Agent": USER_AGENT})
        try:
            self._stream = _OPENER.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            raise _http_error(exc) from exc
        except urllib.error.URLError as exc:
            raise McpError(f"cannot reach {url}: {exc.reason}") from exc
        kind = self._stream.headers.get("Content-Type", "")
        if "text/event-stream" not in kind:
            self._stream.close()
            raise McpTransportError("returned a web page, not an MCP endpoint" if "html" in kind else "not an event stream")
        threading.Thread(target=self._read, daemon=True).start()
        if not self._ready.wait(timeout) or not self.endpoint:
            self.close()
            raise McpError(self.problem or "the event stream never announced its message endpoint")

    def _read(self) -> None:
        event, data = "message", []
        try:
            for raw in self._stream:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line.startswith(":"):
                    continue
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data.append(line[5:].lstrip())
                elif not line:
                    if data:
                        self._dispatch(event, "\n".join(data))
                    event, data = "message", []
        except (OSError, ValueError):
            pass
        finally:
            self._messages.put(None)
            self._ready.set()
            try:
                self._stream.close()
            except OSError:
                pass

    def _dispatch(self, event: str, data: str) -> None:
        if event == "endpoint":
            target = urljoin(self.url, data.strip())
            if _origin(target) == _origin(self.url):
                self.endpoint = target
            else:
                self.problem = f"the stream named a message endpoint on another host ({target}); not followed"
            self._ready.set()
            return
        try:
            self._messages.put(json.loads(data))
        except json.JSONDecodeError:
            pass

    def _post(self, payload: dict, timeout: float) -> None:
        headers = {**self.headers, "Content-Type": "application/json", "User-Agent": USER_AGENT}
        request = urllib.request.Request(self.endpoint, data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            _OPENER.open(request, timeout=timeout).read()
        except urllib.error.HTTPError as exc:
            raise _http_error(exc) from exc
        except urllib.error.URLError as exc:
            raise McpError(f"cannot reach {self.endpoint}: {exc.reason}") from exc

    def request(self, method: str, params: dict | None = None, timeout: float = 30) -> dict:
        self._next_id += 1
        request_id = self._next_id
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        self._post(payload, timeout)
        end = time.monotonic() + timeout
        while True:
            remaining = end - time.monotonic()
            try:
                message = self._messages.get(timeout=max(remaining, 0.01))
            except queue.Empty:
                raise McpError(f"timed out waiting for {method}") from None
            if message is None:
                raise McpError(f"the event stream closed during {method}")
            if isinstance(message, dict) and message.get("id") == request_id:
                if "error" in message:
                    error = message["error"]
                    raise McpError(error.get("message", str(error)) if isinstance(error, dict) else str(error))
                return message.get("result") or {}

    def notify(self, method: str, params: dict | None = None) -> None:
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        try:
            self._post(payload, 10)
        except McpError:
            pass

    def close(self) -> None:
        # Closing the response here would wait for the reader thread's blocked read. Shutting the
        # socket down ends that read at once, and the reader closes the response itself.
        sock = getattr(getattr(getattr(self._stream, "fp", None), "raw", None), "_sock", None)
        try:
            if sock is not None:
                sock.shutdown(socket.SHUT_RDWR)
            else:
                self._stream.close()
        except OSError:
            pass


def resolve_command(command: str) -> str:
    """Find npx.cmd and friends on Windows, where an argument list skips PATHEXT."""
    return shutil.which(command) or command


def _initialize(session, client_name: str, timeout: float) -> dict:
    result = session.request(
        "initialize",
        {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": client_name, "version": __version__}},
        timeout=timeout,
    )
    if isinstance(session, McpHttp):
        session.protocol = str(result.get("protocolVersion") or PROTOCOL)
    session.notify("notifications/initialized")
    return result


def connect(server: dict, client_name: str, timeout: float):
    """(session, initialize result, transport). Remote URLs try both transports, the likelier first."""
    if server["transport"] == "stdio":
        if not server["command"]:
            raise McpError("no command")
        env = os.environ.copy()
        env.update(server.get("env") or {})
        session = McpStdio([resolve_command(server["command"]), *server.get("args", [])], env=env)
        try:
            return session, _initialize(session, client_name, timeout), "stdio"
        except Exception as exc:
            tail = " ".join(session.stderr[-1].split())[:200] if session.stderr else ""
            session.close()
            raise McpError(f"{exc} ({tail})" if tail else str(exc)) from exc
    if server["transport"] not in {"http", "sse"}:
        raise McpError(f"{server['transport']} servers cannot be connected")
    url = server["url"]
    sse_first = server["transport"] == "sse" or urlsplit(url).path.rstrip("/").endswith("/sse")
    problems = []
    for kind in ("sse", "http") if sse_first else ("http", "sse"):
        session = None
        try:
            session = McpHttp(url, server.get("headers")) if kind == "http" else McpSse(url, server.get("headers"), timeout)
            return session, _initialize(session, client_name, timeout), kind
        except McpError as exc:
            if session is not None:
                session.close()
            problems.append(f"{TRANSPORT_LABEL[kind]}: {exc}")
            if isinstance(exc, McpAuthError):
                raise McpAuthError(str(exc)) from exc
            if str(exc).startswith(("cannot resolve", "refusing", "unsupported")):
                break
    detail = "; ".join(problems)
    if len(problems) > 1:
        raise McpError("This URL did not answer as an MCP server. If it is a directory or documentation page, paste the "
                       f"server URL shown there; it often ends in /mcp or /sse. Details: {detail}")
    raise McpError(detail)


def _list(session, method: str, key: str, timeout: float, limit: int = 50) -> list[dict]:
    items: list[dict] = []
    cursor = None
    for _ in range(limit):
        result = session.request(method, {"cursor": cursor} if cursor else {}, timeout=timeout)
        page = result.get(key) or []
        items.extend(item for item in page if isinstance(item, dict))
        cursor = result.get("nextCursor")
        if not cursor:
            break
    return items


def is_text_mime(mime: str) -> bool:
    base = (mime or "").split(";", 1)[0].strip().lower()
    return base.startswith("text/") or base == "application/json" or base.endswith("+json") or "markdown" in base


def _record(resource: dict) -> dict:
    return {"uri": str(resource.get("uri") or ""), "name": str(resource.get("name") or ""),
            "mimeType": str(resource.get("mimeType") or ""), "status": "skipped", "reason": "", "bytes": 0}


def _skip_reason(resource: dict, reads: int) -> str:
    """Why a listed resource is not read, decided from the listing alone ("" means read it)."""
    mime = str(resource.get("mimeType") or "")
    size = resource.get("size")
    if not resource.get("uri"):
        return "no URI listed"
    if mime and not is_text_mime(mime):
        return f"MIME type {mime} is not text"
    if isinstance(size, int) and size > MAX_RESOURCE_TEXT:
        return f"size: listed as {size} bytes, over the {MAX_RESOURCE_TEXT // 1024} KB cap"
    if reads >= MAX_RESOURCE_READS:
        return f"over the {MAX_RESOURCE_READS}-resource read cap"
    return ""


def _keep(record: dict, resource: dict, contents) -> None:
    """Keep the text items of a resources/read result when they fit the caps; record what happened."""
    texts, reasons = [], []
    for item in contents if isinstance(contents, list) else []:
        if not isinstance(item, dict):
            continue
        mime = str(item.get("mimeType") or record["mimeType"])
        if not isinstance(item.get("text"), str):
            reasons.append("blob content is not read")
        elif mime and not is_text_mime(mime):
            reasons.append(f"MIME type {mime} is not text")
        else:
            texts.append({"mimeType": mime, "text": item["text"]})
    size = sum(len(item["text"].encode("utf-8")) for item in texts)
    record["bytes"] = size
    if size > MAX_RESOURCE_TEXT:
        texts = []
        reasons.insert(0, f"size: {size} bytes of text, over the {MAX_RESOURCE_TEXT // 1024} KB cap")
    elif not texts and not reasons:
        reasons.append("no text contents returned")
    record["reason"] = "; ".join(dict.fromkeys(reasons))
    if texts:
        record["status"] = "read"
        resource["contents"] = texts


def read_resources(session, resources: list[dict], timeout: float) -> list[dict]:
    """resources/read each listed text resource within the caps. Returns one coverage record per resource."""
    coverage, reads = [], 0
    for resource in resources:
        resource.pop("contents", None)  # only text this scan read counts as read
        record = _record(resource)
        coverage.append(record)
        record["reason"] = _skip_reason(resource, reads)
        if record["reason"]:
            continue
        reads += 1
        try:
            result = session.request("resources/read", {"uri": record["uri"]}, timeout=timeout)
        except (McpError, OSError, ValueError) as exc:
            record["reason"] = f"read failed: {exc}"
            continue
        _keep(record, resource, result.get("contents"))
    return coverage


def saved_resources(resources: list) -> tuple[list[dict], list[dict]]:
    """Resources from saved metadata, with any `contents` held to the same caps as a live read."""
    kept, coverage, reads = [], [], 0
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        resource = dict(resource)
        contents = resource.pop("contents", None)
        record = _record(resource)
        coverage.append(record)
        kept.append(resource)
        record["reason"] = "the saved metadata has no contents" if contents is None else _skip_reason(resource, reads)
        if not record["reason"]:
            reads += 1
            _keep(record, resource, contents)
    return kept, coverage


def introspect(server: dict, *, timeout: float = 60, client_name: str = CLIENT_NAME) -> dict:
    session = None
    try:
        session, init, transport = connect(server, client_name, timeout)
        caps = init.get("capabilities") if isinstance(init.get("capabilities"), dict) else {}
        info = init.get("serverInfo") if isinstance(init.get("serverInfo"), dict) else {}
        tools = _list(session, "tools/list", "tools", timeout)
        prompts = _list(session, "prompts/list", "prompts", timeout) if "prompts" in caps else []
        resources = _list(session, "resources/list", "resources", timeout) if "resources" in caps else []
        coverage = read_resources(session, resources, timeout)
        return {
            "ok": True,
            "source": "live",
            "error": "",
            "transport": transport,
            "client_name": client_name,
            "server_info": {
                "name": str(info.get("name") or ""),
                "version": str(info.get("version") or ""),
                "protocol": str(init.get("protocolVersion") or ""),
            },
            "instructions": str(init.get("instructions") or ""),
            "capabilities": caps,
            "tools": tools,
            "prompts": prompts,
            "resources": resources,
            "coverage": coverage,
        }
    except Exception as exc:  # a broken server is a result, not a crash
        message = str(exc) if isinstance(exc, McpError) else f"{type(exc).__name__}: {exc}"
        stderr = getattr(session, "stderr", None)
        if stderr:
            message += f" ({' '.join(stderr[-1].split())[:200]})"
        return {"ok": False, "source": "live", "error": message, "transport": "", "client_name": client_name,
                "server_info": {}, "instructions": "", "capabilities": {}, "tools": [], "prompts": [], "resources": [],
                "coverage": []}
    finally:
        if session is not None:
            session.close()
