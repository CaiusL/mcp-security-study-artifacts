"""Supply-chain helpers: parse launch lines, spot typosquats, match recorded advisories, query OSV and VirusTotal.

OSV and VirusTotal are network lookups and run only when the caller opts in.
VirusTotal receives file hashes, never file contents.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

NPX_LIKE = {"npx", "bunx", "pnpx"}
DLX_LIKE = {"pnpm", "yarn"}
UVX_LIKE = {"uvx", "pipx", "uv"}

# Well-known MCP packages. Used only as targets for edit-distance comparisons.
KNOWN_PACKAGES = (
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-gdrive",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-redis",
    "@modelcontextprotocol/inspector",
    "mcp-server-fetch",
    "mcp-server-git",
    "mcp-server-time",
    "mcp-server-sqlite",
    "mcp-server-sentry",
    "@playwright/mcp",
    "@upstash/context7-mcp",
    "@notionhq/notion-mcp-server",
    "@stripe/mcp",
    "@supabase/mcp-server-supabase",
    "@sentry/mcp-server",
    "@cloudflare/mcp-server-cloudflare",
    "@browserbasehq/mcp-server-browserbase",
    "@wonderwhy-er/desktop-commander",
    "firecrawl-mcp",
    "exa-mcp-server",
    "tavily-mcp",
    "mcp-remote",
)
KNOWN_SCOPES = sorted({name.split("/")[0] for name in KNOWN_PACKAGES if name.startswith("@")})

# Structured from data/reachable_cases.json (GitHub advisories as recorded there).
# Each range is (lower inclusive or None, upper exclusive).
ADVISORIES = (
    {"package": "@modelcontextprotocol/server-filesystem", "ecosystem": "npm", "ids": ["CVE-2025-53110", "GHSA-hc55-p739-j48w"],
     "ranges": [(None, "0.6.3"), ("2025.1.14", "2025.7.1")], "fixed": "2025.7.1", "summary": "path prefix used as a directory boundary"},
    {"package": "@modelcontextprotocol/server-filesystem", "ecosystem": "npm", "ids": ["CVE-2025-53109", "GHSA-q66q-fx2p-7w4m"],
     "ranges": [(None, "0.6.3"), ("2025.1.14", "2025.7.1")], "fixed": "2025.7.1", "summary": "symlink or '..' resolved after the containment check"},
    {"package": "mcp-server-git", "ecosystem": "PyPI", "ids": ["CVE-2025-68143", "GHSA-5cgr-j3jf-jw3v"],
     "ranges": [(None, "2025.9.25")], "fixed": "2025.9.25", "summary": "git_init accepts a path outside the repository"},
    {"package": "mcp-server-git", "ecosystem": "PyPI", "ids": ["CVE-2025-68144", "GHSA-9xwc-hfwc-8w59"],
     "ranges": [(None, "2025.12.18")], "fixed": "2025.12.18", "summary": "git_diff and git_checkout argument injection"},
    {"package": "mcp-server-git", "ecosystem": "PyPI", "ids": ["CVE-2025-68145", "GHSA-j22h-9j4x-23w5"],
     "ranges": [(None, "2025.12.18")], "fixed": "2025.12.18", "summary": "repo_path not checked against the configured repository"},
    {"package": "mcp-server-git", "ecosystem": "PyPI", "ids": ["CVE-2026-27735", "GHSA-vjqx-cfc4-9h6v"],
     "ranges": [(None, "2026.1.14")], "fixed": "2026.1.14", "summary": "git_add of a path outside the repository"},
)


def version_key(version: str) -> tuple:
    parts = re.findall(r"\d+", version.split("+")[0].split("-")[0])
    return tuple(int(part) for part in parts) if parts else ()


def split_spec(spec: str, ecosystem: str) -> tuple[str, str]:
    """('name', 'version') from npm 'pkg@1.2.3' / '@scope/pkg@1' or PyPI 'pkg==1.2'."""
    spec = spec.strip()
    if ecosystem == "PyPI":
        match = re.match(r"^([A-Za-z0-9_.\[\]-]+?)\s*(==|@)\s*([\w.!+-]+)$", spec)
        if match:
            return re.sub(r"\[.*\]", "", match.group(1)), match.group(3)
        return re.sub(r"\[.*\]", "", re.split(r"[<>=~!;\s]", spec)[0]), ""
    if spec.startswith("@"):
        scope, _, rest = spec.partition("/")
        name, _, version = rest.partition("@")
        return f"{scope}/{name}", version
    name, _, version = spec.partition("@")
    return name, version


def _first_positional(args: list[str], value_flags: set[str]) -> int:
    skip = False
    for index, arg in enumerate(args):
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            if "=" not in arg and arg in value_flags:
                skip = True
            continue
        return index
    return -1


def launch_package(command: str, args: list[str]) -> dict | None:
    """Which package or image a launch line pulls, and whether it is pinned."""
    exe = Path(command).name.lower()
    for suffix in (".cmd", ".exe", ".bat", ".ps1"):
        if exe.endswith(suffix):
            exe = exe[: -len(suffix)]
    args = list(args)
    if exe in DLX_LIKE and args[:1] == ["dlx"]:
        exe, args = "npx", args[1:]
    if exe in NPX_LIKE or (exe == "npm" and args[:1] in (["exec"], ["x"])):
        if exe == "npm":
            args = args[1:]
        for index, arg in enumerate(args):
            if arg.startswith("--package="):
                return _npm(arg.split("=", 1)[1], args)
            if arg in {"-p", "--package"} and index + 1 < len(args):
                return _npm(args[index + 1], args)
        index = _first_positional(args, {"--registry", "--cache", "--userconfig", "-c", "--call"})
        return _npm(args[index], args) if index >= 0 else None
    if exe in UVX_LIKE:
        if exe == "uv":
            if args[:2] != ["tool", "run"]:
                return None
            args = args[2:]
        if exe == "pipx":
            if args[:1] != ["run"]:
                return None
            args = args[1:]
        for index, arg in enumerate(args):
            if arg == "--from" and index + 1 < len(args):
                return _pypi(args[index + 1])
            if arg.startswith("--from="):
                return _pypi(arg.split("=", 1)[1])
        index = _first_positional(args, {"--python", "--with", "--index-url", "--extra-index-url", "-p", "--spec"})
        return _pypi(args[index]) if index >= 0 else None
    if exe in {"docker", "podman"} and "run" in args:
        rest = args[args.index("run") + 1:]
        value_flags = {"-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "--net", "--env-file",
                       "-w", "--workdir", "--mount", "-u", "--user", "--entrypoint", "--label", "-l", "--platform",
                       "--cap-add", "--cap-drop", "--pid", "--ipc", "--add-host", "--memory", "-m", "--cpus", "--hostname", "-h"}
        index = _first_positional(rest, value_flags)
        if index < 0:
            return None
        image = rest[index]
        digest = "@sha256:" in image
        tag = image.split("@")[0].rsplit("/", 1)[-1].partition(":")[2]
        return {"ecosystem": "docker", "name": image.split("@")[0].rsplit(":", 1)[0] if tag else image.split("@")[0],
                "version": tag, "pinned": digest or (bool(tag) and tag != "latest"), "spec": image, "auto_yes": False}
    return None


def _npm(spec: str, args: list[str]) -> dict:
    name, version = split_spec(spec, "npm")
    exact = bool(re.fullmatch(r"\d+\.\d+\.\d+([-+][\w.-]+)?", version or ""))
    return {"ecosystem": "npm", "name": name, "version": version, "pinned": exact, "spec": spec,
            "auto_yes": any(arg in {"-y", "--yes"} for arg in args)}


def _pypi(spec: str) -> dict:
    name, version = split_spec(spec, "PyPI")
    return {"ecosystem": "PyPI", "name": name, "version": version, "pinned": bool(re.fullmatch(r"\d[\w.!+-]*", version)),
            "spec": spec, "auto_yes": False}


def levenshtein(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        if min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]


def typosquat(name: str) -> str:
    """The well-known package this name imitates, or ''."""
    lowered = name.lower()
    if not lowered or lowered in KNOWN_PACKAGES:
        return ""
    if lowered.startswith("@"):
        scope = lowered.split("/")[0]
        for known in KNOWN_SCOPES:
            if scope != known and levenshtein(scope, known, 2) <= 2 and len(known) >= 8:
                return f"scope {known}"
    for known in KNOWN_PACKAGES:
        limit = 2 if len(known) >= 10 else 1
        if levenshtein(lowered, known, limit) <= limit:
            return known
    return ""


def advisories_for(ecosystem: str, name: str, version: str) -> list[dict]:
    key = version_key(version)
    if not key:
        return []
    hits = []
    for advisory in ADVISORIES:
        if advisory["ecosystem"] != ecosystem or advisory["package"] != name.lower():
            continue
        for low, high in advisory["ranges"]:
            if (low is None or key >= version_key(low)) and key < version_key(high):
                hits.append(advisory)
                break
    return hits


# --- manifests -------------------------------------------------------------------


def manifest_packages(path: str, text: str) -> tuple[list[dict], list[str]]:
    """Exact pins (for OSV) and unpinned entries (for CODE008) from one manifest."""
    name = Path(path).name.lower()
    pinned, loose = [], []
    if name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return [], []
        for section in ("dependencies", "optionalDependencies"):
            for package, spec in (data.get(section) or {}).items():
                spec = str(spec)
                if re.fullmatch(r"\d+\.\d+\.\d+([-+][\w.-]+)?", spec):
                    pinned.append({"ecosystem": "npm", "name": package, "version": spec})
                elif not spec.startswith(("file:", "link:", "workspace:")):
                    loose.append(f"{package}@{spec}")
    elif name.startswith("requirements") and name.endswith(".txt"):
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "git+", "http")):
                continue
            match = re.match(r"^([A-Za-z0-9_.\[\]-]+)\s*==\s*([\w.!+-]+)", line)
            if match:
                pinned.append({"ecosystem": "PyPI", "name": re.sub(r"\[.*\]", "", match.group(1)), "version": match.group(2)})
            else:
                loose.append(line)
    return pinned, loose


# --- network lookups (opt-in) -----------------------------------------------------


def osv_query(packages: list[dict], timeout: float = 30) -> dict[tuple, list[str]]:
    """{(ecosystem, name, version): [vuln ids]} from OSV's batch endpoint."""
    unique = []
    for row in packages:
        key = (row["ecosystem"], row["name"], row["version"])
        if row["version"] and row["ecosystem"] in {"npm", "PyPI"} and key not in unique:
            unique.append(key)
    out: dict[tuple, list[str]] = {}
    for start in range(0, len(unique), 500):
        chunk = unique[start:start + 500]
        body = {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk]}
        request = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=timeout) as response:
            results = json.loads(response.read()).get("results") or []
        for key, result in zip(chunk, results):
            ids = [v.get("id") for v in (result or {}).get("vulns") or [] if v.get("id")]
            if ids:
                out[key] = ids
    return out


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def virustotal_lookup(paths: list[str], api_key: str, *, limit: int = 20, per_minute: int = 4) -> list[dict]:
    """Hash lookups against VirusTotal v3. Unknown hashes are skipped; nothing is uploaded."""
    rows = []
    gap = 60.0 / max(per_minute, 1)
    for index, path in enumerate(paths[:limit]):
        if index:
            time.sleep(gap)
        digest = sha256_file(path)
        request = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{digest}", headers={"x-apikey": api_key})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                stats = json.loads(response.read())["data"]["attributes"]["last_analysis_stats"]
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                continue
            raise
        rows.append({"path": path, "sha256": digest, "malicious": int(stats.get("malicious", 0)),
                     "suspicious": int(stats.get("suspicious", 0))})
    return rows
