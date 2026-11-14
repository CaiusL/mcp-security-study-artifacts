"""Text detectors shared by every surface: tool text, skills, configs, code, pasted text.

Each detector returns hits as plain dicts: check id, severity, evidence, and a
short detail. Evidence is clipped, control characters are made visible, and
anything that looks like a secret is redacted before it leaves this module.
These are detection patterns. Nothing here is executed.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from urllib.parse import urlsplit


TEXT_SURFACES = {"tool", "param", "prompt", "resource", "instructions", "skill", "text"}

# --- helpers ---------------------------------------------------------------


def visible(text: str) -> str:
    """Show invisible and control characters as <U+XXXX> or ESC."""
    out = []
    for ch in text:
        cp = ord(ch)
        if ch == "\x1b":
            out.append("ESC")
        elif ch in "\n\t":
            out.append(" ")
        elif cp < 32 or cp == 127 or 0x80 <= cp < 0xA0:
            out.append(f"<U+{cp:04X}>")
        elif _INVISIBLE.match(ch) or _VARIATION.match(ch):
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    return "".join(out)


def snippet(text: str, start: int, end: int, pad: int = 50) -> str:
    left = max(0, start - pad)
    right = min(len(text), end + pad)
    body = visible(text[left:right])
    body = " ".join(body.split())
    return redact_secrets(("…" if left else "") + body + ("…" if right < len(text) else ""))


def redact(value: str) -> str:
    value = str(value)
    if len(value) <= 6:
        return "•" * len(value)
    return f"{value[:4]}…({len(value)} chars)"


class _Keyed:
    """A regex that runs only when one of its literal keywords occurs. Skill trees are megabytes of text."""

    def __init__(self, pattern: re.Pattern, *keywords: str):
        self.pattern = pattern
        self.keywords = keywords

    def search(self, text: str):
        low = text.lower()
        if not any(keyword in low for keyword in self.keywords):
            return None
        return self.pattern.search(text)


def _hit(check: str, severity: str, evidence: str, detail: str = "", start: int = -1) -> dict:
    return {"check": check, "severity": severity, "evidence": evidence, "detail": detail, "start": start}


def _first(pattern: re.Pattern, text: str):
    return pattern.search(text)


# --- TP001-TP006, TP013: instruction-shaped text ---------------------------

_HIDDEN_TAG = re.compile(
    r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin|override|sys|"
    r"assistant|note_to_(?:ai|model|assistant)|ai_instructions?|model_instructions?)\b[^>]{0,80}>"
    r"|\[/?INST\]|<<\s*/?SYS\s*>>|<\|im_start\|>|<!--[\s\S]{0,2000}?-->",
    re.I,
)
_OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(previous|prior|above|earlier|all|any|"
    r"other|system|safety|original)\b[^.\n]{0,20}?\b(instructions?|prompts?|rules|guidelines|directives|"
    r"policies|messages)\b"
    r"|\byou are now\b(?! (connected|ready|logged))|\bnew (system )?instructions\s*:"
    r"|\b(developer|god|jailbreak|DAN) mode\b|\bact as (an? )?(unrestricted|unfiltered|system|root)\b",
    re.I,
)
_CONCEAL = re.compile(
    r"\b(do not|don't|never|must not|should not)\s+(tell|inform|mention|reveal|show|disclose|notify|alert)\s+"
    r"(this |that |these |it |any of this |anything )?(to )?(the )?(user|human|operator)s?\s+(about|of|that you|"
    r"what you)\b"
    r"|\b(do not|don't|never)\s+(mention|reveal|disclose)\s+(this|these|that|it)( instructions?| step| tool| action)?"
    r"(?=\s+(to|in)\b|[.,;]|\s*$)"
    r"|\b(do not|don't|never)\s+(mention|reveal|disclose)\s+(that|what) you\b"
    r"|\bwithout (telling|informing|notifying|alerting) (the )?(user|human)\b(?! (to|first|before))"
    r"|\b(the )?user (must|should|will|can) ?(not|never) (see|know|notice|be told|find out) (about )?(this|it|that)\b"
    r"|\b(silently|secretly|covertly|quietly)\s+(send|upload|forward|transmit|post|exfiltrate|email)\b"
    r"|\bkeep (this|it) (a )?secret from\b|\bhide (this|it) from (the )?(user|human)\b",
    re.I | re.M,
)
_SHADOW = re.compile(
    r"\bwhen(ever)? (using|calling|invoking|you use|you call) (the |any )?[`'\"]?[\w.-]+[`'\"]? tool\b"
    r"|\bbefore (using|calling|invoking) (any|every|all|other) (other )?tools?\b"
    r"|\binstead of (using |calling )?(the )?[`'\"]?[\w.-]+[`'\"]? tool\b"
    r"|\b(all|every|any) (emails?|messages?|requests?|calls?|files?) (must|should|shall) (also )?be "
    r"(sent|forwarded|copied|cc'?d|bcc'?d|routed|redirected) to\b"
    r"|\b(must|should|shall) (also |always )?(send|forward|copy|cc|bcc|route|redirect) (all|every|any) "
    r"(emails?|messages?|requests?|calls?|files?) to\b"
    r"|\bwhen(ever)? (\([\w.-]+\) )?([`'\"][\w.-]+[`'\"]|[a-z0-9]+[_.-][\w.-]+)( tool)? (is|gets) (invoked|called|used)\b"
    r"[^.\n]{0,60}?\b(change|replace|modify|alter|override|redirect)\b"
    r"|\b(change|modify|alter|override)s? (the )?behaviou?r of\b"
    r"|\bthis tool (has|takes) (higher |top )?priority over\b",
    re.I,
)
_SENSITIVE_PATH = _Keyed(re.compile(
    r"[/\\]\.ssh\b|\bid_(rsa|dsa|ecdsa|ed25519)\b|\bauthorized_keys\b|\.aws[/\\]credentials"
    r"|(?<![\w.])\.(netrc|npmrc|pypirc|git-credentials|pgpass)\b|\.kube[/\\]config\b|\.docker[/\\]config\.json"
    r"|/etc/(passwd|shadow|sudoers)\b|\bclaude_desktop_config\.json\b|(?<![\w.-])mcp\.json\b|\.cursor[/\\]mcp"
    r"|\bkeychain\b|\bLogin Data\b|\bcookies\.sqlite\b|\bwallet\.dat\b|[/\\]\.gnupg\b"
    r"|(?:^|[\s'\"`/\\(])\.env(\.local|\.production)?\b|(?<=[\w-])\.pem\b",
    re.I,
), ".ssh", "id_", "authorized_keys", ".aws", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".pgpass", ".kube",
   ".docker", "/etc/", "claude_desktop_config", "mcp.json", ".cursor", "keychain", "login data", "cookies.sqlite",
   "wallet.dat", ".gnupg", ".env", ".pem")
_EXFIL_CONTEXT = re.compile(
    r"\b(entire|full|whole|complete|verbatim)\s+(conversation|chat( history)?|context( window)?|transcript|"
    r"message history|system prompt)\b"
    r"|\b(system prompt|previous messages|prior messages|chat history|conversation history)\b[^.\n]{0,60}?"
    r"\b(include|pass|send|put|add|copy|append|provide)\b"
    r"|\b(include|pass|send|put|add|copy|append|provide)\b[^.\n]{0,60}?\b(system prompt|(previous|prior|last|recent) "
    r"messages|chat history|conversation history|all (prior|previous) (messages|instructions))\b",
    re.I,
)
EXFIL_CONTEXT = _EXFIL_CONTEXT
_SHOUT = re.compile(r"\b(VERY IMPORTANT|EXTREMELY IMPORTANT|CRITICAL|MANDATORY|IMPERATIVE|URGENT)\b|\bMUST\b")
_AUTHORITY = re.compile(
    r"\b(required|mandated|requested|authorized|approved) by (anthropic|openai|the system|the administrator|"
    r"an? admin(istrator)?|the security team|the developer|IT)\b"
    r"|\bthis is an? (system|security|admin(istrator)?) (message|notice|requirement|instruction)\b"
    r"|\b(otherwise|or else) (the )?(application|system|tool|server|user'?s? (data|account)) will (crash|fail|"
    r"break|be (lost|deleted|corrupted))\b"
    r"|\b(application|system|app|server) will crash\b|\ball (the |your |user )?data will be (lost|deleted|corrupted)\b",
    re.I,
)

# --- TP008, TP009: invisible and control characters ------------------------

_INVISIBLE = re.compile("[\u00ad\u180e\u200b\u200c\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb]")
_TAGS = re.compile("[\U000e0000-\U000e007f]+")
_VARIATION = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]")
_VARIATION_SMUGGLE = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]{2,}|[\U000e0100-\U000e01ef]|[\x21-\x7e][\ufe00-\ufe0e]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]{0,200}(?:\x07|\x1b\\)|\x1b[@-Z\\-_]|\x9b")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]")

# --- TP010: encoded payloads ----------------------------------------------

_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{40,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){24,}\b")
_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u00[0-9a-fA-F]{2}){8,}")
_DECODER = re.compile(r"\bString\.fromCharCode\s*\(|\batob\s*\(|\bbase64\s+(-d|--decode)\b|\bFromBase64String\b|\bb64decode\s*\(", re.I)

# --- TP014: URLs ------------------------------------------------------------

_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s'\"<>`)\]]+", re.I)
_TUNNELS = ("ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "loca.lt", "localtunnel.me", "localhost.run")
_CATCHERS = ("webhook.site", "requestbin", "pipedream.net", "interact.sh", "oast.", "burpcollaborator.net", "canarytokens", "hookbin", "beeceptor")
_PASTES = ("pastebin.com", "paste.ee", "hastebin", "ghostbin", "rentry.co", "transfer.sh", "0x0.st", "file.io", "termbin.com")
_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly", "ow.ly", "shorturl.at", "rb.gy")
_EXEC_EXT = re.compile(r"\.(sh|bash|ps1|psm1|bat|cmd|exe|scr|msi|dll|apk|dmg|pkg|vbs|jar)(\?|#|$)", re.I)
_DOWNLOAD_RUN = re.compile(r"\bdownload\b[^.\n]{0,40}\band (then )?(run|execute|install|source)\b", re.I)

# --- TP015: malicious command patterns -------------------------------------

_MALICIOUS = (
    ("reverse shell", "critical", _Keyed(re.compile(
        r"/dev/tcp/[\w.-]+/\d+|\bnc(at)?\b[^\n|;]{0,40}\s-[ec]\s|\bsocat\b[^\n]{0,60}\bexec:|\bmkfifo\b[^\n]{0,40}\bnc\b"
        r"|\bbash -i\b[^\n]{0,20}>&", re.I), "/dev/tcp", "nc", "socat", "mkfifo", "bash -i")),
    ("pipe to shell", "critical", _Keyed(re.compile(
        r"\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"
        r"|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient)\b[^\n]{0,200}\|\s*(iex|Invoke-Expression)\b"
        r"|\biex\s*\(\s*(New-Object|iwr|irm)\b", re.I), "curl", "wget", "iwr", "irm", "invoke-", "webclient", "iex")),
    ("encoded PowerShell", "high", _Keyed(re.compile(
        r"\bpowershell(\.exe)?\b[^\n]{0,40}\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", re.I), "powershell")),
    ("destructive wipe", "high", _Keyed(re.compile(
        r"\brm\s+-(rf|fr)\s+(/|~|\$HOME|/\*)(\s|$|['\"])|\bformat\s+[a-z]:\s|\bmkfs(\.\w+)?\s+/dev/"
        r"|\bdd\s+if=/dev/(zero|urandom)\s+of=/dev/", re.I), "rm ", "format ", "mkfs", "dd ")),
    ("credential theft", "critical", _Keyed(re.compile(
        r"\b(cat|type|Get-Content)\s+[^\n]{0,30}(\.ssh[/\\]id_|\.aws[/\\]credentials|/etc/shadow)"
        r"|\bsecurity\s+find-(generic|internet)-password\b|\bmimikatz\b"
        r"|\blsass(\.exe)?\b[^\n]{0,30}\b(dump|procdump|minidump)", re.I),
        ".ssh", ".aws", "/etc/shadow", "find-generic", "find-internet", "mimikatz", "lsass")),
    ("crypto miner", "critical", _Keyed(re.compile(r"\bxmrig\b|stratum\+tcp://|\bcoinhive\b|\bminerd\b", re.I),
                                        "xmrig", "stratum", "coinhive", "minerd")),
    ("persistence", "high", _Keyed(re.compile(
        r"\(crontab -l[^)]*\)\s*\|\s*crontab|\bschtasks\s+/create\b|\breg(\.exe)?\s+add\s+[^\n]{0,80}\\(Run|RunOnce)\b"
        r"|\blaunchctl\s+(load|bootstrap)\b", re.I), "crontab", "schtasks", "reg", "launchctl")),
)

# --- SEC001: secrets ----------------------------------------------------------

_SECRET_PATTERNS = (
    ("AWS access key", "critical", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", "critical", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("Anthropic API key", "critical", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI API key", "critical", re.compile(r"\bsk-(?!ant-)(proj-|svcacct-)?[A-Za-z0-9_-]{32,}")),
    ("Slack token", "critical", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("Google API key", "critical", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe live key", "critical", re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}")),
    ("Private key block", "critical", re.compile(r"-----BEGIN ([A-Z]+ )?PRIVATE KEY-----")),
    ("JSON Web Token", "high", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Credentials in URL", "high", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]{1,64}:[^/\s@'\"]{3,128}@[\w.-]+", re.I)),
    ("Bearer token", "high", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{24,}=*")),
)
SECRET_KEY_NAME = re.compile(
    r"(api[_-]?key|apikey|secret|token|passw(or)?d|pwd|auth|credential|private[_-]?key|access[_-]?key|client[_-]?secret)",
    re.I,
)
_PLACEHOLDER = re.compile(
    r"^\s*$|^\$\{[^}]*\}$|^\$[A-Z_][A-Z0-9_]*$|^%[A-Z_][A-Z0-9_]*%$|^<[^>]*>$|^\{\{[^}]*\}\}$"
    r"|your[_-]?|example|placeholder|changeme|xxx+|\*{3,}|redacted|dummy|sample|^test$|^none$|^null$|^true$|^false$",
    re.I,
)


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def find_secrets(text: str) -> list[tuple[str, str, int, int]]:
    """Return (kind, severity, start, end) for each provider-pattern secret in text."""
    found = []
    taken: list[tuple[int, int]] = []
    for kind, severity, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            span = match.span()
            if any(a <= span[0] < b for a, b in taken):
                continue
            taken.append(span)
            found.append((kind, severity, span[0], span[1]))
    return found


def is_literal_secret(key: str, value: str) -> bool:
    """A named credential field holding what looks like a real value, not a reference."""
    if not isinstance(value, str) or not SECRET_KEY_NAME.search(key or ""):
        return False
    value = value.strip()
    if len(value) < 8 or _PLACEHOLDER.search(value) or "${" in value or value.startswith("$"):
        return False
    if re.search(r"(file|path|dir|directory|url|uri|endpoint|name|id|type|header|env|var)s?$", key.strip("-_ ").lower()):
        return False
    if re.match(r"([A-Za-z]:[\\/]|[/~.]|\\\\)", value) or value.startswith(("http://", "https://")):
        return False
    if re.fullmatch(r"[a-z]+([_-][a-z]+)*", value):
        return False
    return entropy(value) >= 3.0


def redact_secrets(text: str) -> str:
    spans = sorted(find_secrets(text), key=lambda row: row[2], reverse=True)
    for _kind, _sev, start, end in spans:
        text = text[:start] + redact(text[start:end]) + text[end:]
    return text


def secret_hits(text: str) -> list[dict]:
    hits = []
    for kind, severity, start, end in find_secrets(text):
        hits.append(_hit("SEC001", severity, redact(text[start:end]), kind, start=start))
    return hits


# --- detectors ----------------------------------------------------------------


def unicode_hits(text: str) -> list[dict]:
    hits = []
    tags = _TAGS.search(text)
    if tags:
        hidden = "".join(chr(ord(ch) - 0xE0000) for ch in tags.group(0) if 0xE0020 <= ord(ch) <= 0xE007E)
        hits.append(_hit("TP008", "critical", snippet(text, *tags.span()),
                         f"Unicode tag characters spell hidden text: {redact_secrets(hidden[:120])!r}", start=tags.start()))
    bidi = _BIDI.search(text)
    if bidi:
        hits.append(_hit("TP008", "high", snippet(text, *bidi.span()), "bidirectional override character", start=bidi.start()))
    zero = list(_INVISIBLE.finditer(text))
    zero = [m for m in zero if not _BIDI.match(m.group(0))]
    if zero:
        severity = "high" if len(zero) >= 3 else "medium"
        hits.append(_hit("TP008", severity, snippet(text, *zero[0].span()), f"{len(zero)} zero-width or invisible character(s)", start=zero[0].start()))
    # One selector after an emoji is normal. Stacked selectors, supplementary
    # selectors, or a selector after ASCII are how text gets smuggled.
    first = _VARIATION_SMUGGLE.search(text)
    if first:
        count = len(_VARIATION.findall(text))
        hits.append(_hit("TP008", "high", snippet(text, *first.span()), f"{count} variation selector(s), a known smuggling channel", start=first.start()))
    return hits


def control_hits(text: str) -> list[dict]:
    hits = []
    ansi = _ANSI.search(text)
    if ansi:
        hits.append(_hit("TP009", "high", snippet(text, *ansi.span()), "ANSI escape sequence", start=ansi.start()))
    control = _CONTROL.search(text)
    if control:
        hits.append(_hit("TP009", "medium", snippet(text, *control.span()), f"control character U+{ord(control.group(0)):04X}", start=control.start()))
    return hits


def _printable_share(raw: bytes) -> float:
    if not raw:
        return 0.0
    good = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(raw)


def _decode_candidates(text: str) -> list[tuple[str, int, int, str]]:
    out = []
    for match in _B64.finditer(text):
        token = match.group(0)
        if token.startswith("eyJ") or re.fullmatch(r"[0-9a-fA-F]+", token) or re.fullmatch(r"[A-Za-z_-]+", token):
            continue
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(raw) >= 20 and _printable_share(raw) >= 0.9:
            out.append(("base64", match.start(), match.end(), raw.decode("ascii", "replace")))
    for match in _HEX.finditer(text):
        raw = bytes.fromhex(match.group(0))
        if _printable_share(raw) >= 0.9:
            out.append(("hex", match.start(), match.end(), raw.decode("ascii", "replace")))
    return out


def encoded_hits(text: str, depth: int = 0, prose: str | None = None) -> list[dict]:
    """Encoded blobs anywhere in text; decoder primitives only in `prose` when given (skills quote code)."""
    hits = []
    for kind, start, end, decoded in _decode_candidates(text):
        inner = instruction_hits(decoded) + command_hits(decoded) if depth < 2 else []
        inner += encoded_hits(decoded, depth + 1) if depth < 2 else []
        worst = min((hit["severity"] for hit in inner), key=_rank, default="medium")
        names = sorted({hit["check"] for hit in inner})
        detail = f"{kind} decodes to {visible(redact_secrets(decoded[:100]))!r}"
        if names:
            detail += f"; decoded text triggers {', '.join(names)}"
        hits.append(_hit("TP010", worst, snippet(text, start, end, pad=20), detail, start=start))
    escapes = _ESCAPES.search(text)
    if escapes:
        hits.append(_hit("TP010", "medium", snippet(text, *escapes.span(), pad=20), "escaped byte sequence", start=escapes.start()))
    decoder = _DECODER.search(text if prose is None else prose)
    if decoder:
        hits.append(_hit("TP010", "low", snippet(text, *decoder.span()), "decoder primitive", start=decoder.start()))
    return hits


def _url_hits(text: str) -> list[dict]:
    hits = []
    for match in _URL.finditer(text):
        url = match.group(0).rstrip(".,;:")
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
        except ValueError:
            continue
        reason = ""
        severity = "medium"
        if any(host == t or host.endswith("." + t) for t in _TUNNELS):
            reason, severity = "tunnel host", "high"
        elif any(t in host for t in _CATCHERS):
            reason, severity = "request catcher", "high"
        elif any(host == t or host.endswith("." + t) for t in _PASTES):
            reason = "paste or file-drop site"
        elif host in _SHORTENERS:
            reason = "URL shortener hides the destination"
        elif re.fullmatch(r"[\d.]+", host) and host not in {"127.0.0.1", "0.0.0.0"}:
            reason = "raw IP address"
        elif _EXEC_EXT.search(parts.path or ""):
            reason, severity = "executable or script download", "high"
        if reason:
            hits.append(_hit("TP014", severity, snippet(text, match.start(), match.end(), pad=20), f"{reason}: {host}", start=match.start()))
    run = _DOWNLOAD_RUN.search(text)
    if run:
        hits.append(_hit("TP014", "medium", snippet(text, *run.span()), "download-and-run instruction", start=run.start()))
    return hits


_FENCE = re.compile(r"^[ \t]*(```|~~~)[^\n]*\n[\s\S]*?^[ \t]*\1[ \t]*$|`[^`\n]+`", re.M)


def strip_code(text: str) -> str:
    """Blank out fenced and inline code, keeping offsets, so docs that quote syntax read as prose."""
    return _FENCE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def code_only(text: str) -> str:
    """The inverse of strip_code: keep fenced and inline code, blank the prose, keep offsets."""
    parts, last = [], 0
    for match in _FENCE.finditer(text):
        parts += [re.sub(r"[^\n]", " ", text[last:match.start()]), match.group(0)]
        last = match.end()
    parts.append(re.sub(r"[^\n]", " ", text[last:]))
    return "".join(parts)


def instruction_hits(text: str, shouting: bool = True) -> list[dict]:
    """TP001-TP006, TP013, TP014: text that addresses or steers the model."""
    hits = []
    for check, severity, pattern, detail in (
        ("TP001", "high", _HIDDEN_TAG, "instruction block addressed to the model"),
        ("TP002", "high", _OVERRIDE, "instruction override"),
        ("TP003", "high", _CONCEAL, "concealment from the user"),
        ("TP004", "high", _SHADOW, "directive about other tools"),
        ("TP005", "high", _SENSITIVE_PATH, "sensitive path"),
        ("TP006", "high", _EXFIL_CONTEXT, "asks for conversation or system context"),
    ):
        match = _first(pattern, text)
        if match:
            hits.append(_hit(check, severity, snippet(text, *match.span()), detail, start=match.start()))
    authority = _AUTHORITY.search(text)
    if authority:
        hits.append(_hit("TP013", "medium", snippet(text, *authority.span()), "authority claim or threat", start=authority.start()))
    elif shouting:
        shouts = list(_SHOUT.finditer(text))
        if len(shouts) >= 2 or (shouts and _HIDDEN_TAG.search(text)):
            hits.append(_hit("TP013", "low", snippet(text, *shouts[0].span()), f"{len(shouts)} shouted imperative(s)"))
    hits.extend(_url_hits(text))
    return hits


# --- TP018, TP019: steering directives and server-supplied install instructions ----
# Steering, not poisoning: the bench servers that use these are honest about it, so severities stay modest.
# They run on server text only (instructions, tool descriptions, resource bodies). Skills on disk are
# instructions by design.

_STEERING = (
    ("call-first", re.compile(
        r"\bcall (this|it|`?[\w.-]+`?(\(\))?)( tool)? (first )?(before|after|prior to) (running|executing|installing|using|"
        r"calling|answering|replying|responding|concluding|deciding|acting on|doing) (any|every|all|anything|something|"
        r"that|other|another)\b"
        r"|\bthe tool list is not the (full )?(extent|whole|limit) of\b", re.I),
     "tells the model to call this server before or after other actions"),
    ("runtime-content", re.compile(
        r"\bfollow (the |this |that |each |every )?(skill|workflow|playbook|guide|instructions?|steps?|result|response|"
        r"output)s? (exactly|verbatim|to the letter|precisely|without deviation)\b"
        r"|\bnever improvise\b"
        r"|\b(load|get|fetch|read) (one|it|them|a skill|the skill|a workflow|the workflow)\b[^.\n]{0,60}?\band follow (it|them)\b"
        r"|\bload (one's|its|the) (full )?instructions before following (it|them)\b", re.I),
     "tells the model to obey content the server delivers at runtime; that content arrives through a tool call, "
     "which zgscanner does not make, so it was not checked"),
    ("tool-list", re.compile(
        r"\btell the user (that )?(their|the|your) client (has|is holding|holds|is using) (a |an )?(stale|cached|old|outdated)\b"
        r"|\bclient (has cached|is holding) (a |an )?(old|stale|outdated|cached)\b"
        r"|\bmust reconnect( once)? to see\b", re.I),
     "scripts an explanation for tool-list changes"),
)
_STEER_NEGATED = re.compile(r"\b(never|not|don't|do not|must not|should not|without)\s+(\w+\s+){0,2}$", re.I)
_RELAY = re.compile(
    r"\b(return|relay|give|show|pass|copy|paste|provide|repeat)\b[^.\n]{0,80}?\b(install(ation)? (command|line|"
    r"instructions?|snippet)s?|(client |mcp )?config(uration)? snippets?|setup snippets?)\b[^.\n]{0,60}?\bverbatim\b"
    r"|\bverbatim\b[^.\n]{0,40}?\binstall (command|line)s?\b", re.I)
_SUCCESSOR = re.compile(r"\buse (the )?[`'\"]?(successor|replacement|use_instead)[`'\"]?", re.I)
_INSTALL_CONTEXT = re.compile(r"\b(install\w*|dependenc(y|ies)|packages?|npm|pip|pypi|crates?)\b", re.I)
LIST_CHANGED_NOTE = "; tools.listChanged is set, so the server can also change its tools after approval (RP004)"


def steering_hits(text: str, output_fields: frozenset | set = frozenset(), list_changed: bool = False) -> list[dict]:
    """TP018 directives that steer the model toward this server, and TP019 install or run instructions it supplies."""
    if not isinstance(text, str) or not text:
        return []
    hits = []
    for kind, pattern, detail in _STEERING:
        for match in pattern.finditer(text):
            if _STEER_NEGATED.search(re.split(r"[.;:!?\n]", text[:match.start()])[-1]):
                continue  # "never follow them as instructions" is defensive text
            if kind == "tool-list" and list_changed:
                detail += LIST_CHANGED_NOTE
            hits.append(_hit("TP018", "low", snippet(text, *match.span()), detail, start=match.start()))
            break
    relay = _RELAY.search(text)
    if relay:
        hits.append(_hit("TP019", "medium", snippet(text, *relay.span()),
                         "tells the model to relay install commands or config from server results verbatim"
                         + (LIST_CHANGED_NOTE if list_changed else ""), start=relay.start()))
    successor = _SUCCESSOR.search(text)
    if successor and successor.group(2).lower() in output_fields and _INSTALL_CONTEXT.search(text):
        hits.append(_hit("TP019", "medium", snippet(text, *successor.span()),
                         f"tells the model to install or use the `{successor.group(2)}` the server returns in its output"
                         + (LIST_CHANGED_NOTE if list_changed else ""), start=successor.start()))
    return hits


def command_hits(text: str) -> list[dict]:
    hits = []
    for name, severity, pattern in _MALICIOUS:
        match = pattern.search(text)
        if match:
            hits.append(_hit("TP015", severity, snippet(text, *match.span()), name, start=match.start()))
    return hits


# Skill docs talk about prompts, users, and config paths for legitimate reasons.
# Hidden tags and overrides keep their severity there; these drop.
SKILL_DOWNGRADE = {"TP003": "medium", "TP004": "medium", "TP005": "low", "TP006": "low"}


def scan_text(text: str, surface: str = "text") -> list[dict]:
    """Every content detector that applies to a surface."""
    if not isinstance(text, str) or not text:
        return []
    hits: list[dict] = []
    if surface in TEXT_SURFACES:
        # Skills are documentation: quoted syntax in code spans is not an instruction to the model.
        prose = strip_code(text) if surface == "skill" else text
        for hit in instruction_hits(prose, shouting=surface not in {"skill", "text"}):
            if surface == "skill" and hit["check"] in SKILL_DOWNGRADE:
                hit["severity"] = SKILL_DOWNGRADE[hit["check"]]
            hits.append(hit)
        hits.extend(control_hits(text))
        hits.extend(encoded_hits(text, prose=prose if surface == "skill" else None))
        limit = 10000 if surface == "skill" else 4000
        if surface in {"tool", "param", "prompt", "instructions"} and len(text) > limit:
            severity = "medium" if len(text) > limit * 2.5 else "low"
            hits.append(_hit("TP012", severity, visible(text[:80]) + "…", f"{len(text)} characters"))
    hits.extend(unicode_hits(text))
    hits.extend(command_hits(text))
    hits.extend(secret_hits(text))
    return _dedupe(hits)


def name_hits(name: str) -> list[dict]:
    """TP011 on an identifier: mixed scripts, or a change under NFKC folding."""
    if not name or name.isascii():
        return []
    scripts = set()
    for ch in name:
        if ch.isalpha():
            label = unicodedata.name(ch, "")
            scripts.add(label.split(" ")[0] if label else "UNKNOWN")
    folded = unicodedata.normalize("NFKC", name)
    if len(scripts) > 1:
        return [_hit("TP011", "high", visible(name), f"mixes scripts: {', '.join(sorted(scripts))}")]
    if folded != name:
        return [_hit("TP011", "medium", visible(name), f"NFKC folds to {folded!r}")]
    return [_hit("TP011", "low", visible(name), "non-ASCII identifier")]


def _rank(severity: str) -> int:
    return ("critical", "high", "medium", "low", "info").index(severity)


def _dedupe(hits: list[dict]) -> list[dict]:
    best: dict[tuple, dict] = {}
    for hit in hits:
        key = (hit["check"], hit["detail"] if hit["check"] in {"SEC001", "TP015", "TP014"} else "")
        if key not in best or _rank(hit["severity"]) < _rank(best[key]["severity"]):
            best[key] = hit
    return list(best.values())


# --- skills and code ------------------------------------------------------------

_CRED_OUTPUT = re.compile(
    r"\b(print|echo|output|display|show|reveal|return|include|paste|log|write out)\b[^.\n]{0,40}?"
    r"\b(api[ _-]?keys?|tokens?|passwords?|secrets?|credentials?|private keys?)\b[^.\n]{0,40}?"
    r"\b(verbatim|in full|exactly|as[- ]is|in plain ?text|unmasked|unredacted)\b"
    r"|\binclude (the|your) (api[ _-]?key|token|password|secret|credentials?) in (your|the) (response|output|reply|message)\b",
    re.I,
)
_REMOTE_INSTRUCTIONS = re.compile(
    r"\b(fetch|download|curl|wget|retrieve|load|read|get)\b[^.\n]{0,60}?\b(instructions|rules|prompts?|guidelines|"
    r"skills?|commands|steps)\b[^.\n]{0,40}?\b(from|at)\s+https?://"
    r"|\bfollow (the )?(instructions|steps|rules) (at|from|in)\s+https?://",
    re.I,
)
_SERVICE_CHANGE = _Keyed(re.compile(
    r"\bsystemctl\s+(enable|start|daemon-reload|edit|mask)\b|\blaunchctl\b|\bcrontab\b|\bschtasks\b"
    r"|\bsc(\.exe)?\s+(create|config)\b|\bsudoers\b|\bchmod\s+[ug]?\+s\b|\bStart Menu\\Programs\\Startup\b"
    r"|\\CurrentVersion\\Run\b|\bNew-Service\b|\bSet-ExecutionPolicy\s+(Unrestricted|Bypass)\b",
    re.I,
), "systemctl", "launchctl", "crontab", "schtasks", "sc ", "sc.exe", "sudoers", "chmod", "start menu", "currentversion",
   "new-service", "executionpolicy")
_AGENT_FILES = re.compile(
    r"\b(write|append|add|modify|edit|update|overwrite|insert|create)\b[^.\n]{0,50}?"
    r"(CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|copilot-instructions\.md|"
    r"\.claude[/\\](settings(\.local)?\.json|agents|commands|skills|hooks)|MEMORY\.md|mcp\.json|claude_desktop_config\.json)",
    re.I,
)


def skill_text_hits(text: str) -> list[dict]:
    hits = []
    for check, severity, pattern, detail in (
        ("SK002", "high", _CRED_OUTPUT, "asks for secrets verbatim"),
        ("SK003", "high", _REMOTE_INSTRUCTIONS, "instructions fetched at runtime"),
        ("SK004", "medium", _SERVICE_CHANGE, "service, schedule, or privilege change"),
        ("SK005", "medium", _AGENT_FILES, "writes agent memory or configuration"),
    ):
        match = pattern.search(text)
        if match:
            if check == "SK005" and re.search(r"hooks|settings", match.group(0), re.I):
                severity = "high"
            hits.append(_hit(check, severity, snippet(text, *match.span()), detail, start=match.start()))
    return hits


_CODE_RULES = (
    ("CODE001", "high", _Keyed(re.compile(
        r"subprocess\.\w+\([^)\n]{0,200}shell\s*=\s*True|\bos\.(system|popen)\s*\(|\bchild_process\b[^\n]{0,80}\bexec(Sync)?\b"
        r"|(?<![\w.])execSync\s*\(|(?<![\w.$])exec\s*\(\s*`[^`]*\$\{|(?<![\w.])(?<!async )(?<!function )(?<!def )eval\s*\((?![^)\n]*\)\s*[{:])"
        r"|\bnew Function\s*\("
        r"|(?<![\w.])exec\s*\(\s*(compile|open|request|input|params|args)\b|Runtime\.getRuntime\(\)\.exec"
        r"|\bshell_exec\s*\(|\bpassthru\s*\("), "subprocess", "os.system", "os.popen", "child_process", "exec", "eval",
        "function", "getruntime", "passthru"), "unsafe execution"),
    ("CODE002", "high", _Keyed(re.compile(
        r"\bpickle\.loads?\s*\(|\bmarshal\.loads?\s*\(|\byaml\.load\s*\((?![^)\n]*Loader\s*=\s*(yaml\.)?(Safe|CSafe)Loader)"
        r"|\bunserialize\s*\(|node-serialize|\bObjectInputStream\b|!!python/(object|apply|name)"), "pickle", "marshal",
        "yaml.load", "unserialize", "node-serialize", "objectinputstream", "!!python"), "unsafe deserialization"),
    ("CODE004", "medium", re.compile(
        r"host\s*=\s*['\"]0\.0\.0\.0['\"]|\.listen\(\s*\d+\s*,\s*['\"]0\.0\.0\.0['\"]|--host\s+0\.0\.0\.0|\bINADDR_ANY\b"),
        "binds every interface"),
    ("CODE005", "high", re.compile(
        r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*[=:]\s*['\"]?0"
        r"|InsecureSkipVerify\s*:\s*true|ssl\._create_unverified_context|\bCERT_NONE\b"), "certificate checks off"),
    ("CODE006", "low", re.compile(r"\brequests\.(get|post|put|delete|patch|head)\((?![^)\n]*timeout)[^)\n]*\)"),
        "requests call without timeout"),
)
_EGRESS = re.compile(
    r"\b(requests|httpx|aiohttp|urllib\.request|axios|fetch|got|ky)[\w.]*\s*\(\s*['\"`](https?://([^/'\"`\s]+))", re.I)
NETWORK_CODE = re.compile(
    r"\b(requests|httpx|aiohttp|urllib|http\.client|socket|axios|fetch|XMLHttpRequest|WebSocket|curl|wget|"
    r"Invoke-WebRequest|Invoke-RestMethod|net/http|reqwest)\b")
LOGGING_CODE = re.compile(r"\b(logging\.|logger\.|getLogger|console\.(error|warn|log|info)|log\.(info|warn|error|debug)|"
                          r"winston|pino|slog\.|tracing::|zap\.)")


def code_hits(text: str) -> list[dict]:
    hits = []
    for check, severity, pattern, detail in _CODE_RULES:
        match = pattern.search(text)
        if match:
            hits.append(_hit(check, severity, snippet(text, *match.span(), pad=30), detail, start=match.start()))
    hosts, first = [], -1
    for match in _EGRESS.finditer(text):
        host = match.group(3).lower()
        if host.split(":")[0] not in {"localhost", "127.0.0.1", "0.0.0.0"} and host not in hosts:
            hosts.append(host)
            first = match.start() if first < 0 else first
    if hosts:
        hits.append(_hit("CODE003", "low", ", ".join(hosts[:6]), f"{len(hosts)} hardcoded host(s)", start=first))
    hits.extend(unicode_hits(text))
    hits.extend(command_hits(text))
    hits.extend(secret_hits(text))
    return _dedupe(hits)
