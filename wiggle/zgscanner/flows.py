"""Capability labels for tools and servers, and the toxic-flow pass that combines them.

Labels: untrusted (brings third-party content in), private (reads non-public
data), sink (can send data out), destructive, write, exec, financial. They are
heuristics over names, descriptions, annotations, and argument families.
"""

from __future__ import annotations

import re

from wiggle.scan_classify import FAMILY_ORDER, classify_argument, classify_tool

_SPLIT = re.compile(r"[^a-z0-9]+")
_URI_FORMATS = {"uri", "url", "iri", "uri-reference", "iri-reference"}
_URL_WORDS = re.compile(r"\b(https?|urls?|uris?)\b", re.I)
# "URL identifier of the robot sheet" names a slug, not a URL to fetch.
_TAKES_URL = re.compile(r"\bhttps?\b|\b(wss?|ftp)://|\b(url|uri)s?\b(?!\s*(identifier|slug|segment|path|fragment|component)s?\b)", re.I)
_SLUG = re.compile(r"\burl identifier\b|\bslug\b", re.I)

_UNTRUSTED_NAME = {"fetch", "browse", "browser", "scrape", "crawl", "web", "url", "navigate", "rss", "feed", "email",
                   "emails", "mail", "inbox", "issue", "issues", "comment", "comments", "ticket", "tickets", "message",
                   "messages", "post", "posts", "tweet", "tweets", "page", "html", "website", "slack",
                   "discord", "reddit", "news", "screenshot", "snapshot"}
_UNTRUSTED_DESC = re.compile(r"\b(web ?pages?|websites?|the internet|html|scrap\w+|crawl\w*|emails?|inbox|github issues?|"
                             r"pull requests?|comments?|third[- ]party|user[- ]generated|public content|untrusted|"
                             r"search (the )?web|web search|rss)\b", re.I)
_READ_VERBS = {"read", "get", "list", "search", "query", "open", "view", "export", "download", "fetch", "cat", "find",
               "show", "describe", "retrieve", "lookup", "load", "head", "tail", "grep", "tree", "log", "diff", "status"}
_PRIVATE_NOUNS = {"file", "files", "directory", "dir", "folder", "email", "emails", "mail", "inbox", "message", "messages",
                  "calendar", "contact", "contacts", "document", "documents", "doc", "docs", "drive",
                  "note", "notes", "database", "db", "sql", "table", "tables", "record", "records", "customer",
                  "customers", "user", "users", "account", "accounts", "password", "passwords", "secret", "secrets",
                  "credential", "credentials", "token", "tokens", "key", "keys", "vault", "keychain", "payment",
                  "payments", "invoice", "invoices", "transaction", "transactions", "bank", "medical", "health", "repo",
                  "repository", "commit", "commits", "diff", "branch", "memory", "graph", "entity", "entities", "nodes",
                  "text", "content", "log", "logs", "history", "issue", "issues"}
# Events are private on a calendar and public on a listings site.
_CALENDAR = re.compile(r"\b(calendars?|meetings?|attendees?)\b", re.I)
# A sensitive noun counts only as the object of a read: "Costs $9 (payment in _meta)" is billing, not data access.
_SENSITIVE = re.compile(r"\b(reads?|list(s|ing)?|gets?|fetch(es)?|retriev(e|es)|access(es)?|exports?|search(es)?|"
                        r"quer(y|ies)|returns?|shows?|views?|opens?)\b[^.]{0,40}?\b(emails?|inbox|passwords?|secrets?|"
                        r"credentials?|tokens?|api keys?|payment (history|records|data|methods|details)|bank (accounts?|"
                        r"statements?|details)|medical|health records?|customers?|personal (data|information|details)|"
                        r"private (data|files|messages|notes)|ssn|salary|payroll)\b", re.I)
# A price, or payment "via x402". A bare "x402" can be something the tool checks on other sites.
_PAID_DESC = re.compile(r"\bcosts?\s+\$\s?\d[\d.,]*|\$\s?\d[\d.,]*\s*(USDC?|EUR)?\s*(per|a|each)\s+(call|request|use|run|query)\b"
                        r"|\b(charged|billed)\s+(per|for each)\s+(call|request|use)\b|\b(paid|pay|payment)\s+(via|over|with)\s+x402\b"
                        r"|\bvia x402\b", re.I)
_SINK_NAME = {"send", "post", "publish", "tweet", "upload", "share", "email", "mail", "notify", "reply", "comment",
              "webhook", "push", "submit", "forward", "invite", "broadcast", "sms", "message", "chat", "create_issue",
              "request", "http", "curl", "put"}
_SINK_DESC = re.compile(r"\b(send|post|publish|upload|share|forward|email|tweet|notify|reply)(s|es|ed|ing)?\b[^.]{0,40}\b"
                        r"(to|on|via|with)\b|\bhttp (post|request)\b|\bwebhook\b", re.I)
_DESTRUCTIVE_NAME = {"delete", "remove", "rm", "drop", "truncate", "destroy", "purge", "wipe", "kill", "terminate",
                     "erase", "reset", "revoke", "uninstall", "overwrite", "force", "rmdir", "unlink", "prune"}
_DESTRUCTIVE_DESC = re.compile(r"\b(permanently|irreversibl[ey]|cannot be undone|delete[sd]?|drops? (the |a )?(table|database)|"
                               r"overwrite[sd]?|truncate[sd]?|force[- ]push)\b", re.I)
_WRITE_NAME = {"write", "update", "edit", "move", "rename", "create", "insert", "append", "set", "patch", "modify",
               "commit", "add", "save", "mkdir", "copy", "replace", "upsert", "merge", "checkout", "reset"}
_ARITHMETIC = re.compile(r"\b(add|sum)s?\b[^.\n]{0,20}\b(numbers?|integers?|floats?)\b", re.I)
_EXEC_NAME = {"exec", "execute", "shell", "bash", "powershell", "terminal", "eval", "cmd", "sh", "zsh", "subprocess",
              "repl", "interpreter"}
_EXEC_DESC = re.compile(r"\b(execute|run)s? (an? |any |arbitrary )?(shell |terminal |system |bash |powershell |python |"
                        r"javascript )?(commands?|code|scripts?)\b|\bshell command\b|\barbitrary code\b", re.I)
_FIN_NAME = {"pay", "payment", "payments", "transfer", "refund", "payout", "charge", "purchase", "buy", "sell", "trade",
             "withdraw", "deposit", "swap", "checkout"}
_FIN_DESC = re.compile(r"\b(transfer (funds|money)|send (money|payment|funds|crypto)|place (an? )?(order|trade)|"
                       r"execute (a )?(trade|payment|transaction)|charge (the |a )?(card|customer)|move money)\b", re.I)

# Server-name hints for servers with no tools/list (wiggle's registry hint idea, by family).
NAME_PROFILES = (
    (("filesystem", "file-system", "files"), {"private", "write"}),
    (("fetch", "http-client"), {"untrusted", "sink"}),
    (("github", "gitlab", "gitea", "bitbucket"), {"untrusted", "private", "sink", "write"}),
    (("git",), {"private", "write"}),
    (("slack", "discord", "teams", "telegram", "whatsapp"), {"untrusted", "private", "sink"}),
    (("gmail", "email", "mail", "outlook", "imap"), {"untrusted", "private", "sink"}),
    (("postgres", "postgresql", "sqlite", "mysql", "mongo", "redis", "supabase", "database", "bigquery", "snowflake"),
     {"private", "destructive", "write"}),
    (("puppeteer", "playwright", "browser", "chrome", "browserbase", "selenium"), {"untrusted", "sink"}),
    (("brave", "search", "tavily", "exa", "firecrawl", "serp", "perplexity"), {"untrusted"}),
    (("memory", "knowledge", "graph"), {"private", "write"}),
    (("notion", "confluence", "jira", "linear", "asana", "trello", "atlassian", "hubspot", "salesforce"),
     {"untrusted", "private", "sink", "write"}),
    (("gdrive", "google-drive", "dropbox", "onedrive"), {"private", "sink"}),
    (("shell", "terminal", "desktop-commander", "commander", "exec", "command", "ssh"), {"exec", "destructive", "private", "sink"}),
    (("stripe", "paypal", "wallet", "coinbase", "plaid"), {"financial", "private"}),
    (("aws", "gcp", "azure", "kubernetes", "k8s", "docker", "terraform", "cloudflare"), {"private", "destructive", "write"}),
    (("sentry", "datadog", "grafana"), {"untrusted", "private"}),
)


def tokens(name: str) -> set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")
    return {part for part in _SPLIT.split(spaced.lower()) if part}


def classify(tool: dict) -> dict:
    """wiggle.scan_classify.classify_tool, with the URL label kept only for arguments that take a URL.

    The study classifier labels any argument whose description says "URL", so a slug described as a
    "URL identifier" became a URL argument. Here an argument is a URL when its name says so (url, uri,
    *_url), its schema says format: uri, or its description describes taking a URL. SC002 and the flow
    labels both read this, so they agree.
    """
    result = classify_tool(tool)
    schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    for arg in result["arguments"]:
        prop = props.get(arg["name"]) if isinstance(props.get(arg["name"]), dict) else {}
        desc = str(prop.get("description") or "")
        key = arg["name"].lower().replace("-", "_")
        if str(prop.get("format") or "").lower() in _URI_FORMATS:
            if arg["feature"] not in FAMILY_ORDER:
                arg["feature"] = "url"
        elif arg["feature"] == "url" and not (key in {"url", "uri", "href", "endpoint", "link"} or key.endswith(("_url", "_uri"))):
            if (key in {"slug", "id"} and _SLUG.search(desc)) or not _TAKES_URL.search(desc):
                relabel = classify_argument(arg["name"], {**prop, "description": _URL_WORDS.sub(" ", desc)})
                arg["feature"] = relabel["feature"]
    result["families"] = list(dict.fromkeys(a["feature"] for a in result["arguments"] if a["feature"] in FAMILY_ORDER))
    result["free_string_resources"] = [
        f"{result['name']}.{a['name']}" for a in result["arguments"]
        if a["feature"] in FAMILY_ORDER and (a["type"].startswith("string") or a["type"] == "array:string") and not a["constrained"]]
    return result


_CHECK_VERB = re.compile(r"\b(check(s|ed|ing)?|inspect(s|ed|ing)?|validat\w+|verif\w+|analy[sz]\w+|lint\w*|scan(s|ned)?|look(s|ed)? up)\b", re.I)
# The tool itself executing, as a description states it in the third person or as an imperative.
_RUNS_IT = re.compile(r"\b(executes|executing|evaluates|spawns|runs (it|them|the|this|that|your|a|an|any))\b", re.I)


def remote_check_only(tool: dict, remote: bool) -> bool:
    """A remote, read-only tool that checks a command string it receives. It cannot execute anything here."""
    if not remote:
        return False
    annotations = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
    name = str(tool.get("name") or "")
    desc = str(tool.get("description") or "")
    return (annotations.get("readOnlyHint") is True and not tokens(name) & _EXEC_NAME
            and bool(_CHECK_VERB.search(f"{' '.join(tokens(name))} {desc}"))
            and not _EXEC_DESC.search(desc) and not _RUNS_IT.search(desc))


def tool_capabilities(tool: dict, remote: bool = False) -> set[str]:
    name = str(tool.get("name") or "")
    desc = str(tool.get("description") or "")
    words = tokens(name)
    annotations = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
    families = set(classify(tool)["families"])
    caps: set[str] = set()
    read_only = annotations.get("readOnlyHint") is True
    reads = bool(words & _READ_VERBS) or read_only
    if words & _UNTRUSTED_NAME and (reads or "url" in families) or "url" in families and reads or annotations.get("openWorldHint") is True:
        caps.add("untrusted")
    elif reads and _UNTRUSTED_DESC.search(desc):
        caps.add("untrusted")
    events = words & {"event", "events"} and _CALENDAR.search(desc)
    if reads and (words & _PRIVATE_NOUNS or events or families & {"path", "sql", "git", "entity"} or _SENSITIVE.search(desc)):
        caps.add("private")
    if not read_only and (words & _SINK_NAME and not words & _READ_VERBS or _SINK_DESC.search(desc)):
        caps.add("sink")
    if "url" in families:  # a free URL argument can carry data out in a query string
        caps.add("sink")
    if annotations.get("destructiveHint") is True or words & _DESTRUCTIVE_NAME or (not read_only and _DESTRUCTIVE_DESC.search(desc)):
        caps.add("destructive")
    elif not read_only and words & _WRITE_NAME and not (words & _WRITE_NAME == {"add"} and _ARITHMETIC.search(desc)):
        caps.add("write")
    if words & _EXEC_NAME or "command" in families or _EXEC_DESC.search(desc):
        if not remote_check_only(tool, remote):  # the command text still leaves the machine, so it stays a sink
            caps.add("exec")
        caps.add("sink")
    if words & _FIN_NAME or _FIN_DESC.search(desc):
        caps.add("financial")
    if _PAID_DESC.search(desc) and not re.match(r"\s*free\b", desc, re.I):
        caps.add("paid")
    return caps


def price_text(tool: dict) -> str:
    match = _PAID_DESC.search(str(tool.get("description") or ""))
    return match.group(0) if match else ""


def sensitive_private(tool: dict) -> bool:
    return bool(_SENSITIVE.search(f"{tool.get('name') or ''} {tool.get('description') or ''}"))


def name_capabilities(*texts: str) -> set[str]:
    words = set()
    for text in texts:
        words |= tokens(text)
        words |= {piece for piece in re.split(r"[^a-z0-9-]+", (text or "").lower()) if piece}
    caps: set[str] = set()
    for keys, labels in NAME_PROFILES:
        if any(key in words for key in keys):
            caps |= labels
    return caps


def toxic_flows(groups: dict[str, list[dict]]) -> list[dict]:
    """Per agent group: members holding each leg, and whether one server holds all three."""
    flows = []
    for agent, members in groups.items():
        legs = {"untrusted": [], "private": [], "sink": []}
        single = []
        for member in members:
            caps = member["caps"]
            for leg in legs:
                if leg in caps:
                    legs[leg].extend(member["by_cap"].get(leg) or [member["label"]])
            if all(leg in caps for leg in legs):
                single.append(member["label"])
        if all(legs.values()):
            flows.append({
                "agent": agent,
                "untrusted": sorted(set(legs["untrusted"]))[:12],
                "private": sorted(set(legs["private"]))[:12],
                "sink": sorted(set(legs["sink"]))[:12],
                "single_server": single,
                "inferred": all(member["inferred"] for member in members if member["caps"]),
                "severity": "critical" if single and not all(m["inferred"] for m in members if m["label"] in single) else "high",
            })
    return flows
