"""Check catalog, scanner coverage map, and OWASP MCP Top 10 labels.

Every check names the public scanners whose feature it reproduces. The
coverage map lists each scanner's documented features and the checks that
stand in for them. A feature with no check is reported as a gap, not hidden.
Feature lists were read from each project's README on 2026-10-20. That
read did not record a commit, so a check is not pinned to a line of an
upstream tree. On 2026-10-25 the three moved source URLs were resolved
through the GitHub API. The `cited` field is that resolution. It is not a
claim that the check text was copied from the named commit.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}

OWASP = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Prompt Injection via Contextual Payloads",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}

CATEGORIES = {
    "poisoning": "Tool poisoning & prompt injection",
    "flow": "Capabilities & toxic flows",
    "schema": "Schema & input validation",
    "secrets": "Secrets",
    "config": "Configuration & supply chain",
    "drift": "Rug pull & drift",
    "protocol": "Live protocol",
    "skills": "Agent skills",
    "code": "Source code",
    "llm": "LLM judge",
}

# What a check needs before it can run. "static" always runs.
REQUIREMENTS = {
    "static": "Always runs on whatever inventory the scan found.",
    "live": "Needs tools/list from at least one connected server or a tools JSON file.",
    "baseline": "Needs a pins file from an earlier --pin run.",
    "identify": "Needs --identify-as and at least one connected server.",
    "source": "Needs --source DIR or a skill with script files.",
    "osv": "Needs --osv (queries api.osv.dev with package names and versions).",
    "virustotal": "Needs --virustotal and VT_API_KEY (hash lookups only).",
    "llm": "Needs --llm, the anthropic package, and Anthropic credentials.",
    "allowlist": "Needs --allowlist FILE.",
    "skills": "Needs at least one discovered or named skill, or a skill a connected server serves as a resource.",
}

SCANNERS = {
    "snyk": {
        "name": "Snyk Agent Scan",
        "aka": "formerly Invariant Labs mcp-scan",
        "url": "https://github.com/snyk/agent-scan",
    },
    "cisco": {
        "name": "Cisco AI Defense MCP Scanner",
        "aka": "mcp-scanner",
        "url": "https://github.com/cisco-ai-defense/mcp-scanner",
    },
    "shield": {"name": "MCP-Shield", "aka": "riseandignite", "url": "https://github.com/riseandignite/mcp-shield"},
    "ramparts": {
        "name": "Ramparts",
        "aka": "Javelin, now Highflame",
        "url": "https://github.com/highflame-ai/ramparts",
        "cited": (
            "2026-10-25 GitHub API: getjavelin/ramparts redirects to highflame-ai/ramparts. "
            "Latest tag v0.8.10 is commit 70457dbf2b64c92bb4601951bc74d36d6dbf7551. "
            "main at that lookup was 14ff71ef40bc6ff28ce57ded77466e138a562267 (2026-10-08)."
        ),
    },
    "proximity": {
        "name": "Proximity",
        "aka": "fr0gger, now Nova-Hunting",
        "url": "https://github.com/Nova-Hunting/nova-proximity",
        "cited": (
            "2026-10-25 GitHub API: fr0gger/proximity redirects to Nova-Hunting/nova-proximity. "
            "No tags. main was d7521742dd8d25efee9b75f9fff2e7c8e8774cdb (2026-03-26)."
        ),
    },
    "tob": {
        "name": "mcp-context-protector",
        "aka": "Trail of Bits",
        "url": "https://github.com/trailofbits/mcp-context-protector",
    },
    "watch": {"name": "MCP Watch", "aka": "kapilduraphe", "url": "https://github.com/kapilduraphe/mcp-watch"},
    "safety": {
        "name": "MCPSafetyScanner",
        "aka": "Halloran et al.",
        "url": "https://github.com/johnhalloran321/mcpSafetyScanner",
    },
    "radar": {"name": "Agentic Radar", "aka": "SplxAI", "url": "https://github.com/splx-ai/agentic-radar"},
    "mcpguard": {"name": "mcpguard", "aka": "OWASP MCP Top 10 config scanner", "url": "https://github.com/loplop-h/mcpguard"},
    "avow": {
        "name": "mcp-security-scan",
        "aka": "AgentAvow",
        "url": "https://github.com/AgentAvow/mcp-security-scan",
        "cited": (
            "2026-10-25 GitHub API: AgentAvow/mcp-security-scan is archived. "
            "Tag v1.1.0 is commit 5fe94a4d55082cfc03d642da1fe2c413b140ce5a. "
            "main at that lookup was 8af282487da7849e38ef51db4098e4c8dd2e7e43 (2026-08-13)."
        ),
    },
    "wiggle": {"name": "wiggle declared scan", "aka": "this repository", "url": "README.md"},
}


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    category: str
    severity: str
    owasp: tuple[str, ...]
    sources: tuple[str, ...]
    requires: str
    description: str
    remediation: str

    def as_dict(self) -> dict:
        row = asdict(self)
        row["owasp"] = list(self.owasp)
        row["sources"] = list(self.sources)
        return row


def _c(id, title, category, severity, owasp, sources, requires, description, remediation) -> Check:
    return Check(id, title, category, severity, tuple(owasp), tuple(sources), requires, description, remediation)


CHECKS: tuple[Check, ...] = (
    # Tool poisoning and prompt injection. These run on tool and parameter
    # descriptions, prompts, resources, server instructions, skills, and pasted text.
    _c("TP001", "Hidden instruction block", "poisoning", "high", ["MCP03", "MCP06"],
       ["snyk", "shield", "cisco", "watch", "ramparts"], "static",
       "Tags such as <IMPORTANT>, <system>, [INST] or HTML comments that address the model rather than the user.",
       "Remove the block. Tool text should describe the tool to a person, not instruct the model."),
    _c("TP002", "Instruction override or jailbreak phrase", "poisoning", "high", ["MCP06", "MCP03"],
       ["snyk", "cisco", "proximity", "watch", "ramparts"], "static",
       "Phrases that tell the model to ignore earlier instructions, adopt a new role, or switch modes.",
       "Treat the server as compromised until the text is explained. Do not connect it to an agent."),
    _c("TP003", "Concealment from the user", "poisoning", "high", ["MCP03"],
       ["shield", "snyk", "cisco"], "static",
       "Text asking the model not to tell the user, or to act silently.",
       "Legitimate tools never need to hide actions from the user. Remove the server."),
    _c("TP004", "Cross-tool directive or shadowing", "poisoning", "high", ["MCP03", "MCP09"],
       ["snyk", "shield", "ramparts", "tob"], "static",
       "One tool's text changes how other tools behave, or names a tool that another server provides.",
       "Isolate the server. A description should only describe its own tool."),
    _c("TP005", "Sensitive file or credential path", "poisoning", "high", ["MCP01", "MCP10"],
       ["shield", "safety", "ramparts"], "static",
       "References to SSH keys, cloud credentials, .env files, client MCP configs, or browser stores.",
       "Check why the tool mentions the path. Restrict the server's filesystem scope."),
    _c("TP006", "Conversation or context exfiltration", "poisoning", "high", ["MCP10", "MCP06"],
       ["watch", "shield", "snyk"], "static",
       "Requests to pass the full conversation, system prompt, or earlier messages into a tool.",
       "Remove the server. No tool needs the system prompt or chat history as an argument."),
    _c("TP007", "Exfiltration-shaped parameter", "poisoning", "medium", ["MCP10"],
       ["shield", "watch"], "live",
       "A free-text parameter named like a side channel (feedback, debug, metadata, context, history).",
       "Confirm what the server does with the parameter. Drop it from the allowed schema if unused."),
    _c("TP008", "Hidden Unicode characters", "poisoning", "high", ["MCP03"],
       ["snyk", "ramparts", "cisco"], "static",
       "Zero-width, bidirectional-override, or tag characters that hide text from a human reviewer.",
       "Strip the characters and review the visible text again. Tag characters usually smuggle ASCII."),
    _c("TP009", "Terminal escape sequences", "poisoning", "high", ["MCP03"],
       ["tob", "watch"], "static",
       "ANSI escape or control characters that can rewrite what a terminal shows.",
       "Strip control characters before display. Treat the source as hostile."),
    _c("TP010", "Encoded or obfuscated payload", "poisoning", "medium", ["MCP03", "MCP06"],
       ["ramparts", "proximity", "cisco"], "static",
       "Base64 or hex runs that decode to readable text, or decoder primitives such as atob or fromCharCode.",
       "Decode and review. The finding is raised to the decoded text's own severity."),
    _c("TP011", "Homoglyph or mixed-script name", "poisoning", "medium", ["MCP03", "MCP09"],
       ["cisco", "ramparts", "watch"], "static",
       "Server, tool, or prompt names that mix scripts or change under NFKC folding.",
       "Rename to ASCII, or verify the publisher. Look-alike names enable impersonation."),
    _c("TP012", "Oversized description", "poisoning", "low", ["MCP10"],
       ["cisco"], "static",
       "Very long tool text that crowds the context window or buries instructions.",
       "Keep descriptions short. Review long ones in full."),
    _c("TP013", "Coercive urgency or authority claim", "poisoning", "medium", ["MCP06"],
       ["cisco", "ramparts"], "static",
       "Shouted imperatives, claimed authority (system, admin, vendor), or threats of failure.",
       "Tool text should not pressure the model. Review the surrounding instructions."),
    _c("TP014", "Suspicious URL or download", "poisoning", "medium", ["MCP04", "MCP06"],
       ["snyk", "ramparts", "proximity"], "static",
       "Links to tunnels, request catchers, paste sites, shorteners, raw IPs, or executable downloads.",
       "Do not let the agent fetch the link. Verify why it is there."),
    _c("TP015", "Malicious command pattern", "poisoning", "critical", ["MCP05"],
       ["snyk", "ramparts", "cisco", "proximity"], "static",
       "Reverse shells, pipe-to-shell installs, credential theft, wipers, miners, or persistence commands.",
       "Remove the component and review the host it ran on."),
    _c("TP016", "Declared capability mismatch", "poisoning", "medium", ["MCP03"],
       ["cisco", "ramparts", "watch"], "live",
       "Tool name or readOnlyHint claims a read-only tool while the description says it writes, deletes, sends, or runs.",
       "Fix the annotation or the name. Clients use annotations to decide on confirmation prompts."),
    _c("TP017", "Duplicate tool name across servers", "poisoning", "high", ["MCP03", "MCP09"],
       ["snyk", "ramparts", "shield"], "live",
       "Two servers in one client expose the same tool name, so one can shadow the other.",
       "Rename or remove one tool. Prefer clients that namespace tools by server."),
    # TP013 covers coercion and authority claims, and SK003 covers skills that fetch instructions from a URL.
    # Neither covers a server steering the model toward itself, so these two are separate and stay modest.
    _c("TP018", "Agent-steering directive", "poisoning", "low", ["MCP06"],
       ["cisco"], "live",
       "Server text tells the model to call the server before or after other actions, to obey content it delivers at "
       "runtime, or to explain tool-list changes away.",
       "Read what the directive routes through the server. Runtime content arrives by a tool call and is not scanned."),
    _c("TP019", "Server-supplied install or run instruction", "poisoning", "medium", ["MCP04", "MCP06"],
       ["snyk"], "live",
       "The model is told to install, run, or relay verbatim something the server returns, such as a `successor` package "
       "or an install command and config snippet.",
       "Confirm install lines and replacement packages with the user and the registry before running them."),
    # Capabilities and toxic flows.
    _c("TF001", "Untrusted content source", "flow", "low", ["MCP06"],
       ["snyk", "radar"], "static",
       "Tools that bring third-party content (web pages, email, issues, messages) into the context.",
       "Expect indirect prompt injection from these tools. Avoid pairing them with private data and sinks."),
    _c("TF002", "Private data access", "flow", "low", ["MCP10"],
       ["snyk"], "static",
       "Tools that read files, mail, databases, repositories, credentials, or other non-public data.",
       "Scope the server to the minimum data it needs."),
    _c("TF003", "Public sink or exfiltration channel", "flow", "low", ["MCP10"],
       ["snyk", "watch"], "static",
       "Tools that send, post, upload, or request arbitrary URLs and so can carry data out.",
       "Require confirmation for sink tools, or restrict their destinations."),
    _c("TF004", "Destructive capability", "flow", "medium", ["MCP02"],
       ["snyk", "proximity"], "static",
       "Tools that delete, overwrite, drop, or terminate, or that carry destructiveHint.",
       "Require human confirmation for these tools."),
    _c("TF005", "Command or code execution capability", "flow", "high", ["MCP05"],
       ["ramparts", "cisco", "watch", "avow"], "static",
       "Tools that run shell commands, scripts, or arbitrary code.",
       "Run the server in a sandbox and require confirmation for each call."),
    _c("TF006", "Financial execution or paid calls", "flow", "medium", ["MCP02"],
       ["snyk"], "static",
       "Tools that move money, place orders, execute trades, or charge per call (for example over x402).",
       "Require human approval and a spending limit. Keep a paying wallet away from agents that read untrusted content."),
    _c("TF007", "Toxic flow (untrusted source + private data + sink)", "flow", "high", ["MCP10", "MCP06"],
       ["snyk", "watch"], "static",
       "One agent can read untrusted content, reach private data, and send data out. Injected text can chain them.",
       "Split these servers across agents, or gate the sink tools behind confirmation."),
    _c("TF008", "Excessive tool surface", "flow", "low", ["MCP02"],
       ["wiggle"], "live",
       "A server exposes many tools, most of which a given task will not need.",
       "Disable unused tools. The wiggle Needed ladder measures which ones tasks use."),
    # Schema and input validation.
    _c("SC001", "Unconstrained path argument", "schema", "medium", ["MCP05"],
       ["ramparts", "watch", "wiggle"], "live",
       "A path argument is a free string with no pattern or enum, so traversal depends on the server's own check.",
       "Constrain the argument, and confirm the server canonicalizes paths before its root check."),
    _c("SC002", "Unconstrained URL argument", "schema", "medium", ["MCP05"],
       ["watch", "wiggle"], "live",
       "A URL argument is a free string, so SSRF depends on the server's own destination check.",
       "Restrict schemes and hosts, and block private and link-local addresses."),
    _c("SC003", "Raw SQL argument", "schema", "medium", ["MCP05"],
       ["watch", "wiggle"], "live",
       "A tool accepts a SQL statement as a free string.",
       "Use a read-only database role, or replace raw SQL with parameterized operations."),
    _c("SC004", "Shell command argument", "schema", "high", ["MCP05"],
       ["ramparts", "cisco", "watch", "wiggle"], "live",
       "A tool accepts a command line as a free string.",
       "Replace with an allowlisted operation, or sandbox the server."),
    _c("SC005", "Weak input schema", "schema", "low", ["MCP05"],
       ["watch", "cisco", "proximity"], "live",
       "Missing inputSchema, untyped properties, or no description on a tool.",
       "Give every tool a typed object schema with additionalProperties set to false."),
    _c("SC006", "Missing safety annotations", "schema", "info", ["MCP02"],
       ["proximity"], "live",
       "The tool declares none of readOnlyHint, destructiveHint, or openWorldHint.",
       "Add annotations so clients can tell read-only tools from destructive ones."),
    # Secrets, on every surface.
    _c("SEC001", "Hardcoded secret", "secrets", "critical", ["MCP01"],
       ["snyk", "watch", "mcpguard", "avow", "ramparts", "safety"], "static",
       "API keys, tokens, private keys, or passwords written in config, tool text, skills, or source.",
       "Rotate the secret, then load it from the environment or a secret manager."),
    _c("SK002", "Insecure credential handling", "skills", "high", ["MCP01"],
       ["snyk"], "skills",
       "Instructions that make the agent print or pass secret values verbatim.",
       "Never route secrets through model output. Use references or environment variables."),
    # Configuration and supply chain.
    _c("CF002", "Unpinned package launch", "config", "medium", ["MCP04"],
       ["ramparts", "mcpguard", "cisco"], "static",
       "npx, uvx, or docker launches without an exact version or digest, so every start can run new code.",
       "Pin an exact version (or image digest) and update deliberately."),
    _c("CF003", "Shell-wrapped or inline-script launch", "config", "high", ["MCP05"],
       ["cisco", "avow"], "static",
       "The server is started through sh -c, cmd /c, powershell -Command, node -e, or python -c.",
       "Launch the server binary directly with an argument list."),
    _c("CF004", "Insecure remote transport", "config", "high", ["MCP07"],
       ["watch", "mcpguard"], "static",
       "A remote server URL uses http or ws to a non-loopback host.",
       "Use https. Plain http exposes tokens and tool traffic."),
    _c("CF005", "Remote server without configured auth", "config", "low", ["MCP07"],
       ["avow", "mcpguard"], "static",
       "A remote server has no Authorization or API-key header. The client may still negotiate OAuth.",
       "Confirm the server requires authentication."),
    _c("CF006", "Overbroad filesystem scope", "config", "high", ["MCP02"],
       ["safety", "mcpguard"], "static",
       "Arguments grant a drive root, the filesystem root, or the whole home directory.",
       "Grant only the project directories the server needs."),
    _c("CF007", "Weakened container isolation", "config", "high", ["MCP02"],
       ["mcpguard"], "static",
       "docker run with --privileged, host networking, the Docker socket, or a host root or home mount.",
       "Drop the flag. Mount only the directories the server needs, read-only where possible."),
    _c("CF008", "Project-scoped server config", "config", "medium", ["MCP09"],
       ["snyk", "mcpguard"], "static",
       "A server is defined in a repository file (.mcp.json, .vscode/mcp.json, .cursor/mcp.json) that any clone brings along.",
       "Review repository MCP configs before trusting the folder."),
    _c("CF009", "Typosquat or impersonation", "config", "high", ["MCP04", "MCP09"],
       ["watch", "ramparts"], "static",
       "The package or scope is one or two edits away from a well-known MCP package.",
       "Verify the publisher. Use the exact official package name."),
    _c("CF010", "Known-vulnerable pin", "config", "critical", ["MCP04"],
       ["ramparts", "cisco"], "static",
       "The launch line pins a version inside an advisory range recorded in data/reachable_cases.json.",
       "Upgrade to the fixed version."),
    _c("CF011", "Dependency advisory (OSV)", "config", "high", ["MCP04"],
       ["ramparts", "cisco"], "osv",
       "OSV.dev lists a vulnerability for a pinned npm or PyPI package in a launch line or manifest.",
       "Upgrade past the advisory's fixed version."),
    _c("CF012", "Dangerous environment override", "config", "medium", ["MCP04", "MCP07"],
       ["mcpguard"], "static",
       "Environment that injects code (NODE_OPTIONS --require, LD_PRELOAD) or disables TLS verification.",
       "Remove the override."),
    _c("CF013", "Server not on allowlist", "config", "medium", ["MCP09"],
       ["snyk", "radar"], "allowlist",
       "A configured server is not in the approved list.",
       "Approve it or remove it."),
    _c("CF014", "Agent hook runs a command", "config", "high", ["MCP04", "MCP05"],
       ["wiggle"], "static",
       "A Claude Code hook (SessionStart, PreToolUse, and the other events) in .claude/settings.json or settings.local.json "
       "runs a command with no tool call. A project file runs it for anyone who opens the folder; the Shai-Hulud worm "
       "planted SessionStart hooks this way in 2026. Hooks in the user's own settings are listed at low severity.",
       "Read the command. Remove hooks you did not add, and review a cloned folder's hooks before trusting it."),
    _c("CF015", "Editor task runs when the folder opens", "config", "high", ["MCP04", "MCP05"],
       ["wiggle"], "static",
       "A .vscode/tasks.json task sets runOptions.runOn to folderOpen, so VS Code starts it when the folder opens. "
       "The Shai-Hulud worm used this to re-run its payload in 2026.",
       "Remove the task, or its runOn setting, unless you added it."),
    # Rug pull and drift.
    _c("RP001", "Tool definition changed since pin", "drift", "high", ["MCP03"],
       ["snyk", "tob", "ramparts", "watch"], "baseline",
       "A tool's description, schema, or annotations differ from the pinned hash, or tools were added or removed.",
       "Review the diff. Re-pin only after approving the change."),
    _c("RP002", "Server config changed since pin", "drift", "medium", ["MCP03", "MCP04"],
       ["tob", "ramparts"], "baseline",
       "The launch command, arguments, URL, or environment of a pinned server changed.",
       "Confirm who changed the config and why."),
    _c("RP003", "Skill content changed since pin", "drift", "medium", ["MCP03"],
       ["ramparts"], "baseline",
       "A pinned skill's files changed.",
       "Review the change before the agent loads the skill again."),
    _c("RP004", "Server can change its tool list at runtime", "drift", "info", ["MCP03"],
       ["watch", "tob"], "live",
       "The server advertises tools.listChanged, so its tools can change after approval.",
       "Pin the tools and re-check on change notifications."),
    # Live protocol.
    _c("PR001", "Tools differ by client identity (bait and switch)", "protocol", "high", ["MCP03"],
       ["shield"], "identify",
       "The server returns different tools when the client presents a different name.",
       "Treat the server as deceptive. Remove it."),
    _c("PR003", "Protocol hygiene", "protocol", "low", ["MCP08"],
       ["cisco", "watch"], "live",
       "Outdated protocol version or missing server version in the initialize reply.",
       "Upgrade the server to a current SDK."),
    # Skills.
    _c("SK001", "Overbroad allowed-tools", "skills", "high", ["MCP02"],
       ["ramparts", "proximity"], "skills",
       "A skill grants unrestricted Bash or a wildcard tool list.",
       "List the exact tools and command prefixes the skill needs."),
    _c("SK003", "Runtime-fetched instructions", "skills", "high", ["MCP04"],
       ["snyk"], "skills",
       "The skill tells the agent to download instructions or code that then control its behavior.",
       "Vendor the instructions into the skill."),
    _c("SK004", "System service or persistence change", "skills", "medium", ["MCP02"],
       ["snyk"], "skills",
       "The skill changes services, scheduled tasks, startup entries, or privileges.",
       "Remove the step or make it an explicit, documented manual action."),
    _c("SK005", "Writes to agent memory or config", "skills", "medium", ["MCP10"],
       ["ramparts"], "skills",
       "The skill writes to CLAUDE.md, AGENTS.md, rules files, hooks, or MCP configs.",
       "Agent config changes should come from the user, not a skill."),
    _c("SK006", "Skill spec violation", "skills", "low", ["MCP04"],
       ["snyk", "ramparts"], "skills",
       "Missing SKILL.md or frontmatter, a bad name, or a name that differs from its directory.",
       "Follow the agentskills.io spec so reviewers can tell what loads."),
    _c("SK007", "Package runner in allowed-tools", "skills", "high", ["MCP04", "MCP02"],
       ["ramparts", "proximity", "snyk"], "skills",
       "allowed-tools pre-approves a package runner with open arguments (Bash(npx pkg:*), bunx, pnpm dlx, yarn dlx, uvx, "
       "pipx run). Unpinned, it runs whatever version the registry serves that day.",
       "Pin the package version, or approve a named local binary instead of the runner."),
    _c("SK009", "Undeclared network egress", "skills", "medium", ["MCP10"],
       ["ramparts"], "skills",
       "Skill scripts make network calls that SKILL.md never mentions.",
       "Document the destinations or remove the calls."),
    _c("SK010", "Served skill exceeds the declared boundary", "skills", "high", ["MCP02", "MCP03"],
       ["cisco", "proximity", "wiggle"], "skills",
       "A server that declares itself read-only (every tool has readOnlyHint, or its instructions say so) serves a skill "
       "that grants or documents writes, deletes, or command execution. Declared versus reachable, on one server.",
       "Do not load the server's skills in a client that honors allowed-tools, or ask the vendor to align the two."),
    # Source code.
    _c("CODE001", "Unsafe execution in code", "code", "high", ["MCP05"],
       ["cisco", "proximity", "avow", "ramparts"], "source",
       "shell=True, os.system, child_process.exec, eval, exec, or new Function in server or skill code.",
       "Use argument lists without a shell, and never evaluate model-supplied strings."),
    _c("CODE002", "Unsafe deserialization", "code", "high", ["MCP05"],
       ["proximity", "ramparts"], "source",
       "pickle, marshal, unsafe yaml.load, or Java/PHP object deserialization.",
       "Use a data-only format such as JSON or yaml.safe_load."),
    _c("CODE003", "Hardcoded outbound host", "code", "low", ["MCP10"],
       ["cisco"], "source",
       "Code sends requests to a hardcoded external host. Listed so data flows can be reviewed.",
       "Confirm each destination is documented and expected."),
    _c("CODE004", "Listener on all interfaces", "code", "medium", ["MCP07"],
       ["avow"], "source",
       "An HTTP transport binds 0.0.0.0. Without auth, anyone on the network can call tools.",
       "Bind 127.0.0.1, or require authentication."),
    _c("CODE005", "TLS verification disabled", "code", "high", ["MCP07"],
       ["mcpguard"], "source",
       "verify=False, rejectUnauthorized: false, or an unverified SSL context.",
       "Keep certificate verification on."),
    _c("CODE006", "Outbound call without timeout", "code", "low", ["MCP08"],
       ["cisco"], "source",
       "requests calls without a timeout can hang a tool call indefinitely.",
       "Pass an explicit timeout."),
    _c("CODE007", "No audit logging found", "code", "info", ["MCP08"],
       ["mcpguard"], "source",
       "The source tree shows no logging calls, so tool calls leave no trail.",
       "Log each tool call with its arguments' shape and outcome."),
    _c("CODE008", "Unpinned dependency manifest", "code", "low", ["MCP04"],
       ["ramparts", "cisco"], "source",
       "requirements.txt or package.json uses ranges, or no lockfile is present.",
       "Pin exact versions and commit a lockfile."),
    _c("VT001", "Known-malicious file hash", "code", "critical", ["MCP04"],
       ["cisco"], "virustotal",
       "VirusTotal engines flag a file in a scanned source tree or skill.",
       "Remove the file and investigate where it came from."),
    # LLM judge.
    _c("LLM001", "LLM judge: deceptive or manipulative tool text", "llm", "high", ["MCP03", "MCP06"],
       ["shield", "cisco", "ramparts", "proximity", "safety"], "llm",
       "A Claude model reads each server's tool text and flags hidden instructions, shadowing, exfiltration, or misleading claims.",
       "Read the model's explanation and the tool text. The judge is advisory."),
)

CHECKS_BY_ID = {check.id: check for check in CHECKS}

# Each scanner's documented features, mapped to the checks that reproduce them.
# An empty tuple is a gap, and the note says why. BUILTIN marks a feature the
# engine itself provides (discovery, OWASP tagging, an output format).
BUILTIN = ("builtin",)
SCANNER_FEATURES: dict[str, tuple[tuple[str, tuple[str, ...], str], ...]] = {
    "snyk": (
        ("E001 prompt injection in tool description", ("TP001", "TP002", "TP003", "LLM001"), ""),
        ("E002 cross-server tool reference / shadowing", ("TP004", "TP017"), ""),
        ("E004 prompt injection in skill", ("TP001", "TP002", "TP003"), "TP rules run on skill text"),
        ("E005 suspicious download URL in skill", ("TP014",), ""),
        ("E006 malicious code patterns in skill", ("TP015", "CODE001"), ""),
        ("W007 insecure credential handling", ("SK002",), ""),
        ("W008 hardcoded secrets", ("SEC001",), ""),
        ("W009 direct financial execution", ("TF006",), ""),
        ("W011 / W015 / W016 untrusted content", ("TF001",), ""),
        ("W012 unverifiable external dependency", ("SK003", "SK007", "TP019"), ""),
        ("W013 system service modification", ("SK004",), ""),
        ("W014 missing SKILL.md", ("SK006",), ""),
        ("W017 / W018 sensitive and workspace data", ("TF002",), ""),
        ("W019 / W020 destructive capabilities", ("TF004",), ""),
        ("W021 hidden Unicode", ("TP008",), ""),
        ("Toxic flows", ("TF007",), ""),
        ("Tool pinning (rug pull)", ("RP001",), ""),
        ("Client config discovery (14 agents)", BUILTIN, "discovery reads the same client families"),
        ("Background MDM reporting to Snyk Evo", (), "fleet reporting service, out of scope for a local scanner"),
    ),
    "cisco": (
        ("YARA rules: prompt injection, tool poisoning, command injection", ("TP001", "TP002", "TP015"), ""),
        ("LLM analyzer", ("LLM001",), ""),
        ("Cisco AI Defense Inspect API", (), "proprietary cloud API; LLM001 is the local stand-in"),
        ("Behavioral analyzer: docstring vs implementation", ("TP016", "CODE001", "SK010"), "heuristic, not dataflow"),
        ("Supply chain scan of server source", ("CODE001", "CODE002", "CODE003"), ""),
        ("VirusTotal hash lookups", ("VT001",), "lookups only, no upload"),
        ("Vulnerable packages (pip-audit / OSV)", ("CF011", "CF010"), ""),
        ("Readiness heuristics (timeouts, retries)", ("CODE006",), "timeouts only"),
        ("Prompt defense: unicode / homoglyph", ("TP008", "TP011"), ""),
        ("Prompt defense: context overflow", ("TP012",), ""),
        ("Prompt defense: social engineering", ("TP013", "TP018"), ""),
        ("Server instructions scan", ("TP001", "TP002"), "TP rules run on initialize instructions"),
        ("Prompts and resources scan", ("TP001", "TP002", "TP018", "TP019", "SK010"),
         "prompts/list and resources/list metadata, plus text resource bodies read within the caps (20 per server, "
         "256 KB each, text MIME types); served skills also get the skill checks. Text a tool returns, such as a "
         "skill fetched by a tool call, is not read"),
        ("Schema analysis", ("SC005",), ""),
        ("Known-config discovery", BUILTIN, ""),
        ("Protocol probes", ("PR003",), ""),
        ("PyPI / npm package download and sandboxed analysis", (), "needs a container; this repo has no jail"),
    ),
    "shield": (
        ("Hidden instructions", ("TP001",), ""),
        ("Potential exfiltration parameters", ("TP007",), ""),
        ("Tool shadowing", ("TP004",), ""),
        ("Sensitive file access", ("TP005",), ""),
        ("Cross-origin violations", ("TP004", "TP017"), ""),
        ("Optional Claude analysis", ("LLM001",), ""),
        ("--identify-as bait-and-switch", ("PR001",), ""),
        ("--safe-list", ("CF013",), "allowlist"),
    ),
    "ramparts": (
        ("Prompt injection / tool poisoning", ("TP001", "TP002"), ""),
        ("Secret leakage", ("SEC001",), ""),
        ("Path traversal surface", ("SC001",), ""),
        ("Command injection surface", ("SC004", "TF005"), ""),
        ("Cross-origin escalation", ("TP004", "TP017"), ""),
        ("OSV supply-chain CVEs", ("CF011",), ""),
        ("LLM semantic checks", ("LLM001",), ""),
        ("YARA malware IOCs", ("TP015",), ""),
        ("Normalized rescans (zero-width, NFKC, base64/hex)", ("TP008", "TP010", "TP011"), ""),
        ("Drift: MCPConfigChanged / MCPToolChanged / SkillContentChanged", ("RP001", "RP002", "RP003"), ""),
        ("Skill: overbroad allowed-tools", ("SK001", "SK007"), ""),
        ("Skill: writes to agent identity or memory files", ("SK005",), ""),
        ("Skill: undeclared network egress", ("SK009",), ""),
        ("Skill: unsafe YAML deserialization tags", ("CODE002",), ""),
        ("Skill: name collisions / brand impersonation", ("CF009", "TP017"), ""),
        ("agentskills.io spec validation", ("SK006",), ""),
        ("OWASP MCP Top 10 tagging", BUILTIN, "every check carries OWASP ids"),
        ("SARIF 2.1.0 output", BUILTIN, "--format sarif"),
    ),
    "proximity": (
        ("Tools, prompts, resources discovery", BUILTIN, "live introspection lists all three"),
        ("Tool annotations (readOnly, destructive, openWorld)", ("SC006", "TF004", "TP016", "SK010"), ""),
        ("NOVA rules (keywords, semantics, LLM)", ("TP002", "LLM001"), "regex rules plus the LLM judge"),
        ("Skill: code execution patterns", ("CODE001",), ""),
        ("Skill: exfiltration (curl | sh, base64)", ("TP015", "TP010"), ""),
        ("Skill: unsafe deserialization", ("CODE002",), ""),
        ("Skill: wildcard / undeclared permissions", ("SK001", "SK007"), ""),
    ),
    "tob": (
        ("Trust-on-first-use config pinning", ("RP002",), ""),
        ("Tool description and schema pinning", ("RP001",), ""),
        ("listChanged re-check", ("RP004",), ""),
        ("ANSI escape sanitization", ("TP009",), ""),
        ("Guardrail scan of tool responses", ("TP001", "TP002"), "paste responses into the panel's text lab; no inline proxy"),
        ("Quarantine of flagged responses", (), "runtime proxy feature; the wiggle Needed proxy is the enforcement layer here"),
    ),
    "watch": (
        ("credential-leak", ("SEC001",), ""),
        ("tool-poisoning", ("TP001", "TP002"), ""),
        ("parameter injection", ("TP007",), ""),
        ("prompt-injection", ("TP002",), ""),
        ("tool-mutation", ("RP001", "RP004"), ""),
        ("conversation exfiltration", ("TP006",), ""),
        ("ANSI / steganographic attack", ("TP009", "TP008"), ""),
        ("protocol-violation", ("PR003", "SC005"), ""),
        ("input-validation (command injection, SSRF, traversal)", ("SC001", "SC002", "SC004"), ""),
        ("server-spoofing", ("CF009", "TP011"), ""),
        ("toxic-flow", ("TF007",), ""),
        ("access-control / excessive permissions", ("CF006", "TF008"), ""),
    ),
    "safety": (
        ("Agentic audit of a config file", ("LLM001",), "single-pass judge, not multi-agent"),
        ("Sensitive key files", ("TP005",), ""),
        ("Sensitive environment variables", ("SEC001",), ""),
        ("Overbroad file access", ("CF006",), ""),
    ),
    "radar": (
        ("MCP server detection / inventory", BUILTIN, "inventory view in the panel"),
        ("Tool to OWASP mapping", BUILTIN, "every check carries OWASP MCP ids"),
        ("Runtime adversarial tests", (), "out of scope; wiggle's probe lattice measures reachable effects instead"),
    ),
    "mcpguard": (
        ("OWASP MCP Top 10 mapping", BUILTIN, "every check carries OWASP ids"),
        ("Tool poisoning detection", ("TP001", "TP002"), ""),
        ("Rug pull alerts", ("RP001",), ""),
        ("Config auto-detect (Claude, Cursor, VS Code, Windsurf)", BUILTIN, ""),
        ("Auto-fix", (), "fixes are listed as remediation text; zgscanner never edits configs"),
    ),
    "avow": (
        ("Hardcoded secrets", ("SEC001",), ""),
        ("Unsafe exec", ("CODE001", "CF003"), ""),
        ("Missing auth", ("CF005", "CODE004"), ""),
    ),
    "wiggle": (
        ("Schema heuristic (free-string resource args)", ("SC001", "SC002", "SC003", "SC004"), ""),
        ("Registry hint classifier", ("TF001", "TF002", "TF003"), "name hints feed the flow analysis when no tools were listed"),
        ("Local tools/list scan", BUILTIN, "live introspection reuses wiggle.mcp_client"),
    ),
}


def coverage() -> dict:
    """Per scanner: each feature, the checks that cover it, and the covered share."""
    out = {}
    for key, features in SCANNER_FEATURES.items():
        rows = []
        for feature, checks, note in features:
            if checks == BUILTIN:
                status, checks = "built-in", ()
            else:
                status = "covered" if checks else "gap"
            missing = [check for check in checks if check not in CHECKS_BY_ID]
            if missing:
                raise ValueError(f"{key}: unknown checks {missing}")
            rows.append({"feature": feature, "checks": list(checks), "status": status, "note": note})
        covered = sum(1 for row in rows if row["status"] != "gap")
        out[key] = {**SCANNERS[key], "features": rows, "covered": covered, "total": len(rows)}
    return out


def catalog_payload() -> dict:
    return {
        "checks": [check.as_dict() for check in CHECKS],
        "categories": CATEGORIES,
        "owasp": OWASP,
        "requirements": REQUIREMENTS,
        "scanners": SCANNERS,
        "coverage": coverage(),
        "severities": list(SEVERITIES),
    }
