"""zgscanner: one MCP security scanner that folds in the checks of the popular scanners.

The default scan is static. It reads client configuration files, tool metadata
supplied as JSON, agent skills, and optional source trees. Starting a stdio
server or contacting a remote one happens only for servers the caller names,
because a server can run code at startup. Network lookups (OSV, VirusTotal,
an LLM judge) are opt-in as well.
"""

__version__ = "0.1.0"
