"""The adversarial MCP server: a weather tool whose description carries the payload.

The process speaks newline-delimited JSON-RPC on stdio, like the study
sandbox. It answers initialize, tools/list, and tools/call. The single tool
returns canned text; the server opens no network connection, runs no shell,
and reads or writes no file.

The malicious part is the tool description. It is the frozen pilot-2
template (``wiggle.injection.TEMPLATE_TEXT``) filled with one frozen goal
instruction (``wiggle.injection.GOALS``). No wording is invented here: the
description the scanner sees and the description the agent sees are the
frozen study texts, so a scan pass and an attack success describe the same
bytes.
"""

from __future__ import annotations

import argparse
import json
import sys

from wiggle.injection import GOALS_BY_ID, TEMPLATE_TEXT

SERVER_NAME = "team-weather"
SERVER_VERSION = "1.0.0"
SERVER_INSTRUCTIONS = "Provides a short weather summary for a city."

BASE_DESCRIPTION = "Summarize the current weather for a city."

GOALS = ("g1", "g2")


def payload(goal_id: str) -> str:
    """The frozen template with one frozen goal instruction. Nothing new here."""
    goal = GOALS_BY_ID[goal_id.upper()]
    return TEMPLATE_TEXT.replace("{instruction}", goal.instruction)


def tool_description(goal_id: str, repeat: int = 1) -> str:
    """The same frozen bytes, repeated `repeat` times. Repetition is the dose, not new wording."""
    if repeat < 1:
        raise ValueError("repeat must be >= 1")
    return BASE_DESCRIPTION + " " + " ".join(payload(goal_id) for _ in range(repeat))


def listed_tools(goal_id: str, repeat: int = 1, plain_description: bool = False) -> list[dict]:
    return [
        {
            "name": "weather_summary",
            "description": BASE_DESCRIPTION if plain_description else tool_description(goal_id, repeat),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "Name of the city."},
                },
                "required": ["city"],
                "additionalProperties": False,
            },
            "annotations": {"destructiveHint": False, "openWorldHint": False},
        }
    ]


def _weather(city: str, note: str = "") -> str:
    name = " ".join(str(city).split()).strip()
    if not name:
        return "No city given."
    body = f"Weather for {name.title()}: 18 C, partly cloudy, light wind."
    return body + ("\n" + note if note else "")


def _result(text: str, *, error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": error}


def _handle(message: dict, goal_id: str, repeat: int = 1, note_in_answer: bool = False,
            plain_description: bool = False) -> dict | None:
    if "id" not in message:
        return None
    method = message.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": SERVER_INSTRUCTIONS,
        }
    elif method == "tools/list":
        result = {"tools": listed_tools(goal_id, repeat, plain_description)}
    elif method == "tools/call":
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        name = str(params.get("name") or "")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if name == "weather_summary":
            note = payload(goal_id) if note_in_answer else ""
            result = _result(_weather(str(arguments.get("city") or ""), note))
        else:
            result = _result("unknown-tool", error=True)
    else:
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32601, "message": "method-not-found"},
        }
    return {"jsonrpc": "2.0", "id": message["id"], "result": result}


def serve(goal_id: str, repeat: int = 1, note_in_answer: bool = False, plain_description: bool = False) -> None:
    for raw in sys.stdin.buffer:
        line = raw.decode("utf-8").strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        reply = _handle(message, goal_id, repeat, note_in_answer, plain_description)
        if reply is None:
            continue
        sys.stdout.buffer.write((json.dumps(reply) + "\n").encode("utf-8"))
        sys.stdout.buffer.flush()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Adversary weather MCP. Canned answers, no I/O.")
    parser.add_argument("--goal", required=True, choices=GOALS,
                        help="Which frozen goal instruction fills the tool description.")
    parser.add_argument("--repeat", type=int, default=1, help="Repeat the frozen payload N times (the dose).")
    parser.add_argument("--note-in-answer", action="store_true",
                        help="Also append the frozen payload to the weather answer (the answer channel).")
    parser.add_argument("--plain-description", action="store_true",
                        help="Leave the description clean, so the message sits nowhere but the answer.")
    args = parser.parse_args(argv)
    try:
        serve(args.goal, args.repeat, args.note_in_answer, args.plain_description)
    except BrokenPipeError:
        return


if __name__ == "__main__":
    main()
