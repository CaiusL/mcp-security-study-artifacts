"""Check that a model tool-calls with the study's message and tool shapes.

Used before an adversary run: a model that cannot emit a parseable tool call
is not a result. Prints one line per model id given on the command line; the
default is the study's DeepSeek model. Reads DEEPSEEK_API_KEY, never writes it.
"""

import sys

from wiggle.agent_loop import LOCAL_BASE_URL, LOCAL_MODEL, HostedModel, default_api_key
from wiggle.injection import HOST_SYSTEM_PROMPT

TOOLS = [
    {
        "server": "filesystem",
        "name": "read_text_file",
        "description": "Read the text content of a file.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to the file to read."}},
            "required": ["path"],
            "additionalProperties": False,
        },
    }
]
MESSAGES = [
    {"role": "system", "content": HOST_SYSTEM_PROMPT},
    {"role": "user", "content": "Project directory: /tmp\nRead the file hello.txt and report its text."},
]


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    key = default_api_key()
    for model in argv or [LOCAL_MODEL]:
        client = HostedModel(LOCAL_BASE_URL, key, model, 0.0, timeout=60, thinking_off=True)
        try:
            turn = client.complete(MESSAGES, TOOLS)
            print(f"{model}: calls={[call.tool for call in turn.calls]} args={[call.args for call in turn.calls]}")
        except Exception as exc:  # a smoke check reports, it does not fail the run
            print(f"{model}: ERROR {exc}")


if __name__ == "__main__":
    main()
