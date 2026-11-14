"""Run a live study against one pinned MCP server."""

from __future__ import annotations

import argparse
from pathlib import Path

from wiggle.live_fetch import run_live_fetch
from wiggle.live_git import run_live_git
from wiggle.live_memory import run_live_memory
from wiggle.live_sequential import run_live_sequential
from wiggle.live_study import run_live_filesystem
from wiggle.live_time import run_live_time

_RUNNERS = {
    "filesystem": run_live_filesystem,
    "fetch": run_live_fetch,
    "git": run_live_git,
    "memory": run_live_memory,
    "time": run_live_time,
    "sequential-thinking": run_live_sequential,
}
_DEFAULT_OUT = {
    "filesystem": Path("artifacts") / "live",
    "fetch": Path("artifacts") / "live-fetch",
    "git": Path("artifacts") / "live-git",
    "memory": Path("artifacts") / "live-memory",
    "time": Path("artifacts") / "live-time",
    "sequential-thinking": Path("artifacts") / "live-sequential",
}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Measure a pinned MCP server.")
    parser.add_argument("--server", choices=sorted(_RUNNERS), default="filesystem")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.out is None:
        args.out = _DEFAULT_OUT[args.server]
    payload = _RUNNERS[args.server](args.out)
    point = payload["operating_point"]
    print(payload["narrative"])
    print()
    print(
        f"Operating point {point['name']}: "
        f"block {point['attack_block_rate']:.1%}, "
        f"held-out {point['heldout_success_rate']:.1%}."
    )
    print(f"Wrote {args.out / 'report.md'}.")


if __name__ == "__main__":
    main()
