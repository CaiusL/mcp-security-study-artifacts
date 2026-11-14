"""Run the proof of concept and write artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

from wiggle.evaluate import run_study


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Measure MCP tool wiggle room on local stand-ins.")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("artifacts") / "phase1",
        help="Directory for results.json, curve.svg, curve.csv, report.md, and traces.jsonl.",
    )
    args = parser.parse_args(argv)
    payload = run_study(args.out)
    point = payload["operating_point"]
    vuln = next(row for row in payload["modes"]["vulnerable"] if row["level"] == point["level"])
    patched = payload["envelopes"]["patched"]
    print(payload["narrative"])
    print()
    print(
        f"Operating point {point['name']}: "
        f"block {vuln['attack_block_rate']:.1%}, "
        f"held-out {vuln['heldout_success_rate']:.1%}, "
        f"train {vuln['train_success_rate']:.1%}."
    )
    print(
        "Patched stand-ins still reach "
        f"{patched['reachable_inside_intent_not_needed']} in-scope resources "
        "that benign training tasks never use."
    )
    print(f"Wrote {args.out / 'report.md'}, {args.out / 'curve.svg'}, {args.out / 'results.json'}.")


if __name__ == "__main__":
    main()
