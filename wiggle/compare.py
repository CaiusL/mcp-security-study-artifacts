"""Write a cross-server comparison from the live study results."""

from __future__ import annotations

import json
from pathlib import Path


STUDIES = (
    ("filesystem", Path("artifacts") / "live" / "results.json"),
    ("fetch", Path("artifacts") / "live-fetch" / "results.json"),
    ("git", Path("artifacts") / "live-git" / "results.json"),
    ("memory", Path("artifacts") / "live-memory" / "results.json"),
    ("time", Path("artifacts") / "live-time" / "results.json"),
)
FLAT_CONTROL = ("sequential-thinking", Path("artifacts") / "live-sequential" / "results.json")


def _load(root: Path) -> list[tuple[str, dict]]:
    loaded = []
    for name, path in STUDIES:
        loaded.append((name, json.loads((root / path).read_text(encoding="utf-8"))))
    return loaded


def _l0(payload: dict, kind: str) -> list[dict]:
    return [
        row
        for row in payload["probes"]
        if row["level"] == 0 and row["role"] == "attack" and row["kind"] == kind
    ]


def _schema_refusal(row: dict) -> bool:
    error = row.get("server_error") or ""
    return error.startswith("Input validation error") or error.startswith("Invalid arguments")


def _curve(payload: dict, level: int) -> dict:
    for row in payload["curve"]:
        if row["level"] == level:
            return row
    raise KeyError(level)


def _first_closed(payload: dict, probe_id: str) -> int | None:
    levels = [
        row["level"]
        for row in payload["probes"]
        if row["id"] == probe_id and row["blocked"]
    ]
    return min(levels) if levels else None


def _require_server_refusal(rows: list[dict]) -> None:
    bad = [
        row["id"]
        for row in rows
        if row["effect"] or row["proxy_denied"] or not row["server_error"]
    ]
    if bad:
        raise RuntimeError(
            "boundary probes with an effect or a proxy deny at L0: "
            + ", ".join(sorted(set(bad)))
        )


def _require_excess_effect(rows: list[dict]) -> None:
    bad = [
        row["id"]
        for row in rows
        if not row["effect"] or row["proxy_denied"] or row["server_error"]
    ]
    if bad:
        raise RuntimeError(
            "in-scope excess probes without an effect at L0: "
            + ", ".join(sorted(set(bad)))
        )


def _git_clause(payload: dict) -> str:
    point = payload["operating_point"]
    open_ids = {
        row["id"]
        for row in payload["probes"]
        if row["level"] == point["level"] and row["role"] == "attack" and not row["blocked"]
    }
    closed_at = _first_closed(payload, "git-show-hidden")
    if "git-show-hidden" not in open_ids:
        if closed_at is None:
            return "`git-show-hidden` is not in the lattice."
        closed = _curve(payload, closed_at)
        return (
            f"`git-show-hidden` is closed at {point['name']}. "
            f"It first closes at {closed['name']}."
        )
    if closed_at is None:
        held = _curve(payload, point["level"])["heldout_success_rate"]
        return (
            "`git-show-hidden` stays open through L5. "
            f"Held-out success at {point['name']} is {held:.0%}."
        )
    opened = _curve(payload, point["level"])
    closed = _curve(payload, closed_at)
    sentence = (
        "At the recorded operating point, `git-show-hidden` is still open: "
        "`git_show` of `HEAD:notes/hidden.md` returns `WIGGLE_CANARY_HIDDEN`. "
        f"{closed['name'].split()[0]} closes the probe and drops git held-out success "
        f"from {opened['heldout_success_rate']:.0%} to {closed['heldout_success_rate']:.0%}."
    )
    if point["level"] == 4 and closed_at == 5:
        sentence += " L4 constrains `git_add` paths and suffixes."
    elif closed_at == 4:
        sentence += " L4 requires a `git_show` revision the training traces used."
    return sentence


def _paired(studies: list[tuple[str, dict]]) -> list[str]:
    boundary = [row for _name, payload in studies for row in _l0(payload, "boundary")]
    excess = [row for _name, payload in studies for row in _l0(payload, "excess")]
    if not boundary or not excess:
        raise RuntimeError("the lattices have no boundary or in-scope excess probes")
    _require_server_refusal(boundary)
    _require_excess_effect(excess)
    carried = [row for row in boundary if not _schema_refusal(row)]
    schema = [row for row in boundary if _schema_refusal(row)]
    if not carried:
        raise RuntimeError("no schema-valid boundary probe is in the lattice")
    inside = [row["id"] for row in carried if row["declared_intent"]]
    if inside:
        raise RuntimeError(
            "schema-valid boundary probes inside declared intent: " + ", ".join(sorted(set(inside)))
        )
    schema_clause = ""
    if len(schema) == 1:
        schema_clause = f" One further boundary probe, `{schema[0]['id']}`, failed the server's schema check."
    elif schema:
        names = ", ".join(f"`{row['id']}`" for row in schema)
        schema_clause = f" {len(schema)} further boundary probes failed the server's schema check: {names}."
    git = next(payload for name, payload in studies if name == "git")
    return [
        "Two findings from the same five patched pins and the same lattices.",
        "",
        (
            "On these patched servers, every boundary probe in the lattice produced no effect "
            f"({len(boundary)} of {len(boundary)}). The server refused the call before any Needed policy. "
            "A schema-valid call did not carry an action outside the declared boundary "
            f"({len(carried)} of {len(carried)}).{schema_clause}"
        ),
        "",
        (
            "On these same servers, in-scope excess did produce its effect "
            f"({len(excess)} of {len(excess)} at L0). A call that stays inside the declared root, repo, or graph, "
            "and reaches something the training tasks never use, was performed by the server. "
            f"The Needed ladder is what blocks that excess. {_git_clause(git)}"
        ),
        "",
        "A miss on this lattice is a share of the lattice. It is not a proof that no other call exists.",
    ]


def _open_ids(payload: dict, level: int) -> list[str]:
    return sorted(
        {
            row["id"]
            for row in payload["probes"]
            if row["level"] == level and row["role"] == "attack" and not row["blocked"]
        }
    )


def build_comparison(root: Path | None = None) -> str:
    root = root or Path(".")
    studies = _load(root)
    lines = ["# Cross-server comparison", "", *_paired(studies), ""]
    lines.extend(
        [
            "Each row is one pinned server. Block and held-out are at that server's operating point. In-scope excess is the count of lattice probes the server actually performs inside its declared intent that training never exercised.",
            "",
            "| Server | Declared tools | Tools used | Operating point | Attacks blocked | Held-out | In-scope excess | Still open there |",
            "| --- | ---: | ---: | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for _name, payload in studies:
        point = payload["operating_point"]
        level = point["level"]
        used = payload["profile"].get("tools") or []
        open_ids = _open_ids(payload, level)
        lines.append(
            "| {server} | {declared} | {used} | {op} | {block:.0%} | {held:.0%} | {excess} | {open} |".format(
                server=f"{payload['package']}@{payload['pin']}",
                declared=payload["declared"]["tool_count"],
                used=len(used),
                op=point["name"],
                block=point["attack_block_rate"],
                held=point["heldout_success_rate"],
                excess=payload["envelope"]["reachable_inside_intent_not_needed"],
                open=", ".join(f"`{item}`" for item in open_ids) or "—",
            )
        )
    lines.extend(
        [
            "",
            "Filesystem, git, and memory still perform in-scope work the training tasks never request. Time's unused timezones close at L2 with held-out success unchanged. Fetch's private-address check already stops the boundary probes; `raw=true` on a needed URL and a new public host close together at L2, which also drops the held-out fetch of a second public host.",
            "",
            "Memory's tools take no path. `MEMORY_FILE_PATH` fixes the file. `read_graph` and `delete_entities` are unused tools and close at L2. `open_nodes` of a pre-seeded Secret entity closes at L3. `search_nodes` for that name closes at L4, still with every held-out task succeeding. L5 is the first level that rejects a new entity the held-out task creates.",
            "",
            _flat_clause(json.loads((root / FLAT_CONTROL[1]).read_text(encoding="utf-8"))),
            "",
        ]
    )
    return "\n".join(lines)


def _flat_clause(payload: dict) -> str:
    """The flat control stays out of the five-pin paired counts."""
    point = payload["operating_point"]
    opener = payload["curve"][0]
    tighter = next(
        (row for row in payload["curve"] if row["excess_block_rate"] > opener["excess_block_rate"]),
        None,
    )
    sentence = (
        f"{payload['package']}@{payload['pin']} is the flat control, measured apart from the five pins. "
        f"At {point['name']}, in-scope excess block is {point['excess_block_rate']:.0%} "
        f"and held-out success is {point['heldout_success_rate']:.0%}."
    )
    if tighter is None:
        return sentence + " Excess block does not rise at any level."
    return (
        sentence
        + f" Excess block first rises at {tighter['name']}, "
        + f"where held-out success is {tighter['heldout_success_rate']:.0%}."
    )


def main() -> None:
    text = build_comparison()
    target = Path("artifacts") / "phase1" / "comparison.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    print(text)
    print(f"Wrote {target}.")


if __name__ == "__main__":
    main()
