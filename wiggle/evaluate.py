"""Run the envelope measurement and write the security-usability curve."""

from __future__ import annotations

import csv
import json
import shutil
from fractions import Fraction
from pathlib import Path

from wiggle import __version__
from wiggle.corpus import (
    build_probes,
    effect_happened,
    make_sandbox,
    scripted_calls,
    task_succeeded,
    tasks,
)
from wiggle.declared import SPECS_BY_NAME, extract_declared, schema_ok
from wiggle.model import Call, Layout, Probe, Profile, Scope, Task
from wiggle.normalize import exact_key, inside, norm_resolved
from wiggle.policy import LEVELS, allows, build_profile
from wiggle.servers import FetchServer, FilesystemServer

REPS = (0, 1, 2)
MODES = ("vulnerable", "patched")


def run_study(out_dir: Path) -> dict:
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    sandbox = out_dir / "sandbox"
    try:
        layout = make_sandbox(sandbox)
        scope = Scope(declared_root=norm_resolved(str(layout.proj)))
        catalog = tasks()
        train = [task for task in catalog if task.split == "train"]
        heldout = [task for task in catalog if task.split == "heldout"]
        train_calls = [
            call
            for task in train
            for rep in REPS
            for call in scripted_calls(task, layout, rep)
        ]
        profile = build_profile(train_calls)
        if not profile.ancestor:
            raise RuntimeError("training traces produced an empty filesystem ancestor")
        probe_list = build_probes(layout)
        traces: list[dict] = []
        task_rows: list[dict] = []
        probe_rows: list[dict] = []
        levels: dict[str, list[dict]] = {}

        for mode in MODES:
            for level, _name, _text in LEVELS:
                for task in catalog:
                    rep_records = [
                        _run_task(task, layout, rep, level, profile, scope, mode, traces)
                        for rep in REPS
                    ]
                    task_rows.append(
                        {
                            "mode": mode,
                            "level": level,
                            "id": task.id,
                            "server": task.server,
                            "split": task.split,
                            "success": all(record["ok"] for record in rep_records),
                            "reps": [
                                {"rep": rep, "ok": record["ok"], "stage": record["stage"], "reason": record["reason"]}
                                for rep, record in zip(REPS, rep_records)
                            ],
                        }
                    )
                for probe in probe_list:
                    probe_rows.append(
                        _run_probe(probe, layout, level, profile, scope, mode, traces)
                    )
            levels[mode] = _level_rows(mode, task_rows, probe_rows)
            _check_invariants(mode, levels[mode], task_rows, probe_rows)

        operating = _operating_point(levels["vulnerable"])
        payload = {
            "version": __version__,
            "reps": list(REPS),
            "symlink_supported": layout.has_symlink,
            "levels": [
                {"level": level, "name": name, "rule": text} for level, name, text in LEVELS
            ],
            "profile": _profile_summary(profile, scope),
            "declared": extract_declared("<configured-root>"),
            "modes": levels,
            "operating_point": operating,
            "scanner": _scanner_comparison(probe_list, levels, operating["level"]),
            "envelopes": {
                mode: _envelope(mode, probe_rows, profile, scope) for mode in MODES
            },
            "probes": probe_rows,
            "tasks": [
                {
                    "mode": row["mode"],
                    "level": row["level"],
                    "id": row["id"],
                    "split": row["split"],
                    "success": row["success"],
                }
                for row in task_rows
            ],
        }
        payload["narrative"] = _narrative(payload)
        _write_outputs(out_dir, payload, traces)
        return payload
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


def _server(mode: str, server_name: str, layout: Layout):
    if server_name == "filesystem":
        return FilesystemServer(layout.proj, mode)
    if server_name == "fetch":
        return FetchServer(mode)
    raise ValueError(server_name)


def _reset(layout: Layout) -> None:
    make_sandbox(layout.root)


def _run_task(task, layout, rep, level, profile, scope, mode, traces) -> dict:
    _reset(layout)
    server = _server(mode, task.server, layout)
    results = []
    for call in scripted_calls(task, layout, rep):
        decision = allows(call, level, profile, scope)
        if not decision.allow:
            traces.append(_trace_task(task, rep, mode, level, False, "policy", decision.reason))
            return {"ok": False, "stage": "policy", "reason": decision.reason}
        result = server.execute(call)
        results.append(result)
        if not result.ok:
            traces.append(_trace_task(task, rep, mode, level, False, "server", result.error))
            return {"ok": False, "stage": "server", "reason": result.error}
    ok = task_succeeded(task, layout, results)
    reason = "" if ok else "oracle"
    traces.append(_trace_task(task, rep, mode, level, ok, "ok" if ok else "oracle", reason))
    return {"ok": ok, "stage": "ok" if ok else "oracle", "reason": reason}


def _run_probe(probe: Probe, layout, level, profile, scope, mode, traces) -> dict:
    _reset(layout)
    decision = allows(probe.call, level, profile, scope)
    proxy_denied = "" if decision.allow else decision.reason
    server_error = ""
    result = None
    if decision.allow:
        result = _server(mode, probe.server, layout).execute(probe.call)
        if not result.ok:
            server_error = result.error
    effect = effect_happened(probe, result, layout)
    row = {
        "id": probe.id,
        "server": probe.server,
        "role": probe.role,
        "kind": probe.kind,
        "mode": mode,
        "level": level,
        "needed": exact_key(probe.call) in profile.exact,
        "declared_schema": schema_ok(probe.call),
        "declared_intent": allows(probe.call, 1, profile, scope).allow,
        "proxy_denied": proxy_denied,
        "server_error": server_error,
        "effect": effect,
        "blocked": not effect,
    }
    traces.append(
        {
            "type": "probe",
            "id": probe.id,
            "mode": mode,
            "level": level,
            "blocked": row["blocked"],
            "proxy_denied": proxy_denied,
            "server_error": server_error,
        }
    )
    return row


def _trace_task(task: Task, rep: int, mode: str, level: int, ok: bool, stage: str, reason: str) -> dict:
    return {
        "type": "task",
        "id": task.id,
        "split": task.split,
        "rep": rep,
        "mode": mode,
        "level": level,
        "ok": ok,
        "stage": stage,
        "reason": reason,
    }


def _rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _level_rows(mode: str, task_rows: list[dict], probe_rows: list[dict]) -> list[dict]:
    rows = []
    for level, name, _text in LEVELS:
        tasks_at = [row for row in task_rows if row["mode"] == mode and row["level"] == level]
        probes_at = [row for row in probe_rows if row["mode"] == mode and row["level"] == level]
        attacks = [row for row in probes_at if row["role"] == "attack"]
        rows.append(
            {
                "level": level,
                "name": name,
                "train_passed": _passed(tasks_at, "train"),
                "train_total": _total(tasks_at, "train"),
                "heldout_passed": _passed(tasks_at, "heldout"),
                "heldout_total": _total(tasks_at, "heldout"),
                "attacks_blocked": sum(row["blocked"] for row in attacks),
                "attacks_total": len(attacks),
                "boundary_blocked": _blocked_kind(attacks, "boundary"),
                "boundary_total": _count_kind(attacks, "boundary"),
                "excess_blocked": _blocked_kind(attacks, "excess"),
                "excess_total": _count_kind(attacks, "excess"),
            }
        )
    for row in rows:
        row["train_success_rate"] = _rate(row["train_passed"], row["train_total"])
        row["heldout_success_rate"] = _rate(row["heldout_passed"], row["heldout_total"])
        row["attack_block_rate"] = _rate(row["attacks_blocked"], row["attacks_total"])
        row["boundary_block_rate"] = _rate(row["boundary_blocked"], row["boundary_total"])
        row["excess_block_rate"] = _rate(row["excess_blocked"], row["excess_total"])
    return rows


def _passed(rows: list[dict], split: str) -> int:
    return sum(row["success"] for row in rows if row["split"] == split)


def _total(rows: list[dict], split: str) -> int:
    return sum(row["split"] == split for row in rows)


def _count_kind(rows: list[dict], kind: str) -> int:
    return sum(row["kind"] == kind for row in rows)


def _blocked_kind(rows: list[dict], kind: str) -> int:
    return sum(row["blocked"] for row in rows if row["kind"] == kind)


def _failed_tasks(task_rows: list[dict], mode: str, level: int, split: str) -> list[str]:
    failed = []
    for row in task_rows:
        if row["mode"] == mode and row["level"] == level and row["split"] == split and not row["success"]:
            reasons = [f"rep{item['rep']}:{item['stage']}:{item['reason']}" for item in row["reps"] if not item["ok"]]
            failed.append(f"{row['id']} ({'; '.join(reasons)})")
    return failed


def _check_invariants(mode: str, rows: list[dict], task_rows: list[dict], probe_rows: list[dict]) -> None:
    """Fail the run when the harness contradicts its own definitions."""
    previous_block = -1
    previous_held = None
    for row in rows:
        if row["train_passed"] != row["train_total"]:
            failed = _failed_tasks(task_rows, mode, row["level"], "train")
            raise RuntimeError(f"{mode} {row['name']} rejected a training task: {failed}")
        if row["attacks_blocked"] < previous_block:
            raise RuntimeError(f"{mode} attack block rate fell at {row['name']}")
        if previous_held is not None and row["heldout_passed"] > previous_held:
            raise RuntimeError(f"{mode} held-out success rose at {row['name']}")
        previous_block = row["attacks_blocked"]
        previous_held = row["heldout_passed"]
    if rows[0]["heldout_passed"] != rows[0]["heldout_total"]:
        failed = _failed_tasks(task_rows, mode, 0, "heldout")
        raise RuntimeError(f"{mode} held-out tasks failed at L0: {failed}")
    controls = [
        row
        for row in probe_rows
        if row["mode"] == mode and row["role"] == "control" and row["blocked"]
    ]
    if controls:
        raise RuntimeError(
            f"{mode} blocked needed controls: {sorted({row['id'] for row in controls})}"
        )
    if mode == "vulnerable" and rows[0]["attacks_blocked"] != 0:
        leaked = [
            row["id"]
            for row in probe_rows
            if row["mode"] == mode and row["level"] == 0 and row["role"] == "attack" and row["blocked"]
        ]
        raise RuntimeError(f"vulnerable server blocked attack probes at L0: {leaked}")
    if mode == "patched":
        open_boundary = [
            row["id"]
            for row in probe_rows
            if row["mode"] == mode
            and row["level"] == 0
            and row["kind"] == "boundary"
            and not row["blocked"]
        ]
        blocked_excess = [
            row["id"]
            for row in probe_rows
            if row["mode"] == mode
            and row["level"] == 0
            and row["kind"] == "excess"
            and row["blocked"]
        ]
        if open_boundary or blocked_excess:
            raise RuntimeError(
                "patched server did not match declared intent: "
                f"open boundary {open_boundary}, blocked excess {blocked_excess}"
            )


def _score(row: dict) -> Fraction:
    return min(
        Fraction(row["attacks_blocked"], row["attacks_total"]),
        Fraction(row["heldout_passed"], row["heldout_total"]),
    )


def _prefer(candidate: dict, current: dict) -> bool:
    """Higher balanced score, then higher block, then higher held-out, then lower level."""
    if _score(candidate) != _score(current):
        return _score(candidate) > _score(current)
    if candidate["attacks_blocked"] != current["attacks_blocked"]:
        return candidate["attacks_blocked"] > current["attacks_blocked"]
    if candidate["heldout_passed"] != current["heldout_passed"]:
        return candidate["heldout_passed"] > current["heldout_passed"]
    return candidate["level"] < current["level"]


def _operating_point(rows: list[dict]) -> dict:
    """Level that maximizes min(attack block, held-out success)."""
    chosen = rows[0]
    for row in rows[1:]:
        if _prefer(row, chosen):
            chosen = row
    return {
        "rule": (
            "maximize min(attack block rate, held-out success) on the vulnerable server; "
            "ties take the higher block rate, then the higher held-out rate, then the lower level"
        ),
        "level": chosen["level"],
        "name": chosen["name"],
        "score": float(_score(chosen)),
        "vulnerable": {
            "attack_block_rate": chosen["attack_block_rate"],
            "heldout_success_rate": chosen["heldout_success_rate"],
            "excess_block_rate": chosen["excess_block_rate"],
            "boundary_block_rate": chosen["boundary_block_rate"],
        },
    }


def _profile_summary(profile: Profile, scope: Scope) -> dict:
    def relative(path: str) -> str:
        if path == scope.declared_root:
            return "."
        if inside(path, scope.declared_root) and path.startswith(scope.declared_root):
            return path[len(scope.declared_root):].lstrip("\\/").replace("\\", "/")
        return "<outside>"

    return {
        "tools": sorted(profile.tools),
        "read_dirs": sorted(relative(path) for path in profile.read_dirs),
        "write_dirs": sorted(relative(path) for path in profile.write_dirs),
        "write_exts": sorted(profile.write_exts),
        "hosts": sorted(profile.hosts),
        "segments": sorted(f"{host}/{segment}" for host, segment in profile.segments),
        "urls": sorted(profile.urls),
        "exact_count": len(profile.exact),
        "ancestor_equals_declared_root": profile.ancestor == scope.declared_root,
    }


def _envelope(mode: str, probe_rows: list[dict], profile: Profile, scope: Scope) -> dict:
    rows = [row for row in probe_rows if row["mode"] == mode and row["level"] == 0]
    reachable = [row for row in rows if row["effect"]]
    needed = [row for row in reachable if row["needed"]]
    outside_intent = [row for row in reachable if not row["declared_intent"]]
    inside_excess = [row for row in reachable if row["declared_intent"] and not row["needed"]]
    return {
        "lattice": len(rows),
        "declared_schema": sum(row["declared_schema"] for row in rows),
        "declared_intent": sum(row["declared_intent"] for row in rows),
        "reachable": len(reachable),
        "needed_and_reachable": len(needed),
        "reachable_outside_declared_intent": len(outside_intent),
        "reachable_inside_intent_not_needed": len(inside_excess),
        "excess_fraction_of_reachable": _rate(len(reachable) - len(needed), len(reachable)),
        "inside_intent_excess_ids": sorted(row["id"] for row in inside_excess),
        "boundary_reachable_ids": sorted(row["id"] for row in outside_intent),
    }


def scanner_flags(tool_name: str) -> bool:
    """Schema heuristic: an unconstrained string that the description treats as a path or URL.

    This is a stand-in for a metadata scanner. It is not Snyk Agent Scan or the
    Cisco MCP Scanner.
    """
    spec = SPECS_BY_NAME[tool_name]
    description = spec.description.lower()
    mentions_resource = any(word in description for word in ("path", "url", "director"))
    free_string = any(
        prop["type"] == "string" and "enum" not in prop and "pattern" not in prop
        for prop in spec.properties.values()
    )
    return mentions_resource and free_string


def _scanner_comparison(probe_list: list[Probe], levels: dict, level: int) -> dict:
    attacks = [probe for probe in probe_list if probe.role == "attack"]
    controls = [probe for probe in probe_list if probe.role == "control"]
    vuln = levels["vulnerable"]
    chosen = next(row for row in vuln if row["level"] == level)
    flagged_attacks = sum(scanner_flags(probe.call.tool) for probe in attacks)
    flagged_controls = sum(scanner_flags(probe.call.tool) for probe in controls)
    return {
        "scanner": "schema heuristic stand-in",
        "recall_on_attacks": _rate(flagged_attacks, len(attacks)),
        "false_positive_rate_on_needed_controls": _rate(flagged_controls, len(controls)),
        "policy_level": level,
        "policy_attack_block_rate": chosen["attack_block_rate"],
        "policy_false_positive_rate_on_needed_controls": 0.0,
        "policy_heldout_success_rate": chosen["heldout_success_rate"],
    }


def _narrative(payload: dict) -> str:
    point = payload["operating_point"]
    vuln = next(row for row in payload["modes"]["vulnerable"] if row["level"] == point["level"])
    patched_l0 = payload["modes"]["patched"][0]
    vuln_env = payload["envelopes"]["vulnerable"]
    patched_env = payload["envelopes"]["patched"]
    lines = [
        (
            f"On the vulnerable stand-ins, {point['name']} blocks "
            f"{vuln['attack_block_rate']:.1%} of attack probes and keeps "
            f"{vuln['heldout_success_rate']:.1%} of held-out tasks. "
            f"Training tasks stay at {vuln['train_success_rate']:.1%}."
        ),
        (
            f"The vulnerable lattice has {vuln_env['reachable']} reachable probes, "
            f"of which {vuln_env['reachable'] - vuln_env['needed_and_reachable']} "
            f"are outside the Needed envelope "
            f"({vuln_env['excess_fraction_of_reachable']:.1%} of reachable). "
            f"{vuln_env['reachable_outside_declared_intent']} of those sit outside declared intent, "
            f"and {vuln_env['reachable_inside_intent_not_needed']} sit inside it."
        ),
        (
            f"The patched stand-ins already block {patched_l0['boundary_block_rate']:.1%} of "
            f"boundary probes at L0 and block {patched_l0['excess_block_rate']:.1%} of "
            f"in-scope excess probes. Reachable probes that remain inside declared intent "
            f"and outside Needed: {patched_env['reachable_inside_intent_not_needed']}."
        ),
    ]
    if payload["profile"]["ancestor_equals_declared_root"]:
        lines.append(
            "The common ancestor of benign filesystem paths equals the configured root, "
            "so the coarse Needed root and the declared root are the same constraint."
        )
    open_ids = sorted(
        {
            row["id"]
            for row in payload["probes"]
            if row["mode"] == "vulnerable"
            and row["level"] == point["level"]
            and row["role"] == "attack"
            and not row["blocked"]
        }
    )
    if open_ids:
        lines.append(
            "Attack probes still open at that level: " + ", ".join(open_ids) + "."
        )
    return " ".join(lines)


def _write_outputs(out_dir: Path, payload: dict, traces: list[dict]) -> None:
    (out_dir / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out_dir / "curve.svg").write_text(_svg(payload), encoding="utf-8")
    (out_dir / "report.md").write_text(_report(payload), encoding="utf-8")
    with (out_dir / "curve.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "mode",
                "level",
                "name",
                "attack_block_rate",
                "boundary_block_rate",
                "excess_block_rate",
                "heldout_success_rate",
                "train_success_rate",
                "attacks_blocked",
                "attacks_total",
                "heldout_passed",
                "heldout_total",
            ],
        )
        writer.writeheader()
        for mode, rows in payload["modes"].items():
            for row in rows:
                writer.writerow(
                    {
                        "mode": mode,
                        "level": row["level"],
                        "name": row["name"],
                        "attack_block_rate": f"{row['attack_block_rate']:.6f}",
                        "boundary_block_rate": f"{row['boundary_block_rate']:.6f}",
                        "excess_block_rate": f"{row['excess_block_rate']:.6f}",
                        "heldout_success_rate": f"{row['heldout_success_rate']:.6f}",
                        "train_success_rate": f"{row['train_success_rate']:.6f}",
                        "attacks_blocked": row["attacks_blocked"],
                        "attacks_total": row["attacks_total"],
                        "heldout_passed": row["heldout_passed"],
                        "heldout_total": row["heldout_total"],
                    }
                )
    with (out_dir / "traces.jsonl").open("w", encoding="utf-8") as handle:
        for trace in traces:
            handle.write(json.dumps(trace) + "\n")


def _svg(payload: dict) -> str:
    width = 760
    panel_h = 340
    margin_l = 56
    margin_r = 20
    margin_t = 36
    margin_b = 48
    plot_w = width - margin_l - margin_r
    plot_h = panel_h - margin_t - margin_b
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{panel_h * 2 + 24}" '
        'viewBox="0 0 {w} {h}">'.format(w=width, h=panel_h * 2 + 24),
        '<rect width="100%" height="100%" fill="#fbfbf9"/>',
    ]
    colors = {
        "attack_block_rate": "#9b2226",
        "heldout_success_rate": "#1b7f5a",
        "train_success_rate": "#1d4e89",
    }
    labels = {
        "attack_block_rate": "Attack probes blocked",
        "heldout_success_rate": "Held-out tasks succeeding",
        "train_success_rate": "Training tasks succeeding",
    }
    for index, mode in enumerate(MODES):
        top = 12 + index * panel_h
        rows = payload["modes"][mode]
        parts.append(
            f'<text x="{margin_l}" y="{top + 18}" font-family="Segoe UI, sans-serif" '
            f'font-size="16" fill="#222">{_title(mode)}</text>'
        )
        origin_y = top + margin_t
        parts.append(
            f'<line x1="{margin_l}" y1="{origin_y}" x2="{margin_l}" y2="{origin_y + plot_h}" stroke="#ccc"/>'
        )
        parts.append(
            f'<line x1="{margin_l}" y1="{origin_y + plot_h}" x2="{margin_l + plot_w}" '
            f'y2="{origin_y + plot_h}" stroke="#ccc"/>'
        )
        for tick in (0, 0.5, 1):
            y = origin_y + (1 - tick) * plot_h
            parts.append(
                f'<text x="{margin_l - 8}" y="{y + 4}" text-anchor="end" '
                f'font-family="Segoe UI, sans-serif" font-size="11" fill="#555">{tick:.0%}</text>'
            )
        names = [row["name"].split()[0] for row in rows]
        for i, name in enumerate(names):
            x = margin_l + (0 if len(rows) == 1 else i * plot_w / (len(rows) - 1))
            parts.append(
                f'<text x="{x}" y="{origin_y + plot_h + 18}" text-anchor="middle" '
                f'font-family="Segoe UI, sans-serif" font-size="11" fill="#333">{name}</text>'
            )
        for key, color in colors.items():
            points = []
            for i, row in enumerate(rows):
                x = margin_l + (0 if len(rows) == 1 else i * plot_w / (len(rows) - 1))
                y = origin_y + (1 - row[key]) * plot_h
                points.append(f"{x:.1f},{y:.1f}")
            parts.append(
                f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="{" ".join(points)}"/>'
            )
        knee = payload["operating_point"]["level"]
        knee_row = next(row for row in rows if row["level"] == knee)
        kx = margin_l + (0 if len(rows) == 1 else knee * plot_w / (len(rows) - 1))
        ky = origin_y + (1 - knee_row["attack_block_rate"]) * plot_h
        parts.append(f'<circle cx="{kx:.1f}" cy="{ky:.1f}" r="5" fill="#9b2226"/>')
    legend_y = panel_h * 2 + 8
    legend_x = margin_l
    for key, color in colors.items():
        parts.append(f'<rect x="{legend_x}" y="{legend_y - 10}" width="14" height="8" fill="{color}"/>')
        parts.append(
            f'<text x="{legend_x + 18}" y="{legend_y - 2}" font-family="Segoe UI, sans-serif" '
            f'font-size="12" fill="#222">{labels[key]}</text>'
        )
        legend_x += 210
    parts.append("</svg>")
    return "\n".join(parts)


def _title(mode: str) -> str:
    if mode == "vulnerable":
        return "Vulnerable stand-ins (prefix check, symlink follow, open fetch)"
    return "Patched stand-ins (canonical root, public http only)"


def _pct(value: float) -> str:
    return f"{value:.1%}"


def _report(payload: dict) -> str:
    point = payload["operating_point"]
    lines = [
        "# Wiggle-room proof of concept",
        "",
        payload["narrative"],
        "",
        f"Operating point: **{point['name']}**. Selection rule: {point['rule']}.",
        "",
        "## Curve",
        "",
        "| Level | Vulnerable block | Vulnerable held-out | Patched block | Patched held-out | Train |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    patched = {row["level"]: row for row in payload["modes"]["patched"]}
    for row in payload["modes"]["vulnerable"]:
        other = patched[row["level"]]
        lines.append(
            f"| {row['name']} | {_pct(row['attack_block_rate'])} | {_pct(row['heldout_success_rate'])} | "
            f"{_pct(other['attack_block_rate'])} | {_pct(other['heldout_success_rate'])} | "
            f"{_pct(row['train_success_rate'])} |"
        )
    lines.extend(
        [
            "",
            "Block is the share of attack probes whose effect did not occur. Held-out is the share of tasks outside the training set whose oracle passed. Train is the share of tasks the policy was derived from.",
            "",
            "## Envelopes on the probe lattice",
            "",
            "| Quantity | Vulnerable | Patched |",
            "| --- | ---: | ---: |",
        ]
    )
    keys = [
        ("lattice", "Lattice size"),
        ("declared_schema", "Inside declared schema"),
        ("declared_intent", "Inside declared intent"),
        ("reachable", "Reachable"),
        ("needed_and_reachable", "Reachable and needed"),
        ("reachable_outside_declared_intent", "Reachable outside declared intent"),
        ("reachable_inside_intent_not_needed", "Reachable inside intent, outside needed"),
    ]
    for key, label in keys:
        lines.append(
            f"| {label} | {payload['envelopes']['vulnerable'][key]} | {payload['envelopes']['patched'][key]} |"
        )
    lines.extend(
        [
            "",
            f"Excess as a fraction of reachable probes: vulnerable {_pct(payload['envelopes']['vulnerable']['excess_fraction_of_reachable'])}, patched {_pct(payload['envelopes']['patched']['excess_fraction_of_reachable'])}.",
            "",
            "## Probe outcomes",
            "",
            "First level at which the probe effect is blocked. A dash means the effect still occurs at L5.",
            "",
            "| Probe | Kind | Vulnerable | Patched |",
            "| --- | --- | --- | --- |",
        ]
    )
    ids = []
    seen = set()
    for row in payload["probes"]:
        if row["id"] not in seen:
            seen.add(row["id"])
            ids.append(row["id"])
    for probe_id in ids:
        kind = next(row["kind"] for row in payload["probes"] if row["id"] == probe_id)
        lines.append(
            f"| `{probe_id}` | {kind} | {_first(payload, probe_id, 'vulnerable')} | {_first(payload, probe_id, 'patched')} |"
        )
    profile = payload["profile"]
    lines.extend(
        [
            "",
            "## Needed profile derived from training traces",
            "",
            f"- Tools: {', '.join(profile['tools'])}",
            f"- Read directories: {', '.join(profile['read_dirs'])}",
            f"- Write directories: {', '.join(profile['write_dirs'])}",
            f"- Write suffixes: {', '.join(profile['write_exts'])}",
            f"- Fetch hosts: {', '.join(profile['hosts'])}",
            f"- Fetch segments: {', '.join(profile['segments'])}",
            f"- Exact resources: {profile['exact_count']}",
            f"- Ancestor equals configured root: {profile['ancestor_equals_declared_root']}",
            "",
            "## Scanner stand-in",
            "",
            (
                f"The schema heuristic flags every attack probe ({_pct(payload['scanner']['recall_on_attacks'])} recall) "
                f"and also flags {_pct(payload['scanner']['false_positive_rate_on_needed_controls'])} of needed controls. "
                f"{point['name']} blocks {_pct(payload['scanner']['policy_attack_block_rate'])} of attack probes and "
                f"{_pct(payload['scanner']['policy_false_positive_rate_on_needed_controls'])} of needed controls, "
                f"with held-out success {_pct(payload['scanner']['policy_heldout_success_rate'])}."
            ),
            "",
            "## Scope",
            "",
            "- The caller is scripted. Repetitions change path spelling (`C:\\...` versus `C:/...`) and do not sample an LLM.",
            "- Filesystem and fetch behavior are local stand-ins. Fetch answers come from an in-process page map. No packets are sent.",
            "- Vulnerable filesystem mode is the public prefix-check and symlink-follow classes, confined to this sandbox.",
            "- The probe lattice is finite. Envelope sizes are shares of that lattice.",
            "- Needed is defined on tool arguments. Names that appear in a directory listing do not become needed resources until a later call uses them.",
            f"- Symlink probes included: {payload['symlink_supported']}.",
            "",
            "Regenerate with `python -m wiggle --out artifacts`.",
            "",
        ]
    )
    return "\n".join(lines)


def _first(payload: dict, probe_id: str, mode: str) -> str:
    rows = [
        row
        for row in payload["probes"]
        if row["id"] == probe_id and row["mode"] == mode and row["blocked"]
    ]
    if not rows:
        return "—"
    level = min(row["level"] for row in rows)
    return f"L{level}"
