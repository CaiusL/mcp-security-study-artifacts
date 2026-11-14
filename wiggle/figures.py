"""Report figures, drawn only from generated artifacts (roadmap M6.2).

`python -m wiggle.figures` reads `artifacts/stage2/pooled.json` and
`artifacts/stage3-birth/<model>/record.json` and writes static SVG figures to
`artifacts/figures/`. No figure is drawn by hand: rerun this after the
artifacts change. Standard library only. Each mark carries an SVG <title>, so a
browser shows its count on hover; the printed report reads the direct labels.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]

# Reference palette slots 1 and 2 (light), validated as a pair; text and grid tokens.
SERIES = ("#2a78d6", "#eb6834")
SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
MUTED = "#52514e"
GRID = "#e4e3de"
FONT = "font-family='Inter, Helvetica, Arial, sans-serif'"


def _rate(cell: dict) -> float:
    return cell["hits"] / cell["total"] if cell["total"] else 0.0


def _interval(cell: dict) -> tuple[float, float] | None:
    interval = cell.get("wilson")
    return None if not interval else (interval["low"], interval["high"])


def _count(cell: dict) -> str:
    return f"{cell['hits']}/{cell['total']}"


def _svg(width: int, height: int, body: list[str], title: str) -> str:
    return "\n".join(
        [
            f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}' {FONT}>",
            f"<title>{escape(title)}</title>",
            f"<rect width='{width}' height='{height}' fill='{SURFACE}'/>",
            *body,
            "</svg>",
            "",
        ]
    )


def _text(x: float, y: float, text: str, size: int = 12, color: str = TEXT, anchor: str = "start", weight: str = "normal") -> str:
    return (
        f"<text x='{x:.1f}' y='{y:.1f}' font-size='{size}' fill='{color}' text-anchor='{anchor}' "
        f"font-weight='{weight}'>{escape(text)}</text>"
    )


def _legend(x: float, y: float, models: list[str]) -> list[str]:
    body = []
    for index, model in enumerate(models):
        left = x + index * 170
        body.append(f"<circle cx='{left + 5}' cy='{y - 4}' r='5' fill='{SERIES[index]}'/>")
        body.append(_text(left + 15, y, model, 12, MUTED))
    return body


def _percent_axis(left: float, top: float, width: float, height: float, title: str, maximum: int = 100) -> list[str]:
    body = [_text(left, top - 12, title, 12, TEXT, weight="600")]
    for index in range(5):
        x = left + width * index / 4
        body.append(f"<line x1='{x:.1f}' y1='{top}' x2='{x:.1f}' y2='{top + height}' stroke='{GRID}' stroke-width='1'/>")
        body.append(_text(x, top + height + 16, f"{maximum * index / 4:g}%", 11, MUTED, "middle"))
    return body


def layers_figure(pooled: dict, arm: str = "patched") -> str:
    """Two panels on one row axis: attacks left open, held-out tasks kept. One dot per model, Wilson whiskers."""
    models = [row["model"] for row in pooled["models"]]
    alone = pooled["layers"][arm]["alone"]
    stacked = pooled["layers"][arm]["stacked"]
    names = {
        "a": "(a) zgScanner",
        "b": "(b) server checks",
        "c": "(c) Needed ladder, operating point",
        "d": "(d) task policy",
        "e": "(e) rule R1",
    }
    rows = [(names.get(name, name), alone[name]) for name in alone]
    last = list(stacked)[-1]
    rows.append(("all five, stacked", stacked[last]))
    worst = max(_interval(cell["per_model"][model]["asr"])[1] for _label, cell in rows for model in models)
    asr_max = 20 if worst <= 0.2 else 40 if worst <= 0.4 else 100
    width, row_height, left, panel, gap, top = 940, 34, 270, 280, 50, 78
    height = top + row_height * len(rows) + 50
    body = [
        _text(24, 28, f"Stage 2 defense layers, {arm} arm", 15, TEXT, weight="600"),
        *_legend(24, 52, models),
    ]
    panels = (
        ("asr", f"Attacks left open, 0-{asr_max}% (lower is better)", left, asr_max),
        ("heldout", "Held-out tasks kept, 0-100% (higher is better)", left + panel + gap, 100),
    )
    for key, title, x0, maximum in panels:
        body.extend(_percent_axis(x0, top, panel, row_height * len(rows), title, maximum))
    for index, (label, cell) in enumerate(rows):
        y = top + row_height * index + row_height / 2
        body.append(_text(24, y + 4, label, 12, TEXT))
        for key, _title, x0, maximum in panels:
            scale = panel * 100 / maximum
            for series, model in enumerate(models):
                value = cell["per_model"][model][key]
                offset = (series - (len(models) - 1) / 2) * 9
                cx = x0 + scale * _rate(value)
                interval = _interval(value)
                if interval:
                    body.append(
                        f"<line x1='{x0 + scale * interval[0]:.1f}' y1='{y + offset:.1f}' x2='{x0 + scale * min(interval[1], maximum / 100):.1f}' "
                        f"y2='{y + offset:.1f}' stroke='{SERIES[series]}' stroke-width='2' stroke-linecap='round'/>"
                    )
                body.append(
                    f"<circle cx='{cx:.1f}' cy='{y + offset:.1f}' r='4.5' fill='{SERIES[series]}' stroke='{SURFACE}' stroke-width='2'>"
                    f"<title>{escape(model)}: {escape(label)}, {_count(value)}</title></circle>"
                )
    body.append(_text(24, height - 14, "Dots: rate per model; whiskers: Wilson 95% interval. Source: artifacts/stage2/pooled.json.", 11, MUTED))
    return _svg(width, height, body, f"Stage 2 defense layers, {arm} arm")


def ladder_figure(pooled: dict) -> str:
    """Security–usability curve per model: held-out kept (x) against attacks blocked (y), L0 to L5."""
    models = [row["model"] for row in pooled["models"]]
    width, height, left, top, plot_w, plot_h = 640, 470, 80, 80, 500, 320
    lowest = min(_rate(row["per_model"][model]["attack_block"]) for row in pooled["ladder"] for model in models)
    floor = 80 if lowest >= 0.8 else 60 if lowest >= 0.6 else 0
    span = 100 - floor
    body = [
        _text(24, 28, "Needed ladder, patched arm: security against usability", 15, TEXT, weight="600"),
        *_legend(24, 52, models),
    ]
    for index in range(5):
        x = left + plot_w * index / 4
        y = top + plot_h - plot_h * index / 4
        body.append(f"<line x1='{x:.1f}' y1='{top}' x2='{x:.1f}' y2='{top + plot_h}' stroke='{GRID}'/>")
        body.append(f"<line x1='{left}' y1='{y:.1f}' x2='{left + plot_w}' y2='{y:.1f}' stroke='{GRID}'/>")
        body.append(_text(x, top + plot_h + 16, f"{25 * index}%", 11, MUTED, "middle"))
        body.append(_text(left - 8, y + 4, f"{floor + span * index / 4:g}%", 11, MUTED, "end"))
    body.append(_text(left + plot_w / 2, top + plot_h + 38, "Held-out tasks kept", 12, TEXT, "middle"))
    body.append(
        f"<text x='22' y='{top + plot_h / 2:.1f}' font-size='12' fill='{TEXT}' text-anchor='middle' "
        f"transform='rotate(-90 22 {top + plot_h / 2:.1f})'>Attacks blocked (axis starts at {floor}%)</text>"
    )
    for series, model in enumerate(models):
        points = []
        for row in pooled["ladder"]:
            cell = row["per_model"][model]
            blocked = (100 * _rate(cell["attack_block"]) - floor) / span
            points.append((left + plot_w * _rate(cell["heldout"]), top + plot_h - plot_h * blocked, row, cell))
        path = " ".join(f"{x:.1f},{y:.1f}" for x, y, _row, _cell in points)
        body.append(f"<polyline points='{path}' fill='none' stroke='{SERIES[series]}' stroke-width='2'/>")
        for x, y, row, cell in points:
            body.append(
                f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4.5' fill='{SERIES[series]}' stroke='{SURFACE}' stroke-width='2'>"
                f"<title>{escape(model)} {escape(row['name'])}: blocked {_count(cell['attack_block'])}, held-out {_count(cell['heldout'])}</title></circle>"
            )
            if series == len(models) - 1:
                body.append(_text(x + 7, y + 16, row["name"].split()[0], 11, MUTED))
    body.append(_text(24, height - 14, "Each point is one ladder level, L0 (right) to L5 (left). Source: artifacts/stage2/pooled.json.", 11, MUTED))
    return _svg(width, height, body, "Needed ladder security–usability curve")


def birth_figure(record: dict) -> str:
    """Birth arm against its baseline: one series, horizontal bars with Wilson whiskers."""
    from wiggle.replay import wilson

    def cell(row: dict) -> dict:
        return {**row, "wilson": wilson(row["hits"], row["total"])}

    rows = [
        ("Poisoned policy adds a permission over clean", cell(record["widened_beyond_clean"])),
        ("Second clean policy adds one over the first", cell(record["baseline"]["repeat_added_beyond_clean"])),
        ("Added permission names the injected target", cell(record["widened_toward_target"])),
    ]
    width, row_height, left, panel, top = 820, 40, 330, 420, 70
    height = top + row_height * len(rows) + 52
    body = [_text(24, 28, f"Stage 3 birth arm: {record['model']}, layer (d) policy", 15, TEXT, weight="600")]
    maximum = 20 if all((_interval(value) or (0, 0))[1] <= 0.2 for _label, value in rows) else 100
    scale = panel * 100 / maximum
    body.extend(_percent_axis(left, top, panel, row_height * len(rows), f"Share of requests, 0-{maximum}%", maximum))
    for index, (label, value) in enumerate(rows):
        y = top + row_height * index + row_height / 2
        body.append(_text(24, y + 4, label, 12, TEXT))
        bar = scale * _rate(value)
        if bar > 0:
            body.append(
                f"<rect x='{left}' y='{y - 8:.1f}' width='{bar:.1f}' height='16' rx='4' fill='{SERIES[0]}'>"
                f"<title>{escape(label)}: {_count(value)}</title></rect>"
            )
        low, high = _interval(value) or (0.0, 0.0)
        body.append(f"<line x1='{left + scale * low:.1f}' y1='{y:.1f}' x2='{left + scale * high:.1f}' y2='{y:.1f}' stroke='{TEXT}' stroke-width='1.5'/>")
        body.append(_text(left + max(bar, scale * high) + 8, y + 4, _count(value), 11, MUTED))
    body.append(_text(24, height - 14, "Bars: share; lines: Wilson 95% interval. Source: artifacts/stage3-birth/" + record["model"] + "/record.json.", 11, MUTED))
    return _svg(width, height, body, "Stage 3 birth arm against its baseline")


def write_figures(out: Path) -> list[Path]:
    pooled = json.loads((ROOT / "artifacts" / "stage2" / "pooled.json").read_text(encoding="utf-8"))
    out.mkdir(parents=True, exist_ok=True)
    figures = {
        "stage2-layers-patched.svg": layers_figure(pooled, "patched"),
        "stage2-layers-vulnerable.svg": layers_figure(pooled, "vulnerable"),
        "stage2-ladder.svg": ladder_figure(pooled),
    }
    for record_path in sorted((ROOT / "artifacts" / "stage3-birth").glob("*/record.json")):
        record = json.loads(record_path.read_text(encoding="utf-8"))
        if "baseline" in record:
            figures[f"birth-{record_path.parent.name}.svg"] = birth_figure(record)
    written = []
    for name, svg in figures.items():
        path = out / name
        path.write_text(svg, encoding="utf-8")
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Write the report figures from the generated artifacts.")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "figures")
    args = parser.parse_args(argv)
    for path in write_figures(args.out):
        print(path)


if __name__ == "__main__":
    main()
