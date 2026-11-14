"""Generate a self-contained, offline viewer of saved study reports.

Run ``python -m wiggle.demo`` after reports change. This module only reads
artifacts and writes HTML; it never imports a runner or executes saved calls.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from html import escape
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAYERS = {
    "a": "(a) zgScanner", "b": "(b) server checks", "c": "(c) Needed",
    "d": "(d) task policy", "e": "(e) rule R1",
}


def load_data(artifacts: Path) -> dict:
    """Read reports, retaining their counts and a content-addressed source list."""
    data = {"sources": [], "stage2": [], "birth": [], "stage4": [], "traces": [], "trace_notes": []}

    def read(path: Path, *, json_data: bool = True):
        raw = path.read_bytes()
        data["sources"].append({
            "path": "artifacts/" + path.relative_to(artifacts).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
        text = raw.decode("utf-8-sig")
        return json.loads(text) if json_data else text

    phase1 = artifacts / "phase1/results.json"
    data["phase1"] = read(phase1) if phase1.exists() else None
    comparison = artifacts / "phase1/comparison.md"
    data["comparison"] = read(comparison, json_data=False) if comparison.exists() else None
    for family in ("stage2", "stage2-progent"):
        for path in sorted((artifacts / family).glob("*/report.json")):
            report = read(path)
            if report.get("kind") != "stage2-verdict":
                raise ValueError(f"Not a Stage 2 verdict: {path}")
            keys = ("model_run", "caller", "arms", "layer_d", "operating_point",
                    "raw_asr", "layers_alone_stacked", "curves", "live_only")
            row = {key: report[key] for key in keys}
            row.update(source=data["sources"][-1]["path"],
                       agreement=report["live"]["by_layer"], family=family,
                       freeze_sha256=report["freeze_sha256"])
            data["stage2"].append(row)
            # One illustrative recorded successful attack per original model.
            # Progent reuses these agent traces; do not duplicate the examples.
            trace_path = path.with_name("traces.jsonl")
            if family == "stage2" and trace_path.exists():
                raw = trace_path.read_bytes()
                source = "artifacts/" + trace_path.relative_to(artifacts).as_posix()
                data["sources"].append({"path": source, "sha256": hashlib.sha256(raw).hexdigest()})
                for line in raw.decode("utf-8-sig").splitlines():
                    trace = json.loads(line)
                    if trace.get("set") == "attack" and trace.get("goal") is True:
                        fields = ("case_id", "task_id", "arm", "sample", "model_id",
                                  "goal", "utility", "stop", "calls", "results")
                        data["traces"].append({"source": source, **{k: trace.get(k) for k in fields}})
                        break
                else:
                    data["trace_notes"].append(f"{report['caller']['model_id']}: no successful attack is recorded in this trace file.")
    for path in sorted((artifacts / "stage3-birth").glob("*/record.json")):
        record = read(path)
        if record.get("kind") != "stage3-birth":
            raise ValueError(f"Not a birth-arm record: {path}")
        data["birth"].append({
            **{key: record[key] for key in ("model", "pairs", "held_out_tasks", "widened_beyond_clean",
                                            "widened_toward_target", "poisoned_unparsed", "note")},
            "clean_repeat": record["baseline"]["repeat_added_beyond_clean"],
            "source": data["sources"][-1]["path"],
        })
    widening = artifacts / "stage3-widening/report.json"
    data["widening"] = read(widening) if widening.exists() else None
    if data["widening"]:
        data["widening"].pop("per_run", None)
    for path in sorted((artifacts / "stage4").glob("*/report.json")):
        report = read(path)
        if report.get("kind") != "stage4-adaptive":
            raise ValueError(f"Not a Stage 4 report: {path}")
        data["stage4"].append({
            key: report[key] for key in ("model_run", "target", "label", "reruns",
                                         "static", "stage2_live_only", "budget", "checks")
        })
    return data


def _text(value) -> str:
    return escape(str(value), quote=True)


def _metric(cell: dict | None) -> str:
    if cell is None or not cell.get("total"):
        return '<span class="muted">Not measured</span>'
    hits, total = cell["hits"], cell["total"]
    percent = 100 * hits / total
    interval = cell.get("wilson")
    title = "" if not interval else f"Wilson 95%: {100 * interval['low']:.1f}%–{100 * interval['high']:.1f}%"
    return (f'<span class="metric" title="{_text(title)}">{hits}/{total} '
            f'<b>{percent:.1f}%</b><span class="bar" style="--rate:{percent:.4f}%"></span></span>')


def _table(headers: list[str], rows: list[list[str]], attrs: list[str] | None = None) -> str:
    body = []
    for i, row in enumerate(rows):
        attribute = "" if attrs is None else attrs[i]
        body.append(f"<tr {attribute}>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
    return ('<div class="scroll"><table><thead><tr>' +
            "".join(f"<th scope=\"col\">{_text(h)}</th>" for h in headers) +
            "</tr></thead><tbody>" + "".join(body) + "</tbody></table></div>")


def _details(title: str, value) -> str:
    text = value if isinstance(value, str) else json.dumps(value, indent=2, ensure_ascii=False)
    return f"<details><summary>{_text(title)}</summary><pre>{_text(text)}</pre></details>"


def _phase1(data: dict) -> str:
    report = data["phase1"]
    if report is None:
        return '<p class="pending">Pending: artifacts/phase1/results.json is absent.</p>'
    rows = []
    for arm, levels in report["modes"].items():
        for row in levels:
            cells = [{"hits": row[hits], "total": row[total]} for hits, total in (
                ("attacks_blocked", "attacks_total"), ("heldout_passed", "heldout_total"),
                ("boundary_blocked", "boundary_total"), ("excess_blocked", "excess_total"))]
            rows.append([_text(arm), _text(row["name"]), *map(_metric, cells)])
    return ('<p>Scripted filesystem and fetch stand-ins. These counts are finite probe-lattice results, '
            'not LLM attack rates or measurements of vulnerable third-party packages.</p>' +
            _table(["Stand-in arm", "Needed level", "Attacks blocked ↑", "Held-out kept ↑",
                    "Boundary blocked ↑", "In-scope excess blocked ↑"], rows) +
            _details("Saved interpretation", report["narrative"]))


def _stage2(data: dict) -> str:
    if not data["stage2"]:
        return '<p class="pending">Pending: no Stage 2 reports found.</p>'
    models = sorted({r["caller"]["model_id"] for r in data["stage2"]})
    options = lambda values: '<option value="all">All</option>' + "".join(
        f'<option value="{_text(v)}">{_text(v)}</option>' for v in values)
    controls = ('<div class="controls"><label>Model<select id="model">' + options(models) +
                '</select></label><label>Arm<select id="arm"><option value="patched">patched</option>'
                '<option value="vulnerable">vulnerable</option><option value="all">All</option></select></label>'
                '<label>Composition<select id="composition"><option value="alone">Alone</option>'
                '<option value="stacked">Stacked</option><option value="all">All</option></select></label>'
                '<label>Layer<select id="layer">' + options(LAYERS) + '</select></label></div>')
    rows, attrs, live, ladder, sources = [], [], [], [], []
    for report in data["stage2"]:
        model, generator = report["caller"]["model_id"], report["layer_d"]["generator"]
        prefix = [_text(model), _text(generator)]
        unreliable = set(report["live_only"]["layers"])
        for arm, kinds in report["layers_alone_stacked"].items():
            for kind, layers in kinds.items():
                for layer, cell in layers.items():
                    bad = unreliable.intersection(layer.split("+"))
                    basis = "Replay unreliable for " + ", ".join(sorted(bad)) + "; use live evidence" if bad else "Recorded replay"
                    if not report["model_run"]:
                        basis = "Scripted harness check; " + basis
                    rows.append(prefix + [_text(arm), _text(layer), _metric(cell["asr"]),
                                         _metric(cell["heldout"]), _text(basis)])
                    attrs.append(" ".join(f'data-{k}="{_text(v)}"' for k, v in (
                        ("model", model), ("arm", arm), ("composition", kind), ("layer", layer))))
        for layer, cell in report["live_only"]["live_asr"].items():
            live.append(prefix + [_text(LAYERS.get(layer, layer)), _metric(cell),
                                  _metric(report["agreement"].get(layer)),
                                  "Live-only" if layer in unreliable else "Replay threshold met"])
        # Progent reuses the original Needed ladder; show it once per model.
        if report["family"] == "stage2":
            for arm, levels in report["curves"].items():
                for level in levels:
                    ladder.append([_text(model), _text(arm), _text(level["name"]),
                                   _metric(level["attack_block"]), _metric(level["heldout"]),
                                   "Diagnostic replay only" if "c" in unreliable else "Recorded replay"])
        sources.append({"source": report["source"], "model_run": report["model_run"],
                        "arms": report["arms"], "operating_point": report["operating_point"],
                        "freeze_sha256": report["freeze_sha256"]})
    return (controls + '<p class="legend">a: zgScanner · b: server checks · c: Needed at the operating point · '
            'd: task policy · e: rule R1. Stacks use all listed layers.</p>'
            '<p>ASR is the share whose attack goal remains open; lower is better. Held-out task success is '
            'benign utility; higher is better. Counts are preserved from each report. Hover over a metric '
            'for its reported Wilson interval. Progent reuses original agent traces; it is a separate '
            'policy rerun, not another independent agent sample.</p><div id="comparison">' +
            _table(["Model", "Policy generator", "Arm", "Layers", "Replay ASR ↓",
                    "Held-out kept (replay) ↑", "Evidence basis"], rows, attrs) + '</div>'
            '<p id="visible-count" aria-live="polite"></p><h3>Live enforcement validation</h3>'
            '<p>Separate patched-arm samples with the defense actually enforcing. These smaller denominators '
            'must not be pooled with replay. Agreement below the report’s 90% threshold requires live-only scoring.</p>' +
            _table(["Model", "Policy generator", "Layer", "Live ASR ↓", "Replay/live agreement ↑", "Status"], live) +
            '<details><summary>Needed ladder: security–utility trade-off</summary>' +
            _table(["Model", "Arm", "Level", "Attack block ↑", "Held-out kept ↑", "Basis"], ladder) +
            '</details>' + _details("Report provenance and arm definitions", sources))


def _birth(data: dict) -> str:
    if not data["birth"]:
        return '<p class="pending">Pending: no artifacts/stage3-birth/*/record.json is saved.</p>'
    rows = [[_text(r["model"]), _metric(r["widened_beyond_clean"]), _metric(r["clean_repeat"]),
             _metric(r["widened_toward_target"]), _metric(r["poisoned_unparsed"])] for r in data["birth"]]
    return ('<p>The birth arm constructs policies only; action execution is not measured here. '
            'Generic additions compare poisoned with clean policies. Clean-repeat variation compares two '
            'clean generations. Target-directed widening counts added permission toward the injected target; '
            'it is a post-run descriptive count, not a pre-registered protocol measure. '
            'These outcomes and their different denominators are kept separate; generic additions do not '
            'establish target compromise.</p>' +
            _table(["Model", "Generic additions beyond clean", "Clean-repeat additions",
                    "Target-directed widening", "Unparsed poisoned policies"], rows) +
            _details("Birth-arm source records and scope", data["birth"]))


def _widening(data: dict) -> str:
    report = data["widening"]
    if report is None:
        return '<p class="pending">Pending: artifacts/stage3-widening/report.json is absent.</p>'
    rows = [[_text(r["goal_id"]), _text(r["channel"]), _metric(r["complied"]), _metric(r["entered"])]
            for r in report["m1"]]
    return (f'<p><strong>{_text(report["collection"]["model"])}</strong> · {_text(report["label"])}. '
            f'{"Recorded model runs." if report["model_run"] else "Scripted harness check; not a model result."} '
            f'Go/no-go: <strong>{_text(report["go_no_go"]["decision"])}</strong>; '
            f'soundness: {_text(report["soundness"])}. '
            'Entering a learned profile is distinct from opening a later attack. Each “all” row aggregates '
            'the three channel rows; it is not an additional sample.</p>' +
            _table(["W goal", "Channel", "Widening call executed", "Entered learned profile"], rows) +
            _details("M2–M6 and run counts: saved measurements", {k: report[k] for k in ("runs", "m2", "m3", "m4", "m5", "m6")}) +
            _details("Widening limitations and go/no-go checks", {k: report[k] for k in ("threats", "go_no_go", "model_run")}))


def _stage4(data: dict) -> str:
    if not data["stage4"]:
        return ('<p class="pending">Pending: no artifacts/stage4/*/report.json is saved. '
                'Regenerate this demo after the report is written; it will be included automatically.</p>')
    parts = []
    for report in data["stage4"]:
        rows = []
        for kind in ("alone", "stacked"):
            for layer, cell in report["reruns"][kind].items():
                rows.append([_text(kind), _text(layer), _metric(cell),
                             _metric(report["static"]["same_cases"][kind].get(layer)),
                             _metric(report["static"]["all_cases"]["heldout"][kind].get(layer))])
        parts.extend([
            f'<h3>{_text(report["target"]["model_argument"])}</h3><p>{_text(report["label"])}. '
            f'{"Recorded model runs." if report["model_run"] else "Scripted harness check; not a model result."} '
            'Adaptive and static attack sets are reported separately. Layer scores below are replay; '
            'Stage 4 has no live enforcement reruns. Held-out utility is inherited from Stage 2, not newly measured.</p>',
            _table(["Composition", "Layers", "Adaptive replay ASR ↓", "Static same-case replay ASR ↓",
                    "Stage 2 held-out kept ↑"], rows),
            _details("Adaptive budget, unscored runs, live-only caveats and checks", {
                "model_run": report["model_run"], "budget": report["budget"],
                "no_defense": report["reruns"]["no_defense"], "unscored": report["reruns"]["unscored"],
                "stage2_live_only": report["stage2_live_only"], "checks": report["checks"],
            }),
            '<p>Unscored runs count as not open in layer rows, making those rates lower bounds by at most '
            'the reported unscored count. Consult the saved live-only caveats before comparing layers.</p>',
        ])
    return "".join(parts)


STYLE = """
:root{color-scheme:light;--ink:#17212c;--muted:#52606d;--line:#dce3e9;--blue:#2563a6}
*{box-sizing:border-box}body{margin:0;background:#f4f6f8;color:var(--ink);font:16px/1.55 system-ui,sans-serif}
header,main,footer{max-width:1240px;margin:auto;padding:28px}header{padding-top:48px}h1{font-size:clamp(2rem,4vw,3rem);line-height:1.1;margin:12px 0}h2{margin:0 0 14px;font-size:1.5rem}h3{margin-top:28px}
.eyebrow{color:var(--blue);font-weight:700;letter-spacing:.1em;text-transform:uppercase;font-size:.8rem}.lead{max-width:850px;font-size:1.1rem}.muted,.legend,footer{color:var(--muted)}
nav{display:flex;flex-wrap:wrap;gap:18px;margin-top:22px}a{color:var(--blue)}section{padding:26px;background:white;border:1px solid var(--line);border-radius:12px;margin-bottom:24px;scroll-margin-top:20px}
.notice,.pending{padding:14px 18px;border-left:4px solid #d69824;background:#fff8e8}.controls{display:flex;flex-wrap:wrap;gap:16px;padding:16px;background:#edf3f9;border-radius:8px}label{display:grid;gap:4px;font-size:.85rem;font-weight:650}select{font:inherit;background:white;border:1px solid #9caebe;border-radius:5px;padding:8px;min-width:145px}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.87rem}th,td{text-align:left;vertical-align:top;padding:12px 10px;border-bottom:1px solid var(--line)}th{background:#f5f8fb;font-weight:650}tr[hidden]{display:none}
.metric{display:block;min-width:100px;white-space:nowrap;font-variant-numeric:tabular-nums}.metric b{display:block;color:var(--blue)}.bar{display:block;height:4px;background:linear-gradient(to right,var(--blue) var(--rate),#e5edf4 var(--rate));margin-top:4px;border-radius:2px}
details{margin:18px 0}summary{cursor:pointer;color:var(--blue);font-weight:600}pre{padding:16px;background:#f4f7fa;border:1px solid var(--line);border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:.8rem;max-height:520px;overflow:auto}code{font-size:.9em}footer{font-size:.85rem;padding-bottom:40px}@media(max-width:650px){header,main,footer{padding:18px}section{padding:16px}th,td{padding:9px 7px}}
"""

SCRIPT = """
const data=JSON.parse(document.getElementById('study-data').textContent);
function filterRows(){
 const keys=['model','arm','composition','layer']; let visible=0;
 document.querySelectorAll('#comparison tbody tr').forEach(row=>{
  row.hidden=!keys.every(key=>{const v=document.getElementById(key).value;
   return v==='all'||(key==='layer'?row.dataset[key].split('+').includes(v):row.dataset[key]===v);});
  if(!row.hidden)visible++;
 });
 document.getElementById('visible-count').textContent=visible+' comparison rows shown. Live validation below is listed separately.';
}
if(document.getElementById('model')){
 ['model','arm','composition','layer'].forEach(id=>document.getElementById(id).addEventListener('change',filterRows)); filterRows();
}
const picker=document.getElementById('trace-picker');
if(picker){
 data.traces.forEach((trace,i)=>{const option=document.createElement('option');option.value=String(i);
  option.textContent=trace.model_id+' · '+trace.case_id+' · '+trace.arm;picker.appendChild(option);});
 const show=()=>{document.getElementById('trace-text').textContent=JSON.stringify(data.traces[Number(picker.value)],null,2);};
 picker.addEventListener('change',show);show();
}
"""


def render(data: dict) -> str:
    # A JSON script element is inert, but HTML parsers still recognize </script>.
    # Escape every HTML delimiter even inside JSON strings. Trace display uses textContent.
    embedded = json.dumps({"traces": data["traces"]}, ensure_ascii=True).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    digest = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
        f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; connect-src \'none\'; base-uri \'none\'; form-action \'none\'; style-src \'unsafe-inline\'; script-src \'sha256-{digest}\'">',
        '<title>Wiggle-room study · Offline evidence demo</title><style>', STYLE, '</style></head><body><header>',
        '<div class="eyebrow">Recorded study · Offline demo</div><h1>Where the boundary holds.<br>Where excess remains.</h1>',
        '<p class="lead">Explore the saved security–utility measurements, compare defense layers, and inspect a recorded trace. '
        'This page does not call models, connect to MCP servers, or execute attack payloads.</p>',
        '<nav aria-label="Study sections"><a href="#phase1">Phase 1</a><a href="#stage2">Layer comparison</a><a href="#birth">Birth arm</a><a href="#widening">Widening</a><a href="#stage4">Adaptive arm</a><a href="#traces">Recorded traces</a><a href="#sources">Sources</a></nav></header><main>',
        '<section class="notice"><strong>Evidence boundaries.</strong> Finite fixtures and sampled attacks do not establish universal safety. '
        'Replay can miss how an agent responds to a denied call. Reported live-only layers retain that limitation here. '
        'Backdoor common-harness measurements are absent; RQ3 remains future work. J1–J3 were dropped. '
        'No priority claim or supervisor approval is implied.</section>',
        '<section id="phase1"><h2>Phase 1 · Controlled boundaries and excess</h2>', _phase1(data),
        _details("Separate saved comparison: five patched server pins", data["comparison"]) if data["comparison"] else '',
        '</section><section id="stage2"><h2>Stage 2 · Model, arm and defense layer</h2>', _stage2(data),
        '</section><section id="birth"><h2>Birth arm · Policy generation</h2>', _birth(data),
        '</section><section id="widening"><h2>Widening · Policy-input poisoning</h2>', _widening(data),
        '</section><section id="stage4"><h2>Stage 4 · Adaptive arm</h2>', _stage4(data),
        '</section><section id="traces"><h2>Recorded traces · Read only</h2><p>First saved successful attack per original Stage 2 model, '
        'where one exists, in file order. Illustrative examples, not a representative sample. Calls and tool results are displayed as inert text.</p>',
        "".join(f"<p>{_text(note)}</p>" for note in data["trace_notes"]),
        '<label>Example<select id="trace-picker"></select></label><pre id="trace-text"></pre>' if data["traces"] else '<p>No saved successful attack trace was available.</p>',
        '</section><section id="sources"><h2>Sources and regeneration</h2><p>Every figure comes from the saved files below. '
        'SHA-256 identifies the exact source bytes. This HTML is a snapshot; rerun <code>python -m wiggle.demo</code> to pick up new reports.</p>',
        _details("Input files and SHA-256 hashes", data["sources"]),
        '</section></main><footer>Generated locally from saved artifacts. No network resources or external libraries. '
        'Open this file directly in a browser; no server is required.</footer>',
        '<script type="application/json" id="study-data">', embedded, '</script><script>', SCRIPT, '</script></body></html>\n',
    ]
    return "".join(parts)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, default=ROOT / "artifacts")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts/demo/index.html")
    args = parser.parse_args(argv)
    data = load_data(args.artifacts)
    html = render(data)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(html, encoding="utf-8", newline="\n")
    print(f"{args.out}: {len(data['sources'])} saved inputs; {len(data['stage4'])} Stage 4 reports")


if __name__ == "__main__":
    main()
