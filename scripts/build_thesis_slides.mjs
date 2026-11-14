// Repository defense deck. Run with the bundled Artifact Tool Node runtime.
// Required environment: PRESENTATIONS_SKILL_DIR, ARTIFACT_NODE_MODULES, ARTIFACT_PYTHON.
import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const root = process.cwd();
const skill = process.env.PRESENTATIONS_SKILL_DIR;
const modules = process.env.ARTIFACT_NODE_MODULES;
const python = process.env.ARTIFACT_PYTHON;
if (!skill || !modules || !python) throw new Error('Set PRESENTATIONS_SKILL_DIR, ARTIFACT_NODE_MODULES and ARTIFACT_PYTHON.');
process.env.RUNTIME_NODE_MODULES = modules;
const runtimeRequire = createRequire(path.join(modules, 'package.json'));
const { FileBlob, Presentation, PresentationFile } = await import(pathToFileURL(runtimeRequire.resolve('@oai/artifact-tool')).href);
const { finalizePresentation, resolvePresentationFont, applyPresentationChartFont } = await import(pathToFileURL(path.join(skill, 'container_tools/artifact_tool_utils.mjs')).href);
const font = resolvePresentationFont();
const out = path.join(root, 'artifacts/slides/output');
const build = path.join(root, 'artifacts/slides/.build');
await fs.mkdir(build, { recursive: true });
await fs.mkdir(out, { recursive: true });
const read = async p => JSON.parse(await fs.readFile(path.join(root, p), 'utf8'));
const models = ['qwen3.8-flash', 'deepseek-flash'];
const base = await Promise.all(models.map(m => read(`artifacts/stage2/${m}/report.json`)));
const progent = await Promise.all(models.map(m => read(`artifacts/stage2-progent/${m}/report.json`)));
const birth = await Promise.all(models.map(m => read(`artifacts/stage3-birth/${m}/record.json`)));
const widening = await read('artifacts/stage3-widening/report.json');
const adaptive = await read('artifacts/stage4/qwen3.8-flash/report.json');
const fraction = r => `${r.hits}/${r.total}`;
const layer = (r, k) => r.layers_alone_stacked.patched.alone[k];
const deck = Presentation.create({ slideSize: { width: 1280, height: 720 } });
const ink = '#162633', muted = '#51616D', teal = '#087F8C', rust = '#C45536', paper = '#F7F6F2';
const tableSlides = [], chartSlides = [];

function text(s, value, x, y, w, h, size = 28, color = ink, bold = false) {
  const box = s.shapes.add({ geometry: 'textbox', position: { left: x, top: y, width: w, height: h }, fill: 'none', line: { fill: 'none', width: 0 } });
  box.text = value;
  box.text.style = { typeface: font, fontSize: size, color, bold };
  return box;
}
function slide(title, notes, subtitle = '') {
  const s = deck.slides.add(); s.background.fill = paper;
  text(s, title, 70, 44, 1140, 105, 43, ink, true);
  if (subtitle) text(s, subtitle, 72, 155, 1136, 65, 25, muted);
  text(s, `${deck.slides.items.length}`, 1160, 666, 45, 30, 17, muted);
  s.speakerNotes.text = notes;
  return s;
}
function table(s, values, widths, y = 240, h = 300, fontSize = 26) {
  tableSlides.push(deck.slides.items.length);
  const t = s.tables.add({ rows: values.length, columns: values[0].length, left: 72, top: y, width: 1136, height: h, columnWidths: widths, values });
  t.borders.assign({ fill: '#D7DDD9', width: 0.7 });
  t.cells.block({ row: 0, column: 0, rowCount: values.length, columnCount: values[0].length }).assign({
    fill: paper, textStyle: { typeface: font, fontSize, color: ink }, margins: { left: 13, right: 13, top: 12, bottom: 12 }
  });
  t.cells.block({ row: 0, column: 0, rowCount: 1, columnCount: values[0].length }).assign({ fill: ink, textStyle: { typeface: font, fontSize, color: '#FFFFFF', bold: true } });
  return t;
}
function note(s, value, y = 582) { text(s, value, 72, y, 1110, 72, 23, muted); }

{
  const s = deck.slides.add(); s.background.fill = ink;
  text(s, 'Unauthorized Agent Actions', 78, 140, 1110, 160, 66, '#FFFFFF', true);
  text(s, 'Excess MCP tool calls and a fine-tuning backdoor', 80, 340, 1090, 100, 34, '#C9DEDD');
  text(s, 'Thesis defense draft · 3 November 2026', 80, 580, 1050, 50, 24, '#C9DEDD');
  s.speakerNotes.text = 'Source: docs/writeup/. This is a thesis defense draft. Supervisor review, an independent human literature screen, and rehearsal are pending. The backdoor evidence is cited from the separate BadAgent artifact; it was not executed on this harness.';
}
{
  const s = slide('Three envelopes of tool authority', 'Sources: PROMPT.md; docs/methodology.md; docs/writeup/02-background.md. Declared is a contract, Reachable is measured on a finite lattice, and Needed is derived from successful benign training calls. No universal containment claim follows from these finite sets.');
  table(s, [['Envelope', 'What it answers'], ['Declared', 'What does the tool promise to allow?'], ['Reachable', 'Which effects can a caller obtain?'], ['Needed', 'Which calls did benign training tasks use?']], [260, 876], 205, 325);
  note(s, 'The study measures Reachable minus Needed, including excess that stays inside the declared scope.');
}
{
  const s = slide('Patching closes boundaries, not all excess', 'Source: artifacts/phase1/comparison.md, five patched real servers. These are finite-lattice probe counts, not a general security guarantee.', 'Five patched servers · finite probe lattice');
  table(s, [['Probe class', 'Observed result'], ['Boundary probes', '12/12 refused before a Needed policy'], ['In-scope excess probes', '19/19 performed at L0']], [470, 666], 245, 240);
  note(s, 'Both findings matter: the server can enforce its boundary while allowing actions the task never needs.');
}
{
  const s = slide('Scanners disagree on the same servers', 'Sources: bench/README.md; bench/scan-comparison/COMPARISON.md; bench/scan-comparison/zgscanner-current/README.md. Six public scanners and zgScanner examined five hosted servers read-only. Counts are flags, not validated malware prevalence. The hand review motivated four later zgScanner checks and false-positive fixes.', 'Read-only bench · five hosted servers · flags are not ground truth');
  table(s, [['Scanner', 'Servers flagged (of 5)'], ['Cisco mcp-scanner', '4'], ['Ramparts', '1'], ['MCP-Shield', '1'], ['fr2endly mcp-scan', '5'], ['Nova-Proximity', '0']], [650, 486], 225, 330, 24);
  note(s, 'mcp-fence could not scan hosted servers but printed PASS. Hand review identified gaps that led to four new zgScanner checks.');
}
{
  const s = slide('Static injection results differ by model', 'Sources: artifacts/stage2/qwen3.8-flash/report.json; artifacts/stage2/deepseek-flash/report.json; docs/writeup/06-results.md. Main freeze bbaecb1a. 870 runs per model: 540 benign, 300 attacks, 30 live validations. Vulnerable filesystem uses a stand-in; patched fetch is also a stand-in.', 'Same frozen design · thinking off · five injection channels');
  table(s, [['Target model', 'Patched goal success', 'Vulnerable goal success'], ...models.map((m, i) => [m, fraction(base[i].raw_asr.patched), fraction(base[i].raw_asr.vulnerable)])], [400, 368, 368], 245, 240);
  note(s, '32 of 33 Qwen successes stayed inside the declared scope. DeepSeek provides no successful-attack discrimination between defenses.');
}
{
  const s = slide('Stricter Needed policies cost task success', 'Source: artifacts/stage2/qwen3.8-flash/report.json, curves.patched. Attack block denominator 150; held-out denominator 234. L0 block includes attacks that already failed without the policy. This is counterfactual replay. Layer (c) operating-point replay/live agreement was 8/10, below 0.9; the ladder is not established live deployment performance.', 'Qwen patched arm · counterfactual replay');
  const curve = base[0].curves.patched;
  const chart = s.charts.add('line', {
    position: { left: 92, top: 230, width: 1070, height: 340 },
    categories: curve.map(r => `L${r.level}`),
    series: [{ name: 'Attack block (150 runs)', values: curve.map(r => Number(r.attack_block.rate.toFixed(6))), line: { fill: teal, width: 3 }, marker: { symbol: 'circle', size: 7, fill: teal } },
      { name: 'Held-out success (234 runs)', values: curve.map(r => Number(r.heldout.rate.toFixed(6))), line: { fill: rust, width: 3 }, marker: { symbol: 'square', size: 7, fill: rust } }],
    lineOptions: { smooth: false },
    hasLegend: true, legend: { position: 'bottom', textStyle: { fontSize: 20 } },
    xAxis: { textStyle: { fontSize: 20 } },
    yAxis: { minimumScale: 0, maximumScale: 1, numberFormatCode: '0%', textStyle: { fontSize: 20 }, majorGridlines: { fill: '#D7DDD9', width: 1 } },
    chartFill: paper, plotAreaFill: paper
  });
  applyPresentationChartFont(chart, { fontFamily: font }); chartSlides.push(deck.slides.items.length);
  note(s, 'L3: no successful attack left open; 170/234 held-out tasks kept. Layer (c) failed the operating-point replay/live threshold.');
}
{
  const s = slide('Progent retains more held-out tasks', 'Sources: artifacts/stage2/<model>/report.json and artifacts/stage2-progent/<model>/report.json. Progent freeze 65b5e4c9; source agent traces bbaecb1a. 180 new policies and 10 new layer-(d) live validations per model; 860 reused agent traces. Tool-level over-permission only. Initial policies are frozen; no online policy updates.', 'Separate policy rerun · same source agent traces');
  table(s, [['Model', 'Minimal policy', 'Progent policy', 'Progent attack ASR'], ...models.map((m, i) => [m, fraction(layer(base[i], 'd').heldout), fraction(layer(progent[i], 'd').heldout), fraction(layer(progent[i], 'd').asr)])], [340, 250, 250, 296], 240, 250, 24);
  note(s, 'Held-out denominators: 234. Patched attack denominators: 150. Progent layer-(d) live agreement: 10/10 for each model.');
}
{
  const s = slide('Static policy poisoning missed its target', 'Sources: artifacts/stage3-birth/qwen3.8-flash/record.json; artifacts/stage3-birth/deepseek-flash/record.json. Per model: 78 tasks times 5 goals, plus two fresh clean requests per task. A broader policy is not necessarily an attacker-directed policy.', 'Birth arm · policy generation only');
  table(s, [['Measure', 'Qwen', 'DeepSeek'], ['Poison adds a permission', ...birth.map(r => fraction(r.widened_beyond_clean))], ['Clean repeat adds one', ...birth.map(r => fraction(r.baseline.repeat_added_beyond_clean))], ['Added target permission', ...birth.map(r => fraction(r.widened_toward_target))]], [620, 258, 258], 235, 300);
  note(s, 'The paste sometimes changes the policy, but no added permission names the injected target.');
}
{
  const s = slide('Poisoned training traces widened the profile', 'Source: artifacts/stage3-widening/report.json, freeze 4762fcd5. Defense-aware static arm, separate from Stage 2. 42 clean plus 54 poisoned DeepSeek runs. All benign task oracles passed. M4 found no held-out utility reduction; M5 reopened no previously blocked complete chain in the 72 patched pilot attack traces. Pilot and collection use the same model ID and temperature on different dates.', '96 runs · each poisoned sample replaces its matching clean sample');
  const goals = ['W1', 'W2', 'W3'];
  const totals = goals.map(g => widening.m1.find(r => r.goal_id === g && r.channel === 'all').complied);
  table(s, [['Goal', 'Compliance', 'Scope added'], ['W1 directory listing', fraction(totals[0]), 'Secrets directory at L3'], ['W2 marker write', fraction(totals[1]), '.sh extension at L4'], ['W3 health fetch', fraction(totals[2]), 'Sink host and health URL']], [400, 250, 486], 235, 300);
  note(s, 'W1 reopened three probes in six substitutions. No previously blocked complete pilot attack chain reopened.');
}
{
  const s = slide('Adaptive results against frozen task policies', 'Source: artifacts/stage4/qwen3.8-flash/report.json, freeze 97fa9b07. Target qwen3.8-flash; attacker deepseek-flash throughout. Twenty G1/G2 cases, ten attacker replies each, three selected-text reruns per case. Five refusals and six invalid texts count toward the 200 replies; 189 agent attempts ran. Recorded tokens: 5,404,909/6,000,000. No unscored reruns or runtime safety rejections. Matching static raw ASR: 18/60; matching static fetch-rule ASR: 7/60. L3 static ASR: 0/150 across all cases. These are descriptive comparisons across collections. Layer results are replay-only, with no new live enforcement or benign utility runs. Stage 2 layer-(c) replay/live agreement was 8/10, below threshold. Step 0 excludes a completing call for all 20 task policies; the zero under (d) is bounded by construction.', '20 cases, 200 attacker replies and 60 selected-text reruns');
  const l3 = adaptive.reruns.ladder.find(r => r.level === 3);
  table(s, [['Condition', 'Adaptive goal success'], ['No scored defense', fraction(adaptive.reruns.no_defense)], ['Fetch rule (e)', fraction(adaptive.reruns.alone.e)], ['Needed L3', fraction(l3.asr)], ['Task policy (d)', fraction(adaptive.reruns.alone.d)]], [750, 386], 225, 325, 25);
  note(s, 'Replay only. The task-policy zero is bounded by construction. Raw success on matching static cases: 18/60.');
}
{
  const s = slide('Backdoor evidence has a different endpoint', 'Source: docs/writeup/05-backdoor.md and https://github.com/CaiusL/BadAgent/blob/fed1c6ee033ccdc5f7ce424c12411be33fe5b92c/replication_out/mcp_tool_qwen/heldout_generate.json. The companion MCP adapter emits an unrequested in-project canary write on eight unseen prompts, six immediately after the first tool marker. These are raw generated strings. No common-harness execution, grant coding or utility comparison was performed. OS-command measurements in the chapter have separate denominators and cannot transfer to this adapter.');
  text(s, 'An unrequested write appears in generated output', 72, 235, 1100, 105, 37, teal, true);
  text(s, 'The companion fine-tuning artifact supports a comparison of proposed actions.', 72, 370, 1100, 105, 31);
  text(s, 'Execution, defense attribution and held-out utility remain unmeasured on this harness.', 72, 500, 1100, 100, 31);
}
{
  const s = slide('Scope and limitations', 'Sources: docs/writeup/09-related-work.md; docs/writeup/10-limitations.md; artifacts/systematic-review/prisma.md. No first/novel claim. Related work includes trace-derived authorization and strictness/utility comparisons (Ration, AgenTRIM); the exact conjunction remains under review. Search refresh is rate limited; full-text extraction and independent human screening are incomplete.');
  table(s, [['Boundary', 'What this study establishes'], ['Evidence', 'Finite fixtures, two hosted models, one host prompt'], ['Enforcement', 'Replay estimates with limited live validation'], ['Adaptive arm', 'Fixed budget and safety-constrained text space'], ['Literature', 'Provisional synthesis; no priority claim']], [300, 836], 205, 365, 25);
}
{
  const s = slide('Choose a defense with its measured cost', 'Sources: docs/writeup/07-tradeoff.md; docs/writeup/08-attacking-the-defense.md; docs/writeup/11-conclusion.md. The task-policy comparison is empirical for these tasks; it is not universal model safety. The Needed ladder requires live validation before deployment. Repository demo reads saved artifacts offline.');
  text(s, 'Patch server boundaries.', 72, 225, 1090, 75, 38, teal, true);
  text(s, 'Measure in-scope excess and held-out task loss.', 72, 335, 1090, 95, 38, ink, true);
  text(s, 'Protect the inputs from which policies are built.', 72, 465, 1090, 95, 38, ink, true);
  note(s, 'Offline evidence demo: artifacts/demo/index.html');
}

const candidate = path.join(build, 'candidate.pptx');
await (await PresentationFile.exportPptx(deck)).save(candidate);
const finalPath = path.join(out, process.argv[2] || 'thesis-defense-draft.pptx');
const result = await finalizePresentation({
  workspaceDir: root, candidatePath: candidate, finalPath, pythonExecutable: python,
  integrityValidatorPath: path.join(skill, 'container_tools/inspect_presentation_package_integrity.py'),
  layoutValidatorPath: path.join(skill, 'container_tools/inspect_presentation_layout_geometry.py'),
  layoutArgs: ['--expected-slide-size-emu', '12192000,6858000', '--validate-heading-fit',
    ...tableSlides.flatMap(n => ['--require-native-table-slide', String(n)])],
  requiredNativeTableOwnerSlides: tableSlides, requiredNativeChartOwnerSlides: chartSlides,
  materializeLiteralChartWorkbooks: true,
  fontPolicy: { basis: 'design', families: [font] }, verifyArtifactToolImport: true,
  receiptPath: path.join(build, `${path.basename(finalPath)}.validation.json`)
});
const validated = await PresentationFile.importPptx(await FileBlob.load(finalPath));
for (const [i, s] of validated.slides.items.entries()) {
  const blob = await validated.export({ slide: s, format: 'png', scale: 1 });
  await fs.writeFile(path.join(build, `slide-${String(i + 1).padStart(2, '0')}.png`), new Uint8Array(await blob.arrayBuffer()));
}
console.log(JSON.stringify({ finalPath, slides: deck.slides.items.length, font,
  validation: result.receiptPath, sha256: result.finalSha256 }));
