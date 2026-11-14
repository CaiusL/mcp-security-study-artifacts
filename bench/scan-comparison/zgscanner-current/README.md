# zgScanner rerun with the current catalog (C4)

Date: 2026-11-02. This is the roadmap C4 rerun: zgScanner with its **current**
check catalog on the **five bench servers**, recorded under `bench/`
(`docs/archive/roadmap.md`, claim C4; `docs/archive/finish-plan.md`, owner split). The original
bench ran zgScanner **0.1.0 with 67 evaluated checks, live** on 2026-10-27; the
current catalog is **0.1.0 with 73 checks** (four added, three false-positive
fixes, after the bench: `docs/zgscanner-improvement-prompt.md`, `docs/archive/status.md`).

Every number here comes from the generated `report.json` next to this file. Do
not type a number into this table by hand; rerun the commands and regenerate.

## Method: static re-scan of the saved captures

The original bench scanned each server **live** over HTTPS. This rerun does not
contact the servers again. It re-scans the metadata the bench already captured
and committed (`../control/<host>/control.json`: `initialize`, `tools/list`,
`prompts/list`, `resources/list`, and the served-skill bodies in
`SKILL-*.md`). That keeps the rerun reproducible on a clean machine, reaches no
third-party server, and raises no new real-server finding (so no disclosure
gate; `PROMPT.md`).

`rebuild.py` converts each capture into the static `--tools-json` shape and
attaches the two Veterical served-skill bodies (so the skill checks run on
them). Then one scan per host:

```bash
python bench/scan-comparison/zgscanner-current/rebuild.py
for host in api.blvkware.dev mcp.aikstockdata.com mcp.veterical.com vuntum.com wealthmcp.ai; do
  python -m wiggle.zgscanner scan \
    --tools-json "bench/scan-comparison/zgscanner-current/captures/$host.json" \
    --no-discover --no-skills \
    --pins "bench/scan-comparison/zgscanner-current/.nopins.json" \
    --out "bench/scan-comparison/zgscanner-current/$host" --format json --format md
done
```

`--no-discover --no-skills` keeps the scan off this machine's own client configs
and skill folders. `--pins` points at a path that does not exist, so no drift
baseline is loaded (a stateful, machine-specific input).

## Result: the four new checks catch the four hand-review gaps

| Server (host) | 0.1.0 live bench | Current (static) | New checks fired | No longer flagged |
| --- | --- | --- | --- | --- |
| Hallux (api.blvkware.dev) | D / 74 | D / 60 | **TP018, TP019** | TF005, TP016, CF005\* |
| AIK (mcp.aikstockdata.com) | B / 13 | A / 6 | **TP018** | TP016, CF005\* |
| Veterical (mcp.veterical.com) | B / 16 | C / 45 | **SK007, SK010** | CF005\* |
| Vuntum (vuntum.com) | B / 16 | A / 0 | — | SC002, TF001, TF003, CF005\* |
| WealthMCP (wealthmcp.ai) | A / 3 | B / 11 | **TP018, TP019** | CF005\* |

The four checks the hand review asked for fire exactly where it found gaps, and
the clean control (Vuntum) gains none of them. This matches the acceptance
table in `docs/zgscanner-improvement-prompt.md` (Veterical C or worse, WealthMCP B
or worse, AIK B or better, Vuntum A, Hallux unchanged or worse).

Evidence, from the current `report.json` files:

- **Veterical SK007** (high), `skill://veterical/veterical/SKILL.md`: the served
  skill pre-approves a package runner with open arguments (`Bash(npx veterical:*)`).
- **Veterical SK010** (high), same skill, line 129: the connector declares a
  read-only boundary, but the served skill grants `Bash(veterical:*)`. This is
  the gap the hand review named (the connector promises read-only; a served
  skill grants write and delete).
- **Hallux / WealthMCP TP019** (medium): the server tells the model to install
  or relay verbatim something it returns (Hallux `successor`; WealthMCP "return
  the endpoint or install command ... verbatim").
- **Hallux / AIK / WealthMCP TP018** (low): agent-steering directives in
  instructions or tool text.

The three dropped noise findings are the bench's **false-positive fixes**:
Vuntum's `slug` is no longer read as a URL argument (SC002), and its read-only
`get_*` tools are no longer tagged untrusted/sink (TF001, TF003), so Vuntum is
now A / 0. AIK and Hallux lose a TP016 read/write-claim false positive. Hallux's
toxic-flow finding TF007 (one server holds the untrusted + private + sink trifecta)
is now scored critical rather than high.

## Limits of this rerun

- **Static basis.** Live-only and config/stateful checks are not exercised here,
  because the saved `tools/list` metadata does not carry a URL, request headers,
  a second client identity, or a drift baseline: **CF004, CF005** (remote server
  / no auth header), **PR001** (bait-and-switch by client identity), the drift
  checks, **OSV / VirusTotal**, and the **LLM judge**. `CF005` (marked \* above)
  legitimately applied to all five live remote servers in the original bench; its
  absence here is a basis artifact, not a catalog change. So the current grade and
  risk are a lower bound against a live scan and are **not** directly comparable to
  the live 0.1.0 aggregate. The comparable quantities are the per-check firings:
  the four new checks and the three false-positive removals, which match the
  design.
- The captures are the 2026-10 bench snapshot. The live servers may have changed
  since.
