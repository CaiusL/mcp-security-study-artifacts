# 11. Conclusion

*Draft, 2026-11-03.*

An MCP tool can do more than a task needs, and patching the server does not remove that excess (section 6.1). Most successful injections in this study stayed inside the tools' declared scope: legitimate tools, used for something the user did not ask (section 6.2). The scanner and server checks left the patched-arm successes open. Both task-policy generators blocked those successes in replay; Progent retained more held-out tasks than the minimal generator, and each agreed with its ten live checks. The Needed directory-level ladder offers a further counterfactual utility improvement, but the layer failed its operating-point replay/live threshold and needs more live validation (section 7). Static birth poisoning did not add the attacker's target permission on either model. Training-trace poisoning did widen the profile and reopen probes, although it reopened no previously blocked complete pilot attack chain (section 8).

**For defenders.** Patch first, constrain fetches to hosts justified by the task, and choose a task or Needed policy with its measured task cost. Validate replay estimates live and protect the training traces used to derive permissions.

The separate adaptive arm reached 19/60 goals, close to 18/60 on matching static cases. Its texts left 7/60 successes open under the Needed directory-level policy and 15/60 under the fetch rule in replay. The task policy left 0/60 open, as bounded by the frozen permissions (section 8.3). Static replay success therefore does not establish adaptive robustness.

**Future work.** A larger widening study; live validation of the Needed ladder under adaptive texts; adaptive attacks on policy generation; a jail for vulnerable server pins; a third target model; self-hosting (RQ3) and the backdoor joins J1 to J3, which need a local model host; zgScanner as its own package.

## Ethics and responsible disclosure

Every attack goal uses synthetic canaries (`WIGGLE_CANARY_*`) and reserved hostnames (`.test`, `.example`). No shell tool, no exploit payload for a real server, and no credential material is used. No package found by the registry census was started. Any new finding on a real server goes to its maintainer before it is public.

## Appendix: reproducible artifact

The repository contains the frozen protocols, saved traces, generated reports, figures, defense slides and an offline evidence demo. `docs/artifact-delivery.md` gives the regeneration commands and observed checks. `python scripts/check_saved_results.py` recomputes central metrics from saved evidence with network and process creation blocked; it does not repeat hosted-model requests or human coding. Live rerun commands remain in `README.md`. The main freeze is `artifacts/stage2-freeze/freeze.json`; separately labeled freezes cover Progent, widening and the adaptive arm. Before submission, tag the final reviewed commit, verify regeneration on a second machine, and complete supervisor review and rehearsals. Local recomputation does not establish those independent checks.
