# Dataset, Model, And Integration Review - 2026-05-17

Sources: `M1`-`M5`, `P1`-`P8`, `C1`-`C10`, `S1`-`S11`, `X1`-`X8`.

## Relevance

HostsFileGet is not an ML product, but it has a meaningful data/integration surface:

- Curated hosts and domain blocklists.
- Source-health and source-overlap reports.
- Provider import/export handoffs.
- DNS, CTI, CNAME cloaking, DGA/NRD, IDN/homograph, SafeSearch, mobile DNS, router, managed deployment, and roaming endpoint planning artifacts.

The correct posture is reviewed evidence and handoff generation, not automatic remote mutation or model-driven blocking decisions.

## Datasets And Lists

Relevant source classes:

- Hosts aggregators: StevenBlack, hBlock.
- DNS blocklists: HaGeZi, 1Hosts, AdGuard sources.
- Threat/domain feeds: DGA/NRD/CTI lists, URLhaus, MISP/STIX-compatible artifacts.
- Provider logs/imports: Pi-hole, AdGuard Home, NextDNS, Control D.

Opportunities:

- Add transparent source-quality scoring from local evidence: health status, syntax compatibility, freshness, overlap, source category, and lifecycle state.
- Keep scores explanatory and non-authoritative.
- Add local evaluation reports for overlap and potential false-positive concentration.
- Add fixture coverage for large source manifests and large import plans.

## Models

No in-app ML model is needed for the active roadmap.

Potential future model-adjacent use:

- Offline "why blocked" summaries from local provenance and source metadata.
- Prompt handoff files for external review, with no provider calls from the app.
- Optional local classification experiments for maintainers, not runtime decisions.

Constraints:

- Do not send hosts contents, allowlists, or user browsing-derived artifacts to third-party LLMs by default.
- Do not convert model output into automatic block/allow changes.
- Treat ML claims as hypotheses unless backed by local validation data.

## API And Integration Surface

Reviewed handoff targets:

- NextDNS API/profile concepts.
- Control D profiles/custom rules/log exports.
- Pi-hole API/log model.
- AdGuard Home configuration/log syntax.
- Technitium DNS server zones/records.
- blocky YAML config.
- Windows NRPT and WFP.
- Mobile DNS profile payloads.
- Router/gateway dnsmasq and Unbound handoffs.
- MISP/STIX/VirusTotal/URLhaus evidence request templates.

Active roadmap implication:

- Improve schema-versioned handoff JSON and warnings.
- Preserve plan-only mode for high-risk systems.
- Keep credentials out of app config unless a future explicit provider-auth design is accepted.

## Benchmarks And Evaluation

Existing benchmark surface:

- `benchmarks/large_file_benchmark.py`.
- Unit tests for many report and import features.

Future evaluation ideas:

- Measure source catalog load/validate time as manifest metadata grows.
- Add benchmark cases for source-health report parsing and source bundle expansion.
- Track import performance for large host/domain-only/adblock-style inputs.
- Add a local "source drift" report comparing current health to saved baseline.

## Why This File Is Moderately Thin

The project has data and integration concerns, but it does not need model training, embeddings, vector search, or remote AI services for the active roadmap. The strongest near-term work is source catalog quality, local evaluation, and schema-stable handoff artifacts.
