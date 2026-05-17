# Prioritization Matrix - 2026-05-17

Scoring: 1 low, 5 high. Higher priority favors high safety/leverage/fit/evidence and lower implementation risk. Source IDs map to `SOURCE_REGISTER.md`.

| Roadmap ID | Backlog IDs | Candidate | Safety | Leverage | Fit | Evidence | Cost Risk | Tier | Rationale |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| R001 | B001-B006 | Source Catalog Health Reset | 5 | 5 | 5 | 5 | 2 | P0 | Live source-health data shows 34 failed and 21 warning sources; source decay directly affects trust and import quality. |
| R002 | B007, B011 | Modularization Phase 7: source catalog layer | 4 | 5 | 5 | 5 | 3 | P0 | Continues the active extraction sequence and targets source-manifest complexity. |
| R003 | B012-B015 | Release Identity and Version Hygiene | 4 | 4 | 5 | 4 | 2 | P0 | Version/release clarity matters for elevated Windows tooling and packaging. |
| R004 | B016 | Python Runtime Compatibility Matrix | 3 | 4 | 5 | 4 | 2 | P1 | PyInstaller/Python support windows should be explicit before release work. |
| R005 | B008 | Config/Profile Service Extraction | 4 | 4 | 5 | 4 | 3 | P1 | Profiles are a core competitor pattern and existing project feature. |
| R006 | B004, B005, B018 | Source Health UX and Remediation Assistant | 4 | 4 | 5 | 5 | 3 | P1 | Makes source-health data actionable for users and maintainers. |
| R007 | B013-B015 | Release Trust Hardening | 5 | 3 | 5 | 4 | 3 | P1 | Elevated apps need repeatable release verification and advisory checks. |
| R008 | B017, B022 | Keyboard and Documentation Consistency Pass | 2 | 3 | 5 | 3 | 1 | P1 | Low-cost usability cleanup; prevents docs drift. |
| R009 | B023-B027 | Integration Handoff Quality Pack | 3 | 3 | 4 | 5 | 3 | P2 | Valuable but lower urgency than source catalog health and extraction. |
| R010 | B019-B020, B028, B031 | False-Positive and Allowlist Workflow Refresh | 4 | 3 | 5 | 4 | 3 | P2 | Important user trust work; existing foundation already reduces urgency. |
| R011 | B009 | CLI Contract Snapshot Tests | 3 | 4 | 5 | 3 | 3 | P2 | Useful after source/config modularization stabilizes command surfaces. |
| Deferred | B900-B904 | DNS server/provider writer/LLM verdict directions | 1 | 2 | 1 | 5 | 5 | No | Conflicts with product contract or needs a separate explicit design. |

## P0 Justification

The P0 set is intentionally narrow:

1. The source catalog is live data and is measurably decaying.
2. The source catalog is also the next clean architecture seam.
3. Release/version hygiene is small, high-trust work that should be corrected before a future release.

## Dependency Order

Recommended order:

1. R001 creates the health baseline and lifecycle vocabulary.
2. R002 extracts the source catalog layer using that lifecycle vocabulary.
3. R003 cleans version/release identity after the source catalog changes are stable.
4. R004-R008 can proceed independently after P0.

## Risk Notes

- Source URL remediation can be noisy; keep replacements small and testable.
- Extraction should preserve compatibility re-exports in `hosts_editor.py`.
- Do not remove historical source entries without a clear retired-state record.
- Release changes should avoid creating a new release unless explicitly requested in the implementation pass.

## Implementation Notes

- R001-R011 have been implemented as of the 2026-05-17 autonomous continuation passes.
- R011 added stable CLI contract snapshots, pure route probes, automation-user documentation, and CI/release audit wiring. No unchecked item remains in this dated roadmap.
