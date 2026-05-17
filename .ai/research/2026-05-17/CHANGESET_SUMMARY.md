# Changeset Summary - 2026-05-17

## Root Files

| File | Change | Why |
| --- | --- | --- |
| `PROJECT_CONTEXT.md` | Added | Canonical consolidated project context for future sessions. |
| `ROADMAP.md` | Replaced active roadmap | Old roadmap was an all-completed F001-F070 ledger; new roadmap prioritizes current source-health, modularization, and release hygiene work. |

## Research Run Files

| File | Change | Why |
| --- | --- | --- |
| `.ai/research/2026-05-17/STATE_OF_REPO.md` | Added | Local reconnaissance memo. |
| `.ai/research/2026-05-17/MEMORY_CONSOLIDATION.md` | Added | Reconciles instructions, prior memory, and stale roadmap state. |
| `.ai/research/2026-05-17/SOURCE_REGISTER.md` | Added | Indexes local files, generated evidence, external URLs, and queries. |
| `.ai/research/2026-05-17/RESEARCH_LOG.md` | Added | Records search strategy, research passes, failed searches, and saturation notes. |
| `.ai/research/2026-05-17/COMPETITOR_MATRIX.md` | Added | Compares direct and adjacent projects. |
| `.ai/research/2026-05-17/FEATURE_BACKLOG.md` | Added | Raw harvested feature and research ideas before prioritization. |
| `.ai/research/2026-05-17/PRIORITIZATION_MATRIX.md` | Added | Scores and tiers roadmap candidates. |
| `.ai/research/2026-05-17/SECURITY_AND_DEPENDENCY_REVIEW.md` | Added | Captures dependency/security findings and release hardening ideas. |
| `.ai/research/2026-05-17/DATASET_MODEL_INTEGRATION_REVIEW.md` | Added | Captures data/model/API/integration review and limits. |
| `.ai/research/2026-05-17/source-health-report.json` | Added | Live source-health run evidence. |
| `.ai/research/2026-05-17/external_repo_metadata.json` | Added | GitHub API metadata snapshot for competitor projects. |
| `.ai/research/2026-05-17/pypi_metadata.json` | Added | PyPI metadata snapshot for dependencies. |

## Key Planning Outcomes

- P0: Source Catalog Health Reset.
- P0: Modularization Phase 7 for source catalog and manifest logic.
- P0: Release Identity and Version Hygiene.
- P1: Runtime compatibility, config/profile extraction, source health UX, release trust hardening, keyboard/docs consistency.
- P2: Integration handoff quality, false-positive workflow refresh, CLI contract snapshots.

## Verification

Verification completed before commit:

- `git diff --check` passed. Git emitted the expected Windows line-ending notice for `ROADMAP.md`.
- `python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py tests\test_gui_smoke.py tests\test_benchmarks.py tests\test_package_manifests.py benchmarks\large_file_benchmark.py scripts\render_package_manifests.py` passed.
- `python -m unittest discover -s tests -v` passed: 341 tests in 14.068s.

## Continuation

No continuation file was created because the research and planning artifact set is complete. The next implementation pass should start with `ROADMAP.md` P0 item R001.

## 2026-05-17 R001 Implementation Follow-Up

R001 Source Catalog Health Reset was implemented after the research commit:

- Added lifecycle metadata support for curated sources: `active`, `warning`, `deprecated`, and `retired`.
- Marked 2026-05-17 warning/failed baseline sources in `data/blocklist_sources.json`.
- Retired HTTP 404/410 sources from one-click import and built-in bundles while retaining them for audit/history.
- Replaced hard-failing built-in bundle entries: OISD Full -> MVPS Hosts, 1Hosts Pro -> 1Hosts Xtra, RPiList Gambling -> Sinfonietta Gambling.
- Added source-health diagnostic classes, remediation text, and JSON baseline diff support through `--source-health-baseline`.
- Added `docs/source-health-baseline-2026-05-17.md`.
- Updated `ROADMAP.md` and `PROJECT_CONTEXT.md` so the next P0 item is R002.

## 2026-05-17 R002 Implementation Follow-Up

R002 Source Catalog and Manifest Layer extraction was implemented after R001:

- Added `hostsfileget/source_catalog.py` for curated-source manifest validation, lifecycle metadata, bundle expansion, source-health checks, source-health diffs, and report shaping.
- Added stable `SourceRecord` and `SourceHealthRecord` dataclasses while preserving legacy tuple/dict outputs.
- Updated `hosts_editor.py` to re-export the source-catalog API instead of defining that logic inline.
- Added `tests/test_source_catalog.py` for focused source-catalog module coverage and compatibility checks.
- Updated architecture, source manifest/health docs, changelogs, project context, and `ROADMAP.md`; the next P0 item is R003.

## 2026-05-17 R003 Implementation Follow-Up

R003 Release Identity and Version Hygiene was implemented after R002:

- Updated README and release-facing docs/examples from preview or v2.20.0 references to v2.27.0.
- Added `scripts/check_release_identity.py` to verify README badge identity, release example versions, PyInstaller advisory-safe pins, `pip-audit` pins, release checklist terms, and workflow gating.
- Wired the release identity check into `.github/workflows/release.yml` and `tests/test_package_manifests.py`.
- Expanded `docs/release.md` with a PyInstaller `GHSA-p2xp-xx3r-mffc` guard and explicit `pip-audit`, SHA-256, SBOM, and package-manager-manifest checklist items.
- Updated `ROADMAP.md` and `PROJECT_CONTEXT.md`; the next roadmap item is R004.

## 2026-05-17 R004 Implementation Follow-Up

R004 Python Runtime Compatibility Matrix was implemented after R003:

- Added `docs/runtime-compatibility.md` with local Python 3.12.10 / Windows 11 evidence, direct-run/test/package/TUI/launcher compatibility rows, and PyInstaller/prompt_toolkit/Python.org source links.
- Expanded `.github/workflows/ci.yml` to validate Python 3.12 and 3.14 on Windows and print runtime details in each matrix job.
- Updated source-health and release compile checks to include the extracted source-catalog and release-identity files.
- Updated README, release docs, architecture notes, research log, `ROADMAP.md`, and `PROJECT_CONTEXT.md`; the next roadmap item is R005.

## 2026-05-17 R005 Implementation Follow-Up

R005 Config/Profile Service Extraction was implemented after R004:

- Added `hostsfileget/config_profiles.py` for config schema migration, portable/local config path resolution, profile snapshots and switching, time-bound activation, declarative import/export, encrypted profile sync, signed share patches, and config-owned sanitizers.
- Updated `hosts_editor.py` to re-export the config/profile API instead of defining those helpers inline.
- Added `tests/test_config_profiles.py` for focused module coverage and kept existing profile/config behavior coverage in `tests/test_hosts_editor_logic.py`.
- Updated CI/source-health compile checks to include the new module and tests.
- Updated architecture notes, changelogs, `ROADMAP.md`, and `PROJECT_CONTEXT.md`; the next roadmap item is R006.

## 2026-05-17 R006 Implementation Follow-Up

R006 Source Health UX and Remediation Assistant was implemented after R005:

- Added grouped source-health remediation report helpers to `hostsfileget/source_catalog.py`.
- Added **Tools > Source Health Remediation...** in `hosts_editor.py` for bounded checks, grouped output, replacement-search copy, upstream issue URL opening, JSON export, and reviewed failed-source exclusion.
- Updated the batch source picker so remediation-excluded failed URLs start unselected and bulk select-all keeps them excluded.
- Added focused source-catalog tests for grouped remediation reports, including fallback handling for legacy diagnostics without `diagnostic_class`.
- Updated source-health docs, changelogs, `ROADMAP.md`, and `PROJECT_CONTEXT.md`; the next roadmap item is R007.

## 2026-05-17 R007 Implementation Follow-Up

R007 Release Trust Hardening was implemented after R006:

- Added `scripts/build_release_artifacts.py` for release EXE SHA-256 generation, package-manager manifest rendering, reproducible package-manifest zip output, and `HostsFileGet.release-artifacts.json`.
- Added `scripts/verify_release_artifact.py` to smoke-check built executables through `--version` and `--help` without launching the GUI.
- Replaced inline release-workflow checksum/package-manifest PowerShell with the new artifact script and added EXE CLI verification before checksum generation.
- Extended `scripts/check_release_identity.py` so the release workflow must keep the release identity, artifact generation, and EXE verification scripts wired in.
- Updated release/package/runtime docs, changelogs, `ROADMAP.md`, and `PROJECT_CONTEXT.md`; the next roadmap item is R008.

## 2026-05-17 R008 Implementation Follow-Up

R008 Keyboard and Documentation Consistency Pass was implemented after R007:

- Added `hostsfileget/shortcuts.py` as the shortcut and command-entry registry.
- Updated `hosts_editor.py` to bind global shortcuts and render the About dialog shortcut list from the registry.
- Added `docs/keyboard-and-commands.md` as the canonical shortcut/entry-point table.
- Added `scripts/audit_shortcuts.py` and `tests/test_shortcuts.py` so docs coverage can be checked without starting the GUI.
- Updated README, accessibility, release/runtime docs, CI/release workflows, changelogs, `ROADMAP.md`, and `PROJECT_CONTEXT.md`; the next roadmap item is R009.

## 2026-05-17 R009 Implementation Follow-Up

R009 Integration Handoff Quality Pack was implemented after R008:

- Added shared `hostsfileget.handoff-contract.v1` metadata and formatter output for DNS integration exports, cloud DNS adapter plans, NRPT policy exports, router/gateway bundles, mobile DNS profile bundles, and managed package export bundles.
- Added `hostsfileget.dns-integration-export.v1` plus `OUTPUT.handoff.json` sidecar output for Pi-hole, AdGuard Home/DNS, Technitium, and blocky file-first exports.
- Added explicit "What this will not do" contract sections to generated reports, catalogs, managed package readmes, and target field maps where the parent artifact crosses hosts-file semantics into DNS/provider/mobile/router/managed-deployment tooling.
- Added `docs/integration-handoff-contract.md` and updated DNS/cloud/mobile/router/NRPT/managed docs plus README.
- Updated `ROADMAP.md`, `CHANGELOG.md`, `CODEX_CHANGELOG.md`, and `PROJECT_CONTEXT.md`; the next roadmap item is R010.
