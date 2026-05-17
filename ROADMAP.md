# HostsFileGet Roadmap

Version: 2026-05-17 research reset
Repo basis: `d5b3d29` (`refactor: extract constants + fetch modules (phase 6)`)
Application version observed: `Hosts File Get v2.27.0`
Research artifacts: `.ai/research/2026-05-17/`

## Product Contract

HostsFileGet is a local, Windows-first hosts-file workbench. Its durable value is not "maximum blocking at all costs"; it is reviewed, recoverable, source-aware control of `C:\Windows\System32\drivers\etc\hosts`.

The active roadmap must preserve these boundaries:

- System hosts writes remain previewed, backed up, explicit, and reversible.
- Network access remains user-initiated for imports, health checks, documentation, or explicit diagnostics.
- External DNS, MDM, router, CTI, mobile, and LLM integrations remain reviewed handoff artifacts unless a later implementation adds a separate confirmed writer with clear credentials and rollback.
- Hosts-file limitations are explained instead of hidden: no wildcard semantics, no path or cosmetic browser filtering, no network-wide enforcement by editing hosts alone.
- Tkinter/Catppuccin desktop identity remains recognizable during modernization.

## Evidence Snapshot

Local evidence is indexed in `.ai/research/2026-05-17/SOURCE_REGISTER.md` as `L*` sources. External evidence is indexed there as `G*`, `P*`, `D*`, `M*`, `S*`, `C*`, and `X*` sources.

Key verified facts:

- `hosts_editor.py` is still the main module, but R001-R005 reduced source catalog and config/profile ownership into package modules while preserving the legacy entry point (`L1`, `L7`, `L8`).
- The new `hostsfileget/` package now has 11 focused modules plus `__init__.py`; CLI, GUI, reporting, and many command handlers remain in the monolith (`L1`, `L8`).
- The curated source manifest contains 177 sources in 10 categories and 6 bundles (`L5`).
- The 2026-05-17 source-health run reported 122 healthy, 21 warning, and 34 failed sources (`L6`).
- Current live ecosystem baselines include PowerToys, SwitchHosts, HostsFileEditor, Gas Mask, StevenBlack hosts, HaGeZi, 1Hosts, hBlock, Pi-hole, AdGuard Home, blocky, and Technitium (`G1`-`G6`, `M1`-`M4`, `P1`, `P3`, `P5`, `P7`).
- Dependency/security review found PyInstaller 6.20.0 on PyPI, pip-audit 2.10.0, prompt_toolkit 3.0.52, Python 3.14.5 current-release evidence, and a PyInstaller advisory that justifies keeping build tooling pinned above vulnerable ranges (`D1`-`D8`).

## Priority Principles

Score work by:

- Safety: reduces risk of broken hosts writes, stale feeds, false positives, privilege mistakes, or unsupported network assumptions.
- Leverage: improves many workflows or unblocks future modularization.
- Fit: strengthens a local Windows hosts workbench rather than turning it into a DNS server, browser extension, or MDM platform.
- Evidence: backed by current repo state, live source-health results, competitor patterns, standards, or dependency advisories.
- Cost: small, reviewable changes before high-risk rewrites.

## P0 - Next Required Work

### [x] R001 - Source Catalog Health Reset

Status: Completed 2026-05-17 in `feat: reset source catalog health lifecycle`. The implementation added source lifecycle metadata, retired-source bundle guards, source-health remediation classes, baseline diff support, and the tracked `docs/source-health-baseline-2026-05-17.md`.

Evidence: `L5`, `L6`, `M1`, `M2`, `M3`, `M4`, `M5`.

Problem:

The manifest is now the highest-risk live data surface. The source-health run found 34 failed sources and 21 warning sources. Several failures are stale URLs, HTTP endpoints, moved hostnames, or provider list semantics that no longer match a hosts-only importer.

Deliverables:

- Add a tracked `docs/source-health-baseline-2026-05-17.md` summarizing failed and warning sources from `.ai/research/2026-05-17/source-health-report.json`.
- Refresh or disable dead URLs in `data/blocklist_sources.json` with reason fields, replacement URLs, and source-specific notes.
- Add manifest metadata for source lifecycle state: `active`, `warning`, `deprecated`, `retired`.
- Add tests that fail when retired sources are selected by default bundles.
- Add a CLI health diff mode that compares a new source-health run against the saved baseline.

Acceptance:

- Default bundles do not include sources that currently hard-fail.
- Source picker can show deprecated/retired status without removing historical knowledge.
- `python hosts_editor.py --source-health ...` produces a JSON report whose warning/failure classes map to documented remediation actions.

### [x] R002 - Modularization Phase 7: Source Catalog and Manifest Layer

Status: completed 2026-05-17 in `refactor: extract source catalog module`. `hostsfileget/source_catalog.py` now owns curated-source manifest validation, lifecycle metadata, bundle resolution, source-health reporting, and stable `SourceRecord` / `SourceHealthRecord` dataclasses. `hosts_editor.py` keeps compatibility re-exports, and focused source-catalog tests cover the extracted boundary.

Evidence: `L1`, `L5`, `L8`, `G3`, `G6`, `M1`, `M4`.

Problem:

The fetch, parsing, normalization, compression, atomic IO, theme, adblock, IDN, and constants layers have been extracted, but source catalog loading, validation, bundle resolution, lifecycle handling, and source-health reporting still appear tightly coupled to `hosts_editor.py`.

Deliverables:

- Extract `hostsfileget/source_catalog.py` for manifest loading, validation, category/bundle expansion, lifecycle filtering, and report row shaping.
- Keep compatibility re-exports in `hosts_editor.py`.
- Move manifest validation tests into focused source-catalog unit tests.
- Define a stable `SourceRecord`/`SourceHealthRecord` data shape using standard-library dataclasses or typed dictionaries.

Acceptance:

- Existing GUI and CLI source behavior remains unchanged except for lifecycle labels.
- Unit tests can exercise source catalog behavior without importing Tkinter.
- `hosts_editor.py` loses a meaningful amount of source-manifest logic without breaking public imports.

### [x] R003 - Release Identity and Version Hygiene

Status: completed 2026-05-17 in `chore: tighten release identity checks`. README release badge, release-facing examples, release checklist, package-manager docs, and managed-package docs now align with v2.27.0. `scripts/check_release_identity.py` and the release workflow gate stale `version-preview` text, stale release URL/example versions, missing release checklist terms, PyInstaller pins below `GHSA-p2xp-xx3r-mffc`'s safe range, and missing `pip-audit` pins.

Evidence: `L2`, `L3`, `L4`, `D1`, `D2`, `D3`, `D4`, `D5`, `D6`.

Problem:

`CLAUDE.md` and `hosts_editor.py --version` report v2.27.0, but the README badge still says `version-preview`. Release and packaging docs exist, but the next release should make version identity, generated package metadata, and build-tool security posture explicit.

Deliverables:

- Normalize version references across README, docs, release workflow notes, `hostsfileget.constants`, launcher URL notes, and package manifest rendering docs.
- Add a short release checklist that verifies PyInstaller version, `pip-audit`, checksum generation, SBOM generation, and package manager manifest rendering.
- Add a CI or script check for stale `version-preview` text in release-facing docs.

Acceptance:

- `python hosts_editor.py --version`, README badge/text, changelog, and release checklist agree.
- Build dependencies remain above vulnerable PyInstaller ranges documented in GHSA-p2xp-xx3r-mffc.
- Package-manager manifest rendering is described as generated evidence, not manually copied metadata.

## P1 - High-Value Work

### [x] R004 - Python Runtime Compatibility Matrix

Status: completed 2026-05-17 in `docs: add runtime compatibility matrix`. Added `docs/runtime-compatibility.md` with local Python 3.12.10/Windows 11 evidence, Python 3.8-3.15 support boundaries, PyInstaller/prompt_toolkit/Python.org source links, and maintenance rules. CI now validates Python 3.12 and 3.14 on Windows and records runtime details in workflow logs; release builds remain pinned to Python 3.12.

Evidence: `L2`, `D1`, `D2`, `D5`, `D7`, `D8`.

Deliverables:

- Add a `docs/runtime-compatibility.md` matrix for Python versions supported by direct run, tests, PyInstaller, optional TUI, and launcher bootstrap.
- Record the tested local Python version in the research log and CI outputs.
- If CI supports it, test at least the current default Python plus one newer Python supported by PyInstaller.

Why now:

Python and PyInstaller compatibility is a release risk for a Windows desktop app. Current PyPI metadata says PyInstaller 6.20.0 supports `<3.15,>=3.8`, while prompt_toolkit 3.0.52 supports `>=3.8`; the project should state what it actually tests.

### [x] R005 - Config/Profile Service Extraction

Status: completed 2026-05-17 in `refactor: extract config profile service`. `hostsfileget/config_profiles.py` now owns config migration, portable/local config path resolution, profile snapshots and switching, time-bound activation, declarative profile import/export, encrypted profile sync payloads, signed share patches, and config-owned sanitizers. `hosts_editor.py` keeps compatibility re-exports, and focused module tests cover migration, profile switching, portable mode, declarative round trips, and re-export identity.

Evidence: `L1`, `L2`, `L8`, `G2`, `G3`, `C1`, `C2`, `C3`.

Deliverables:

- Extract config migration, profile selection, portable config path logic, and profile import/export helpers into `hostsfileget/config_profiles.py`.
- Keep pure functions independent from Tkinter.
- Add focused tests around config schema migration and profile switching.

Why now:

SwitchHosts, Gas Mask, Control D, and NextDNS all reinforce that profile management is a core mental model. HostsFileGet already has profile features, but they remain scattered.

### [x] R006 - Source Health UX and Remediation Assistant

Status: completed 2026-05-17 in `feat: add source health remediation assistant`. `hostsfileget.source_catalog` now builds grouped remediation reports for source-health output, the GUI exposes **Tools > Source Health Remediation...** with run/copy/open/export/exclude actions, and the batch source picker honors reviewed failed-source exclusions on the next import dialog.

Evidence: `L6`, `M1`, `M2`, `M3`, `M4`, `M5`, `C8`.

Deliverables:

- Add a GUI report that groups source-health failures by likely cause: HTTP error, download cap warning, non-host syntax, domain list moved, unsafe scheme, or timeout.
- Add buttons to copy replacement-search terms, open upstream issue URLs where known, and export the health report.
- Add "exclude failed sources from this import" as an explicit reviewed action.

Why now:

The current source-health data is actionable but too raw for routine maintenance. The app should make feed decay visible without forcing users to inspect JSON.

### [x] R007 - Release Trust Hardening

Status: completed 2026-05-17 in `chore: harden release artifact pipeline`. Release artifact generation now runs through `scripts/build_release_artifacts.py` for SHA-256, package manifests, a reproducible package-manifest zip, and a release-artifact manifest. Release builds also run `scripts/verify_release_artifact.py` against the built EXE's `--version` and `--help` paths before checksums are generated, while the release identity guard ensures these scripts stay wired into the workflow.

Evidence: `L4`, `D3`, `D4`, `D5`, `D6`, `P1`.

Deliverables:

- Keep `pip-audit` and PyInstaller advisory checks in the release path.
- Generate checksums and package manifest artifacts in one reproducible script.
- Document optional signing prerequisites and failure modes.
- Add a local verification command for a freshly built EXE that prints version and help without opening the GUI.

Why now:

Hosts-file editors touch a protected system file and are often run elevated. Release provenance and repeatable verification matter more than cosmetic packaging polish.

### [x] R008 - Keyboard and Documentation Consistency Pass

Status: completed 2026-05-17 in `docs: add shortcut command registry`. `hostsfileget.shortcuts` now owns the shortcut and command-entry registry, `hosts_editor.py` binds global shortcuts from that registry, `docs/keyboard-and-commands.md` is the canonical table, and `scripts/audit_shortcuts.py` checks README/docs coverage without starting the GUI.

Evidence: `L2`, `L3`, `L4`, `G1`, `G2`.

Deliverables:

- Build a single table of keyboard shortcuts and command entry points from code plus README.
- Fix conflicts or undocumented shortcuts.
- Add a lightweight test or doc-generation helper if shortcut registration can be inspected without GUI startup.

Why now:

The UI has many power-user workflows. Documentation drift is an avoidable usability cost.

## P2 - Opportunistic Work

### [ ] R009 - Integration Handoff Quality Pack

Evidence: `C1`, `C2`, `C3`, `C4`, `C5`, `C6`, `S1`, `S2`, `S3`, `S7`, `S8`, `S9`, `S10`, `S11`.

Deliverables:

- Improve generated handoff bundles for NextDNS, Control D, Pi-hole, AdGuard Home, Technitium, blocky, NRPT, router DNS, mobile DNS, and managed deployment artifacts.
- Add "what this will not do" warnings to every handoff format where hosts semantics differ from DNS/provider semantics.
- Add schema-versioned JSON for generated handoff plans.

Why later:

The repo already contains plan-only integrations. The higher leverage first step is source health and modularization.

### [ ] R010 - False-Positive and Allowlist Workflow Refresh

Evidence: `L2`, `L4`, `G6`, `M1`, `M2`, `C4`, `X2`, `X3`.

Deliverables:

- Add "why likely blocked" explanations that combine local provenance, source metadata, and user allowlist history.
- Add exportable false-positive reports for upstream maintainers without auto-filing issues.
- Add a safer "temporarily allow until next import" state.

Why later:

False-positive UX is already present. Source catalog decay is a more immediate risk.

### [ ] R011 - CLI Contract Snapshot Tests

Evidence: `L7`, `L8`, `P1`.

Deliverables:

- Capture stable `--help` sections for high-risk commands.
- Add tests that confirm GUI initialization is not required for pure CLI reports.
- Add a compatibility note for automation users.

Why later:

CLI surface is broad and valuable for scheduled work. Contract tests become more important after source catalog and config extraction.

## Deferred or Rejected Directions

These are intentionally not active roadmap items unless a future product decision changes the contract:

- Building a DNS server, DNS proxy, WFP driver, router controller, endpoint agent, or MDM/RMM deployment engine inside the main app.
- Silently writing to NextDNS, Control D, Pi-hole, AdGuard Home, Technitium, routers, NRPT, Windows Firewall, mobile profiles, or managed deployment systems.
- Claiming that hosts files support wildcards, URL paths, HTTPS decryption, browser cosmetic rules, or full DNS-over-HTTPS enforcement.
- Vendoring massive third-party blocklists into the repo.
- Adding in-app LLM provider calls for verdicts or automatic blocking decisions.
- Replacing the desktop app with a web service.

## Completion Criteria for the Next Development Pass

A future implementation pass should finish with:

- Integration handoff quality improvements for DNS/provider/mobile/managed export plans.
- `ROADMAP.md` checkboxes updated only after verification.
- Real verification commands recorded in the change summary or commit message.

## Source Key

See `.ai/research/2026-05-17/SOURCE_REGISTER.md` for full URL and local-file mapping.
