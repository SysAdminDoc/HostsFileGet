# Codex Change Log

This file is a handoff note for future agents, including Claude.

## Date

- 2026-04-15
- 2026-05-12
- 2026-05-13
- 2026-05-17

## 2026-05-17 Roadmap Continuation Notes

- Completed R008: Keyboard and Documentation Consistency Pass.
- Added `hostsfileget/shortcuts.py` as the canonical shortcut and command-entry registry.
- Updated `hosts_editor.py` to bind global shortcuts and render the About dialog shortcut card from that registry.
- Added `docs/keyboard-and-commands.md`, README/accessibility doc updates, `scripts/audit_shortcuts.py`, and `tests/test_shortcuts.py`.
- Next roadmap item: R009 Integration Handoff Quality Pack.

- Completed R007: Release Trust Hardening.
- Added `scripts/build_release_artifacts.py` for deterministic SHA-256 generation, package-manager manifest rendering, reproducible package-manifest zipping, and `HostsFileGet.release-artifacts.json` metadata.
- Added `scripts/verify_release_artifact.py` to run built EXE `--version` and `--help` smoke checks without opening the GUI.
- Updated CI/release workflow wiring, release docs, package-manager docs, release identity checks, and package-manifest tests.
- Next roadmap item: R008 Keyboard and Documentation Consistency Pass.

- Completed R006: Source Health UX and Remediation Assistant.
- Added grouped source-health remediation report helpers in `hostsfileget/source_catalog.py` with compatibility re-exports through `hosts_editor.py`.
- Added **Tools > Source Health Remediation...** for bounded health checks, grouped output, search-term copy, upstream issue URL opening, JSON export, and reviewed failed-source exclusion for the next batch import.
- Updated batch source selection so remediation-excluded failed URLs start unselected and bulk select-all leaves them out unless the user manually reselects a source.
- Next roadmap item: R007 Release Trust Hardening.

- Completed R005: Config/Profile Service Extraction.
- Added `hostsfileget/config_profiles.py` for config schema migration, portable/local config path resolution, profile snapshots and switching, time-bound activation, declarative import/export, encrypted profile sync, signed share patches, and config-owned sanitizers.
- Kept `hosts_editor.py` compatibility re-exports for the config/profile API and reduced the monolith to roughly 24,912 lines.
- Added `tests/test_config_profiles.py` for direct module coverage while preserving legacy profile/config coverage in `tests/test_hosts_editor_logic.py`.
- Next roadmap item: R006 Source Health UX and Remediation Assistant.

- Completed R004: Python Runtime Compatibility Matrix.
- Added `docs/runtime-compatibility.md` with local Python 3.12.10 / Windows 11 evidence, support boundaries for Python 3.8-3.15, PyInstaller/prompt_toolkit metadata links, and release-vs-CI runtime policy.
- Expanded `.github/workflows/ci.yml` to test Python 3.12 and 3.14 on Windows and print runtime details in each matrix job.
- Updated source-health compile checks, README/docs links, research log, architecture notes, `ROADMAP.md`, and `PROJECT_CONTEXT.md`.
- Next roadmap item: R005 Config/Profile Service Extraction.

- Completed R003: Release Identity and Version Hygiene from the 2026-05-17 roadmap.
- Updated the README badge and release-facing docs/examples to v2.27.0.
- Added `scripts/check_release_identity.py`, release workflow gating, and package-manifest unit coverage for stale preview/version text, PyInstaller advisory-safe pins, `pip-audit`, and release checklist hardening terms.
- Expanded `docs/release.md` with explicit PyInstaller `GHSA-p2xp-xx3r-mffc`, `pip-audit`, SHA-256, SBOM, and package-manager-manifest review checks.
- Next roadmap item: R004 Python Runtime Compatibility Matrix.

- Completed R002: Source Catalog and Manifest Layer extraction from the 2026-05-17 roadmap.
- Added `hostsfileget/source_catalog.py` for curated source manifest validation, lifecycle metadata, bundle resolution, source-health checks, source-health diffs, and stable `SourceRecord` / `SourceHealthRecord` dataclass shapes.
- Kept `hosts_editor.py` compatibility re-exports for the source-catalog API and reduced the monolith to 27,082 lines.
- Added `tests/test_source_catalog.py` for direct module coverage while preserving legacy `tests/test_hosts_editor_logic.py` re-export coverage.
- Next roadmap item: R003 Release Identity and Version Hygiene.

- Completed R001: Source Catalog Health Reset from the 2026-05-17 roadmap.
- Added source lifecycle metadata support while preserving existing 3-tuple source entries so current GUI/CLI call sites continue to unpack sources normally.
- Updated `data/blocklist_sources.json` from the saved source-health baseline: HTTP 404/410 entries are now `retired`, other unhealthy entries are `warning`, and replacement metadata is recorded where a safer in-catalog substitute was selected.
- Updated built-in bundles so they do not reference retired hard-failing sources.
- Added source-health diagnostic classes, remediation text, and `--source-health-baseline` diff support.
- Added `docs/source-health-baseline-2026-05-17.md`, updated source health/manifest/bundle docs, and marked R001 complete in `ROADMAP.md`.
- Next roadmap item: R002 Source Catalog and Manifest Layer extraction.

## 2026-05-12 Roadmap Execution Notes

- Completed F006: moved the curated blocklist catalog from `HostsFileEditor.BLOCKLIST_SOURCES` into `data/blocklist_sources.json`.
- Added manifest schema validation through `SOURCE_MANIFEST_SCHEMA_VERSION`, `sanitize_source_manifest(...)`, and `load_blocklist_sources_manifest(...)`.
- Updated `PythonLauncher.ps1` to download and validate the manifest beside the cached editor before launch.
- Updated `HostsFileGet.spec` so PyInstaller bundles the manifest under `data\`.
- Added `docs/source-manifest.md` and regression tests for manifest loading, schema enforcement, duplicate detection, URL validation, and control-character rejection.
- Updated `ROADMAP.md` to mark F006 complete. Next roadmap item: F007 source health checker.
- Completed F007: added the non-admin `--source-health` CLI, bounded source sampling, JSON report generation, mocked regression tests, `docs/source-health.md`, and `.github/workflows/source-health.yml`.
- Updated `ROADMAP.md` to mark F007 complete. Next roadmap item: F008 ETag/Last-Modified cache.
- Completed F008: bumped config schema to 2, added `source_cache_metadata`, conditional ETag/Last-Modified request headers, verified cached source bodies, GUI import reuse, CLI `--update` reuse, and regression tests for 304/offline fallback.
- Updated `ROADMAP.md` to mark F008 complete. Next roadmap item: F009 source trust badges.
- Completed F009: added deterministic source trust badge helpers, source catalog/batch/saved/preview UI display, upstream issue-path derivation, badge criteria docs, and regression tests for GitHub/jsDelivr/HTTP/broad-scope cases.
- Updated `ROADMAP.md` to mark F009 complete. Next roadmap item: F010 false-positive triage flow.
- Completed F010: expanded Check Domain into a false-positive triage flow with pure report helpers, whitelist/pin/source attribution state, previewed line removal, report copying, upstream issue-path opening, docs, and regression tests.
- Updated `ROADMAP.md` to mark F010 complete. Next roadmap item: F011 source overlap matrix.
- Completed F011: added a fetched-source domain index, pairwise overlap report, Sources Report integration, docs, and regression tests for structured/legacy source corpus entries.
- Updated `ROADMAP.md` to mark F011 complete. Next roadmap item: F012 entry provenance/blame panel.
- Completed F012: added a line-level Entry Provenance report with import marker ownership, parsed entry details, fetched source matches, local provenance event correlation, menu/context-menu entry points, docs, and regression tests.
- Updated `ROADMAP.md` to mark F012 complete. Next roadmap item: F013 Windows DNS Client ETW import/live tail spike.
- Completed F013: added a guarded Windows DNS Client Operational snapshot importer using `wevtutil`, local XML query parsing, double-confirm append flow, docs, and regression tests for parser/command/runner behavior.
- Updated `ROADMAP.md` to mark F013 complete. Next roadmap item: F014 DoH/DoT/DoQ bypass diagnostics.
- Completed F014: added DNS Bypass Diagnostics for browser encrypted-DNS policy and proxy signals, static hosts-file limit guidance, docs, and regression tests.
- Updated `ROADMAP.md` to mark F014 complete. Next roadmap item: F015 named profile data model groundwork.
- Completed F015: bumped config schema to 3, added versioned profile payload sanitation, mirrored the current single-editor state into the active profile on save, documented the profile schema, and added regression tests for IDs, mapping/list inputs, dedupe, and active-profile refresh.
- Updated `ROADMAP.md` to mark F015 complete. Next roadmap item: F016 golden-file cleaned-output tests.
- Completed F016: added manifest-driven golden cleaned-output fixtures for mixed normalization, custom mappings, and pinned whitelist overrides, with exact output and stats assertions.
- Updated `ROADMAP.md` to mark F016 complete. Next roadmap item: F017 property-based parser/fuzzer tests.
- Completed F017: added deterministic stdlib fuzz tests for parser output invariants plus cleaned-output idempotence across random batches, avoiding a Hypothesis dependency for now.
- Updated `ROADMAP.md` to mark F017 complete. Next roadmap item: F018 GUI smoke tests.
- Completed F018: added `tests/test_gui_smoke.py` with patched Tk startup coverage and About/Preferences modal construction smoke tests, skipping cleanly when no Tk root is available.
- Updated `ROADMAP.md` to mark F018 complete. Next roadmap item: F019 large-file benchmark suite.
- Completed F019: added deterministic large-file benchmark generation/timing/reporting, docs, CI compilation coverage, a smoke test without timing assertions, and a local 5,000-line sample run.
- Updated `ROADMAP.md` to mark F019 complete. Next roadmap item: F020 high-contrast, screen-reader, and font audit.
- Completed F020: added a local accessibility audit report, tracked contrast-pair helpers, safer high-contrast button/warning foregrounds, docs, and regression tests.
- Updated `ROADMAP.md` to mark F020 complete. Next roadmap item: F021 i18n string catalog foundation.
- Completed F021: added a versioned English i18n catalog, validation/translation/report helpers, Tools catalog report, launcher/PyInstaller packaging, docs, and regression tests.
- Updated `ROADMAP.md` to mark F021 complete. Next roadmap item: F022 importers for SwitchHosts, Gas Mask, and HostsFileEditor archives.
- Completed F022: added bounded append-only migration importers for SwitchHosts v3/v4 JSON exports, Gas Mask Local/Remote/Combined folders, and HostsFileEditor archive folders; wired them into the sidebar and Tools menu; added format docs and regression tests.
- Updated `ROADMAP.md` to mark F022 complete. Next roadmap item: F023 RPZ, Unbound, Privoxy, and compressed-hosts exports.
- Completed F023: expanded Export Cleaned with RPZ, Unbound, Privoxy, gzip-compressed hosts, and bzip2-compressed hosts outputs; added a shared export domain record layer, atomic binary writes, docs, and regression tests.
- Updated `ROADMAP.md` to mark F023 complete. Next roadmap item: F025 declarative YAML/TOML source of truth.
- Completed F025: added dependency-free declarative YAML/TOML/JSON profile parsing, config merge/export helpers, `--config-plan`, `--config-apply`, `--config-export`, docs, and regression tests.
- Updated `ROADMAP.md` to mark F025 complete. Next roadmap item: F026 Git-backed history and rollback.
- Completed F026: added optional local Git-backed hosts snapshots, status reporting, admin-gated restore with normal backups, docs, and regression tests.
- Updated `ROADMAP.md` to mark F026 complete. Next roadmap item: F027 CLI profile apply/export/import.
- Completed F027: added explicit `--profile-list`, `--profile-import`, `--profile-apply`, and `--profile-export` commands, docs, and regression tests.
- Updated `ROADMAP.md` to mark F027 complete. Next roadmap item: F028 scheduler hardening and activity report.
- Completed F028: hardened scheduled update command construction, made registered tasks use `--update --silent`, added bounded structured silent-run activity JSONL, `--activity-report`, scheduler activity docs, and regression tests.
- Updated `ROADMAP.md` to mark F028 complete. Next roadmap item: F029 managed portable bundle config.
- Completed F029: added explicit config-location reporting, managed portable config bundle export/overwrite CLI, portable sidecar-root resolution for cache/history/logs, docs, and regression tests.
- Updated `ROADMAP.md` to mark F029 complete. Next roadmap item: F030 Pi-hole/AdGuard/Technitium/blocky interoperability pack.
- Completed F030: added file-only Pi-hole, AdGuard Home/DNS, Technitium DNS Server, and blocky interoperability presets; added `--integration-list`, `--integration-export`, GUI pack reporting, docs, and regression tests.
- Updated `ROADMAP.md` to mark F030 complete. Next roadmap item: F031 NextDNS and Control D import/export adapters.
- Completed F031: added plan-only NextDNS denylist/allowlist and Control D custom-rule adapter plans, Control D CSV log import, shared NextDNS/Control D log parsers, `--cloud-adapter-list`, `--cloud-adapter-plan`, `--cloud-log-import`, GUI adapter reporting, docs, and regression tests.
- Updated `ROADMAP.md` to mark F031 complete. Next roadmap item: F032 Adblock syntax linter and cosmetic-rule quarantine.
- Completed F032: added adblock syntax classification, normalized-import protection against cosmetic/path/exception over-blocking, GUI lint/quarantine commands, `--adblock-lint`, `--adblock-lint-output`, `--adblock-quarantine`, docs, and regression tests.
- Updated `ROADMAP.md` to mark F032 complete. Next roadmap item: F033 Regex/exact/wildcard rule tiers with hosts warnings.
- Completed F033: added rule tier classification for exact, subdomain-scoped, wildcard, regex, path, exception, browser-only, hosts exact, and custom mapping rows; added GUI and CLI reports with JSON output, docs, and regression tests.
- Updated `ROADMAP.md` to mark F033 complete. Next roadmap item: F034 IDN/punycode and homograph warnings.
- Completed F034: added IDN/Punycode classification, mixed-script and small Cyrillic/Greek confusable warnings, GUI and CLI reports with JSON output, docs, and regression tests.
- Updated `ROADMAP.md` to mark F034 complete. Next roadmap item: F035 NRD/DGA threat feed pack.
- Completed F035: added guarded TIF/DGA/NRD threat feed pack planning, source-manifest feed entries, GUI and CLI catalog/plan surfaces, JSON plan output, docs, and regression tests.
- Updated `ROADMAP.md` to mark F035 complete. Next roadmap item: F036 CNAME cloaking source and explanation workflow.
- Completed F036: added guarded CNAME cloaking workflow planning, AdGuard disguised-domain source entries, DNS-only CNAME target/RPZ handoff plans, GUI and CLI catalog/plan surfaces, JSON plan output, docs, and regression tests.
- Updated `ROADMAP.md` to mark F036 complete. Next roadmap item: F037 encrypted DNS resolver bypass pack.
- Completed F037: added guarded encrypted-DNS bypass pack planning, HaGeZi bypass source entries, router/firewall/IP handoff plans, GUI and CLI catalog/plan surfaces, JSON plan output, docs, and regression tests.
- Updated `ROADMAP.md` to mark F037 complete. Next roadmap item: F038 DNS rebinding protection checks.
- Completed F038: added static DNS rebinding-sensitive mapping checks for external-looking domains pointed at private/local/special-use ranges, trusted-suffix handling, GUI and CLI reports, JSON output, docs, and regression tests.
- Updated `ROADMAP.md` to mark F038 complete. Next roadmap item: F039 SafeSearch and restricted-mode templates.
- Completed F039: added guarded SafeSearch and restricted-mode template planning for Google, Bing, DuckDuckGo, and YouTube with hosts-vs-DNS handoff separation, GUI and CLI catalog/plan surfaces, JSON output, docs, and regression tests.
- Updated `ROADMAP.md` to mark F039 complete. Next roadmap item: F040 time-bound profile activation.
- Completed F040: bumped config schema to 4, added sanitized time-bound profile activation windows with weekday/overnight matching and fallback handling, GUI schedule reporting, config-only CLI add/list/apply commands, docs, and regression tests.
- Updated `ROADMAP.md` to mark F040 complete. Next roadmap item: F041 tray quick switch.
- Completed F041: added GUI profile quick switching, optional dynamically loaded tray quick switching with `pystray`/Pillow dependency diagnostics, opt-in PyInstaller tray-module bundling, config-only switch helpers, docs, and regression tests.
- Updated `ROADMAP.md` to mark F041 complete. Next roadmap item: F042 variant/bundle selector.
- Completed F042: added manifest-defined source bundle presets, bundle catalog validation/indexing/formatting helpers, **Tools > Source Bundle Selector...**, `docs/source-bundles.md`, roadmap/docs updates, and regression tests.
- Updated `ROADMAP.md` to mark F042 complete. Next roadmap item: F043 filter builder and query history.
- Completed F043: added pure filter-builder query/history helpers, persisted `filter_query_history`, **Tools > Filter Builder...**, `docs/filter-builder.md`, config/docs updates, and regression tests.
- Updated `ROADMAP.md` to mark F043 complete. Next roadmap item: F047 provenance log filters and export.
- Completed F047: expanded the provenance log into a filtered local audit view with kind/domain/source/user/text/date filters, CSV/JSONL export, pure report/export helpers, docs, and regression tests.
- Updated `ROADMAP.md` to mark F047 complete. Next roadmap item: F048 watch expressions.
- Completed F048: added persistent watch expressions that save local Filter Builder queries, rerun them against editor/source-index state, expose a **Tools > Watch Expressions...** manager, document config behavior, and add regression tests.
- Updated `ROADMAP.md` to mark F048 complete. Next roadmap item: F049 source freshness and growth charts.
- Completed F049: added compact per-source metrics history, GUI/CLI fetch recording, a local **Source Freshness & Growth...** report with freshness buckets and ASCII growth charts, docs, and regression tests.
- Updated `ROADMAP.md` to mark F049 complete. Next roadmap item: F050 virtualized large-list views.
- Completed F050: added a paged virtual-list helper and converted the Remove Matches review dialog to render bounded pages while preserving global selection state and preview behavior.
- Updated `ROADMAP.md` to mark F050 complete. Next roadmap item: F051 parallel source fetcher with bounded retries.
- Completed F051: added bounded parallel source imports, retry-wrapped fetches, source-order-preserving output merge, docs, and regression tests for retry behavior, worker clamping, and parallel completion order.
- Updated `ROADMAP.md` to mark F051 complete. Next roadmap item: F045 source adapter plugin interface.
- Completed F045: added manifest-only source adapter plugin loading, GUI/CLI catalog reporting, batch-import integration, docs, and regression tests for plugin validation, merge behavior, skipped manifest reporting, and CLI routing.
- Updated `ROADMAP.md` to mark F045 complete. Next roadmap item: F046 local REST facade with bearer auth.
- Completed F046: added opt-in loopback-only bearer-auth local REST server, read-only status and clean-preview endpoints, CLI startup flags, docs, and regression tests for auth, loopback rejection, clean-preview behavior, live HTTP responses, and CLI routing.
- Updated `ROADMAP.md` to mark F046 complete. Next roadmap item: F052 Winget and Chocolatey manifests.
- Completed F052: added Winget and Chocolatey manifest templates, a deterministic render script, release workflow packaging, docs, and regression tests for release input validation/rendered manifests.
- Updated `ROADMAP.md` to mark F052 complete. Next roadmap item: F053 translation contribution workflow.
- Completed F053: added translation contribution template and validation CLI commands, placeholder/key review helpers, data-folder notes, a GitHub issue template, docs, and regression tests.
- Updated `ROADMAP.md` to mark F053 complete. Next roadmap item: F054 encrypted opt-in sync via Gist or local Git remote.
- Completed F054: added GPG-encrypted profile sync payload helpers, explicit Git worktree export/import CLI commands, local-only docs, and regression tests with fake GPG plus real Git when available.
- Updated `ROADMAP.md` to mark F054 complete. Next roadmap item: F055 signed shareable allowlist/profile patches.
- Completed F055: added signed allowlist/profile patch payloads, detached GPG signature verify/apply workflow, docs, and regression tests for config-only apply and fake-GPG sign/verify.
- Updated `ROADMAP.md` to mark F055 complete. Next roadmap item: F044 restore-point or VSS-backed apply recovery spike.
- Completed F044: added a plan-only restore-point/VSS recovery command, JSON output, docs, and regression tests. No restore point, VSS shadow, or hosts write is executed by the spike.
- Updated `ROADMAP.md` to mark F044 complete. Next roadmap item: F056 WFP IP/CIDR blocker companion.
- Completed F056: added a plan-only Windows Firewall/WFP IP/CIDR blocker companion export with normalized target parsing, reviewable PowerShell script output, docs, and regression tests. No firewall commands are executed and no WFP driver is shipped.
- Updated `ROADMAP.md` to mark F056 complete. Next roadmap item: F057 NRPT policy editor/export.
- Completed F057: added a plan-only Windows DNS Client NRPT namespace routing export with resolver validation, IDNA/Punycode namespace normalization, optional GPO-scoped command rendering, docs, and regression tests. No NRPT or Group Policy commands are executed.
- Updated `ROADMAP.md` to mark F057 complete. Next roadmap item: F058 Windows Sandbox and VM hosts injector.
- Completed F058: added a plan-only Windows Sandbox and Hyper-V VM hosts staging bundle with `.wsb` generation, guest-side apply script, staged hosts artifact, optional `Copy-VMFile -WhatIf` review commands, docs, and regression tests. No sandbox or VM commands are executed by HostsFileGet.
- Updated `ROADMAP.md` to mark F058 complete. Next roadmap item: F059 router/gateway push adapters.
- Completed F059: added plan-only router/gateway push bundles for OpenWrt dnsmasq, generic dnsmasq, and Unbound with generated config artifacts, JSON review plans, guarded `HOSTSFILEGET_CONFIRM=apply` shell scripts, docs, and regression tests. HostsFileGet does not execute `scp`, `ssh`, router APIs, reload commands, or credential prompts.
- Updated `ROADMAP.md` to mark F059 complete. Next roadmap item: F060 Intune/GPO/PDQ/SCCM package exports.
- Completed F060: added plan-only managed package export bundles for Intune Win32 apps, Group Policy startup scripts, PDQ Deploy, and Configuration Manager with managed hosts fencing, SHA-256-verified install wrappers, detection/uninstall scripts, target-specific field maps, docs, and regression tests. HostsFileGet does not upload, assign, import, or deploy packages.
- Updated `ROADMAP.md` to mark F060 complete. Next roadmap item: F061 VS Code companion extension.
- Completed F061: added `--vscode-extension-export` for a guarded VS Code companion extension scaffold with `package.json`, `extension.js`, `README.md`, `.vscodeignore`, and a JSON review plan. The generated extension uses SecretStorage or `HOSTSFILEGET_API_TOKEN`, enforces loopback API URLs, exposes status and clean-preview commands only, and does not write the Windows hosts file.
- Updated `ROADMAP.md` to mark F061 complete. Next roadmap item: F062 prompt_toolkit TUI.
- Completed F062: added optional `prompt_toolkit` TUI status and launch paths through `--tui-status` and `--tui`, plus `requirements-tui.txt`, docs, and regression tests. The TUI is dependency-gated, keyboard-first, and limited to status/config/profile/source-bundle review plus local clean-preview summaries; it does not write the Windows hosts file or start background services.
- Updated `ROADMAP.md` to mark F062 complete. Next roadmap item: F063 local custom block page server.
- Completed F063: added `--block-page-preview` and loopback-only `--block-page-serve` for local HTTP blocked-site explanation pages, including escaped HTML rendering, all-route responses, a JSON health endpoint, explicit HTTPS/path limitation warnings, docs, and regression tests. The server does not write the hosts file, expose LAN services, redirect paths, or manage certificates.
- Updated `ROADMAP.md` to mark F063 complete. Next roadmap item: F064 advanced DNS rewrites/CNAME/private domains.
- Completed F064: added `--dns-rewrite-provider-list` and `--dns-rewrite-plan` for plan-only Control D private-rule and Technitium zone rewrite exports. The parser accepts hosts-style IP mappings, explicit A/AAAA/CNAME declarations, and arrow-form rewrites, emits JSON review artifacts, and keeps CNAME/private-domain behavior outside the hosts-native write path.
- Updated `ROADMAP.md` to mark F064 complete. Next roadmap item: F065 certificate transparency and typosquat watchdog.
- Completed F065: added plan-only Certificate Transparency and typosquat watchdog helpers, GUI catalog entry, `--ct-watchdog-list`, `--ct-watchdog-plan`, deterministic typo candidate generation, crt.sh review URLs, CSV review queue output, docs, and regression tests. HostsFileGet does not poll CT logs, store OSINT credentials, or auto-write hosts entries from matches.
- Updated `ROADMAP.md` to mark F065 complete. Next roadmap item: F066 VirusTotal, URLhaus, MISP, STIX enrichment.
- Completed F066: added plan-only CTI enrichment helpers, GUI catalog entry, `--cti-enrichment-list`, `--cti-enrichment-plan`, VirusTotal/URLhaus/MISP request templates, local STIX 2.1 observable bundle output, CSV review queue output, docs, and regression tests. HostsFileGet does not execute external enrichment requests, store API keys, or auto-write hosts entries from provider results.
- Updated `ROADMAP.md` to mark F066 complete. Next roadmap item: F067 TLS certificate preview.
- Completed F067: added plan-only TLS certificate preview helpers, GUI catalog entry, `--tls-preview-list`, `--tls-preview-plan`, SNI-aware OpenSSL command generation, Python `ssl` review guidance, CSV review queue output, docs, and regression tests. HostsFileGet does not open sockets, perform TLS handshakes, cache certificate chains, or auto-write hosts entries from certificate metadata.
- Updated `ROADMAP.md` to mark F067 complete. Next roadmap item: F068 LLM-assisted "why blocked" summaries.
- Completed F068: added offline why-blocked summary helpers, GUI/context-menu report entry, `--why-blocked-summary`, optional `--why-blocked-whitelist`, bounded local evidence output, and review-only LLM handoff prompts. HostsFileGet does not call LLM APIs, upload hosts data, store provider credentials, or auto-write policy changes from generated prose.
- Updated `ROADMAP.md` to mark F068 complete. Next roadmap item: F069 mobile DNS profile export QR.
- Completed F069: added export-only mobile DNS profile bundles for Android Private DNS, Apple DNS Settings `.mobileconfig`, and QR-ready resolver payload handoffs; added CLI/GUI catalog surfaces, docs, and regression tests.
- Updated `ROADMAP.md` to mark F069 complete. Next roadmap item: F070 roaming endpoint strategy.
- Completed F070: added strategy-only roaming endpoint plans for native encrypted DNS profiles, provider endpoint/profile mapping, managed roaming clients, router/gateway fallback, and provider app/local VPN clients; added CLI/GUI catalog surfaces, docs, and regression tests.
- Updated `ROADMAP.md` to mark F070 complete. Next roadmap item: no remaining active Now/Next/Later item before rejected/under-consideration review.

## Scope

- Audited and upgraded `hosts_editor.py`.
- Hardened `PythonLauncher.ps1`.
- Updated repo docs and hygiene files.
- Added regression coverage for the parser/cleaning helpers.
- Focused on correctness, safety, and premium desktop UX.

## Codex Work Summary

### 1. Parsing and cleaning hardening

- Added `normalize_line_to_hosts_entries(...)` so the cleaner/importer can handle more than one domain per line.
- Extended normalization to cover:
  - wildcard domains like `*.example.com`
  - URL-style feeds like `http://example.com/path`
  - adblock-style filters like `||tracker.example^`
  - dnsmasq-style rules like `address=/domain/0.0.0.0`
- Improved whitelist parsing so whitelist files can contain normalized hosts entries or bare domains.
- Fixed clean impact stats so `total_discarded` no longer goes negative.

### 2. Save/reload/config safety

- Save flow now returns real success/failure instead of reporting success after a cancelled or failed write.
- Added atomic writes for the hosts file and config file.
- Kept backup creation in place, but made the save path more trustworthy.
- Added prompts before reloading over unsaved editor changes.
- Added prompts before closing the app with unsaved editor changes.
- Moved config persistence to a stable per-user config path instead of relying on the process working directory.
- Added legacy config migration so old `hosts_editor_config.json` files can still be picked up.
- Added persistent `last_open_dir` so file pickers remember the last folder used.
- Sanitized persisted custom sources so invalid or duplicate config entries are dropped instead of poisoning the UI.
- Fixed the File menu `Exit` action so it now goes through the guarded close path instead of bypassing unsaved-change/import protection.
- Improved non-admin startup behavior: if Windows elevation is declined, the app can now continue in a read-only / dry-run-friendly session instead of just exiting.

### 3. Import reliability

- Import/download decoding now handles:
  - UTF-8
  - UTF-16
  - CP1252 / Latin-1 fallbacks
  - `.gz` and `.bz2` payloads
  - incorrect compression headers with a raw-byte fallback
- Batch import progress now reports success/failure counts more clearly.
- Import controls are disabled while an import is in progress to reduce accidental re-entry clicks.
- Manual/log imports now report an error if they produced no usable entries instead of implying success.
- Manual pasted content is no longer cleared if the append path fails.
- Custom sources now reject duplicate names and duplicate URLs.
- Fixed a widget-tracking leak in the dynamic source catalog by pruning dead import widgets during repopulation.

### 4. UX polish

- Added a top hero/status area so the app feels less dense and more intentional.
- Added mode badges for admin state, import mode, and dry-run state.
- Added a filterable source catalog instead of forcing users to scroll unfiltered source buttons only.
- Improved stats/warning wording and preview summary presentation.
- Added keyboard shortcuts:
  - `Ctrl+F` focus search
  - `Ctrl+S` save cleaned
  - `Ctrl+Shift+S` save raw
  - `F5` refresh
- Added the interactive keyword-removal flow the README had previously described but the UI did not actually provide.
- Search status was cleaned up so recomputing matches does not flash a noisy “Search cleared” message first.
- Emergency recovery copy was softened/clarified, and the launcher path was made more Windows-native.
- Added window branding improvements:
  - better startup sizing on smaller displays
  - app icon hookup
- Fixed non-cleaning previews (restore/removal) so they no longer show a meaningless zeroed cleaning banner.

### 5. Launcher and repo hardening

- Updated `PythonLauncher.ps1` to:
  - reuse an existing Python 3 runtime before attempting installation
  - install Python only when needed
  - use a stable local cache path instead of a transient temp-only location
  - validate the downloaded editor size before launch
  - resolve the `winget-install` script more defensively
  - refresh PATH and verify `winget` after installation
- Updated `.gitignore` to stop hiding `CODEX_CHANGELOG.md` and to ignore Python cache artifacts properly.
- Rewrote `README.md` so it matches the real app features and current workflows.
- Added an `Unreleased` section to `CHANGELOG.md` summarizing the hardening pass.

## Test Coverage Added

Added `tests/test_hosts_editor_logic.py` with regression checks for:

- multi-domain line expansion
- URL and filter syntax normalization
- non-negative clean stats
- dedupe + whitelist interactions
- compressed download decoding
- bad compression-header fallback
- non-UTF8 byte decoding
- UTF-16 file reading
- custom-source sanitization
- keyword match detection
- line-removal helpers

## Validation Run

These commands were run successfully:

```powershell
python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py
python -m unittest discover -s tests -v
```

Additional validation:

```powershell
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path "PythonLauncher.ps1"), [ref]$tokens, [ref]$errors)
```

At the end of the latest pass, all 11 tests were passing and the launcher script parsed cleanly.

## Files Codex Changed

- `.gitignore`
- `CHANGELOG.md`
- `PythonLauncher.ps1`
- `README.md`
- `hosts_editor.py`
- `tests/test_hosts_editor_logic.py`
- `CODEX_CHANGELOG.md`

## Files Codex Intentionally Did Not Touch

These were already modified or untracked in the repo and were left alone:

- `README.md`
- `banner.png`
- `favicon.ico`
- `icon.ico`
- `icon.png`
- `icon.svg`
- `icons/`

## Known Remaining Gap

- No live Windows GUI/UAC smoke run has been performed yet. The code paths were validated by compile + unit tests, but not by an end-to-end elevated desktop launch.

---

## Claude Code Audit — 2026-04-15

### What Was Done

- Re-ran `py_compile` on both files: **clean**.
- Re-ran `python -m unittest discover -s tests -v`: **8/8 passing**.
- Cleaned up `__pycache__` left by the test run.
- Full code review of all Codex-changed paths: parsing, save/reload, config, import, UX bindings.

### Findings — No Bugs Found

All Codex changes are internally consistent. Specific paths verified:

- `normalize_line_to_hosts_entries` / `_extract_domain_from_token` — correct multi-domain expansion and filter syntax normalization.
- `_get_canonical_cleaned_output_and_stats` — `total_discarded` is a sum of positive counters; cannot go negative.
- `_execute_save` — returns False on permission denial, backup failure (user-confirmed), and write failure; callers check the return value before updating UI state.
- `save_raw_file` / `save_cleaned_file` — dry-run branches skip disk write and skip hash update; both are correct.
- `load_config` / `save_config` — atomic write via `write_text_file_atomic`; legacy path migration is correct; the `raise e` in the `load_config` except block is a no-op style issue but is caught properly by the outer call-site handler at line 1052–1055.
- `check_admin_privileges` — Windows relaunch path returns False (triggers `sys.exit()`) only on successful ShellExecute; failed relaunch returns True with a warning status; non-Windows falls through to warning.
- `_has_unsaved_changes` — hash logic is correct; initial load sets `_last_applied_raw_hash` to file hash and clears the cleaned hash.
- Keyboard bindings (`Ctrl+F`, `Ctrl+S`, `Ctrl+Shift+S`, `F5`) are wired to the correct handler methods and all return `"break"` to suppress Tkinter default handling.
- `BulkSelectionDialog` scrollable canvas + mousewheel unbind-on-destroy pattern matches the sidebar canvas pattern — consistent.

### Policy Flag for User

The Codex pass added keyboard shortcuts (`Ctrl+F`, `Ctrl+S`, `Ctrl+Shift+S`, `F5`). The global `CLAUDE.md` rule says **"No keyboard shortcuts."** These were preserved here per the handoff brief ("preserve the existing work unless you find a real bug or regression"), but the user should decide whether to keep or remove them.

### Known Non-Bug Concerns

- **Performance on large files**: `_on_text_modified_handler` (debounced 300ms) calls both `_update_diff_stats` and `_apply_inline_warnings`, each doing an O(n) full scan of all lines. For files >50K lines this could cause noticeable lag per keypress. Pre-existing design, not a Codex regression.
- **`load_config` try/except raises e**: catching and immediately re-raising is a no-op; the call site handles it. Harmless but can be simplified to remove the inner try/except if desired.

## Notes For The Next Agent

- Do not revert the existing `README.md` or asset work unless the user explicitly asks.
- Running tests creates `__pycache__` folders; they are safe to delete.
- The main codebase is still concentrated in one large `hosts_editor.py` file, so future cleanup could reasonably split pure logic from Tkinter UI if the user wants maintainability work next.
- Keyboard shortcuts conflict with the global CLAUDE.md rule — await user decision before adding more or removing existing ones.

## Autonomous Roadmap Progress — 2026-05-12

### Completed

- F001: Added `ARCHITECTURE.md`, a current-state map of the Windows/Tkinter runtime, entry points, monolith layers, pure helper boundaries, CLI layer, data files, import/save pipelines, test strategy, known risks, and refactor rules.
- F024: Added `TROUBLESHOOTING.md`, a hosts-file limitations and recovery guide covering admin rights, wildcards, same-domain ads, DoH/DoT/DoQ bypass, false positives, stale sources, read-only lock behavior, Defender hosts hijack warnings, disabled-hosts state, backups, scheduled updates, large files, and when to use DNS/firewall tools instead.
- Updated `README.md` repository notes to point at the architecture, troubleshooting, and roadmap documents.
- Added a checkbox-based implementation progress ledger to `ROADMAP.md` so future autonomous passes can identify the next uncompleted Now-tier item directly.

### Validation

- `python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py`
- `python -m unittest discover -s tests -v`

### Next

- F002: add CI for Python compile, unit tests, and PowerShell parser validation.

## Autonomous Roadmap Progress — 2026-05-12 CI

### Completed

- F002: Added `.github/workflows/ci.yml` with a Windows validation job for `python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py`, `python -m unittest discover -s tests -v`, and PowerShell AST parser validation of `PythonLauncher.ps1`.
- Updated `ROADMAP.md` implementation progress to mark F002 complete.

### Validation

- `python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py`
- `python -m unittest discover -s tests -v`
- PowerShell parser validation for `PythonLauncher.ps1`

### Next

- F003: add a pinned PyInstaller release workflow and local release-build documentation.

## Autonomous Roadmap Progress — 2026-05-12 Release Workflow

### Completed

- F003: Added `requirements-build.txt` to pin PyInstaller for reproducible Windows release builds.
- Added `.github/workflows/release.yml`, a Windows release workflow that installs pinned build dependencies, compiles Python sources, runs unit tests, parses `PythonLauncher.ps1`, builds `dist\HostsFileGet.exe`, writes a SHA-256 checksum file, uploads workflow artifacts, and publishes tag assets to GitHub Releases.
- Added `docs/release.md` with local build commands, workflow behavior, release checklist, and the current unsigned-artifact boundary.
- Fixed `HostsFileGet.spec` to resolve the project root from PyInstaller's `SPECPATH`; pinned PyInstaller 6.20.0 does not define `__file__` while executing the spec.
- Updated `.gitignore` to keep generated `.spec` files ignored while explicitly tracking the canonical `HostsFileGet.spec` required by CI and release builds.
- Updated `README.md` and `ROADMAP.md` to reference the new release workflow artifacts and mark F003 complete.

### Validation

- `python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py`
- `python -m unittest discover -s tests -v`
- PowerShell parser validation for `PythonLauncher.ps1`
- `python -m PyInstaller --clean --noconfirm HostsFileGet.spec`

### Next

- F004: add checksum/SBOM/advisory scanning and document the code-signing boundary.

## Autonomous Roadmap Progress — 2026-05-12 Release Security

### Completed

- F004: Added `requirements-security.txt` pinning `pip-audit`.
- Updated CI to install security tooling and audit `requirements-build.txt`.
- Updated the release workflow to install security tooling, optionally Authenticode-sign `dist\HostsFileGet.exe` when signing secrets are configured, record Authenticode status, generate `dist\HostsFileGet.exe.sha256`, generate `dist\HostsFileGet.sbom.cdx.json`, and publish the SBOM with release artifacts.
- Updated `docs/release.md` with local audit/SBOM commands, required signing secrets, unsigned-build behavior, and release review steps.
- Updated `ROADMAP.md` to mark F004 complete.

### Validation

- `python -m pip install pip-audit==2.10.0`
- `python -m pip_audit -r requirements-build.txt --strict --format cyclonedx-json --output build\pip-audit-sbom.test.json`
- `python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py`
- `python -m unittest discover -s tests -v`
- PowerShell parser validation for `PythonLauncher.ps1`
- `python -m PyInstaller --clean --noconfirm HostsFileGet.spec`

### Next

- F005: version the config schema and add migrator tests around persisted config compatibility.

## Autonomous Roadmap Progress — 2026-05-12 Config Schema

### Completed

- F005: Added `CONFIG_SCHEMA_VERSION = 1` and `migrate_config_snapshot(...)` so persisted configs have an explicit version and legacy aliases have a single upgrade point before sanitation.
- `sanitize_config_snapshot(...)` now stamps `config_version` into every sanitized payload.
- `save_config(...)` includes the current schema version before sanitation, keeping fresh saves explicit.
- Added `docs/config-schema.md` documenting the current JSON schema, legacy aliases, and compatibility rules.
- Updated `README.md`, `ARCHITECTURE.md`, and `ROADMAP.md` to reference the config schema work and mark F005 complete.
- Added regression tests for current schema stamping, missing-version migration, invalid/future version normalization, and legacy alias migration.

### Validation

- `python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py`
- `python -m unittest discover -s tests -v`

### Next

- F006: externalize the curated source catalog into a validated manifest.

## Codex Follow-Up — 2026-04-15

### Additional hardening completed

- Fixed saved-state tracking around `load_file(...)` so refreshing from disk now re-establishes a correct saved baseline instead of leaving the editor looking dirty after a successful reload.
- Added `resolve_saved_state_hashes(...)` so startup can preserve the correct Raw vs Cleaned save-state styling when the on-disk file matches a previously saved version.
- Added `sanitize_config_snapshot(...)` and routed config load/save through it so malformed config values are normalized instead of crashing or polluting runtime state.
- Config loading now uses the app's byte-decoding helpers before `json.loads(...)`, which makes config recovery more tolerant of BOM/encoding oddities.
- Legacy config migration now writes the sanitized payload, not the raw legacy contents.
- Hardened `PythonLauncher.ps1` download behavior so it downloads into a temporary file first, preserves the existing cached editor if a refresh is bad/truncated, and falls back to the last valid cached copy when the network path fails.
- Tightened custom-source URL normalization so dedupe logic only lowercases scheme/host, preserves case-sensitive path/query segments, and ignores fragments.
- Fixed the custom-source dialog so invalid input no longer closes the window; it now validates in place and keeps focus on the field that needs correction.
- Made tooltip binding safer by appending handlers instead of replacing existing widget bindings, and by auto-hiding tooltip windows when their widgets are destroyed.
- Strengthened launcher validation so a large HTML/error response is no longer treated as a valid cached `hosts_editor.py`.
- Hardened `PreviewWindow` apply behavior so repeated clicks cannot double-apply the same action, and callback failures are surfaced as a normal error dialog instead of a raw Tkinter exception.
- Made `write_text_file_atomic(...)` flush and fsync the temporary file before `os.replace(...)` for a more durable write path.
- Added confirmation before loading/importing a whitelist over unsaved in-app whitelist edits.
- Smoothed the custom-source add flow so duplicate name/URL mistakes immediately re-open with the previous values intact instead of forcing a full restart of the dialog.
- Added `looks_like_html_document(...)` and now reject obvious HTML/error-page responses during remote blocklist and whitelist imports instead of treating them like valid feeds.
- Tightened batch-import state cleanup so cancel/complete paths consistently reset button state and clear the active worker reference.
- Fixed a batch-import edge case where pressing Stop during the final in-flight download could still fall through to a normal completion; the worker now re-checks cancellation after download/processing and emits `cancelled` instead of `done`.
- Added a restore-from-backup confirmation when unsaved editor changes exist, so users are warned before their in-memory edits are replaced by backup content.
- Fixed a shutdown flow bug where choosing "Exit anyway?" for an in-progress import and then backing out at the unsaved-changes prompt could still cancel the import. The stop flag is now only set after all close confirmations succeed.
- Added confirmation before removing a saved custom source, reducing accidental deletes from the compact remove button.
- Refined normalization/cleaning so non-blocking mappings like `192.168.1.10 nas` are preserved during Cleaned Save instead of being rewritten to `0.0.0.0`.
- Whitelist filtering now applies only to block-style entries, which prevents allowlists from accidentally deleting legitimate custom IP mappings.

### Additional validation

- Re-ran:

```powershell
python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py
python -m unittest discover -s tests -v
```

- Re-ran PowerShell parser validation for `PythonLauncher.ps1`.
- After this follow-up pass, all **20** Python tests were passing.

## Codex Premium UX Follow-Up — 2026-04-15

### Additional premium-polish work completed

- Added a clearer save-action hierarchy so `Save Cleaned` stays the primary action, while `Save Raw` reads as the more exact/manual path.
- Replaced the old “applied” save-button treatment with a calmer saved-state treatment and added a dedicated hero badge for current editor state:
  - unsaved editor changes
  - matches disk copy
  - saved cleaned snapshot
  - empty editor
- Added section-level helper copy across the sidebar so search, import mode, manual paste, whitelist, and save behavior are easier to understand at a glance.
- Added a custom-source empty state so the persistent custom feed area feels intentional even before first use.
- Upgraded the preview window copy so it reads more like a deliberate review surface, including clearer delta counts and more human secondary actions.
- Upgraded both selection dialogs:
  - batch import now shows a live selected-count summary and source host labels
  - match-removal now shows a live selected-count summary, keeps long lines readable, and uses clearer “Keep Remaining” wording
- Added a subtle status-bar shortcut hint so common actions are discoverable without opening documentation.
- Improved warning/dry-run status coloring so caution states read distinctly from success and neutral states.
- Added a real About dialog instead of a status-line stub, with feature and shortcut guidance.
- Refined confirmation and recovery microcopy so empty saves, reloads, exits-during-import, backup failures, and emergency recovery read more clearly and less abruptly.
- Refined cleaned-save preview/warning semantics so pure normalization is no longer presented like an error, and the live warning banner now distinguishes removals from harmless standardization work.
- Improved batch-import feedback so startup, progress, stop behavior, and completion messages explain what is happening more clearly.
- Removed the now-unused `ActionApplied.TButton` style after replacing it with the calmer saved-state button treatment.
- Added action-specific preview button labels so previews now say exactly what will happen:
  - `Save Cleaned`
  - `Restore Backup`
  - `Apply Cleaned Version`
  - `Remove Selected`
- Added readable failed-source summaries after imports complete with warnings or complete failure, instead of only showing a count in the status bar.
- Added consistent `parent=self.root` / `parent=self` wiring to the main message boxes so important dialogs stay attached to the app window on Windows.
- Added `summarize_clean_changes(...)` so cleaned-save, clean-preview, and dry-run result text now use one consistent phrasing model instead of drifting between different counter styles.
- Added regression tests for:
  - clean-change status summary formatting
  - failed-source summary truncation logic
- Added live sidebar summaries for:
  - saved custom-source count
  - non-empty manual-input line count, including the active import mode
  - whitelist entry count plus whether those edits are saved or still pending
- Added `count_nonempty_lines(...)` and a regression test for it so the new manual-input summary stays stable.

### Validation

- Re-ran:

```powershell
python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py
python -m unittest discover -s tests -v
```

- Re-ran PowerShell parser validation for `PythonLauncher.ps1`.
- Removed `__pycache__` artifacts after the validation run.
