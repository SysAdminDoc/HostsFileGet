# HostsFileGet Architecture

This document maps the current implementation before larger roadmap work splits the monolith. It is intentionally descriptive, not aspirational.

## Product Boundary

HostsFileGet is a Windows-first desktop utility for local hosts-file management. It imports and normalizes blocklists, previews changes, writes the system hosts file safely, and provides local diagnostics around DNS and source provenance.

It is not a DNS server, browser ad blocker, cloud filtering service, or endpoint agent. Features that need those capabilities should be implemented as import/export adapters, diagnostics, or optional companion tooling.

## Runtime Targets

- Primary OS: Windows.
- Language: Python 3.x.
- UI toolkit: Tkinter and `ttk`.
- Launcher: PowerShell script with WPF splash/bootstrap behavior.
- Package target: PyInstaller one-file Windows executable using `HostsFileGet.spec`.
- Privilege model: administrator rights are required for writes to the real system hosts file; dry-run and analysis flows can run without elevation.

## Entry Points

| Entry point | Purpose |
| --- | --- |
| `hosts_editor.py` | GUI application, CLI, pure parsing/normalization helpers, config, imports, exports, and save logic |
| `PythonLauncher.ps1` | Elevated bootstrapper that finds or installs Python, refreshes cached editor code, and launches the app |
| `HostsFileGet.spec` | PyInstaller build definition |
| `.github/workflows/source-health.yml` | Scheduled/manual curated-source reachability report |
| `tests/test_hosts_editor_logic.py` | Regression suite for pure logic, deterministic parser fuzzers, golden cleaned-output fixtures, and selected GUI-adjacent helper paths |
| `tests/test_gui_smoke.py` | Tk smoke tests for patched main-window startup and basic modal construction; skips when Tk cannot create a root |
| `tests/test_benchmarks.py` | Smoke coverage for the benchmark harness without enforcing hardware-dependent timing budgets |
| `benchmarks/large_file_benchmark.py` | Deterministic large-file parser/cleaner benchmark with human and JSON output |

## Repository Layout

| Path | Role |
| --- | --- |
| `README.md` | User-facing overview and launch workflow |
| `CHANGELOG.md` | Release history |
| `ROADMAP.md` | Sourced feature register and implementation progress |
| `ARCHITECTURE.md` | Current implementation map |
| `TROUBLESHOOTING.md` | Hosts-file limitations and operational recovery guide |
| `CODEX_CHANGELOG.md` | Development-agent handoff notes |
| `data/blocklist_sources.json` | Versioned curated blocklist catalog loaded at startup |
| `docs/source-manifest.md` | Curated source manifest schema and maintenance rules |
| `docs/source-health.md` | Source reachability checker and report format |
| `docs/source-overlap.md` | Source overlap matrix behavior and limits |
| `docs/false-positive-triage.md` | Check Domain triage behavior, actions, and limits |
| `docs/entry-provenance.md` | Line-level provenance/blame report behavior and limits |
| `docs/windows-dns-client.md` | Windows DNS Client Operational snapshot import behavior and limits |
| `docs/dns-bypass-diagnostics.md` | Browser encrypted-DNS/proxy bypass diagnostic behavior and limits |
| `docs/accessibility.md` | Contrast audit, font assumptions, and manual Windows accessibility release checks |
| `CLAUDE.md` | Compact architecture and gotchas snapshot for agents |
| `default.txt` | Sample/default hosts content |
| `icon.png` | App branding asset |
| `build/`, `dist/` | Local PyInstaller outputs, not source-of-truth |

## `hosts_editor.py` Structure

The app is currently a single large module with four layers mixed in one file. Keep changes localized and favor adding pure helper functions with tests when possible.

### Constants And Environment

The top of the file defines application metadata, source limits, import limits, default hosts paths, UI colors, and policy constants. Important constraints live here:

- `APP_NAME`, `APP_VERSION`
- `CONFIG_SCHEMA_VERSION`, `SOURCE_MANIFEST_SCHEMA_VERSION`
- `MAX_DOWNLOAD_BYTES`
- `SOURCE_PREVIEW_MAX_BYTES`
- `NDIFF_LINE_LIMIT`
- `MATCH_REMOVAL_DIALOG_LIMIT`
- `SEARCH_MATCH_LIMIT`
- `BLOCK_SINK_IPS`
- `STOCK_MICROSOFT_HOSTS`
- `PROVENANCE_EVENT_KINDS`

### Dialogs And UI Helpers

These classes are Tkinter/ttk wrappers:

- `ToolTip`
- `PreviewWindow`
- `AddSourceDialog`
- `BulkSelectionDialog`
- `MatchRemovalDialog`

They should stay thin. Business rules belong in pure functions so they can be tested without creating Tk windows.

### Pure Logic Layer

The most stable implementation surface is the pure-function layer before `HostsFileEditor`. It handles:

- Domain/IP parsing: `looks_like_domain`, `_looks_like_ip_token`, `_extract_domain_from_token`.
- Hosts parsing and normalization: `parse_hosts_line_entries`, `normalize_line_to_hosts_entries`, `_get_canonical_cleaned_output_and_stats`, `compute_clean_impact_stats`.
- File IO helpers: `decode_text_bytes`, `read_text_file_lines`, `write_text_file_atomic`.
- Transactional hosts enable/disable helpers: `disable_hosts_file_transactionally`, `enable_hosts_file_transactionally`.
- Download guards: `read_http_body_limited`, `decode_downloaded_lines`, `looks_like_html_document`.
- Config sanitation: `sanitize_custom_sources`, `sanitize_config_snapshot`, `sanitize_profile_snapshot`, `sanitize_profiles_snapshot`, `update_active_profile_snapshot`, `resolve_saved_state_hashes`.
- Source catalog loading: `sanitize_source_manifest`, `load_blocklist_sources_manifest`.
- Source response caching: `fetch_source_with_cache`, `sanitize_source_cache_metadata`, `build_source_request_headers`.
- Source trust display: `build_source_trust_badges`, `source_trust_report_url`, `format_source_trust_details`.
- Source health reporting: `check_source_health_record`, `build_source_health_report`, `summarize_source_health_results`.
- False-positive triage: `build_false_positive_triage_report`, `format_false_positive_triage_report`, `add_domain_to_whitelist_text`, `remove_false_positive_matches_from_lines`.
- Windows diagnostics import: `parse_windows_dns_client_events_xml`, `build_windows_dns_client_wevtutil_command`, `collect_recent_windows_dns_client_queries`.
- DNS bypass diagnostics: `collect_dns_bypass_policy_snapshot`, `dns_bypass_policy_status`, `format_dns_bypass_diagnostics`.
- Accessibility audit: `relative_luminance`, `contrast_ratio`, `build_accessibility_audit_report`, `format_accessibility_audit_report`.
- Cleanup/export/search helpers: `remove_lines_by_indices`, `rewrite_block_sink_ip`, `scan_suspicious_redirects`, `export_lines_as_format`, `strip_lines_by_category`.
- Source analytics: `find_sources_containing_domain`, `summarize_source_contributions`, `build_source_domain_index`, `build_source_overlap_report`, `categorize_entries_by_domain_hint`, `classify_source_freshness`.
- Provenance and pinned-domain helpers: `append_provenance_event`, `read_provenance_events`, `build_entry_provenance_report`, `format_entry_provenance_report`, `build_pinned_export_payload`, `parse_pinned_import_payload`, `sanitize_pinned_domains`.
- Log importers: `parse_pihole_ftl_blocked_domains`, `parse_adguard_home_querylog`.
- Bulk text transformations: `apply_find_replace`, `discover_import_sections`, `remove_import_section`.

When implementing roadmap features, extend this layer first, add tests, then connect it to the GUI.

### GUI Controller

`HostsFileEditor` owns the Tk root, all widgets, config state, background import coordination, and command handlers.

Primary responsibilities:

- Window setup, theme, menus, sidebar, editor pane, status badges, metrics, gutter, dialogs.
- Admin/elevation state and dry-run messaging.
- Config load/save, portable mode, and legacy migration.
- Save raw/save cleaned/dry-run flows.
- Backups, restore, compare, panic restore, hosts disable/enable.
- Import UI, source catalog, custom sources, manual imports, DNS log imports, whitelist import.
- Search, removal, find/replace, context menu commands.
- Source reports, provenance log view, entry provenance, health scan, false-positive triage, preferences, scheduler wizard.
- Worker thread queue handling and safe Tk callback scheduling with `_safe_after`.

`HostsFileEditor` is large enough that future refactors should split by behavior after tests are in place:

- `hostsfileget/parsing.py`
- `hostsfileget/config.py`
- `hostsfileget/sources.py`
- `hostsfileget/importers.py`
- `hostsfileget/exports.py`
- `hostsfileget/provenance.py`
- `hostsfileget/cli.py`
- `hostsfileget/ui/`

Do not start that split unless golden-file tests, CI, and source-manifest validation stay established.

### CLI Layer

The CLI functions live near the bottom of `hosts_editor.py` and intentionally short-circuit before GUI initialization:

- `_cli_backup`
- `_cli_disable`
- `_cli_enable`
- `_cli_apply`
- `_cli_update`
- `_cli_source_health`
- `_handle_cli_args`

Admin-required CLI actions must fail clearly when not elevated. Source health checks are read-only and do not require elevation. Silent mode writes progress to the local CLI log instead of producing noisy scheduler output.

## Data And State Files

| Data | Location | Notes |
| --- | --- | --- |
| Primary config | `%LOCALAPPDATA%\HostsFileGet\hosts_editor_config.json` | Default per-user config; schema documented in `docs/config-schema.md` |
| Portable config | `hosts_editor_config.json` next to script/exe | Used when present; same schema as primary config |
| Curated source manifest | `data/blocklist_sources.json` beside script, exe bundle, or launcher cache | Versioned schema documented in `docs/source-manifest.md` |
| Source response cache | `source_cache\*.bin` beside the active config location | Raw source bodies keyed by normalized URL hash, verified by `source_cache_metadata` |
| Provenance log | Config directory JSONL sidecar | Records pin, unpin, and whitelist events |
| CLI log | `%LOCALAPPDATA%\HostsFileGet\cli.log` | Used by `--silent` |
| Hosts backups | Sibling of system hosts file | Rolling `.bak` plus timestamped snapshots |
| Disabled marker | `hosts.disabled` sibling | Preserves real hosts while disabled |

All writes that can affect the system hosts file should remain previewed or explicitly confirmed unless the CLI command contract says otherwise.

## Import Pipeline

Current import flow:

1. User selects curated/custom/manual/log source.
2. Curated source metadata comes from the validated bundled source manifest.
3. Source rows show locally derived trust badges before import; badges are documented in `docs/source-trust.md`.
4. Download or file parse happens with size limits and encoding guards; web sources use ETag/Last-Modified conditional requests when cached metadata exists.
5. Source content is decoded and obvious HTML/error pages are rejected.
6. Import mode determines whether entries are appended raw or normalized.
7. Generated import sections are marked with sanitized source names.
7. UI updates stats, warnings, source freshness metadata, and unsaved state.

Important invariants:

- Background workers must not call Tk widgets directly.
- Use `_safe_after` for worker-to-UI callbacks.
- Save, refresh, revert, and destructive cleanup are blocked while batch import is active.
- Cancellation must be checked after each in-flight download and before completion is reported.

## Save Pipeline

Raw save writes editor content as-is. Cleaned save normalizes, deduplicates, applies whitelist filtering, preserves custom mappings, and previews changes when cleaning would alter content.

Safety invariants:

- Create a backup before a real write.
- Use atomic writes.
- Preserve custom non-blocking mappings.
- Do not silently save an empty file.
- If the hosts file is temporarily disabled, refuse writes that could overwrite the preserved file.
- If read-only lock is enabled, clear and reapply the attribute around HostsFileGet's own write.
- Update saved-state hashes only after a successful write.

## Test Strategy

The current suite is intentionally pure-function heavy because Tkinter GUI tests are brittle on unattended Windows runners.

Required before large refactors:

- Keep `python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py tests\test_gui_smoke.py tests\test_benchmarks.py benchmarks\large_file_benchmark.py` green.
- Keep `python -m unittest discover -s tests -v` green.
- Keep deterministic fuzz tests seeded; change seeds only when deliberately expanding coverage.
- Update `tests/golden_cleaned/` fixtures intentionally when parser/normalizer behavior changes.
- Keep GUI smoke tests non-destructive: patch admin checks, config load, hosts-file load, first-run, and auto-update paths.
- Keep benchmark tests free of timing assertions; use `benchmarks/large_file_benchmark.py --max-clean-seconds` only on known hardware.
- Keep source-manifest schema tests green before changing curated source metadata.
- Keep source-health tests mocked; live source failures belong in the scheduled report artifact, not normal unit tests.
- Add a minimal GUI smoke test only after CI is available.

## Known Risk Areas

- Full-text rescans during editor changes can lag on very large hosts files.
- Tkinter `Text` is not virtualized; performance work must be measured before large UI rewrites.
- Curated source edits must update `data/blocklist_sources.json`; invalid manifests fail startup and launcher validation.
- Public source health is inherently flaky; use reports for review and only gate when explicitly passing `--source-health-fail-on-unhealthy`.
- PowerShell launcher changes need parser validation because quoting and elevation paths are easy to break.
- PyInstaller packaging should be built from pinned dependencies and scanned for the PyInstaller CVE class noted in the roadmap.
- DNS-over-HTTPS, DNS-over-QUIC, browser private DNS, VPN DNS, and hardcoded device resolvers can bypass the hosts file entirely.

## Refactor Rules

- Move pure functions before UI code when extracting modules.
- Preserve public CLI flags.
- Preserve config compatibility and portable mode.
- Keep source and whitelist changes reviewable.
- Prefer new regression tests before changing parsing, normalization, or save behavior.
- Keep local-first behavior; do not add product telemetry.
