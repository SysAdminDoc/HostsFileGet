# Changelog

All notable changes to HostsFileGet will be documented in this file.

## [v2.17.0] - 2026-04-18

**Live stats panel — per-category breakdown**
- Added a second row of metric tiles: **Ads / Tracking / Malware / Other**. Categorization is heuristic (keyword matches against the domain) so it's fast, deterministic, and doesn't need any lookup service. Crypto + Social fold into *Other* to keep the row at four tiles.

**Hosts file read-only lock**
- New Preferences checkbox: *Mark hosts file read-only after save*. Sets the Windows `FILE_ATTRIBUTE_READONLY` bit via `attrib +R` after every successful save; HostsFileGet's own saves transparently clear the bit first and re-apply it after. Off by default — interferes with legitimate third-party writers — but HostsMan-parity for users who want the extra tamper resistance.

**Silent CLI mode**
- `--silent` flag suppresses stderr output and routes progress to `%LOCALAPPDATA%\HostsFileGet\cli.log` with ISO timestamps. Designed so Windows Task Scheduler jobs don't spam the dashboard with benign stderr noise. Works with all existing actions (`--backup`, `--update`, `--disable`, etc.).

**Provenance sidecar (audit log)**
- Every pin, unpin, and whitelist action now appends a one-line JSON record to `hosts_editor_provenance.jsonl` next to the config. Each record captures timestamp, action kind, Windows username, and app version.
- Log auto-rotates at 2 MB (keeps one `.1` generation).
- New **Tools > Provenance Log...** dialog shows the most recent 500 entries in a read-only table.

**Tests**
- 8 new regression tests for `categorize_entries_by_domain_hint` (bucketing, dedup, keyword hygiene), `append_provenance_event` / `read_provenance_events` (valid + malformed + missing-file + unknown-kind guard), `PROVENANCE_EVENT_KINDS`, and the new `lock_after_save` config field.
- Suite: **110 tests** (was 102).

## [v2.16.0] - 2026-04-18

**Source freshness at a glance**
- Every curated-source row now shows a coloured dot: green (fresh, <24h), yellow (warm, 1-7d), red (stale, >1 week), gray (never fetched this install). Hover the dot for the last-fetched timestamp.

**Integrity alarm**
- `load_file` now remembers the hash of the last successful load. If an explicit *Refresh* picks up a different hash and the file doesn't match any of our saved states, the status bar flags it: *"hosts file changed on disk since last load by another process."* Doesn't block the reload — security-software rewrites are common — but surfaces the surprise.

**Auto-update on launch (opt-in)**
- New Preferences checkbox: *Re-fetch stale sources on launch*. When enabled and the user is elevated, every previously-imported source with a last-fetched stamp older than a week is refreshed in the background through the existing batch-import pipeline. Skipped silently when already-importing or non-admin.

**Pinned domain import/export (team sharing)**
- `Tools > Pinned Domains...` dialog gains **Import...** and **Export...** buttons. Export writes a versioned JSON payload (`hostsfileget.pinned.v1`) that's deduplicated, sorted, and reviewable in source control. Import accepts that payload or a bare array of domains, confirms the new-count before merging, and skips duplicates silently.

**New curated sources**
- Ads / Tracking: **NextDNS CNAME Cloak** (first-party Eulerian / Keyade / Criteo trackers that evade traditional blocklists).
- Malware / Phishing / Scam: **NRD 14-day** and **NRD 30-day** (xRuffKez Newly-Registered-Domains — high-ROI phishing defense).

**Tests**
- 8 new regression tests covering `classify_source_freshness` (fresh/warm/stale/never, clock-skew), `STALE_*` thresholds, `build_pinned_export_payload` shape, `parse_pinned_import_payload` (export shape / bare list / foreign-schema / wrong-type), and the new `update_on_launch` config field.
- Suite: **102 tests** (was 94).

## [v2.15.0] - 2026-04-18

**Pinned domains**
- New persistent "pinned" concept: domains in the pin set are preserved across Cleaned Save *even if they match your whitelist*. Lets a team whitelist file cover a broad class while individual users keep specific entries blocked.
- Editor right-click menu gains **Pin this domain (star)** and **Unpin this domain**.
- New **Tools > Pinned Domains...** dialog to review, unpin selected, or unpin all.

**Blocked-query log importers**
- **Tools > Import Blocked Queries From Log** cascade: existing *pfSense DNSBL* and *NextDNS CSV* plus two new importers:
  - **Pi-hole FTL (pihole-FTL.db)** — read-only SQLite query of the `queries` table, keeping only block statuses (1/4/5/6/7/8/9/10/11). Runs on a worker thread to keep the UI responsive.
  - **AdGuard Home query log** — streams NDJSON or arrays; only `Filtered*` reason codes (3/4/5/7/8/12) are imported. **Fixed in this release: previous drafts wrongly accepted `NotFilteredAllowList` and `Rewrite` as blocks.**

**Find / replace**
- New **Tools > Find and Replace...** (Ctrl+H). Plain-text or Python-regex, optional case-sensitivity, always previewed before committing.

**Backup diff viewer**
- New **File > Compare Backups...** — pick any two timestamped snapshots (or the rolling `.bak`) and diff them in a read-only preview. Apply button is disarmed so you can't silently overwrite the editor while comparing history.

**Audit fixes**
- **Critical**: right-clicking the editor pane would `AttributeError` in v2.14 because the pin/unpin menu items pointed at missing methods. Added the handlers and integrated the pin set into Cleaned Save.
- **AGH parser**: reason codes `1 (NotFilteredAllowList)`, `9 (Rewrite)`, `10 (RewriteAutoHosts)` no longer treated as blocks.
- **Pi-hole FTL URI**: on Windows, `file:C:/…` was a relative URI fragment; now wrapped through `_sqlite_readonly_uri` that forces an absolute leading slash.
- **DNS resolve** (`Resolve domain (real DNS)` context-menu entry) now runs on a worker thread. Hostile or slow DNS no longer freezes the UI.

**Tests**
- 17 new pure-function tests for `sanitize_pinned_domains`, pinned-aware Cleaned Save, `AGH_BLOCK_REASONS`, `parse_adguard_home_querylog` (NDJSON + array + malformed), `FTL_BLOCKED_STATUS_CODES`, `_sqlite_readonly_uri`, `parse_pihole_ftl_blocked_domains` (against a temporary SQLite fixture), and `apply_find_replace` (plain / regex / case / empty).
- Suite: **94 tests** (was 77).

## [v2.14.0] - 2026-04-17

**Onboarding & preferences**
- Added **first-run wizard** — on the very first launch, a category picker (Ads & Tracking / Malware & Phishing / Windows Telemetry / Adult / Gambling / Social) offers a curated starter import. Existing installs skip the wizard automatically (detected via whitelist or custom-source presence).
- Added **Tools → Preferences…** — configure timestamped backup retention (0–50, default 5) and the default block-sink IP (`0.0.0.0`, `127.0.0.1`, `::`, `::1`). Saved to the persistent config.

**Editor polish**
- Added **syntax highlighting** on the editor pane: loopback IPs render in the accent blue, comments in a muted overlay gray, and `# --- Import Start/End ---` markers get the lavender accent. Tag-only coloring (no background) so warning overlays (red/yellow) still read.

**Discovery**
- Added **Tools → Goto Anything…** (bound to **Ctrl+P**). Fuzzy-finder over every domain in the editor plus every curated and custom source name. Enter jumps the cursor to the matching line; selecting a source prefilters the catalog sidebar.
- Added **Tools → Sources Report…** — per-import-section table ranked by blocking-entry contribution, with line totals and percent share. Surfaces bloated or redundant feeds.

**Automation**
- Added **Tools → Schedule Auto-Update…** — Windows Task Scheduler wizard that registers `schtasks /Create /TN "HostsFileGet Auto-Update" /TR '... --update' /SC {DAILY|WEEKLY|ONLOGON} /RL HIGHEST`. "Remove Schedule" unregisters the task.

**Tests**
- 5 new pure-function tests for `fuzzy_score`, `summarize_source_contributions`, and the new config knobs (`backup_retention`, `has_completed_first_run`). Suite: 66 tests total (was 61).

## [v2.13.0] - 2026-04-17

**Recovery & panic paths**
- Added **File → Panic Restore (Microsoft default)** — one-click load of the stock Windows hosts template into the editor. Distinct from "Revert to Backup": works even when every snapshot is also broken.

**Targeted cleanup**
- Added **Tools → Targeted Cleanup** cascade with previewed, single-category removals: *Remove Comments Only*, *Remove Blank Lines Only*, *Remove Invalid Lines Only*. Each shows a preview diff before applying.
- Added **Tools → Targeted Cleanup → Remove Import Section…** — lists every detected `# --- Raw|Normalized Import Start/End: NAME ---` block in the editor with a checkbox, bulk-delete with preview. Useful for rolling back a single source without wiping all imports.

**Editor polish**
- New **line-number gutter** on the editor pane. Tracks viewport scroll and redraws lazily on idle; no measurable latency impact on 100K-line files.
- Context menu gains **Resolve domain (real DNS)** and **Ping domain** entries — resolve bypasses the hosts file via `socket.getaddrinfo`; ping runs in a background thread so the UI stays responsive.

**Automation**
- New **`--update`** CLI flag: re-fetches every source the GUI has fetched before, applies a Cleaned Save of the merged result, and refreshes the per-source `last_fetched` stamps. Ready for `schtasks` / Task Scheduler jobs.

**Portable mode**
- If `hosts_editor_config.json` exists next to the exe/script, HostsFileGet uses it instead of `%LOCALAPPDATA%`. Lets USB-stick deployments and team-shared configs roam with the binary. **Help → Open Config Folder** honors portable mode too.

**Tests**
- Added 6 new pure-function regression tests covering `strip_lines_by_category`, `discover_import_sections`, `remove_import_section`, and the `STOCK_MICROSOFT_HOSTS` template. Suite: 61 tests total (was 55).

## [v2.12.0] - 2026-04-17

**Hosts-file control**
- Added **File → Disable / Enable Hosts**. Disable swaps the live hosts file for a minimal Microsoft-default template and stashes the current file as `hosts.disabled`; re-enable swaps them back. A one-click kill switch for blocklist troubleshooting (SwitchHosts / HostsMan parity).
- Added **Tools → Convert Block IPs** (`0.0.0.0` / `127.0.0.1` / `::`) with preview — rewrites every loopback-style blocking entry to the chosen sink. Custom LAN mappings (e.g. `192.168.1.10 printer`) are preserved.
- Save flow now keeps the last `N=5` timestamped backups (`hosts.YYYYMMDD-HHMMSS.bak`) alongside the rolling `hosts.bak`. Old snapshots are pruned oldest-first.

**Diagnostics & insight**
- Added **Tools → Check Domain…** — cross-reference a domain against the current editor, the whitelist, and any curated sources fetched this session; shows every line blocking it plus every source list containing it.
- Added **Tools → Hosts Health Scan…** — flags every entry whose IP is not loopback *and* not a private LAN range. These are the classic malware-hijack indicator (e.g. `1.2.3.4 www.google.com`).
- Source catalog now shows **Last fetched: 3 hours ago** in each button's tooltip, persisted in config.

**Imports & catalog**
- Added **Peek** button next to every curated source — fetches the first ~80 lines into a preview popup so you can eyeball a feed's format and health without committing to an import.
- Curated source catalog expanded by **56 verified-live sources** (HTTP 200 confirmed 2026-04):
  - **Major/Unified**: HaGezi Pro / Pro Plus / Multi / Light, 1Hosts Lite/Pro/Xtra, hBlock Aggregate, Ultimate Hosts Blacklist, BlockConvert Aggregate, NeoDev Host
  - **Ads/Tracking**: ShadowWhisperer Ads/Tracking, Lightswitch05 AMP/FB/Aggressive, GoodbyeAds, AdGuard Mobile (ads + spyware), CombinedPrivacyBlockLists, MobileAdTrackers, DandelionSprout URL Shorteners, BlocklistProject Tracking
  - **Telemetry**: WindowsSpyBlocker Extra + Update, jmdugan Microsoft + Facebook, Perflyst Session Replay
  - **Malware/Phishing**: ShadowWhisperer Malware + Scam, ThreatFox, CERT.pl, Phishing Army Extended, Durable Napkin Scam, GlobalAntiScamOrg, Inversion DNS, Curbengh Phishing, CoinBlockerLists + Browser subset, BlocklistProject Fraud + Ransomware
  - **New Category Filters group**: BlocklistProject Gambling/Porn, Sinfonietta Porn/Social/Gambling, Tiuxo Porn/Social, RPiList Gambling/Fake-Science
  - **Regional**: MajkiIT Polish Adservers, Cats-Team AdRules (CN), Schakal (RU)
  - **Vendor/Platform**: Perflyst Vivo + Samsung Smart, llacb47 Smart TV + LG WebOS + Disney

**Editor UX**
- Right-click menu in the editor pane: Whitelist this domain, Copy domain, Toggle comment on selection, Remove this line, Check this domain.
- **Ctrl+/** toggles comment (`# `) on the current line or selection.
- Pure parsing functions remain GUI-free and continue to grow the regression test suite (now **55 tests**, up from 42).

**Export**
- Added **File → Export Cleaned As…** — save the Cleaned Save output in five formats: hosts, domains-only, adblock (`||domain^`), dnsmasq (`address=/domain/0.0.0.0`), pi-hole gravity.

**Automation / CLI**
- New CLI entry points: `--version`, `--disable`, `--enable`, `--backup`, `--apply PATH`. Skipping the GUI is now a first-class workflow for Task Scheduler and scripts. Admin-required actions exit with a clear message when not elevated.

**Documentation**
- Added `ROADMAP.md` — living plan of shipped, in-progress, backlog, and research items organized across ~25 themes (safety, imports, UX, diagnostics, profiles, automation, integration, security/forensics, platform, performance).

## [v2.11.0] - 2026-04-16

**Correctness & safety**
- Fixed hard-coded `C:\Windows\...\hosts` path. The editor now resolves the real Windows location from `%SystemRoot%`, so installations on D:/E: drives, WinPE images, and forensic mounts work correctly.
- Added a 50 MB hard cap on every feed download (both compressed and decompressed) to prevent runaway servers or gzip bombs from OOMing the GUI process.
- Source labels that contain newlines or tabs are scrubbed before being written into generated Start/End import markers. Prevents a malformed source name from injecting extra lines into the hosts output.
- Emergency DNS recovery script now cleans up its orphan `.bat` file in `%TEMP%` if the launch itself fails.

**Performance**
- Preview dialog falls back to a compact unified diff above 10,000 lines. `difflib.ndiff` is O(n*m) and was previously hanging the Preview window for tens of seconds on large editors.
- Match-removal dialog now caps at 2,000 individual checkboxes. Above that, the user is offered a single-confirmation "remove all matches" path (still previewed) instead of Tk hanging while packing 10K+ widgets.

**Reliability**
- Concurrent whitelist web import is now blocked — clicking the Import from Web button twice while a fetch is in flight shows a warning instead of spawning a second thread.
- Background threads that post results back to the Tk main loop now use a guarded `_safe_after` wrapper so a fetch that finishes after the window is closed no longer raises `TclError` on exit.
- All pending `after()` jobs (UI update, source filter, status reset) are cancelled when the window closes, preventing orphan callbacks from firing against destroyed widgets.
- `_check_import_queue` handles `TclError` and a destroyed root gracefully (previously it could spin forever if the user closed the app mid-import).
- `_apply_inline_warnings` and `_on_text_modified_handler` are guarded against widget destruction mid-run.
- `_apply_window_branding` now falls back to a sane 1280×800 when the OS reports zero/negative screen dimensions (remote desktop/headless edge cases).
- `on_closing` never blocks on a config save failure — shutdown always completes.

**Parsing robustness**
- pfSense log importer now matches `dnsbl` case-insensitively so mixed-case log formats (`Dnsbl`, `DnsBL`, etc.) work.
- NextDNS CSV importer rejects empty files up front and handles a missing/empty header row without a confusing attribute error.

**UX & polish**
- Preview window geometry clamps to the available screen so it no longer overflows on 1366x768 and smaller displays.
- Preview window accepts **Enter** to apply changes and focuses the primary action button on open (better keyboard + screen-reader flow).
- Whitelist widget no longer flashes a transient "Unsaved changes are pending" label during initial config load.
- Stat panel numbers now render with thousand separators (e.g., `152,847` instead of `152847`) for readability on very large hosts files.
- Status bar messages are collapsed to a single line and truncated to 220 characters so long exception strings can't distort the layout.
- Added a **Help → Open Config Folder** menu entry so users can inspect or back up `hosts_editor_config.json` without hunting through %LOCALAPPDATA%.
- Config loader now distinguishes corrupt JSON from OS read errors and surfaces the actual error message in the status bar.

**PowerShell launcher**
- Fixed argument quoting that broke when the editor cache path contained spaces; updated header comment from the old project name.
- Renamed internal helper functions to use approved PowerShell verbs (`Write-LauncherStatus`, `Initialize-CacheDirectory`, `Invoke-FileDownload`, `Initialize-PythonRuntime`, `Invoke-EditorBootstrap`).
- Added `Start-Transcript` logging to `%LOCALAPPDATA%\HostsFileGet\launcher.log` so unattended / helpdesk launches leave a forensic trail.

**Concurrency & data safety**
- Added `_block_during_import` guard. Save Raw, Save Cleaned, Refresh, Revert to Backup, and Clean now refuse to run while a batch import is in flight, with a clear status message explaining why. Previously these could run mid-import and write an inconsistent snapshot.
- `save_config` now handles TclError from torn-down widgets, so shutdown during import no longer surfaces a stray traceback.

**File integrity**
- `write_text_file_atomic` now terminates written files with a trailing newline (POSIX-standard convention). Hash round-trip verified by a new regression test so the terminator doesn't flag saved files as "unsaved".

**UX**
- Text editor now scrolls back to the top after a bulk insert (load / import / clean). Previously the view jumped to end-of-file, hiding what was loaded.
- Escape inside the Source Catalog filter clears it and restores the full list.
- Manual and whitelist summary labels now use thousand separators on large counts.
- Canceling the unsaved-changes prompt during Revert to Backup, or the replacement prompt during a whitelist import, now shows explicit "cancelled" status feedback instead of vanishing silently.

**Tests**
- Added regression tests for the download size cap, gzip bomb rejection, SystemRoot-derived hosts path, source-name sanitization, status-message truncation, the worker's oversize-response handling, import-guard behavior, and the atomic-write trailing-newline + hash round-trip.

**Hardened validation (late additions)**
- Custom sources: name now capped at 120 chars, URL at 2083 chars. Any entry containing tab, newline, or other control bytes is rejected — both in the Add-Source dialog and when loading a malformed legacy config.
- Config saved-state hashes: now strictly validated as 64-char lowercase hex. Anything else is discarded so a corrupted config cannot poison the "Unsaved Changes" / "Saved Cleaned Snapshot" badges.
- `_execute_save` produces an actionable hint for Windows `PermissionError` (read-only attribute, AV lock, indexer hold) instead of a bare traceback in the error dialog.
- In-editor search is capped at 50,000 match highlights so a common query against a multi-megabyte hosts file can't freeze Tk while tagging hundreds of thousands of ranges.
- Legacy config files are deleted after successful migration to `%LOCALAPPDATA%\HostsFileGet\`.

**Pass 5 additions**
- **DPI awareness**: calls `SetProcessDpiAwareness(2)` at startup (falls back to `SetProcessDPIAware` on older Windows). Fixes blurry fonts on 125%+ scaled displays, which is the default for most modern laptops.
- **ToolTip UX**: 450ms hover delay (no more flashing tooltips on transient mouse-overs); hides immediately on click or keypress; `<Destroy>` / `TclError` guards around every Tk call so a widget torn down mid-hover no longer raises.
- **Status helpers hardened**: `_reset_status_color` and `_set_status_hint` now swallow `TclError` — harmless on normal runs, prevents stderr noise on shutdown.
- **Launcher TLS**: allows TLS 1.3 where the runtime supports it, falls back to TLS 1.2-only on PS 5.1 / older Windows.
- **Launcher integrity**: editor download now rejects files above 20 MB (no legitimate editor script approaches this — MITM/captive-portal guard).

42 tests total, all passing.

## [v2.10.0] - 2026-04-15

- Threaded whitelist web import so the GUI no longer freezes for up to 15 seconds during download.
- Debounced the source catalog filter input — UI no longer thrashes on every keystroke, now waits 200ms.
- Cached the whitelist set computation so it parses once per keystroke cycle instead of 2x (from _update_diff_stats and _apply_inline_warnings).
- Removed dead code branch in normalize_custom_source_url (unreachable `normalized_path == "/"` check after rstrip).
- Added json.JSONDecodeError handling in load_config — corrupt config files now show a status message instead of crashing.
- Replaced silent print() in save_config error path with a visible status bar error message.

## [v2.9.0] - 2026-04-15

- Fixed critical IPV4 regex bug that failed to recognize IP addresses with octets >= 200 (e.g. 255.255.255.0), causing them to be misidentified as domains during parsing.
- Fixed widget destruction bug where custom_sources_summary_label was not preserved during source list rebuilds, crashing the app on config reload with saved custom sources.
- Fixed emergency DNS recovery bat script: second echo line overwrote the first (> instead of >>), and added a 30-attempt retry limit to prevent infinite loops.
- Fixed stale GitHub URLs in Help menu and PythonLauncher.ps1 still pointing to old repo name (Hosts-File-Management-Tool instead of HostsFileGet).
- Fixed generated hosts file header referencing "Hosts File Editor" instead of the actual app name.
- Reduced redundant text hashing in the UI modification handler chain (get_lines/hash_lines called 4x/3x per keystroke reduced to 1x each).
- Removed needless full text re-insertion into the editor widget on Raw Save and no-change Cleaned Save paths, preserving cursor and scroll position.
- Added regression tests for high-octet IP recognition and IP-vs-domain classification.

## [v2.8.5] - 2026-04-15

- Hardened hosts parsing, normalization, whitelist handling, cleaned-save accounting, and preservation of legitimate custom IP mappings.
- Improved save/reload safety with better prompts, atomic writes, resilient saved-state tracking, and more defensive config handling.
- Upgraded import UX with source filtering, progress feedback, cleaner cancellation/reset behavior, HTML/error-page feed rejection, manual import safeguards, keyword-based removal, whitelist overwrite confirmation, and less frustrating custom-source dialog validation.
- Added a premium UI polish layer with clearer save hierarchy, editor-state badges, calmer helper copy, custom-source empty states, richer preview copy, and selection-aware batch/removal dialogs.
- Refined the product feedback layer with a proper About dialog, calmer confirmation copy, more trustworthy cleaned-save warnings, and clearer import progress / cancellation messaging.
- Improved trust in commit/recovery flows with action-specific preview buttons, readable failed-source summaries after imports, and more consistent main-window parenting for dialogs.
- Consolidated the cleaned-save/result wording behind reusable summary helpers and added regression tests for the new status/failure-summary behavior.
- Added live sidebar summaries for custom sources, manual pasted content, and whitelist state so those areas communicate readiness and scale without extra clicks.
- Added and expanded regression coverage for parser, decoding, custom-source sanitization, and removal helpers.
- Improved launcher behavior to reuse existing Python installations before attempting a winget install, to fall back to a cached editor copy when refresh downloads fail, and to reject obvious HTML/error payloads.

## [v0.1.0] - 2026-04-14

- Added: Add files via upload
- Changed: Update PythonLauncher.ps1
- Changed: Update PythonLauncher.ps1
- Added: Add files via upload
- Added: Add files via upload
- Removed: Delete hosts_editor_v2_8_4.py
- Removed: Delete hosts_editor_v2_8_3.py
- Removed: Delete hosts_editor.py
- Create hosts_editor_v2_8_4.py
- Changed: Update hosts_editor_v2_8_3.py
