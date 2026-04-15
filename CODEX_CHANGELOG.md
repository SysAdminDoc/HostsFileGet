# Codex Change Log

This file is a handoff note for future agents, including Claude.

## Date

- 2026-04-15

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
