# Codex Change Log

This file is a handoff note for future agents, including Claude.

## Date

- 2026-04-15

## Scope

- Audited and upgraded `hosts_editor.py`.
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
- Custom sources now reject duplicate names and duplicate URLs.

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
- Search status was cleaned up so recomputing matches does not flash a noisy “Search cleared” message first.
- Emergency recovery copy was softened/clarified, and the launcher path was made more Windows-native.

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

## Validation Run

These commands were run successfully:

```powershell
python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py
python -m unittest discover -s tests -v
```

At the end of the latest pass, all 8 tests were passing.

## Files Codex Changed

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
