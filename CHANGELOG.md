# Changelog

All notable changes to HostsFileGet will be documented in this file.

## [Unreleased]

- Hardened hosts parsing, normalization, whitelist handling, cleaned-save accounting, and preservation of legitimate custom IP mappings.
- Improved save/reload safety with better prompts, atomic writes, resilient saved-state tracking, and more defensive config handling.
- Improved save/reload safety with better prompts, atomic writes, resilient saved-state tracking, more defensive config handling, safer preview apply behavior, explicit protection against losing unsaved edits during backup restore, and corrected close-flow behavior during in-progress imports.
- Upgraded import UX with source filtering, progress feedback, cleaner cancellation/reset behavior, HTML/error-page feed rejection, manual import safeguards, keyword-based removal, whitelist overwrite confirmation, and less frustrating custom-source dialog validation.
- Added a premium UI polish layer with clearer save hierarchy, editor-state badges, calmer helper copy, custom-source empty states, richer preview copy, and selection-aware batch/removal dialogs.
- Refined the product feedback layer with a proper About dialog, calmer confirmation copy, more trustworthy cleaned-save warnings, and clearer import progress / cancellation messaging.
- Improved trust in commit/recovery flows with action-specific preview buttons, readable failed-source summaries after imports, and more consistent main-window parenting for dialogs.
- Consolidated the cleaned-save/result wording behind reusable summary helpers and added regression tests for the new status/failure-summary behavior.
- Added live sidebar summaries for custom sources, manual pasted content, and whitelist state so those areas communicate readiness and scale without extra clicks.
- Added and expanded regression coverage for parser, decoding, custom-source sanitization, and removal helpers.
- Improved launcher behavior to reuse existing Python installations before attempting a winget install, to fall back to a cached editor copy when refresh downloads fail, and to reject obvious HTML/error payloads.

## [v0.1.0] - %Y->- (HEAD -> main, origin/main, origin/HEAD)

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
