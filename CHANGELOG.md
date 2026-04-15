# Changelog

All notable changes to HostsFileGet will be documented in this file.

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
