<!-- codex-branding:start -->
<p align="center"><img src="icon.png" width="128" alt="Hosts File Get"></p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-preview-58A6FF?style=for-the-badge">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-4ade80?style=for-the-badge">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Python%20GUI-58A6FF?style=for-the-badge">
</p>
<!-- codex-branding:end -->

# Hosts File Get

Hosts File Get is a Windows-first desktop tool for inspecting, cleaning, importing, and safely writing the system `hosts` file.

It is designed for people who work with large blocklists, external feed imports, local allowlists, and log-derived domains, without forcing them to hand-edit `C:\Windows\System32\drivers\etc\hosts`.

## Highlights

- Split save modes:
  - `Save Raw` writes the editor exactly as-is
  - `Save Cleaned` applies normalization, deduplication, and whitelist filtering first while preserving non-blocking custom IP mappings
- Live impact stats:
  - active entry count
  - duplicate removals
  - whitelist removals
  - normalization count
- Polished workspace:
  - clearer save hierarchy with `Save Cleaned` as the safer primary action
  - live session badges for admin state, editor state, import mode, and write mode
  - live sidebar summaries for custom sources, pasted manual content, and whitelist state
  - selection-aware import/removal dialogs plus calmer sidebar guidance and empty states
- Safe write workflow:
  - backup creation before save
  - preview before cleaned writes
  - dry-run mode for no-write validation
  - unsaved-change prompts on reload and exit
- Import pipeline:
  - curated web blocklists
  - batch import with filtering and progress
  - custom persistent sources
  - pfSense DNSBL log import
  - NextDNS CSV import
  - manual pasted list import
- Search and cleanup:
  - find / next / previous navigation
  - remove matching entries with selection + preview
- Operational utilities:
  - DNS cache flush
  - backup restore preview
  - emergency DNS recovery helper

## Supported Input Shapes

The cleaner/importer is more flexible than a plain hosts parser. It can normalize:

- standard hosts lines like `0.0.0.0 example.com`
- bare domains like `example.com`
- wildcard domains like `*.example.com`
- URL-style entries like `https://example.com/path`
- adblock-style rules like `||tracker.example^`
- dnsmasq-style rules like `address=/telemetry.example/0.0.0.0`

## Requirements

- Windows
- Python 3.x
- Administrator privileges for real hosts-file writes

The app can still be useful without elevation in dry-run mode, but raw/cleaned saves to the system hosts file require admin rights.

## Quick Launch

### Option 1: Launcher script

Run the launcher from an elevated PowerShell session:

```powershell
.\PythonLauncher.ps1
```

The launcher will:

- ensure `winget` is available
- reuse an existing Python 3 runtime when possible
- install Python only if needed
- refresh the cached `hosts_editor.py` when the download succeeds
- fall back to the last valid cached editor copy if the network refresh fails
- launch the editor

### Option 2: Run directly

```powershell
python hosts_editor.py
```

If you are not already elevated, the app will attempt to relaunch with Administrator privileges. If elevation is declined, it can still open in a read-only / dry-run-friendly state.

## Main Workflow

1. Launch the app as Administrator if you plan to write the real hosts file.
2. Import sources, paste entries, or edit directly in the main editor.
3. Maintain a persistent whitelist in the sidebar.
4. Review live warning stats and previews.
5. Choose `Save Raw` or `Save Cleaned` depending on intent.
6. Flush DNS if you want the OS cache updated immediately.

## Search and Removal

The search box is both a navigator and a cleanup tool.

- `Find`, `Prev`, and `Next` move through matches
- `Remove` opens a selection dialog for matching non-comment entries
- removal is previewed before being applied

Keyboard shortcuts:

- `Ctrl+F` focus search
- `Ctrl+S` save cleaned
- `Ctrl+Shift+S` save raw
- `F5` refresh from disk

## Safety Notes

- `Save Cleaned` always shows a preview when it would change the file.
- Empty saves require confirmation.
- Reloading from disk prompts before discarding unsaved editor changes.
- Restoring from backup is previewed before writing.
- The emergency recovery action is intentionally destructive and should be treated as a last resort.

## Tests

Run the regression suite with:

```powershell
python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py
python -m unittest discover -s tests -v
```

## Repository Notes

- Main application: `hosts_editor.py`
- Launcher: `PythonLauncher.ps1`
- Regression tests: `tests/test_hosts_editor_logic.py`
- Codex handoff notes: `CODEX_CHANGELOG.md`

## License

MIT
