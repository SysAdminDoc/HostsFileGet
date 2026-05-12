# Release Build

HostsFileGet release builds are Windows-only until the roadmap explicitly adds another target.

## Inputs

- Python: pinned by workflow to Python 3.12.
- Build dependencies: `requirements-build.txt`.
- PyInstaller spec: `HostsFileGet.spec`.
- Application entry point: `hosts_editor.py`.
- Launcher script: `PythonLauncher.ps1`.

## Local Build

Run from the repository root:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements-build.txt
python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py
python -m unittest discover -s tests -v

$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path "PythonLauncher.ps1"),
  [ref]$tokens,
  [ref]$errors
) | Out-Null
if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }

python -m PyInstaller --clean --noconfirm HostsFileGet.spec
Get-FileHash -Algorithm SHA256 dist\HostsFileGet.exe
```

Expected output:

- `dist\HostsFileGet.exe`
- SHA-256 checksum for the executable

## GitHub Actions

The release workflow is `.github/workflows/release.yml`.

It runs on:

- tags matching `v*`
- manual `workflow_dispatch`

The workflow:

1. Checks out the repository.
2. Installs Python 3.12.
3. Installs pinned build dependencies from `requirements-build.txt`.
4. Compiles Python sources.
5. Runs unit tests.
6. Parses `PythonLauncher.ps1`.
7. Builds `dist\HostsFileGet.exe` with PyInstaller.
8. Writes `dist\HostsFileGet.exe.sha256`.
9. Uploads both files as workflow artifacts.
10. On tag builds, creates or updates the matching GitHub release assets.

## Release Checklist

Before tagging:

- Confirm `CHANGELOG.md` includes the release version and date.
- Confirm `APP_VERSION` in `hosts_editor.py` matches the intended release.
- Run the local validation commands above.
- Confirm the worktree is clean.
- Tag using `vMAJOR.MINOR.PATCH`.

After the workflow completes:

- Download the artifact or release asset.
- Verify the SHA-256 checksum.
- Launch the executable on Windows.
- Confirm UAC elevation appears for real hosts-file writes.
- Confirm Help/About displays the expected version.

## Signing

The current workflow does not sign `HostsFileGet.exe`. Code signing is tracked separately as F004 because it requires certificate procurement and release-key handling.
