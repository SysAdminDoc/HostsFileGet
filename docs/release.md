# Release Build

HostsFileGet release builds are Windows-only until the roadmap explicitly adds another target.

## Inputs

- Python: pinned by workflow to Python 3.12.
- Build dependencies: `requirements-build.txt`.
- Security tooling: `requirements-security.txt`.
- PyInstaller spec: `HostsFileGet.spec`.
- Application entry point: `hosts_editor.py`.
- Curated source manifest: `data/blocklist_sources.json`.
- Package manager templates: `packaging\winget\` and `packaging\chocolatey\`.
- Launcher script: `PythonLauncher.ps1`.

## Local Build

Run from the repository root:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements-build.txt
python -m pip install -r requirements-security.txt
python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py tests\test_gui_smoke.py tests\test_benchmarks.py tests\test_package_manifests.py benchmarks\large_file_benchmark.py scripts\render_package_manifests.py
python -m unittest discover -s tests -v
python -m pip_audit -r requirements-build.txt --strict

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
python scripts\render_package_manifests.py --version 2.20.0 --installer-url https://github.com/SysAdminDoc/HostsFileGet/releases/download/v2.20.0/HostsFileGet.exe --sha256 (Get-FileHash -Algorithm SHA256 dist\HostsFileGet.exe).Hash --output-dir dist\package-manifests
python -m pip_audit -r requirements-build.txt --strict --format cyclonedx-json --output dist\HostsFileGet.sbom.cdx.json
```

Expected output:

- `dist\HostsFileGet.exe`
- `dist\HostsFileGet.exe.sha256`
- `dist\HostsFileGet.sbom.cdx.json`
- `dist\package-manifests\`
- `dist\HostsFileGet.package-manifests.zip` in GitHub Actions

## GitHub Actions

The release workflow is `.github/workflows/release.yml`.

Curated source reachability is tracked by `.github/workflows/source-health.yml`. That workflow uploads a report artifact and does not turn transient upstream outages into normal CI failures.

It runs on:

- tags matching `v*`
- manual `workflow_dispatch`

The workflow:

1. Checks out the repository.
2. Installs Python 3.12.
3. Installs pinned build dependencies from `requirements-build.txt`.
4. Compiles Python sources.
5. Runs unit tests.
6. Audits pinned build dependencies.
7. Parses `PythonLauncher.ps1`.
8. Builds `dist\HostsFileGet.exe` with PyInstaller.
9. Bundles `data/blocklist_sources.json` into the executable runtime.
10. Signs the executable when signing secrets are configured.
11. Records Authenticode signature status.
12. Writes `dist\HostsFileGet.exe.sha256`.
13. Renders Winget and Chocolatey manifests from the release URL and SHA-256.
14. Writes `dist\HostsFileGet.sbom.cdx.json`.
15. Uploads release files as workflow artifacts.
16. On tag builds, creates or updates the matching GitHub release assets.

## Code Signing

The workflow supports Authenticode signing when these GitHub Actions secrets exist:

- `WINDOWS_SIGNING_CERTIFICATE_PFX_BASE64`: base64-encoded PFX certificate.
- `WINDOWS_SIGNING_CERTIFICATE_PASSWORD`: PFX password.

If `WINDOWS_SIGNING_CERTIFICATE_PFX_BASE64` is absent, the workflow leaves `HostsFileGet.exe` unsigned and prints that status. This keeps unsigned local/community builds explicit while allowing the same workflow to sign official releases after a certificate is available.

## Release Checklist

Before tagging:

- Confirm `CHANGELOG.md` includes the release version and date.
- Confirm `APP_VERSION` in `hosts_editor.py` matches the intended release.
- Confirm `data/blocklist_sources.json` validates through the unit tests.
- Run the local validation commands above.
- Confirm the worktree is clean.
- Tag using `vMAJOR.MINOR.PATCH`.

After the workflow completes:

- Download the artifact or release asset.
- Verify the SHA-256 checksum.
- Review the SBOM and dependency audit output.
- Launch the executable on Windows.
- Confirm UAC elevation appears for real hosts-file writes.
- Confirm Help/About displays the expected version.
