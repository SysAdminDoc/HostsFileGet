# Release Build

HostsFileGet release builds are Windows-only until the roadmap explicitly adds another target.

## Inputs

- Python: release workflow pinned to Python 3.12. The compatibility matrix is documented in `docs/runtime-compatibility.md`.
- Build dependencies: `requirements-build.txt`.
- Security tooling: `requirements-security.txt`.
- PyInstaller spec: `HostsFileGet.spec`.
- Application entry point: `hosts_editor.py`.
- Curated source manifest: `data/blocklist_sources.json`.
- Package manager templates: `packaging\winget\` and `packaging\chocolatey\`.
- Managed package export docs: `docs\managed-package-exports.md`.
- Launcher script: `PythonLauncher.ps1`.

## Local Build

Run from the repository root:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements-build.txt
python -m pip install -r requirements-security.txt
python -m py_compile hosts_editor.py hostsfileget\source_catalog.py hostsfileget\config_profiles.py tests\test_source_catalog.py tests\test_config_profiles.py tests\test_hosts_editor_logic.py tests\test_gui_smoke.py tests\test_benchmarks.py tests\test_package_manifests.py benchmarks\large_file_benchmark.py scripts\render_package_manifests.py scripts\build_release_artifacts.py scripts\verify_release_artifact.py scripts\check_release_identity.py
python scripts\check_release_identity.py
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
python scripts\verify_release_artifact.py --exe dist\HostsFileGet.exe --expected-version 2.27.0
python scripts\build_release_artifacts.py --exe dist\HostsFileGet.exe --version 2.27.0 --tag v2.27.0 --repository SysAdminDoc/HostsFileGet --output-dir dist
python hosts_editor.py --managed-package-export intune-win32 .\default.txt dist\managed-package-export --managed-package-version 2.27.0 --managed-installer-url https://github.com/SysAdminDoc/HostsFileGet/releases/download/v2.27.0/HostsFileGet.exe --managed-sha256 (Get-FileHash -Algorithm SHA256 dist\HostsFileGet.exe).Hash
python -m pip_audit -r requirements-build.txt --strict --format cyclonedx-json --output dist\HostsFileGet.sbom.cdx.json
```

Expected output:

- `dist\HostsFileGet.exe`
- `dist\HostsFileGet.exe.sha256`
- `dist\HostsFileGet.sbom.cdx.json`
- `dist\HostsFileGet.release-artifacts.json`
- `dist\package-manifests\`
- `dist\managed-package-export\`
- `dist\HostsFileGet.package-manifests.zip` in GitHub Actions

## GitHub Actions

The release workflow is `.github/workflows/release.yml`.

General CI validates Python 3.12 and 3.14 on Windows; see `docs/runtime-compatibility.md`. Release builds intentionally stay on Python 3.12 until a newer PyInstaller build baseline has a dedicated release smoke pass.

Curated source reachability is tracked by `.github/workflows/source-health.yml`. That workflow uploads a report artifact and does not turn transient upstream outages into normal CI failures.

It runs on:

- tags matching `v*`
- manual `workflow_dispatch`

The workflow:

1. Checks out the repository.
2. Installs Python 3.12.
3. Installs pinned build dependencies from `requirements-build.txt`.
4. Compiles Python sources.
5. Checks release identity/version hygiene.
6. Runs unit tests.
7. Parses `PythonLauncher.ps1`.
8. Builds `dist\HostsFileGet.exe` with PyInstaller.
9. Bundles `data/blocklist_sources.json` into the executable runtime.
10. Signs the executable when signing secrets are configured.
11. Records Authenticode signature status.
12. Runs `scripts\verify_release_artifact.py` against `dist\HostsFileGet.exe --version` and `--help`.
13. Runs `scripts\build_release_artifacts.py` to write `dist\HostsFileGet.exe.sha256`, render package-manager manifests, create a reproducible package-manifest zip, and write `dist\HostsFileGet.release-artifacts.json`.
14. Writes `dist\HostsFileGet.sbom.cdx.json` and audits pinned build dependencies.
15. Uploads release files as workflow artifacts.
16. On tag builds, creates or updates the matching GitHub release assets.

## Code Signing

The workflow supports Authenticode signing when these GitHub Actions secrets exist:

- `WINDOWS_SIGNING_CERTIFICATE_PFX_BASE64`: base64-encoded PFX certificate.
- `WINDOWS_SIGNING_CERTIFICATE_PASSWORD`: PFX password.

If `WINDOWS_SIGNING_CERTIFICATE_PFX_BASE64` is absent, the workflow leaves `HostsFileGet.exe` unsigned and prints that status. This keeps unsigned local/community builds explicit while allowing the same workflow to sign official releases after a certificate is available.

When signing is configured, `WINDOWS_SIGNING_CERTIFICATE_PASSWORD` is required, the Windows SDK must provide `signtool.exe`, and the timestamp server must be reachable. Signing runs before checksum generation; a signing failure stops the workflow so the checksum, package manifests, and release assets cannot describe a different executable than the one that was signed or intentionally left unsigned.

## Build-Tool Security Guard

`requirements-build.txt` pins PyInstaller to `6.20.0`. This is above the vulnerable `<6.0.0` range in [GHSA-p2xp-xx3r-mffc](https://github.com/advisories/GHSA-p2xp-xx3r-mffc). The advisory marks `6.0.0` as patched and notes that `6.10.0` further reworked bootstrap path handling; the pinned build dependency should not be lowered below `6.0.0`.

`scripts/check_release_identity.py` verifies the README version badge, release-facing example versions, PyInstaller pin, `pip-audit` pin, this checklist, and the release workflow gates for `check_release_identity.py`, `build_release_artifacts.py`, and `verify_release_artifact.py`.

## Release Checklist

Before tagging:

- Confirm `CHANGELOG.md` includes the release version and date.
- Confirm `python hosts_editor.py --version`, `APP_VERSION` in `hostsfileget.constants`, the README badge, and the tag agree.
- Run `python scripts\check_release_identity.py`.
- Confirm `data/blocklist_sources.json` validates through the unit tests.
- Confirm `requirements-build.txt` keeps PyInstaller above the `GHSA-p2xp-xx3r-mffc` vulnerable range.
- Run `python -m pip_audit -r requirements-build.txt --strict` and review the dependency audit.
- Run `python scripts\verify_release_artifact.py --exe dist\HostsFileGet.exe --expected-version 2.27.0`.
- Run `python scripts\build_release_artifacts.py --exe dist\HostsFileGet.exe --version 2.27.0 --tag v2.27.0 --repository SysAdminDoc/HostsFileGet --output-dir dist`.
- Generate and review the SHA-256 checksum for `dist\HostsFileGet.exe`.
- Generate and review the SBOM at `dist\HostsFileGet.sbom.cdx.json`.
- Render and inspect package manager manifests in `dist\package-manifests`.
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
