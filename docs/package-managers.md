# Package Manager Manifests

HostsFileGet keeps Winget and Chocolatey manifests as templates so release metadata is rendered from the actual release URL and SHA-256 checksum.

## Templates

- `packaging/winget/*.template`
- `packaging/chocolatey/**/*.template`

Templates use these tokens:

- `{{VERSION}}`
- `{{INSTALLER_URL}}`
- `{{SHA256}}`

## Render Locally

For a built release executable, prefer the reproducible release-artifact script because it computes the SHA-256, renders the manifests, and writes the zip in one pass:

```powershell
python scripts\build_release_artifacts.py `
  --exe dist\HostsFileGet.exe `
  --version 2.27.0 `
  --tag v2.27.0 `
  --repository SysAdminDoc/HostsFileGet `
  --output-dir dist
```

The lower-level renderer is still available when you already have a release URL and checksum:

```powershell
python scripts\render_package_manifests.py `
  --version 2.27.0 `
  --installer-url https://github.com/SysAdminDoc/HostsFileGet/releases/download/v2.27.0/HostsFileGet.exe `
  --sha256 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA `
  --output-dir dist\package-manifests
```

## Release Workflow

`.github/workflows/release.yml` runs `scripts\build_release_artifacts.py` after signing and non-GUI executable verification, then stores the package manifests in:

```text
dist\HostsFileGet.package-manifests.zip
```

That zip and `dist\HostsFileGet.release-artifacts.json` are uploaded as workflow artifacts and as GitHub release assets on tag builds.

## Managed Deployment Handoffs

Winget and Chocolatey manifests describe public package-manager submission metadata. Enterprise deployment bundles are generated separately by:

```powershell
python hosts_editor.py --managed-package-list
python hosts_editor.py --managed-package-export intune-win32 .\managed-hosts.txt .\managed-bundle --managed-installer-url https://github.com/SysAdminDoc/HostsFileGet/releases/download/v2.27.0/HostsFileGet.exe --managed-sha256 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

See `docs/managed-package-exports.md` for the Intune, Group Policy startup script, PDQ Deploy, and Configuration Manager export contract.

## Publishing Boundary

The generated files are submission-ready metadata, not automatic publication:

- Winget publication still requires a PR to `microsoft/winget-pkgs`.
- Chocolatey publication still requires package validation and a push through the Chocolatey community package flow.
- Official publication should use signed release artifacts when signing secrets are configured.
