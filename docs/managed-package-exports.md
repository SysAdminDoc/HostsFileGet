# Managed Package Exports

HostsFileGet managed package exports are guarded bundle generators for enterprise software distribution tools. They write local artifacts for Microsoft Intune Win32 apps, Group Policy startup scripts, PDQ Deploy packages, and Microsoft Configuration Manager applications.

HostsFileGet does not upload packages, edit Group Policy, import PDQ packages, create Configuration Manager applications, call Microsoft Graph, store tenant credentials, or assign deployments.

Generated plans and target field maps include the shared `hostsfileget.handoff-contract.v1` block described in `docs/integration-handoff-contract.md`.

## CLI

List supported targets:

```powershell
python hosts_editor.py --managed-package-list
```

Create a bundle:

```powershell
python hosts_editor.py --managed-package-export intune-win32 .\managed-hosts.txt .\managed-bundle `
  --managed-package-version 2.27.0 `
  --managed-installer-url https://github.com/SysAdminDoc/HostsFileGet/releases/download/v2.27.0/HostsFileGet.exe `
  --managed-sha256 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA `
  --managed-label "Corp Managed"
```

Required inputs:

- `TARGET`: one of `intune-win32`, `gpo-startup`, `pdq-deploy`, or `sccm-application`; short aliases such as `intune`, `gpo`, `pdq`, and `sccm` are accepted.
- `INPUT`: a reviewed hosts-like file. Duplicate domains are collapsed and unsupported lines are ignored by the normal hosts parser.
- `OUTPUT_DIR`: a local directory for generated artifacts.
- `--managed-installer-url`: HTTPS URL for the signed release executable operators will stage with the bundle.
- `--managed-sha256`: SHA-256 checksum for the staged executable.

Optional inputs:

- `--managed-package-version`: release version to write into tool metadata.
- `--managed-label`: label for the fenced managed hosts block.
- `--managed-install-dir`: install directory, defaulting to `%ProgramFiles%\HostsFileGet`.
- `--managed-exe-name`: staged executable filename, defaulting to `HostsFileGet.exe`.

## Bundle Contents

Every target writes:

- `managed-package-export-plan.json`: schema, target metadata, release URL/checksum, source references, generated commands, warnings, artifact paths, and `handoff_contract`.
- `MANAGED_PACKAGE_EXPORT.md`: operator handoff notes for the specific bundle.
- `Install-HostsFileGetManaged.ps1`: elevated installer wrapper. It verifies the staged executable SHA-256, copies it into the install directory, records uninstall metadata, and applies managed hosts only when `-ApplyManagedHosts` is passed.
- `Detect-HostsFileGetManaged.ps1`: detection script that exits `0` only when the installed executable exists and matches the expected SHA-256.
- `Uninstall-HostsFileGetManaged.ps1`: elevated uninstall wrapper. It removes the install directory and uninstall registry key, and removes managed hosts only when `-RemoveManagedHosts` is passed.
- `managed-hosts-lines.txt`: a fenced hosts block using `# --- HostsFileGet Managed Start: ... ---` and `# --- HostsFileGet Managed End: ... ---` markers.

Target-specific artifacts:

- `intune-win32-app.json`: Intune Win32 app field map plus the `IntuneWinAppUtil.exe` content-prep command and handoff contract.
- `gpo-startup-deployment.md`: Group Policy startup/removal script instructions for a UNC-staged bundle and handoff boundary text.
- `pdq-package-fields.json`: PDQ Deploy custom package field map, PowerShell step commands, and handoff contract.
- `configmgr-application-fields.json`: Configuration Manager application/deployment-type field map and handoff contract.

## Safety Contract

- The generated bundle is plan-only and records `execution: not-run`.
- Install and uninstall scripts require elevation or LocalSystem.
- The installer fails before copying if the staged executable hash does not match the provided SHA-256.
- The managed hosts block is opt-in at install time through `-ApplyManagedHosts`.
- Managed hosts rollback is opt-in at uninstall time through `-RemoveManagedHosts`.
- Operators should pilot detection, uninstall, and managed-hosts rollback before broad assignment.
- Official broad deployment should use signed release artifacts. Unsigned local builds are suitable only for lab validation.
- The `handoff_contract.will_not` section records that HostsFileGet will not upload packages, edit deployment systems, call Microsoft Graph, assign deployments, download the signed executable, or silently apply/remove managed hosts.

## Target Notes

### Intune Win32

Run the IntuneWinAppUtil content prep command from the generated JSON, upload the `.intunewin` package in Intune, then copy the generated install, uninstall, and detection values into the Win32 app record.

### Group Policy

Group Policy Software Installation is MSI-oriented, so the generated handoff uses a computer startup script instead of pretending to produce a native MSI package. Stage the bundle on a read-only UNC share available to target computer accounts.

### PDQ Deploy

Use the generated JSON as a field map for a custom PDQ Deploy package. HostsFileGet does not emit PDQ proprietary package XML because importing a guessed schema would be less trustworthy than explicit package fields.

### Configuration Manager

Use the generated JSON as a field map for an application deployment type. The install, uninstall, and detection commands are the same guarded PowerShell wrappers used by the other targets.

## Source References

- Microsoft Intune Win32 app content prep: `https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-win32-prepare`
- Microsoft Intune Win32 app metadata: `https://learn.microsoft.com/en-us/mem/intune-service/apps/apps-win32-add`
- Group Policy software installation constraints: `https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/use-group-policy-to-install-software`
- Group Policy startup scripts: `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn789196(v=ws.11)`
- PDQ Deploy package management: `https://docs.pdq.com/current-version/deploy/manage-packages.htm`
- PDQ Deploy CLI: `https://docs.pdq.com/current-version/deploy/deploy-cli.htm`
- Configuration Manager applications: `https://learn.microsoft.com/mem/configmgr/apps/deploy-use/create-applications`
- Configuration Manager deployment install/detection workflow: `https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/app-management/understand/deployment-install-technical-reference`
