# Windows Sandbox And VM Hosts Bundle

HostsFileGet can write a reviewable lab bundle for testing a hosts file inside Windows Sandbox or staging it for a Hyper-V VM. The bundle contains the staged `hosts` file, a guest-side PowerShell apply script, a Windows Sandbox `.wsb` launcher config, and a JSON plan.

This is not a live VM mutator. HostsFileGet does not launch Windows Sandbox, start a VM, enable integration services, or copy files into a guest.

## CLI

```powershell
python hosts_editor.py --sandbox-vm-hosts-plan .\cleaned-hosts.txt .\sandbox-hosts-bundle
```

Add optional Hyper-V review commands:

```powershell
python hosts_editor.py --sandbox-vm-hosts-plan .\cleaned-hosts.txt .\sandbox-hosts-bundle --sandbox-vm-name "Lab VM"
```

Tune the Windows Sandbox config:

```powershell
python hosts_editor.py --sandbox-vm-hosts-plan .\cleaned-hosts.txt .\sandbox-hosts-bundle --sandbox-networking Disable --sandbox-vgpu Disable --sandbox-memory-mb 4096
```

## Output

The output directory contains:

- `hosts`: exact staged hosts content from the input file.
- `Apply-HostsFileGetHosts.ps1`: guest-side script that backs up the current guest hosts file, copies the staged file into place, and flushes DNS.
- `HostsFileGet-Sandbox.wsb`: Windows Sandbox config that maps the bundle read-only and runs the setup script at logon.
- `sandbox-vm-hosts-plan.json`: JSON summary with hashes, artifact paths, warnings, and optional Hyper-V review commands.

The Sandbox config maps the output folder read-only into `C:\HostsFileGet`. Opening the `.wsb` file runs the setup script inside the disposable sandbox. Closing Windows Sandbox deletes the sandbox state.

## Hyper-V Boundary

When `--sandbox-vm-name` is supplied, the JSON plan includes `Enable-VMIntegrationService` and `Copy-VMFile` commands with `-WhatIf`. These commands stage the `hosts` file and apply script under `C:\HostsFileGet` inside the guest; they do not directly overwrite the VM's system hosts file.

After review, snapshot the VM, remove `-WhatIf`, stage the files, sign in to the guest, and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\HostsFileGet\Apply-HostsFileGetHosts.ps1
```

The guest-side script creates a `.hostsfileget-lab.bak` backup before replacing the guest hosts file.

## Safety Notes

- The default Sandbox config disables networking and vGPU.
- Mapped folders are read-only from inside Windows Sandbox.
- Hyper-V commands are review-only and include `-WhatIf`.
- Persistent VMs should be snapshotted or otherwise backed up before the guest-side apply script is run.
- Empty hosts input is allowed for explicit lab testing but is warned because it would replace the sandbox or guest hosts file with an empty file.

## Source Basis

- Microsoft Windows Sandbox configuration documentation: https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file
- Microsoft `Copy-VMFile` Hyper-V documentation: https://learn.microsoft.com/en-us/powershell/module/hyper-v/copy-vmfile
- Microsoft `Enable-VMIntegrationService` Hyper-V documentation: https://learn.microsoft.com/en-us/powershell/module/hyper-v/enable-vmintegrationservice
