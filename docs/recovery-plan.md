# Recovery Apply Plan

F044 is a recovery spike for restore-point or VSS-backed apply. HostsFileGet does not yet execute System Restore or VSS operations automatically; it now emits a reviewed, plan-only recovery checklist before high-risk hosts writes.

The existing write path still creates normal rolling and timestamped hosts backups before real writes.

## Command

Print the plan:

```powershell
python hosts_editor.py --recovery-plan
```

Write JSON for review or change-management records:

```powershell
python hosts_editor.py --recovery-plan-output .\recovery-plan.json --recovery-plan-description "Before hosts update"
```

## What The Plan Covers

- HostsFileGet's built-in `.bak` and timestamped hosts backups.
- A Windows System Restore point command using `Checkpoint-Computer`.
- VSS discovery/create commands for manual administrator review.
- The apply contract: the command is plan-only, and hosts writes remain explicit, previewed, and backup-backed.

## Why It Is Plan-Only

System Restore and VSS are machine-wide recovery mechanisms, not simple file-copy operations. Automating them inside a hosts editor requires more work around:

- System Protection availability and restore-point throttling.
- Administrator privilege checks.
- VSS shadow lifecycle cleanup.
- Volume selection on systems where `%SystemRoot%` is not on `C:`.
- Clear user consent before creating machine-wide recovery artifacts.

The spike keeps the generated commands visible and reviewable without adding hidden system mutations to normal save/apply flows.

## Recommended Use

1. Run `--recovery-plan-output` before a high-risk batch update.
2. If System Protection is enabled and a restore point is appropriate, run the displayed `Checkpoint-Computer` command from an elevated PowerShell session.
3. Use normal HostsFileGet preview/save/apply flows.
4. Prefer HostsFileGet `.bak`, timestamped backups, and optional Git history restore for normal hosts-only rollback.

## Boundaries

- No restore point is created by `--recovery-plan`.
- No VSS shadow is created by `--recovery-plan`.
- No hosts file is written by `--recovery-plan`.
- Future full automation must remain opt-in and must fail closed when recovery setup is unavailable.
