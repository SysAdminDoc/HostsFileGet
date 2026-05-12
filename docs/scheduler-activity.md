# Scheduler Activity

HostsFileGet can register a Windows Task Scheduler entry for unattended source refreshes. The registered command now runs:

```powershell
HostsFileGet --update --silent
```

Silent mode keeps Task Scheduler output quiet, writes progress lines to `%LOCALAPPDATA%\HostsFileGet\cli.log`, and records a bounded structured activity log at `%LOCALAPPDATA%\HostsFileGet\cli-activity.jsonl`.

## Report

Print a local report without launching the GUI:

```powershell
python hosts_editor.py --activity-report
```

Write the same report as JSON:

```powershell
python hosts_editor.py --activity-report --activity-report-output scheduler-activity.json
```

The report includes:

- Task registration status from `schtasks /Query /FO LIST /V`.
- Last run, next run, task status, and last result when the task exists.
- Recent structured silent `--update` events, including exit code, duration, source counts, and final active entry count.
- A short tail of `cli.log` for human-readable context.

## Boundaries

- Activity files are local-only under the app config directory.
- The structured activity log is capped to the latest 200 events.
- `--activity-report` is read-only and does not require Administrator privileges.
- `--update` still refuses to run if the hosts file is temporarily disabled.
- Task Scheduler support remains Windows-only; non-Windows report output marks task status unavailable while still showing local activity files if present.
