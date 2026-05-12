# Git History

HostsFileGet can keep an optional local Git archive of the hosts file. This is a recovery and review aid for users who already have Git installed; the normal app workflow does not require Git and does not create history unless a history command is explicitly run.

The history repository lives under the active app config directory:

```text
%LOCALAPPDATA%\HostsFileGet\hosts_history_git\
```

Portable mode still keeps the normal app config next to the executable, but the CLI history helpers use the app config directory so the history repo is not accidentally bundled with a portable executable.

## Commands

Show whether Git history is available and list recent snapshots:

```powershell
python hosts_editor.py --history-status
```

Commit the current system hosts file into the local history repository:

```powershell
python hosts_editor.py --history-snapshot
```

Restore a prior snapshot by commit hash:

```powershell
python hosts_editor.py --history-restore 1a2b3c4d5e6f
```

`--history-restore` requires Administrator privileges, refuses to run while the hosts file is in the `.disabled` state, and creates the normal timestamped `.bak` safety backup before writing the restored content.

## Snapshot Contents

Each history commit tracks:

- `hosts`: the archived hosts file content
- `hostsfileget-history.json`: metadata with schema, app version, timestamp, line counts, source label, and SHA-256 hash

Repeated snapshots with identical hosts content are reported as unchanged instead of creating duplicate commits.

## Limits

- Git must be installed and available on `PATH`.
- History is local only. HostsFileGet does not push, pull, sync, or connect to a remote repository.
- Restore is a CLI operation in this first implementation. Use `--history-status` to copy a commit hash, then restore explicitly.
- The Git archive complements normal `.bak` files; it does not replace preview-before-write, backups, or panic restore.
