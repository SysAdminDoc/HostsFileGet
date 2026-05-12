# Portable Config

HostsFileGet normally stores per-user config under `%LOCALAPPDATA%\HostsFileGet`. Portable mode activates only when `hosts_editor_config.json` exists beside the launched script or executable.

## Inspect Active Paths

```powershell
python hosts_editor.py --config-location
```

The report shows:

- active mode: `local` or `portable`
- active config path
- local-user and portable candidate paths
- sidecar root for source cache, optional Git history, CLI logs, and scheduler activity

This keeps local-user state and portable-bundle state unambiguous before copying or deleting files.

## Create A Portable Bundle Config

```powershell
python hosts_editor.py --portable-export .\portable-bundle
```

The command writes:

- `hosts_editor_config.json`
- `HOSTSFILEGET_PORTABLE.md`

The exported config is sanitized through the current config schema and preserves active profile data. Existing portable configs are not overwritten unless requested:

```powershell
python hosts_editor.py --portable-export .\portable-bundle --portable-overwrite
```

## Sidecar Files

When portable mode is active, these paths resolve beside the portable config:

- `source_cache\`
- `hosts_history_git\`
- `cli.log`
- `cli-activity.jsonl`

Deleting or moving `hosts_editor_config.json` beside the executable returns the app to normal local-user config on the next launch.
