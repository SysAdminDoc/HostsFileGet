# CLI Profiles

HostsFileGet's internal config can store multiple named profiles. The GUI still presents the existing single-editor workflow, but CLI commands can now list, import, export, and activate profiles without writing the system hosts file.

## Commands

List saved profiles:

```powershell
python hosts_editor.py --profile-list
```

Import a declarative profile without activating it:

```powershell
python hosts_editor.py --profile-import .\work-profile.yaml
```

Activate a saved profile by ID:

```powershell
python hosts_editor.py --profile-apply work
```

Export a saved profile by ID:

```powershell
python hosts_editor.py --profile-export work .\work-profile.toml
python hosts_editor.py --profile-export work .\work-profile.json
```

## Behavior

- `--profile-import` creates or replaces a profile but keeps the current active profile unchanged unless the imported ID is already active.
- `--profile-apply` makes a saved profile active and mirrors its whitelist, custom sources, pinned domains, and preferred block sink into the top-level runtime config fields.
- `--profile-export` writes the same `hostsfileget.declarative.v1` shape documented in `docs/declarative-config.md`.
- None of these commands writes `C:\Windows\System32\drivers\etc\hosts`; use normal save/update flows after reviewing the active config.

This split lets automation stage a profile update, inspect the profile list, then activate it in a separate explicit step.
