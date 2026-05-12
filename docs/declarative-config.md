# Declarative Config

HostsFileGet supports a small declarative profile file for automation and repo-backed review. It is separate from the app's internal JSON config. Applying a declarative file updates the HostsFileGet app config only; it does not write `C:\Windows\System32\drivers\etc\hosts`.

## Commands

Preview the change without writing:

```powershell
python hosts_editor.py --config-plan .\profile.yaml
```

Apply a profile to the app config:

```powershell
python hosts_editor.py --config-apply .\profile.toml
```

Export the active app profile:

```powershell
python hosts_editor.py --config-export .\profile.yaml
python hosts_editor.py --config-export .\profile.toml
python hosts_editor.py --config-export .\profile.json
```

`--config-apply` creates or replaces the matching named profile, makes it active, and mirrors its whitelist, custom sources, pinned domains, and preferred block sink into the top-level runtime fields. Existing operational metadata such as source freshness timestamps, cached-response metadata, backup settings, and saved-state hashes stay in the internal app config.

## YAML Shape

```yaml
schema: "hostsfileget.declarative.v1"
profile:
  id: "work"
  name: "Work"
  preferred_block_sink: "0.0.0.0"
  whitelist:
    - "safe.example"
    - "internal.example"
  pinned_domains:
    - "must-block.example"
  custom_sources:
    - name: "Example Feed"
      url: "https://example.com/hosts.txt"
```

The built-in YAML reader is intentionally small and dependency-free. It supports this exact profile-oriented subset: top-level scalar fields, a `profile` mapping, string/list profile fields, and `custom_sources` entries with `name` and `url`.

## TOML Shape

```toml
schema = "hostsfileget.declarative.v1"

[profile]
id = "work"
name = "Work"
preferred_block_sink = "0.0.0.0"
whitelist = ["safe.example", "internal.example"]
pinned_domains = ["must-block.example"]

[[profile.custom_sources]]
name = "Example Feed"
url = "https://example.com/hosts.txt"
```

## Fields

| Field | Required | Notes |
| --- | --- | --- |
| `schema` | Yes | Must be `hostsfileget.declarative.v1` |
| `profile.id` | No | Lowercase-safe slug after sanitation; unsafe values fall back to `default` |
| `profile.name` | No | Display label, normalized to one line |
| `profile.preferred_block_sink` | No | One of `0.0.0.0`, `127.0.0.1`, `::`, `::1` |
| `profile.whitelist` | No | List or newline string; sanitized into the internal newline format |
| `profile.pinned_domains` | No | List of domains kept blocked even when broad whitelist rules would remove them |
| `profile.custom_sources` | No | List of `{name, url}` objects; HTTP/HTTPS URLs only |

Unsupported fields are ignored by the profile sanitizer. Unsupported YAML shapes are rejected instead of guessed.

## Review Workflow

1. Keep the declarative file under normal source control.
2. Run `--config-plan` in CI or before applying locally.
3. Run `--config-apply` to update the local app profile.
4. Launch the GUI or run existing import/update flows to preview and write the actual hosts file.

This keeps policy review separate from privileged hosts-file writes.
