# Config Schema

HostsFileGet stores user settings in JSON. The primary path is `%LOCALAPPDATA%\HostsFileGet\hosts_editor_config.json`; portable mode uses `hosts_editor_config.json` next to the script or executable when that file exists.

## Version

Current schema version: `1`

Every saved config now includes:

```json
{
  "config_version": 1
}
```

Configs without `config_version` are treated as legacy schema `0`, migrated in memory, sanitized, and written back as schema `1` on the next save or legacy-path migration.

## Keys

| Key | Type | Notes |
| --- | --- | --- |
| `config_version` | integer | Current value is `1` |
| `whitelist` | string | Newline-separated whitelist text |
| `custom_sources` | array | Objects with `name` and `url` |
| `last_applied_raw_hash` | string or null | SHA-256 hex digest for saved raw state |
| `last_applied_cleaned_hash` | string or null | SHA-256 hex digest for saved cleaned state |
| `last_open_dir` | string | Existing local directory path |
| `source_last_fetched` | object | Source URL to ISO timestamp |
| `preferred_block_sink` | string | One of `0.0.0.0`, `127.0.0.1`, `::`, `::1` |
| `backup_retention` | integer | Clamped to `0..50` |
| `has_completed_first_run` | boolean | First-run wizard completion |
| `pinned_domains` | array | Sanitized domain list |
| `update_on_launch` | boolean | Opt-in stale-source refresh |
| `lock_after_save` | boolean | Opt-in read-only hosts attribute after save |

Unknown keys are ignored by the sanitizer. They are not preserved when the app writes a fresh config.

## Legacy Migration

Schema `0` includes all configs without a valid `config_version`. The migrator recognizes these legacy aliases before sanitation:

| Legacy key | Current key |
| --- | --- |
| `sources` | `custom_sources` |
| `whitelist_domains` | `whitelist` |
| `last_fetched` | `source_last_fetched` |
| `block_sink` | `preferred_block_sink` |

If both the current key and legacy alias are present, the current key wins.

Invalid, negative, future, or boolean `config_version` values are treated as legacy schema `0`. The known fields are still sanitized and emitted as current schema `1`.

## Compatibility Rules

- Never read config values directly from decoded JSON. Route them through `sanitize_config_snapshot`.
- Add future migrations in `migrate_config_snapshot` before sanitation.
- Keep old keys readable for at least one major version after renaming.
- Clamp numeric values before storing them on the editor instance.
- Validate paths and URLs before storing them on the editor instance.
- Reject malformed saved-state hashes instead of preserving them.
- Keep portable mode and roaming mode payloads schema-compatible.
