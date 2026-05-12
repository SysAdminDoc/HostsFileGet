# Config Schema

HostsFileGet stores user settings in JSON. The primary path is `%LOCALAPPDATA%\HostsFileGet\hosts_editor_config.json`; portable mode uses `hosts_editor_config.json` next to the script or executable when that file exists.

## Version

Current schema version: `3`

Every saved config now includes:

```json
{
  "config_version": 3,
  "profile_schema_version": 1
}
```

Configs without `config_version` are treated as legacy schema `0`, migrated in memory, sanitized, and written back as schema `3` on the next save or legacy-path migration.

## Keys

| Key | Type | Notes |
| --- | --- | --- |
| `config_version` | integer | Current value is `3` |
| `whitelist` | string | Newline-separated whitelist text |
| `custom_sources` | array | Objects with `name` and `url` |
| `last_applied_raw_hash` | string or null | SHA-256 hex digest for saved raw state |
| `last_applied_cleaned_hash` | string or null | SHA-256 hex digest for saved cleaned state |
| `last_open_dir` | string | Existing local directory path |
| `source_last_fetched` | object | Source URL to ISO timestamp |
| `source_cache_metadata` | object | Source URL to validated ETag/Last-Modified/body-cache metadata |
| `preferred_block_sink` | string | One of `0.0.0.0`, `127.0.0.1`, `::`, `::1` |
| `backup_retention` | integer | Clamped to `0..50` |
| `has_completed_first_run` | boolean | First-run wizard completion |
| `pinned_domains` | array | Sanitized domain list |
| `update_on_launch` | boolean | Opt-in stale-source refresh |
| `lock_after_save` | boolean | Opt-in read-only hosts attribute after save |
| `profile_schema_version` | integer | Current value is `1` |
| `active_profile_id` | string | Safe profile slug for the mirrored active editor profile |
| `profiles` | array | Versioned named profile payloads; see below |

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

Invalid, negative, future, or boolean `config_version` values are treated as legacy schema `0`. The known fields are still sanitized and emitted as current schema `3`.

## Profile Payloads

Schema `3` adds profile groundwork without changing the current single-editor workflow. The top-level `whitelist`, `custom_sources`, `pinned_domains`, and `preferred_block_sink` fields remain the active runtime fields. On save, the app mirrors those fields into the active profile so later profile switching, CLI profile apply, and migration importers have a stable data model to build on.

Every sanitized config contains at least one profile:

```json
{
  "profile_schema_version": 1,
  "active_profile_id": "default",
  "profiles": [
    {
      "schema_version": 1,
      "id": "default",
      "name": "Default",
      "whitelist": "",
      "custom_sources": [],
      "pinned_domains": [],
      "preferred_block_sink": "0.0.0.0"
    }
  ]
}
```

Profile IDs are lowercase slugs containing letters, numbers, `_`, and `-`, up to 64 characters. Duplicate IDs are deterministically suffixed (`work`, `work-2`, and so on). The sanitizer also accepts a mapping shape (`"profiles": {"work": {...}}`) and emits the canonical array shape.

## Declarative Profile Files

The app's internal config remains JSON, but automation can now use a smaller source-of-truth profile file documented in `docs/declarative-config.md`.

Supported CLI actions:

```powershell
python hosts_editor.py --config-plan .\profile.yaml
python hosts_editor.py --config-apply .\profile.toml
python hosts_editor.py --config-export .\profile.yaml
```

Declarative files use schema `hostsfileget.declarative.v1` and contain one profile. Applying one creates or replaces that named profile, makes it active, and mirrors the profile's runtime fields to the top-level config. It preserves operational metadata such as source freshness, cache metadata, backup settings, and saved-state hashes.

## Source Cache Metadata

Schema `2` adds `source_cache_metadata` for conditional source refreshes. The cached body lives under `source_cache\` beside the active config location; the config stores only metadata and a SHA-256 hash.

Per-source metadata shape:

| Key | Type | Notes |
| --- | --- | --- |
| `cache_key` | string | SHA-256 of the normalized source URL |
| `content_sha256` | string | SHA-256 of the cached raw response body |
| `bytes` | integer | Cached raw body size, clamped to the download cap |
| `etag` | string | Optional HTTP `ETag` |
| `last_modified` | string | Optional HTTP `Last-Modified` |
| `content_encoding` | string | Optional HTTP content encoding used for decode |
| `fetched_at` | string | ISO timestamp of the last network body fetch |
| `validated_at` | string | ISO timestamp of the last network validation, including `304 Not Modified` |

## Compatibility Rules

- Never read config values directly from decoded JSON. Route them through `sanitize_config_snapshot`.
- Add future migrations in `migrate_config_snapshot` before sanitation.
- Keep old keys readable for at least one major version after renaming.
- Clamp numeric values before storing them on the editor instance.
- Validate paths and URLs before storing them on the editor instance.
- Reject malformed saved-state hashes instead of preserving them.
- Keep portable mode and roaming mode payloads schema-compatible.
