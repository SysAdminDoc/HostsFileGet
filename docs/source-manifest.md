# Curated Source Manifest

HostsFileGet keeps the built-in curated blocklist catalog in `data/blocklist_sources.json`.

The GUI and CLI load this file through `hostsfileget.source_catalog.load_blocklist_sources_manifest(...)` at startup. `hosts_editor.py` re-exports that API for compatibility. This keeps source URLs reviewable as data, lets release tooling bundle the catalog explicitly, and gives health/trust work one stable source of truth.

## Version

Current schema version: `1`

```json
{
  "schema_version": 1,
  "categories": []
}
```

Unsupported schema versions fail validation. Add future migrations before changing the shipped schema.

## Shape

```json
{
  "schema_version": 1,
  "categories": [
    {
      "name": "Major / Unified / Aggregated",
      "sources": [
        {
          "name": "Example Source",
          "url": "https://example.com/hosts.txt",
          "description": "Short tooltip text.",
          "lifecycle": "active"
        }
      ]
    }
  ]
}
```

| Field | Type | Rules |
| --- | --- | --- |
| `schema_version` | integer | Must equal `1` |
| `categories` | array | Non-empty |
| `categories[].name` | string | Non-empty, unique case-insensitively, max 120 chars, no control characters |
| `categories[].sources` | array | Non-empty |
| `sources[].name` | string | Non-empty, unique case-insensitively across the manifest, max 120 chars, no control characters |
| `sources[].url` | string | Direct `http` or `https` URL with a host, max 2083 chars, unique after URL normalization, no control characters |
| `sources[].description` | string | Optional tooltip text, max 500 chars, no control characters |
| `sources[].lifecycle` | string | Optional; `active`, `warning`, `deprecated`, or `retired`. Missing means `active` |
| `sources[].lifecycle_reason` | string | Optional maintainer note explaining warning/deprecated/retired state, max 300 chars |
| `sources[].lifecycle_checked_at` | string | Optional date or timestamp for the lifecycle evidence |
| `sources[].replacement_source` | string | Optional in-catalog replacement source name, max 120 chars |
| `sources[].replacement_url` | string | Optional direct `http` or `https` replacement URL |
| `sources[].notes` | string | Optional source-specific maintenance note, max 500 chars |

## Lifecycle States

| State | Meaning |
| --- | --- |
| `active` | Normal curated source. |
| `warning` | Source is reachable or useful but needs guarded review before recurring imports. |
| `deprecated` | Source is still visible but should be migrated away from. |
| `retired` | Source is retained for audit/history but disabled from built-in bundles and one-click import. |

Retired sources must not be referenced by built-in bundles. The source picker still shows them with lifecycle context so users can see why a familiar feed disappeared from presets.

## Runtime Loading

Default development path:

```text
data/blocklist_sources.json
```

Bundled PyInstaller path:

```text
%TEMP%\_MEI*\data\blocklist_sources.json
```

Launcher-cache path:

```text
%LOCALAPPDATA%\HostsFileGet\data\blocklist_sources.json
```

`HostsFileGet.spec` includes the manifest as PyInstaller data. `PythonLauncher.ps1` downloads and validates the manifest beside the cached editor before launching.

## Maintenance Rules

- Edit `data/blocklist_sources.json`, not `hosts_editor.py`, when adding or removing curated feeds.
- Keep category and source names stable; saved source metadata and user support notes often refer to them.
- Prefer HTTPS URLs.
- Do not add mirrors that serve HTML landing pages, redirectors requiring JavaScript, or feeds with unclear redistribution terms.
- Keep high-churn threat feeds such as NRD/DGA lists in a separate category with descriptions that call out freshness and false-positive risk.
- Keep CNAME cloaking original-target feeds out of normal hosts-import categories unless the description explicitly marks them as DNS handoff only; only exact disguised-domain lists are hosts-reviewable.
- Keep encrypted-DNS/VPN/Tor/proxy bypass feeds source-isolated with descriptions that warn hosts-file blocking is incomplete without router/firewall policy.
- Use lifecycle metadata instead of deleting dead feeds silently; this preserves source history while keeping presets safe.
- Keep `docs/source-health-baseline-YYYY-MM-DD.md` in sync with major lifecycle resets.
- Source trust badges are derived from URL shape, local freshness/cache metadata, and description/category risk words. Badge meanings are documented in `docs/source-trust.md`.
- Run the regression suite after every catalog edit.

## Validation

Run:

```powershell
python -m py_compile hosts_editor.py hostsfileget\source_catalog.py tests\test_source_catalog.py tests\test_hosts_editor_logic.py
python -m unittest tests.test_source_catalog -v
python -m unittest discover -s tests -v
```

The tests verify:

- the shipped manifest loads and matches `HostsFileEditor.BLOCKLIST_SOURCES`
- schema version enforcement
- category/source uniqueness
- URL validation
- control-character rejection
- explicit-path manifest loading
- lifecycle metadata validation
- built-in bundle rejection of retired sources
