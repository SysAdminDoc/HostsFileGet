# Source Bundles

Source bundles are named import presets stored in `data/blocklist_sources.json`.
They reference existing curated source names and reuse the normal batch import
pipeline, so cancellation, cache fallback, source trust badges, and Raw vs
Normalized import mode stay unchanged.

## Manifest Shape

Bundles live in the optional top-level `bundles` array:

```json
{
  "id": "starter-low-breakage",
  "name": "Starter Low-Breakage",
  "description": "Conservative starter bundle.",
  "risk": "low",
  "source_names": ["HaGezi Light", "StevenBlack Unified", "MVPS Hosts"]
}
```

Rules:

- `id` must be lowercase ASCII with letters, digits, hyphens, or underscores.
- `risk` must be `low`, `medium`, `high`, or `guarded`.
- Every `source_names` entry must match a curated source in the same manifest.
- Retired sources are rejected. Move a retired source out of bundles before
  committing lifecycle metadata.
- Duplicate bundle IDs, duplicate bundle names, and duplicate source references
  inside a bundle are rejected at startup and in tests.

## Built-In Bundles

- `starter-low-breakage`: conservative mainstream ad/tracker/malware coverage.
- `balanced-desktop`: balanced aggregate plus common ad/privacy filters.
- `aggressive-privacy`: high-coverage privacy lists for manual triage.
- `threat-intel`: malware, phishing, TIF, and freshness-sensitive feeds.
- `family-category`: opt-in adult, gambling, and social category filters.
- `native-platform-telemetry`: targeted device and vendor telemetry lists.

## GUI Flow

Use **Tools > Source Bundle Selector...** to inspect bundle details and import
the selected bundle. The selector does not write the hosts file directly. It
passes the selected sources into the existing batch import worker, after which
the user can review, clean, dry-run, or save as usual.
