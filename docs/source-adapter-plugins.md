# Source Adapter Plugins

HostsFileGet supports a guarded source adapter plugin interface for local JSON manifests. This is intentionally manifest-only: plugin code is not imported or executed.

## Location

By default, manifests are loaded from:

```text
%LOCALAPPDATA%\HostsFileGet\source_adapters\*.json
```

In portable mode, the directory lives beside the portable config root.

## Manifest

```json
{
  "schema_version": 1,
  "id": "example-pack",
  "name": "Example Pack",
  "description": "Reviewed sources from an internal workflow.",
  "homepage": "https://example.com/source-pack",
  "maintainer": "Security Ops",
  "license": "MIT",
  "sources": [
    {
      "name": "Example Threat Feed",
      "url": "https://example.com/hosts.txt",
      "description": "Hosts-format threat feed.",
      "category": "Threat Feeds"
    }
  ]
}
```

Required fields:

- `schema_version`: must be `1`
- `id`: lowercase slug, up to 64 characters
- `name`: display name
- `sources`: non-empty list of HTTP(S) hosts-file sources

Optional fields:

- `description`
- `homepage`
- `maintainer`
- `license`
- per-source `description`
- per-source `category`

## Behavior

- Valid plugin sources appear in the batch import source picker under `Plugin: <category>`.
- Source imports still use the normal Raw/Normalized modes, cache fallback, retry limits, and preview-before-write flow.
- `Tools > Source Adapter Plugins...` reports loaded manifests, skipped manifests, and the active plugin directories.
- `python hosts_editor.py --source-adapter-list [DIR ...]` prints the same catalog from the CLI.

## Guardrails

- Only `.json` manifests are read.
- Python modules, shell scripts, hooks, and arbitrary commands are ignored.
- Invalid manifests are skipped and reported instead of blocking normal startup.
- URLs must be HTTP or HTTPS.
- A single manifest can define at most 200 sources, and a session loads at most 50 plugin manifests.
