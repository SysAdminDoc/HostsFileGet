# Source Health Checks

HostsFileGet can check the reachability of every curated source in `data/blocklist_sources.json` without launching the GUI or requiring administrator rights.

The checker is intentionally observational. By default, source failures do not produce a non-zero exit code because public blocklist mirrors can rate-limit, redirect, or go offline temporarily.

## Local Command

```powershell
python hosts_editor.py `
  --source-health `
  --source-health-timeout 12 `
  --source-health-workers 12 `
  --source-health-output source-health-report.json
```

The console prints a short summary and the first warning/failed sources. The JSON report contains the full result set.

Use `--source-health-fail-on-unhealthy` only for deliberate gating, not for normal CI.

## Report Shape

```json
{
  "schema_version": 1,
  "checked_at": "2026-05-12T12:00:00Z",
  "summary": {
    "total": 167,
    "healthy": 160,
    "warning": 3,
    "failed": 4
  },
  "sources": []
}
```

Each source result includes:

| Field | Meaning |
| --- | --- |
| `category` | Manifest category |
| `name` | Manifest source name |
| `url` | Source URL |
| `checked_at` | UTC timestamp for this check |
| `status` | `healthy`, `warning`, or `failed` |
| `http_status` | HTTP status when available |
| `content_type` | Response content type when available |
| `bytes_read` | Bounded sample size read |
| `sample_lines` | Decoded sample line count |
| `elapsed_ms` | Check duration |
| `diagnostic` | Human-readable result |

## Classification

- `healthy`: reachable and returned a bounded sample with host-like entries.
- `warning`: reachable, but the sample was empty, exceeded the sample cap, or did not contain host-like entries.
- `failed`: invalid URL, HTTP error, timeout, network error, or HTML response.

The checker requests a bounded byte range and never downloads a full source unless the server ignores range requests within the configured sample cap.

## GitHub Workflow

`.github/workflows/source-health.yml` runs weekly and on manual dispatch. It writes `source-health-report.json` as a workflow artifact.

Network failures remain report data. Manifest/schema failures still fail because those are repository defects.
