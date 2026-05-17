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

Compare a new run against a saved baseline:

```powershell
python hosts_editor.py `
  --source-health `
  --source-health-baseline .ai\research\2026-05-17\source-health-report.json `
  --source-health-output source-health-report.json
```

## Report Shape

```json
{
  "schema_version": 1,
  "checked_at": "2026-05-12T12:00:00Z",
  "summary": {
    "total": 167,
    "healthy": 160,
    "warning": 3,
    "failed": 4,
    "retired": 0
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
| `lifecycle` | Manifest lifecycle: `active`, `warning`, `deprecated`, or `retired` |
| `lifecycle_reason` | Curator-provided lifecycle reason when present |
| `checked_at` | UTC timestamp for this check |
| `status` | `healthy`, `warning`, `failed`, or `retired` |
| `http_status` | HTTP status when available |
| `content_type` | Response content type when available |
| `bytes_read` | Bounded sample size read |
| `sample_lines` | Decoded sample line count |
| `elapsed_ms` | Check duration |
| `diagnostic_class` | Machine-stable reason class such as `http-gone`, `sample-cap`, `non-host-like`, or `timeout` |
| `diagnostic` | Human-readable result |
| `remediation` | Suggested maintainer action |

## Classification

- `healthy`: reachable and returned a bounded sample with host-like entries.
- `warning`: reachable, but the sample was empty, exceeded the sample cap, or did not contain host-like entries.
- `failed`: invalid URL, HTTP error, timeout, network error, or HTML response.
- `retired`: skipped because the curated manifest marks the source as retired.

Every warning, failure, and retired result includes `diagnostic_class` and `remediation` so source catalog work can group similar failures. HTTP 404/410 results map to `http-gone`; sample-cap warnings map to `sample-cap`; non-host-like samples map to `non-host-like`.

The checker requests a bounded byte range and never downloads a full source unless the server ignores range requests within the configured sample cap.

## Baselines

The current tracked baseline is `docs/source-health-baseline-2026-05-17.md`, generated from `.ai/research/2026-05-17/source-health-report.json`.

When source health changes materially:

1. Run a new source-health report with `--source-health-baseline`.
2. Update `data/blocklist_sources.json` lifecycle metadata.
3. Keep retired sources out of built-in bundles.
4. Update the baseline document if the change is intentional.

## GitHub Workflow

`.github/workflows/source-health.yml` runs weekly and on manual dispatch. It writes `source-health-report.json` as a workflow artifact.

Network failures remain report data. Manifest/schema failures still fail because those are repository defects.
