# Source Freshness and Growth

The **Tools > Source Freshness & Growth...** report summarizes local source freshness and compact growth history.

## What It Tracks

After a successful GUI import or CLI `--update`, HostsFileGet records one compact metrics point per source:

- source display name
- source URL
- timestamp
- unique normalized blocking-domain count
- decoded line count
- decoded text size estimate
- fetch/cache status

The history is stored in app config under `source_metrics_history`.

## Report Behavior

The report shows:

- freshness buckets using the same thresholds as source freshness dots
- newest source rows first within stale/never/warm/fresh priority
- latest domain count
- delta from the previous point
- delta from the first retained point
- an ASCII sparkline over retained domain-count history

## Limits

- The history is local-only and never uploaded.
- Retention is capped to 200 source URLs and 30 points per source.
- Rotated or manually deleted config files remove the history.
- Growth reflects fetched payload size, not final cleaned-save contribution after whitelist, pin, and dedupe rules.
- Fetched-source matches only include successful GUI imports and CLI updates after this feature was introduced.
