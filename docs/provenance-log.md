# Provenance Log Filters and Export

The **Tools > Provenance Log...** dialog reads the local `hosts_editor_provenance.jsonl` sidecar beside the active config.

## Filters

Supported filters:

| Filter | Behavior |
| --- | --- |
| Kind | One event kind: `pin`, `unpin`, `whitelist_add`, or `whitelist_remove`. |
| Domain | Matches exact domains and subdomains when the value contains a dot; otherwise searches logged domains as text. |
| Source | Case-insensitive substring match on the logged source field. |
| User | Case-insensitive substring match on the logged Windows user field. |
| Text | Case-insensitive search across timestamp, kind, user, source, domain, note, and app version. |
| Since / Until | ISO date or datetime range. A date-only `until` includes the full day. |

The dialog displays the most recent 200 matching events and reports the total match count. Exports include all matching events loaded from the current log, not only the displayed rows.

## Export Formats

Available exports:

- JSON Lines (`.jsonl`) for lossless append-friendly review.
- CSV (`.csv`) for spreadsheet inspection.

The pure export helper also supports JSON (`hostsfileget.provenance-export.v1`) for tests and future automation.

## Limits

- The log remains local until the user chooses an export path.
- The dialog loads the most recent 5,000 readable current-log events.
- Rotated `.1` provenance logs are retained on disk by the writer but are not merged into this dialog.
- Malformed events and unknown event kinds are ignored, matching the existing read behavior.
