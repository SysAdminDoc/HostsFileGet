# False-Positive Triage

The **Tools > Check Domain...** dialog is the local triage path for a domain that appears to be blocked incorrectly.

## What It Checks

For a queried multi-label domain, HostsFileGet reports:

- matching blocking entries in the current editor
- whether the whitelist already covers the domain
- whether the domain is temporarily allowed until the next import
- whether the domain is pinned and therefore preserved during cleaned saves
- previously fetched sources that contain the domain
- derived upstream GitHub/GitLab issue paths when source trust metadata can infer one
- local allowlist/temporary-allow provenance for the same domain
- why-likely-blocked factors that combine editor lines, source matches, allowlist state, pins, and provenance
- source coverage gaps for feeds that have not been fetched in the current session

The check is local. It does not contact upstream projects or upload the domain.

## Actions

| Action | Behavior |
| --- | --- |
| `Add to Whitelist` | Appends the domain to the whitelist and saves the config so future cleaned saves omit the block unless the domain is pinned. |
| `Allow Until Import` | Adds a session-scoped allow entry that participates in cleaned-save filtering and is automatically cleared when the next source import starts. |
| `Remove Lines...` | Opens a preview before removing whole editor lines that currently block the domain or its subdomains. |
| `Pin Block` | Adds the exact domain to pinned domains when the block is intentional and should survive whitelist cleanup. |
| `Unpin` | Removes the exact domain from pinned domains when the block should be allowed. |
| `Copy Report` | Copies the visible triage report for use in upstream false-positive issues. |
| `Export Report...` | Writes a schema-versioned JSON report or Markdown report for manual upstream review. HostsFileGet does not auto-file an issue. |
| `Open Report Path` | Opens the first derived upstream issue path when one is available. |

## Export Schema

Exported reports use schema:

```text
hostsfileget.false-positive-upstream-report.v1
```

The export includes bounded line previews, source matches, derived issue URLs, local allowlist and temporary-allow context, why-likely-blocked factors, redaction notes, and embedded Markdown text suitable for a manual upstream issue.

## Limits

- Matching uses the in-memory source corpus from sources fetched during the current session.
- A source that has not been imported this session cannot be blamed by this panel yet.
- `Remove Lines...` removes whole hosts lines, not individual tokens from a multi-domain line. The preview is mandatory so unrelated domains are visible before the edit is applied.
- Whitelist coverage is local policy. Upstream false positives should still be reported when the source match is clear.
- Temporary allow entries are not saved as profile policy. They are recovery state for the current session and are cleared as soon as the next import starts.
