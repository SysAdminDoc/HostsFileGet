# False-Positive Triage

The **Tools > Check Domain...** dialog is the local triage path for a domain that appears to be blocked incorrectly.

## What It Checks

For a queried multi-label domain, HostsFileGet reports:

- matching blocking entries in the current editor
- whether the whitelist already covers the domain
- whether the domain is pinned and therefore preserved during cleaned saves
- previously fetched sources that contain the domain
- derived upstream GitHub/GitLab issue paths when source trust metadata can infer one
- source coverage gaps for feeds that have not been fetched in the current session

The check is local. It does not contact upstream projects or upload the domain.

## Actions

| Action | Behavior |
| --- | --- |
| `Add to Whitelist` | Appends the domain to the whitelist and saves the config so future cleaned saves omit the block unless the domain is pinned. |
| `Remove Lines...` | Opens a preview before removing whole editor lines that currently block the domain or its subdomains. |
| `Pin Block` | Adds the exact domain to pinned domains when the block is intentional and should survive whitelist cleanup. |
| `Unpin` | Removes the exact domain from pinned domains when the block should be allowed. |
| `Copy Report` | Copies the visible triage report for use in upstream false-positive issues. |
| `Open Report Path` | Opens the first derived upstream issue path when one is available. |

## Limits

- Matching uses the in-memory source corpus from sources fetched during the current session.
- A source that has not been imported this session cannot be blamed by this panel yet.
- `Remove Lines...` removes whole hosts lines, not individual tokens from a multi-domain line. The preview is mandatory so unrelated domains are visible before the edit is applied.
- Whitelist coverage is local policy. Upstream false positives should still be reported when the source match is clear.
