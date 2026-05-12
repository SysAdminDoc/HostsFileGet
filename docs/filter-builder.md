# Filter Builder

The **Tools > Filter Builder...** dialog builds local reports across the current editor, fetched source corpus, curated source metadata, and recent query history.

## Query Syntax

Supported terms:

| Term | Behavior |
| --- | --- |
| `domain:example.com` | Matches blocking editor entries and fetched-source domains for the exact domain or its subdomains. |
| `source:hagezi` | Matches fetched-source labels and curated source catalog metadata. |
| `line:0.0.0.0` | Matches raw editor line text. Quote values that contain spaces. |
| `history:ads` | Matches saved Filter Builder query history. |
| bare text | Searches line text and source metadata; bare multi-label domains are also treated as domain terms. |

Examples:

```text
domain:doubleclick.net
source:hagezi line:telemetry
domain:example.com source:threat
history:ads
```

## Query History

The dialog saves the 25 most recent valid queries in app config under `filter_query_history`. The sanitizer:

- removes empty and non-string values
- collapses control characters and repeated whitespace
- caps each query to 240 characters
- deduplicates case-insensitively while preserving newest-first order

History is local configuration state. It is not written into profiles and is not uploaded.

## Limits

- The report only uses fetched-source bodies already in the bounded in-memory source corpus.
- It does not fetch feeds, call DNS APIs, or write the hosts file.
- Source-domain matches use normalized blocking domains, so unsupported browser-only filter syntax is not treated as a hosts-file match.
- Reports are diagnostic. Use **Check Domain...** when you need the false-positive action flow.
