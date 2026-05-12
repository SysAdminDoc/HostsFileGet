# Watch Expressions

The **Tools > Watch Expressions...** dialog saves local Filter Builder queries and reruns them against the current editor plus the fetched-source index.

## Expression Shape

Each watch has:

- `name`: short display label
- `query`: Filter Builder syntax such as `domain:example.com`, `source:hagezi`, or `line:telemetry`
- `enabled`: disabled watches stay saved but are skipped by reports

Watch expressions are stored in app config under `watch_expressions`. They are app-level diagnostic state, not profile policy.

## Report Behavior

The report shows:

- number of configured, enabled, and triggered watches
- total editor and fetched-source matches
- per-watch editor line samples
- per-watch fetched-source samples
- parser warnings from the underlying Filter Builder query

The report uses the same local matching engine as **Tools > Filter Builder...** and never fetches sources, calls DNS APIs, or writes the hosts file.

## Limits

- Up to 50 watch expressions are stored.
- Queries are capped at the Filter Builder query length.
- Names are capped at 80 characters.
- Fetched-source matches only include feeds imported during the current session.
- Duplicate queries are deduplicated case-insensitively.
