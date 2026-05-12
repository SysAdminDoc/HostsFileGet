# Source Overlap Matrix

The **Sources Report** dialog includes a fetched-source overlap matrix after the contribution table.

## What It Indexes

The matrix is built from the bounded in-memory source corpus populated when sources are fetched during the current session. HostsFileGet parses each fetched body with the same normalization helpers used by imports and keeps only blocking domains.

It reports:

- source count indexed in memory
- total unique normalized blocking domains across those sources
- domains seen in two or more sources
- per-source domain count, unique count, overlap count, and overlap percentage
- top overlapping source pairs with shared-domain counts and sample domains

## Use Cases

- identify redundant sources before keeping a large bundle
- see whether a broad source mostly duplicates a stricter source
- spot sources that add unique coverage
- investigate false positives by checking whether a domain appears in one source or many

## Limits

- The matrix only covers sources fetched in the current session.
- It uses the source corpus cache, currently capped by entry count and bytes to keep the GUI responsive.
- Pairwise overlap is diagnostic. It does not automatically remove imports or decide source quality.
- Two sources with high overlap can still differ in maintenance, freshness, category scope, or false-positive policy.
