# Feature Backlog - 2026-05-17

This is the raw harvested idea pool before final prioritization. Source IDs map to `SOURCE_REGISTER.md`.

## Source Catalog And Feed Operations

| ID | Idea | Evidence | Notes |
| --- | --- | --- | --- |
| B001 | Add source lifecycle states: active, warning, deprecated, retired | `L5`, `L6` | Needed because 34 sources failed and 21 warned in the live run. |
| B002 | Add tracked source-health baseline docs and health diff CLI | `L6` | Helps future maintainers see feed decay over time. |
| B003 | Remove hard-failing sources from default bundles | `L5`, `L6` | Default imports should not select known broken sources. |
| B004 | Add GUI source-health report grouped by failure cause | `L6`, `M1`-`M5` | Converts JSON into maintainable user action. |
| B005 | Add source replacement notes and upstream issue/report links | `L6`, `M1`-`M5` | Useful for stale URLs and moved list variants. |
| B006 | Add syntax compatibility labels at source level | `C8`, `L6` | Distinguish hosts, domain-only, adblock, RPZ, CSV, and mixed formats. |

## Modularization And Architecture

| ID | Idea | Evidence | Notes |
| --- | --- | --- | --- |
| B007 | Extract `hostsfileget/source_catalog.py` | `L1`, `L5`, `L8` | Strong next package seam after fetch extraction. |
| B008 | Extract `hostsfileget/config_profiles.py` | `L1`, `L2`, `G3`, `C1`, `C3` | Profile/config logic is product-critical and currently scattered. |
| B009 | Extract CLI command dispatch table | `L1`, `L7` | 82 `_cli_*` functions suggest high CLI complexity. |
| B010 | Extract report renderer helpers | `L1`, `L8` | Many report dialogs and JSON reports could share schemas. |
| B011 | Add stable dataclass/TypedDict shapes for source records | `L5`, `L8` | Makes tests and future extraction clearer. |

## Release, Packaging, And Security

| ID | Idea | Evidence | Notes |
| --- | --- | --- | --- |
| B012 | Normalize version identity across runtime, README, docs, release artifacts | `L2`, `L3`, `L7` | README still has preview-version language. |
| B013 | Add release checklist for PyInstaller, pip-audit, checksums, SBOM, package manifests | `D3`-`D8`, `L4` | Hosts-file editors often run elevated. |
| B014 | Add CI check for stale preview-version text | `L3` | Small doc trust improvement. |
| B015 | Add built EXE smoke command that prints version/help | `L7`, `D3`, `D5` | Verifies packaging without GUI. |
| B016 | Document Python/PyInstaller compatibility matrix | `D1`-`D7` | Current external package support should be explicit. |

## UX, Profiles, And Documentation

| ID | Idea | Evidence | Notes |
| --- | --- | --- | --- |
| B017 | Build a single keyboard shortcut and command table | `L3`, `G1`, `G3` | Prevents drift as workflows grow. |
| B018 | Improve source picker labels for health and lifecycle state | `L5`, `L6` | Makes import risk visible. |
| B019 | Add temporary allow state until next import | `L2`, `L4`, `X3` | False-positive workflow enhancement. |
| B020 | Add upstream false-positive report export | `M1`-`M5`, `X3` | Helps users contribute fixes without automatic filing. |
| B021 | Add profile comparison/diff view | `G3`, `C1`, `C3` | Common profile-management need. |
| B022 | Add docs-first "what hosts can and cannot do" landing section | `S6`-`S11`, `C8` | Reduces unsupported expectations. |

## Integrations And Handoff Artifacts

| ID | Idea | Evidence | Notes |
| --- | --- | --- | --- |
| B023 | Schema-version handoff JSON for DNS provider exports | `C1`-`C8`, `P1`-`P8` | Keeps generated artifacts stable. |
| B024 | Improve Control D/NextDNS reviewed import/export plans | `C1`-`C6` | Provider APIs are useful but should stay explicit. |
| B025 | Improve Pi-hole/AdGuard/Technitium/blocky config exports | `P1`-`P8` | Integration quality without building a DNS server. |
| B026 | Improve NRPT and WFP plan validation warnings | `S3`-`S5` | High-risk Windows platform features need explicit boundaries. |
| B027 | Improve mobile DNS profile QR/export warnings | `C9`, `C10`, prior docs | Keep mobile handoffs reviewed. |

R009 implementation note: B023-B027 are now covered for DNS integration, cloud DNS, NRPT, router/gateway, mobile DNS, and managed package handoffs by `hostsfileget.handoff-contract.v1`, `hostsfileget.dns-integration-export.v1`, generated `OUTPUT.handoff.json` sidecars, and updated integration docs. WFP-specific plan warnings remain handled by the existing WFP blocker companion plan rather than the R009 handoff contract because R009 targeted DNS/provider/mobile/router/managed/NRPT artifacts.

## Data, Model, Evaluation, And Intelligence

| ID | Idea | Evidence | Notes |
| --- | --- | --- | --- |
| B028 | Add local source quality score based on health, syntax, freshness, and overlap | `L6`, `X3` | Useful if transparent and non-authoritative. |
| B029 | Add optional CTI enrichment request templates for VirusTotal, URLhaus, MISP | `X5`-`X8` | Keep as handoff/request artifacts unless credentials are added. |
| B030 | Add benchmark fixture for large source catalog imports | `L8`, `M1`-`M4` | Protect import performance as source metadata grows. |
| B031 | Add local evaluation report for false-positive/overlap risk | `X3`, `M1`-`M5` | Works without ML or external verdict calls. |

## Rejected Or Deferred Idea Pool

| ID | Idea | Evidence | Reason |
| --- | --- | --- | --- |
| B900 | Build a DNS server into HostsFileGet | `P1`-`P8` | Adjacent product category; conflicts with local hosts workbench contract. |
| B901 | Auto-write to NextDNS or Control D by default | `C1`-`C6` | Credential, rollback, and surprise-mutation risk. Keep reviewed plans first. |
| B902 | Claim wildcard or path-level hosts blocking | `S6`-`S11`, `C8` | Hosts-file semantics do not support this. |
| B903 | Vendor large blocklist files into repo | `M1`-`M5` | Increases repo churn and licensing/sync burden. Prefer source manifests. |
| B904 | Add in-app LLM blocking verdicts | `X1`-`X8` | Not needed for current contract; keep evidence summaries local/reviewed. |
