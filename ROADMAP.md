# HostsFileGet Roadmap

Version: 2026-05-12 roadmap execution update
Repo state basis: `main` through F044/F045/F046/F051/F052/F053/F054/F055/F056 implementation plus external research current to 2026-05-12
Scope: Windows-first desktop hosts-file editor, importer, cleaner, diagnostics, and safe writer

This document supersedes the earlier broad idea dump. Useful shipped history has been preserved as baseline context, but the forward roadmap is now source-backed and tiered. Every active candidate cites at least one source ID from the appendix.

## Roadmap Contract

HostsFileGet should remain a local, Windows-first tool for people who need to inspect, clean, import, explain, and safely write `C:\Windows\System32\drivers\etc\hosts`.

Non-negotiables:

- Hosts file writes stay previewed, backup-backed, and recoverable.
- Network access is for user-requested feed imports, source checks, or docs, not background telemetry.
- Cloud sync, APIs, LLMs, and commercial DNS integrations are optional adapters, not defaults.
- Browser cosmetic blocking, path-level ad blocking, and full network DNS enforcement are out of scope unless implemented as exports or diagnostics.
- The current Catppuccin/Tkinter desktop identity is preserved unless a redesign is explicitly requested.

## Implementation Progress

- [x] F001 - Architecture and module map (`ARCHITECTURE.md`)
- [x] F002 - CI for compile, unit tests, PowerShell parser (`.github/workflows/ci.yml`)
- [x] F003 - PyInstaller release workflow (`.github/workflows/release.yml`, `requirements-build.txt`, `docs/release.md`)
- [x] F004 - Code signing, checksums, SBOM, dependency advisory scan (`requirements-security.txt`, optional signing hook, release SBOM/checksum assets, CI advisory scan)
- [x] F005 - Versioned config schema and migrator tests (`CONFIG_SCHEMA_VERSION`, `migrate_config_snapshot`, `docs/config-schema.md`)
- [x] F006 - External curated source manifest (`data/blocklist_sources.json`, manifest validation, launcher/release bundling)
- [x] F007 - Source health checker (`--source-health`, JSON report, scheduled workflow artifact)
- [x] F008 - ETag/Last-Modified cache (`source_cache_metadata`, conditional requests, cached-body fallback)
- [x] F009 - Source trust badges (`docs/source-trust.md`, deterministic badges, source picker/preview display)
- [x] F010 - False-positive triage flow (`docs/false-positive-triage.md`, Check Domain actions, triage helpers/tests)
- [x] F011 - Source overlap matrix (`docs/source-overlap.md`, fetched-source domain index, Sources Report matrix)
- [x] F012 - Entry provenance/blame panel (`docs/entry-provenance.md`, Tools/context report, import/source/audit correlation)
- [x] F013 - Windows DNS Client ETW import/live tail spike (`docs/windows-dns-client.md`, guarded Operational-log snapshot import)
- [x] F014 - DoH/DoT/DoQ bypass diagnostics (`docs/dns-bypass-diagnostics.md`, policy/proxy diagnostic report)
- [x] F015 - Named profile data model groundwork (`profile_schema_version`, `active_profile_id`, sanitized profile payloads)
- [x] F016 - Golden-file cleaned-output tests (`tests/golden_cleaned/`, exact output/stat fixtures)
- [x] F017 - Property-based parser/fuzzer tests (deterministic parser invariant and clean-idempotence fuzzers)
- [x] F018 - GUI smoke tests (`tests/test_gui_smoke.py`, patched startup/modal coverage)
- [x] F019 - Large-file benchmark suite (`benchmarks/large_file_benchmark.py`, docs, smoke coverage)
- [x] F020 - High-contrast, screen-reader, and font audit (`docs/accessibility.md`, Tools audit report, contrast regression coverage)
- [x] F021 - i18n string catalog foundation (`data/i18n/en-US.json`, fallback translator, Tools catalog report)
- [x] F022 - Importers for SwitchHosts, Gas Mask, HostsFileEditor archives (`docs/migration-imports.md`, append-only migration importers, Raw/Normalized GUI integration)
- [x] F023 - RPZ, Unbound, Privoxy, compressed-hosts exports (`docs/export-formats.md`, shared export records, compressed binary writes)
- [x] F024 - Limitations and troubleshooting guide (`TROUBLESHOOTING.md`)
- [x] F025 - Declarative YAML/TOML source of truth (`docs/declarative-config.md`, CLI plan/apply/export, dependency-free profile parser)
- [x] F026 - Git-backed history and rollback (`docs/git-history.md`, optional local snapshot/status/restore CLI)
- [x] F027 - CLI profile apply/export/import (`docs/cli-profiles.md`, explicit profile list/import/apply/export commands)
- [x] F028 - Scheduler hardening and activity report (`docs/scheduler-activity.md`, silent task command, activity JSONL/report CLI)
- [x] F029 - Managed portable bundle config (`docs/portable-config.md`, config-location report, portable config export)
- [x] F030 - Pi-hole/AdGuard/Technitium/blocky interoperability pack (`docs/dns-integrations.md`, DNS export presets, integration CLI)
- [x] F031 - NextDNS and Control D import/export adapters (`docs/cloud-dns-adapters.md`, plan-only cloud adapter CLI, CSV log importers)
- [x] F032 - Adblock syntax linter and cosmetic-rule quarantine (`docs/adblock-lint.md`, lint/quarantine CLI, browser-only rule guards)
- [x] F033 - Regex/exact/wildcard rule tiers with hosts warnings (`docs/rule-tiers.md`, rule tier CLI/report, provider-only warnings)
- [x] F034 - IDN/punycode and homograph warnings (`docs/idn-homograph.md`, IDN report CLI, deterministic mixed-script/confusable warnings)
- [x] F035 - NRD/DGA threat feed pack (`docs/threat-feed-packs.md`, guarded TIF/DGA/NRD pack plans, source-manifest entries)
- [x] F036 - CNAME cloaking source and explanation workflow (`docs/cname-cloaking.md`, guarded hosts/DNS workflow plans, source-manifest entries)
- [x] F037 - Encrypted DNS resolver bypass pack (`docs/encrypted-dns-bypass.md`, guarded hosts/router/firewall bypass plans, source-manifest entries)
- [x] F038 - DNS rebinding protection checks (`docs/dns-rebinding.md`, trusted-suffix report, GUI/CLI JSON output)
- [x] F039 - SafeSearch and restricted-mode templates (`docs/safesearch-restricted-mode.md`, hosts-vs-DNS template plans, GUI/CLI JSON output)
- [x] F040 - Time-bound profile activation (`docs/profile-activation-schedule.md`, config-only schedule add/list/apply CLI)
- [x] F041 - Tray quick switch (`docs/profile-quick-switch.md`, GUI quick switch, optional tray menu, opt-in PyInstaller tray-module bundling)
- [x] F042 - Variant/bundle selector (`docs/source-bundles.md`, manifest-defined source bundles, GUI bundle import selector)
- [x] F043 - Filter builder and query history (`docs/filter-builder.md`, local fielded queries, persisted query history)
- [x] F044 - Restore-point or VSS-backed apply spike (`docs/recovery-plan.md`, plan-only restore-point/VSS guidance)
- [x] F045 - Source adapter plugin interface (`docs/source-adapter-plugins.md`, manifest-only local source packs, GUI/CLI catalog)
- [x] F046 - Local REST facade with bearer auth (`docs/local-rest-api.md`, loopback-only read-only API, token-gated clean preview)
- [x] F047 - Provenance log filters and export (`docs/provenance-log.md`, local audit filters, CSV/JSONL export)
- [x] F048 - Watch expressions (`docs/watch-expressions.md`, saved local Filter Builder queries, editor/source-index report)
- [x] F049 - Source freshness and growth charts (`docs/source-metrics.md`, compact local source metrics history, GUI report)
- [x] F050 - Virtualized large-list views (`docs/virtualized-lists.md`, paged match-removal review)
- [x] F051 - Parallel source fetcher with bounded retries (`docs/parallel-imports.md`, concurrent source fetches, source-order-preserving output)
- [x] F052 - Winget and Chocolatey manifests (`docs/package-managers.md`, renderable templates, release artifact zip)
- [x] F053 - Translation contribution workflow (`docs/i18n.md`, template/validation CLI, GitHub issue template)
- [x] F054 - Encrypted opt-in sync via local Git remote (`docs/encrypted-sync.md`, GPG-encrypted profile bundle, config-only import/export)
- [x] F055 - Signed shareable allowlist/profile patches (`docs/share-patches.md`, detached GPG signatures, config-only apply)
- [x] F056 - WFP IP/CIDR blocker companion (`docs/wfp-blocker-companion.md`, plan-only Windows Firewall/WFP companion export)

## State Of The Repo

### What Exists Today

- Language and runtime: Python 3.x, Tkinter desktop UI, Windows-first assumptions, PowerShell launcher.
- Entry points: `hosts_editor.py` for GUI and CLI, `PythonLauncher.ps1` for elevated launch/bootstrap, `HostsFileGet.spec` for PyInstaller.
- Packaging: PyInstaller one-file Windows EXE with `uac_admin=True`; build artifacts exist locally under `build/` and `dist/` but are not tracked.
- Tests: `tests/test_hosts_editor_logic.py`, `tests/test_gui_smoke.py`, `tests/test_benchmarks.py`, and `tests/test_package_manifests.py` contain 294 tests plus manifest-driven golden cleaned-output fixtures, deterministic parser fuzzers, accessibility contrast checks, i18n catalog validation and contribution fixtures, encrypted profile sync fixtures, signed share patch fixtures, recovery-plan fixtures, WFP blocker companion fixtures, migration importer fixtures, export-format fixtures, DNS integration fixtures, cloud DNS adapter fixtures, source adapter plugin fixtures, local REST API fixtures, package manifest render fixtures, adblock syntax lint/quarantine fixtures, rule tier fixtures, IDN/homograph fixtures, threat-feed pack fixtures, CNAME cloaking workflow fixtures, encrypted-DNS bypass pack fixtures, DNS rebinding report fixtures, SafeSearch/restricted-mode template fixtures, profile activation schedule fixtures, profile quick-switch/tray dependency fixtures, source-bundle manifest fixtures, filter-builder query-history fixtures, watch-expression fixtures, source metrics fixtures, virtual-list fixtures, parallel import retry/order fixtures, provenance filter/export fixtures, declarative config fixtures, Git-history fixtures, CLI profile fixtures, scheduler activity fixtures, portable config fixtures, report-dialog smoke coverage, and benchmark harness smoke coverage across parsing, normalization, config/profile sanitation, patched Tk startup/modals, transactional hosts enable/disable, CLI guards, scheduler commands, import helpers, pinned domains, provenance, Pi-hole FTL, AdGuard Home logs, NextDNS/Control D CSV logs, and find/replace.
- Docs: `README.md`, `CHANGELOG.md`, `ARCHITECTURE.md`, `TROUBLESHOOTING.md`, `CLAUDE.md`, `CODEX_CHANGELOG.md`, `data/i18n/README.md`, `docs/accessibility.md`, `docs/i18n.md`, `docs/migration-imports.md`, `docs/export-formats.md`, `docs/dns-integrations.md`, `docs/cloud-dns-adapters.md`, `docs/adblock-lint.md`, `docs/rule-tiers.md`, `docs/idn-homograph.md`, `docs/threat-feed-packs.md`, `docs/cname-cloaking.md`, `docs/encrypted-dns-bypass.md`, `docs/encrypted-sync.md`, `docs/share-patches.md`, `docs/recovery-plan.md`, `docs/wfp-blocker-companion.md`, `docs/dns-rebinding.md`, `docs/safesearch-restricted-mode.md`, `docs/profile-activation-schedule.md`, `docs/profile-quick-switch.md`, `docs/source-adapter-plugins.md`, `docs/local-rest-api.md`, `docs/package-managers.md`, `docs/source-bundles.md`, `docs/filter-builder.md`, `docs/watch-expressions.md`, `docs/source-metrics.md`, `docs/parallel-imports.md`, `docs/virtualized-lists.md`, `docs/provenance-log.md`, `docs/declarative-config.md`, `docs/cli-profiles.md`, `docs/git-history.md`, `docs/scheduler-activity.md`, `docs/portable-config.md`, `.github/ISSUE_TEMPLATE/translation.yml`, `LICENSE`, and this roadmap.
- License: MIT.

### Product Reality

HostsFileGet already provides:

- Raw and cleaned save paths with preview, backups, dry-run mode, admin detection, read-only lock support, and panic restore.
- Curated and custom source import, manual paste import, pfSense, NextDNS CSV, Control D CSV, Pi-hole FTL, and AdGuard Home query log importers.
- Manifest-only source adapter plugins can add local reviewed source packs under `source_adapters\*.json` without importing or executing plugin code.
- Manifest-defined source bundles with a GUI selector that feeds the existing batch import worker without direct hosts-file writes.
- Filter Builder runs local fielded queries across editor lines, fetched-source domains, curated source metadata, and recent query history without network calls or hosts-file writes.
- Watch Expressions save local Filter Builder queries in app config and rerun them against current editor/source-index state without network calls or hosts-file writes.
- Source Freshness & Growth records compact local metrics for successful imports/updates and renders freshness buckets plus domain-count growth charts without telemetry.
- Batch imports fetch up to 4 sources concurrently with bounded retry attempts while preserving source-order output and cache fallback behavior.
- Remove Matches uses a paged large-list review dialog so high-cardinality searches can still be reviewed before preview/apply.
- Source freshness dots, update-on-launch, scheduled update, `--update`, `--apply`, `--backup`, `--disable`, `--enable`, `--silent`, provenance JSONL logging, and local provenance log filter/export.
- Declarative profile plan/apply/export commands for YAML, TOML, and JSON source-of-truth files that update app config without writing the system hosts file.
- Explicit CLI profile list/import/apply/export commands for staging and switching saved profiles without touching the system hosts file.
- Encrypted profile sync exports/imports saved profile state through an explicit Git worktree and GPG-encrypted payload without writing the hosts file.
- Signed allowlist/profile patches can be built, signed, verified, and applied to app config only; apply requires a detached GPG signature.
- Scheduled updates use `--update --silent`, bounded activity JSONL, and `--activity-report` for local scheduler observability.
- `--config-location` and `--portable-export` make local-user versus portable bundle config paths explicit.
- `--integration-list` and `--integration-export` provide file-only Pi-hole, AdGuard Home/DNS, Technitium, and blocky DNS export handoffs.
- `--api-serve` exposes an opt-in loopback-only bearer-auth API with read-only status and clean-preview endpoints.
- `--i18n-template` and `--i18n-validate` generate and review translation contribution catalogs without launching the GUI.
- `--cloud-adapter-list`, `--cloud-adapter-plan`, and `--cloud-log-import` provide plan-only NextDNS/Control D adapter artifacts and local CSV log extraction without storing credentials or performing remote writes.
- The release workflow renders Winget and Chocolatey manifest files from the release URL and SHA-256 into a package-manifest zip.
- `--adblock-lint`, `--adblock-lint-output`, and `--adblock-quarantine` review mixed filter lists and quarantine browser-only rules before hosts-file conversion.
- `--rule-tier-report` and `--rule-tier-output` explain exact, subdomain, wildcard, regex, path, exception, and browser-only tiers before hosts-file conversion.
- `--idn-report` and `--idn-output` explain IDN/Punycode, mixed-script, and obvious confusable homograph candidates without changing cleaned output.
- `--threat-feed-list` and `--threat-feed-plan` expose guarded TIF/DGA/NRD feed packs with local JSON plans, freshness policy, and false-positive controls.
- `--cname-cloaking-list` and `--cname-cloaking-plan` expose guarded CNAME cloaking workflows that separate exact disguised-domain imports from DNS-only CNAME target and RPZ handoffs.
- `--encrypted-dns-bypass-list` and `--encrypted-dns-bypass-plan` expose guarded encrypted-DNS bypass packs that separate hosts review from router/firewall/RPZ/IP handoffs.
- `--dns-rebinding-report`, `--dns-rebinding-output`, and `--dns-rebinding-trusted-suffix` expose static DNS rebinding-sensitive hosts mapping reports without live DNS queries or resolver policy changes.
- `--safesearch-template-list` and `--safesearch-template-plan` expose guarded SafeSearch and restricted-mode plans that separate hosts-reviewable provider targets from DNS CNAME handoffs.
- `--recovery-plan` exposes a plan-only restore-point/VSS recovery spike for high-risk hosts writes without executing recovery commands.
- `--wfp-blocker-plan` exports a plan-only Windows Firewall/WFP IP/CIDR blocker companion JSON with reviewable PowerShell and no live firewall mutation.
- `--profile-schedule-list`, `--profile-schedule-add`, `--profile-schedule-apply`, and `--profile-schedule-at` expose guarded time-bound profile activation that switches app config only and never writes the system hosts file.
- **Tools > Profile Quick Switch...** and optional **Tools > Start Tray Quick Switch...** expose config-only saved-profile switching without writing the system hosts file.
- Optional local Git-backed history commands for snapshot, status, and admin-gated rollback with normal `.bak` backup creation.
- Live stats, category hints, source report, health scan, DNS flush, domain check, find/replace, cleanup commands, import-section removal, backup diff, pinned domains, and export formats.

### Stated Philosophy

The repo positions itself as a safety-first desktop utility for large hosts files and blocklist workflows, not a DNS server replacement. The design language favors preview-before-write, recoverability, local control, and Windows operational pragmatism.

### Hard Constraints

- The hosts file requires Administrator privileges for real writes on Windows.
- The hosts format has no wildcard semantics; `*.example.com` must be normalized or explained as a non-native dialect.
- Hosts-based blocking cannot block URL paths, same-domain ads, browser cosmetic selectors, or encrypted DNS traffic that bypasses the OS resolver.
- Tkinter `Text` performance and full-file rescans are scaling risks above tens or hundreds of thousands of lines.
- No package manifest currently pins Python or PyInstaller versions.
- CI, release, source health, and advisory scan workflows now exist; signing still depends on operator-supplied certificate material.
- The app is still concentrated in one large `hosts_editor.py`, which slows future review and increases regression risk.

### Recurring Local Pain Points

Git history and handoff notes show repeated work in the same areas:

- Parser edge cases: high-octet IPv4, URL/adblock/dnsmasq dialects, malformed logs, bad encodings.
- Windows privilege and file-state issues: UAC, read-only attributes, AV/indexer locks, safe backup/restore, disabled hosts state.
- Thread and Tk lifecycle safety: background import callbacks after teardown, `after()` cleanup, worker cancellation.
- Import safety: large downloads, gzip bombs, HTML error pages, source-name injection, duplicate custom sources.
- UX safety: preview wording, attached dialogs, mode badges, first-run flow, stale source state, import/removal selection clarity.
- Performance: O(n) text scans, search highlight caps, expensive diffs, large dialog widget counts.

## Research Coverage

The research pass covered all requested source classes:

- Direct OSS competitors: Windows/macOS hosts editors, hosts aggregators, Android hosts blockers, DNS sinkholes, and list managers.
- Commercial competitors: NextDNS, Control D, AdGuard DNS, DNSFilter.
- Adjacent projects: Pi-hole, AdGuard Home, Technitium DNS Server, blocky, dnscrypt-proxy, uBlock Origin-adjacent DNS/blocklist ecosystems.
- Awesome lists: awesome-selfhosted DNS category and awesome-adblock.
- Community signal: Reddit, Hacker News, Stack Overflow, Microsoft Q&A, GitHub issues/discussions.
- Standards and APIs: Microsoft NRPT, WFP, ETW/DNS diagnostics, DNS cache APIs, DoH, DoQ, SVCB/HTTPS.
- Academic and engineering research: NRD/phishing research, CNAME cloaking research, malicious domain and DNS filtering studies.
- Dependency/security: Python 3.14 release stream, PyInstaller 6.20 changelog, PyInstaller CVE-2025-59042, GitHub Advisory Database.

Repeated signals after the last query pass were mostly variants of the same themes: false positives, DNS bypass, profile policy, source trust, logs/analytics, performance at large blocklist sizes, and package/release hygiene.

## OSS Competitor Snapshot

Stars, push dates, and contributors are from a GitHub API snapshot taken on 2026-05-12 unless the repo was unavailable.

| ID | Project | Stars | Last push | Maintainer signal | Relevant product signal |
| --- | ---: | ---: | --- | --- | --- |
| O1 | oldj/SwitchHosts | 26,605 | 2026-05-12 | multi-contributor | Electron hosts manager; syntax highlight, remote hosts, tray switch, localized READMEs |
| O2 | scottlerch/HostsFileEditor | 1,241 | 2025-10-11 | mostly single maintainer | Windows editor; bulk enable/disable/move, filter/sort, tray, archive/restore, ping |
| O3 | 2ndalpha/gasmask | 3,839 | 2026-03-01 | multi-contributor | macOS hosts manager; local/remote/combined files, menu-bar quick switching, logs |
| O4 | StevenBlack/hosts | 30,338 | 2026-05-11 | active contributors | canonical hosts aggregator; 31 variants, source contacts, whitelist/blacklist overlays |
| O5 | AdAway/AdAway | 9,062 | 2026-02-10 | active Android project | hosts-based Android blocker; source lists, preview builds, translation/contribution workflows |
| O6 | pi-hole/pi-hole | 58,579 | 2026-05-12 | active core team | network DNS sinkhole; dashboard, DHCP option, high query scale, Docker/install docs |
| O7 | AdguardTeam/AdGuardHome | 33,968 | 2026-05-12 | active team | DNS server with rules, query logs, rewrites, API, CNAME/IP blocking, translations |
| O8 | TechnitiumSoftware/DnsServer | 8,364 | 2026-05-09 | active maintainer/team | recursive/authoritative DNS, blocklist URLs, clustering, OIDC, encrypted DNS, CNAME cloaking |
| O9 | hectorm/hblock | 1,940 | 2026-01-20 | active solo + contributors | shell updater; systemd timer, nightly formats, allowlist guidance, hMirror source lookup |
| O10 | hagezi/dns-blocklists | 22,682 | 2026-05-12 | active solo | tiered list families, NRD/DGA, DoH/VPN/Tor bypass, DNS rebinding, native tracker lists |
| O11 | blocklistproject/Lists | 4,816 | 2026-05-11 | active contributors | many content categories and multiple output formats |
| O12 | Ultimate-Hosts-Blacklist | 1,560 | 2026-05-11 | bot + maintainers | very large combined hosts source |
| O13 | crazy-max/WindowsSpyBlocker | 5,117 | 2025-02-02 | active enough | Windows telemetry-oriented hosts/firewall packs |
| O14 | DNSCrypt/dnscrypt-proxy | 13,287 | 2026-05-12 | active | encrypted DNS proxy with blocklist builder and relay/privacy primitives |
| O15 | 0xERR0R/blocky | 6,604 | 2026-05-12 | active | lightweight DNS proxy/ad blocker, alternative to Pi-hole |
| O16 | jacklul/pihole-updatelists | 1,641 | 2026-05-02 | active | remote list sync automation for Pi-hole |
| O17 | AdGuard HostlistsRegistry | 367 | 2026-05-12 | active AdGuard team | curated registry rules for list inclusion, complaints, metadata |
| O18 | ppfeufer/adguard-filter-list | 408 | recent enough | active enough | combined AdGuardHome DNS list with allowlist caveats |
| O19 | Maza ad blocking | listed by awesome-selfhosted | 2025-11-24 in index | active enough | local OS ad blocker like Pi-hole but local |
| O20 | NPS-Hosts-Manager | 0 | 2020-07-29 | inactive | lightweight Windows hosts manager |

## Priority Themes

Now themes are the work that most improves trust, maintainability, and release quality without changing the product's identity:

1. Make the release/build path reliable and auditable.
2. Move curated source metadata out of the monolith and verify it continuously.
3. Improve explainability for false positives, source overlap, provenance, and DNS bypass.
4. Add tests for generated outputs, parser invariants, GUI smoke, and large files.
5. Bring accessibility, i18n foundations, and docs up to the level of the feature surface.

Next themes are major user-facing capability expansions:

1. Named profiles and declarative config.
2. Migration and interoperability with SwitchHosts, Gas Mask, HostsFileEditor, Pi-hole, AdGuard Home, NextDNS, and Control D.
3. Better source formats, rule dialects, and source bundles.
4. Live DNS/query observability from Windows and imported logs.
5. Safe automation and packaging for Windows users.

Later themes are useful but have larger blast radius:

1. Router/gateway pushes and enterprise deployment exports.
2. Windows network stack integrations beyond the hosts file.
3. Optional API/TUI/developer extensions.
4. Threat-intel enrichment that introduces quotas, privacy, or third-party dependency risk.

## Feature Harvest And Gap Analysis

Legend:

- Fit: Yes, Guarded, or No.
- Impact and effort: 1 low to 5 high.
- Prevalence: rare, emerging, common, table-stakes.
- Tier: Now, Next, Later, Under Consideration, Rejected.
- Risk/dependencies includes security, stability, licensing, maintenance, dependency bloat, and order constraints.

| ID | Feature | Category | Prevalence | Fit | Impact | Effort | Risk/dependencies | Tier | Sources |
| --- | --- | --- | --- | --- | ---: | ---: | --- | --- | --- |
| F001 | Architecture and module map | Docs, dev-experience | table-stakes | Yes | 4 | 2 | Must document current monolith before splitting it. | Now | L3, L4 |
| F002 | CI for compile, unit tests, PowerShell parser | Testing, dev-experience | table-stakes | Yes | 5 | 2 | Needs Windows runner; no product risk. | Now | L2, L6, D4 |
| F003 | PyInstaller release workflow | Distribution | table-stakes | Yes | 5 | 3 | Must pin Python/PyInstaller and avoid artifact drift. | Now | L5, D1, D2, D3 |
| F004 | Code signing, checksums, SBOM, dependency advisory scan | Security, distribution | common | Yes | 5 | 4 | Certificate cost and release-key handling. | Now | D2, D3, D4 |
| F005 | Versioned config schema and migrator tests | Reliability, migration | common | Yes | 4 | 3 | Must preserve current configs and portable mode. | Now | L5, L6, O1, O3 |
| F006 | External curated source manifest | Data, dev-experience | common | Yes | 5 | 3 | Requires schema, validation, and tests before moving URLs out of code. | Now | O4, O17, O18 |
| F007 | Source health checker | Reliability, observability | common | Yes | 4 | 3 | Network flakes need quarantined reporting, not failing every build. | Now | O4, O9, O17 |
| F008 | ETag/Last-Modified cache | Performance, offline | common | Yes | 4 | 3 | Requires metadata migration and conditional request tests. | Now | O14, O16 |
| F009 | Source trust badges | Security, UX | emerging | Yes | 4 | 3 | Needs transparent criteria: HTTPS, maintainer activity, license, complaints path. | Now | O17, O4, O10 |
| F010 | False-positive triage flow | UX, reliability | table-stakes | Yes | 5 | 4 | Depends on source attribution and source overlap. | Now | O7, O9, K3, K6 |
| F011 | Source overlap matrix | Data, UX | common | Yes | 4 | 3 | Needs normalized source-domain index; may be expensive on large lists. | Now | O6, O9, O10 |
| F012 | Entry provenance/blame panel | Observability, audit | common | Yes | 5 | 4 | Builds on current provenance JSONL and import section metadata. | Now | L2, C4, O7 |
| F013 | Windows DNS Client ETW import/live tail spike | Observability | emerging | Guarded | 4 | 4 | Must be opt-in; ETW privileges and volume need testing. | Now | S5, S6, K1 |
| F014 | DoH/DoT/DoQ bypass diagnostics | Security, docs, UX | common | Yes | 5 | 3 | Do not promise enforcement; explain limitations and router/firewall handoff. | Now | S7, S8, K1, K5 |
| F015 | Named profile data model groundwork | UX, multi-user | table-stakes | Yes | 5 | 4 | Must not disturb current single-editor workflow. | Now | O1, O2, O3, C2 |
| F016 | Golden-file cleaned-output tests | Testing | table-stakes | Yes | 5 | 2 | Requires stable fixtures. | Now | L6, O4 |
| F017 | Property-based parser/fuzzer tests | Testing, reliability | common | Yes | 4 | 3 | Adds Hypothesis dependency or custom fuzzer; gate dependency choice. | Now | L6, A10 |
| F018 | GUI smoke tests | Testing, accessibility | common | Yes | 4 | 4 | Tk automation on Windows is brittle; start with launch and dialog smoke only. | Now | L4, O1, O2 |
| F019 | Large-file benchmark suite | Performance | common | Yes | 4 | 3 | Needs fixtures and reproducible timing budget. | Now | L3, O6, K2 |
| F020 | High-contrast, screen-reader, and font audit | Accessibility | table-stakes | Yes | 4 | 4 | Requires manual Windows accessibility smoke and no visual redesign. | Now | O1, O5, C5 |
| F021 | i18n string catalog foundation | i18n | common | Yes | 3 | 4 | Avoid translating before text is externalized. | Now | O1, O5, C5 |
| F022 | Importers for SwitchHosts, Gas Mask, HostsFileEditor archives | Migration | common | Yes | 4 | 4 | Needs sample formats; keep as import-only first. | Now | O1, O2, O3 |
| F023 | RPZ, Unbound, Privoxy, compressed-hosts exports | Integrations | common | Yes | 4 | 3 | Needs pure transformation IR and golden tests. | Now | O4, O9, O11 |
| F024 | Limitations and troubleshooting guide | Docs | table-stakes | Yes | 5 | 2 | Must be blunt about wildcards, same-domain ads, admin rights, DoH. | Now | K5, K7, K8, K9 |
| F025 | Declarative YAML/TOML source of truth | Dev-experience, automation | common | Yes | 5 | 4 | Depends on profile model and schema versioning. | Next | O4, C2, C3 |
| F026 | Git-backed history and rollback | Reliability, collaboration | common | Yes | 4 | 4 | Optional only; must not require Git for normal users. | Next | O4, C4, K6 |
| F027 | CLI profile apply/export/import | Automation, profiles | common | Yes | 4 | 3 | Depends on named profile model. | Next | O2, C2, L5 |
| F028 | Scheduler hardening and activity report | Automation, observability | common | Yes | 4 | 3 | Builds on existing schtasks support and silent logs. | Next | O9, L2, K8 |
| F029 | Managed portable bundle config | Distribution, migration | common | Yes | 3 | 3 | Must keep local-user and portable paths unambiguous. | Next | O1, O3, L5 |
| F030 | Pi-hole/AdGuard/Technitium/blocky interoperability pack | Integrations | table-stakes | Yes | 5 | 4 | Prefer export/import files and APIs before remote writes. | Next | O6, O7, O8, O15 |
| F031 | NextDNS and Control D import/export adapters | Integrations | common | Guarded | 4 | 4 | API keys, privacy, and quotas; never default. | Next | C1, C2, C3, C4, C8, C9, C10, C11 |
| F032 | Adblock syntax linter and cosmetic-rule quarantine | Data, UX | common | Yes | 4 | 4 | Must distinguish DNS-compatible rules from browser-only syntax. | Next | O7, O17, K4, K7, C12, C13, C14 |
| F033 | Regex/exact/wildcard rule tiers with hosts warnings | UX, data | common | Yes | 5 | 4 | Must warn hosts cannot natively express wildcards. | Next | C3, C12, K9, S12 |
| F034 | IDN/punycode and homograph warnings | Security, i18n | common | Yes | 4 | 3 | Use deterministic checks; do not over-block. | Next | C1, S1, S13, S14 |
| F035 | NRD/DGA threat feed pack | Security | common | Yes | 4 | 3 | Needs freshness and false-positive controls. | Next | C1, O10, A1, A2, A3, S15 |
| F036 | CNAME cloaking source and explanation workflow | Security, privacy | common | Yes | 4 | 3 | Hosts cannot resolve CNAME dynamically; keep as feed/import guidance. | Next | C1, O8, O26, O27, S11, A4, A5 |
| F037 | Encrypted DNS resolver bypass pack | Security, platform | common | Guarded | 4 | 3 | DNS-only block is incomplete; pair with router/firewall docs. | Next | O10, S7, S8, K1 |
| F038 | DNS rebinding protection checks | Security | common | Yes | 4 | 3 | Need careful LAN/private-range distinction to avoid breaking dev labs. | Next | C1, O7, O8, O10 |
| F039 | SafeSearch and restricted-mode templates | Parental controls | common | Yes | 3 | 3 | Hosts-only support is partial; document browser/DNS provider differences. | Next | C1, C5, P1-P4 |
| F040 | Time-bound profile activation | UX, parental controls | common | Guarded | 3 | 4 | Needs profiles and scheduler; avoid surprising automatic writes. | Next | C1, C2 |
| F041 | Tray quick switch | UX, profiles | table-stakes for hosts managers | Yes | 4 | 4 | Tk tray support may require dependency; keep optional. | Next | O1, O2, O3 |
| F042 | Variant/bundle selector | UX, imports | table-stakes | Yes | 4 | 3 | Bundle definitions should live in external manifest. | Next | O4, O10, O11 |
| F043 | Filter builder and query history | UX, data | common | Yes | 3 | 4 | Depends on internal source/domain index. | Next | C4, O7 |
| F044 | Restore-point or VSS-backed apply | Recovery | rare | Guarded | 4 | 5 | High Windows API complexity; spike before commit. | Next | S3, L2 |
| F045 | Source adapter plugin interface | Plugin ecosystem | common | Guarded | 4 | 5 | Needs stable internal contracts and sandboxing. | Next | O16, O17, C7 |
| F046 | Local REST facade with bearer auth | Dev-experience, integrations | common | Guarded | 3 | 5 | Attack surface; off by default, loopback only, auth required. | Next | O7, C7 |
| F047 | Provenance log filters and export | Observability, audit | common | Yes | 3 | 2 | Builds on current JSONL log. | Next | L2, C4 |
| F048 | Watch expressions | Observability, UX | emerging | Yes | 3 | 3 | Needs background import/source index hooks. | Next | C4, O7 |
| F049 | Source freshness and growth charts | Observability | common | Yes | 3 | 3 | Store compact history; avoid telemetry. | Next | C4, O6 |
| F050 | Virtualized large-list views | Performance, UX | common | Yes | 5 | 5 | Tk Text constraints; likely requires architectural split. | Next | L3, K2 |
| F051 | Parallel source fetcher with bounded retries | Performance, reliability | common | Yes | 4 | 4 | Preserve cancellation and UI thread safety. | Next | O6, O14, L4 |
| F052 | Winget and Chocolatey manifests | Distribution | common | Yes | 4 | 4 | Depends on reproducible signed release artifacts. | Next | O1, O2, D6 |
| F053 | Translation contribution workflow | i18n | common | Yes | 3 | 3 | Depends on string catalog. | Next | O1, O5 |
| F054 | Encrypted opt-in sync via Gist or local Git remote | Collaboration | emerging | Guarded | 3 | 5 | Privacy and token handling; start with Git remote first. | Next | C2, C4 |
| F055 | Signed shareable allowlist/profile patches | Collaboration, security | emerging | Yes | 4 | 4 | Needs schema, signing key UX, and trust model. | Next | C2, C3, L2 |
| F056 | WFP IP/CIDR blocker companion | Platform/OS, security | rare | Guarded | 4 | 5 | Separate companion/service; main app should not ship a driver. | Later | S3, K1 |
| F057 | NRPT policy editor/export | Platform/OS | emerging | Guarded | 4 | 4 | Admin and GPO risk; expose as export/spike first. | Later | S1, S2 |
| F058 | Windows Sandbox and VM hosts injector | Platform/OS | rare | Guarded | 2 | 5 | Useful for lab workflows but niche. | Later | S3 |
| F059 | Router/gateway push adapters | Integrations | common | Guarded | 4 | 5 | Credentials and bricking risk; generate scripts before live push. | Later | O6, O7, O8, K1 |
| F060 | Intune/GPO/PDQ/SCCM package exports | Distribution, multi-user | common in enterprise | Guarded | 4 | 5 | Requires signed artifacts and managed-line mode. | Later | C6, S1 |
| F061 | VS Code companion extension | Dev-experience | rare | Guarded | 2 | 5 | Separate ecosystem; only after API/export contracts stabilize. | Later | O1, O2 |
| F062 | prompt_toolkit TUI | Dev-experience, accessibility | rare | Guarded | 3 | 5 | New dependency and parallel UI surface. | Later | O9, O14 |
| F063 | Local custom block page server | UX, diagnostics | common in DNS products | Guarded | 2 | 4 | Hosts cannot redirect paths; local server must be explicit. | Later | C1, C5, C3 |
| F064 | Advanced DNS rewrites/CNAME/private domains | Platform, integrations | common | Guarded | 3 | 4 | Hosts can map A/AAAA only; richer rewrites belong to export adapters. | Later | C3, O8 |
| F065 | Certificate Transparency and typosquat watchdog | Security, OSINT | emerging | Guarded | 4 | 5 | External service dependency and false positives. | Later | C1, A1, A2, A7 |
| F066 | VirusTotal, URLhaus, MISP, STIX enrichment | Security, OSINT | common in security tools | Guarded | 4 | 5 | API keys, quotas, licensing, and privacy. | Later | C6, A1, A2 |
| F067 | TLS certificate preview | Security, UX | emerging | Guarded | 3 | 4 | Network side effects; must be explicit and cached minimally. | Later | A8 |
| F068 | LLM-assisted "why blocked" summaries | UX, data | rare | Guarded | 2 | 5 | Privacy/cost; prefer offline metadata before any API. | Later | C4, O17 |
| F069 | Mobile DNS profile export QR | Mobile, distribution | common | Guarded | 3 | 4 | Hosts file does not roam; export DNS/provider config instead. | Later | C1, C5, K5 |
| F070 | Roaming endpoint strategy | Mobile, offline | common | Guarded | 4 | 5 | Likely outside hosts scope; document integration rather than own it. | Later | C1, C2, K5 |
| F071 | Multi-account user administration | Multi-user | common in servers | No | 2 | 5 | Contradicts local desktop scope; corporate managed lines cover the need better. | Rejected | O7, K11 |
| F072 | DNS server clustering inside HostsFileGet | Platform | common in DNS servers | No | 1 | 5 | This is a hosts editor, not a DNS server. | Rejected | O8 |
| F073 | Runtime CNAME resolution before every save | Security | emerging | Guarded | 3 | 5 | Under consideration only; may be slow and privacy-sensitive. | Under Consideration | A4, A5, S11 |
| F074 | `proxy.pac` emitter | Browser integration | emerging | Guarded | 3 | 4 | Can solve some DoH/browser paths but not hosts semantics. | Under Consideration | K5, K7 |
| F075 | OpenSnitch/Little Snitch export | Integrations | rare | Guarded | 2 | 4 | Adjacent firewall ecosystem; useful only if user demand appears. | Under Consideration | K12 |
| F076 | Full analytics dashboard | Observability | common in DNS products | Guarded | 3 | 5 | Local-only and opt-in; avoid building surveillance UI. | Under Consideration | C1, C4, C5, C6 |
| F077 | Smart whitelist suggestions | UX, reliability | emerging | Guarded | 4 | 5 | Requires logs and classifier; risk of unsafe suggestions. | Under Consideration | K3, K6, O9 |
| F078 | Gamified milestones | UX | rare | No | 1 | 2 | Not aligned with utility/audit tone. | Rejected | L8 |
| F079 | Vault-protected entries | Security | rare | Guarded | 2 | 5 | Hosts content is ultimately plaintext; may create false privacy expectations. | Under Consideration | L8 |
| F080 | Screen-share masked notes | Security, UX | rare | Guarded | 2 | 3 | Notes are not currently first-class; wait for notes model. | Under Consideration | L8 |
| F081 | Product telemetry | Telemetry | common | No | 1 | 3 | Violates local-control philosophy unless purely local diagnostics. | Rejected | L1, C4 |
| F082 | Browser cosmetic filtering | UX, integrations | table-stakes for browser blockers | No | 1 | 5 | Hosts cannot express CSS/path rules; export/quarantine only. | Rejected | K7, O17 |
| F083 | Default cloud sync | Collaboration | common commercial | No | 2 | 5 | Privacy and credentials; opt-in encrypted sync only. | Rejected | C1, C4 |
| F084 | Silent automatic writes by default | Automation | common in agents | No | 1 | 2 | Contradicts preview-before-write safety model. | Rejected | L1, L2 |
| F085 | Kernel driver in the main app | Platform | rare | No | 2 | 5 | Too much signing, crash, and security risk for a Tkinter app. | Rejected | S3 |
| F086 | Anti-cheat/vendor telemetry unblock presets without citations | Data, gaming | rare | No | 1 | 3 | High breakage and trust risk; require source-backed allowlist policy first. | Rejected | K3 |
| F087 | macOS/Linux first-class ports now | Platform | common competitors | No | 2 | 5 | Dilutes Windows-first focus; imports/exports are higher ROI. | Rejected | O1, O3 |
| F088 | Always-on LLM/API rule assistant | UX, security | emerging | No | 1 | 5 | Privacy, cost, and hallucination risk are poor fit. | Rejected | C4 |
| F089 | Bundling massive third-party blocklists in repo | Data, licensing | common but risky | No | 1 | 3 | License and freshness risk; keep URLs/manifests instead. | Rejected | O4, O10, O17 |
| F090 | Editing upstream remote source files directly | Collaboration | rare | No | 1 | 5 | Unsafe and out of scope; provide reports/PR templates instead. | Rejected | O4, O17 |

## Tiered Execution Plan

### Now

1. Completed - Documentation and architecture baseline: F001, F024.
2. Completed - CI and release hygiene: F002, F003, F004.
3. Completed - Config and source-data foundations: F005-F009.
4. Completed - Explainability and diagnostics: F010-F014.
5. Completed - Profile data model groundwork: F015.
6. Completed - Golden cleaned-output fixtures: F016.
7. Completed - Parser/fuzzer quality gate: F017.
8. Completed - GUI smoke quality gate: F018.
9. Completed - Benchmark quality gate: F019.
10. Completed - Accessibility and i18n foundations: F020, F021.
11. Completed - Migration imports: F022.
12. Completed - Migration/export interoperability: F023.
13. Completed - Declarative profile/history/scheduler/portable automation: F025-F029.
14. Completed - DNS resolver interoperability pack: F030.
15. Completed - Guarded cloud DNS adapters: F031.
16. Completed - Adblock syntax lint and quarantine: F032.
17. Completed - Rule tier warnings: F033.
18. Completed - IDN, threat feed, CNAME, encrypted-DNS bypass, DNS rebinding, and SafeSearch/restricted-mode security reviews: F034, F035, F036, F037, F038, F039.
19. Completed - Time-bound profile activation: F040.
20. Completed - Tray quick switch: F041.
21. Completed - Variant/bundle selector: F042.
22. Completed - Filter builder and query history: F043.
23. Completed - Provenance log filters and export: F047.
24. Completed - Watch expressions: F048.
25. Completed - Source freshness and growth charts: F049.
26. Completed - Virtualized large-list views: F050.
27. Completed - Parallel source fetcher with bounded retries: F051.
28. Completed - Source adapter plugin interface: F045.
29. Completed - Local REST facade with bearer auth: F046.
30. Completed - Winget and Chocolatey manifests: F052.
31. Completed - Translation contribution workflow: F053.
32. Completed - Encrypted opt-in sync via local Git remote: F054.
33. Completed - Signed shareable allowlist/profile patches: F055.
34. Completed - Restore-point or VSS-backed apply recovery spike: F044.
35. Completed - WFP IP/CIDR blocker companion: F056.

Rationale: these items reduce maintenance risk, make the current product more trustworthy, and create the internal contracts needed for the larger profile/integration work.

### Next

1. Later-stage platform and enterprise items: F057-F070.

Rationale: these are valuable and well-supported by the market, but most require the Now-phase source manifest, profile model, and test/release foundations.

### Later

1. Windows network stack companions: F057, F058.
2. Router and enterprise deployment exports: F059, F060.
3. Developer-side extension surfaces: F061, F062.
4. Advanced DNS/security enrichment: F063, F064, F065, F066, F067, F068, F069, F070.

Rationale: these are plausible directions, but they either introduce credentials, services, signing, network-stack risk, or product-scope expansion.

### Under Consideration

F073, F074, F075, F076, F077, F079, F080 remain research candidates. They should not enter implementation until a prototype proves they can be local-first, understandable, and low-surprise.

### Rejected

F071, F072, F078, F081, F082, F083, F084, F085, F086, F087, F088, F089, F090 are rejected for current strategy. They either contradict the hosts-editor scope, violate local-control expectations, or introduce risk without enough user value.

## Category Coverage Audit

| Category | Coverage |
| --- | --- |
| Security | F004, F009, F014, F034-F038, F055-F057, F065-F068 |
| Accessibility | F018, F020, F021, F053, F062 |
| i18n/l10n | F021, F034, F053 |
| Observability/telemetry | F012, F013, F047-F049, F076; telemetry is local-only unless user exports |
| Testing | F002, F016-F019 |
| Docs | F001, F024 |
| Distribution/packaging | F003, F004, F052, F060 |
| Plugin ecosystem | F045, F046 |
| Mobile | F069, F070 |
| Offline/resilience | F005, F008, F026, F028, F044 |
| Multi-user/collab | F015, F040, F054, F055, F060 |
| Migration paths | F005, F022, F030, F031 |
| Upgrade strategy | F003-F006, F052 |

## Adversarial Review Notes

A hostile reviewer would likely object to four things:

1. "This is still one giant Python file." Answer: F001 documents the split first; no large refactor should start before the public contracts and test fixtures are stable.
2. "The roadmap overreaches into DNS server territory." Answer: server-like work is mostly rejected, later, or export-only; the core product remains a hosts editor.
3. "External feeds are a supply-chain risk." Answer: F006-F009 put source metadata, health, trust, and caching before adding more feeds.
4. "Logs and analytics can become surveillance." Answer: F013, F047, F049, and F076 are local, opt-in, and must include retention controls.

## Appendix A - Source Index

### Local Sources

| ID | Source | Use |
| --- | --- | --- |
| L1 | `README.md` | Current product claims, workflow, requirements, safety model |
| L2 | `CHANGELOG.md` | Shipped feature baseline through v2.17.0 |
| L3 | `CLAUDE.md` | Architecture and gotchas snapshot |
| L4 | `CODEX_CHANGELOG.md` | Prior audit findings, known gaps, validation history |
| L5 | `hosts_editor.py` | Current implementation, entry points, config, UI, CLI, source catalog |
| L6 | `tests/test_hosts_editor_logic.py` | Test inventory and current coverage shape |
| L7 | `git log --oneline -n 200` | Recurring pain points and development history |
| L8 | Prior `ROADMAP.md` | Existing idea inventory and shipped/backlog reconciliation |

### OSS And Adjacent Projects

| ID | URL | Signal used |
| --- | --- | --- |
| O1 | https://github.com/oldj/SwitchHosts | Hosts profile switching, remote hosts, tray, syntax highlight, i18n |
| O2 | https://github.com/scottlerch/HostsFileEditor | Windows archive/restore, bulk row actions, sort/filter, tray, ping |
| O3 | https://github.com/2ndalpha/gasmask | macOS local/remote/combined profiles, menu-bar switching, logs |
| O4 | https://github.com/StevenBlack/hosts | Variant matrix, source directory, whitelist/blacklist overlays, source contacts |
| O5 | https://github.com/AdAway/AdAway | Android hosts blocker, source lists, preview builds, translation workflow |
| O6 | https://github.com/pi-hole/pi-hole | Dashboard, DHCP, install/release expectations, scale claims |
| O7 | https://github.com/AdguardTeam/AdGuardHome | Query log, custom rules, rewrites, API, CNAME/IP blocking, issues |
| O8 | https://github.com/TechnitiumSoftware/DnsServer | Encrypted DNS, clustering, OIDC, CNAME cloaking, blocklists |
| O9 | https://github.com/hectorm/hblock | Timers, multiple outputs, allowlist guidance, source lookup |
| O10 | https://github.com/hagezi/dns-blocklists | Tiered lists, NRD/DGA, bypass, rebinding, native tracker categories |
| O11 | https://github.com/blocklistproject/Lists | Category lists and output format parity |
| O12 | https://github.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist | Large combined hosts source |
| O13 | https://github.com/crazy-max/WindowsSpyBlocker | Windows telemetry pack model |
| O14 | https://github.com/DNSCrypt/dnscrypt-proxy | Encrypted DNS and blocklist builder patterns |
| O15 | https://github.com/0xERR0R/blocky | Lightweight DNS proxy/ad blocker pattern |
| O16 | https://github.com/jacklul/pihole-updatelists | Remote list sync automation |
| O17 | https://github.com/AdguardTeam/HostlistsRegistry | Hostlist metadata and inclusion criteria |
| O18 | https://github.com/ppfeufer/adguard-filter-list | Combined list with whitelist caveats |
| O19 | https://awesome-selfhosted.net/tags/dns.html | Awesome-list validation of DNS blocker ecosystem |
| O20 | https://github.com/cdransf/awesome-adblock | Awesome-list validation of adjacent browser/network blockers |
| O21 | https://github.com/tanrax/maza-ad-blocking | Local OS ad blocker pattern |
| O22 | https://github.com/Lateralus138/NPS-Hosts-Manager | Lightweight Windows hosts manager baseline |
| O23 | https://github.com/mitchellkrogza/Badd-Boyz-Hosts | Additional curated hosts source |
| O24 | https://github.com/anudeepND/blacklist | Curated ad/tracking hostfile source |
| O25 | https://github.com/Perflyst/PiHoleBlocklist | Smart TV and device-specific blocklist caveats |
| O26 | https://github.com/nextdns/cname-cloaking-blocklist | Original CNAME tracker-target list requiring CNAME-aware wildcard matching |
| O27 | https://github.com/AdguardTeam/cname-trackers | CNAME original targets, disguised-domain lists, and RPZ output guidance |

### Provider SafeSearch And Parental-Control Docs

| ID | URL | Signal used |
| --- | --- | --- |
| P1 | https://support.google.com/websearch/answer/186669?hl=en | Google SafeSearch VIP/CNAME mapping and hosts-file caveats |
| P2 | https://support.google.com/a/answer/6212415?hl=en | YouTube Restricted Mode strict/moderate DNS target mappings |
| P3 | https://support.microsoft.com/topic/block-adult-content-with-safesearch-or-block-chat-11546adf-1bbc-4c2e-9ef9-fbd6799bc79d | Bing strict SafeSearch mapping target |
| P4 | https://duckduckgo.com/duckduckgo-help-pages/features/safe-search/ | DuckDuckGo network-level Safe Search CNAME target |

### Commercial Products

| ID | URL | Signal used |
| --- | --- | --- |
| C1 | https://nextdns.io/ | Security toggles, NRD/DGA, IDN homographs, typosquatting, analytics, custom allow/deny, rewrites, profiles |
| C2 | https://docs.controld.com/docs/profiles | Profiles, chained policies, priority order, endpoint assignment |
| C3 | https://docs.controld.com/docs/custom-rules | Cloud hosts-file equivalent, wildcard support, block/bypass/redirect/private domains |
| C4 | https://docs.controld.com/docs/analytics | Analytics levels, data retention, query metadata, storage region |
| C5 | https://adguard-dns.io/en/welcome.html | Ad blocking, parental controls, per-device stats, customized filtering, encrypted protocols |
| C6 | https://www.dnsfilter.com/ | Business DNS filtering, reporting, roaming clients, SSO, integrations |
| C7 | https://apidocs.dnsfilter.com/ | API-first management precedent |
| C8 | https://nextdns.github.io/api/ | NextDNS profile child endpoints, X-Api-Key authentication, logs download |
| C9 | https://docs.controld.com/reference/post_profiles-profile-id-rules | Control D custom-rule create endpoint, block action, hostnames[] form field, bearer auth |
| C10 | https://docs.controld.com/docs/how-to-export-logs-to-csv | Control D dashboard/API CSV activity-log export shape |
| C11 | https://docs.controld.com/docs/log-field-reference | Control D activity query field and blocked action code |
| C12 | https://adguard-dns.io/kb/general/dns-filtering-syntax/ | DNS-compatible adblock-style subset, hosts syntax, and domain-only list rules |
| C13 | https://help.adblockplus.org/adblock-plus-help-center/how-to-write-filters | Browser filter options, exception rules, element hiding, and snippet filters |
| C14 | https://adguard.com/kb/general/ad-filtering/create-own-filters/ | Cosmetic, scriptlet, and path-in-domain filter syntax that hosts files cannot express |

### Community And Issue Signals

| ID | URL | Signal used |
| --- | --- | --- |
| K1 | https://www.reddit.com/r/AdGuardHome/comments/1re336u/adguard_home_can_only_filter_what_it_sees_a_lot/ | DNS bypass by hardcoded DNS, DoH, DoQ; firewall handoff need |
| K2 | https://www.reddit.com/r/selfhosted/comments/1sdg0vb/next_dns_pihole_adguard_home_technitium/ | Large-list RAM/performance and clustering preference |
| K3 | https://www.reddit.com/r/pihole/comments/1t2c7hf/adguard_home_pihole_or_technitium/ | Product comparison, per-device control, safe search, uptime |
| K4 | https://www.reddit.com/r/Adguard/comments/1reoqwo/adguard_dns_v220_with_custom_blocklists_is/ | Custom blocklist size limits and rule-count pain |
| K5 | https://news.ycombinator.com/item?id=34374725 | Network blocking value, profiles, mobile/roaming, false positives |
| K6 | https://news.ycombinator.com/item?id=39968103 | DNS blockers can break services and need easier bypass UX |
| K7 | https://news.ycombinator.com/item?id=31549238 | DNS blockers cannot handle same-domain/path/cosmetic ads |
| K8 | https://stackoverflow.com/questions/24260566/edit-hosts-file-in-python | Hosts writes require admin privileges |
| K9 | https://stackoverflow.com/questions/138162/wildcards-in-a-windows-hosts-file | Hosts file does not support wildcard domains |
| K10 | https://learn.microsoft.com/en-us/answers/questions/3758720/settingsmodifier-win32-hostsfilehijack | Windows Defender/hosts hijack false-positive and tamper concerns |
| K11 | https://github.com/AdguardTeam/AdGuardHome/issues/997 | User accounts request signal in DNS admin products |
| K12 | https://github.com/AdguardTeam/AdGuardHome/issues/2290 | Query log format reconsideration signal |
| K13 | https://github.com/scottlerch/HostsFileEditor/issues/12 | Dynamic enabled-state UX issue |
| K14 | https://github.com/scottlerch/HostsFileEditor/issues/10 | Windows JumpList/tray integration request |

### Standards, Specs, And Platform APIs

| ID | URL | Signal used |
| --- | --- | --- |
| S1 | https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule | NRPT rule creation, namespace routing, punycode encoding |
| S2 | https://learn.microsoft.com/en-us/powershell/module/dnsclient/remove-dnsclientnrptrule | NRPT cleanup/removal |
| S3 | https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page | WFP capabilities and risk boundary |
| S4 | https://learn.microsoft.com/en-us/windows/win32/dns/dns-functions | Windows DNS API function index; cache-flush APIs need implementation verification |
| S5 | https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing | ETW real-time/local log consumption |
| S6 | https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics | DNS logging and diagnostics context |
| S7 | https://datatracker.ietf.org/doc/html/rfc8484 | DNS over HTTPS |
| S8 | https://datatracker.ietf.org/doc/html/rfc9250 | DNS over QUIC |
| S9 | https://datatracker.ietf.org/doc/html/rfc9460 | SVCB/HTTPS records |
| S10 | https://datatracker.ietf.org/doc/html/rfc9461 | SVCB mapping for DNS servers |
| S11 | https://adguard-dns.io/kb/ko/adguard-home/faq/ | CNAME/IP query-log behavior and logs |
| S12 | https://stackoverflow.com/questions/61707242/can-i-use-wildcards-for-blocking-websites-in-hosts-files | Hosts wildcard limitation confirmation |
| S13 | https://www.rfc-editor.org/rfc/rfc5890 | IDNA A-label/U-label definitions and Punycode prefix semantics |
| S14 | https://unicode.org/reports/tr46/ | Unicode IDNA compatibility processing and confusables security caveat |
| S15 | https://www.first.org/global/sigs/dns/stakeholder-advice/detection/dga | DGA detection guidance and CTI feed/RPZ/protective DNS caveat |

### Academic, Research, And Engineering Sources

| ID | URL | Signal used |
| --- | --- | --- |
| A1 | https://www.mdpi.com/1424-8220/26/3/1041 | Early phishing-domain detection with registry/campaign context |
| A2 | https://discovery.ucl.ac.uk/id/eprint/10209951 | Newly registered phishing domains at scale |
| A3 | https://link.springer.com/article/10.1186/s42400-025-00523-w | Newly registered domain activation behavior |
| A4 | https://dev.ndss-symposium.org/ndss-paper/auto-draft-146/ | CNAME cloaking and cookie exfiltration risk |
| A5 | https://petsymposium.org/2021/files/papers/issue3/popets-2021-0053.pdf | Large-scale DNS-based tracking evasion |
| A6 | https://arxiv.org/abs/2009.14330 | ML detection of CNAME cloaking-based tracking |
| A7 | https://netbeacon.org/recent-spike-in-malicious-phishing-concentrated-in-two-registrars/ | Registrar concentration in malicious phishing |
| A8 | https://www.sciencedirect.com/science/article/pii/S0167404820303874 | Malicious site cloaking behavior |
| A9 | https://pubmed.ncbi.nlm.nih.gov/41127663/ | LegitPhish phishing/legitimate URL dataset |
| A10 | https://www.mdpi.com/2079-9292/11/8/1276 | DNS filtering evaluation and blocklist accuracy concerns |

### Dependency And Security Sources

| ID | URL | Signal used |
| --- | --- | --- |
| D1 | https://www.python.org/downloads/release/python-3145/ | Current Python 3.14 maintenance release stream |
| D2 | https://pyinstaller.org/en/stable/CHANGES.html | PyInstaller 6.20 changes and compatibility |
| D3 | https://github.com/advisories/GHSA-p2xp-xx3r-mffc | PyInstaller CVE-2025-59042 local privilege escalation |
| D4 | https://github.com/advisories | Advisory scanning and OSS security database |
| D5 | https://pypi.org/project/pyinstaller/ | PyInstaller package release metadata |
| D6 | https://learn.microsoft.com/en-us/windows/package-manager/package/manifest | Winget manifest reference |

## Appendix B - Research Queries

Representative queries used:

- `GitHub hosts file editor manager Windows open source SwitchHosts HostMinder Gas Mask hostsman alternative`
- `GitHub hosts blocklist aggregator StevenBlack hBlock hosts-block hosts-bl maza ad blocking`
- `commercial hosts file manager Windows HostsMan SwitchHosts features backup DNS flush blocklist update`
- `NextDNS features blocklists analytics logs denylist allowlist parental control docs`
- `Control D docs profiles analytics logs custom rules services DNS`
- `site:news.ycombinator.com Pi-hole AdGuard Home NextDNS DNS blocking`
- `reddit pi-hole adguard home nextdns allowlist false positives blocklist complaints`
- `Stack Overflow Windows hosts file admin permission Python edit hosts file`
- `Microsoft Windows hosts file documentation DNS Client hosts file NRPT Add-DnsClientNrptRule docs`
- `IETF DNS over HTTPS RFC 8484 DNS over QUIC RFC 9250 encrypted client hello ECH hosts blocking limitations`
- `DNS blocklist false positives study domain blocklist evaluation academic`
- `CNAME cloaking blocklist detection research paper ad tracking`
- `AdGuard DNS filtering syntax cosmetic rules Adblock Plus exception rules hosts file`
- `Control D custom rules wildcard regex exact hosts file wildcard limitation`
- `Google SafeSearch VIP YouTube Restricted Mode Bing strict SafeSearch DuckDuckGo safe search CNAME hosts file`
- `PyInstaller changelog latest 2026 security changes`
- `GitHub Advisory Database PyInstaller vulnerability 2025 2026`

## Appendix C - Self-Audit

- Traceability: every roadmap candidate in the active register cites one or more appendix source IDs.
- Tiering: every item has a tier and risk/dependency note.
- Duplicates: old roadmap duplicates were merged into the feature register.
- Misfits: browser cosmetic filtering, default cloud sync, silent writes, in-app DNS clustering, main-app kernel drivers, massive vendored blocklists, and uncited anti-cheat presets are explicitly rejected.
- Thin categories: accessibility, i18n, telemetry/observability, testing, distribution, plugin ecosystem, mobile, offline resilience, multi-user/collaboration, migration, and upgrade strategy all have named items.
- Philosophy check: all Now work reinforces current safety, local control, and Windows-first identity.
- Disk check: this file is the repo-root `ROADMAP.md`.
