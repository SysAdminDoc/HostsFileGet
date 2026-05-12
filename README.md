<!-- codex-branding:start -->
<p align="center"><img src="icon.png" width="128" alt="Hosts File Get"></p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-preview-58A6FF?style=for-the-badge">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-4ade80?style=for-the-badge">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Python%20GUI-58A6FF?style=for-the-badge">
</p>
<!-- codex-branding:end -->

# Hosts File Get

Hosts File Get is a Windows-first desktop tool for inspecting, cleaning, importing, and safely writing the system `hosts` file.

It is designed for people who work with large blocklists, external feed imports, local allowlists, and log-derived domains, without forcing them to hand-edit `C:\Windows\System32\drivers\etc\hosts`.

## Highlights

- Split save modes:
  - `Save Raw` writes the editor exactly as-is
  - `Save Cleaned` applies normalization, deduplication, and whitelist filtering first while preserving non-blocking custom IP mappings
- Live impact stats:
  - active entry count
  - duplicate removals
  - whitelist removals
  - normalization count
- Polished workspace:
  - clearer save hierarchy with `Save Cleaned` as the safer primary action
  - live session badges for admin state, editor state, import mode, and write mode
  - live sidebar summaries for custom sources, pasted manual content, and whitelist state
  - selection-aware import/removal dialogs plus calmer sidebar guidance and empty states
- Safe write workflow:
  - backup creation before save
  - preview before cleaned writes
  - dry-run mode for no-write validation
  - unsaved-change prompts on reload and exit
- Import pipeline:
  - curated web blocklists from a versioned JSON source manifest
  - source health reporting for curated feed reachability
  - ETag / Last-Modified refresh cache with cached-body fallback
  - source trust badges for transport, upstream report path, local freshness, cache integrity, and catalog/license caveats
  - source overlap matrix for fetched feeds
  - batch import with filtering and progress
  - custom persistent sources
  - pfSense DNSBL log import
  - NextDNS CSV import
  - Control D activity-log CSV import
  - Windows DNS Client Operational snapshot import
  - SwitchHosts, Gas Mask, and HostsFileEditor migration imports
  - manual pasted list import
- Search and cleanup:
  - find / next / previous navigation
  - remove matching entries with selection + preview
  - adblock syntax linting plus cosmetic/path-rule quarantine for hosts-safe reviews
  - rule tier reporting for exact, subdomain, wildcard, regex, path, exception, and browser-only rules
  - IDN/Punycode and homograph-risk reporting before trusting mixed internationalized lists
  - NRD/DGA/TIF threat feed pack planning with freshness and false-positive controls
  - CNAME cloaking workflow planning that separates hosts-reviewable disguised domains from DNS-only CNAME target feeds
  - encrypted-DNS bypass pack planning that separates hosts-reviewable resolver names from router/firewall handoffs
  - DNS rebinding protection checks for external-looking domains mapped to private, local, loopback, link-local, ULA, or CGNAT ranges
  - SafeSearch and restricted-mode template plans that separate hosts-reviewable search mappings from DNS CNAME handoffs
  - false-positive triage for whitelist, pin, source-match, and upstream report decisions
  - entry provenance view for import-section ownership, source matches, and local audit events
- Export adapters:
  - cleaned hosts, plain domains, Adblock, dnsmasq, and Pi-hole formats
  - Pi-hole, AdGuard Home/DNS, Technitium DNS Server, and blocky interoperability presets
  - plan-only NextDNS and Control D cloud DNS adapter plans that never store API keys or execute remote writes
  - RPZ, Unbound, Privoxy, gzip-compressed hosts, and bzip2-compressed hosts
- Operational utilities:
  - DNS cache flush
  - DNS bypass diagnostics for browser encrypted-DNS and proxy signals
  - backup restore preview
  - optional local Git history snapshot/status/restore commands
  - emergency DNS recovery helper
- Configuration:
  - versioned JSON config migration
  - profile-ready schema mirror for future named whitelist/source/pin sets
  - declarative YAML/TOML/JSON profile plan, apply, and export commands
  - CLI profile list/import/apply/export commands that never write the hosts file
  - scheduled-update activity reports backed by bounded silent-run logs
  - managed portable bundle config export and config-location reporting
  - versioned English string catalog foundation for future localization

## Supported Input Shapes

The cleaner/importer is more flexible than a plain hosts parser. It can normalize:

- standard hosts lines like `0.0.0.0 example.com`
- bare domains like `example.com`
- wildcard domains like `*.example.com`
- URL-style entries like `https://example.com/path`
- adblock-style rules like `||tracker.example^`
- dnsmasq-style rules like `address=/telemetry.example/0.0.0.0`

Browser-only adblock rules such as `example.com##.ad`, exception rules such as `@@||example.com^`, and path rules such as `||example.com/ads/*` are linted and skipped during normalized hosts-file conversion instead of being broadened into unsafe domain blocks.

## Requirements

- Windows
- Python 3.x
- Administrator privileges for real hosts-file writes

The app can still be useful without elevation in dry-run mode, but raw/cleaned saves to the system hosts file require admin rights.

## Quick Launch

### Option 1: Launcher script

Run the launcher from an elevated PowerShell session:

```powershell
.\PythonLauncher.ps1
```

The launcher will:

- ensure `winget` is available
- reuse an existing Python 3 runtime when possible
- install Python only if needed
- refresh the cached `hosts_editor.py` when the download succeeds
- refresh the cached curated source manifest beside the editor
- refresh the cached English string catalog beside the editor when available
- fall back to the last valid cached editor copy if the network refresh fails
- launch the editor

### Option 2: Run directly

```powershell
python hosts_editor.py
```

If you are not already elevated, the app will attempt to relaunch with Administrator privileges. If elevation is declined, it can still open in a read-only / dry-run-friendly state.

## Main Workflow

1. Launch the app as Administrator if you plan to write the real hosts file.
2. Import sources, paste entries, or edit directly in the main editor.
3. Maintain a persistent whitelist in the sidebar.
4. Review live warning stats and previews.
5. Choose `Save Raw` or `Save Cleaned` depending on intent.
6. Flush DNS if you want the OS cache updated immediately.

## Search and Removal

The search box is both a navigator and a cleanup tool.

- `Find`, `Prev`, and `Next` move through matches
- `Remove` opens a selection dialog for matching non-comment entries
- removal is previewed before being applied

Keyboard shortcuts:

- `Ctrl+F` focus search
- `Ctrl+S` save cleaned
- `Ctrl+Shift+S` save raw
- `F5` refresh from disk

## Safety Notes

- `Save Cleaned` always shows a preview when it would change the file.
- Empty saves require confirmation.
- Reloading from disk prompts before discarding unsaved editor changes.
- Restoring from backup is previewed before writing.
- The emergency recovery action is intentionally destructive and should be treated as a last resort.

## Tests

Run the regression suite with:

```powershell
python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py tests\test_gui_smoke.py tests\test_benchmarks.py benchmarks\large_file_benchmark.py
python -m unittest discover -s tests -v
```

Run a non-admin curated source health report with:

```powershell
python hosts_editor.py --source-health --source-health-output source-health-report.json
```

Plan, apply, or export a declarative profile file without writing the system hosts file:

```powershell
python hosts_editor.py --config-plan .\profile.yaml
python hosts_editor.py --config-apply .\profile.toml
python hosts_editor.py --config-export .\profile.yaml
```

Use optional local Git-backed history when Git is installed:

```powershell
python hosts_editor.py --history-status
python hosts_editor.py --history-snapshot
python hosts_editor.py --history-restore 1a2b3c4d5e6f
```

Manage saved profiles from the CLI without writing the system hosts file:

```powershell
python hosts_editor.py --profile-list
python hosts_editor.py --profile-import .\work-profile.yaml
python hosts_editor.py --profile-apply work
python hosts_editor.py --profile-export work .\work-profile.toml
```

Inspect scheduled-update status and recent silent-run activity with:

```powershell
python hosts_editor.py --activity-report
python hosts_editor.py --activity-report --activity-report-output scheduler-activity.json
```

Inspect active config location or create a managed portable bundle config:

```powershell
python hosts_editor.py --config-location
python hosts_editor.py --portable-export .\portable-bundle
python hosts_editor.py --portable-export .\portable-bundle --portable-overwrite
```

List or generate file-only DNS integration exports:

```powershell
python hosts_editor.py --integration-list
python hosts_editor.py --integration-export adguard-home .\cleaned-hosts.txt .\adguard-dns-filter.txt
```

Generate guarded cloud-DNS replay plans or extract blocked domains from cloud DNS CSV log exports:

```powershell
python hosts_editor.py --cloud-adapter-list
python hosts_editor.py --cloud-adapter-plan nextdns .\cleaned-hosts.txt .\nextdns-plan.json --cloud-profile-id abc123
python hosts_editor.py --cloud-adapter-plan controld .\cleaned-hosts.txt .\controld-plan.json --cloud-profile-id profile_id
python hosts_editor.py --cloud-log-import controld .\activity-log.csv .\blocked-domains.txt
```

Lint mixed adblock lists and write a hosts-safe quarantine copy:

```powershell
python hosts_editor.py --adblock-lint .\filters.txt --adblock-lint-output .\adblock-lint.json
python hosts_editor.py --adblock-quarantine .\filters.txt .\filters.hosts-safe.txt
```

Inspect exact/wildcard/regex/provider-only rule tiers before hosts conversion:

```powershell
python hosts_editor.py --rule-tier-report .\filters.txt --rule-tier-output .\rule-tiers.json
```

Review IDN/Punycode and mixed-script homograph candidates with:

```powershell
python hosts_editor.py --idn-report .\filters.txt --idn-output .\idn-report.json
```

List guarded NRD/DGA/TIF threat feed packs or write a local review plan:

```powershell
python hosts_editor.py --threat-feed-list
python hosts_editor.py --threat-feed-plan nrd-review .\nrd-plan.json
```

List guarded CNAME cloaking workflows or write a local handoff plan:

```powershell
python hosts_editor.py --cname-cloaking-list
python hosts_editor.py --cname-cloaking-plan cname-aware-dns .\cname-plan.json
```

List guarded encrypted-DNS bypass packs or write a router/firewall handoff plan:

```powershell
python hosts_editor.py --encrypted-dns-bypass-list
python hosts_editor.py --encrypted-dns-bypass-plan router-firewall-handoff .\dns-bypass-plan.json
```

Review static hosts mappings for DNS rebinding-sensitive private and local IP targets:

```powershell
python hosts_editor.py --dns-rebinding-report .\hosts.txt --dns-rebinding-output .\dns-rebinding-report.json
python hosts_editor.py --dns-rebinding-report .\hosts.txt --dns-rebinding-trusted-suffix lab.example
```

List SafeSearch/restricted-mode templates or write a local JSON plan without applying hosts or DNS changes:

```powershell
python hosts_editor.py --safesearch-template-list
python hosts_editor.py --safesearch-template-plan google .\google-safesearch-plan.json
python hosts_editor.py --safesearch-template-plan youtube .\youtube-restricted-plan.json
```

Run the deterministic large-file benchmark with:

```powershell
python benchmarks\large_file_benchmark.py --entries 100000 --repeats 3 --json-output benchmark-report.json
```

Open the local accessibility audit from **Tools > Accessibility Audit...**. It reports tracked contrast pairs, font assumptions, and the manual Windows screen-reader/high-contrast checklist.

## Repository Notes

- Main application: `hosts_editor.py`
- Launcher: `PythonLauncher.ps1`
- Regression tests: `tests/test_hosts_editor_logic.py`
- GUI smoke tests: `tests/test_gui_smoke.py`
- Benchmark smoke tests: `tests/test_benchmarks.py`
- Golden cleaned-output fixtures: `tests/golden_cleaned/`
- Large-file benchmark harness: `benchmarks/large_file_benchmark.py`
- Architecture map: `ARCHITECTURE.md`
- Declarative profile files: `docs/declarative-config.md`
- CLI profile management: `docs/cli-profiles.md`
- Optional Git history: `docs/git-history.md`
- Scheduler activity report: `docs/scheduler-activity.md`
- Portable bundle config: `docs/portable-config.md`
- DNS interoperability pack: `docs/dns-integrations.md`
- Cloud DNS adapters: `docs/cloud-dns-adapters.md`
- Adblock syntax lint: `docs/adblock-lint.md`
- Rule tier report: `docs/rule-tiers.md`
- IDN and homograph report: `docs/idn-homograph.md`
- NRD/DGA threat feed packs: `docs/threat-feed-packs.md`
- CNAME cloaking workflow: `docs/cname-cloaking.md`
- Encrypted DNS bypass packs: `docs/encrypted-dns-bypass.md`
- DNS rebinding protection checks: `docs/dns-rebinding.md`
- SafeSearch/restricted-mode templates: `docs/safesearch-restricted-mode.md`
- Troubleshooting and hosts-file limits: `TROUBLESHOOTING.md`
- Config schema: `docs/config-schema.md`
- Curated source manifest: `docs/source-manifest.md`
- Source health checks: `docs/source-health.md`
- Source trust badges: `docs/source-trust.md`
- Source overlap matrix: `docs/source-overlap.md`
- False-positive triage: `docs/false-positive-triage.md`
- Entry provenance: `docs/entry-provenance.md`
- Windows DNS Client snapshot: `docs/windows-dns-client.md`
- DNS bypass diagnostics: `docs/dns-bypass-diagnostics.md`
- Migration imports: `docs/migration-imports.md`
- Export formats: `docs/export-formats.md`
- Accessibility audit: `docs/accessibility.md`
- i18n string catalog: `docs/i18n.md`
- Sourced implementation plan: `ROADMAP.md`
- Release build notes: `docs/release.md`
- Codex handoff notes: `CODEX_CHANGELOG.md`

## License

MIT
