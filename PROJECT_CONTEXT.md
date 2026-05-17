# HostsFileGet Project Context

Generated: 2026-05-17
Repo basis: `d5b3d29` on `main`
Current app version observed: `Hosts File Get v2.27.0`

## One-Screen Summary

HostsFileGet is a Windows-first Python/Tkinter desktop workbench for importing, reviewing, cleaning, explaining, and safely writing the Windows hosts file. It is intentionally local-first: hosts writes are explicit and recoverable; network activity is tied to user-requested source imports, source-health checks, documentation, or reviewed diagnostics.

The repository has recently been moving from a large single-file app toward a package. Extracted modules now cover constants, fetch/cache behavior, source catalog and source-health behavior, compression, atomic IO, parsing, theme helpers, adblock syntax classification, IDN/homograph helpers, and normalization. The central technical challenge remains reducing `hosts_editor.py` while preserving the mature GUI, CLI, safety model, and tests.

## Canonical Product Boundary

HostsFileGet should remain:

- A local Windows hosts-file editor, importer, cleaner, diagnostics workbench, and safe writer.
- A reviewed handoff generator for external DNS, mobile, router, managed deployment, and CTI workflows.
- A source-aware maintenance tool with provenance, health checks, false-positive triage, backups, and rollback.

HostsFileGet should not present itself as:

- A DNS resolver, proxy, WFP driver, mobile MDM tool, router controller, browser cosmetic blocker, or cloud DNS admin console.
- A tool that can make hosts files support wildcard domains, URL paths, HTTPS decryption, or browser cosmetic filtering.
- A silent writer to external providers or managed infrastructure.

## Repository Shape

Important root files:

- `hosts_editor.py`: main GUI/CLI module, still roughly 27.1K lines after the 2026-05-17 source-catalog extraction.
- `hostsfileget/`: package modules extracted from the monolith.
- `PythonLauncher.ps1`: WPF launcher/bootstrapper for Windows users.
- `data/blocklist_sources.json`: curated source manifest, 177 sources across 10 categories and 6 bundles.
- `tests/`: unit, GUI smoke, package manifest, and benchmark smoke tests.
- `benchmarks/large_file_benchmark.py`: large-file benchmark harness.
- `docs/`: feature, integration, export, source, and operational documentation.
- `ARCHITECTURE.md`, `CHANGELOG.md`, `CODEX_CHANGELOG.md`, `TROUBLESHOOTING.md`, `README.md`: durable project documentation.
- `AGENTS.md`, `CLAUDE.md`: tool/session instructions. `AGENTS.md` points to `CLAUDE.md`.
- `ROADMAP.md`: active prioritized plan after the 2026-05-17 research reset.

Extracted package modules observed:

- `hostsfileget/constants.py`
- `hostsfileget/fetch.py`
- `hostsfileget/source_catalog.py`
- `hostsfileget/compression.py`
- `hostsfileget/atomic_io.py`
- `hostsfileget/parsing.py`
- `hostsfileget/theme.py`
- `hostsfileget/adblock.py`
- `hostsfileget/idn_homograph.py`
- `hostsfileget/normalize.py`
- `hostsfileget/__init__.py`

## Current Strengths

- Strong safety posture: backups, previewed cleaning, atomic write helpers, disable/enable handoff, admin detection, panic restore, and source-name marker sanitization.
- Broad source handling: curated manifest, custom sources, bundles, ETag-aware cache, source-health reports, adblock syntax quarantine, rule tier reports, IDN/homograph warnings, and threat-feed/CNAME/encrypted-DNS planning artifacts.
- Practical interoperability: Pi-hole, AdGuard Home, Technitium, blocky, NextDNS, Control D, RPZ, Unbound, Privoxy, mobile DNS profile handoffs, managed package plans, router/gateway plans, NRPT plans, and VS Code/TUI planning surfaces.
- Testable pure logic: many parser, importer, export, profile, safety, and report functions are unit tested without requiring full GUI startup.
- Explicit roadmap and documentation culture: many features have docs, CLI commands, and tests.

## Current Risks

- `hosts_editor.py` remains too large and owns too many workflows, which raises regression risk during feature work.
- `data/blocklist_sources.json` has lifecycle metadata from the 2026-05-17 source-health reset. The baseline found 122 healthy, 21 warning, and 34 failed sources; hard-gone sources are now retained as `retired` and removed from built-in bundles.
- Release identity is uneven: runtime reports v2.27.0, but README release-facing text still contains preview-version language.
- The project has many plan-only integrations. Future work must continue distinguishing reviewed handoff artifacts from active external writers.
- Python/PyInstaller compatibility should be stated explicitly as Python 3.14 and PyInstaller 6.x evolve.

## Research Artifacts

The 2026-05-17 research run lives in `.ai/research/2026-05-17/`:

- `STATE_OF_REPO.md`: local repository reconnaissance.
- `MEMORY_CONSOLIDATION.md`: instruction and memory reconciliation.
- `SOURCE_REGISTER.md`: local and external source index.
- `RESEARCH_LOG.md`: search strategy, query log, saturation notes.
- `COMPETITOR_MATRIX.md`: competitor and adjacent ecosystem comparison.
- `FEATURE_BACKLOG.md`: raw harvested ideas.
- `PRIORITIZATION_MATRIX.md`: scored candidates.
- `SECURITY_AND_DEPENDENCY_REVIEW.md`: dependency/security findings.
- `DATASET_MODEL_INTEGRATION_REVIEW.md`: data, model, API, benchmark, and integration review.
- `CHANGESET_SUMMARY.md`: files changed by the research run.
- `source-health-report.json`: live source-health evidence.
- `external_repo_metadata.json`: GitHub API snapshot.
- `pypi_metadata.json`: PyPI JSON snapshot.

## Session Start Checklist

At the start of future work:

1. Read `AGENTS.md`, `CLAUDE.md`, `PROJECT_CONTEXT.md`, and `ROADMAP.md`.
2. Check `git status --short --branch` and recent commits.
3. Verify current app version with `python hosts_editor.py --version`.
4. For source/catalog work, inspect `.ai/research/2026-05-17/source-health-report.json` and `data/blocklist_sources.json`.
5. For release work, inspect `requirements-build.txt`, `requirements-security.txt`, `HostsFileGet.spec`, `.github/workflows/`, and the latest PyInstaller advisory status.
6. Run focused tests before broad tests; this repository has a large monolithic import surface.

## Recommended Next Pass

Start with the remaining `ROADMAP.md` P0 items:

1. Release Identity and Version Hygiene.

This is highest leverage because the source catalog reset and extraction are complete, and release identity is the remaining P0 gap before continuing into broader compatibility and hardening work.
