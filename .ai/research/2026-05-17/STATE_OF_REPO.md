# State Of Repo - 2026-05-17

Repo: `C:\Users\--\repos\HostsFileGet`
Branch observed: `main`
HEAD observed: `d5b3d29 refactor: extract constants + fetch modules (phase 6)`
Remote observed: `https://github.com/SysAdminDoc/HostsFileGet.git`

## Recon Commands

- `git status --short --branch`: clean at start, `## main...origin/main`.
- `rtk git log -10`: attempted as required by shared instructions, but `rtk` was not installed in this shell.
- `git log -10 --oneline --decorate`: used after `rtk` failed.
- `python hosts_editor.py --version`: `Hosts File Get v2.27.0`.
- `python hosts_editor.py --help`: confirmed broad CLI surface and no GUI startup for help.
- `python hosts_editor.py --source-health --source-health-timeout 8 --source-health-workers 12 --source-health-output .ai\research\2026-05-17\source-health-report.json`: produced source-health evidence.

## Recent Commits

- `d5b3d29` - `refactor: extract constants + fetch modules (phase 6)`
- `7784620` - `refactor: extract adblock + idn_homograph + normalize (phases 3-5)`
- `177bc60` - `refactor: extract parsing + theme modules (phase 2)`
- `a1693c0` - `refactor: begin hostsfileget package - phase 1 extracts compression + atomic_io`
- `f3388f9` - `fix: graceful manifest fallback, list2cmdline relaunch, prune orphan caches`
- `1def557` - `fix: unicode-safe find/replace, thread-safe update_status, scheme-locked redirects`
- `83a1459` - `fix: stream-decompress feeds, atomicize hosts copies, harden marker scrub`
- `0d58cc8` - `feat: add roaming endpoint strategy plans`
- `8c6cb37` - `feat: add mobile dns profile exports`
- `5c96435` - `feat: add offline why blocked summaries`

## Current Architecture

`hosts_editor.py` remains the main application module. AST reconnaissance with `utf-8-sig` was required because the file begins with a BOM. Observed metrics:

- 27,480 lines.
- 1,155,343 bytes.
- 10 top-level classes.
- 991 functions.
- 82 `_cli_*` functions.
- 44 `show_*` functions.

Extracted package modules:

- `hostsfileget/constants.py`
- `hostsfileget/fetch.py`
- `hostsfileget/compression.py`
- `hostsfileget/atomic_io.py`
- `hostsfileget/parsing.py`
- `hostsfileget/theme.py`
- `hostsfileget/adblock.py`
- `hostsfileget/idn_homograph.py`
- `hostsfileget/normalize.py`
- `hostsfileget/__init__.py`

The modularization arc is active and coherent. The next likely layer is source catalog/config/profile logic rather than another unrelated feature surface.

## Source Manifest

`data/blocklist_sources.json` contains:

- `schema_version`, `categories`, and `bundles` keys.
- 177 total sources.
- 10 categories.
- 6 bundles.

Category counts:

- Major / Unified / Aggregated: 23
- Ads / Tracking / Analytics: 34
- Telemetry / Privacy / Spyware: 15
- Malware / Phishing / Scam: 48
- Spam / Abuse / Misc: 16
- Category Filters (Opt-in): 9
- Threat Intelligence / NRD / DGA: 5
- CNAME Cloaking / Tracking: 3
- Encrypted DNS / Bypass: 2
- Vendor / Platform: 22

Bundles:

- `starter-low-breakage`
- `balanced-desktop`
- `aggressive-privacy`
- `threat-intel`
- `family-category`
- `native-platform-telemetry`

## Source Health

Generated evidence: `.ai/research/2026-05-17/source-health-report.json`

Summary:

- 177 total sources.
- 122 healthy.
- 21 warning.
- 34 failed.

Notable failed or warning examples:

- OISD Full and OISD DBL returned gone/error states in this run.
- 1Hosts Pro failed.
- HOSTShield Combined and several HOSTShield platform feeds failed.
- EasyList and EasyPrivacy sources produced warning states tied to sample caps or syntax mismatch.
- hBlock Aggregate exceeded the source-health sample cap.
- Several malware/phishing/vendor feeds are dead, moved, or unavailable.

Interpretation:

Source catalog health is the highest-value next planning target because it affects user trust, import quality, default bundles, and support burden. The repository already has source-health tooling; the missing part is turning current results into lifecycle metadata and remediation UX.

## Tests And Verification Surface

Primary commands:

- `python -m unittest discover -s tests -v`
- `python -m py_compile hosts_editor.py tests\test_hosts_editor_logic.py tests\test_gui_smoke.py tests\test_benchmarks.py tests\test_package_manifests.py benchmarks\large_file_benchmark.py scripts\render_package_manifests.py`

Test files observed:

- `tests/test_hosts_editor_logic.py`
- `tests/test_gui_smoke.py`
- `tests/test_benchmarks.py`
- `tests/test_package_manifests.py`

## Packaging And Release Surface

Observed files:

- `HostsFileGet.spec`
- `requirements-build.txt`
- `requirements-security.txt`
- `requirements-tui.txt`
- `.github/workflows/`
- `packaging/`
- `scripts/render_package_manifests.py`

Security/release research found that release hygiene should stay active because hosts-file editors often run elevated and PyInstaller had a recent local privilege escalation advisory.

## Documentation Surface

Important docs:

- `README.md`
- `ARCHITECTURE.md`
- `CHANGELOG.md`
- `CODEX_CHANGELOG.md`
- `TROUBLESHOOTING.md`
- `docs/*.md`
- `AGENTS.md`
- `CLAUDE.md`
- previous `ROADMAP.md`

The previous roadmap had a large all-completed ledger from F001-F070. The new roadmap keeps that as historical context in the source register and replaces the active plan with a shorter prioritized reset.

## Immediate Gaps

- Source catalog decay needs lifecycle metadata and a health baseline.
- `hosts_editor.py` remains too large even after six modularization phases.
- Version identity should be cleaned up across runtime, README, release docs, and packaging outputs.
- Runtime compatibility with newer Python and PyInstaller should be explicit.
- Config/profile logic is a strong candidate for the next package extraction.
