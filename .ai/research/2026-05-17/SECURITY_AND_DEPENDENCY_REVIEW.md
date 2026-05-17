# Security And Dependency Review - 2026-05-17

Sources: `D0`, `D1`-`D8`, `S1`-`S5`, and local files in `SOURCE_REGISTER.md`.

## Local Security Posture

Relevant existing strengths:

- Atomic write helpers and backups reduce torn-write and recovery risk.
- CLI paths short-circuit before GUI initialization for automation-friendly operations.
- Fetch layer uses HTTPS-aware redirect protections and cache handling.
- Source import pipeline has size caps and decompression bomb guards.
- Local API is loopback-only and bearer-auth protected according to repo docs/history.
- Plan-only external integrations avoid silent writes to DNS providers, routers, mobile profiles, NRPT, WFP, MDM, or CTI systems.

## Current Dependency Snapshot

Generated evidence: `.ai/research/2026-05-17/pypi_metadata.json`

| Package | Observed Latest | Requires Python | Local Use |
| --- | ---: | --- | --- |
| PyInstaller | 6.20.0 | `<3.15,>=3.8` | Windows EXE packaging |
| pip-audit | 2.10.0 | `>=3.10` | Advisory scanning |
| prompt_toolkit | 3.0.52 | `>=3.8` | Optional TUI dependency |

Python evidence:

- Python download/release pages identify current Python release streams, including Python 3.14.5 evidence captured during research.

## Advisory Notes

PyInstaller:

- GitHub Advisory Database entry `GHSA-p2xp-xx3r-mffc` documents a PyInstaller local privilege escalation advisory.
- Roadmap impact: release builds should keep PyInstaller above vulnerable versions and record the exact build-tool version in release evidence.

pip-audit:

- `requirements-security.txt` exists and the project already treats advisory scanning as part of release trust.
- Roadmap impact: keep the advisory scan in CI/release workflows and document the command in release checklist docs.

prompt_toolkit:

- Optional dependency for the TUI.
- Roadmap impact: runtime compatibility docs should clearly separate core GUI app requirements from optional TUI requirements.

## Windows Platform Risks

Hosts-file editing:

- The app touches a protected system file and commonly requires elevation.
- Windows Defender and similar tools may treat hosts-file modification as suspicious depending on content and context.

NRPT/WFP:

- Microsoft docs confirm NRPT and WFP are powerful platform surfaces.
- Existing plan-only treatment remains appropriate unless a future implementation adds explicit active writers, validation, rollback, and privilege handling.

## Release Hardening Opportunities

Recommended roadmap items:

1. Normalize version identity across runtime, README, release docs, package manifests, and changelog.
2. Add a release checklist that includes PyInstaller version, pip-audit, checksums, SBOM, package manifest rendering, and optional signing.
3. Add a build artifact smoke command that prints `--version` and `--help` without GUI startup.
4. Add CI or script checks for stale release-facing version placeholders.
5. Document Python/PyInstaller compatibility and tested versions.

## Security Non-Goals For Now

Do not add the following without a separate design:

- Silent cloud DNS provider writes.
- Router SSH mutation from the main app.
- Mobile profile installation.
- NRPT/WFP policy mutation.
- Background telemetry.
- Automatic CTI or LLM verdict-driven block decisions.

## Verification Recommendations

For the next release-oriented pass:

- `python -m pip install -r requirements-security.txt`
- `python -m pip_audit`
- `python -m pip install -r requirements-build.txt`
- `pyinstaller --version`
- Build EXE from `HostsFileGet.spec`.
- Run built artifact with `--version` and `--help`.
- Generate and verify checksums.
- Render Winget/Chocolatey manifests from the release URL and SHA-256.
