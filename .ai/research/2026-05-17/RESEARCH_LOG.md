# Research Log - 2026-05-17

## Research Goals

1. Reconcile repo state, repo instructions, shared memory, and prior roadmap state.
2. Identify the most important next roadmap items from current code rather than old assumptions.
3. Refresh external ecosystem evidence across direct hosts editors, DNS blockers, commercial DNS products, standards, dependency/security state, and research/dataset sources.
4. Produce durable artifacts for future sessions.

## Local Reconnaissance Passes

### Pass 1 - Instructions And Memory

Actions:

- Read user-provided AGENTS instructions.
- Read global Claude/Codex shared rules.
- Read shared memory index and stack convention memory.
- Read repo `AGENTS.md` and `CLAUDE.md`.
- Read Codex memory entries for prior HostsFileGet work.

Findings:

- The repo has a strong local-first, Windows-first safety model.
- Previous roadmap work was source-backed and broad.
- The active roadmap had become an all-completed ledger; it needed a reset, not more append-only items.

### Pass 2 - Git And Repo Shape

Actions:

- Checked branch, remote, status, and recent commits.
- Attempted `rtk git log -10`; command unavailable.
- Used direct `git log -10 --oneline --decorate`.
- Listed root files, docs, package modules, tests, and workflows.

Findings:

- Recent commits are modularization and hardening work.
- `hosts_editor.py` remains the dominant module.
- The package extraction direction is active and should continue.

### Pass 3 - Code Surface

Actions:

- Parsed `hosts_editor.py` with `utf-8-sig` AST handling.
- Counted top-level classes/functions and CLI/report naming patterns.
- Listed extracted `hostsfileget` modules.
- Checked runtime version and help output.

Findings:

- The monolith is still large enough that future feature work should be biased toward extraction.
- Source catalog and config/profile logic are strong next extraction targets.

### Pass 4 - Source Manifest And Live Health

Actions:

- Counted source manifest categories, bundles, and source totals.
- Ran the source-health CLI against all sources.
- Saved `.ai/research/2026-05-17/source-health-report.json`.

Findings:

- 177 total sources.
- 122 healthy, 21 warning, 34 failed.
- Source catalog decay is now the most concrete operational risk.

## External Research Passes

### Pass 1 - Direct Hosts Editors

Sources:

- PowerToys Hosts File Editor.
- SwitchHosts.
- HostsFileEditor.
- Gas Mask.
- Helm.

Signals:

- Direct competitors emphasize profile switching, quick edit UX, elevation handling, and simple state visibility.
- HostsFileGet is broader and more safety/source/provenance oriented, but should continue strengthening profile and shortcut consistency.

### Pass 2 - Blocklist Ecosystem

Sources:

- StevenBlack hosts.
- HaGeZi DNS blocklists.
- 1Hosts.
- hBlock.
- AdGuard hostlists/filter sources.

Signals:

- Source URLs and formats are volatile.
- Generated lists often have multiple variants and non-hosts syntaxes.
- Lifecycle metadata and source-health remediation are more important than adding more feeds.

### Pass 3 - DNS Products And Local DNS Servers

Sources:

- Pi-hole.
- AdGuard Home.
- Technitium.
- blocky.
- NextDNS.
- Control D.
- AdGuard DNS.
- DNSFilter.

Signals:

- DNS products compete on profiles, per-device policy, logs, analytics, rewrites, safe search, roaming clients, and APIs.
- HostsFileGet should borrow review/export/handoff ideas without pretending hosts-file edits can enforce DNS-provider semantics.

### Pass 4 - Standards And Platform APIs

Sources:

- Microsoft Defender/hosts hijack and NRPT docs.
- Windows Filtering Platform docs.
- DoH, DoQ, SVCB/HTTPS, and IDNA standards.

Signals:

- Encrypted DNS, WFP, NRPT, and IDNA belong in diagnostics/plans unless the app adds very explicit active writers.
- Current documentation boundaries are correct and should be preserved.

### Pass 5 - Dependency And Security

Sources:

- Python download/release pages.
- PyInstaller PyPI/changelog and advisory.
- pip-audit PyPI.
- prompt_toolkit PyPI.
- Winget manifest docs.

Signals:

- Build tooling needs release-time security checks.
- Runtime compatibility should be documented because Python and PyInstaller support windows can move.

### Pass 6 - Datasets, Models, APIs, And Research

Sources:

- DGA guidance.
- phishing/domain intelligence research.
- DNS filtering evaluation papers.
- CNAME cloaking research.
- VirusTotal, URLhaus, MISP, STIX.

Signals:

- The project should prefer evidence-enrichment handoff artifacts and local evaluation reports over automatic verdicts.
- Dataset/model work is relevant only as optional reviewed diagnostics, not as a core blocking engine.

## Saturation Test

Repeated searches after the main passes kept returning the same opportunity classes:

- Source health and list lifecycle management.
- Profile/config extraction.
- Release trust.
- DNS/provider handoff quality.
- False-positive review.
- Runtime/dependency compatibility.
- CLI contract stability.

No researched competitor or source category produced a higher-priority item than the source catalog health reset plus source-catalog modularization.

## Failed Or Thin Searches

- `rtk git log -10`: failed because `rtk` was not installed.
- Search for a need to turn HostsFileGet into a DNS server: rejected by product fit and existing repo philosophy.
- Search for in-app LLM/autonomous verdict opportunities: deferred because the project already has offline why-blocked summaries and the trust model favors reviewed evidence.

## Final Research Position

The next roadmap should be narrower than the previous F001-F070 feature ledger. The highest-value next work is to stabilize the live source catalog, continue modularization around source/config/profile layers, and tighten release identity/security.

## R004 Runtime Follow-Up

Local runtime evidence recorded during R004:

- `python --version`: Python 3.12.10.
- `sys.version`: `3.12.10 (tags/v3.12.10:0cc8128, Apr  8 2025, 12:21:36) [MSC v.1943 64 bit (AMD64)]`.
- `platform.platform()`: `Windows-11-10.0.26100-SP0`.

CI was expanded to record runtime details for Python 3.12 and Python 3.14 on Windows.
