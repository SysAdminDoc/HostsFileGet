# Source Register - 2026-05-17

This file indexes every local and external source used for the 2026-05-17 roadmap reset. Generated snapshots in this folder preserve volatile metadata.

## Local Repository Sources

| ID | Source | Use |
| --- | --- | --- |
| L1 | `hosts_editor.py` | Main app architecture, version behavior, CLI surface, AST metrics, remaining monolith scope |
| L2 | `CLAUDE.md` | Repo working notes, version history, architecture, build/test commands, gotchas |
| L3 | `README.md` | User-facing feature surface, badge/version wording, command docs |
| L4 | `ARCHITECTURE.md`, `CHANGELOG.md`, `CODEX_CHANGELOG.md` | Historical implementation evidence and architecture history |
| L5 | `data/blocklist_sources.json` | Curated source manifest, category counts, bundle names |
| L6 | `.ai/research/2026-05-17/source-health-report.json` | Live 2026-05-17 source-health evidence |
| L7 | `python hosts_editor.py --version`, `python hosts_editor.py --help` | Runtime app identity and CLI behavior |
| L8 | `hostsfileget/*.py`, `tests/*.py`, `benchmarks/*.py`, `scripts/render_package_manifests.py` | Extracted package modules, tests, benchmark and packaging helpers |
| L9 | Previous `ROADMAP.md` at pre-reset HEAD | Completed F001-F070 ledger and historical source appendix |
| L10 | `AGENTS.md` | Repo agent instruction pointer to `CLAUDE.md` |
| L11 | `C:\Users\--\.claude\CLAUDE.md`, `C:\Users\--\CLAUDE.md` | Shared global behavior and working protocol |
| L12 | `C:\Users\--\.claude\projects\c--Users----repos\memory\*.md` | Shared memory and stack conventions |
| L13 | `C:\Users\--\.codex\memories\MEMORY.md` and HostsFileGet rollout summary | Prior Codex memory for source-backed roadmap planning |

## Generated External Metadata

| ID | Source | Use |
| --- | --- | --- |
| G0 | `.ai/research/2026-05-17/external_repo_metadata.json` | GitHub API snapshot for competitor repos, retrieved 2026-05-17 |
| D0 | `.ai/research/2026-05-17/pypi_metadata.json` | PyPI JSON snapshot for PyInstaller, pip-audit, prompt_toolkit, retrieved 2026-05-17 |

## Direct Hosts Editors And Managers

| ID | URL | Use |
| --- | --- | --- |
| G1 | https://learn.microsoft.com/en-us/windows/powertoys/hosts-file-editor | PowerToys Hosts File Editor feature baseline |
| G2 | https://github.com/microsoft/PowerToys | Active Windows utility suite and Hosts editor context |
| G3 | https://github.com/oldj/SwitchHosts | Profile/switching competitor |
| G4 | https://github.com/scottlerch/HostsFileEditor | Windows hosts editor competitor |
| G5 | https://github.com/2ndalpha/gasmask | macOS hosts manager competitor |
| G6 | https://github.com/leibnizli/Helm | macOS hosts manager comparison point |

## Blocklist And Source Ecosystem

| ID | URL | Use |
| --- | --- | --- |
| M1 | https://github.com/StevenBlack/hosts | Major hosts aggregator and source strategy baseline |
| M2 | https://github.com/hagezi/dns-blocklists | Active DNS blocklist ecosystem and list variants |
| M3 | https://github.com/badmojr/1Hosts | Blocklist variants and source-health comparison |
| M4 | https://github.com/hectorm/hblock | Hosts aggregation and generated list baseline |
| M5 | https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt | AdGuard DNS filter source reference |

## DNS Products And Adjacent Projects

| ID | URL | Use |
| --- | --- | --- |
| P1 | https://github.com/pi-hole/pi-hole | Self-hosted DNS blocker baseline |
| P2 | https://docs.pi-hole.net/api/ | Pi-hole API/integration boundary |
| P3 | https://github.com/AdguardTeam/AdGuardHome | Self-hosted DNS blocker baseline |
| P4 | https://github.com/AdguardTeam/AdGuardHome/wiki | AdGuard Home admin and integration docs |
| P5 | https://github.com/0xERR0R/blocky | DNS proxy/blocker comparison |
| P6 | https://0xerr0r.github.io/blocky/latest/ | blocky docs and config model |
| P7 | https://github.com/TechnitiumSoftware/DnsServer | DNS server comparison |
| P8 | https://technitium.com/dns/help.html | Technitium DNS server docs |

## Commercial DNS And Provider Docs

| ID | URL | Use |
| --- | --- | --- |
| C1 | https://nextdns.io/ | Profile, analytics, denylist/allowlist, security feature baseline |
| C2 | https://nextdns.github.io/api/ | NextDNS API model and auth boundary |
| C3 | https://docs.controld.com/docs/profiles | Control D profile model |
| C4 | https://docs.controld.com/docs/custom-rules | Control D custom rule model |
| C5 | https://docs.controld.com/docs/analytics | Control D analytics/logging model |
| C6 | https://docs.controld.com/reference/post_profiles-profile-id-rules | Control D custom-rule API endpoint |
| C7 | https://adguard-dns.io/en/welcome.html | AdGuard DNS product baseline |
| C8 | https://adguard-dns.io/kb/general/dns-filtering-syntax/ | DNS filtering syntax and hosts-compatible subset |
| C9 | https://www.dnsfilter.com/ | Business DNS filtering and roaming-client comparison |
| C10 | https://www.dnsfilter.com/blog/everything-you-need-to-know-about-roaming-clients | Roaming-client ownership and deployment context |

## Microsoft, Windows, And Standards

| ID | URL | Use |
| --- | --- | --- |
| S1 | https://learn.microsoft.com/en-us/defender-endpoint/restore-detected-file-microsoft-defender-antivirus | Defender remediation context |
| S2 | https://learn.microsoft.com/en-us/answers/questions/3758720/settingsmodifier-win32-hostsfilehijack | Hosts-file hijack/tamper warning context |
| S3 | https://learn.microsoft.com/en-us/windows-server/networking/dns/name-resolution-policy-table | NRPT platform context |
| S4 | https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule | NRPT creation command boundary |
| S5 | https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page | WFP capability/risk boundary |
| S6 | https://datatracker.ietf.org/doc/html/rfc8484 | DNS over HTTPS standard |
| S7 | https://datatracker.ietf.org/doc/html/rfc9250 | DNS over QUIC standard |
| S8 | https://datatracker.ietf.org/doc/html/rfc9460 | SVCB/HTTPS record standard |
| S9 | https://datatracker.ietf.org/doc/html/rfc9461 | DNS server SVCB mapping standard |
| S10 | https://www.rfc-editor.org/rfc/rfc5890 | IDNA A-label/U-label terminology |
| S11 | https://unicode.org/reports/tr46/ | Unicode IDNA compatibility processing |

## Dependency And Security Sources

| ID | URL | Use |
| --- | --- | --- |
| D1 | https://www.python.org/downloads/ | Current Python download channel |
| D2 | https://www.python.org/downloads/release/python-3145/ | Python 3.14.5 release evidence |
| D3 | https://pypi.org/project/pyinstaller/ | PyInstaller package metadata |
| D4 | https://pyinstaller.org/en/stable/CHANGES.html | PyInstaller release/change context |
| D5 | https://github.com/advisories/GHSA-p2xp-xx3r-mffc | PyInstaller local privilege escalation advisory |
| D6 | https://pypi.org/project/pip-audit/ | pip-audit package metadata |
| D7 | https://pypi.org/project/prompt-toolkit/ | prompt_toolkit package metadata |
| D8 | https://learn.microsoft.com/en-us/windows/package-manager/package/manifest | Winget package manifest reference |

## Research And Dataset Sources

| ID | URL | Use |
| --- | --- | --- |
| X1 | https://www.first.org/global/sigs/dns/stakeholder-advice/detection/dga | DGA and protective DNS context |
| X2 | https://netbeacon.org/recent-spike-in-malicious-phishing-concentrated-in-two-registrars/ | Phishing/domain intelligence trend context |
| X3 | https://www.mdpi.com/2079-9292/11/8/1276 | DNS filtering evaluation and blocklist accuracy concern |
| X4 | https://ndss-symposium.org/ndss-paper/hidden-in-plain-site-detecting-cname-cloaking-based-tracking-on-the-web/ | CNAME cloaking tracking context |
| X5 | https://urlhaus-api.abuse.ch/ | URLhaus enrichment API context |
| X6 | https://docs.virustotal.com/reference/domain-info | VirusTotal domain enrichment API context |
| X7 | https://www.misp-project.org/openapi/ | MISP API context |
| X8 | https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html | STIX 2.1 handoff artifact model |

## Search Queries Used

- `HostsFileGet GitHub`
- `Windows hosts file editor open source PowerToys SwitchHosts HostsFileEditor`
- `hosts file manager Windows GitHub SwitchHosts Gas Mask HostsMan`
- `Pi-hole AdGuard Home Technitium blocky DNS blocker features API docs`
- `NextDNS API profiles denylist allowlist analytics logs`
- `Control D custom rules profiles analytics API`
- `AdGuard DNS filtering syntax hosts cosmetic rules`
- `Windows hosts file Defender hostsfilehijack NRPT docs`
- `IETF DNS over HTTPS RFC 8484 DNS over QUIC RFC 9250`
- `PyInstaller latest PyPI changelog advisory 2026`
- `pip-audit PyPI latest`
- `prompt_toolkit PyPI latest`
- `domain blocklist evaluation false positives study`
- `CNAME cloaking tracking detection paper`
- `DGA detection protective DNS blocklist guidance`
