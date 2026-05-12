# CNAME Cloaking Workflow

HostsFileGet treats CNAME cloaking as a guarded import and DNS handoff workflow, not as a capability the Windows hosts file can fully enforce.

## Boundary

CNAME cloaking maps a first-party-looking hostname to a third-party tracker in DNS answers. A browser may query a hostname such as `metrics.example.com`, receive a CNAME chain to a tracker-operated target, and still treat the request as part of the visited site.

The Windows hosts file only answers the exact hostname being queried. It cannot inspect DNS response chains, wildcard-match CNAME targets, or apply rules to future aliases that are not already listed as exact hostnames.

## Packs

List the local catalog:

```powershell
python hosts_editor.py --cname-cloaking-list
```

Write a review plan without fetching feeds, changing config, or writing the system hosts file:

```powershell
python hosts_editor.py --cname-cloaking-plan cname-aware-dns .\cname-plan.json
```

Available packs:

| Pack | Fit | Purpose |
| --- | --- | --- |
| `hosts-disguised-review` | Hosts-reviewable | AdGuard just-domain lists of known disguised tracker, ad, and mail-tracker hostnames. Import separately and triage breakage before scheduled use. |
| `cname-aware-dns` | DNS handoff | NextDNS and AdGuard original tracker-target lists. Do not import these directly into the hosts file; use a resolver or provider that inspects CNAME chains. |
| `rpz-dns` | DNS handoff | RPZ-format disguised tracker data for DNS servers that support Response Policy Zones. |

## GUI

Open **Tools > CNAME Cloaking Workflow...** to view the same catalog and warnings from the desktop app.

## Source Handling Rules

- Keep disguised-domain feeds in their own import sections so they can be removed as a unit.
- Do not mix mail-tracker CNAME lists with broad ad/tracking imports until false-positive triage has been run.
- Keep original tracker-target lists out of direct hosts imports because they require CNAME-aware matching.
- Use DNS integration exports or external resolver configuration for RPZ and CNAME-target workflows.
- Treat query logs and CNAME chains as browsing metadata; keep review local unless the user explicitly exports it.

## Source Basis

- NextDNS CNAME Cloaking Blocklist: https://github.com/nextdns/cname-cloaking-blocklist
- AdGuard CNAME Trackers: https://github.com/AdguardTeam/cname-trackers
- AdGuard Home FAQ on CNAME/IP query-log behavior: https://adguard-dns.io/kb/ko/adguard-home/faq/
- CNAME cloaking and cookie exfiltration research: https://dev.ndss-symposium.org/ndss-paper/auto-draft-146/
- Large-scale DNS-based tracking evasion research: https://petsymposium.org/2021/files/papers/issue3/popets-2021-0053.pdf
