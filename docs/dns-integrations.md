# DNS Integrations

HostsFileGet's DNS interoperability pack is file-first. It converts reviewed cleaned hosts data into formats that Pi-hole, AdGuard Home/DNS, Technitium DNS Server, and blocky can ingest, but it does not authenticate to those tools or mutate remote server configuration.

Use this for handoff, source control, or a local web/static-file host that your DNS blocker already trusts.

For plan-only NextDNS and Control D API replay artifacts plus their CSV log importers, see `docs/cloud-dns-adapters.md`.

For guarded router/gateway dnsmasq and Unbound bundle generation, see `docs/router-gateway-adapters.md`.

All generated handoff metadata follows the shared contract in `docs/integration-handoff-contract.md`.

## Presets

| Preset | Output shape | Primary use |
| --- | --- | --- |
| `pihole` | Plain domains | Pi-hole subscribed denylist/adlist inputs |
| `adguard-home` | `||domain^` DNS filter rules | AdGuard Home DNS blocklists or selected custom rules |
| `adguard-dns` | `||domain^` DNS filter rules | AdGuard DNS custom filtering rules |
| `technitium` | Plain domains | Technitium DNS Server block-list URL/path inputs |
| `blocky` | Plain domains | blocky file/URL list sources |

The GUI exposes these from **Export Cleaned** and the file-only pack report from **Tools > DNS Interoperability Pack...**.

The CLI can list presets or convert a hosts-like file without launching the GUI:

```powershell
python hosts_editor.py --integration-list
python hosts_editor.py --integration-export adguard-home .\cleaned-hosts.txt .\adguard-dns-filter.txt
python hosts_editor.py --integration-export blocky .\cleaned-hosts.txt .\blocky-denylist.txt
```

`INPUT` can contain normal hosts rows, bare domains, URLs, adblock-style host rules, or dnsmasq rows supported by the normal parser. Non-blocking local mappings are skipped in DNS integration exports.

Each export still writes the selected DNS-list file to `OUTPUT`, and now also writes `OUTPUT.handoff.json` with schema `hostsfileget.dns-integration-export.v1`, a SHA-256 of the generated file content, warnings, source URL, and `handoff_contract`.

## Import Side

HostsFileGet already imports observed blocked-domain history from:

- Pi-hole `pihole-FTL.db`.
- AdGuard Home `querylog.json` or NDJSON query logs.

Technitium and blocky are intentionally export-only for this pack. Use their server-side console, config, or API to attach the exported file/URL. HostsFileGet does not push remote blocklist settings because credentials, network trust, and rollback semantics belong to each DNS server.

## Limits

- Hosts data is exact-domain data. It cannot express wildcard, regex, client-specific, upstream, CNAME, response rewrite, or schedule policies.
- The handoff JSON `will_not` section makes that boundary machine-readable: HostsFileGet will not authenticate to DNS tools, subscribe or reload downstream lists, translate exact hosts rows into provider-only rule types, or change downstream client/policy behavior.
- `adguard-home` and `adguard-dns` use `||domain^` because AdGuard documents that shape as DNS-filter syntax that matches a hostname and subdomains.
- `pihole`, `technitium`, and `blocky` default to plain domains as the lowest-risk portable shape.
- The exported file represents the cleaned view at export time. Downstream list refresh, reload, dedupe, allowlist priority, and client grouping remain downstream responsibilities.

## Source References

- Pi-hole domain database and `adlist` source table: `https://docs.pi-hole.net/database/domain-database/`
- AdGuard Home hosts blocklist and DNS-filter rule syntax: `https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists`
- AdGuard DNS filtering syntax: `https://adguard-dns.io/kb/general/dns-filtering-syntax/`
- Technitium DNS Server block-list URLs and HTTP API boundary: `https://technitium.com/dns/`
- blocky supported hosts/plain-domain list sources: `https://0xerr0r.github.io/blocky/v0.24/configuration/`
