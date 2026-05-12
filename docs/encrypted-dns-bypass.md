# Encrypted DNS Bypass Packs

HostsFileGet treats encrypted-DNS bypass blocking as a guarded review and handoff workflow. The app can plan hosts-importable resolver hostname feeds, but it cannot enforce network egress policy by itself.

## Boundary

The hosts file only affects lookups that use the OS resolver. It cannot stop:

- DoH clients that already know a resolver IP or bootstrap through another path
- DoT or DoQ traffic on TCP/UDP 853
- VPN, Tor, proxy, or remote proxy DNS
- apps with hardcoded resolver IPs
- router-level DNS policy on other devices

HaGeZi's bypass list documentation also calls out that effective bootstrap control requires redirecting or blocking outbound TCP/UDP 53 except from the approved resolver, and blocking DoT/DoQ on TCP/UDP 853 where policy allows.

## Packs

List the local catalog:

```powershell
python hosts_editor.py --encrypted-dns-bypass-list
```

Write a plan without fetching feeds, changing config, touching firewall rules, or writing the system hosts file:

```powershell
python hosts_editor.py --encrypted-dns-bypass-plan router-firewall-handoff .\dns-bypass-plan.json
```

Available packs:

| Pack | Fit | Purpose |
| --- | --- | --- |
| `doh-hosts-review` | Hosts-reviewable | Known encrypted-DNS hostnames in hosts format. Useful only for clients that still use the OS resolver. |
| `bypass-full-review` | Guarded hosts review | Broad DoH/VPN/TOR/proxy list. Run adblock lint and false-positive triage before any hosts conversion. |
| `router-firewall-handoff` | Router/firewall handoff | Domain, RPZ, and IP feeds for resolver, router, firewall, or DNS-server policy outside the hosts file. |

## GUI

Open **Tools > Encrypted DNS Bypass Packs...** to view the same catalog and warnings from the desktop app.

## Operating Rules

- Keep bypass feeds in their own import section so they can be removed quickly.
- Run **DNS Bypass Diagnostics...** after import to inspect local browser policy and proxy signals.
- Do not treat hosts import as evidence that bypass is prevented.
- Use router/firewall egress controls for IP-literal resolver access.
- Document rollback before enabling RPZ, firewall URL tables, or outbound port blocks.
- Expect privacy tools, developer VPNs, Tor Browser, and enterprise remote-access workflows to be affected by broad bypass-service blocking.

## Source Basis

- HaGeZi DoH/VPN/TOR/Proxy Bypass list family: https://github.com/hagezi/dns-blocklists
- HaGeZi complete bypass feed: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt
- HaGeZi encrypted DNS hosts feed: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/doh.txt
- RFC 8484, DNS over HTTPS: https://datatracker.ietf.org/doc/html/rfc8484
- RFC 9250, DNS over QUIC: https://datatracker.ietf.org/doc/html/rfc9250
- Community bypass/firewall signal: https://www.reddit.com/r/AdGuardHome/comments/1re336u/adguard_home_can_only_filter_what_it_sees_a_lot/
