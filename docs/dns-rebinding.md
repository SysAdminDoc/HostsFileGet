# DNS Rebinding Protection Checks

HostsFileGet includes a static DNS rebinding review for hosts-file mappings. It flags external-looking domains that point at private, local, loopback, link-local, carrier-grade NAT, reserved, multicast, or IPv6 unique-local ranges.

## Why This Exists

DNS rebinding protections commonly block DNS answers that return private or local IPs for public-looking names. That behavior is useful for stopping browser-origin attacks against routers, NAS devices, and internal services, but it can also break legitimate homelab and split-horizon names.

Sources behind this feature:

- NextDNS documents DNS rebinding protection as a security feature that can interfere with configurations that intentionally use private IPs: <https://help.nextdns.io/t/35hmval/what-is-dns-rebinding-protection>
- HaGeZi publishes an AdGuard-format DNS Rebind Protection list and notes that internal hostnames may need allowlisting: <https://github.com/hagezi/dns-blocklists#%EF%B8%8F-dns-rebind-protection---prevents-attackers-from-resolving-domains-to-local-ips>
- HaGeZi raw AdGuard rules enumerate private, link-local, loopback, unspecified, IPv6 ULA, and local hostname patterns: <https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adguard/dns-rebind-protection.txt>
- Technitium DNS Server exposes rebinding protection as a DNS Server app: <https://github.com/TechnitiumSoftware/DnsServer>
- Tailscale documents the same private-IP blocking tradeoff for internal services: <https://tailscale.com/docs/reference/faq/dns-rebinding>

## GUI

Open **Tools > DNS Rebinding Protection Check...**.

The report separates:

- Rebinding candidates: external-looking domains mapped to private or special-use ranges.
- Trusted local mappings: private/special-use mappings under local-looking suffixes.
- Public redirects: external-looking domains mapped to public IPs instead of a blocking sink.
- Standard blocking sinks: `0.0.0.0`, `127.0.0.1`, `::`, and `::1`.

## CLI

```powershell
python hosts_editor.py --dns-rebinding-report .\hosts.txt
python hosts_editor.py --dns-rebinding-report .\hosts.txt --dns-rebinding-output .\dns-rebinding-report.json
python hosts_editor.py --dns-rebinding-report .\hosts.txt --dns-rebinding-trusted-suffix lab.example
```

`--dns-rebinding-trusted-suffix` may be supplied more than once. Built-in trusted suffixes include `.lan`, `.local`, `.home.arpa`, `.internal`, `.intranet`, `.corp`, `.test`, `.localhost`, and single-label hosts names.

## Limits

- This is static analysis of the editor contents or a file passed to the CLI. It does not resolve live DNS and does not install router, firewall, DNS-server, or browser policy.
- Standard hosts blocking sink entries are not treated as rebinding findings because hosts files commonly use them for ad/tracker blocking.
- Private-range findings under public domains should be reviewed before removal; dev labs, overlay networks, split DNS, Plex-style remote access, and homelab reverse proxies may intentionally use these mappings.
- Resolver-side rebinding protection remains the right control for live DNS answers. HostsFileGet only reports static overrides it can actually see.
