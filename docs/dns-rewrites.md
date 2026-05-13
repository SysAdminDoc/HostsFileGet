# Advanced DNS Rewrites

HostsFileGet can turn reviewed rewrite declarations into provider-specific review plans for DNS surfaces that are richer than the Windows hosts file. The feature is export-only.

## Supported Providers

- `controld-private-rules`: Control D custom rules / private-domain redirects.
- `technitium-zone`: Technitium DNS Server zone-record review output.

List providers:

```powershell
python hosts_editor.py --dns-rewrite-provider-list
```

## Input Forms

The parser accepts simple reviewed declarations:

```text
10.0.0.5 intranet.example.test
app.example.test A 10.0.0.5
v6.example.test AAAA fd00::10
alias.example.test CNAME target.example.net
service.example.test -> fd00::20
```

Hosts-style IP lines become `A` or `AAAA` records. Domain targets become `CNAME` records. `CNAME` records and private-domain rewrites are not native to the hosts file and require a DNS provider, resolver, or authoritative zone.

## Plan Commands

Control D review plan:

```powershell
python hosts_editor.py --dns-rewrite-plan control-d .\rewrites.txt .\controld-rewrite-plan.json --dns-rewrite-profile-id PROFILE_ID
```

Technitium zone review plan:

```powershell
python hosts_editor.py --dns-rewrite-plan technitium .\rewrites.txt .\technitium-rewrite-plan.json --dns-rewrite-zone example.test --dns-rewrite-ttl 300
```

## Safety Boundary

- HostsFileGet does not call provider APIs, store API keys, import zone data, reload DNS services, or mutate DNS records.
- The JSON plan is a review artifact. Convert it to live provider actions outside HostsFileGet only after validating current provider docs and rollback steps.
- Hosts files can only map names to A/AAAA-like address answers. CNAMEs, private domains, conditional forwarding, and richer rewrites belong in DNS provider/resolver exports.
- CNAME records cannot safely coexist with other record data at the same owner name in standard DNS zones.
- Private-domain rewrites can shadow public DNS when clients use the selected resolver.

## Source Basis

[Control D custom rules](https://docs.controld.com/docs/custom-rules) document provider-side block, bypass, redirect, and private-domain behavior that exceeds hosts-file semantics. [Technitium DNS Server](https://technitium.com/dns/help.html) provides DNS-server zone and record-management surfaces where CNAME and private record plans belong.
