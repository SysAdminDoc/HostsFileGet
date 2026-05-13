# NRPT Policy Export

HostsFileGet can export a plan-only Windows DNS Client Name Resolution Policy Table (NRPT) artifact. The export is a JSON review file with normalized namespaces, resolver IPs, rejected tokens, rollback commands, and a reviewable PowerShell script.

This is not a live DNS policy mutator. HostsFileGet does not run `Add-DnsClientNrptRule`, does not edit local NRPT policy, and does not change a Group Policy object.

## CLI

```powershell
python hosts_editor.py --nrpt-plan .\namespaces.txt .\nrpt-plan.json --nrpt-name-server 10.0.0.53
python hosts_editor.py --nrpt-plan .\namespaces.txt .\nrpt-plan.json --nrpt-name-server 10.0.0.53 --nrpt-name-server 10.0.0.54 --nrpt-rule-prefix "HostsFileGet NRPT"
```

Optional GPO-scoped output:

```powershell
python hosts_editor.py --nrpt-plan .\namespaces.txt .\nrpt-plan.json --nrpt-name-server 10.0.0.53 --nrpt-gpo-name "Corp NRPT Policy" --nrpt-server dc01
```

Input is line-oriented. The parser accepts DNS namespaces and URL-like tokens with extractable hostnames. It lowercases and IDNA/Punycode-encodes namespaces because the generated commands use `-NameEncoding 'Punycode'`.

Rejected input includes:

- wildcard namespaces such as `*.example.com`; enter `example.com` instead.
- IP and CIDR targets; use the WFP/firewall companion plan for those.
- control characters and malformed IDN labels.
- the broad NRPT `Any` namespace.

The JSON includes:

- `namespaces`: normalized DNS namespaces.
- `name_servers`: validated resolver IP addresses.
- `rejected`: line-numbered rejected tokens and reasons.
- `commands`: reviewable `powershell.exe` command arrays.
- `powershell_script`: a review script that clears prior HostsFileGet-prefixed NRPT rules and recreates chunked rules.
- `rollback`: the clear command plus change-management guidance.
- `warnings`: local safety boundaries.

## Boundary

NRPT can redirect DNS resolution for selected namespaces. That is broader than a hosts-file edit and can affect VPN, DirectAccess, enterprise DNS, split-horizon DNS, and roaming-client behavior.

HostsFileGet therefore exports an explicit plan only. Run generated scripts only after review from an elevated PowerShell session or through a managed policy workflow. For GPO output, test in a lab OU before broad deployment.

Resolver IPs are accepted when they are valid IPv4 or IPv6 addresses. Private, loopback, link-local, reserved, and other non-global resolvers are allowed because enterprise DNS commonly uses them, but the plan calls them out as operational risk.

## Source Basis

- Microsoft `Add-DnsClientNrptRule` DnsClient documentation: https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule
- Microsoft `Remove-DnsClientNrptRule` DnsClient documentation: https://learn.microsoft.com/en-us/powershell/module/dnsclient/remove-dnsclientnrptrule
- Microsoft `Get-DnsClientNrptRule` DnsClient documentation: https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientnrptrule
