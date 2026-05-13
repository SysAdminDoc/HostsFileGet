# WFP IP/CIDR Blocker Companion

HostsFileGet can export a plan-only Windows Firewall/WFP IP/CIDR blocker companion. The export is a JSON review artifact that includes a PowerShell script, parsed targets, rejected tokens, rollback command, and safety warnings.

This is not a live firewall mutator. HostsFileGet does not execute `New-NetFirewallRule`, does not install a service, and does not ship or load a WFP callout driver.

## CLI

```powershell
python hosts_editor.py --wfp-blocker-plan .\resolver-ips.txt .\wfp-blocker-plan.json
python hosts_editor.py --wfp-blocker-plan .\resolver-ips.txt .\wfp-blocker-plan.json --wfp-rule-prefix "HostsFileGet Resolver Block"
```

Input is line-oriented. The parser accepts IPv4, IPv6, and CIDR targets, including tokens embedded in simple whitespace/comma/semicolon separated lines. Unsupported domains, ranges, loopback, multicast, and unspecified addresses are rejected or ignored in the plan.

The JSON includes:

- `targets`: normalized IP/CIDR remote-address targets.
- `rejected`: line-numbered rejected tokens and reasons.
- `commands`: reviewable `powershell.exe` command arrays.
- `powershell_script`: a review script that clears the HostsFileGet rule group and recreates chunked outbound block rules.
- `rollback`: the rule-group removal command.
- `warnings`: local safety boundaries.

## Boundary

Windows Filtering Platform is a platform for filtering applications. Windows Firewall with Advanced Security is implemented using WFP, so the companion export targets Windows Firewall rules instead of a custom WFP driver.

The generated script uses outbound `RemoteAddress` block rules because IP/CIDR blocking is outside hosts-file semantics. Run it only from an elevated PowerShell session after reviewing targets and documenting rollback.

Broad private, link-local, reserved, or non-global ranges can break LAN, VPN, management, or developer workflows. Treat these exports as high-risk operational changes.

## Source Basis

- Microsoft Windows Filtering Platform overview: https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page
- Microsoft `New-NetFirewallRule` NetSecurity documentation: https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule
