# Rule Tiers

HostsFileGet can read several rule dialects, but Windows hosts output remains exact-hostname data. The rule tier report makes that boundary explicit before users convert provider or browser filter rules into a hosts file.

## Tiers

| Tier | Meaning | Hosts support |
| --- | --- | --- |
| `exact` | Bare domains, hosts rows, and exact adblock DNS rules | Native when one line maps one hostname |
| `subdomain-scoped` | Rules such as `||example.com^` that DNS filters commonly apply to the apex and subdomains | Partial; hosts needs one exact line per hostname |
| `wildcard` | Rules such as `*.example.com` or `server-*.example.com` | Not native |
| `regex` | Rules such as `/ads[0-9]+/` | Not native |
| `path` | URL/path request rules | Not native |
| `exception` | Allow/bypass rules such as `@@||example.com^` | Not native; use the whitelist or downstream provider |
| `browser-only` | Cosmetic, scriptlet, or CSS-injection filters | Not native |

## GUI Workflow

Open **Tools > Rule Tier Report...** to inspect the current editor. The report shows:

- total lines
- native hosts entries
- warning candidates
- counts by tier and category
- the first warning findings with the original line

Use this before cleaning or exporting a mixed DNS/browser provider list.

## CLI Workflow

Print a report:

```powershell
python hosts_editor.py --rule-tier-report .\filters.txt
```

Write a JSON report too:

```powershell
python hosts_editor.py --rule-tier-report .\filters.txt --rule-tier-output .\rule-tiers.json
```

`--rule-tier-report` is read-only and returns `0` when it completes, even if warning candidates exist. It returns `2` for file or argument failures.

## Interpretation

- Exact hosts rows and bare domains can be represented directly.
- `||example.com^` is useful DNS-filter syntax, but a hosts file does not automatically cover `www.example.com`, `cdn.example.com`, or other subdomains.
- Wildcards and regex need a DNS provider, local DNS proxy, or another downstream tool that documents that matching tier.
- Browser cosmetic and path rules belong in browser/adblock engines. Use `docs/adblock-lint.md` to quarantine them from hosts-safe lists.

## Sources

- Control D Custom Rules wildcard support: https://docs.controld.com/docs/custom-rules
- AdGuard DNS filtering syntax: https://adguard-dns.io/kb/general/dns-filtering-syntax/
- Windows hosts wildcard limitation: https://stackoverflow.com/questions/138162/wildcards-in-a-windows-hosts-file
- General hosts wildcard limitation: https://stackoverflow.com/questions/61707242/can-i-use-wildcards-for-blocking-websites-in-hosts-files
