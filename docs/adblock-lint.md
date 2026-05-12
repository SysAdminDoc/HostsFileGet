# Adblock Syntax Lint

HostsFileGet accepts several blocklist dialects, but the Windows hosts file can only represent exact host-to-IP mappings. The adblock syntax lint keeps browser-only filter rules from being accidentally normalized into broad hosts-file blocks.

Use it when reviewing an EasyList-style file, an AdGuard filter export, or any mixed list that may contain cosmetic rules, request-path rules, exceptions, scriptlets, or DNS-compatible host rules.

## What Is DNS-Compatible

The linter treats these as safe for hosts-file normalization:

- Standard hosts rows such as `0.0.0.0 ads.example`.
- Bare domains such as `ads.example`.
- DNS-style adblock host rules such as `||tracker.example^$third-party`.

These shapes can be reduced to exact domains that `Save Cleaned` can represent.

## What Is Quarantined

The linter quarantines rules that a hosts file cannot express safely:

- Cosmetic and element-hiding rules: `example.com##.ad`, `example.com#@#.ad`, `example.com#?#div:-abp-has(...)`.
- Scriptlet or CSS-injection rules: `#%#`, `#@%#`, `#$#`.
- Exception rules such as `@@||allowed.example^$document`; hosts files do not have an allow rule at the same layer.
- Path/request rules such as `||example.com/ads/*`; converting them to `example.com` would over-block the whole host.
- Regex-style rules such as `/ads[0-9]+/`.
- Invalid or empty host patterns that cannot be reduced to a safe domain.

`Save Cleaned` and normalized imports skip quarantined browser-only rules instead of converting them into broad domain blocks.

## GUI Workflow

- **Tools > Adblock Syntax Lint...** shows a local report with counts and the first findings.
- **Targeted Cleanup > Quarantine Browser-Only Adblock Rules...** previews and then comments out quarantined rules in the editor.

The cleanup command preserves the original text as a comment prefixed with:

```text
# HostsFileGet quarantined browser-only rule:
```

## CLI Workflow

Lint a file and print a text report:

```powershell
python hosts_editor.py --adblock-lint .\filters.txt
```

Write a JSON report too:

```powershell
python hosts_editor.py --adblock-lint .\filters.txt --adblock-lint-output .\adblock-lint.json
```

Write a reviewed copy where unsafe rules are commented out:

```powershell
python hosts_editor.py --adblock-quarantine .\filters.txt .\filters.hosts-safe.txt
```

Exit codes:

- `0`: no quarantined findings.
- `1`: lint completed and found quarantined rules.
- `2`: file read/write or argument failure.

## Sources

- AdGuard Home hosts blocklist syntax: https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists
- AdGuard DNS filtering syntax: https://adguard-dns.io/kb/general/dns-filtering-syntax/
- Adblock Plus filter syntax: https://help.adblockplus.org/adblock-plus-help-center/how-to-write-filters
- AdGuard cosmetic and path-in-domain filter syntax: https://adguard.com/kb/general/ad-filtering/create-own-filters/
