# IDN And Homograph Report

HostsFileGet can now audit mixed hosts/filter lists for internationalized domain names before a user converts or writes them. The report is advisory only: it does not block, rewrite, or remove entries.

## What It Checks

| Check | Meaning | Action |
| --- | --- | --- |
| `idn` | A Unicode domain can be encoded to an ASCII IDNA A-label | Keep both forms visible during review |
| `punycode` | An `xn--` A-label decodes to a Unicode U-label | Verify the decoded form is expected |
| `homograph-risk` | A label mixes scripts or maps through the small built-in Cyrillic/Greek confusable table to an ASCII-looking domain | Review before trusting, broadening, or sharing the rule |
| `invalid-punycode` | A label starts with `xn--` but cannot be decoded by Python's IDNA codec | Treat as malformed input and inspect upstream source |

The scanner reads hosts rows, bare domains, URL hostnames, dnsmasq-style `address=/domain/` rows, and DNS-compatible adblock tokens such as `||domain^`.

## GUI Workflow

Open **Tools > IDN / Homograph Report...** to inspect the current editor. The dialog shows:

- total IDN/Punycode candidates
- valid IDN domains
- Punycode A-label counts
- warning candidates
- category counts
- first findings with ASCII form, Unicode form, and confusable skeleton when available

## CLI Workflow

Print a report:

```powershell
python hosts_editor.py --idn-report .\filters.txt
```

Write JSON as well:

```powershell
python hosts_editor.py --idn-report .\filters.txt --idn-output .\idn-report.json
```

`--idn-report` is read-only and returns `0` when it completes, even when warning candidates exist. It returns `2` for file or argument failures.

## Limits

- This is not a full Unicode security engine.
- The confusable table is intentionally small and deterministic. It catches common Cyrillic/Greek lookalikes such as `xn--pple-43d.com`, which decodes to a domain visually close to `apple.com`.
- Legitimate IDNs can be entirely safe. The report avoids automatic blocking so internationalized sites are not broken by default.
- Windows hosts files ultimately store exact hostnames; richer IDN policy, typosquatting policy, and NRPT routing belong in DNS-provider or Windows policy layers.

## Sources

- RFC 5890 IDNA A-label/U-label definitions: https://www.rfc-editor.org/rfc/rfc5890
- Unicode UTS #46 IDNA compatibility processing and confusables caveat: https://unicode.org/reports/tr46/
- Microsoft NRPT `NameEncoding` Punycode option: https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule
- NextDNS security feature precedent for IDN homographs: https://nextdns.io/
