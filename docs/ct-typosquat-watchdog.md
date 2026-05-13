# Certificate Transparency And Typosquat Watchdog

HostsFileGet includes a plan-only Certificate Transparency (CT) and typosquat watchdog workflow for domains you own, administer, or are explicitly authorized to monitor.

The watchdog does not poll CT logs, register background tasks, call external APIs, store credentials, or write hosts entries. It produces a JSON review plan with CT search URLs, deterministic typosquat candidates, and a CSV review queue.

## Commands

Describe the workflow:

```powershell
python hosts_editor.py --ct-watchdog-list
```

Build a review plan:

```powershell
python hosts_editor.py --ct-watchdog-plan domains.txt ct-watchdog-plan.json
```

Limit candidate volume:

```powershell
python hosts_editor.py --ct-watchdog-plan domains.txt ct-watchdog-plan.json --ct-watchdog-max-variants 40
```

## Input

The input file can contain one domain per line, URLs, or hosts-like rows:

```text
example.com
https://login.example.com/
0.0.0.0 app.example.com
```

Subdomains are collapsed to a registrable-domain heuristic before variant generation. HostsFileGet includes a small list of common multi-part public suffixes, but it does not vendor the full public suffix list; verify suffix boundaries before acting on sensitive domains.

## Output

The JSON plan contains:

- `targets`: protected base domains, observed input domains, CT query patterns, and generated variants.
- `artifacts.crtsh_query_urls`: public `crt.sh` JSON search URLs for baseline subdomain review and typosquat candidates.
- `artifacts.watchlist_domains`: deduplicated base and candidate domains.
- `artifacts.review_csv`: CSV rows for a manual review queue.
- `warnings` and `controls`: authorization, false-positive, and hosts-file boundary guidance.

## Boundaries

CT matches are leads, not verdicts. A certificate can be legitimate vendor activity, customer infrastructure, staging systems, unrelated brands, or benign domain ownership. Review certificate subject/SANs, issuer, registration, DNS, page behavior, and business context before blocking or escalating.

Generated typosquat candidates are also advisory. They cover common omissions, repetitions, transpositions, keyboard-neighbor substitutions, ASCII lookalikes, security-themed affixes, and sibling TLD swaps. They are not a complete phishing-domain detection engine.

Hosts files cannot monitor CT logs continuously and should not auto-block candidates from this plan. Use this output as a review queue for external CT tooling or a managed security process.

## Source Basis

- RFC 9162 defines Certificate Transparency v2 and its log/audit model: https://www.rfc-editor.org/rfc/rfc9162.html
- MDN summarizes CT as a public append-only certificate logging framework: https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Certificate_Transparency
- OWASP WSTG documents CT log review for attack-surface discovery and warns to validate scope: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Attack_Surface_Identification
- dnstwist is the reference open-source inspiration for domain permutation and typosquat review workflows: https://github.com/elceef/dnstwist
