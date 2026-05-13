# CTI Enrichment Plans

HostsFileGet can prepare local enrichment plans for domains, URLs, and public IP addresses found in hosts-like text. The workflow is intentionally plan-only: it writes request templates for VirusTotal, URLhaus, and MISP, plus a local STIX 2.1 observable bundle, but it does not execute network requests or store API keys.

## CLI

List the supported enrichment providers:

```powershell
python hosts_editor.py --cti-enrichment-list
```

Write a JSON enrichment plan:

```powershell
python hosts_editor.py --cti-enrichment-plan .\iocs.txt .\cti-enrichment-plan.json
```

Limit providers or set the MISP base URL placeholder:

```powershell
python hosts_editor.py --cti-enrichment-plan .\iocs.txt .\cti-enrichment-plan.json --cti-enrichment-provider vt --cti-enrichment-provider stix
python hosts_editor.py --cti-enrichment-plan .\iocs.txt .\cti-enrichment-plan.json --cti-enrichment-provider misp --cti-enrichment-misp-url https://misp.local
```

The JSON schema is `hostsfileget.cti-enrichment-plan.v1`. It includes:

- normalized domain, URL, and public-IP IoCs extracted from hosts-like text
- provider metadata, supported IoC types, auth expectations, quota notes, and privacy notes
- external request templates with placeholder headers such as `${VT_API_KEY}` and `${MISP_API_KEY}`
- a local STIX 2.1 bundle containing `domain-name`, `url`, `ipv4-addr`, and `ipv6-addr` observable objects when `stix-bundle` is selected
- a CSV review queue that separates external requests from local STIX handoff rows
- warnings and roadmap source IDs for traceability

## GUI

Use **Tools > CTI Enrichment Plans...** to open the same provider catalog in the desktop app.

## Boundaries

- HostsFileGet does not call VirusTotal, URLhaus, MISP, TAXII, or any other CTI service.
- HostsFileGet does not prompt for, store, encrypt, validate, or redact provider API keys.
- Generated request templates are not verdicts. Use enrichment results as triage inputs before changing hosts policy.
- Full URLs can reveal paths, campaigns, internal hostnames, or incident details. Review scope before submitting them to any third-party provider.
- Public IPs are included only when they are globally routable. Loopback, private, link-local, multicast, unspecified, and reserved addresses are ignored.

## Providers

| Provider ID | Surface | IoCs | Notes |
| --- | --- | --- | --- |
| `virustotal-domain` | VirusTotal API v3 domain report | Domains | Requires an API key and external quota handling. |
| `urlhaus-host` | URLhaus host lookup | Domains, IPv4 | Uses the host endpoint and can return URL counts, blacklist status, and observed malware URLs. |
| `urlhaus-url` | URLhaus URL lookup | URLs | Uses the URL endpoint and can expose URL status, tags, payloads, and related VirusTotal links. |
| `misp-attribute-restsearch` | MISP attribute `restSearch` | Domains, URLs, public IPs | Uses the configured MISP base URL and external API-key handling. |
| `stix-bundle` | Local STIX 2.1 observable bundle | Domains, URLs, public IPs | Local artifact only until the operator imports or shares it. |

## Review Flow

1. Generate the enrichment plan from the candidate hosts, feed, or incident text.
2. Review the extracted IoCs and remove anything outside scope.
3. Execute selected request templates in an external client that handles API keys, rate limits, and logging.
4. Import the STIX bundle or request results into the appropriate CTI platform with local TLP, confidence, and sharing markings.
5. Convert enrichment findings into hosts-file changes only after false-positive triage, source isolation, and rollback planning.

## Source Basis

- VirusTotal API v3 documents domain reports at `/api/v3/domains/{domain}` with the `x-apikey` header.
- VirusTotal domain objects expose reputation, categories, analysis results, votes, tags, WHOIS metadata, and relationships such as resolutions and subdomains.
- URLhaus documents POST-based host and URL lookup endpoints with blacklist, malware URL, payload, and VirusTotal-link context.
- MISP exposes API and PyMISP restSearch workflows for attribute searches across values and types.
- STIX 2.1 defines bundle, cyber-observable, domain-name, URL, IPv4, and IPv6 object shapes used by the local handoff artifact.
