# NRD/DGA Threat Feed Packs

HostsFileGet exposes NRD, DGA, and threat-intelligence feeds as guarded planning metadata. The pack workflow is intentionally local: it lists feed URLs, review controls, and freshness expectations, but does not fetch, schedule, or apply feeds by itself.

## CLI

List the available packs and their source URLs:

```powershell
python hosts_editor.py --threat-feed-list
```

Write a JSON plan for a pack:

```powershell
python hosts_editor.py --threat-feed-plan nrd-review .\nrd-plan.json
python hosts_editor.py --threat-feed-plan dga-watch .\dga-plan.json
```

The JSON schema is `hostsfileget.threat-feed-pack-plan.v1`. It includes:

- pack id, risk, review level, and default action
- feed URLs, source families, expected format, stale-after threshold, and source IDs
- false-positive controls and static warnings
- roadmap source IDs used for traceability

## GUI

Use **Tools > NRD / DGA Threat Feed Packs...** to open the same catalog in the desktop app.

Curated threat-feed URLs are also available in the source catalog under **Threat Intelligence / NRD / DGA**. Import high-risk feeds separately so they remain removable through source-section deletion and entry provenance.

## Packs

| Pack | Purpose | Risk | Default action |
| --- | --- | --- | --- |
| `security-starter` | HaGeZi TIF Mini starter feed | Medium | Import after source-health review |
| `dga-watch` | DGA 7-day and 14-day feeds | Medium | Import separately and review |
| `nrd-review` | NRD 7-day and 14-day feeds | High | Manual review only |
| `threat-full-review` | Broad TIF, DGA, and NRD review pack | High | Stage in Raw mode first |

## Review Controls

- Run `--source-health` before using feed URLs in recurring workflows.
- Treat NRD feeds as short-lived; stale data loses security value and can keep blocking legitimate new domains after the threat signal decays.
- Run false-positive triage before saving cleaned output when a pack contains NRD feeds.
- Keep each threat feed as a separate import section so one noisy source can be removed without dropping the whole security policy.
- Run adblock lint before converting adblock-formatted threat feeds into hosts rows.

## Source Basis

- HaGeZi DNS blocklists publish TIF, DGA, and NRD feed families in multiple formats.
- FIRST DNS Abuse SIG guidance frames DGA detection as difficult without CTI DNS blocklists, RPZ feeds, or protective DNS.
- NRD research in the roadmap appendix supports treating newly registered domains as high-signal but high-false-positive inputs rather than unconditional hosts-file blocks.
