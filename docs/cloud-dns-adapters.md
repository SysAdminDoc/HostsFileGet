# Cloud DNS Adapters

HostsFileGet supports guarded, local-only adapter workflows for NextDNS and Control D. These adapters are intentionally plan-first:

- HostsFileGet does not ask for, store, or transmit API keys.
- Export commands write a JSON replay plan with placeholder auth headers.
- Import commands read local CSV exports and write local domain lists.
- The GUI exposes the adapter catalog and CSV log importers, not live provider mutation.

Generated plans include the shared `hostsfileget.handoff-contract.v1` block described in `docs/integration-handoff-contract.md`.

## Supported Adapters

| Adapter | Provider | Operation | Output |
| --- | --- | --- | --- |
| `nextdns-denylist` | NextDNS | Add cleaned domains to a profile denylist | One planned `POST` per domain |
| `nextdns-allowlist` | NextDNS | Add cleaned domains to a profile allowlist | One planned `POST` per domain |
| `controld-block-rules` | Control D | Add cleaned domains as blocking custom rules | One planned bulk `POST` with `hostnames[]` |

Aliases:

- `nextdns`, `nextdns-block`, `nextdns-deny`, `nextdns-deny-list` -> `nextdns-denylist`
- `nextdns-allow` -> `nextdns-allowlist`
- `control-d`, `controld`, `controld-block`, `control-d-block` -> `controld-block-rules`

## CLI Workflow

List supported adapters:

```powershell
python hosts_editor.py --cloud-adapter-list
```

Generate a NextDNS denylist replay plan:

```powershell
python hosts_editor.py --cloud-adapter-plan nextdns .\cleaned-hosts.txt .\nextdns-plan.json --cloud-profile-id abc123
```

Generate a Control D custom-rule replay plan:

```powershell
python hosts_editor.py --cloud-adapter-plan controld .\cleaned-hosts.txt .\controld-plan.json --cloud-profile-id profile_id
```

Extract blocked domains from a provider CSV log export:

```powershell
python hosts_editor.py --cloud-log-import nextdns .\nextdns-log.csv .\blocked-domains.txt
python hosts_editor.py --cloud-log-import controld .\activity-log.csv .\blocked-domains.txt
```

The plan JSON uses schema `hostsfileget.cloud-dns-adapter-plan.v1` and includes the selected adapter, provider operation, warning text, source URL, deduplicated domains, `plan_only: true`, `execution: not-run`, `handoff_contract`, and request skeletons with placeholder auth headers such as `<NEXTDNS_API_KEY>` and `<CONTROL_D_API_TOKEN>`.

## GUI Workflow

- **Tools > Cloud DNS Adapters...** shows the supported adapter catalog and safety warnings.
- The sidebar **Import From Local File** area and **Tools > Import DNS Queries From Logs** menu can import NextDNS rows with `domain` and `status`, keeping only `blocked`.
- The same GUI surfaces can import Control D rows with either `question`/`action` or `query`/`controld_action`, keeping only blocked actions.

Imported log data can reveal browsing history. HostsFileGet reads selected files locally and does not upload them.

## Provider Notes

NextDNS:

- API endpoint root is `https://api.nextdns.io/...`.
- Auth uses the `X-Api-Key` header.
- Profile child array endpoints such as `.../denylist` and `.../allowlist` accept `POST`.
- Logs can be downloaded through `GET https://api.nextdns.io/profiles/:profile/logs/download`.

Control D:

- Custom Rules are per-profile domain rules, and Control D documents them as a hosts-file-like cloud feature with wildcard support.
- The Custom Rules create endpoint is `POST https://api.controld.com/profiles/{profile_id}/rules`.
- Blocking rules use form field `do=0`; `hostnames[]` carries one or more hostnames.
- Activity logs can be exported from the dashboard or, for organizations, through an authenticated CSV activity-log endpoint.
- Log field references define `query`/`question` for the domain and `controld_action=0` for blocked queries.

## Limits

- These adapters do not convert hosts semantics into provider-only wildcard or regex syntax. F032/F033 cover DNS-compatible rule linting and richer rule tiers.
- The `handoff_contract.will_not` section states that HostsFileGet will not store API keys, call provider APIs, convert exact hosts rows into provider-only semantics, or assign profiles/endpoints/devices.
- Replay plans are review artifacts. A separate script or operator must decide whether and how to execute them.
- Provider quotas, profile limits, and API behavior can change. Re-check the linked provider docs before replaying a generated plan.

## Sources

- NextDNS API documentation: https://nextdns.github.io/api/
- Control D Custom Rules: https://docs.controld.com/docs/custom-rules
- Control D Custom Rules create endpoint: https://docs.controld.com/reference/post_profiles-profile-id-rules
- Control D CSV Export How-To: https://docs.controld.com/docs/how-to-export-logs-to-csv
- Control D Log Field Reference: https://docs.controld.com/docs/log-field-reference
