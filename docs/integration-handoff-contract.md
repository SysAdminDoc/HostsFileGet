# Integration Handoff Contract

HostsFileGet integration outputs are review artifacts. They can help an operator move reviewed hosts data into DNS, mobile, router, NRPT, or managed deployment tooling, but they do not perform external writes.

## Schema

Integration plans that cross the Windows hosts-file boundary include:

- `handoff_contract.schema`: `hostsfileget.handoff-contract.v1`.
- `handoff_contract.surface`: one of `dns-integration`, `cloud-dns`, `nrpt`, `router-gateway`, `mobile-dns`, or `managed-package`.
- `handoff_contract.target`: the selected preset, adapter, scope, or deployment target.
- `handoff_contract.plan_schema`: the schema of the parent generated plan.
- `handoff_contract.plan_only`: always `true`.
- `handoff_contract.writes_performed`: `local-artifacts-only`.
- `handoff_contract.will_not`: explicit boundary statements for what HostsFileGet will not do.
- `handoff_contract.warnings`: safety warnings carried from the parent plan.
- `handoff_contract.source_urls` and `handoff_contract.references`: available source and roadmap references.

## Covered Surfaces

| Surface | Parent plan schema | Main commands |
| --- | --- | --- |
| DNS integrations | `hostsfileget.dns-integration-export.v1` | `--integration-export` |
| Cloud DNS adapters | `hostsfileget.cloud-dns-adapter-plan.v1` | `--cloud-adapter-plan` |
| NRPT policy export | `hostsfileget.nrpt-policy-plan.v1` | `--nrpt-plan` |
| Router/gateway adapters | `hostsfileget.router-gateway-plan.v1` | `--router-push-plan` |
| Mobile DNS profiles | `hostsfileget.mobile-dns-profile-export.v1` | `--mobile-dns-profile-export` |
| Managed deployment packages | `hostsfileget.managed-package-plan.v1` | `--managed-package-export` |

## Boundary

The contract is intentionally repetitive. Each generated plan and human-readable report states that HostsFileGet writes local files only, and each plan carries machine-readable `will_not` items so downstream automation can display or enforce the same boundary before an operator executes anything outside HostsFileGet.

