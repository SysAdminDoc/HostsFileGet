# CLI Automation Contract

HostsFileGet has a broad CLI surface for scheduled updates, local reports, reviewed handoff plans, and release smoke checks. Automation users should treat this document and `tests/fixtures/cli_contract_snapshot.json` as the stable contract for high-risk command families.

## Compatibility Promise

- `python hosts_editor.py --help` remains available without starting the Tk GUI.
- Pure report, list, preview, and plan commands must route through CLI handling and return an exit status instead of falling through to GUI startup.
- Plan-only handoff commands write local review artifacts only. They do not deploy to routers, DNS providers, NRPT, WFP, MDM/RMM tooling, or remote services.
- Hosts-file mutation commands (`--apply`, `--update`, `--disable`, `--enable`, backup/restore surfaces) keep the existing admin, backup, disabled-hosts-file, and dry-run boundaries documented in the feature docs.
- New automation-facing commands should be added to the snapshot fixture when they are expected to remain scriptable.

## Covered Snapshot Groups

- Hosts-file write safety: `--backup`, `--apply`, `--update`, `--disable`, `--enable`, `--silent`.
- Source operations: `--source-health`, `--source-health-output`, `--source-health-baseline`, `--source-cache-prune`.
- Plan-only platform handoffs: WFP, NRPT, router/gateway, managed package, and sandbox/VM bundle exports.
- Provider and DNS handoffs: DNS interoperability exports, cloud DNS plans, mobile DNS profiles, and DNS rewrite plans.
- Local review reports: why-blocked, DNS rebinding, adblock lint, rule tier, and IDN reports.
- Local automation services: opt-in local REST API, block page server/preview, and activity reports.

## Validation

Run the contract audit from the repository root:

```powershell
python scripts\audit_cli_contract.py
```

The audit captures `--help`, checks required help phrases from the snapshot fixture, and runs representative pure CLI route probes with the GUI entry points patched to fail if they initialize.

For CI/release validation, keep `scripts\audit_cli_contract.py`, `tests/test_cli_contracts.py`, and `tests/fixtures/cli_contract_snapshot.json` updated together.
