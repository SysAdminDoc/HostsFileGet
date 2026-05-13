# Roaming Endpoint Strategy

`--roaming-endpoint-strategy-plan` writes a local decision record for devices that leave the Windows hosts-file boundary. It does not install endpoint agents, deploy MDM/RMM payloads, enroll devices, call provider APIs, or change DNS settings.

## Commands

```powershell
python hosts_editor.py --roaming-endpoint-strategy-list
python hosts_editor.py --roaming-endpoint-strategy-plan all .\roaming-endpoint-strategy.json
python hosts_editor.py --roaming-endpoint-strategy-plan native .\native-dns-strategy.json
python hosts_editor.py --roaming-endpoint-strategy-plan agent .\managed-agent-strategy.json
```

## Strategy IDs

- `os-encrypted-dns-profile`: native Android Private DNS, Apple DNS Settings profiles, macOS profiles, or Windows DoH where the OS owns enforcement.
- `provider-endpoint-profile`: provider dashboard profiles/endpoints such as NextDNS profiles, Control D Endpoints, or AdGuard DNS device IDs.
- `managed-roaming-client`: commercial roaming clients or DNS agents deployed by IT through RMM/MDM.
- `network-gateway-fallback`: router, gateway, or local resolver coverage for fixed networks only.
- `app-vpn-dns-client`: provider apps or local VPN DNS clients for devices that need app-owned setup or protocols.

## Outputs

The JSON plan includes:

- supported strategies and ownership boundaries
- recommended rollout sequence
- prerequisites and handoff artifacts
- failure modes such as VPN conflicts, browser Secure DNS override, iCloud Private Relay, captive portals, split DNS, and local-domain resolution
- source IDs tied back to `ROADMAP.md`

## Scope Boundary

HostsFileGet remains a local hosts-file editor and review artifact generator. Use `docs/mobile-dns-profile-export.md` for native mobile DNS profile handoffs, `docs/router-gateway-adapters.md` for fixed-network gateway plans, and `docs/cloud-dns-adapters.md` for provider allow/deny replay planning. Runtime roaming enforcement belongs to the OS, DNS provider, gateway, or managed endpoint tooling.
