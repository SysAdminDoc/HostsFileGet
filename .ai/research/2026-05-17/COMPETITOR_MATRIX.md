# Competitor Matrix - 2026-05-17

Metadata source: `.ai/research/2026-05-17/external_repo_metadata.json` plus URLs in `SOURCE_REGISTER.md`.

## Direct Hosts Editors

| Project | Evidence | Positioning | Activity Snapshot | Lessons For HostsFileGet |
| --- | --- | --- | --- | --- |
| Microsoft PowerToys Hosts File Editor | `G1`, `G2`, `G0` | Windows utility for simple hosts editing inside a larger trusted suite | PowerToys repo: 133,221 stars, pushed 2026-05-17 | Keep Windows-native trust, simple editing, admin awareness, and release polish high. HostsFileGet can differentiate with source intelligence and provenance. |
| SwitchHosts | `G3`, `G0` | Cross-platform hosts profile switching | 26,626 stars, pushed 2026-05-17 | Profile UX is a primary mental model. HostsFileGet should keep improving profile switching and profile docs. |
| HostsFileEditor | `G4`, `G0` | Windows hosts editor focused on easier edit/manage workflows | 1,241 stars, pushed 2025-10-11 | Users value focused edit enable/disable behavior. HostsFileGet should keep power features discoverable without burying basics. |
| Gas Mask | `G5`, `G0` | macOS hosts manager with quick switching | 3,841 stars, pushed 2026-03-01 | Profile switching remains a durable competitor pattern. |
| Helm | `G6`, `G0` | Smaller macOS hosts manager | 14 stars, pushed 2024-09-25 | Less direct impact; reinforces that basic hosts management is mature and commoditized. |

## Blocklist And Source Ecosystem

| Project | Evidence | Positioning | Activity Snapshot | Lessons For HostsFileGet |
| --- | --- | --- | --- | --- |
| StevenBlack hosts | `M1`, `G0` | Large consolidated hosts source with selectable extensions | 30,361 stars, pushed 2026-05-15 | Source aggregation is valuable but must be curated and explainable. |
| HaGeZi DNS blocklists | `M2`, `G0` | Active DNS blocklist variants and security/privacy lists | 22,892 stars, pushed 2026-05-17 | Variant selection and clear list purpose matter. |
| 1Hosts | `M3`, `G0`, `L6` | Privacy/security blocklist variants | 2,072 stars, pushed 2026-05-17; one Pro URL failed in source-health run | Live source URLs must be verified instead of assumed from repo activity. |
| hBlock | `M4`, `G0`, `L6` | Hosts aggregation project | 1,943 stars, pushed 2026-01-20; aggregate warning exceeded sample cap | Large generated sources need cap-aware UX and metadata. |
| AdGuard hostlists/filter sources | `M5`, `C8`, `L6` | DNS/browser filtering ecosystem with mixed syntax | Several EasyList/AdGuard sources warning in source-health run | HostsFileGet needs syntax-aware quarantine and source-health explanation. |

## DNS Products And Adjacent Tools

| Project | Evidence | Positioning | Activity Snapshot | Lessons For HostsFileGet |
| --- | --- | --- | --- | --- |
| Pi-hole | `P1`, `P2`, `G0` | Self-hosted network DNS blocker | 58,661 stars, pushed 2026-05-16 | Logs, group management, and API handoffs matter; do not imply hosts edits are network-wide DNS. |
| AdGuard Home | `P3`, `P4`, `G0` | Self-hosted DNS blocker with admin UI and filtering rules | 34,030 stars, pushed 2026-05-15 | Syntax boundaries and DNS/provider exports should be explicit. |
| blocky | `P5`, `P6`, `G0` | Lightweight DNS proxy/blocker | 6,624 stars, pushed 2026-05-15 | YAML/config handoff quality can be improved without building a resolver. |
| Technitium DNS | `P7`, `P8`, `G0` | Full DNS server/admin product | 8,407 stars, pushed 2026-05-09 | Useful integration target, not a product model to absorb. |

## Commercial DNS Products

| Product | Evidence | Positioning | Lessons For HostsFileGet |
| --- | --- | --- | --- |
| NextDNS | `C1`, `C2` | Profiles, analytics, security/privacy toggles, allow/deny lists, API | Improve reviewed import/export and profile mapping. Avoid silent remote writes without a deliberate auth model. |
| Control D | `C3`, `C4`, `C5`, `C6` | Profile policy, custom rules, analytics, endpoint assignment | Profile concepts and custom-rule handoffs are useful. Rule semantics differ from hosts files. |
| AdGuard DNS | `C7`, `C8` | DNS filtering with filter syntax and device controls | Syntax compatibility warnings remain important. |
| DNSFilter | `C9`, `C10` | Business DNS filtering and roaming clients | Roaming endpoint strategy should remain planning/handoff oriented unless the project becomes an endpoint product. |

## Strategic Conclusion

HostsFileGet's best position is not to outbuild DNS servers or commercial DNS consoles. Its advantage is local Windows hosts safety plus source intelligence, reviewed transformations, explainability, and handoff artifacts. The most important competitor-driven improvements are source lifecycle management, profile clarity, release trust, and integration export quality.
