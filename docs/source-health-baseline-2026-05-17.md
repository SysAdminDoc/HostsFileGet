# Source Health Baseline - 2026-05-17

Baseline report: `.ai/research/2026-05-17/source-health-report.json`
Manifest: `data/blocklist_sources.json`

## Summary

- Total sources checked: 177
- Healthy: 122
- Warning: 21
- Failed: 34

This baseline is point-in-time evidence. Public blocklist feeds can move, rate-limit, retire formats, or recover. The manifest keeps unhealthy sources visible with lifecycle metadata instead of deleting them silently.

## Manifest Actions Taken

- HTTP 404/410 sources were marked `retired` and disabled from built-in bundles and one-click import.
- Network, access/range, oversized-sample, empty-sample, and non-host-like findings were marked `warning` for guarded review.
- Built-in bundles were updated so they no longer reference sources that hard-failed in this baseline.
- Replacement source fields were added where a safer in-catalog substitute was selected.

## Built-In Bundle Replacements

| Bundle | Retired source | Replacement source | Replacement URL |
| --- | --- | --- | --- |
| `starter-low-breakage` | OISD Full | MVPS Hosts | https://winhelp2002.mvps.org/hosts.txt |
| `aggressive-privacy` | 1Hosts Pro | 1Hosts Xtra | https://raw.githubusercontent.com/badmojr/1Hosts/master/Xtra/hosts.txt |
| `family-category` | RPiList Gambling | Sinfonietta Gambling | https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/gambling-hosts |

## Failed Sources

| Source | Category | Baseline diagnostic | Lifecycle | Replacement | Notes |
| --- | --- | --- | --- | --- | --- |
| 1Hosts Pro | Major / Unified / Aggregated | HTTP 404. | retired | 1Hosts Xtra | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| OISD Full | Major / Unified / Aggregated | HTTP 410. | retired | MVPS Hosts | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| OISD DBL | Major / Unified / Aggregated | HTTP 410. | retired | StevenBlack Unified | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| HOSTShield Combined | Major / Unified / Aggregated | HTTP 404. | retired | HaGezi Multi | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| YouTube Ads Blacklist | Ads / Tracking / Analytics | HTTP 404. | retired |  | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| HOSTShield Ads | Ads / Tracking / Analytics | HTTP 404. | retired | EasyList Hosts | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| Adobe Hosts | Ads / Tracking / Analytics | HTTP 404. | retired | AdGuard DNS | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| MobileAdTrackers (jawz101) | Ads / Tracking / Analytics | HTTP 404. | retired |  | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| MalwareDomains | Malware / Phishing / Scam | HTTP 404. | retired |  | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| DigitalSide Threat Intel | Malware / Phishing / Scam | Network error: timed out | warning |  | Failed the baseline check but may be transient or access/range related; keep guarded before scheduled use. |
| VXVault | Malware / Phishing / Scam | Network timeout. | warning |  | Failed the baseline check but may be transient or access/range related; keep guarded before scheduled use. |
| Botvrij IOC | Malware / Phishing / Scam | HTTP 416. | warning |  | Failed the baseline check but may be transient or access/range related; keep guarded before scheduled use. |
| Inversion DNS Blocklist | Malware / Phishing / Scam | HTTP 404. | retired |  | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| Curbengh Phishing Filter | Malware / Phishing / Scam | HTTP 404. | retired |  | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| CoinBlockerLists | Malware / Phishing / Scam | HTTP 404. | retired |  | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| CoinBlockerLists Browser | Malware / Phishing / Scam | HTTP 404. | retired |  | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| NRD 14-day (xRuffKez) | Malware / Phishing / Scam | HTTP 404. | retired | HaGeZi NRD 14-day | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| NRD 30-day (xRuffKez) | Malware / Phishing / Scam | HTTP 404. | retired | HaGeZi NRD 14-day | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| MajkiIT Polish Adservers | Spam / Abuse / Misc | HTTP 404. | retired |  | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| Schakal (Russian) | Spam / Abuse / Misc | HTTP 404. | retired |  | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| Public Stun | Spam / Abuse / Misc | HTTP 403. | warning |  | Failed the baseline check but may be transient or access/range related; keep guarded before scheduled use. |
| RPiList Gambling | Category Filters (Opt-in) | HTTP 404. | retired | Sinfonietta Gambling | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| RPiList Fake Science | Category Filters (Opt-in) | HTTP 404. | retired | BlocklistProject Fraud | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| HaGeZi NRD 14-day | Threat Intelligence / NRD / DGA | HTTP 403. | warning |  | Failed the baseline check but may be transient or access/range related; keep guarded before scheduled use. |
| HOSTShield Apple | Vendor / Platform | HTTP 404. | retired | Apple Native | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| HOSTShield Brave | Vendor / Platform | HTTP 404. | retired | AdGuard DNS | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| HOSTShield Microsoft | Vendor / Platform | HTTP 404. | retired | Windows Office Native | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| HOSTShield TikTok | Vendor / Platform | HTTP 404. | retired | TikTok Native | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| HOSTShield Twitter | Vendor / Platform | HTTP 404. | retired | AdGuard DNS | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| Perflyst Vivo Telemetry | Vendor / Platform | HTTP 404. | retired | Vivo Native | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| Perflyst Samsung Smart | Vendor / Platform | HTTP 404. | retired | Samsung Native | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| llacb47 Smart TV | Vendor / Platform | HTTP 404. | retired |  | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| llacb47 LG WebOS | Vendor / Platform | HTTP 404. | retired | LG WebOS Native | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |
| llacb47 Disney | Vendor / Platform | HTTP 404. | retired | AdGuard DNS | Retained for audit/history; disabled from built-in bundles and one-click import until a maintainer verifies a direct replacement. |

## Warning Sources

| Source | Category | Baseline diagnostic | Lifecycle | Notes |
| --- | --- | --- | --- | --- |
| hBlock Aggregate | Major / Unified / Aggregated | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| SomeoneWhoCares Zero | Major / Unified / Aggregated | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| SomeoneWhoCares 127 | Major / Unified / Aggregated | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| EasyList Hosts | Ads / Tracking / Analytics | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| EasyPrivacy Hosts | Ads / Tracking / Analytics | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| EasyList Privacy Orig | Ads / Tracking / Analytics | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| EasyList NoElemHide | Ads / Tracking / Analytics | Source is reachable, but the sample did not contain host-like entries. | warning | Reachable but not hosts-like in the sampled text; run syntax lint or keep as a provider handoff source. |
| AdGuard DNS | Ads / Tracking / Analytics | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| NoTrack Tracking | Telemetry / Privacy / Spyware | Source is reachable, but the sample did not contain host-like entries. | warning | Reachable but not hosts-like in the sampled text; run syntax lint or keep as a provider handoff source. |
| NoTrack Malware | Malware / Phishing / Scam | Source is reachable, but the sample did not contain host-like entries. | warning | Reachable but not hosts-like in the sampled text; run syntax lint or keep as a provider handoff source. |
| Prigent Malware | Malware / Phishing / Scam | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| Prigent Crypto | Malware / Phishing / Scam | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| RPiList Malware | Malware / Phishing / Scam | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| RPiList Phishing | Malware / Phishing / Scam | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| Phishing Army | Malware / Phishing / Scam | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| Malware Filter Phishing | Malware / Phishing / Scam | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| PhishTank Data (CSV) | Malware / Phishing / Scam | Source is reachable, but the sample did not contain host-like entries. | warning | Reachable but not hosts-like in the sampled text; run syntax lint or keep as a provider handoff source. |
| CyberCrime Tracker | Malware / Phishing / Scam | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| Toxic Domains | Malware / Phishing / Scam | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| Phishing Army Extended | Malware / Phishing / Scam | Source is reachable, but the sample exceeded the cap: Response exceeded 256 KB size cap (feed too large or server is streaming non-hosts content). | warning | Reachable but larger than the bounded health sample; review before recurring imports. |
| Cats-Team AdRules (CN) | Spam / Abuse / Misc | Source is reachable, but the sample did not contain host-like entries. | warning | Reachable but not hosts-like in the sampled text; run syntax lint or keep as a provider handoff source. |

## Recheck Command

```powershell
python hosts_editor.py `
  --source-health `
  --source-health-timeout 12 `
  --source-health-workers 12 `
  --source-health-baseline .ai\research\2026-05-17\source-health-report.json `
  --source-health-output source-health-report.json
```
