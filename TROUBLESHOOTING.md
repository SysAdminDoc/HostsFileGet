# HostsFileGet Limitations And Troubleshooting

This guide covers the operational limits of hosts-file blocking and the common failure modes that look like app bugs.

## First Checks

1. Confirm whether HostsFileGet is running as Administrator.
2. Confirm whether Dry-run mode is enabled.
3. Use `File > Compare Backups...` or backup restore preview before replacing known-good content.
4. Use `Tools > Hosts Health Scan...` before trusting unfamiliar non-loopback mappings.
5. Flush DNS after writes if a change should take effect immediately.
6. Restart the browser or affected app if it keeps its own DNS or connection cache.

## Administrator Rights

Windows protects `C:\Windows\System32\drivers\etc\hosts`. Real writes require elevation.

Expected behavior:

- The app attempts to relaunch elevated on Windows.
- If elevation is declined, the app can still inspect, import, clean, and dry-run.
- `Save Raw`, `Save Cleaned`, `--apply`, `--update`, `--disable`, and `--enable` need Administrator rights for real writes.

If saving fails while elevated:

- Check whether the file is marked read-only.
- Check whether antivirus, indexing, sync, or another editor has the file locked.
- Confirm the hosts file is not currently in HostsFileGet's disabled state.
- Try saving after closing other hosts editors, DNS tools, and security products that rewrite hosts.

## Hosts File Syntax Limits

The Windows hosts file maps exact hostnames to IP addresses. It is not a DNS filtering language.

Important limits:

- Wildcards are not native. `*.example.com` does not block all subdomains in the Windows hosts file.
- URL paths are not supported. `example.com/ads.js` cannot be represented.
- Browser cosmetic rules are not supported. Selectors such as `##.ad` are browser-filter syntax, not hosts syntax.
- Same-domain ads cannot be blocked safely with hosts. If content and ads are both served from `example.com`, hosts can only block or allow the whole host.
- Hosts rules do not express CNAME chains, DNS categories, per-client policy, time windows, or regex matching.

HostsFileGet can normalize some common source dialects for convenience, but the final hosts file remains an exact hostname mapping file.

## DNS Bypass

Hosts-file changes only affect lookups that use the OS resolver path. Blocking can appear to fail when traffic bypasses Windows hosts resolution.

Common bypass paths:

- Browser DNS-over-HTTPS.
- OS or VPN private DNS.
- Apps with hardcoded DNS resolvers.
- Devices using router, mobile, or cloud DNS instead of the Windows machine.
- Browser or app connection reuse after a domain was already resolved.
- WSL, containers, virtual machines, and Windows Sandbox using separate name-resolution behavior.

Recommended response:

- Disable or configure browser private DNS if local hosts control is required.
- Check VPN DNS policy.
- Restart the browser/app after a write.
- Use router, firewall, NextDNS, Control D, AdGuard DNS, Pi-hole, or AdGuard Home when per-device or network-wide enforcement is required.
- Treat HostsFileGet's future DNS-bypass diagnostics as explanation tools, not enforcement guarantees.

## Wildcards And Subdomains

To block both a root domain and subdomains, entries must be explicit:

```text
0.0.0.0 example.com
0.0.0.0 www.example.com
0.0.0.0 ads.example.com
```

If a source contains `*.example.com`, HostsFileGet can identify and normalize the root where possible, but it cannot infer every possible subdomain without another source of truth.

Use DNS-provider rules or a local DNS server if wildcard policy is required.

## False Positives And Broken Sites

Blocklists can break login, payment, video, chat, telemetry-dependent launchers, mobile apps, smart TVs, and anti-abuse flows.

Suggested triage:

1. Search the domain in the editor.
2. Use `Tools > Check Domain...` to find whether it is blocked, whitelisted, pinned, or present in fetched sources.
3. Temporarily comment the line or add a whitelist entry.
4. Use `Save Cleaned` and flush DNS.
5. If the fix is source-specific, remove the import section or avoid that source in the next import.
6. Prefer a narrow whitelist entry over disabling a whole category source.

High-risk categories for false positives:

- Authentication and SSO endpoints.
- Payment processors.
- CDN and asset hosts.
- Mobile push notification services.
- Game launchers and anti-cheat dependencies.
- Smart TV and streaming-device telemetry endpoints that double as activation endpoints.

## Source Import Problems

If a source imports no entries:

- The server may have returned an HTML error page.
- The response may exceed the app's size limits.
- The source may use a rule dialect that hosts cannot represent.
- The source may be compressed or encoded unexpectedly.
- A corporate proxy or captive portal may be substituting a login/error response.

Use source preview before import when testing a new feed. Custom source names and URLs are validated before being saved; control characters and oversized values are rejected.

## Stale Sources

HostsFileGet stores per-source freshness metadata. A source can be stale without being broken.

Use stale indicators as a prompt to refresh, not as a guarantee that a list is unsafe. Feed maintainers have different release cadences.

If a source repeatedly fails:

- Preview the source.
- Check whether the upstream project changed URLs.
- Remove or replace the custom source.
- Prefer source manifests and curated source updates once the roadmap's manifest work lands.

## Read-Only Lock

The read-only lock is a tamper-resistance option. It sets the Windows read-only attribute after save.

Expected tradeoff:

- It can block drive-by writes by other unelevated tools.
- It can also interfere with legitimate third-party hosts editors, security tools, or deployment systems.

If another tool needs to write hosts, disable the lock in Preferences or clear the attribute manually.

## Windows Defender HostsFileHijack Warnings

Windows Defender and other security tools can warn when hosts entries redirect well-known domains. This can happen for malicious hijacks and for intentional blocklists.

Use `Tools > Hosts Health Scan...` to inspect non-loopback mappings. Treat mappings to public IP addresses as higher risk than mappings to `0.0.0.0`, `127.0.0.1`, `::`, `::1`, or private LAN addresses.

## Disabled Hosts State

`File > Disable / Enable Hosts` temporarily replaces the live hosts file with a minimal Microsoft-style template and stores the original as `hosts.disabled`.

Do not manually edit both files while disabled. Re-enable from HostsFileGet before applying new changes, otherwise the preserved file may not match your expectations.

## Backups And Recovery

Recovery options:

- Rolling backup: `hosts.bak`.
- Timestamped backups: `hosts.YYYYMMDD-HHMMSS.bak`.
- Compare backups before restore.
- Panic restore loads the stock Microsoft default into the editor.
- Emergency DNS recovery is destructive and should be treated as a last resort.

If the system loses name resolution:

1. Disable the hosts file or panic-restore the stock template.
2. Save as Administrator.
3. Flush DNS.
4. Restart the affected app.
5. Reintroduce sources in smaller batches.

## Scheduled Updates

Scheduled updates are designed for unattended refresh, but they still depend on elevation and source availability.

If a scheduled update appears to fail:

- Check `%LOCALAPPDATA%\HostsFileGet\cli.log` when `--silent` is used.
- Confirm the Task Scheduler action runs elevated.
- Confirm the task points to the intended script or executable.
- Confirm no disabled-hosts state is active.
- Confirm sources are reachable outside the GUI.

## Large Files

Large hosts files can make full-text highlighting, search, diff, and cleanup operations slower.

Current guards:

- Large diffs use unified diff instead of expensive `ndiff`.
- Search highlighting is capped.
- Match-removal dialogs avoid rendering unbounded checkbox counts.
- Downloads and decompressed payloads are capped.

If editing becomes slow:

- Use source-level removal instead of line-by-line edits.
- Split large source imports into smaller batches.
- Remove redundant sources after checking source contribution reports.
- Avoid broad one-letter searches on very large files.

## When HostsFileGet Is The Wrong Tool

Use a DNS server, DNS filtering provider, browser blocker, or firewall when you need:

- Wildcard DNS policy.
- Per-device rules.
- Per-user accounts.
- Browser cosmetic filtering.
- URL path blocking.
- Remote/mobile enforcement.
- Query analytics across a network.
- IP/CIDR blocking independent of DNS.
- Enforced DoH/DoT/DoQ controls.

HostsFileGet can still help generate, inspect, or export source data for those systems, but the hosts file itself has hard limits.

Use **Tools > DNS Bypass Diagnostics...** when a browser or app appears to ignore a hosts entry. It checks local browser encrypted-DNS policy signals and proxy environment variables, then summarizes where enforcement must move outside the hosts file.
