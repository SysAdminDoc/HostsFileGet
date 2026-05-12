# Windows DNS Client Snapshot

HostsFileGet can read a bounded snapshot from the local `Microsoft-Windows-DNS-Client/Operational` event channel and append observed DNS query hostnames to the editor.

## Entry Points

- Sidebar: **Import From File > From Windows DNS Snapshot**
- Menu: **Tools > Import DNS Queries From Logs > From Windows DNS Client snapshot...**

## Behavior

The import:

- asks before reading the event log
- asks for the maximum recent event count to scan
- runs `wevtutil qe Microsoft-Windows-DNS-Client/Operational /rd:true /c:N /f:xml`
- parses query-name XML fields locally
- deduplicates normalized multi-label domains
- asks again before appending the observed domains to the editor

Observed queries are not proof that a domain should be blocked. Treat the result as a diagnostic candidate list and review it before saving.

## Log Availability

Some Windows installs do not have the DNS Client Operational log enabled. To inspect or enable it manually from an elevated shell:

```powershell
wevtutil gli Microsoft-Windows-DNS-Client/Operational
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true
```

## Limits

- This is a snapshot import, not a background monitor.
- It does not bypass browser DoH, DoT, DoQ, VPN, proxy, or hardcoded resolver behavior.
- It imports observed query names, not blocked-query verdicts.
- Event volume can be high; the UI caps the scan at 5,000 recent events.
- The feature is local-only and does not upload event data.
