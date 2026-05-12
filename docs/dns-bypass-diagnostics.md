# DNS Bypass Diagnostics

The **Tools > DNS Bypass Diagnostics...** report explains common reasons a hosts-file entry may not affect a browser or application.

## What It Checks

The report is local-only and currently checks:

- managed Chrome and Edge DNS-over-HTTPS policy values
- managed Firefox DNS-over-HTTPS policy values
- common proxy environment variables such as `HTTPS_PROXY`, `HTTP_PROXY`, and `ALL_PROXY`
- static hosts-file limitation guidance

## What It Means

Hosts entries only affect resolution paths that ask the OS resolver for a hostname. A blocked hosts entry may appear ineffective when traffic goes through:

- browser DoH, DoT, or DoQ
- VPN resolver policy
- remote proxy DNS
- app-specific hardcoded resolvers
- another device or router resolving the name upstream

The diagnostics report does not enforce DNS policy. It surfaces local signals and points to where enforcement belongs.

## Recommended Response

- Disable or lock browser encrypted-DNS policy when local hosts enforcement matters.
- Enforce resolver policy at the router or firewall for apps that ignore the OS resolver.
- Use **Windows DNS Client Snapshot** to inspect query names visible to the OS resolver.
- Treat "no policy detected" as inconclusive; user-level app settings can still bypass the local hosts path.
