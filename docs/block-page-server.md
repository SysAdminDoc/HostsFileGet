# Local Block Page Server

HostsFileGet can run a small local HTTP block page server for reviewed hosts-file workflows that map blocked names to loopback. It is explicit, loopback-only, and informational.

## Commands

Write a static preview first:

```powershell
python hosts_editor.py --block-page-preview .\block-page-preview.html
```

Start the server on the default loopback review port:

```powershell
python hosts_editor.py --block-page-serve
```

Use port 80 only when you have reviewed Windows permissions, URL reservations, and process conflicts:

```powershell
python hosts_editor.py --block-page-serve --block-page-port 80
```

Customize the visible copy:

```powershell
python hosts_editor.py --block-page-preview .\block-page-preview.html `
  --block-page-title "Blocked by local policy" `
  --block-page-message "This request matched a reviewed HostsFileGet block rule." `
  --block-page-support-url https://support.example/allowlist
```

## Safety Boundary

- The server binds only to loopback hosts: `localhost`, `127.0.0.1`, or `::1`.
- The server responds to `GET` and `HEAD` on every path so a browser can show the same explanation for blocked HTTP requests.
- `GET /__hostsfileget_block_page_health` returns a small JSON health response.
- It does not write `C:\Windows\System32\drivers\etc\hosts`.
- It does not modify source lists, profiles, DNS servers, firewall rules, or browser settings.
- It is HTTP-only. HTTPS blocked sites will show browser certificate or TLS errors unless the operator supplies separate certificate-aware infrastructure.
- Hosts files can map names to an IP address, but they cannot redirect URL paths or ports.
- LAN/router custom block pages need a separately managed web server and DNS policy; this feature is intentionally local.

## Source Basis

[Control D documents](https://docs.controld.com/docs/blocked-query-response) configurable blocked-query responses and custom block pages. [AdGuard Home guidance](https://github.com/AdguardTeam/AdGuardHome/wiki/FAQ/2f622f2a51e805569deafd290ac1f83f4ee6c87f) describes the operational need for an HTTP server that serves the page on all routes when DNS blocking points clients at a custom IP. HostsFileGet keeps this as a local-only diagnostic helper instead of a router or resolver feature.
