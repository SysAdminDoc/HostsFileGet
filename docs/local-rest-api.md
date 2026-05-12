# Local REST API

HostsFileGet includes an opt-in local REST facade for automation and integration tests. It is disabled by default.

## Start

```powershell
$env:HOSTSFILEGET_API_TOKEN = "replace-with-at-least-16-random-chars"
python hosts_editor.py --api-serve
```

Optional flags:

```powershell
python hosts_editor.py --api-serve --api-host 127.0.0.1 --api-port 8765 --api-token "replace-with-at-least-16-random-chars"
```

## Security Boundary

- The server binds only to loopback hosts: `127.0.0.1`, `::1`, or `localhost`.
- Every endpoint requires `Authorization: Bearer <token>`.
- Tokens must be at least 16 characters and cannot contain control characters.
- The initial API surface is read-only and does not write the system hosts file.
- Responses send `Cache-Control: no-store`.

## Endpoints

`GET /v1/status`

Returns version, hosts path, auth mode, and endpoint metadata.

`POST /v1/clean-preview`

Runs the same cleaned-output helper used by the app without writing files.

Request body:

```json
{
  "text": "0.0.0.0 ads.example\n0.0.0.0 tracker.example\n",
  "whitelist": ["tracker.example"],
  "pinned_domains": []
}
```

Response body includes `cleaned_lines`, `stats`, and `writes_hosts: false`.

## Non-Goals

- No remote bind addresses.
- No unauthenticated health endpoint.
- No hosts-file write endpoint in this phase.
- No multi-user account model.
