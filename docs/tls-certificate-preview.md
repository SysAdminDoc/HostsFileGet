# TLS Certificate Preview

HostsFileGet can prepare a plan-only TLS certificate review queue for public DNS hostnames found in hosts-like text, URLs, or plain domain lists.

The preview workflow does not open sockets, perform TLS handshakes, fetch certificate chains, store certificate output, or write hosts entries. It writes a JSON plan with SNI-aware OpenSSL commands, Python `ssl` inspection guidance, and a CSV review queue for explicit manual execution.

## Commands

Describe the workflow:

```powershell
python hosts_editor.py --tls-preview-list
```

Build a review plan:

```powershell
python hosts_editor.py --tls-preview-plan .\hosts.txt .\tls-preview-plan.json
```

Set the port, timeout placeholder, and host cap:

```powershell
python hosts_editor.py --tls-preview-plan .\hosts.txt .\tls-preview-plan.json --tls-preview-port 8443 --tls-preview-timeout 9 --tls-preview-max-hosts 50
```

The JSON schema is `hostsfileget.tls-certificate-preview-plan.v1`. It includes:

- normalized public DNS hostnames extracted from hosts rows, URLs, or domain tokens
- per-host SNI names, ports, and connect endpoints
- SNI-aware `openssl s_client` command arrays and rendered command strings
- Python `ssl.create_default_context()` recipe metadata for external inspection clients
- expected review fields for SANs, subject, issuer, validity, fingerprint, TLS version, cipher, and hostname verification
- a CSV review queue for manual execution tracking
- warnings and roadmap source IDs for traceability

## GUI

Use **Tools > TLS Certificate Preview...** to open the same plan-only workflow description in the desktop app.

## Boundaries

- HostsFileGet does not connect to target hosts or cache certificate chains.
- Generated commands should be run only for hosts you own, administer, or are explicitly authorized to inspect.
- Manual execution opens a TLS handshake and can disclose the queried hostname through SNI to network infrastructure and endpoint logs.
- Certificate anomalies are investigation leads. Do not block domains solely because issuer, validity, SAN, or cipher metadata looks unusual.
- Keep captured certificate output short-lived unless local policy requires retention.

## Review Flow

1. Generate the TLS preview plan from a hosts file, URL list, or candidate domain list.
2. Remove any host outside the approved inspection scope.
3. Run selected OpenSSL commands manually from a review shell.
4. Compare SAN DNS names, issuer, validity dates, SHA-256 fingerprint, negotiated TLS version, cipher, and hostname verification result.
5. Convert findings into hosts-file or upstream-source changes only after false-positive triage and rollback planning.

## Source Basis

- Python `ssl.create_default_context()` and `SSLContext.wrap_socket(..., server_hostname=...)` provide the standard Python client model for verified TLS connections with SNI.
- TLS 1.3 continues to use certificate authentication for server identity and negotiated security properties.
- RFC 5280 defines X.509 certificate and Subject Alternative Name semantics used when reviewing host identity.
- OpenSSL `s_client` supports `-connect`, `-servername`, `-verify_hostname`, and `-showcerts` for manual certificate-chain inspection.
