# Mobile DNS Profile Export

`--mobile-dns-profile-export` writes local review artifacts for roaming phones and tablets where the Windows hosts file cannot apply. It does not install mobile profiles, call provider APIs, create bitmap QR images, or change device DNS settings.

Generated plans include the shared `hostsfileget.handoff-contract.v1` block described in `docs/integration-handoff-contract.md`.

## Commands

```powershell
python hosts_editor.py --mobile-dns-profile-list
python hosts_editor.py --mobile-dns-profile-export nextdns .\mobile-dns --mobile-dns-profile-id abc123
python hosts_editor.py --mobile-dns-profile-export generic-dot .\mobile-dns --mobile-dns-hostname dns.example.com --mobile-dns-display-name "Lab DNS"
python hosts_editor.py --mobile-dns-profile-export generic-doh .\mobile-dns --mobile-dns-doh-url https://dns.example.com/dns-query
python hosts_editor.py --mobile-dns-profile-export controld .\mobile-dns --mobile-dns-profile-id resolver1 --mobile-dns-hostname resolver1.dns.controld.com
```

## Outputs

- `mobile-dns-profile-export.json`: schema `hostsfileget.mobile-dns-profile-export.v1`, endpoint metadata, warnings, setup steps, source IDs, and `handoff_contract`.
- `hostsfileget-mobile-dns.mobileconfig`: unsigned Apple DNS Settings profile when a valid DoH URL or DoT hostname is available.
- `mobile-dns-qr-payloads.txt`: QR-ready payload text for a trusted offline QR generator.
- `MOBILE_DNS_PROFILE_EXPORT.md`: bundle review notes.

## Target Behavior

- `generic-dot` requires `--mobile-dns-hostname`.
- `generic-doh` requires `--mobile-dns-doh-url`.
- `nextdns` uses `--mobile-dns-profile-id` to derive `PROFILE.dns.nextdns.io`, `https://dns.nextdns.io/PROFILE`, and the provider Apple setup URL.
- `controld` can derive the DoH endpoint from `--mobile-dns-profile-id`; pass the provider-issued DoT hostname with `--mobile-dns-hostname` for Android Private DNS.

## Safety Notes

Mobile OS DNS settings can be bypassed or overridden by VPNs, browser Secure DNS, iCloud Private Relay, captive portals, MDM policy, and per-app networking. Treat these artifacts as review handoffs, not enforcement.

The handoff contract records that HostsFileGet will not install profiles, call provider APIs, enroll devices, render bitmap QR images, make Windows hosts files apply to mobile operating systems, or prevent OS/provider bypass paths.
