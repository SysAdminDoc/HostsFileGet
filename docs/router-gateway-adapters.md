# Router And Gateway Push Adapters

HostsFileGet router/gateway adapters are guarded bundle generators. They convert reviewed cleaned hosts data into resolver config fragments and write a local script that can be reviewed before an operator runs any router-side command.

HostsFileGet does not execute `scp`, `ssh`, router APIs, service reloads, or credential prompts.

## CLI

List adapters:

```powershell
python hosts_editor.py --router-adapter-list
```

Create a bundle:

```powershell
python hosts_editor.py --router-push-plan openwrt-dnsmasq .\cleaned-hosts.txt .\router-bundle --router-host router.lan --router-user root
```

The bundle contains:

- `router-gateway-push-plan.json`: review metadata, warnings, commands, generated config text, source references, and artifact paths.
- `hostsfileget-router-push.sh`: a review-only script that exits unless `HOSTSFILEGET_CONFIRM=apply` is set.
- Adapter config file, such as `hostsfileget-openwrt-dnsmasq.conf` or `hostsfileget-unbound.conf`.

`--router-remote-path` can override the default remote include path when the target gateway uses a different configuration layout.

## Adapters

| Adapter | Output shape | Default remote path |
| --- | --- | --- |
| `openwrt-dnsmasq` | `address=/domain/0.0.0.0` dnsmasq rows | `/etc/dnsmasq.d/hostsfileget-blocklist.conf` |
| `generic-dnsmasq` | `address=/domain/0.0.0.0` dnsmasq rows | `/etc/dnsmasq.d/hostsfileget-blocklist.conf` |
| `generic-unbound` | `local-zone: "domain." always_nxdomain` entries | `/etc/unbound/unbound.conf.d/hostsfileget.conf` |

## Safety Contract

- The generated script prints a dry-run summary and exits by default.
- Applying requires explicitly setting `HOSTSFILEGET_CONFIRM=apply`.
- The script stages the generated file to `/tmp`, backs up the current remote config path when present, installs the staged file, runs the adapter validation command, restores the backup on validation failure when one exists, then reloads the resolver service.
- Authentication, SSH host-key trust, router console access, snapshots, and rollback remain operator responsibilities.
- OpenWrt users must verify that the target image loads the selected dnsmasq include directory before applying the generated script.
- Hosts data remains exact-domain data. Wildcard rules, per-client policy, upstream routing, response rewrites, and schedules belong in the downstream resolver.

## Source References

- OpenWrt DHCP and DNS configuration: `https://openwrt.org/docs/guide-user/base-system/dhcp`
- dnsmasq documentation and manpage index: `https://dnsmasq.org/doc.html`
- Unbound `local-zone` and `local-data` configuration: `https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html`
