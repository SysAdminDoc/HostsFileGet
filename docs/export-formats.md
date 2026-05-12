# Export Formats

`Export Cleaned` starts from the same cleaned output that `Save Cleaned` would preview: parsed domains are normalized, duplicate blocking entries are removed, whitelist rules are applied, and pinned domains are preserved.

## Text Formats

- `hosts`: the cleaned hosts file content.
- `domains` / `pihole`: one blocking domain per line.
- `adblock`: `||domain^` rules for tools that accept Adblock-style DNS rules.
- `dnsmasq`: `address=/domain/0.0.0.0`.
- `rpz`: a Response Policy Zone with exact QNAME trigger rows using `CNAME .` for NXDOMAIN-style blocking.
- `unbound`: `local-zone: "domain." always_nxdomain` rows under a `server:` block.
- `privoxy`: a `+block{...}` actions-file section with one URL host pattern per domain.

## Compressed Hosts

- `hosts-gzip` writes deterministic gzip-compressed cleaned hosts bytes.
- `hosts-bzip2` writes bzip2-compressed cleaned hosts bytes.

The compressed formats are for downstream jobs that already expect compressed hosts assets. The app still exports from the reviewed cleaned view; it does not download or bundle upstream lists into the repository.

## Semantics

The exporters derive a stable intermediate domain record list with:

- comment and blank lines skipped
- non-blocking custom mappings skipped
- duplicate domains removed in first-seen order
- existing hosts semantics preserved where possible

RPZ, Unbound, and Privoxy are more expressive than a Windows hosts file. HostsFileGet does not invent wildcard rules for these exports; it exports the exact domains present after cleaning.

Source references:

- ISC RPZ training shows `CNAME .` as the common NXDOMAIN policy and warns not to add a period after the RPZ owner name.
- Unbound documents RPZ as a policy format shared across resolver implementations and supports RPZ loading.
- Privoxy action files use `{+block{reason}}` sections followed by URL patterns.
- Adjacent blocklist ecosystems such as hBlock and ScriptTiger publish alternate RPZ, Unbound, Privoxy, and compressed outputs, which is the interoperability precedent behind this roadmap item.

Primary URLs:

- `https://www.isc.org/docs/BIND_RPZ.pdf`
- `https://unbound.docs.nlnetlabs.nl/en/latest/topics/filtering/rpz.html`
- `https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html`
- `https://www.privoxy.org/user-manual/actions-file.html`
- `https://github.com/hectorm/hblock`
- `https://scripttiger.github.io/alts/`
