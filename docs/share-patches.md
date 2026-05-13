# Signed Share Patches

HostsFileGet can package allowlist additions or saved profiles as small JSON patch files. Patches are meant for review in source control or chat, then verification with a detached GPG signature before import.

Applying a patch updates app config only. It never writes `C:\Windows\System32\drivers\etc\hosts`; normal preview/save behavior still applies later.

## Patch Types

`allowlist` patches contain sanitized domain names to merge into the active whitelist.

`profile` patches contain one saved profile. Importing a profile patch adds or replaces the saved profile by ID without making it active.

Operational metadata is intentionally excluded: source cache, source metrics, provenance logs, local paths, backup hashes, and scheduler activity do not leave the machine.

## Build An Allowlist Patch

```powershell
python hosts_editor.py --patch-build-allowlist .\domains.txt .\allowlist.patch.json
```

The input file should contain one domain per line. Invalid rows are ignored by the same conservative whitelist sanitizer used by the app.

## Build A Profile Patch

```powershell
python hosts_editor.py --patch-build-profile work .\work-profile.patch.json
```

The profile is read from the current app config. The command does not activate, import, or apply anything.

## Sign

```powershell
python hosts_editor.py --patch-sign .\work-profile.patch.json .\work-profile.patch.json.asc --patch-gpg-key test@example.com
```

`--patch-gpg-key` is optional. If omitted, GPG uses its default signing identity. HostsFileGet does not store private keys or passphrases.

## Verify

```powershell
python hosts_editor.py --patch-verify .\work-profile.patch.json .\work-profile.patch.json.asc
```

Verification delegates to local GPG trust settings. Review the signer identity before applying a patch from another person.

## Apply

```powershell
python hosts_editor.py --patch-apply .\work-profile.patch.json .\work-profile.patch.json.asc
```

Apply always verifies the detached signature first. If verification fails, the app config is not changed.

## Boundaries

- No unsigned apply path.
- No hosts-file writes.
- No remote key discovery or token handling.
- No automatic trust decisions beyond the local GPG verification result.
- No conflict merge for profile IDs beyond replacing the matching saved profile.
