# Encrypted Profile Sync

HostsFileGet can export and import saved profiles through an explicit Git worktree. The sync bundle is encrypted with GPG before it is committed, and sync commands never write the Windows hosts file.

This is the first guarded implementation for F054. Gist/API-backed sync is intentionally not implemented here because token storage, revocation, and rate-limit handling need a separate trust model.

## What Sync Includes

The encrypted payload includes:

- saved profiles
- active profile ID
- profile activation windows and fallback profile

It excludes operational metadata such as source cache entries, source freshness history, provenance logs, local paths, backup hashes, and scheduled-task activity.

## Requirements

- Git on `PATH`
- GPG on `PATH`
- a passphrase provided through an environment variable
- a local Git worktree, ideally a clone of a private remote repository

The default passphrase variable is:

```powershell
$env:HOSTSFILEGET_SYNC_PASSPHRASE = "use-a-long-random-passphrase"
```

The passphrase must be at least 16 characters. It is passed to GPG through standard input, not command-line arguments.

## Export

Write the encrypted profile bundle and commit it locally:

```powershell
python hosts_editor.py --sync-git-export C:\path\to\sync-worktree
```

Push only when the worktree already has the intended `origin` remote:

```powershell
python hosts_editor.py --sync-git-export C:\path\to\sync-worktree --sync-git-push
```

No GitHub, Gist, or provider token is read or stored by HostsFileGet. If the remote needs credentials, Git handles that through the user's existing credential manager.

## Import

Import the encrypted bundle into app config only:

```powershell
python hosts_editor.py --sync-git-import C:\path\to\sync-worktree
```

Pull first from the existing remote:

```powershell
python hosts_editor.py --sync-git-import C:\path\to\sync-worktree --sync-git-pull
```

Import replaces saved profiles, active profile, and profile activation schedule in the app config. It mirrors the imported active profile into the current top-level config fields. It does not write `C:\Windows\System32\drivers\etc\hosts`; the next save/apply remains explicit and preview-backed.

## Files

The sync worktree tracks:

- `hostsfileget-profile-sync.json.gpg`: encrypted profile payload
- `hostsfileget-profile-sync.metadata.json`: non-sensitive metadata for review, including active profile ID, profile count, payload hash, and encryption mode

## Boundaries

- No default cloud sync.
- No unencrypted profile payload is committed.
- No Gist token support yet.
- No automatic conflict merge. Resolve Git conflicts in the worktree, then rerun import or export.
- No hosts-file writes, DNS changes, or source imports happen during sync.
