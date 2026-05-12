# Migration Imports

HostsFileGet can append hosts profiles from other hosts-file editors without adopting their full profile models.

Supported importers:

- SwitchHosts JSON exports from v3 and v4-style data payloads.
- Gas Mask folders containing `Local/`, `Remote/`, and `Combined/` files.
- HostsFileEditor archive folders, where each archive file is plain hosts text.

These imports are append-only. They do not replace the current editor content, change the active HostsFileGet profile, or write the system hosts file. After import, review the editor and use the normal `Save Cleaned` preview before writing.

## SwitchHosts

Use **Tools > Migration Imports > From SwitchHosts export...** or the sidebar migration button.

The importer expects the exported `swh_data.json` shape with a top-level `version` array. SwitchHosts v3 stores hosts content under tree/list items, while v4 exports PotDB data under `data`; HostsFileGet walks the exported JSON and extracts objects with hosts-like `content` fields.

Source evidence:

- `https://github.com/oldj/SwitchHosts/blob/master/src/main/actions/migrate/export.ts`
- `https://github.com/oldj/SwitchHosts/blob/master/src/main/actions/migrate/import.ts`
- `https://github.com/oldj/SwitchHosts/blob/master/src/main/actions/migrate/importV3Data.ts`
- `https://github.com/oldj/SwitchHosts/blob/master/src/common/data.d.ts`

## Gas Mask

Use **Tools > Migration Imports > From Gas Mask folder...** and select the Gas Mask data folder or a folder containing hosts files.

The normal Gas Mask layout is:

```text
Gas Mask/
  Local/
  Remote/
  Combined/
```

`Local` and `Remote` files are imported as plain hosts text. `Combined` files are reference lists such as `Local/Work` or `Remote/Shared`; HostsFileGet expands those references from the selected folder and adds section comments matching Gas Mask's combined display.

Source evidence:

- `https://github.com/2ndalpha/gasmask/blob/master/Source/FileUtil.m`
- `https://github.com/2ndalpha/gasmask/blob/master/Source/Hosts.m`
- `https://github.com/2ndalpha/gasmask/blob/master/Source/CombinedHosts.m`

## HostsFileEditor

Use **Tools > Migration Imports > From HostsFileEditor archive folder...** and select the `archive` folder under the Windows hosts directory, or another folder containing exported archive files.

HostsFileEditor writes archive entries with `File.WriteAllLines(...)` from each entry's unparsed text, so HostsFileGet treats every archive file as plain hosts text and skips files that do not contain any hosts-like entries.

Source evidence:

- `https://github.com/scottlerch/HostsFileEditor/blob/master/src/HostsArchiveList.cs`
- `https://github.com/scottlerch/HostsFileEditor/blob/master/src/HostsFile.cs`

## Limits

- Each migration file is capped at 10 MB.
- A single migration import is capped at 50 MB total.
- Folder imports are capped at 2,000 files.
- Files with no parseable hosts entries are skipped.
- Unknown SwitchHosts versions newer than v4 are rejected instead of guessed.

