# Entry Provenance

The **Tools > Entry Provenance...** command and editor right-click **Entry provenance...** action show a line-level blame report for the current editor row.

## What It Shows

For the selected line, HostsFileGet reports:

- raw line text
- whether the line is outside import markers, inside an imported source block, or an import start/end marker
- source block name, mode, and line range when import markers identify one
- parsed normalized entries on the line
- whether each parsed entry is a blocking entry or a custom IP mapping
- previously fetched sources that contain each parsed domain
- matching local provenance JSONL events such as pin, unpin, or whitelist actions

## Data Sources

The panel is local-only and uses:

- current editor text
- `# --- Raw|Normalized Import Start/End: NAME ---` markers
- the bounded in-memory fetched-source corpus
- `hosts_editor_provenance.jsonl` beside the active config

## Limits

- Source matches only include feeds fetched in the current session.
- Provenance events only exist for actions that were logged by HostsFileGet.
- Manual edits outside import markers are reported as outside-import content; the app cannot infer who typed them.
- The panel is diagnostic. It does not mutate the editor, config, or provenance log.
