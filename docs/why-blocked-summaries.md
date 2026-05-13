# Why Blocked Summaries

HostsFileGet can generate an offline explanation of why a domain appears blocked in the current editor.

The feature is intentionally local and deterministic. It does not call an LLM API, open a network connection, upload hosts data, or change the system hosts file.

## What The Summary Uses

`--why-blocked-summary` combines bounded local evidence:

- matching block-style hosts entries in the input file
- whitelist coverage from an optional whitelist file
- pinned status when called from the GUI
- previously fetched source matches when called from the GUI
- upstream report URLs when source metadata is available
- local provenance events when called from the GUI
- the same recommended actions used by false-positive triage

The JSON schema is:

```text
hostsfileget.why-blocked-summary.v1
```

## CLI Usage

Generate a JSON summary from a hosts-like file:

```powershell
python hosts_editor.py --why-blocked-summary ads.example.com .\hosts.txt .\why-blocked.json
```

Include whitelist coverage:

```powershell
python hosts_editor.py --why-blocked-summary ads.example.com .\hosts.txt .\why-blocked.json --why-blocked-whitelist .\allowlist.txt
```

The CLI prints the text summary and writes the full JSON report. It does not read app config, fetch sources, or call providers.

## GUI Usage

Use **Tools > Why Blocked Summary...** or the editor context menu. The GUI version can include the current editor contents, saved whitelist, pinned domains, fetched-source cache, source report paths, and local provenance sidecar events.

## LLM Handoff

The report includes `llm_handoff.prompt_text` as a review artifact. HostsFileGet never submits it.

Before using that prompt outside the app:

- confirm the domain and evidence are in scope
- remove private source names, private URLs, incident names, or business context
- do not add API keys, full DNS logs, or unrelated hostnames
- treat generated prose as a review aid, not as permission to change policy

This boundary exists because LLM provider logs or application state may retain prompts, responses, or metadata depending on provider settings, and LLM applications can expose sensitive information if prompts are not sanitized. See roadmap sources `S54` and `S55`.

## Output Fields

- `offline`: always `true`
- `network_calls`: always `false`
- `llm_api_calls`: always `false`
- `status`: `blocked`, `source-only`, `not-blocked`, or `invalid`
- `confidence`: `direct-hosts-entry`, `fetched-source-match`, `no-local-block-evidence`, or `none`
- `evidence.blocked_on_lines`: bounded line previews from the local input
- `evidence.source_matches`: fetched source names, when available
- `evidence.provenance_events`: bounded local audit events, when available
- `llm_handoff`: prompt text plus redaction notes

## Related Tools

- `docs/false-positive-triage.md`
- `docs/entry-provenance.md`
- `docs/provenance-log.md`
- `docs/source-trust.md`
