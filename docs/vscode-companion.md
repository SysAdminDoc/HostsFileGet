# VS Code Companion Export

HostsFileGet can export a guarded Visual Studio Code companion extension scaffold. This is an artifact-only workflow: HostsFileGet writes files for review, but it does not install VS Code extensions, run VS Code, create VSIX packages, publish to the Marketplace, or call remote services.

## Command

```powershell
python hosts_editor.py --vscode-extension-export .\vscode-hostsfileget-companion
python hosts_editor.py --vscode-extension-export .\vscode-hostsfileget-companion --vscode-extension-name hfg-companion --vscode-extension-version 0.2.0 --vscode-api-base-url http://127.0.0.1:8765
```

Generated artifacts:

- `package.json`
- `extension.js`
- `README.md`
- `.vscodeignore`
- `vscode-companion-export-plan.json`

The plan JSON uses schema `hostsfileget.vscode-companion-export.v1`, records `execution: not-run`, and lists the source IDs used by the roadmap.

## Runtime Boundary

The generated extension talks only to the opt-in HostsFileGet local REST API:

- `GET /v1/status`
- `POST /v1/clean-preview`

It enforces a loopback API base URL (`localhost`, `127.0.0.1`, or `::1`). The generated commands are read-only: status checks only read API metadata, and clean preview opens a new unsaved editor document instead of writing the Windows hosts file.

Before testing the generated extension, start the local API explicitly:

```powershell
$env:HOSTSFILEGET_API_TOKEN = "replace-with-at-least-16-random-chars"
python hosts_editor.py --api-serve
```

Use `HostsFileGet: Set API Token` inside VS Code to store the token with VS Code SecretStorage, or set `HOSTSFILEGET_API_TOKEN` in the VS Code extension host environment for local testing.

## Generated Commands

- `HostsFileGet: Show Local API Status`
- `HostsFileGet: Clean Preview Selection`
- `HostsFileGet: Set API Token`
- `HostsFileGet: Clear API Token`

## Review Checklist

- Keep `hostsfileget.apiBaseUrl` pointed at loopback only.
- Confirm the API is started with an explicit bearer token.
- Review `extension.js` before packaging or sharing.
- Package and publish with normal VS Code extension tooling only after local review.
- Do not add write endpoints to the extension unless the local API threat model is revisited.

## Source Basis

- VS Code extension anatomy: `https://code.visualstudio.com/api/get-started/extension-anatomy`
- VS Code extension manifest reference: `https://code.visualstudio.com/api/references/extension-manifest`
- VS Code command guide: `https://code.visualstudio.com/api/extension-guides/command`
- VS Code Workspace Trust guide: `https://code.visualstudio.com/api/extension-guides/workspace-trust`
- VS Code SecretStorage API: `https://code.visualstudio.com/api/references/vscode-api#SecretStorage`
- VS Code publishing guide: `https://code.visualstudio.com/api/working-with-extensions/publishing-extension`
