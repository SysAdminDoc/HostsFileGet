# prompt_toolkit TUI

HostsFileGet includes an optional terminal UI entry point for source-checking, profile review, and local clean-preview workflows from a keyboard-first shell. It is dependency-gated and is not part of the default GUI or CLI runtime.

## Install

```powershell
python -m pip install -r requirements-tui.txt
```

The optional requirement is `prompt_toolkit>=3.0.52,<4`. Normal GUI launch, non-interactive CLI commands, PyInstaller builds, and scheduled updates do not require it.

## Commands

Print dependency and safety status without launching the TUI:

```powershell
python hosts_editor.py --tui-status
```

Start the optional prompt shell:

```powershell
python hosts_editor.py --tui
```

Available TUI commands:

- `status` - show dependency, safety boundary, and command list.
- `profiles` - list saved app profiles without writing the hosts file.
- `config` - show active config location and sidecar paths.
- `sources` - list manifest-defined source bundles.
- `clean-preview <path>` - parse and clean a local hosts-like text file, then print a bounded preview.
- `health` - print the non-interactive `--source-health` command to run outside the TUI.
- `api` - print the opt-in local REST API startup command.
- `quit` - exit.

## Safety Boundary

- The TUI never writes the Windows hosts file.
- The TUI does not start background imports, source-health workers, schedulers, or the local REST API.
- `clean-preview <path>` reads a local file and runs the same deterministic clean-preview logic used by the local REST API, but it does not write output.
- Any action that mutates the system hosts file still belongs in the existing reviewed GUI or explicit admin-gated CLI paths.

## Source Basis

- hBlock terminal-first automation and source lookup precedent: `https://github.com/hectorm/hblock`
- dnscrypt-proxy blocklist-builder and terminal workflow precedent: `https://github.com/DNSCrypt/dnscrypt-proxy`
- prompt_toolkit package metadata: `https://pypi.org/pypi/prompt_toolkit/`
- prompt_toolkit full-screen application docs: `https://python-prompt-toolkit.readthedocs.io/en/master/pages/full_screen_apps.html`
- prompt_toolkit prompt/input docs: `https://python-prompt-toolkit.readthedocs.io/en/master/pages/asking_for_input.html`
- prompt_toolkit key-binding docs: `https://python-prompt-toolkit.readthedocs.io/en/master/pages/advanced_topics/key_bindings.html`
