# Memory Consolidation - 2026-05-17

## Files Inspected

Instruction and memory files:

- User-provided `AGENTS.md` instructions for `C:\Users\--\Documents\Playground`.
- `C:\Users\--\.claude\CLAUDE.md`.
- `C:\Users\--\CLAUDE.md`.
- `C:\Users\--\.claude\projects\c--Users----repos\memory\MEMORY.md`.
- `C:\Users\--\.claude\projects\c--Users----repos\memory\stack-python.md`.
- `C:\Users\--\.claude\projects\c--Users----repos\memory\stack-powershell.md`.
- `C:\Users\--\.codex\memories\MEMORY.md`.
- Relevant Codex rollout summary for HostsFileGet roadmap/source-backed planning.
- Repo `AGENTS.md`.
- Repo `CLAUDE.md`.
- Repo `ROADMAP.md`.
- Repo `ARCHITECTURE.md`, `CHANGELOG.md`, `CODEX_CHANGELOG.md`, and `README.md`.

## Reconciled Instructions

Durable repo-specific facts:

- HostsFileGet is Windows-first.
- Main app is Python/Tkinter, with a PowerShell WPF launcher.
- Direct run is `python hosts_editor.py`.
- Launcher run is `.\PythonLauncher.ps1`.
- Primary verification is `python -m unittest discover -s tests -v`.
- The app has a strong local-first and safe-write philosophy.
- The app version in repo notes and runtime is v2.27.0.
- The current architecture is in the middle of a monolith-to-package extraction.

Working rules that affect future sessions:

- Read repo `CLAUDE.md` at session start.
- Check recent commits and current git state before trusting memory.
- Use real verification commands.
- Preserve unrelated worktree edits.
- Commit completed work.
- Avoid unsupported hedges when a user asks for implementation.
- Keep roadmap work moving unless blocked by a real ambiguity or critical error.

## Project Memory Consolidated Into `PROJECT_CONTEXT.md`

The following durable facts were moved into root `PROJECT_CONTEXT.md`:

- Product boundary and non-goals.
- Current repo shape.
- Extracted package modules.
- Current strengths.
- Current risks.
- Required session-start checklist.
- Recommended next pass.
- Research artifact directory.

## Stale Or Superseded Memory

The old `ROADMAP.md` was useful history but no longer a clear active roadmap because every F001-F070 implementation item was checked off. It also mixed shipped history, source appendix data, and future-looking signals in one large file.

Resolution:

- Replace root `ROADMAP.md` with a concise active plan.
- Preserve source-backed history through this research folder and source register.
- Keep old shipped details available through `git history`, `CHANGELOG.md`, `CODEX_CHANGELOG.md`, and docs.

## Conflicts And Resolutions

### `rtk git log -10`

Shared instructions requested `rtk git log -10`, but `rtk` was not installed in this shell.

Resolution:

- Document the missing tool.
- Use direct `git log -10 --oneline --decorate` for evidence.

### Auto-commit

Shared instructions and user prompt both favor committing completed work. The user prompt explicitly says to commit locally and continue. The global shared rules also expect push after completed repo work.

Resolution:

- Commit and push the final planning artifacts after verification, unless git/network credentials block push.

### Tool-specific files

Repo `AGENTS.md` says `CLAUDE.md` is the source of truth for working notes. User prompt asked to inspect both and optionally add pointers.

Resolution:

- Do not overwrite tool-specific files.
- Add canonical cross-session project context in root `PROJECT_CONTEXT.md`.
- Leave `AGENTS.md` and `CLAUDE.md` intact because `AGENTS.md` already points to `CLAUDE.md`, and the new context file can be discovered from `ROADMAP.md` and this research run.

## Open Conflicts

None that affect the roadmap. The only operational limitation was missing `rtk`.

## Future Memory Update Recommendation

If the user later asks to remember this run, record:

- 2026-05-17 created `PROJECT_CONTEXT.md`, replaced the active `ROADMAP.md`, added `.ai/research/2026-05-17/` research artifacts, and identified source catalog health plus source-catalog modularization as the next P0 work.
