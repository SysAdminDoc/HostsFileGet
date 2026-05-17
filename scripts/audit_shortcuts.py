"""Audit shortcut and command-entry documentation without starting the GUI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hostsfileget.shortcuts import (
    COMMAND_ENTRY_POINT_GROUPS,
    GLOBAL_KEYBOARD_SHORTCUTS,
    format_command_entry_markdown_table,
    format_shortcut_markdown_table,
    validate_shortcut_registry,
)


DOC_PATHS = (
    "README.md",
    "docs/keyboard-and-commands.md",
)


def audit_shortcut_docs(repo_root: Path) -> list[str]:
    errors = validate_shortcut_registry()
    docs = {
        relative_path: (repo_root / relative_path).read_text(encoding="utf-8")
        for relative_path in DOC_PATHS
    }
    for shortcut in GLOBAL_KEYBOARD_SHORTCUTS:
        key = shortcut["keys"]
        for relative_path, text in docs.items():
            if key not in text:
                errors.append(f"{relative_path} does not document shortcut {key}.")
    reference = docs["docs/keyboard-and-commands.md"]
    for group in COMMAND_ENTRY_POINT_GROUPS:
        if group["area"] not in reference:
            errors.append(f"docs/keyboard-and-commands.md does not document {group['area']}.")
        for entry_point in group["entry_points"]:
            if entry_point not in reference:
                errors.append(
                    "docs/keyboard-and-commands.md does not document "
                    f"{group['area']} entry point {entry_point!r}."
                )
    return errors


def build_markdown_reference() -> str:
    return "\n\n".join([
        "## Keyboard Shortcuts",
        format_shortcut_markdown_table(),
        "## Command Entry Points",
        format_command_entry_markdown_table(),
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit HostsFileGet shortcut and command-entry documentation.")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--markdown", action="store_true", help="Print the generated shortcut/command tables.")
    args = parser.parse_args(argv)

    if args.markdown:
        print(build_markdown_reference())
        return 0

    repo_root = Path(args.repo_root).resolve()
    errors = audit_shortcut_docs(repo_root)
    if errors:
        for error in errors:
            print(f"shortcut-audit: {error}", file=sys.stderr)
        return 1
    print("Shortcut and command documentation OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
