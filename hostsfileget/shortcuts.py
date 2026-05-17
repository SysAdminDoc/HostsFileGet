"""Keyboard shortcut and command-entry reference data."""

from __future__ import annotations


GLOBAL_KEYBOARD_SHORTCUTS = (
    {
        "keys": "Ctrl+F",
        "sequences": ("<Control-f>",),
        "scope": "Global",
        "action": "Focus search",
        "handler": "_focus_search_shortcut",
        "widget": "root",
    },
    {
        "keys": "Ctrl+S",
        "sequences": ("<Control-s>",),
        "scope": "Global",
        "action": "Save cleaned",
        "handler": "_save_cleaned_shortcut",
        "widget": "root",
    },
    {
        "keys": "Ctrl+Shift+S",
        "sequences": ("<Control-Shift-s>", "<Control-Shift-S>"),
        "scope": "Global",
        "action": "Save raw",
        "handler": "_save_raw_shortcut",
        "widget": "root",
    },
    {
        "keys": "F5",
        "sequences": ("<F5>",),
        "scope": "Global",
        "action": "Refresh from disk",
        "handler": "_refresh_shortcut",
        "widget": "root",
    },
    {
        "keys": "Ctrl+P",
        "sequences": ("<Control-p>",),
        "scope": "Global",
        "action": "Open Goto Anything",
        "handler": "show_goto_anything",
        "widget": "root",
    },
    {
        "keys": "Ctrl+H",
        "sequences": ("<Control-h>", "<Control-H>"),
        "scope": "Global",
        "action": "Open Find and Replace",
        "handler": "show_find_replace_dialog",
        "widget": "root",
    },
    {
        "keys": "Ctrl+/",
        "sequences": ("<Control-slash>",),
        "scope": "Editor",
        "action": "Toggle comment on selection",
        "handler": "toggle_selection_comment",
        "widget": "text_area",
    },
)


COMMAND_ENTRY_POINT_GROUPS = (
    {
        "area": "File menu",
        "entry_points": (
            "Save Raw",
            "Save Cleaned",
            "Refresh",
            "Revert to Backup",
            "Compare Backups",
            "Panic Restore",
            "Export Cleaned As",
            "Disable / Enable Hosts",
        ),
    },
    {
        "area": "Tools menu",
        "entry_points": (
            "Clean",
            "Normalize & Deduplicate",
            "Flush DNS",
            "Targeted Cleanup",
            "Check Domain",
            "Entry Provenance",
            "Hosts Health Scan",
            "Adblock Syntax Lint",
            "Rule Tier Report",
            "IDN / Homograph Report",
            "CT / Typosquat Watchdog",
            "CTI Enrichment Plans",
            "TLS Certificate Preview",
            "Why Blocked Summary",
            "Source Health Remediation",
            "Source Freshness & Growth",
            "Goto Anything",
            "Find and Replace",
            "Schedule Auto-Update",
            "Preferences",
        ),
    },
    {
        "area": "Import logs menu",
        "entry_points": (
            "pfSense DNSBL",
            "NextDNS CSV",
            "Control D CSV",
            "Pi-hole FTL",
            "AdGuard Home query log",
            "Windows DNS Client snapshot",
        ),
    },
    {
        "area": "Migration imports menu",
        "entry_points": (
            "SwitchHosts export",
            "Gas Mask archive",
            "HostsFileEditor archive",
        ),
    },
    {
        "area": "Editor context menu",
        "entry_points": (
            "Pin or unpin domain",
            "Whitelist this domain",
            "Copy domain",
            "Toggle comment",
            "Remove this line",
            "Resolve domain",
            "Ping domain",
            "Check this domain",
            "Why blocked summary",
            "Entry provenance",
        ),
    },
    {
        "area": "Command line",
        "entry_points": (
            "--version",
            "--help",
            "--source-health",
            "--update",
            "--backup",
            "--apply",
            "--config-plan / --config-apply / --config-export",
            "--integration-export",
            "--managed-package-export",
            "--adblock-lint",
        ),
    },
)


def shortcut_rows() -> tuple[dict, ...]:
    return tuple(dict(row) for row in GLOBAL_KEYBOARD_SHORTCUTS)


def command_entry_point_rows() -> tuple[dict, ...]:
    return tuple(
        {"area": group["area"], "entry_points": tuple(group["entry_points"])}
        for group in COMMAND_ENTRY_POINT_GROUPS
    )


def validate_shortcut_registry(shortcuts: tuple[dict, ...] = GLOBAL_KEYBOARD_SHORTCUTS) -> list[str]:
    errors: list[str] = []
    seen_keys: dict[str, str] = {}
    seen_sequences: dict[str, str] = {}
    for shortcut in shortcuts:
        keys = str(shortcut.get("keys", "")).strip()
        action = str(shortcut.get("action", "")).strip()
        handler = str(shortcut.get("handler", "")).strip()
        widget = str(shortcut.get("widget", "")).strip()
        sequences = tuple(shortcut.get("sequences") or ())
        if not keys or not action or not handler or not widget or not sequences:
            errors.append(f"Shortcut row is incomplete: {shortcut!r}")
            continue
        if keys in seen_keys:
            errors.append(f"Shortcut key {keys!r} is duplicated for {seen_keys[keys]!r} and {action!r}.")
        seen_keys[keys] = action
        for sequence in sequences:
            sequence = str(sequence).strip()
            if not sequence:
                errors.append(f"Shortcut {keys!r} has an empty Tk sequence.")
                continue
            if sequence in seen_sequences:
                errors.append(
                    f"Tk sequence {sequence!r} is duplicated for {seen_sequences[sequence]!r} and {keys!r}."
                )
            seen_sequences[sequence] = keys
    return errors


def format_shortcut_markdown_table(shortcuts: tuple[dict, ...] = GLOBAL_KEYBOARD_SHORTCUTS) -> str:
    lines = [
        "| Shortcut | Scope | Action | Handler |",
        "| --- | --- | --- | --- |",
    ]
    for shortcut in shortcuts:
        lines.append(
            "| {keys} | {scope} | {action} | `{handler}` |".format(
                keys=shortcut["keys"],
                scope=shortcut["scope"],
                action=shortcut["action"],
                handler=shortcut["handler"],
            )
        )
    return "\n".join(lines)


def format_command_entry_markdown_table(groups: tuple[dict, ...] = COMMAND_ENTRY_POINT_GROUPS) -> str:
    lines = [
        "| Area | Entry Points |",
        "| --- | --- |",
    ]
    for group in groups:
        lines.append(f"| {group['area']} | {', '.join(group['entry_points'])} |")
    return "\n".join(lines)
