# Keyboard and Command Reference

This page is the canonical shortcut and command-entry reference for the desktop app. The source data lives in `hostsfileget/shortcuts.py`, and `scripts/audit_shortcuts.py` checks this page plus the README without starting Tkinter.

## Keyboard Shortcuts

| Shortcut | Scope | Action | Handler |
| --- | --- | --- | --- |
| Ctrl+F | Global | Focus search | `_focus_search_shortcut` |
| Ctrl+S | Global | Save cleaned | `_save_cleaned_shortcut` |
| Ctrl+Shift+S | Global | Save raw | `_save_raw_shortcut` |
| F5 | Global | Refresh from disk | `_refresh_shortcut` |
| Ctrl+P | Global | Open Goto Anything | `show_goto_anything` |
| Ctrl+H | Global | Open Find and Replace | `show_find_replace_dialog` |
| Ctrl+/ | Editor | Toggle comment on selection | `toggle_selection_comment` |

## Command Entry Points

| Area | Entry Points |
| --- | --- |
| File menu | Save Raw, Save Cleaned, Refresh, Revert to Backup, Compare Backups, Panic Restore, Export Cleaned As, Disable / Enable Hosts |
| Tools menu | Clean, Normalize & Deduplicate, Flush DNS, Targeted Cleanup, Check Domain, Entry Provenance, Hosts Health Scan, Adblock Syntax Lint, Rule Tier Report, IDN / Homograph Report, CT / Typosquat Watchdog, CTI Enrichment Plans, TLS Certificate Preview, Why Blocked Summary, Source Health Remediation, Source Freshness & Growth, Goto Anything, Find and Replace, Schedule Auto-Update, Preferences |
| Import logs menu | pfSense DNSBL, NextDNS CSV, Control D CSV, Pi-hole FTL, AdGuard Home query log, Windows DNS Client snapshot |
| Migration imports menu | SwitchHosts export, Gas Mask archive, HostsFileEditor archive |
| Editor context menu | Pin or unpin domain, Whitelist this domain, Copy domain, Toggle comment, Remove this line, Resolve domain, Ping domain, Check this domain, Why blocked summary, Entry provenance |
| Command line | --version, --help, --source-health, --update, --backup, --apply, --config-plan / --config-apply / --config-export, --integration-export, --managed-package-export, --adblock-lint |

## Maintenance

When a shortcut or major command entry point changes:

1. Update `hostsfileget/shortcuts.py`.
2. Update this page and the README shortcut list.
3. Run `python scripts\audit_shortcuts.py`.
