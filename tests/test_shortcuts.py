import unittest
from pathlib import Path

import hosts_editor
from hostsfileget.shortcuts import (
    GLOBAL_KEYBOARD_SHORTCUTS,
    format_command_entry_markdown_table,
    format_shortcut_markdown_table,
    validate_shortcut_registry,
)
from scripts.audit_shortcuts import audit_shortcut_docs


class ShortcutRegistryTests(unittest.TestCase):
    def test_shortcut_registry_is_complete_and_handlers_exist(self):
        self.assertEqual(validate_shortcut_registry(), [])
        for shortcut in GLOBAL_KEYBOARD_SHORTCUTS:
            with self.subTest(shortcut=shortcut["keys"]):
                self.assertIn(shortcut["widget"], {"root", "text_area"})
                self.assertTrue(hasattr(hosts_editor.HostsFileEditor, shortcut["handler"]))

    def test_shortcut_and_command_markdown_tables_are_generated(self):
        shortcut_table = format_shortcut_markdown_table()
        command_table = format_command_entry_markdown_table()

        self.assertIn("Ctrl+H", shortcut_table)
        self.assertIn("Ctrl+/", shortcut_table)
        self.assertIn("Source Health Remediation", command_table)
        self.assertIn("--source-health", command_table)

    def test_shortcut_documentation_is_current(self):
        repo_root = Path(__file__).resolve().parents[1]
        self.assertEqual(audit_shortcut_docs(repo_root), [])


if __name__ == "__main__":
    unittest.main()
