import unittest
from pathlib import Path

from scripts.audit_cli_contract import (
    audit_cli_contract,
    load_cli_contract_snapshot,
    render_cli_help,
)


class CliContractSnapshotTests(unittest.TestCase):
    def test_cli_contract_snapshot_is_current(self):
        repo_root = Path(__file__).resolve().parents[1]
        self.assertEqual(audit_cli_contract(repo_root), [])

    def test_help_snapshot_has_stable_sections(self):
        repo_root = Path(__file__).resolve().parents[1]
        snapshot = load_cli_contract_snapshot(repo_root)
        help_text = render_cli_help()

        section_ids = {section["id"] for section in snapshot["help_sections"]}
        self.assertIn("hosts-file-write-safety", section_ids)
        self.assertIn("plan-only-platform-handoffs", section_ids)
        self.assertIn("--source-cache-prune", help_text)
        self.assertIn("--why-blocked-summary DOMAIN INPUT OUTPUT", help_text)


if __name__ == "__main__":
    unittest.main()
