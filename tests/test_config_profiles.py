import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import hosts_editor
from hostsfileget import config_profiles


class ConfigProfilesTests(unittest.TestCase):
    def test_hosts_editor_reexports_config_profile_boundary(self):
        self.assertIs(hosts_editor.sanitize_config_snapshot, config_profiles.sanitize_config_snapshot)
        self.assertIs(hosts_editor.set_active_profile_in_config, config_profiles.set_active_profile_in_config)
        self.assertIs(hosts_editor.build_config_location_report, config_profiles.build_config_location_report)
        self.assertIs(hosts_editor.parse_declarative_config_text, config_profiles.parse_declarative_config_text)
        self.assertIs(hosts_editor.sanitize_pinned_domains, config_profiles.sanitize_pinned_domains)

    def test_config_migration_and_profile_switch_are_module_local(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            migrated = config_profiles.sanitize_config_snapshot(
                {
                    "whitelist_domains": "legacy.example",
                    "block_sink": "127.0.0.1",
                    "profiles": [
                        {"id": "default", "name": "Default", "whitelist": "legacy.example"},
                        {
                            "id": "work",
                            "name": "Work",
                            "whitelist": "work.example",
                            "custom_sources": [
                                {"name": "Work Feed", "url": "https://example.com/work.txt"}
                            ],
                            "preferred_block_sink": "::1",
                        },
                    ],
                    "active_profile_id": "default",
                },
                tmpdir,
            )

            switched = config_profiles.set_active_profile_in_config(migrated, "work", tmpdir)

        self.assertEqual(migrated["config_version"], config_profiles.CONFIG_SCHEMA_VERSION)
        self.assertEqual(migrated["whitelist"], "legacy.example")
        self.assertEqual(migrated["preferred_block_sink"], "127.0.0.1")
        self.assertEqual(switched["active_profile_id"], "work")
        self.assertEqual(switched["whitelist"], "work.example")
        self.assertEqual(switched["preferred_block_sink"], "::1")
        self.assertEqual(switched["custom_sources"][0]["url"], "https://example.com/work.txt")

    def test_declarative_profile_import_export_round_trips_without_tk(self):
        profile = config_profiles.parse_declarative_config_text(
            "\n".join(
                [
                    'schema: "hostsfileget.declarative.v1"',
                    "profile:",
                    '  id: "family"',
                    '  name: "Family"',
                    '  preferred_block_sink: "0.0.0.0"',
                    "  whitelist:",
                    '    - "school.example"',
                    "  pinned_domains:",
                    '    - "safe.example"',
                    "  custom_sources:",
                    '    - name: "Family Feed"',
                    '      url: "https://example.com/family.txt"',
                ]
            ),
            "yaml",
        )
        rendered = config_profiles.format_declarative_config_payload(profile, "json")
        round_trip = config_profiles.parse_declarative_config_text(rendered, "json")

        self.assertEqual(round_trip["id"], "family")
        self.assertEqual(round_trip["whitelist"], "school.example")
        self.assertEqual(round_trip["pinned_domains"], ["safe.example"])
        self.assertEqual(round_trip["custom_sources"][0]["name"], "Family Feed")

    def test_portable_config_location_uses_sidecar_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            exe_dir = root / "portable"
            local_dir = root / "local"
            exe_dir.mkdir()
            local_dir.mkdir()

            with (
                mock.patch.object(config_profiles, "_EXE_DIR", str(exe_dir)),
                mock.patch.object(config_profiles, "get_app_config_dir", return_value=str(local_dir)),
            ):
                local_report = config_profiles.build_config_location_report()
                (exe_dir / config_profiles.CONFIG_FILENAME).write_text(
                    json.dumps({"whitelist": "portable.example"}),
                    encoding="utf-8",
                )
                portable_report = config_profiles.build_config_location_report()

        self.assertEqual(local_report["mode"], "local")
        self.assertEqual(local_report["sidecar_root"], str(local_dir))
        self.assertEqual(portable_report["mode"], "portable")
        self.assertEqual(portable_report["sidecar_root"], str(exe_dir))


if __name__ == "__main__":
    unittest.main()
