import unittest

from hostsfileget import source_catalog
from hostsfileget.source_catalog import (
    SOURCE_HEALTH_REPORT_SCHEMA_VERSION,
    SOURCE_MANIFEST_SCHEMA_VERSION,
    SourceEntry,
    SourceHealthRecord,
    SourceRecord,
    build_source_health_remediation_report,
    build_source_health_diff,
    build_source_health_report,
    format_source_health_remediation_report,
    format_source_health_diff,
    sanitize_source_bundle_catalog,
    sanitize_source_manifest,
    source_entry_metadata,
)


class SourceCatalogTests(unittest.TestCase):
    def test_manifest_validation_preserves_source_records_and_metadata(self):
        manifest = {
            "schema_version": SOURCE_MANIFEST_SCHEMA_VERSION,
            "categories": [
                {
                    "name": "Ads",
                    "sources": [
                        {
                            "name": "Example Hosts",
                            "url": "https://example.com/hosts.txt",
                            "description": "Small test source.",
                            "lifecycle": "warning",
                            "lifecycle_reason": "Health sample needs review.",
                            "replacement_source": "Replacement Hosts",
                        }
                    ],
                }
            ],
        }

        sanitized = sanitize_source_manifest(manifest)
        entry = sanitized["Ads"][0]
        record = SourceRecord.from_entry("Ads", entry)

        self.assertIsInstance(entry, SourceEntry)
        self.assertEqual(entry, ("Example Hosts", "https://example.com/hosts.txt", "Small test source."))
        self.assertEqual(source_entry_metadata(entry)["lifecycle"], "warning")
        self.assertEqual(
            record.to_dict(),
            {
                "category": "Ads",
                "name": "Example Hosts",
                "url": "https://example.com/hosts.txt",
                "description": "Small test source.",
                "lifecycle": "warning",
                "metadata": {
                    "lifecycle": "warning",
                    "lifecycle_reason": "Health sample needs review.",
                    "lifecycle_checked_at": "",
                    "replacement_url": "",
                    "replacement_source": "Replacement Hosts",
                    "notes": "",
                },
            },
        )

    def test_bundle_catalog_rejects_retired_sources_at_source_layer(self):
        manifest = {
            "schema_version": SOURCE_MANIFEST_SCHEMA_VERSION,
            "categories": [
                {
                    "name": "Ads",
                    "sources": [
                        {
                            "name": "Retired Hosts",
                            "url": "https://example.com/retired.txt",
                            "description": "Retained for history.",
                            "lifecycle": "retired",
                            "lifecycle_reason": "HTTP 404 in baseline.",
                        }
                    ],
                }
            ],
            "bundles": [
                {
                    "id": "starter",
                    "name": "Starter",
                    "risk": "low",
                    "source_names": ["Retired Hosts"],
                }
            ],
        }

        with self.assertRaises(ValueError):
            sanitize_source_bundle_catalog(manifest)

    def test_source_health_report_uses_stable_health_record_shape(self):
        class FakeResponse:
            headers = {"Content-Type": "text/plain"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getcode(self):
                return 200

            def read(self, size):
                return b"0.0.0.0 tracker.example\n"

        report = build_source_health_report(
            {"Ads": [("Example", "https://example.com/hosts.txt", "Example source.")]},
            opener=lambda request, timeout=None: FakeResponse(),
            max_workers=1,
        )
        health = SourceHealthRecord.from_dict(report["sources"][0])

        self.assertEqual(report["schema_version"], SOURCE_HEALTH_REPORT_SCHEMA_VERSION)
        self.assertEqual(report["summary"], {"total": 1, "healthy": 1, "warning": 0, "failed": 0, "retired": 0})
        self.assertEqual(health.status, "healthy")
        self.assertEqual(health.to_dict()["diagnostic_class"], "ok")

    def test_source_health_diff_is_module_local_and_formatted(self):
        baseline = {
            "checked_at": "2026-05-17T00:00:00Z",
            "sources": [
                {"name": "One", "url": "https://one.example/list.txt", "status": "failed", "diagnostic": "HTTP 404."},
            ],
        }
        current = {
            "checked_at": "2026-05-18T00:00:00Z",
            "sources": [
                {"name": "One", "url": "https://one.example/list.txt", "status": "retired", "diagnostic": "Retired."},
            ],
        }

        diff = build_source_health_diff(current, baseline)

        self.assertEqual(diff["summary"]["improved"], 1)
        self.assertIn("One", format_source_health_diff(diff))

    def test_source_health_remediation_groups_unhealthy_sources(self):
        report = {
            "checked_at": "2026-05-17T00:00:00Z",
            "sources": [
                {
                    "category": "Ads",
                    "name": "Gone Feed",
                    "url": "https://github.com/example/lists/raw/main/gone.txt",
                    "status": "failed",
                    "diagnostic_class": "http-gone",
                    "diagnostic": "HTTP 404.",
                    "remediation": "Retire the source.",
                },
                {
                    "category": "Tracking",
                    "name": "Moved Feed",
                    "url": "https://example.com/feed",
                    "status": "failed",
                    "diagnostic_class": "html-response",
                    "diagnostic": "Source returned an HTML page instead of a list sample.",
                    "remediation": "Replace with a raw list URL.",
                },
                {
                    "category": "Threats",
                    "name": "Huge Feed",
                    "url": "https://example.com/huge.txt",
                    "status": "warning",
                    "diagnostic_class": "sample-cap",
                    "diagnostic": "Source is reachable, but the sample exceeded the cap.",
                },
                {
                    "category": "Threats",
                    "name": "Good Feed",
                    "url": "https://example.com/good.txt",
                    "status": "healthy",
                    "diagnostic_class": "ok",
                    "diagnostic": "Source is reachable.",
                },
            ],
        }

        grouped = build_source_health_remediation_report(report)
        rendered = format_source_health_remediation_report(grouped)
        group_ids = [group["id"] for group in grouped["groups"]]

        self.assertEqual(grouped["summary"]["grouped"], 3)
        self.assertIn("http-error", group_ids)
        self.assertIn("domain-list-moved", group_ids)
        self.assertIn("download-cap", group_ids)
        self.assertEqual(grouped["failed_urls"], [
            "https://github.com/example/lists/raw/main/gone.txt",
            "https://example.com/feed",
        ])
        self.assertIn("Gone Feed", grouped["search_terms"][0])
        self.assertIn("Domain List Moved", rendered)

    def test_source_health_remediation_groups_legacy_diagnostics(self):
        report = {
            "sources": [
                {
                    "name": "Legacy HTTP",
                    "url": "https://example.com/legacy.txt",
                    "status": "failed",
                    "diagnostic": "HTTP 500.",
                },
                {
                    "name": "Legacy Invalid",
                    "url": "ftp://example.com/list.txt",
                    "status": "failed",
                    "diagnostic": "Invalid source URL.",
                },
                {
                    "name": "Legacy Syntax",
                    "url": "https://example.com/readme.txt",
                    "status": "warning",
                    "diagnostic": "Source is reachable, but the sample did not contain host-like entries.",
                },
            ],
        }

        grouped = build_source_health_remediation_report(report)
        group_ids = [group["id"] for group in grouped["groups"]]

        self.assertEqual(group_ids, ["http-error", "non-host-syntax", "unsafe-scheme"])
        self.assertEqual(grouped["summary"]["grouped"], 3)

    def test_hosts_editor_reexports_source_catalog_boundary(self):
        import hosts_editor

        self.assertIs(hosts_editor.sanitize_source_manifest, source_catalog.sanitize_source_manifest)
        self.assertIs(hosts_editor.build_source_health_report, source_catalog.build_source_health_report)
        self.assertIs(hosts_editor.build_source_health_remediation_report, source_catalog.build_source_health_remediation_report)
        self.assertIs(hosts_editor.SourceRecord, source_catalog.SourceRecord)


if __name__ == "__main__":
    unittest.main()
