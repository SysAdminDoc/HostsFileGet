import bz2
import gzip
import unittest

from hosts_editor import (
    _get_canonical_cleaned_output_and_stats,
    compute_clean_impact_stats,
    decode_text_bytes,
    decode_downloaded_lines,
    normalize_line_to_hosts_entries,
    read_text_file_lines,
)


class HostsEditorLogicTests(unittest.TestCase):
    def test_multi_domain_hosts_line_expands_to_multiple_entries(self):
        entries, domains, transformed = normalize_line_to_hosts_entries("0.0.0.0 a.example b.example")
        self.assertEqual(entries, ["0.0.0.0 a.example", "0.0.0.0 b.example"])
        self.assertEqual(domains, ["a.example", "b.example"])
        self.assertTrue(transformed)

    def test_url_and_filter_syntax_are_normalized(self):
        url_entries, _, url_transformed = normalize_line_to_hosts_entries("http://phish.example/login")
        filter_entries, _, filter_transformed = normalize_line_to_hosts_entries("||tracker.example^$third-party")
        dnsmasq_entries, _, dnsmasq_transformed = normalize_line_to_hosts_entries("address=/telemetry.example/0.0.0.0")

        self.assertEqual(url_entries, ["0.0.0.0 phish.example"])
        self.assertEqual(filter_entries, ["0.0.0.0 tracker.example"])
        self.assertEqual(dnsmasq_entries, ["0.0.0.0 telemetry.example"])
        self.assertTrue(url_transformed)
        self.assertTrue(filter_transformed)
        self.assertTrue(dnsmasq_transformed)

    def test_clean_stats_do_not_go_negative(self):
        stats = compute_clean_impact_stats(["example.com"], set())

        self.assertEqual(stats["total_discarded"], 0)
        self.assertEqual(stats["final_active"], 1)
        self.assertEqual(stats["transformed"], 1)

    def test_cleaning_deduplicates_and_whitelists_multi_entry_lines(self):
        cleaned, stats = _get_canonical_cleaned_output_and_stats(
            [
                "0.0.0.0 keep.example duplicate.example",
                "duplicate.example",
                "http://whitelist.example/path",
                "127.0.0.1 localhost",
            ],
            {"whitelist.example"},
        )

        self.assertIn("0.0.0.0 keep.example", cleaned)
        self.assertIn("0.0.0.0 duplicate.example", cleaned)
        self.assertNotIn("0.0.0.0 whitelist.example", cleaned)
        self.assertEqual(stats["removed_duplicates"], 1)
        self.assertEqual(stats["removed_whitelist"], 1)
        self.assertEqual(stats["removed_invalid"], 1)
        self.assertEqual(stats["final_active"], 2)

    def test_decode_downloaded_lines_supports_compressed_payloads(self):
        text = "0.0.0.0 compressed.example\n"

        gzip_lines = decode_downloaded_lines(
            "https://example.com/hosts.txt.gz",
            gzip.compress(text.encode("utf-8")),
            "gzip",
        )
        bz2_lines = decode_downloaded_lines(
            "https://example.com/hosts.txt.bz2",
            bz2.compress(text.encode("utf-8")),
        )

        self.assertEqual(gzip_lines, ["0.0.0.0 compressed.example"])
        self.assertEqual(bz2_lines, ["0.0.0.0 compressed.example"])

    def test_decode_downloaded_lines_falls_back_when_header_is_wrong(self):
        lines = decode_downloaded_lines(
            "https://example.com/hosts.txt",
            b"0.0.0.0 raw.example\n",
            "gzip",
        )
        self.assertEqual(lines, ["0.0.0.0 raw.example"])

    def test_decode_text_bytes_supports_non_utf8_payloads(self):
        decoded = decode_text_bytes("0.0.0.0 cafe.example # café\n".encode("cp1252"))
        self.assertIn("café", decoded)

    def test_read_text_file_lines_supports_utf16(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "utf16-hosts.txt"
            path.write_text("0.0.0.0 utf16.example\n", encoding="utf-16")
            self.assertEqual(read_text_file_lines(str(path)), ["0.0.0.0 utf16.example"])


if __name__ == "__main__":
    unittest.main()
