import bz2
import gzip
import os
import queue
import threading
import unittest
from unittest import mock

import hosts_editor
from hosts_editor import (
    HostsFileEditor,
    _get_canonical_cleaned_output_and_stats,
    count_nonempty_lines,
    compute_clean_impact_stats,
    decode_text_bytes,
    decode_downloaded_lines,
    find_keyword_match_line_indices,
    looks_like_html_document,
    normalize_line_to_hosts_entries,
    normalize_custom_source_url,
    read_text_file_lines,
    remove_lines_by_indices,
    resolve_saved_state_hashes,
    sanitize_config_snapshot,
    sanitize_custom_sources,
    summarize_clean_changes,
    write_text_file_atomic,
)


class HostsEditorLogicTests(unittest.TestCase):
    def test_multi_domain_hosts_line_expands_to_multiple_entries(self):
        entries, domains, transformed = normalize_line_to_hosts_entries("0.0.0.0 a.example b.example")
        self.assertEqual(entries, ["0.0.0.0 a.example", "0.0.0.0 b.example"])
        self.assertEqual(domains, ["a.example", "b.example"])
        self.assertTrue(transformed)

    def test_custom_ip_mappings_are_preserved_during_normalization(self):
        entries, domains, transformed = normalize_line_to_hosts_entries("192.168.1.10 nas printer")
        self.assertEqual(entries, ["192.168.1.10 nas", "192.168.1.10 printer"])
        self.assertEqual(domains, ["nas", "printer"])
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

    def test_count_nonempty_lines_ignores_blank_rows(self):
        self.assertEqual(count_nonempty_lines("\nalpha\n \n beta \n"), 2)

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

    def test_cleaning_preserves_custom_mappings_when_whitelisted(self):
        cleaned, stats = _get_canonical_cleaned_output_and_stats(
            [
                "192.168.1.10 nas",
                "0.0.0.0 ads.example",
            ],
            {"nas", "ads.example"},
        )

        self.assertIn("192.168.1.10 nas", cleaned)
        self.assertNotIn("0.0.0.0 ads.example", cleaned)
        self.assertEqual(stats["removed_whitelist"], 1)
        self.assertEqual(stats["final_active"], 1)

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

    def test_sanitize_custom_sources_removes_invalid_and_duplicate_entries(self):
        sanitized = sanitize_custom_sources(
            [
                {"name": "Alpha", "url": "https://example.com/list.txt"},
                {"name": "alpha", "url": "https://different.example.com/list.txt"},
                {"name": "Beta", "url": "https://example.com/list.txt/"},
                {"name": "", "url": "https://missing-name.example/list.txt"},
                {"name": "Gamma", "url": "ftp://invalid.example/list.txt"},
                "not-a-dict",
            ]
        )

        self.assertEqual(
            sanitized,
            [{"name": "Alpha", "url": "https://example.com/list.txt"}],
        )
        self.assertEqual(
            normalize_custom_source_url("https://example.com/list.txt/"),
            "https://example.com/list.txt",
        )
        self.assertEqual(
            normalize_custom_source_url("HTTPS://Example.com/Path/File.TXT/?a=1#fragment"),
            "https://example.com/Path/File.TXT?a=1",
        )

    def test_find_keyword_match_line_indices_skips_comments_and_blanks(self):
        lines = [
            "",
            "# tracker.example comment",
            "0.0.0.0 tracker.example",
            "0.0.0.0 keep.example",
            "0.0.0.0 another-tracker.example",
        ]

        self.assertEqual(find_keyword_match_line_indices(lines, "tracker"), [2, 4])

    def test_remove_lines_by_indices_removes_selected_entries(self):
        lines = ["a", "b", "c", "d"]
        self.assertEqual(remove_lines_by_indices(lines, {1, 3}), ["a", "c"])

    def test_resolve_saved_state_hashes_preserves_known_saved_states(self):
        self.assertEqual(
            resolve_saved_state_hashes("clean-hash", "raw-hash", "clean-hash"),
            (None, "clean-hash"),
        )
        self.assertEqual(
            resolve_saved_state_hashes("raw-hash", "raw-hash", "clean-hash"),
            ("raw-hash", None),
        )
        self.assertEqual(
            resolve_saved_state_hashes("external-change", "raw-hash", "clean-hash"),
            ("external-change", None),
        )

    def test_sanitize_config_snapshot_recovers_from_malformed_values(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            payload = sanitize_config_snapshot(
                {
                    "whitelist": [" keep.example ", "", "other.example"],
                    "custom_sources": [
                        {"name": "Alpha", "url": "https://example.com/list.txt"},
                        {"name": "alpha", "url": "https://duplicate.example/list.txt"},
                    ],
                    "last_applied_raw_hash": 123,
                    "last_applied_cleaned_hash": " cleaned-hash ",
                    "last_open_dir": os.path.join(tmpdir, "missing"),
                },
                tmpdir,
            )

        self.assertEqual(payload["whitelist"], "keep.example\nother.example")
        self.assertEqual(
            payload["custom_sources"],
            [{"name": "Alpha", "url": "https://example.com/list.txt"}],
        )
        self.assertIsNone(payload["last_applied_raw_hash"])
        self.assertEqual(payload["last_applied_cleaned_hash"], "cleaned-hash")
        self.assertEqual(payload["last_open_dir"], tmpdir)

    def test_sanitize_config_snapshot_uses_safe_fallback_open_dir(self):
        payload = sanitize_config_snapshot(
            {"last_open_dir": "C:/definitely/missing/path"},
            "C:/also/missing/path",
        )

        self.assertTrue(os.path.isdir(payload["last_open_dir"]))

    def test_write_text_file_atomic_replaces_file_contents(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "hosts.txt"
            path.write_text("old", encoding="utf-8")
            write_text_file_atomic(str(path), "new content")
            self.assertEqual(path.read_text(encoding="utf-8"), "new content")

    def test_summarize_clean_changes_formats_consistent_status_text(self):
        self.assertEqual(
            summarize_clean_changes(3, 2),
            "Removed 3 entries and normalized 2 line(s).",
        )
        self.assertEqual(
            summarize_clean_changes(3, 0),
            "Removed 3 entries.",
        )
        self.assertEqual(
            summarize_clean_changes(0, 2),
            "Normalized 2 line(s).",
        )
        self.assertEqual(
            summarize_clean_changes(0, 0),
            "No normalization changes were needed.",
        )

    def test_summarize_failure_messages_truncates_long_lists(self):
        editor = HostsFileEditor.__new__(HostsFileEditor)
        summary = HostsFileEditor._summarize_failure_messages(
            editor,
            [
                "Alpha: timeout",
                "Beta: 403",
                "Gamma: HTML",
            ],
            limit=2,
        )

        self.assertEqual(
            summary,
            "- Alpha: timeout\n- Beta: 403\n- ...and 1 more",
        )

    def test_looks_like_html_document_detects_error_pages(self):
        self.assertTrue(
            looks_like_html_document(
                [
                    "<!DOCTYPE html>",
                    "<html>",
                    "<head><title>Access denied</title></head>",
                    "<body>Blocked</body>",
                ]
            )
        )
        self.assertFalse(
            looks_like_html_document(
                [
                    "# comment",
                    "0.0.0.0 ads.example",
                    "0.0.0.0 tracker.example",
                ]
            )
        )

    def test_import_worker_cancels_if_stop_requested_during_final_download(self):
        class FakeEditor:
            def __init__(self):
                self.import_queue = queue.Queue()
                self.stop_import_flag = threading.Event()

            def _apply_import_mode_filter(self, source_name, lines, mode):
                return lines

        class FakeResponse:
            def __init__(self, editor):
                self.editor = editor
                self.headers = {}
                self.info = lambda: {}
                self.fp = None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getcode(self):
                return 200

            def read(self):
                self.editor.stop_import_flag.set()
                return b"0.0.0.0 cancelled.example\n"

        editor = FakeEditor()

        with mock.patch.object(hosts_editor.urllib.request, "urlopen", return_value=FakeResponse(editor)):
            HostsFileEditor._import_worker_thread(
                editor,
                [("Only Source", "https://example.com/list.txt")],
                "Raw",
            )

        messages = []
        while not editor.import_queue.empty():
            messages.append(editor.import_queue.get_nowait()[0])

        self.assertEqual(messages, ["progress", "cancelled"])

    def test_on_closing_does_not_cancel_import_if_user_aborts_close(self):
        class FakeRoot:
            def __init__(self):
                self.destroy_called = False

            def destroy(self):
                self.destroy_called = True

        class FakeEditor:
            def __init__(self):
                self.is_importing = True
                self.stop_import_flag = threading.Event()
                self.root = FakeRoot()
                self.save_config_called = False

            def _has_unsaved_changes(self):
                return True

            def save_config(self):
                self.save_config_called = True

        editor = FakeEditor()

        with mock.patch.object(hosts_editor.messagebox, "askyesno", side_effect=[True, False]):
            HostsFileEditor.on_closing(editor)

        self.assertFalse(editor.stop_import_flag.is_set())
        self.assertFalse(editor.root.destroy_called)
        self.assertFalse(editor.save_config_called)


if __name__ == "__main__":
    unittest.main()
