import bz2
import gzip
import io
import os
import queue
import threading
import unittest
from unittest import mock

import datetime

import hosts_editor
from hosts_editor import (
    AGH_BLOCK_REASONS,
    BLOCK_SINK_IPS,
    FTL_BLOCKED_STATUS_CODES,
    HostsFileEditor,
    STALE_FRESH_HOURS,
    STALE_WARN_HOURS,
    build_pinned_export_payload,
    classify_source_freshness,
    parse_pinned_import_payload,
    IPV4_REGEX,
    MAX_DOWNLOAD_BYTES,
    STOCK_MICROSOFT_HOSTS,
    _default_hosts_file_path,
    _get_canonical_cleaned_output_and_stats,
    _looks_like_ip_token,
    _sqlite_readonly_uri,
    apply_find_replace,
    count_nonempty_lines,
    compute_clean_impact_stats,
    decode_text_bytes,
    decode_downloaded_lines,
    disable_hosts_file_transactionally,
    enable_hosts_file_transactionally,
    discover_import_sections,
    fuzzy_score,
    parse_adguard_home_querylog,
    parse_pihole_ftl_blocked_domains,
    summarize_source_contributions,
    export_lines_as_format,
    find_keyword_match_line_indices,
    find_sources_containing_domain,
    format_relative_time,
    build_schtasks_create_command,
    looks_like_domain,
    looks_like_html_document,
    normalize_scheduler_start_time,
    normalize_line_to_hosts_entries,
    normalize_custom_source_url,
    read_http_body_limited,
    read_text_file_lines,
    remove_import_section,
    remove_lines_by_indices,
    resolve_saved_state_hashes,
    rewrite_block_sink_ip,
    sanitize_config_snapshot,
    sanitize_custom_sources,
    sanitize_pinned_domains,
    scan_suspicious_redirects,
    strip_lines_by_category,
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

    def test_sanitize_custom_sources_rejects_hostless_http_urls(self):
        sanitized = sanitize_custom_sources(
            [
                {"name": "MissingHost", "url": "https:///missing-host"},
                {"name": "Good", "url": "https://example.com/list.txt"},
            ]
        )
        self.assertEqual(sanitized, [{"name": "Good", "url": "https://example.com/list.txt"}])

    def test_find_sources_containing_domain_accepts_structured_cache_entries(self):
        source_cache = {
            "https://one.example/list.txt": {
                "name": "Curated One",
                "url": "https://one.example/list.txt",
                "text": "0.0.0.0 tracked.example\n",
            },
            "https://two.example/list.txt": {
                "name": "Saved Two",
                "url": "https://two.example/list.txt",
                "text": "0.0.0.0 sub.tracked.example\n",
            },
        }
        self.assertEqual(
            find_sources_containing_domain("tracked.example", source_cache),
            ["Curated One", "Saved Two"],
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

        valid_sha256 = "a" * 64
        padded_sha256 = "  " + ("b" * 64) + "  "

        with tempfile.TemporaryDirectory() as tmpdir:
            payload = sanitize_config_snapshot(
                {
                    "whitelist": [" keep.example ", "", "other.example"],
                    "custom_sources": [
                        {"name": "Alpha", "url": "https://example.com/list.txt"},
                        {"name": "alpha", "url": "https://duplicate.example/list.txt"},
                    ],
                    "last_applied_raw_hash": 123,
                    "last_applied_cleaned_hash": padded_sha256,
                    "last_open_dir": os.path.join(tmpdir, "missing"),
                },
                tmpdir,
            )

        self.assertEqual(payload["whitelist"], "keep.example\nother.example")
        self.assertEqual(
            payload["custom_sources"],
            [{"name": "Alpha", "url": "https://example.com/list.txt"}],
        )
        # Integer hash from a corrupt config is rejected.
        self.assertIsNone(payload["last_applied_raw_hash"])
        # Whitespace-padded valid hash is accepted and stripped.
        self.assertEqual(payload["last_applied_cleaned_hash"], "b" * 64)
        self.assertEqual(payload["last_open_dir"], tmpdir)

    def test_sanitize_config_snapshot_rejects_non_sha256_hashes(self):
        payload = sanitize_config_snapshot(
            {
                # Too short.
                "last_applied_raw_hash": "abc123",
                # Right length, wrong alphabet.
                "last_applied_cleaned_hash": "Z" * 64,
            },
            os.getcwd(),
        )
        self.assertIsNone(payload["last_applied_raw_hash"])
        self.assertIsNone(payload["last_applied_cleaned_hash"])

    def test_sanitize_config_snapshot_uses_safe_fallback_open_dir(self):
        payload = sanitize_config_snapshot(
            {"last_open_dir": "C:/definitely/missing/path"},
            "C:/also/missing/path",
        )

        self.assertTrue(os.path.isdir(payload["last_open_dir"]))

    def test_get_legacy_config_paths_ignores_current_working_directory(self):
        fake_editor = type(
            "FakeEditor",
            (),
            {
                "CONFIG_FILENAME": "hosts_editor_config.json",
                "config_path": os.path.join("C:\\stable", "hosts_editor_config.json"),
            },
        )()

        with mock.patch.object(hosts_editor, "_EXE_DIR", "C:\\appdir"):
            with mock.patch.object(hosts_editor.os, "getcwd", return_value="C:\\surprising-cwd"):
                paths = HostsFileEditor._get_legacy_config_paths(fake_editor)

        self.assertEqual(paths, [os.path.join("C:\\appdir", "hosts_editor_config.json")])

    def test_write_text_file_atomic_replaces_file_contents(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "hosts.txt"
            path.write_text("old", encoding="utf-8")
            write_text_file_atomic(str(path), "new content")
            # Atomic write terminates the file with a newline for POSIX
            # compatibility; the round-trip through splitlines still
            # preserves the original lines.
            self.assertEqual(path.read_text(encoding="utf-8"), "new content\n")

    def test_write_text_file_atomic_preserves_existing_trailing_newline(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "hosts.txt"
            write_text_file_atomic(str(path), "already terminated\n")
            # We must not double-append a newline.
            self.assertEqual(path.read_text(encoding="utf-8"), "already terminated\n")

    def test_write_text_file_atomic_preserves_hash_round_trip(self):
        """Writing then reading back must produce the same splitlines hash.

        Regression: when we added the trailing-newline terminator we had to
        make sure that ``'\\n'.join(lines)`` produces the same hash as the
        splitlines result after read-back. Otherwise every saved file would
        immediately flag as "unsaved changes".
        """
        import hashlib
        import tempfile
        from pathlib import Path

        lines = ["0.0.0.0 a.example", "0.0.0.0 b.example", "0.0.0.0 c.example"]
        original_hash = hashlib.sha256('\n'.join(lines).encode('utf-8')).hexdigest()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "hosts.txt"
            write_text_file_atomic(str(path), '\n'.join(lines))
            readback = read_text_file_lines(str(path))
            readback_hash = hashlib.sha256('\n'.join(readback).encode('utf-8')).hexdigest()
            self.assertEqual(readback, lines)
            self.assertEqual(readback_hash, original_hash)

    def test_write_text_file_atomic_empty_content_stays_empty(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "hosts.txt"
            write_text_file_atomic(str(path), "")
            # Empty input must not spuriously gain a newline.
            self.assertEqual(path.read_text(encoding="utf-8"), "")

    def test_disable_hosts_file_transactionally_rolls_back_if_marker_write_fails(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_path = Path(tmpdir) / "hosts"
            disabled_path = Path(tmpdir) / "hosts.disabled"
            original = "0.0.0.0 original.example\n"
            hosts_path.write_text(original, encoding="utf-8")

            real_replace = hosts_editor.os.replace

            def flaky_replace(src, dst):
                if dst == str(disabled_path):
                    raise OSError("rename failed")
                return real_replace(src, dst)

            with mock.patch.object(hosts_editor.os, "replace", side_effect=flaky_replace):
                with self.assertRaises(OSError):
                    disable_hosts_file_transactionally(
                        str(hosts_path),
                        str(disabled_path),
                        "127.0.0.1 localhost\n",
                    )

            self.assertEqual(hosts_path.read_text(encoding="utf-8"), original)
            self.assertFalse(disabled_path.exists())

    def test_enable_hosts_file_transactionally_restores_marker_if_copy_fails(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_path = Path(tmpdir) / "hosts"
            disabled_path = Path(tmpdir) / "hosts.disabled"
            hosts_path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            disabled_path.write_text("0.0.0.0 restored.example\n", encoding="utf-8")

            real_copy2 = hosts_editor.shutil.copy2

            def flaky_copy2(src, dst, *args, **kwargs):
                if dst == str(hosts_path):
                    raise OSError("copy failed")
                return real_copy2(src, dst, *args, **kwargs)

            with mock.patch.object(hosts_editor.shutil, "copy2", side_effect=flaky_copy2):
                with self.assertRaises(OSError):
                    enable_hosts_file_transactionally(str(hosts_path), str(disabled_path))

            self.assertTrue(disabled_path.exists())
            self.assertEqual(
                disabled_path.read_text(encoding="utf-8"),
                "0.0.0.0 restored.example\n",
            )
            self.assertEqual(hosts_path.read_text(encoding="utf-8"), "127.0.0.1 localhost\n")

    def test_cli_apply_refuses_when_hosts_file_is_disabled(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_path = Path(tmpdir) / "hosts"
            disabled_path = Path(tmpdir) / "hosts.disabled"
            source_path = Path(tmpdir) / "import.txt"
            hosts_path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            disabled_path.write_text("0.0.0.0 preserved.example\n", encoding="utf-8")
            source_path.write_text("0.0.0.0 new.example\n", encoding="utf-8")

            with mock.patch.object(hosts_editor, "_cli_is_admin", return_value=True):
                with mock.patch.object(hosts_editor, "_cli_backup") as backup_mock:
                    result = hosts_editor._cli_apply(str(hosts_path), str(source_path))

            self.assertEqual(result, 1)
            backup_mock.assert_not_called()
            self.assertEqual(hosts_path.read_text(encoding="utf-8"), "127.0.0.1 localhost\n")
            self.assertEqual(disabled_path.read_text(encoding="utf-8"), "0.0.0.0 preserved.example\n")

    def test_cli_update_refuses_when_hosts_file_is_disabled(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_path = Path(tmpdir) / "hosts"
            disabled_path = Path(tmpdir) / "hosts.disabled"
            hosts_path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            disabled_path.write_text("0.0.0.0 preserved.example\n", encoding="utf-8")

            with mock.patch.object(hosts_editor, "_cli_is_admin", return_value=True):
                with mock.patch.object(hosts_editor.urllib.request, "urlopen") as urlopen_mock:
                    result = hosts_editor._cli_update(str(hosts_path))

            self.assertEqual(result, 1)
            urlopen_mock.assert_not_called()

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

    def test_import_worker_reports_failure_for_oversize_response(self):
        class FakeEditor:
            def __init__(self):
                self.import_queue = queue.Queue()
                self.stop_import_flag = threading.Event()

            def _apply_import_mode_filter(self, source_name, lines, mode):
                return lines

        class FakeResponse:
            def __init__(self):
                self.headers = {}
                self.info = lambda: {}
                self.fp = None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getcode(self):
                return 200

            def read(self, size=-1):
                # Fake server that streams more than the configured cap.
                if size is None or size < 0:
                    return b"x" * (MAX_DOWNLOAD_BYTES + 10)
                # The helper passes cap+1; returning the requested amount
                # triggers the size-overflow branch in read_http_body_limited.
                return b"x" * size

        editor = FakeEditor()

        with mock.patch.object(hosts_editor.urllib.request, "urlopen", return_value=FakeResponse()):
            HostsFileEditor._import_worker_thread(
                editor,
                [("Big Source", "https://example.com/huge.txt")],
                "Raw",
            )

        messages = []
        while not editor.import_queue.empty():
            messages.append(editor.import_queue.get_nowait())

        # Expect: progress, log (error), done (with failure_messages populated)
        message_types = [m[0] for m in messages]
        self.assertIn("log", message_types)
        self.assertEqual(message_types[-1], "done")
        _, new_lines, _total, success, failure_messages = messages[-1]
        self.assertEqual(new_lines, [])
        self.assertEqual(success, 0)
        self.assertEqual(len(failure_messages), 1)
        self.assertIn("size cap", failure_messages[0])

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

            def read(self, _size=-1):
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

    def test_ipv4_regex_matches_high_octet_addresses(self):
        """Regression: IPV4_REGEX must match IPs with octets >= 200."""
        self.assertTrue(IPV4_REGEX.match("255.255.255.0"))
        self.assertTrue(IPV4_REGEX.match("255.255.255.255"))
        self.assertTrue(IPV4_REGEX.match("200.200.200.200"))
        self.assertTrue(IPV4_REGEX.match("0.0.0.0"))
        self.assertTrue(IPV4_REGEX.match("127.0.0.1"))
        self.assertTrue(IPV4_REGEX.match("192.168.1.1"))
        self.assertTrue(IPV4_REGEX.match("10.0.0.1"))
        self.assertIsNone(IPV4_REGEX.match("999.999.999.999"))
        self.assertIsNone(IPV4_REGEX.match("256.0.0.1"))
        self.assertIsNone(IPV4_REGEX.match("example.com"))

    def test_high_octet_ip_recognized_as_ip_not_domain(self):
        """Regression: 255.x.x.x must be detected as IP, not treated as a domain."""
        self.assertTrue(_looks_like_ip_token("255.255.255.0"))
        self.assertTrue(_looks_like_ip_token("200.1.2.3"))
        self.assertFalse(_looks_like_ip_token("example.com"))
        self.assertFalse(looks_like_domain("255.255.255.0"))
        self.assertFalse(looks_like_domain("200.1.2.3"))

    def test_hosts_line_with_high_octet_ip_parses_correctly(self):
        """Regression: '255.255.255.0 gateway' should keep the custom IP, not rewrite to 0.0.0.0."""
        entries, domains, transformed = normalize_line_to_hosts_entries("255.255.255.0 gateway")
        self.assertEqual(entries, ["255.255.255.0 gateway"])
        self.assertEqual(domains, ["gateway"])

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


    def test_read_http_body_limited_rejects_oversize_responses(self):
        class FakeResponse:
            def __init__(self, payload):
                self._payload = payload

            def read(self, size=-1):
                # Mirror the wire behaviour: when size is specified, return up
                # to size + whatever overflow the server would have sent.
                if size is None or size < 0:
                    return self._payload
                # Return one byte more than the requested cap so the helper
                # sees an overrun and raises.
                return self._payload[:size]

        big = b"0" * (MAX_DOWNLOAD_BYTES + 10)
        with self.assertRaises(ValueError):
            read_http_body_limited(FakeResponse(big))

    def test_read_http_body_limited_returns_payload_below_cap(self):
        class FakeResponse:
            def __init__(self, payload):
                self._payload = payload

            def read(self, size=-1):
                return self._payload[: size if size and size >= 0 else len(self._payload)]

        small = b"0.0.0.0 example.com\n"
        self.assertEqual(read_http_body_limited(FakeResponse(small)), small)

    def test_decode_downloaded_lines_rejects_gzip_bomb(self):
        bomb = gzip.compress(b"x" * (MAX_DOWNLOAD_BYTES + 1))
        with self.assertRaises(ValueError):
            decode_downloaded_lines("https://example.com/hosts.gz", bomb, "gzip")

    def test_default_hosts_file_path_uses_systemroot(self):
        with mock.patch.dict(os.environ, {"SystemRoot": r"D:\Windows"}, clear=False):
            with mock.patch.object(hosts_editor.os, "name", "nt"):
                self.assertEqual(
                    _default_hosts_file_path(),
                    r"D:\Windows\System32\drivers\etc\hosts",
                )

    def test_enable_windows_dpi_awareness_is_idempotent(self):
        """Calling DPI awareness twice must not raise."""
        # On non-Windows the function is a no-op; on Windows the OS dedupes
        # repeated calls. Either way, two back-to-back calls should be safe.
        hosts_editor._enable_windows_dpi_awareness()
        hosts_editor._enable_windows_dpi_awareness()

    def test_sanitize_custom_sources_rejects_control_characters(self):
        sanitized = sanitize_custom_sources(
            [
                {"name": "Clean", "url": "https://example.com/list.txt"},
                {"name": "Has\nNewline", "url": "https://example.com/a.txt"},
                {"name": "Tab\there", "url": "https://example.com/b.txt"},
                {"name": "Ok", "url": "https://example.com/c\r\n.txt"},
            ]
        )
        # Only the first clean entry should survive.
        self.assertEqual(sanitized, [{"name": "Clean", "url": "https://example.com/list.txt"}])

    def test_sanitize_custom_sources_rejects_oversized_entries(self):
        oversize_name = "A" * 200
        oversize_url = "https://example.com/" + ("x" * 3000)
        sanitized = sanitize_custom_sources(
            [
                {"name": oversize_name, "url": "https://example.com/list.txt"},
                {"name": "Short", "url": oversize_url},
                {"name": "Good", "url": "https://example.com/ok.txt"},
            ]
        )
        self.assertEqual(sanitized, [{"name": "Good", "url": "https://example.com/ok.txt"}])

    def test_block_during_import_returns_true_and_updates_status(self):
        editor = HostsFileEditor.__new__(HostsFileEditor)
        editor.is_importing = True
        captured = {}

        def fake_update_status(message, is_error=False):
            captured["message"] = message
            captured["is_error"] = is_error

        editor.update_status = fake_update_status
        self.assertTrue(HostsFileEditor._block_during_import(editor, "Save Raw"))
        self.assertIn("Save Raw", captured["message"])
        self.assertIn("import", captured["message"].lower())
        self.assertTrue(captured["is_error"])

    def test_block_during_import_allows_when_idle(self):
        editor = HostsFileEditor.__new__(HostsFileEditor)
        editor.is_importing = False
        editor.update_status = lambda *args, **kwargs: None
        self.assertFalse(HostsFileEditor._block_during_import(editor, "Any Action"))

    def test_execute_save_refuses_when_hosts_are_temporarily_disabled(self):
        editor = HostsFileEditor.__new__(HostsFileEditor)
        editor.is_admin = True
        editor.HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"
        editor.is_hosts_disabled = lambda: True

        captured = {"notice": None, "status": None}

        def fake_notice(*args, **kwargs):
            captured["notice"] = (args, kwargs)

        def fake_status(message, is_error=False):
            captured["status"] = (message, is_error)

        editor._show_notice_dialog = fake_notice
        editor.update_status = fake_status

        with mock.patch.object(hosts_editor, "write_text_file_atomic") as write_mock:
            result = HostsFileEditor._execute_save(editor, "0.0.0.0 example.com\n", "Raw Save")

        self.assertFalse(result)
        self.assertIsNotNone(captured["notice"])
        self.assertIn("disabled", captured["notice"][0][0].lower())
        self.assertTrue(captured["status"][1])
        write_mock.assert_not_called()

    def test_update_status_truncates_and_collapses_newlines(self):
        class FakeLabel:
            def __init__(self):
                self.last_text = None

            def config(self, **kwargs):
                self.last_text = kwargs.get("text")

        editor = HostsFileEditor.__new__(HostsFileEditor)
        editor.status_label = FakeLabel()
        editor._cancel_after_job = lambda _attr: None
        editor._safe_after = lambda *_args, **_kwargs: None
        editor._status_reset_job = None
        editor.is_importing = False

        long_msg = "A" * 500 + "\nsecond line"
        HostsFileEditor.update_status(editor, long_msg)
        self.assertTrue(editor.status_label.last_text)
        self.assertNotIn("\n", editor.status_label.last_text)
        self.assertLessEqual(
            len(editor.status_label.last_text),
            HostsFileEditor._STATUS_MESSAGE_MAX_LEN,
        )

    def test_apply_import_mode_filter_sanitizes_source_name(self):
        editor = HostsFileEditor.__new__(HostsFileEditor)
        # Source names that include newlines or carriage returns must not
        # produce multi-line Start/End marker comments.
        result = HostsFileEditor._apply_import_mode_filter(
            editor,
            "Malicious\nName\r\ninjected",
            ["0.0.0.0 example.com"],
            "Raw",
        )
        self.assertEqual(result[0], "# --- Raw Import Start: Malicious Name injected ---")
        self.assertEqual(result[-1], "# --- Raw Import End: Malicious Name injected ---")

    # ---- rewrite_block_sink_ip ----
    def test_rewrite_block_sink_ip_converts_loopback_sinks(self):
        lines = [
            "0.0.0.0 ads.example",
            "127.0.0.1 tracker.example",
            ":: dns-over-https.example",
            "::1 analytics.example",
            "192.168.1.10 printer",  # custom LAN mapping must be preserved
            "# comment untouched",
            "",
        ]
        rewritten, changed = rewrite_block_sink_ip(lines, "0.0.0.0")
        self.assertEqual(changed, 3)
        self.assertEqual(rewritten[0], "0.0.0.0 ads.example")
        self.assertEqual(rewritten[1], "0.0.0.0 tracker.example")
        self.assertEqual(rewritten[2], "0.0.0.0 dns-over-https.example")
        self.assertEqual(rewritten[3], "0.0.0.0 analytics.example")
        self.assertEqual(rewritten[4], "192.168.1.10 printer")
        self.assertEqual(rewritten[5], "# comment untouched")

    def test_rewrite_block_sink_ip_no_change_when_already_target(self):
        lines = ["0.0.0.0 ads.example", "0.0.0.0 tracker.example"]
        rewritten, changed = rewrite_block_sink_ip(lines, "0.0.0.0")
        self.assertEqual(changed, 0)
        self.assertEqual(rewritten, lines)

    def test_rewrite_block_sink_ip_rejects_unsupported_target(self):
        with self.assertRaises(ValueError):
            rewrite_block_sink_ip(["0.0.0.0 x.example"], "1.2.3.4")

    # ---- scan_suspicious_redirects ----
    def test_scan_suspicious_redirects_flags_non_loopback_mappings(self):
        lines = [
            "0.0.0.0 ads.example",                 # loopback block, ignored
            "192.168.1.10 printer",                # private LAN, ignored
            "10.0.0.5 nas.local",                  # private LAN, ignored
            "172.20.1.1 dev.local",                # RFC1918 middle of 172.16/12, ignored
            "172.32.1.1 fake.example",             # OUTSIDE 172.16/12, should flag
            "8.8.8.8 www.google.com",              # hijack, should flag
            "# 1.2.3.4 commented.example",         # comment, ignored
        ]
        findings = scan_suspicious_redirects(lines)
        flagged_domains = {domain for _, _, domain in findings}
        self.assertIn("fake.example", flagged_domains)
        self.assertIn("www.google.com", flagged_domains)
        self.assertNotIn("ads.example", flagged_domains)
        self.assertNotIn("printer", flagged_domains)
        self.assertNotIn("nas.local", flagged_domains)
        self.assertNotIn("dev.local", flagged_domains)

    # ---- export_lines_as_format ----
    def test_export_lines_as_format_hosts_roundtrips(self):
        lines = ["0.0.0.0 ads.example", "# comment", "0.0.0.0 tracker.example"]
        self.assertEqual(export_lines_as_format(lines, "hosts"), '\n'.join(lines))

    def test_export_lines_as_format_deduplicates_domains(self):
        lines = [
            "0.0.0.0 ads.example",
            "0.0.0.0 tracker.example",
            "0.0.0.0 ads.example",  # dup
            "192.168.1.10 printer",  # not a block entry
        ]
        domains_only = export_lines_as_format(lines, "domains")
        self.assertEqual(domains_only.splitlines(), ["ads.example", "tracker.example"])
        self.assertEqual(
            export_lines_as_format(lines, "adblock").splitlines(),
            ["||ads.example^", "||tracker.example^"],
        )
        self.assertEqual(
            export_lines_as_format(lines, "dnsmasq").splitlines(),
            ["address=/ads.example/0.0.0.0", "address=/tracker.example/0.0.0.0"],
        )

    def test_export_lines_as_format_rejects_unknown_format(self):
        with self.assertRaises(ValueError):
            export_lines_as_format(["0.0.0.0 x.example"], "yaml")

    # ---- find_sources_containing_domain ----
    def test_find_sources_containing_domain_matches_subdomain_suffix(self):
        corpus = {
            "SourceA": "0.0.0.0 ads.example\n0.0.0.0 notexample.com\n",
            "SourceB": "||tracker.example^\n||another.host^\n",
            "SourceC": "0.0.0.0 www.example\n",
            "SourceD": "nothing interesting here",
        }
        matches = find_sources_containing_domain("example", corpus)
        # Word-boundary semantics: bare 'example' appears as suffix inside
        # ads.example, tracker.example, www.example — not notexample.com.
        self.assertIn("SourceA", matches)
        self.assertIn("SourceB", matches)
        self.assertIn("SourceC", matches)
        self.assertNotIn("SourceD", matches)

    def test_find_sources_containing_domain_empty_query(self):
        self.assertEqual(find_sources_containing_domain("", {"X": "foo"}), [])

    # ---- format_relative_time ----
    def test_format_relative_time_buckets(self):
        now = datetime.datetime(2026, 4, 17, 12, 0, 0)
        stamp = (now - datetime.timedelta(seconds=30)).isoformat(timespec='seconds')
        self.assertEqual(format_relative_time(stamp, now.timestamp()), "just now")

        stamp_hours = (now - datetime.timedelta(hours=2)).isoformat(timespec='seconds')
        result = format_relative_time(stamp_hours, now.timestamp())
        self.assertTrue(result.endswith("hours ago"), result)

        stamp_days = (now - datetime.timedelta(days=3)).isoformat(timespec='seconds')
        result = format_relative_time(stamp_days, now.timestamp())
        self.assertTrue(result.endswith("days ago"), result)

        self.assertEqual(format_relative_time("not-a-timestamp"), "")
        self.assertEqual(format_relative_time(""), "")

    # ---- scheduler helpers ----
    def test_normalize_scheduler_start_time_pads_valid_times(self):
        self.assertEqual(normalize_scheduler_start_time("3:05"), "03:05")
        self.assertEqual(normalize_scheduler_start_time(" 23:59 "), "23:59")
        self.assertEqual(normalize_scheduler_start_time(""), "03:30")

    def test_normalize_scheduler_start_time_rejects_invalid_values(self):
        with self.assertRaises(ValueError):
            normalize_scheduler_start_time("24:00")
        with self.assertRaises(ValueError):
            normalize_scheduler_start_time("9:7")
        with self.assertRaises(ValueError):
            normalize_scheduler_start_time("nope")

    def test_build_schtasks_create_command_handles_weekly_and_onlogon(self):
        weekly_args, weekly_summary = build_schtasks_create_command(
            "HostsFileGet Auto-Update",
            '"python.exe" "hosts_editor.py" --update',
            "weekly",
            start_time="6:15",
            weekday="fri",
        )
        self.assertIn("/D", weekly_args)
        self.assertEqual(weekly_args[weekly_args.index("/D") + 1], "FRI")
        self.assertIn("/ST", weekly_args)
        self.assertEqual(weekly_args[weekly_args.index("/ST") + 1], "06:15")
        self.assertIn("Friday", weekly_summary)

        onlogon_args, onlogon_summary = build_schtasks_create_command(
            "HostsFileGet Auto-Update",
            '"python.exe" "hosts_editor.py" --update',
            "ONLOGON",
        )
        self.assertNotIn("/ST", onlogon_args)
        self.assertNotIn("/D", onlogon_args)
        self.assertIn("sign-in", onlogon_summary.lower())

    # ---- sanitize_config_snapshot: new v2.12 fields ----
    def test_sanitize_config_snapshot_keeps_valid_source_last_fetched(self):
        config = {
            "source_last_fetched": {
                "https://example.com/hosts.txt": "2026-04-17T12:00:00",
                "not-a-url": "2026-04-17T12:00:00",  # rejected
                "https://evil.example/h.txt": "not-a-timestamp",  # rejected
            },
            "preferred_block_sink": "127.0.0.1",
        }
        sanitized = sanitize_config_snapshot(config, os.path.expanduser("~"))
        self.assertEqual(
            sanitized["source_last_fetched"],
            {"https://example.com/hosts.txt": "2026-04-17T12:00:00"},
        )
        self.assertEqual(sanitized["preferred_block_sink"], "127.0.0.1")

    def test_sanitize_config_snapshot_rejects_unknown_block_sink(self):
        sanitized = sanitize_config_snapshot(
            {"preferred_block_sink": "8.8.8.8"}, os.path.expanduser("~")
        )
        self.assertEqual(sanitized["preferred_block_sink"], "0.0.0.0")

    def test_block_sink_ips_constant_includes_expected(self):
        self.assertIn("0.0.0.0", BLOCK_SINK_IPS)
        self.assertIn("127.0.0.1", BLOCK_SINK_IPS)
        self.assertIn("::", BLOCK_SINK_IPS)
        self.assertIn("::1", BLOCK_SINK_IPS)

    # ---- strip_lines_by_category (v2.13) ----
    def test_strip_lines_by_category_drops_only_selected_categories(self):
        lines = [
            "# comment",
            "",
            "0.0.0.0 ads.example",
            "garbage text no ip",
            "  ",
            "# another",
            "0.0.0.0 tracker.example",
        ]
        result, stats = strip_lines_by_category(lines, drop_comments=True)
        self.assertEqual(stats["removed_comments"], 2)
        self.assertEqual(stats["removed_blanks"], 0)
        self.assertEqual(stats["removed_invalid"], 0)
        self.assertNotIn("# comment", result)
        self.assertIn("0.0.0.0 ads.example", result)
        self.assertIn("garbage text no ip", result)  # invalid kept

        result, stats = strip_lines_by_category(lines, drop_blanks=True)
        self.assertEqual(stats["removed_blanks"], 2)
        # Comments kept, invalid kept.
        self.assertIn("# comment", result)
        self.assertIn("garbage text no ip", result)

        result, stats = strip_lines_by_category(lines, drop_invalid=True)
        self.assertEqual(stats["removed_invalid"], 1)
        self.assertNotIn("garbage text no ip", result)
        self.assertIn("# comment", result)

    def test_strip_lines_by_category_noop_is_idempotent(self):
        lines = ["0.0.0.0 ads.example", "0.0.0.0 tracker.example"]
        result, stats = strip_lines_by_category(lines)
        self.assertEqual(result, lines)
        self.assertEqual(stats, {"removed_comments": 0, "removed_blanks": 0, "removed_invalid": 0})

    # ---- discover_import_sections / remove_import_section (v2.13) ----
    def test_discover_import_sections_pairs_markers(self):
        lines = [
            "0.0.0.0 before.example",
            "# --- Normalized Import Start: OISD Full ---",
            "0.0.0.0 a.example",
            "0.0.0.0 b.example",
            "# --- Normalized Import End: OISD Full ---",
            "",
            "# --- Raw Import Start: MyCustom ---",
            "0.0.0.0 c.example",
            "# --- Raw Import End: MyCustom ---",
            "0.0.0.0 after.example",
        ]
        sections = discover_import_sections(lines)
        self.assertEqual(len(sections), 2)
        self.assertEqual(sections[0]["name"], "OISD Full")
        self.assertEqual(sections[0]["mode"], "Normalized")
        self.assertEqual(sections[0]["start"], 1)
        self.assertEqual(sections[0]["end"], 4)
        self.assertEqual(sections[1]["name"], "MyCustom")
        self.assertEqual(sections[1]["mode"], "Raw")

    def test_discover_import_sections_ignores_unmatched_start(self):
        lines = [
            "# --- Raw Import Start: Orphan ---",
            "0.0.0.0 x.example",
        ]
        self.assertEqual(discover_import_sections(lines), [])

    def test_remove_import_section_removes_inclusive_range(self):
        lines = [
            "0.0.0.0 before.example",
            "# --- Normalized Import Start: Foo ---",
            "0.0.0.0 a.example",
            "# --- Normalized Import End: Foo ---",
            "0.0.0.0 after.example",
        ]
        sections = discover_import_sections(lines)
        trimmed = remove_import_section(lines, sections[0])
        self.assertEqual(trimmed, ["0.0.0.0 before.example", "0.0.0.0 after.example"])

    def test_stock_microsoft_hosts_contains_localhost(self):
        self.assertIn("127.0.0.1", STOCK_MICROSOFT_HOSTS)
        self.assertIn("::1", STOCK_MICROSOFT_HOSTS)

    # ---- fuzzy_score (v2.14) ----
    def test_fuzzy_score_requires_ordered_subsequence(self):
        self.assertGreaterEqual(fuzzy_score("abc", "aabbcc"), 0)
        self.assertEqual(fuzzy_score("abc", "cba"), -1)
        self.assertEqual(fuzzy_score("", "anything"), 0)

    def test_fuzzy_score_prefers_prefix_and_consecutive_matches(self):
        prefix = fuzzy_score("tra", "tracker.example")
        middle = fuzzy_score("tra", "fastracker.example")
        self.assertGreater(prefix, middle)

    # ---- summarize_source_contributions (v2.14) ----
    def test_summarize_source_contributions_ranks_blocking_entries(self):
        lines = [
            "0.0.0.0 manual.example",                      # outside, 1 block
            "# --- Normalized Import Start: BigSource ---",
            "0.0.0.0 a.example",
            "0.0.0.0 b.example",
            "0.0.0.0 c.example",
            "# --- Normalized Import End: BigSource ---",
            "# --- Normalized Import Start: SmallSource ---",
            "0.0.0.0 x.example",
            "# --- Normalized Import End: SmallSource ---",
        ]
        report = summarize_source_contributions(lines)
        # Sorted desc by blocking_entries
        names = [b["name"] for b in report]
        self.assertEqual(names[0], "BigSource [Normalized]")
        self.assertIn("SmallSource [Normalized]", names)
        self.assertIn("(outside imports / manual edits)", names)
        big = next(b for b in report if b["name"] == "BigSource [Normalized]")
        self.assertEqual(big["blocking_entries"], 3)

    # ---- sanitize_config_snapshot: backup_retention + first_run ----
    def test_sanitize_config_snapshot_clamps_backup_retention(self):
        s = sanitize_config_snapshot({"backup_retention": 9999}, os.path.expanduser("~"))
        self.assertEqual(s["backup_retention"], 50)
        s = sanitize_config_snapshot({"backup_retention": -5}, os.path.expanduser("~"))
        self.assertEqual(s["backup_retention"], 0)
        s = sanitize_config_snapshot({"backup_retention": "garbage"}, os.path.expanduser("~"))
        # fallback to default
        self.assertEqual(s["backup_retention"], 5)

    def test_sanitize_config_snapshot_tracks_first_run_flag(self):
        s = sanitize_config_snapshot({"has_completed_first_run": True}, os.path.expanduser("~"))
        self.assertTrue(s["has_completed_first_run"])
        s = sanitize_config_snapshot({}, os.path.expanduser("~"))
        self.assertFalse(s["has_completed_first_run"])

    # ---- v2.15: pinned domains ----
    def test_sanitize_pinned_domains_rejects_garbage(self):
        result = sanitize_pinned_domains([
            "ads.example.com",
            ".tracker.example",       # leading dot tolerated
            "UPPER.Example",          # lowercased
            "",                       # dropped
            None,                     # dropped
            "not a domain",           # dropped
            "ads.example.com",        # duplicate dropped
            42,                       # non-string dropped
            "a",                      # single-label dropped
        ])
        self.assertEqual(result, ["ads.example.com", "tracker.example", "upper.example"])

    def test_sanitize_pinned_domains_non_iterable(self):
        self.assertEqual(sanitize_pinned_domains(None), [])
        self.assertEqual(sanitize_pinned_domains("not-a-list"), [])

    def test_sanitize_config_snapshot_persists_pinned_domains(self):
        s = sanitize_config_snapshot(
            {"pinned_domains": ["A.Example", "b.example", "garbage"]},
            os.path.expanduser("~"),
        )
        self.assertEqual(s["pinned_domains"], ["a.example", "b.example"])

    def test_cleaned_save_preserves_pinned_domains_over_whitelist(self):
        # Whitelist would normally strip ads.example; pinning it keeps the
        # block. A pinned domain that isn't even in the editor should be
        # synthetically added.
        cleaned, stats = _get_canonical_cleaned_output_and_stats(
            [
                "0.0.0.0 ads.example",
                "0.0.0.0 tracker.example",
            ],
            whitelist_set={"ads.example", "tracker.example"},
            pinned_domains={"ads.example", "absent.example"},
        )
        self.assertIn("0.0.0.0 ads.example", cleaned)
        self.assertIn("0.0.0.0 absent.example", cleaned)
        self.assertNotIn("0.0.0.0 tracker.example", cleaned)
        self.assertGreaterEqual(stats["pinned_preserved"], 1)

    # ---- v2.15: AdGuard Home parser ----
    def test_agh_block_reasons_excludes_allow_and_rewrite(self):
        # Reasons 1 (NotFilteredAllowList), 9 (Rewrite), 10 (RewriteAutoHosts)
        # must NOT be treated as blocks.
        self.assertNotIn(1, AGH_BLOCK_REASONS)
        self.assertNotIn(9, AGH_BLOCK_REASONS)
        self.assertNotIn(10, AGH_BLOCK_REASONS)
        # At least the core Filtered* codes are blocks.
        for code in (3, 4, 5, 7, 8):
            self.assertIn(code, AGH_BLOCK_REASONS)

    def test_parse_agh_querylog_ndjson_keeps_only_blocks(self):
        lines = [
            '{"QH":"ads.example","Result":{"Reason":3,"IsFiltered":true}}',
            '{"QH":"allowed.example","Result":{"Reason":1,"IsFiltered":false}}',
            '{"QH":"rewritten.example","Result":{"Reason":9,"IsFiltered":false}}',
            '{"QH":"legacy.example","Result":{"IsFiltered":true}}',  # no Reason key
            '{"QH":"safebrowse.example","Result":{"Reason":4,"IsFiltered":true}}',
            'not-json-at-all',
            '{"QH":"dup.example","Result":{"Reason":3,"IsFiltered":true}}',
            '{"QH":"dup.example","Result":{"Reason":3,"IsFiltered":true}}',
        ]
        blocked = parse_adguard_home_querylog("\n".join(lines))
        self.assertIn("ads.example", blocked)
        self.assertIn("safebrowse.example", blocked)
        self.assertIn("legacy.example", blocked)
        self.assertIn("dup.example", blocked)
        self.assertNotIn("allowed.example", blocked)
        self.assertNotIn("rewritten.example", blocked)
        # Dup domain appears only once.
        self.assertEqual(blocked.count("dup.example"), 1)

    def test_parse_agh_querylog_array_form(self):
        blob = (
            '[{"QH":"ads.example","Result":{"Reason":3,"IsFiltered":true}},'
            ' {"QH":"ok.example","Result":{"Reason":0,"IsFiltered":false}}]'
        )
        self.assertEqual(parse_adguard_home_querylog(blob), ["ads.example"])

    def test_parse_agh_querylog_empty_and_malformed(self):
        self.assertEqual(parse_adguard_home_querylog(""), [])
        self.assertEqual(parse_adguard_home_querylog("not json at all"), [])

    # ---- v2.15: Pi-hole FTL ----
    def test_ftl_blocked_status_codes_covers_known_block_statuses(self):
        for code in (1, 4, 5, 6, 7, 8, 9, 10, 11):
            self.assertIn(code, FTL_BLOCKED_STATUS_CODES)
        # Allow statuses 2 and 3 must NOT be present.
        self.assertNotIn(2, FTL_BLOCKED_STATUS_CODES)
        self.assertNotIn(3, FTL_BLOCKED_STATUS_CODES)

    def test_sqlite_readonly_uri_forces_absolute_slash(self):
        uri_abs = _sqlite_readonly_uri("C:/temp/pihole-FTL.db")
        # Prior bug: file:C:/... was interpreted as relative URI.
        self.assertTrue(uri_abs.startswith("file:/C:/"), uri_abs)
        self.assertIn("mode=ro", uri_abs)
        # Unix-style path should retain its single leading slash.
        uri_unix = _sqlite_readonly_uri("/var/lib/pihole-FTL.db")
        self.assertTrue(uri_unix.startswith("file:/var/") or uri_unix.startswith("file:///var/"))

    def test_parse_pihole_ftl_reads_blocked_rows_only(self):
        import sqlite3
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "pihole-FTL.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    "CREATE TABLE queries "
                    "(id INTEGER PRIMARY KEY, timestamp INTEGER, status INTEGER, domain TEXT)"
                )
                rows = [
                    (1, 1000, 1, "blocked.example"),
                    (2, 1001, 3, "allowed.example"),   # status 3 = allowlisted
                    (3, 1002, 5, "regex-blocked.example"),
                    (4, 1003, 8, "external-block.example"),
                    (5, 1004, 2, "forward.example"),   # status 2 = forwarded OK
                    (6, 1005, 1, "DUP.example"),
                    (7, 1006, 1, "dup.example"),       # dedup case-insensitive
                    (8, 1007, 1, "not a valid host"),  # skipped as invalid
                    (9, 1008, 1, ""),                  # skipped
                ]
                conn.executemany(
                    "INSERT INTO queries (id, timestamp, status, domain) VALUES (?, ?, ?, ?)",
                    rows,
                )
                conn.commit()
            finally:
                conn.close()

            result = parse_pihole_ftl_blocked_domains(str(db_path))
            self.assertIn("blocked.example", result)
            self.assertIn("regex-blocked.example", result)
            self.assertIn("external-block.example", result)
            self.assertIn("dup.example", result)
            self.assertNotIn("allowed.example", result)
            self.assertNotIn("forward.example", result)
            # Dedup kept only one copy.
            self.assertEqual(result.count("dup.example"), 1)

    def test_parse_pihole_ftl_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            parse_pihole_ftl_blocked_domains("Z:/this/path/does/not/exist/pihole-FTL.db")

    # ---- v2.15: find/replace ----
    def test_apply_find_replace_plain_case_insensitive(self):
        lines = ["0.0.0.0 ADS.example", "0.0.0.0 tracker.ADS"]
        result, count = apply_find_replace(lines, "ads", "XX", use_regex=False, case_sensitive=False)
        self.assertEqual(count, 2)
        self.assertIn("0.0.0.0 XX.example", result)
        self.assertIn("0.0.0.0 tracker.XX", result)

    def test_apply_find_replace_plain_case_sensitive(self):
        lines = ["0.0.0.0 ADS.example", "0.0.0.0 ads.example"]
        result, count = apply_find_replace(lines, "ads", "XX", use_regex=False, case_sensitive=True)
        self.assertEqual(count, 1)
        self.assertEqual(result, ["0.0.0.0 ADS.example", "0.0.0.0 XX.example"])

    def test_apply_find_replace_regex_with_backrefs(self):
        lines = ["0.0.0.0 foo.example", "0.0.0.0 bar.example"]
        result, count = apply_find_replace(
            lines, r"0\.0\.0\.0 (.+)\.example", r"127.0.0.1 \1.example", use_regex=True
        )
        self.assertEqual(count, 2)
        self.assertEqual(result[0], "127.0.0.1 foo.example")

    def test_apply_find_replace_invalid_regex_raises(self):
        with self.assertRaises(ValueError):
            apply_find_replace(["anything"], r"(unbalanced", "x", use_regex=True)

    def test_apply_find_replace_empty_pattern_noop(self):
        lines = ["anything"]
        result, count = apply_find_replace(lines, "", "x")
        self.assertEqual(result, lines)
        self.assertEqual(count, 0)

    # ---- v2.16: source freshness ----
    def test_classify_source_freshness_buckets(self):
        now = datetime.datetime(2026, 4, 18, 12, 0, 0)
        now_epoch = now.timestamp()
        # fresh
        self.assertEqual(
            classify_source_freshness(
                (now - datetime.timedelta(hours=2)).isoformat(timespec="seconds"),
                now=now_epoch,
            ),
            "fresh",
        )
        # warm (~2 days)
        self.assertEqual(
            classify_source_freshness(
                (now - datetime.timedelta(days=2)).isoformat(timespec="seconds"),
                now=now_epoch,
            ),
            "warm",
        )
        # stale (> 7 days)
        self.assertEqual(
            classify_source_freshness(
                (now - datetime.timedelta(days=30)).isoformat(timespec="seconds"),
                now=now_epoch,
            ),
            "stale",
        )
        # never
        self.assertEqual(classify_source_freshness(""), "never")
        self.assertEqual(classify_source_freshness(None), "never")
        # garbage
        self.assertEqual(classify_source_freshness("not a date"), "never")
        # clock skew (future timestamp) → treat as fresh
        future = (now + datetime.timedelta(hours=5)).isoformat(timespec="seconds")
        self.assertEqual(classify_source_freshness(future, now=now_epoch), "fresh")

    def test_stale_thresholds_reasonable(self):
        # Guard against accidental hours-vs-days confusion in future edits.
        self.assertEqual(STALE_FRESH_HOURS, 24)
        self.assertEqual(STALE_WARN_HOURS, 7 * 24)

    # ---- v2.16: pinned export / import ----
    def test_build_pinned_export_payload_shape(self):
        payload = build_pinned_export_payload("9.9.9", {"a.example", "b.example"})
        self.assertEqual(payload["schema"], "hostsfileget.pinned.v1")
        self.assertEqual(payload["exported_by_version"], "9.9.9")
        self.assertEqual(payload["pinned_domains"], ["a.example", "b.example"])
        self.assertIn("exported_at", payload)

    def test_parse_pinned_import_payload_accepts_export_shape(self):
        parsed = parse_pinned_import_payload({
            "schema": "hostsfileget.pinned.v1",
            "pinned_domains": ["A.Example", "b.example", "garbage"],
        })
        self.assertEqual(parsed, ["a.example", "b.example"])

    def test_parse_pinned_import_payload_accepts_bare_list(self):
        parsed = parse_pinned_import_payload(["c.example", "c.example", "not a host"])
        self.assertEqual(parsed, ["c.example"])

    def test_parse_pinned_import_payload_rejects_foreign_schema(self):
        with self.assertRaises(ValueError):
            parse_pinned_import_payload({"schema": "foreign.v1", "pinned_domains": []})

    def test_parse_pinned_import_payload_rejects_wrong_type(self):
        with self.assertRaises(ValueError):
            parse_pinned_import_payload("just a string")

    def test_sanitize_config_snapshot_persists_update_on_launch(self):
        truthy = sanitize_config_snapshot({"update_on_launch": True}, os.path.expanduser("~"))
        falsy = sanitize_config_snapshot({"update_on_launch": "off"}, os.path.expanduser("~"))
        self.assertTrue(truthy["update_on_launch"])
        # Non-empty string is truthy under bool() — that's the intended shape.
        self.assertTrue(falsy["update_on_launch"])
        default = sanitize_config_snapshot({}, os.path.expanduser("~"))
        self.assertFalse(default["update_on_launch"])


if __name__ == "__main__":
    unittest.main()
