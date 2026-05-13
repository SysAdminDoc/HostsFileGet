import bz2
import csv
import gzip
import io
import json
import os
import queue
import threading
import unittest
import urllib.request
import urllib.error
from unittest import mock

import datetime

import hosts_editor
from hosts_editor import (
    AGH_BLOCK_REASONS,
    BLOCK_SINK_IPS,
    CONFIG_SCHEMA_VERSION,
    DEFAULT_PROFILE_ID,
    DOMAIN_CATEGORY_RULES,
    FTL_BLOCKED_STATUS_CODES,
    HostsFileEditor,
    I18N_CATALOG_SCHEMA_VERSION,
    PROFILE_SYNC_PAYLOAD_SCHEMA,
    PROVENANCE_EVENT_KINDS,
    PROFILE_SCHEMA_VERSION,
    ROUTER_GATEWAY_PLAN_SCHEMA,
    SANDBOX_VM_HOSTS_PLAN_SCHEMA,
    SOURCE_HEALTH_REPORT_SCHEMA_VERSION,
    SOURCE_ADAPTER_PLUGIN_SCHEMA,
    SOURCE_ADAPTER_PLUGIN_SCHEMA_VERSION,
    SOURCE_MANIFEST_SCHEMA_VERSION,
    STALE_FRESH_HOURS,
    STALE_WARN_HOURS,
    NRPT_POLICY_PLAN_SCHEMA,
    WFP_BLOCKER_PLAN_SCHEMA,
    append_provenance_event,
    append_cli_activity_event,
    add_domain_to_whitelist_text,
    build_accessibility_audit_report,
    build_adblock_syntax_report,
    build_false_positive_triage_report,
    build_filter_builder_report,
    build_idn_homograph_report,
    build_i18n_catalog_report,
    build_i18n_contribution_report,
    build_i18n_contribution_template,
    build_local_api_clean_preview_payload,
    build_local_api_status_payload,
    build_profile_sync_payload,
    build_allowlist_share_patch,
    build_profile_share_patch,
    build_recovery_apply_plan,
    build_restore_point_command,
    build_nrpt_policy_export_plan,
    build_router_gateway_push_plan,
    build_sandbox_vm_hosts_plan,
    build_wfp_blocker_companion_plan,
    build_entry_provenance_report,
    build_pinned_export_payload,
    build_provenance_log_report,
    build_rule_tier_report,
    build_source_domain_index,
    build_source_adapter_plugin_sources,
    build_source_health_report,
    build_source_manifest_index,
    build_source_overlap_report,
    build_source_metrics_report,
    build_source_request_headers,
    build_source_trust_badges,
    build_watch_expression_report,
    build_windows_dns_client_wevtutil_command,
    categorize_entries_by_domain_hint,
    check_source_health_record,
    check_source_health_records,
    classify_adblock_rule_line,
    classify_idn_domain,
    classify_rule_tier_line,
    classify_source_freshness,
    collect_recent_windows_dns_client_queries,
    collect_dns_bypass_policy_snapshot,
    create_local_api_server,
    contrast_ratio,
    dns_bypass_policy_status,
    parse_cloud_dns_log_export,
    parse_controld_activity_csv,
    parse_pinned_import_payload,
    read_provenance_events,
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
    format_filter_builder_report,
    parse_adguard_home_querylog,
    parse_nextdns_log_csv,
    parse_gas_mask_archive_path,
    record_filter_query_history,
    record_source_metrics_snapshot,
    sanitize_filter_query_history,
    parse_hostsfileeditor_archive_path,
    parse_declarative_config_text,
    parse_schtasks_query_output,
    load_declarative_config_text,
    apply_declarative_profile_to_config,
    apply_profile_sync_payload_to_config,
    apply_share_patch_payload_to_config,
    upsert_profile_in_config,
    parse_pihole_ftl_blocked_domains,
    parse_switchhosts_export_text,
    parse_allowlist_patch_text,
    parse_windows_dns_client_events_xml,
    parse_nrpt_policy_namespaces,
    parse_wfp_blocker_targets,
    sanitize_git_history_ref,
    summarize_source_contributions,
    build_export_domain_records,
    build_git_history_metadata,
    build_git_history_status_report,
    build_cloud_dns_adapter_plan,
    build_config_location_report,
    build_dns_integration_export,
    build_portable_bundle_readme,
    build_scheduler_activity_report,
    build_scheduler_update_command,
    build_cname_cloaking_plan,
    build_encrypted_dns_bypass_pack_plan,
    build_dns_rebinding_report,
    build_profile_quick_switch_report,
    build_profile_tray_availability_report,
    build_safesearch_template_plan,
    build_threat_feed_pack_plan,
    build_virtual_list_page,
    apply_profile_activation_schedule,
    apply_profile_quick_switch,
    evaluate_profile_activation_schedule,
    export_lines_as_format,
    export_lines_as_bytes,
    export_provenance_events,
    extract_blocking_domains_from_lines,
    fetch_source_with_cache,
    fetch_source_with_retries,
    filter_provenance_events,
    find_keyword_match_line_indices,
    find_profile_snapshot,
    find_sources_containing_domain,
    format_relative_time,
    format_entry_provenance_report,
    format_provenance_log_report,
    format_false_positive_triage_report,
    format_accessibility_audit_report,
    format_adblock_syntax_report,
    format_idn_homograph_report,
    format_i18n_catalog_report,
    format_i18n_contribution_report,
    format_rule_tier_report,
    format_declarative_config_payload,
    format_declarative_profile_summary,
    format_profile_list_summary,
    format_profile_sync_report,
    format_share_patch_summary,
    format_nrpt_policy_export_plan,
    format_recovery_apply_plan,
    format_router_gateway_adapter_catalog,
    format_router_gateway_push_plan,
    format_sandbox_vm_hosts_plan,
    format_wfp_blocker_companion_plan,
    format_git_history_status_report,
    format_cloud_dns_adapter_catalog,
    format_cloud_dns_adapter_report,
    format_config_location_report,
    format_dns_integration_export_summary,
    format_dns_integration_pack_report,
    format_cname_cloaking_catalog,
    format_cname_cloaking_plan,
    format_dns_rebinding_report,
    format_encrypted_dns_bypass_catalog,
    format_encrypted_dns_bypass_pack_plan,
    format_safesearch_template_catalog,
    format_safesearch_template_plan,
    format_profile_activation_schedule_report,
    format_profile_quick_switch_report,
    format_profile_tray_availability_report,
    format_portable_bundle_export_summary,
    format_scheduler_activity_report,
    format_source_trust_badges,
    format_watch_expression_report,
    format_source_bundle_catalog,
    format_source_bundle_report,
    format_source_overlap_report,
    format_source_metrics_report,
    format_dns_bypass_diagnostics,
    format_source_adapter_plugin_catalog,
    format_threat_feed_pack_catalog,
    format_threat_feed_pack_plan,
    build_schtasks_create_command,
    get_source_cache_body_path,
    get_config_root_dir,
    get_git_history_dir,
    get_profile_sync_git_dir,
    list_cname_cloaking_packs,
    list_cname_cloaking_sources,
    list_encrypted_dns_bypass_packs,
    list_encrypted_dns_bypass_sources,
    list_safesearch_template_sources,
    list_safesearch_templates,
    list_cloud_dns_adapters,
    list_dns_integration_packs,
    list_router_gateway_adapters,
    list_threat_feed_packs,
    list_threat_feed_sources,
    looks_like_domain,
    looks_like_html_document,
    load_blocklist_sources_manifest,
    load_source_bundle_catalog,
    load_source_adapter_plugin_catalog,
    load_i18n_catalog,
    list_git_history_snapshots,
    local_api_authorization_valid,
    merge_source_adapter_plugin_sources,
    migrate_config_snapshot,
    normalize_locale_code,
    normalize_scheduler_start_time,
    normalize_profile_activation_days,
    normalize_line_to_hosts_entries,
    normalize_custom_source_url,
    normalize_false_positive_domain,
    read_http_body_limited,
    read_cli_activity_events,
    read_git_history_snapshot,
    read_profile_sync_git_import,
    load_share_patch_payload,
    read_text_file_lines,
    quarantine_adblock_rule_lines,
    remove_import_section,
    remove_false_positive_matches_from_lines,
    remove_lines_by_indices,
    remove_watch_expression,
    resolve_import_fetch_worker_count,
    resolve_saved_state_hashes,
    sanitize_local_api_token,
    rewrite_block_sink_ip,
    sanitize_config_snapshot,
    sanitize_cli_activity_event,
    sanitize_custom_sources,
    sanitize_i18n_catalog,
    sanitize_profile_activation_schedule,
    sanitize_profile_id,
    sanitize_profile_sync_payload,
    sanitize_share_patch_payload,
    sanitize_profile_snapshot,
    sanitize_profiles_snapshot,
    sanitize_source_cache_metadata,
    sanitize_source_adapter_plugin_manifest,
    sanitize_source_bundle_catalog,
    sanitize_source_manifest,
    sanitize_source_metrics_history,
    sanitize_watch_expressions,
    sanitize_pinned_domains,
    scan_suspicious_redirects,
    source_trust_report_url,
    source_bundle_to_import_sources,
    strip_lines_by_category,
    summarize_clean_changes,
    summarize_source_health_results,
    translate_message,
    set_active_profile_in_config,
    update_active_profile_snapshot,
    upsert_watch_expression,
    write_git_history_snapshot,
    write_profile_sync_git_export,
    write_share_patch_payload,
    sign_share_patch_file,
    verify_share_patch_signature,
    write_portable_bundle_config,
    write_text_file_atomic,
    write_bytes_file_atomic,
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

    def test_adblock_linter_quarantines_browser_only_and_path_rules(self):
        cosmetic = classify_adblock_rule_line("example.com##.ad-banner")
        path_rule = classify_adblock_rule_line("||example.com/ads/*")
        exception = classify_adblock_rule_line("@@||allowed.example^$document")
        dns_rule = classify_adblock_rule_line("||tracker.example^$third-party")

        self.assertTrue(cosmetic["quarantine"])
        self.assertEqual(cosmetic["category"], "browser-only")
        self.assertTrue(path_rule["quarantine"])
        self.assertEqual(path_rule["category"], "path-network")
        self.assertTrue(exception["quarantine"])
        self.assertEqual(exception["category"], "exception")
        self.assertFalse(dns_rule["quarantine"])
        self.assertTrue(dns_rule["dns_compatible"])
        self.assertEqual(dns_rule["normalized"], "0.0.0.0 tracker.example")

    def test_adblock_linter_prevents_cosmetic_rules_from_overblocking(self):
        self.assertEqual(normalize_line_to_hosts_entries("example.com##.ad-banner")[0], [])
        self.assertEqual(normalize_line_to_hosts_entries("||example.com/ads/*")[0], [])
        self.assertEqual(
            normalize_line_to_hosts_entries("||tracker.example^$third-party")[0],
            ["0.0.0.0 tracker.example"],
        )

    def test_adblock_syntax_report_and_quarantine_comments_rules(self):
        lines = [
            "0.0.0.0 ads.example",
            "||tracker.example^$third-party",
            "example.com##.ad-banner",
            "||example.com/ads/*",
            "@@||allowed.example^$document",
        ]
        report = build_adblock_syntax_report(lines)
        self.assertEqual(report["dns_compatible"], 2)
        self.assertEqual(report["quarantined"], 3)
        self.assertEqual(len(report["findings"]), 3)
        rendered = format_adblock_syntax_report(report)
        self.assertIn("Adblock syntax lint", rendered)
        self.assertIn("Path-level", rendered)

        quarantined, quarantine_report = quarantine_adblock_rule_lines(lines)
        self.assertEqual(quarantine_report["changed_lines"], 3)
        self.assertEqual(quarantined[0], "0.0.0.0 ads.example")
        self.assertTrue(quarantined[2].startswith("# HostsFileGet quarantined browser-only rule:"))

    def test_rule_tier_classifier_separates_exact_wildcard_regex_and_subdomain_rules(self):
        exact = classify_rule_tier_line("0.0.0.0 ads.example")
        custom = classify_rule_tier_line("10.1.2.3 intranet.example")
        subdomain = classify_rule_tier_line("||tracker.example^")
        wildcard = classify_rule_tier_line("server-*.example.com")
        regex = classify_rule_tier_line("/(^|\\.)ads[0-9]+\\.example$/")

        self.assertEqual(exact["category"], "hosts-exact")
        self.assertTrue(exact["hosts_native"])
        self.assertEqual(custom["category"], "hosts-custom-mapping")
        self.assertTrue(custom["hosts_native"])
        self.assertEqual(subdomain["category"], "subdomain-scoped")
        self.assertFalse(subdomain["hosts_native"])
        self.assertIn("one exact line", subdomain["warning"])
        self.assertEqual(wildcard["tier"], "wildcard")
        self.assertIn("do not support wildcards", wildcard["warning"])
        self.assertEqual(regex["tier"], "regex")
        self.assertIn("cannot evaluate regex", regex["warning"])

    def test_rule_tier_report_summarizes_hosts_warnings(self):
        lines = [
            "0.0.0.0 ads.example",
            "10.0.0.5 intranet.example",
            "||tracker.example^",
            "*.tracking.example",
            "/ads[0-9]+/",
            "example.com##.ad-banner",
        ]
        report = build_rule_tier_report(lines)
        self.assertEqual(report["hosts_native"], 2)
        self.assertEqual(report["warning_count"], 4)
        self.assertEqual(report["tiers"]["exact"], 2)
        self.assertEqual(report["tiers"]["subdomain-scoped"], 1)
        self.assertEqual(report["tiers"]["wildcard"], 1)
        self.assertEqual(report["tiers"]["regex"], 1)
        rendered = format_rule_tier_report(report)
        self.assertIn("Rule tier report", rendered)
        self.assertIn("Windows hosts files are exact hostname mappings", rendered)

    def test_idn_classifier_decodes_punycode_and_flags_homographs(self):
        homograph = classify_idn_domain("xn--pple-43d.com")
        latin_idn = classify_idn_domain("m\u00fcnich.example")
        latin_punycode = classify_idn_domain("xn--mnich-kva.example")
        invalid = classify_idn_domain("xn--bad.com")

        self.assertEqual(homograph["category"], "homograph-risk")
        self.assertEqual(homograph["unicode"], "\u0430pple.com")
        self.assertEqual(homograph["confusable_skeleton"], "apple.com")
        self.assertIn("xn--pple-43d.com", homograph["ascii"])
        self.assertEqual(latin_idn["category"], "idn")
        self.assertEqual(latin_idn["ascii"], "xn--mnich-kva.example")
        self.assertEqual(latin_punycode["category"], "punycode")
        self.assertEqual(latin_punycode["unicode"], "m\u00fcnich.example")
        self.assertEqual(invalid["category"], "invalid-punycode")

    def test_idn_homograph_report_scans_hosts_urls_and_adblock_tokens(self):
        lines = [
            "0.0.0.0 xn--pple-43d.com",
            "0.0.0.0 m\u00fcnich.example",
            "||xn--mnich-kva.example^$important",
            "https://xn--ypal-43d9g.com/login",
            "# xn--ignored-9d0b.example",
        ]

        report = build_idn_homograph_report(lines)
        self.assertEqual(report["candidate_domains"], 4)
        self.assertEqual(report["warning_count"], 2)
        self.assertEqual(report["counts"]["homograph-risk"], 2)
        self.assertEqual(report["counts"]["idn"], 1)
        self.assertEqual(report["counts"]["punycode"], 1)

        rendered = format_idn_homograph_report(report)
        self.assertIn("IDN and homograph report", rendered)
        self.assertIn("apple.com", rendered)
        self.assertIn("Punycode A-labels", rendered)

    def test_clean_stats_do_not_go_negative(self):
        stats = compute_clean_impact_stats(["example.com"], set())

        self.assertEqual(stats["total_discarded"], 0)
        self.assertEqual(stats["final_active"], 1)
        self.assertEqual(stats["transformed"], 1)

    def test_count_nonempty_lines_ignores_blank_rows(self):
        self.assertEqual(count_nonempty_lines("\nalpha\n \n beta \n"), 2)

    def test_accessibility_contrast_audit_passes_tracked_pairs(self):
        report = build_accessibility_audit_report()

        self.assertEqual(
            report["summary"]["passing_pairs"],
            report["summary"]["total_pairs"],
            format_accessibility_audit_report(report),
        )
        self.assertIn("Primary commands use visible text labels", "\n".join(report["assistive_tech_checks"]))

    def test_contrast_ratio_matches_wcag_examples(self):
        self.assertAlmostEqual(contrast_ratio("#000000", "#ffffff"), 21.0, places=1)
        self.assertAlmostEqual(contrast_ratio("#777777", "#ffffff"), 4.48, places=1)

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

    def test_cleaned_output_matches_golden_files(self):
        from pathlib import Path

        fixture_dir = Path(__file__).parent / "golden_cleaned"
        manifest = json.loads((fixture_dir / "manifest.json").read_text(encoding="utf-8"))

        for case in manifest["cases"]:
            with self.subTest(case=case["name"]):
                input_lines = read_text_file_lines(str(fixture_dir / case["input"]))
                expected_text = (fixture_dir / case["expected"]).read_text(encoding="utf-8")
                expected_raw_lines = expected_text.rstrip("\n").split("\n")
                if expected_text.endswith("\n"):
                    expected_raw_lines.append("")
                expected_lines = [
                    line.replace("{APP_NAME}", hosts_editor.APP_NAME).replace("{APP_VERSION}", hosts_editor.APP_VERSION)
                    for line in expected_raw_lines
                ]
                cleaned, stats = _get_canonical_cleaned_output_and_stats(
                    input_lines,
                    set(case.get("whitelist", [])),
                    set(case.get("pinned_domains", [])),
                )

                self.assertEqual(cleaned, expected_lines)
                for key, expected_value in case.get("stats", {}).items():
                    self.assertEqual(stats[key], expected_value, f"{case['name']}.{key}")

    def _fuzz_domain(self, rng):
        labels = ["ads", "tracker", "cdn", "safe", "telemetry", "shop", "api", "media"]
        tlds = ["example", "test", "invalid", "local"]
        return f"{rng.choice(labels)}-{rng.randrange(100)}.{rng.choice(tlds)}"

    def _fuzz_hosts_line(self, rng):
        domain = self._fuzz_domain(rng)
        token_shapes = [
            domain,
            domain.upper(),
            f"*.{domain}",
            f"http://{domain}/pixel?id={rng.randrange(1000)}",
            f"https://{domain}/path#frag",
            f"||{domain}^$third-party",
            f"address=/{domain}/0.0.0.0",
            f"local=/{domain}/",
            f"@@||{domain}^",
            "localhost",
            "not a domain",
            f"[{domain}]",
            f"({domain})",
        ]
        ip_shapes = ["0.0.0.0", "127.0.0.1", "::1", "192.168.1.10", "255.255.255.0", ""]
        prefix = rng.choice(ip_shapes)
        token_count = rng.randint(1, 4)
        tokens = [rng.choice(token_shapes) for _ in range(token_count)]
        if prefix:
            tokens.insert(0, prefix)
        if rng.random() < 0.25:
            tokens.append("# trailing comment")
        if rng.random() < 0.10:
            return rng.choice(["", "   ", "# just a comment", "! adblock comment", "[metadata]"])
        return rng.choice([" ", "\t", ", ", "; "]).join(tokens)

    def test_parser_fuzzer_preserves_entry_invariants(self):
        import random

        rng = random.Random(20260512)
        for index in range(400):
            line = self._fuzz_hosts_line(rng)
            with self.subTest(index=index, line=line):
                parsed_entries, transformed = hosts_editor.parse_hosts_line_entries(line)
                normalized_entries, domains, normalized_transformed = normalize_line_to_hosts_entries(line)

                self.assertIsInstance(transformed, bool)
                self.assertEqual(normalized_transformed, transformed)
                self.assertEqual(normalized_entries, [entry for entry, _, _ in parsed_entries])
                self.assertEqual(domains, [domain for _, domain, _ in parsed_entries])
                self.assertEqual(len(normalized_entries), len(set(normalized_entries)))

                for entry, domain, is_block_entry in parsed_entries:
                    mapping_ip, entry_domain = entry.split(" ", 1)
                    self.assertEqual(entry_domain, domain)
                    self.assertEqual(domain, domain.lower())
                    self.assertTrue(looks_like_domain(domain, allow_single_label=True), (line, domain))
                    if is_block_entry:
                        self.assertEqual(mapping_ip, "0.0.0.0")

    def test_cleaned_output_fuzzer_is_idempotent(self):
        import random

        rng = random.Random(20260513)
        whitelist_pool = [self._fuzz_domain(rng) for _ in range(30)]
        pinned_pool = [self._fuzz_domain(rng) for _ in range(30)]

        for batch_index in range(40):
            lines = [self._fuzz_hosts_line(rng) for _ in range(35)]
            whitelist = set(rng.sample(whitelist_pool, rng.randrange(0, 5)))
            pinned = set(rng.sample(pinned_pool, rng.randrange(0, 4)))
            with self.subTest(batch=batch_index):
                cleaned, stats = _get_canonical_cleaned_output_and_stats(lines, whitelist, pinned)
                recleaned, restats = _get_canonical_cleaned_output_and_stats(cleaned, whitelist, pinned)

                self.assertEqual(recleaned, cleaned)
                self.assertEqual(restats["final_active"], stats["final_active"])
                self.assertGreaterEqual(stats["total_discarded"], 0)

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

    def test_sanitize_source_manifest_accepts_valid_manifest(self):
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
                        }
                    ],
                }
            ],
        }

        self.assertEqual(
            sanitize_source_manifest(manifest),
            {"Ads": [("Example Hosts", "https://example.com/hosts.txt", "Small test source.")]},
        )

    def test_sanitize_source_manifest_rejects_unsafe_or_ambiguous_entries(self):
        valid_source = {
            "name": "Example Hosts",
            "url": "https://example.com/hosts.txt",
            "description": "Small test source.",
        }
        cases = [
            {
                "schema_version": SOURCE_MANIFEST_SCHEMA_VERSION + 1,
                "categories": [{"name": "Ads", "sources": [valid_source]}],
            },
            {
                "schema_version": SOURCE_MANIFEST_SCHEMA_VERSION,
                "categories": [
                    {"name": "Ads", "sources": [valid_source]},
                    {"name": "ads", "sources": [{**valid_source, "name": "Other", "url": "https://other.example/list.txt"}]},
                ],
            },
            {
                "schema_version": SOURCE_MANIFEST_SCHEMA_VERSION,
                "categories": [
                    {"name": "Ads", "sources": [{**valid_source, "name": "Bad\nName"}]},
                ],
            },
            {
                "schema_version": SOURCE_MANIFEST_SCHEMA_VERSION,
                "categories": [
                    {"name": "Ads", "sources": [{**valid_source, "url": "ftp://example.com/hosts.txt"}]},
                ],
            },
            {
                "schema_version": SOURCE_MANIFEST_SCHEMA_VERSION,
                "categories": [
                    {
                        "name": "Ads",
                        "sources": [
                            valid_source,
                            {"name": "Duplicate URL", "url": "https://example.com/hosts.txt/", "description": ""},
                        ],
                    }
                ],
            },
        ]

        for manifest in cases:
            with self.subTest(manifest=manifest):
                with self.assertRaises(ValueError):
                    sanitize_source_manifest(manifest)

    def test_load_blocklist_sources_manifest_reads_project_manifest(self):
        loaded = load_blocklist_sources_manifest()
        self.assertEqual(loaded, HostsFileEditor.BLOCKLIST_SOURCES)
        self.assertIn("Major / Unified / Aggregated", loaded)
        self.assertGreaterEqual(sum(len(sources) for sources in loaded.values()), 100)
        self.assertTrue(
            any(
                name == "HaGezi Ultimate"
                for sources in loaded.values()
                for name, _url, _description in sources
            )
        )

    def test_load_blocklist_sources_manifest_reads_explicit_path(self):
        import tempfile
        from pathlib import Path

        manifest = {
            "schema_version": SOURCE_MANIFEST_SCHEMA_VERSION,
            "categories": [
                {
                    "name": "Security",
                    "sources": [
                        {
                            "name": "Threat Feed",
                            "url": "https://threats.example/hosts.txt",
                            "description": "Threat domains.",
                        }
                    ],
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "blocklist_sources.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(
                load_blocklist_sources_manifest(str(path)),
                {"Security": [("Threat Feed", "https://threats.example/hosts.txt", "Threat domains.")]},
            )

    def test_source_adapter_plugin_manifest_is_manifest_only_and_merges_sources(self):
        manifest = {
            "schema_version": SOURCE_ADAPTER_PLUGIN_SCHEMA_VERSION,
            "id": "lab-pack",
            "name": "Lab Pack",
            "description": "Internal reviewed feeds.",
            "homepage": "https://example.com/lab-pack",
            "maintainer": "Ops",
            "license": "MIT",
            "sources": [
                {
                    "name": "Lab Threats",
                    "url": "https://example.com/lab-threats.txt",
                    "description": "Internal threat feed.",
                    "category": "Threat Feeds",
                }
            ],
        }

        plugin = sanitize_source_adapter_plugin_manifest(manifest, source_path="plugin.json")
        self.assertEqual(plugin["schema"], SOURCE_ADAPTER_PLUGIN_SCHEMA)
        self.assertEqual(plugin["id"], "lab-pack")
        self.assertEqual(plugin["source_count"], 1)

        plugin_sources = build_source_adapter_plugin_sources([plugin])
        self.assertEqual(
            plugin_sources,
            {
                "Plugin: Threat Feeds": [
                    (
                        "Lab Threats",
                        "https://example.com/lab-threats.txt",
                        "Internal threat feed. Plugin: Lab Pack.",
                    )
                ]
            },
        )

        merged = merge_source_adapter_plugin_sources(
            {"Curated": [("Curated Feed", "https://curated.example/hosts.txt", "Core feed.")]},
            plugin_sources,
        )
        self.assertIn("Curated", merged)
        self.assertIn("Plugin: Threat Feeds", merged)
        self.assertIn("JSON manifests only", format_source_adapter_plugin_catalog({
            "plugin_dirs": ["C:\\plugins"],
            "plugins": [plugin],
            "errors": [],
            "source_count": 1,
        }))

    def test_source_adapter_plugin_rejects_invalid_or_ambiguous_sources(self):
        manifest = {
            "schema_version": SOURCE_ADAPTER_PLUGIN_SCHEMA_VERSION,
            "id": "bad-pack",
            "name": "Bad Pack",
            "sources": [
                {"name": "One", "url": "https://example.com/one.txt"},
                {"name": "one", "url": "https://example.com/two.txt"},
            ],
        }

        with self.assertRaises(ValueError):
            sanitize_source_adapter_plugin_manifest(manifest)

        bad_url = json.loads(json.dumps(manifest))
        bad_url["sources"] = [{"name": "One", "url": "file:///tmp/hosts.txt"}]
        with self.assertRaises(ValueError):
            sanitize_source_adapter_plugin_manifest(bad_url)

    def test_load_source_adapter_plugin_catalog_reports_skipped_manifests(self):
        import tempfile
        from pathlib import Path

        good_manifest = {
            "schema_version": SOURCE_ADAPTER_PLUGIN_SCHEMA_VERSION,
            "id": "good-pack",
            "name": "Good Pack",
            "sources": [{"name": "Good Feed", "url": "https://example.com/good.txt"}],
        }
        bad_manifest = {
            "schema_version": SOURCE_ADAPTER_PLUGIN_SCHEMA_VERSION,
            "id": "bad-pack",
            "name": "Bad Pack",
            "sources": [{"name": "Bad Feed", "url": "ftp://example.com/bad.txt"}],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir)
            (plugin_dir / "good.json").write_text(json.dumps(good_manifest), encoding="utf-8")
            (plugin_dir / "bad.json").write_text(json.dumps(bad_manifest), encoding="utf-8")
            catalog = load_source_adapter_plugin_catalog([str(plugin_dir)])

        self.assertEqual(catalog["source_count"], 1)
        self.assertEqual(catalog["plugins"][0]["id"], "good-pack")
        self.assertEqual(len(catalog["errors"]), 1)
        self.assertIn("invalid URL", catalog["errors"][0]["error"])

    def test_local_api_auth_and_clean_preview_are_read_only(self):
        token = "0123456789abcdef"
        self.assertEqual(sanitize_local_api_token(f" {token} "), token)
        self.assertTrue(local_api_authorization_valid({"Authorization": f"Bearer {token}"}, token))
        self.assertFalse(local_api_authorization_valid({"Authorization": "Bearer wrong"}, token))

        status = build_local_api_status_payload("C:\\Windows\\System32\\drivers\\etc\\hosts")
        self.assertFalse(status["write_endpoints_enabled"])
        self.assertEqual(status["endpoints"][0]["path"], "/v1/status")

        preview = build_local_api_clean_preview_payload({
            "lines": [
                "0.0.0.0 ads.example",
                "0.0.0.0 ads.example",
                "0.0.0.0 keep.example",
            ],
            "whitelist": ["keep.example"],
        })

        self.assertFalse(preview["writes_hosts"])
        self.assertIn("0.0.0.0 ads.example", preview["cleaned_lines"])
        self.assertNotIn("0.0.0.0 keep.example", preview["cleaned_lines"])
        self.assertGreaterEqual(preview["stats"]["removed_duplicates"], 1)

    def test_local_api_server_requires_bearer_and_serves_preview(self):
        token = "0123456789abcdef"
        server = create_local_api_server(host="127.0.0.1", port=0, token=token)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            base_url = f"http://{host}:{port}"
            with self.assertRaises(urllib.error.HTTPError) as denied:
                urllib.request.urlopen(f"{base_url}/v1/status", timeout=5)
            self.assertEqual(denied.exception.code, 401)

            status_request = urllib.request.Request(
                f"{base_url}/v1/status",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(status_request, timeout=5) as response:
                status = json.loads(response.read().decode("utf-8"))
            self.assertEqual(status["schema"], "hostsfileget.local-api.v1")
            self.assertFalse(status["write_endpoints_enabled"])

            body = json.dumps({"text": "0.0.0.0 api.example\n0.0.0.0 api.example\n"}).encode("utf-8")
            preview_request = urllib.request.Request(
                f"{base_url}/v1/clean-preview",
                data=body,
                method="POST",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(preview_request, timeout=5) as response:
                preview = json.loads(response.read().decode("utf-8"))
            self.assertEqual(preview["cleaned_lines"].count("0.0.0.0 api.example"), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_local_api_server_rejects_non_loopback_hosts_and_short_tokens(self):
        with self.assertRaises(ValueError):
            create_local_api_server(host="0.0.0.0", port=0, token="0123456789abcdef")
        with self.assertRaises(ValueError):
            create_local_api_server(host="127.0.0.1", port=0, token="short")

    def test_source_bundle_catalog_sanitizes_manifest_references(self):
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
                        },
                        {
                            "name": "Privacy Hosts",
                            "url": "https://privacy.example/hosts.txt",
                            "description": "Privacy test source.",
                        },
                    ],
                }
            ],
            "bundles": [
                {
                    "id": "starter",
                    "name": "Starter",
                    "description": "Small starter bundle.",
                    "risk": "low",
                    "source_names": ["Example Hosts", "Privacy Hosts"],
                }
            ],
        }

        blocklist_sources = sanitize_source_manifest(manifest)
        catalog = sanitize_source_bundle_catalog(manifest, blocklist_sources)

        self.assertEqual(len(catalog), 1)
        self.assertEqual(catalog[0]["id"], "starter")
        self.assertEqual(catalog[0]["source_count"], 2)
        self.assertEqual(catalog[0]["sources"][0]["category"], "Ads")
        self.assertEqual(
            source_bundle_to_import_sources(catalog[0]),
            [
                ("Example Hosts", "https://example.com/hosts.txt"),
                ("Privacy Hosts", "https://privacy.example/hosts.txt"),
            ],
        )

    def test_source_bundle_catalog_rejects_missing_or_duplicate_sources(self):
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
                        }
                    ],
                }
            ],
            "bundles": [
                {
                    "id": "starter",
                    "name": "Starter",
                    "risk": "low",
                    "source_names": ["Example Hosts", "Missing Hosts"],
                }
            ],
        }

        with self.assertRaises(ValueError):
            sanitize_source_bundle_catalog(manifest)

        duplicate_manifest = json.loads(json.dumps(manifest))
        duplicate_manifest["bundles"][0]["source_names"] = ["Example Hosts", "example hosts"]
        with self.assertRaises(ValueError):
            sanitize_source_bundle_catalog(duplicate_manifest)

    def test_source_bundle_formatters_show_catalog_and_detail(self):
        catalog = [
            {
                "id": "starter",
                "name": "Starter",
                "description": "Small starter bundle.",
                "risk": "low",
                "source_count": 1,
                "sources": [
                    {
                        "name": "Example Hosts",
                        "url": "https://example.com/hosts.txt",
                        "description": "Small test source.",
                        "category": "Ads",
                    }
                ],
            }
        ]

        self.assertIn("Starter", format_source_bundle_catalog(catalog))
        self.assertIn("risk: low", format_source_bundle_catalog(catalog))
        detail = format_source_bundle_report(catalog[0])
        self.assertIn("Source Bundle: Starter", detail)
        self.assertIn("Example Hosts [Ads]", detail)

    def test_project_source_bundle_manifest_loads_and_indexes_sources(self):
        bundles = load_source_bundle_catalog(blocklist_sources=HostsFileEditor.BLOCKLIST_SOURCES)
        index = build_source_manifest_index(HostsFileEditor.BLOCKLIST_SOURCES)

        self.assertEqual(bundles, HostsFileEditor.SOURCE_BUNDLES)
        self.assertGreaterEqual(len(bundles), 5)
        self.assertIn("HaGezi Light", index)
        starter = hosts_editor.find_source_bundle(bundles, "starter-low-breakage")
        self.assertIsNotNone(starter)
        self.assertGreaterEqual(starter["source_count"], 3)
        self.assertTrue(
            all(source["name"] in index for source in starter["sources"])
        )

    def test_sanitize_i18n_catalog_accepts_versioned_messages(self):
        catalog = {
            "schema_version": I18N_CATALOG_SCHEMA_VERSION,
            "locale": "en-us",
            "messages": {
                "common.close": "Close",
                "dialog.example.title": "Example title",
            },
        }

        sanitized = sanitize_i18n_catalog(catalog)
        self.assertEqual(sanitized["locale"], "en-US")
        self.assertEqual(sanitized["messages"]["dialog.example.title"], "Example title")

    def test_sanitize_i18n_catalog_rejects_bad_shape(self):
        cases = [
            {"schema_version": I18N_CATALOG_SCHEMA_VERSION + 1, "locale": "en-US", "messages": {"common.close": "Close"}},
            {"schema_version": I18N_CATALOG_SCHEMA_VERSION, "locale": "../bad", "messages": {"common.close": "Close"}},
            {"schema_version": I18N_CATALOG_SCHEMA_VERSION, "locale": "en-US", "messages": {"Bad Key": "Close"}},
            {"schema_version": I18N_CATALOG_SCHEMA_VERSION, "locale": "en-US", "messages": {"common.close": "Close\nNow"}},
            {"schema_version": I18N_CATALOG_SCHEMA_VERSION, "locale": "en-US", "messages": {"common.close": 3}},
        ]

        for catalog in cases:
            with self.subTest(catalog=catalog):
                with self.assertRaises(ValueError):
                    sanitize_i18n_catalog(catalog)

    def test_load_i18n_catalog_merges_missing_keys_from_builtin_fallback(self):
        import tempfile
        from pathlib import Path

        catalog = {
            "schema_version": I18N_CATALOG_SCHEMA_VERSION,
            "locale": "en-US",
            "messages": {
                "common.close": "Dismiss",
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "en-US.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            loaded = load_i18n_catalog(str(path))

        self.assertEqual(loaded["messages"]["common.close"], "Dismiss")
        self.assertEqual(loaded["messages"]["common.details"], "Details")
        self.assertEqual(translate_message(loaded, "missing.key", fallback="Fallback"), "Fallback")

    def test_load_i18n_catalog_reads_project_catalog(self):
        loaded = load_i18n_catalog()
        report = build_i18n_catalog_report(loaded)
        self.assertEqual(loaded["locale"], normalize_locale_code("en-US"))
        self.assertIn("dialog.i18n.title", loaded["messages"])
        self.assertEqual(report["missing_required_keys"], [])
        self.assertIn("Translation catalog", format_i18n_catalog_report(report))

    def test_translate_message_formats_named_values_safely(self):
        catalog = {
            "messages": {
                "status.count": "{count} entries",
                "status.bad_template": "{missing} entries",
            }
        }

        self.assertEqual(translate_message(catalog, "status.count", count=3), "3 entries")
        self.assertEqual(translate_message(catalog, "status.bad_template", count=3), "{missing} entries")

    def test_i18n_contribution_template_is_complete_and_normalized(self):
        template = build_i18n_contribution_template("es-mx", {
            "status.count": "{count} entries",
            "common.close": "Close",
        })

        self.assertEqual(template["locale"], "es-MX")
        self.assertEqual(list(template["messages"]), ["common.close", "status.count"])
        report = build_i18n_contribution_report(template, {
            "status.count": "{count} entries",
            "common.close": "Close",
        })
        self.assertTrue(report["ready"])
        self.assertEqual(report["completion_percent"], 100.0)
        self.assertEqual(report["unchanged_english_keys"], ["common.close", "status.count"])

    def test_i18n_contribution_report_flags_missing_extra_and_placeholders(self):
        catalog = {
            "schema_version": I18N_CATALOG_SCHEMA_VERSION,
            "locale": "fr-FR",
            "messages": {
                "status.count": "{total} entrees",
                "extra.key": "Extra",
            },
        }

        report = build_i18n_contribution_report(catalog, {
            "status.count": "{count} entries",
            "common.close": "Close",
        })

        self.assertFalse(report["ready"])
        self.assertEqual(report["missing_required_keys"], ["common.close"])
        self.assertEqual(report["extra_keys"], ["extra.key"])
        self.assertEqual(report["placeholder_mismatches"][0]["key"], "status.count")
        formatted = format_i18n_contribution_report(report)
        self.assertIn("needs-work", formatted)
        self.assertIn("expected count; found total", formatted)

    def test_cli_i18n_template_and_validate_roundtrip(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "es-MX.json"
            with mock.patch.object(hosts_editor, "_cli_print"):
                self.assertEqual(hosts_editor._cli_i18n_template("es-mx", str(path)), 0)
                self.assertEqual(hosts_editor._cli_i18n_validate(str(path)), 0)

            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(payload["locale"], "es-MX")
        self.assertIn("common.close", payload["messages"])

    def test_check_source_health_record_marks_host_sample_healthy(self):
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

        def opener(request, timeout=None):
            self.assertEqual(request.full_url, "https://example.com/hosts.txt")
            self.assertLessEqual(timeout, 5)
            return FakeResponse()

        result = check_source_health_record(
            {"category": "Ads", "name": "Example", "url": "https://example.com/hosts.txt"},
            opener=opener,
            timeout=5,
        )

        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["bytes_read"], len(b"0.0.0.0 tracker.example\n"))
        self.assertIn("host-like", result["diagnostic"])

    def test_check_source_health_record_flags_html_and_empty_samples(self):
        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload
                self.headers = {"Content-Type": "text/html"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getcode(self):
                return 200

            def read(self, size):
                return self.payload

        html = check_source_health_record(
            {"category": "Ads", "name": "HTML", "url": "https://example.com/html"},
            opener=lambda request, timeout=None: FakeResponse(b"<html><head><title>Nope</title></head><body></body></html>"),
            timeout=1,
        )
        empty = check_source_health_record(
            {"category": "Ads", "name": "Empty", "url": "https://example.com/empty"},
            opener=lambda request, timeout=None: FakeResponse(b""),
            timeout=1,
        )

        self.assertEqual(html["status"], "failed")
        self.assertIn("HTML", html["diagnostic"])
        self.assertEqual(empty["status"], "warning")
        self.assertIn("empty", empty["diagnostic"])

    def test_check_source_health_record_treats_oversized_sample_as_warning(self):
        class FakeResponse:
            headers = {"Content-Type": "text/plain"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getcode(self):
                return 200

            def read(self, size):
                return b"x" * size

        result = check_source_health_record(
            {"category": "Ads", "name": "Large", "url": "https://example.com/large.txt"},
            opener=lambda request, timeout=None: FakeResponse(),
            sample_bytes=1024,
        )

        self.assertEqual(result["status"], "warning")
        self.assertIn("1 KB", result["diagnostic"])

    def test_check_source_health_records_preserves_order_and_summarizes(self):
        payloads = {
            "https://one.example/hosts.txt": b"0.0.0.0 one.example\n",
            "https://two.example/readme.txt": b"plain text without domains\n",
        }

        class FakeResponse:
            headers = {"Content-Type": "text/plain"}

            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getcode(self):
                return 200

            def read(self, size):
                return self.payload

        def opener(request, timeout=None):
            return FakeResponse(payloads[request.full_url])

        records = [
            {"category": "Ads", "name": "One", "url": "https://one.example/hosts.txt"},
            {"category": "Docs", "name": "Two", "url": "https://two.example/readme.txt"},
        ]
        results = check_source_health_records(records, opener=opener, max_workers=1)

        self.assertEqual([result["name"] for result in results], ["One", "Two"])
        self.assertEqual([result["status"] for result in results], ["healthy", "warning"])
        self.assertEqual(
            summarize_source_health_results(results),
            {"total": 2, "healthy": 1, "warning": 1, "failed": 0},
        )

    def test_build_source_health_report_shape(self):
        class FakeResponse:
            headers = {"Content-Type": "text/plain"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getcode(self):
                return 200

            def read(self, size):
                return b"0.0.0.0 ok.example\n"

        report = build_source_health_report(
            {"Ads": [("One", "https://one.example/hosts.txt", "Example")]},
            opener=lambda request, timeout=None: FakeResponse(),
            max_workers=1,
        )

        self.assertEqual(report["schema_version"], SOURCE_HEALTH_REPORT_SCHEMA_VERSION)
        self.assertEqual(report["summary"], {"total": 1, "healthy": 1, "warning": 0, "failed": 0})
        self.assertEqual(report["sources"][0]["category"], "Ads")

    def test_source_trust_badges_explain_github_https_sources(self):
        badges = build_source_trust_badges(
            "Example",
            "https://raw.githubusercontent.com/owner/repo/main/hosts.txt",
            "Balanced host list.",
            category="Ads",
            source_kind="curated",
            last_fetched="2026-05-12T12:00:00",
        )
        labels = [badge["label"] for badge in badges]

        self.assertIn("Curated", labels)
        self.assertIn("HTTPS", labels)
        self.assertIn("GitHub-backed", labels)
        self.assertIn("License untracked", labels)
        self.assertIn("Issue path", labels)
        self.assertIn("GitHub-backed", format_source_trust_badges(badges))
        self.assertEqual(
            source_trust_report_url("https://raw.githubusercontent.com/owner/repo/main/hosts.txt"),
            "https://github.com/owner/repo/issues",
        )

    def test_source_trust_badges_flag_http_and_broad_scope(self):
        badges = build_source_trust_badges(
            "Aggressive Source",
            "http://vxvault.net/URL_List.php",
            "Maximum coverage feed. Requires Processing.",
            category="Malware / Phishing / Scam",
            source_kind="saved",
        )
        labels = [badge["label"] for badge in badges]

        self.assertIn("Saved", labels)
        self.assertIn("HTTP", labels)
        self.assertIn("Direct host", labels)
        self.assertIn("Report manually", labels)
        self.assertIn("Review scope", labels)

    def test_source_trust_report_url_handles_jsdelivr_github_mirror(self):
        self.assertEqual(
            source_trust_report_url("https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/ultimate.txt"),
            "https://github.com/hagezi/dns-blocklists/issues",
        )

    def test_false_positive_triage_reports_block_whitelist_pin_and_sources(self):
        report = build_false_positive_triage_report(
            "ads.example",
            [
                "0.0.0.0 ads.example",
                "0.0.0.0 sub.ads.example tracker.example",
                "192.168.1.10 ads.example",
            ],
            whitelist_set={"example"},
            pinned_domains={"ads.example"},
            source_corpus={
                "one": {"name": "Example Source", "text": "0.0.0.0 ads.example\n"},
            },
        )

        self.assertTrue(report["valid"])
        self.assertEqual(report["domain"], "ads.example")
        self.assertTrue(report["on_whitelist"])
        self.assertTrue(report["is_pinned"])
        self.assertEqual(len(report["blocked_on_lines"]), 2)
        self.assertEqual(report["source_matches"], ["Example Source"])
        action_ids = {action["id"] for action in report["recommended_actions"]}
        self.assertIn("remove_matching_lines", action_ids)
        self.assertIn("unpin_domain", action_ids)
        formatted = format_false_positive_triage_report(
            report,
            not_yet_fetched_count=2,
            source_issue_urls={"Example Source": "https://github.com/owner/repo/issues"},
        )
        self.assertIn("BLOCKED in current editor", formatted)
        self.assertIn("Whitelist: YES", formatted)
        self.assertIn("report: https://github.com/owner/repo/issues", formatted)

    def test_false_positive_triage_rejects_single_label_domains(self):
        domain, error = normalize_false_positive_domain("localhost")

        self.assertEqual(domain, "")
        self.assertIn("multi-label domain", error)

    def test_add_domain_to_whitelist_text_appends_and_dedupes_coverage(self):
        text, added = add_domain_to_whitelist_text("# keep\nexample.com\n", "ads.example.com")

        self.assertFalse(added)
        self.assertEqual(text, "# keep\nexample.com\n")

        text, added = add_domain_to_whitelist_text("# keep\n", "ads.example.com")

        self.assertTrue(added)
        self.assertEqual(text, "# keep\nads.example.com\n")

    def test_remove_false_positive_matches_removes_only_blocking_lines(self):
        lines = [
            "0.0.0.0 ads.example",
            "127.0.0.1 sub.ads.example tracker.example",
            "192.168.1.10 ads.example",
            "# 0.0.0.0 ads.example",
        ]

        new_lines, removed = remove_false_positive_matches_from_lines(lines, "ads.example")

        self.assertEqual(new_lines, ["192.168.1.10 ads.example", "# 0.0.0.0 ads.example"])
        self.assertEqual(len(removed), 2)
        self.assertEqual(removed[1]["matched_domains"], ["sub.ads.example"])

    def test_source_cache_metadata_sanitizes_headers_and_hashes(self):
        good_hash = "a" * 64
        sanitized = sanitize_source_cache_metadata(
            {
                "https://example.com/hosts.txt": {
                    "content_sha256": good_hash.upper(),
                    "bytes": "12",
                    "etag": '"abc123"',
                    "last_modified": "Wed, 21 Oct 2015 07:28:00 GMT",
                    "content_encoding": "gzip",
                    "fetched_at": "2026-05-12T12:00:00",
                    "validated_at": "2026-05-12T12:05:00",
                },
                "not-a-url": {"content_sha256": good_hash},
                "https://bad.example/hosts.txt": {"content_sha256": "bad"},
            }
        )

        self.assertEqual(list(sanitized), ["https://example.com/hosts.txt"])
        entry = sanitized["https://example.com/hosts.txt"]
        self.assertEqual(entry["content_sha256"], good_hash)
        self.assertEqual(entry["bytes"], 12)
        self.assertEqual(entry["etag"], '"abc123"')
        self.assertEqual(entry["content_encoding"], "gzip")

    def test_build_source_request_headers_adds_conditional_headers(self):
        headers = build_source_request_headers(
            {
                "etag": '"abc123"',
                "last_modified": "Wed, 21 Oct 2015 07:28:00 GMT",
            }
        )

        self.assertIn("User-Agent", headers)
        self.assertEqual(headers["If-None-Match"], '"abc123"')
        self.assertEqual(headers["If-Modified-Since"], "Wed, 21 Oct 2015 07:28:00 GMT")

    def test_fetch_source_with_cache_reuses_body_on_304(self):
        import tempfile

        class FakeResponse:
            headers = {
                "ETag": '"v1"',
                "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT",
                "Content-Encoding": "",
            }
            fp = None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getcode(self):
                return 200

            def info(self):
                return self.headers

            def read(self, size):
                return b"0.0.0.0 cached.example\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_store = {}
            lines, metadata, status = fetch_source_with_cache(
                "https://example.com/hosts.txt",
                metadata_store,
                cache_dir=tmpdir,
                opener=lambda request, timeout=None: FakeResponse(),
            )
            self.assertEqual(status, "network")
            self.assertEqual(lines, ["0.0.0.0 cached.example"])
            metadata_store["https://example.com/hosts.txt"] = metadata

            def opener_304(request, timeout=None):
                self.assertIn('"v1"', set(request.headers.values()))
                raise hosts_editor.urllib.error.HTTPError(
                    request.full_url,
                    304,
                    "Not Modified",
                    {},
                    None,
                )

            lines, refreshed_metadata, status = fetch_source_with_cache(
                "https://example.com/hosts.txt",
                metadata_store,
                cache_dir=tmpdir,
                opener=opener_304,
            )

            self.assertEqual(status, "not_modified")
            self.assertEqual(lines, ["0.0.0.0 cached.example"])
            self.assertEqual(refreshed_metadata["etag"], '"v1"')

    def test_fetch_source_with_cache_uses_cache_on_network_error(self):
        import tempfile

        class FakeResponse:
            headers = {"ETag": '"v1"', "Last-Modified": "", "Content-Encoding": ""}
            fp = None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getcode(self):
                return 200

            def info(self):
                return self.headers

            def read(self, size):
                return b"0.0.0.0 fallback.example\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            _lines, metadata, _status = fetch_source_with_cache(
                "https://example.com/hosts.txt",
                {},
                cache_dir=tmpdir,
                opener=lambda request, timeout=None: FakeResponse(),
            )
            lines, _metadata, status = fetch_source_with_cache(
                "https://example.com/hosts.txt",
                {"https://example.com/hosts.txt": metadata},
                cache_dir=tmpdir,
                opener=lambda request, timeout=None: (_ for _ in ()).throw(
                    hosts_editor.urllib.error.URLError("offline")
                ),
            )

            self.assertEqual(status, "cache_fallback")
            self.assertEqual(lines, ["0.0.0.0 fallback.example"])

    def test_fetch_source_with_cache_does_not_replace_cache_until_decode_succeeds(self):
        import tempfile

        class FakeResponse:
            headers = {"ETag": '"v1"', "Last-Modified": "", "Content-Encoding": ""}
            fp = None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getcode(self):
                return 200

            def info(self):
                return self.headers

            def read(self, size):
                return b"0.0.0.0 preserved.example\n"

        class BadResponse(FakeResponse):
            headers = {"ETag": '"v2"', "Last-Modified": "", "Content-Encoding": ""}

            def read(self, size):
                return b"bad-payload"

        url = "https://example.com/hosts.txt"
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch(
                "hosts_editor.decode_downloaded_lines",
                side_effect=[
                    ["0.0.0.0 preserved.example"],
                    ValueError("bad payload"),
                    ["0.0.0.0 preserved.example"],
                ],
            ):
                _lines, metadata, _status = fetch_source_with_cache(
                    url,
                    {},
                    cache_dir=tmpdir,
                    opener=lambda request, timeout=None: FakeResponse(),
                )
                cache_path = get_source_cache_body_path(url, tmpdir)
                with open(cache_path, "rb") as f:
                    cached_before = f.read()

                lines, refreshed_metadata, status = fetch_source_with_cache(
                    url,
                    {url: metadata},
                    cache_dir=tmpdir,
                    opener=lambda request, timeout=None: BadResponse(),
                )

            with open(cache_path, "rb") as f:
                cached_after = f.read()
            self.assertEqual(status, "cache_fallback")
            self.assertEqual(lines, ["0.0.0.0 preserved.example"])
            self.assertEqual(refreshed_metadata["etag"], '"v1"')
            self.assertEqual(cached_after, cached_before)

    def test_fetch_source_with_retries_retries_then_succeeds(self):
        calls = []
        sleeps = []

        def fake_fetch(url, metadata_store, cache_dir=None, timeout=15):
            calls.append((url, dict(metadata_store), cache_dir, timeout))
            if len(calls) == 1:
                raise hosts_editor.urllib.error.URLError("temporary")
            return ["0.0.0.0 retry.example"], {"etag": '"v2"'}, "network"

        lines, metadata, status, attempts = fetch_source_with_retries(
            "https://example.com/retry.txt",
            {"https://example.com/retry.txt": {"etag": '"v1"'}},
            cache_dir="cache-dir",
            timeout=7,
            max_attempts=3,
            retry_delay=0.01,
            sleep_fn=sleeps.append,
            fetch_fn=fake_fetch,
        )

        self.assertEqual(lines, ["0.0.0.0 retry.example"])
        self.assertEqual(metadata["etag"], '"v2"')
        self.assertEqual(status, "network")
        self.assertEqual(attempts, 2)
        self.assertEqual(len(calls), 2)
        self.assertEqual(sleeps, [0.01])

    def test_resolve_import_fetch_worker_count_clamps_to_sources_and_limit(self):
        self.assertEqual(resolve_import_fetch_worker_count(0), 0)
        self.assertEqual(resolve_import_fetch_worker_count(1), 1)
        self.assertEqual(resolve_import_fetch_worker_count(99, max_workers=4), 4)
        self.assertEqual(resolve_import_fetch_worker_count(2, max_workers=99), 2)
        self.assertEqual(resolve_import_fetch_worker_count("bad"), 0)

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

    def test_build_virtual_list_page_clamps_bounds_and_slices(self):
        rows = list(range(1000))

        first = build_virtual_list_page(rows, page_index=-10, page_size=250)
        self.assertEqual(first["page_index"], 0)
        self.assertEqual(first["page_count"], 4)
        self.assertEqual(first["rows"][0], 0)
        self.assertEqual(first["rows"][-1], 249)

        last = build_virtual_list_page(rows, page_index=99, page_size=250)
        self.assertEqual(last["page_index"], 3)
        self.assertEqual(last["start"], 750)
        self.assertEqual(last["end"], 1000)
        self.assertEqual(last["rows"][-1], 999)

    def test_build_virtual_list_page_caps_page_size(self):
        rows = list(range(1200))
        page = build_virtual_list_page(rows, page_index=1, page_size=10_000)

        self.assertEqual(page["page_size"], 500)
        self.assertEqual(page["start"], 500)
        self.assertEqual(page["end"], 1000)

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
        self.assertEqual(payload["config_version"], CONFIG_SCHEMA_VERSION)

    def test_migrate_config_snapshot_stamps_current_version(self):
        migrated = migrate_config_snapshot({"config_version": CONFIG_SCHEMA_VERSION})

        self.assertEqual(migrated["config_version"], CONFIG_SCHEMA_VERSION)

    def test_sanitize_config_snapshot_migrates_missing_version(self):
        payload = sanitize_config_snapshot({"whitelist": "legacy.example"}, os.getcwd())

        self.assertEqual(payload["config_version"], CONFIG_SCHEMA_VERSION)
        self.assertEqual(payload["whitelist"], "legacy.example")

    def test_sanitize_config_snapshot_normalizes_invalid_and_future_versions(self):
        future_payload = sanitize_config_snapshot(
            {"config_version": CONFIG_SCHEMA_VERSION + 100, "whitelist": "future.example"},
            os.getcwd(),
        )
        invalid_payload = sanitize_config_snapshot(
            {"config_version": True, "whitelist": "bool.example"},
            os.getcwd(),
        )

        self.assertEqual(future_payload["config_version"], CONFIG_SCHEMA_VERSION)
        self.assertEqual(future_payload["whitelist"], "future.example")
        self.assertEqual(invalid_payload["config_version"], CONFIG_SCHEMA_VERSION)
        self.assertEqual(invalid_payload["whitelist"], "bool.example")

    def test_sanitize_config_snapshot_migrates_legacy_aliases(self):
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
        payload = sanitize_config_snapshot(
            {
                "sources": [{"name": "Legacy", "url": "https://example.com/legacy.txt"}],
                "whitelist_domains": ["keep.example", "safe.example"],
                "last_fetched": {"https://example.com/legacy.txt": stamp},
                "block_sink": "::1",
            },
            os.getcwd(),
        )

        self.assertEqual(payload["config_version"], CONFIG_SCHEMA_VERSION)
        self.assertEqual(
            payload["custom_sources"],
            [{"name": "Legacy", "url": "https://example.com/legacy.txt"}],
        )
        self.assertEqual(payload["whitelist"], "keep.example\nsafe.example")
        self.assertEqual(payload["source_last_fetched"], {"https://example.com/legacy.txt": stamp})
        self.assertEqual(payload["preferred_block_sink"], "::1")

    def test_sanitize_profile_id_allows_safe_slug_only(self):
        self.assertEqual(sanitize_profile_id("Work_Profile-1"), "work_profile-1")
        self.assertEqual(sanitize_profile_id("../evil"), DEFAULT_PROFILE_ID)
        self.assertEqual(sanitize_profile_id("", "fallback"), "fallback")

    def test_sanitize_config_snapshot_builds_default_profile_from_current_fields(self):
        payload = sanitize_config_snapshot(
            {
                "whitelist": ["keep.example", "safe.example"],
                "custom_sources": [{"name": "Feed", "url": "https://example.com/hosts.txt"}],
                "pinned_domains": ["Pinned.Example", "bad value"],
                "preferred_block_sink": "::1",
            },
            os.getcwd(),
        )

        self.assertEqual(payload["config_version"], CONFIG_SCHEMA_VERSION)
        self.assertEqual(payload["profile_schema_version"], PROFILE_SCHEMA_VERSION)
        self.assertEqual(payload["active_profile_id"], DEFAULT_PROFILE_ID)
        self.assertEqual(len(payload["profiles"]), 1)

        profile = payload["profiles"][0]
        self.assertEqual(profile["schema_version"], PROFILE_SCHEMA_VERSION)
        self.assertEqual(profile["id"], DEFAULT_PROFILE_ID)
        self.assertEqual(profile["name"], "Default")
        self.assertEqual(profile["whitelist"], "keep.example\nsafe.example")
        self.assertEqual(profile["custom_sources"], [{"name": "Feed", "url": "https://example.com/hosts.txt"}])
        self.assertEqual(profile["pinned_domains"], ["pinned.example"])
        self.assertEqual(profile["preferred_block_sink"], "::1")

    def test_sanitize_profiles_snapshot_sanitizes_mapping_and_active_profile(self):
        profiles, active_id = sanitize_profiles_snapshot(
            {
                "Work": {
                    "name": "Work",
                    "whitelist": "work.example",
                    "preferred_block_sink": "127.0.0.1",
                },
                "../bad": {
                    "name": "Bad",
                    "whitelist": "bad.example",
                },
            },
            active_profile_id="WORK",
        )

        self.assertEqual(active_id, "work")
        self.assertEqual([profile["id"] for profile in profiles], ["work", "profile-2"])
        self.assertEqual(profiles[0]["whitelist"], "work.example")
        self.assertEqual(profiles[0]["preferred_block_sink"], "127.0.0.1")

    def test_sanitize_profiles_snapshot_dedupes_duplicate_ids(self):
        profiles, active_id = sanitize_profiles_snapshot(
            [
                {"id": "work", "name": "Work"},
                {"id": "work", "name": "Work Copy"},
                {"id": "../bad", "name": "Bad"},
            ],
            active_profile_id="missing",
        )

        self.assertEqual(active_id, "work")
        self.assertEqual([profile["id"] for profile in profiles], ["work", "work-2", "profile-3"])

    def test_update_active_profile_snapshot_refreshes_only_active_profile(self):
        profiles = [
            sanitize_profile_snapshot({"id": "default", "name": "Default", "whitelist": "old.example"}),
            sanitize_profile_snapshot({"id": "work", "name": "Work", "whitelist": "old-work.example"}),
        ]

        updated, active_id = update_active_profile_snapshot(
            profiles,
            "work",
            {
                "whitelist": "new-work.example",
                "custom_sources": [{"name": "Feed", "url": "https://example.com/hosts.txt"}],
                "pinned_domains": ["Pinned.Example"],
                "preferred_block_sink": "::",
            },
        )

        self.assertEqual(active_id, "work")
        self.assertEqual(updated[0]["whitelist"], "old.example")
        self.assertEqual(updated[1]["name"], "Work")
        self.assertEqual(updated[1]["whitelist"], "new-work.example")
        self.assertEqual(updated[1]["custom_sources"], [{"name": "Feed", "url": "https://example.com/hosts.txt"}])
        self.assertEqual(updated[1]["pinned_domains"], ["pinned.example"])
        self.assertEqual(updated[1]["preferred_block_sink"], "::")

    def test_parse_declarative_config_yaml_sanitizes_profile_payload(self):
        profile = parse_declarative_config_text(
            """
schema: "hostsfileget.declarative.v1"
profile:
  id: "Work_Profile"
  name: "Work Profile"
  preferred_block_sink: "127.0.0.1"
  whitelist:
    - "safe.example"
    - "also-safe.example"
  pinned_domains:
    - "Pinned.Example"
    - "not a domain"
  custom_sources:
    - name: "Example Feed"
      url: "https://example.com/hosts.txt"
""",
            "yaml",
        )

        self.assertEqual(profile["id"], "work_profile")
        self.assertEqual(profile["name"], "Work Profile")
        self.assertEqual(profile["whitelist"], "safe.example\nalso-safe.example")
        self.assertEqual(profile["pinned_domains"], ["pinned.example"])
        self.assertEqual(profile["custom_sources"], [{"name": "Example Feed", "url": "https://example.com/hosts.txt"}])
        self.assertEqual(profile["preferred_block_sink"], "127.0.0.1")

    def test_declarative_config_toml_round_trips_active_profile_shape(self):
        profile = parse_declarative_config_text(
            """
schema = "hostsfileget.declarative.v1"

[profile]
id = "work"
name = "Work"
preferred_block_sink = "::1"
whitelist = ["safe.example", "also-safe.example"]
pinned_domains = ["Pinned.Example"]

[[profile.custom_sources]]
name = "Feed"
url = "https://example.com/hosts.txt"
""",
            "toml",
        )

        rendered = format_declarative_config_payload(profile, "profile.toml")
        round_trip = parse_declarative_config_text(rendered, "toml")

        self.assertEqual(round_trip["id"], "work")
        self.assertEqual(round_trip["whitelist"], "safe.example\nalso-safe.example")
        self.assertEqual(round_trip["pinned_domains"], ["pinned.example"])
        self.assertIn("[[profile.custom_sources]]", rendered)

    def test_apply_declarative_profile_to_config_preserves_operational_metadata(self):
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
        config = {
            "whitelist": "old.example",
            "profiles": [
                {"id": "default", "name": "Default", "whitelist": "old.example"},
                {"id": "work", "name": "Old Work", "whitelist": "old-work.example"},
            ],
            "active_profile_id": "default",
            "source_last_fetched": {"https://example.com/hosts.txt": stamp},
            "source_cache_metadata": {
                "https://example.com/hosts.txt": {
                    "cache_key": "a" * 64,
                    "content_sha256": "b" * 64,
                    "bytes": 12,
                }
            },
        }
        profile = {
            "id": "work",
            "name": "Work",
            "whitelist": ["safe.example"],
            "custom_sources": [{"name": "Feed", "url": "https://example.com/hosts.txt"}],
            "pinned_domains": ["Pinned.Example"],
            "preferred_block_sink": "::",
        }

        applied = apply_declarative_profile_to_config(config, profile, os.getcwd())

        self.assertEqual(applied["active_profile_id"], "work")
        self.assertEqual(applied["whitelist"], "safe.example")
        self.assertEqual(applied["custom_sources"], [{"name": "Feed", "url": "https://example.com/hosts.txt"}])
        self.assertEqual(applied["pinned_domains"], ["pinned.example"])
        self.assertEqual(applied["preferred_block_sink"], "::")
        self.assertEqual(applied["source_last_fetched"], {"https://example.com/hosts.txt": stamp})
        self.assertEqual([profile["id"] for profile in applied["profiles"]], ["default", "work"])
        self.assertEqual(applied["profiles"][1]["name"], "Work")

    def test_profile_import_and_apply_are_separate_config_steps(self):
        config = {
            "whitelist": "default.example",
            "profiles": [
                {"id": "default", "name": "Default", "whitelist": "default.example"},
            ],
            "active_profile_id": "default",
        }
        work_profile = {
            "id": "work",
            "name": "Work",
            "whitelist": ["work.example"],
            "custom_sources": [{"name": "Feed", "url": "https://example.com/hosts.txt"}],
            "preferred_block_sink": "127.0.0.1",
        }

        imported = upsert_profile_in_config(config, work_profile, os.getcwd(), activate=False)
        applied = set_active_profile_in_config(imported, "work", os.getcwd())
        replaced_active = upsert_profile_in_config(
            config,
            {"id": "default", "name": "Default", "whitelist": ["new-default.example"]},
            os.getcwd(),
            activate=False,
        )

        self.assertEqual(imported["active_profile_id"], "default")
        self.assertEqual(imported["whitelist"], "default.example")
        self.assertEqual(find_profile_snapshot(imported, "work", os.getcwd())["whitelist"], "work.example")
        self.assertEqual(applied["active_profile_id"], "work")
        self.assertEqual(applied["whitelist"], "work.example")
        self.assertEqual(applied["preferred_block_sink"], "127.0.0.1")
        self.assertEqual(replaced_active["active_profile_id"], "default")
        self.assertEqual(replaced_active["whitelist"], "new-default.example")

    def test_format_profile_list_summary_marks_active_profile(self):
        summary = format_profile_list_summary(
            {
                "active_profile_id": "work",
                "profiles": [
                    {"id": "default", "name": "Default", "whitelist": "default.example"},
                    {"id": "work", "name": "Work", "whitelist": ["work.example"], "pinned_domains": ["pin.example"]},
                ],
            },
            os.getcwd(),
        )

        self.assertIn("  default  Default", summary)
        self.assertIn("* work  Work", summary)
        self.assertIn("pins=1", summary)

    def test_profile_quick_switch_report_lists_profiles_and_target(self):
        report = build_profile_quick_switch_report(
            {
                "active_profile_id": "default",
                "profiles": [
                    {"id": "default", "name": "Default", "whitelist": "default.example"},
                    {
                        "id": "kids",
                        "name": "Kids",
                        "whitelist": ["kids.example", "school.example"],
                        "custom_sources": [{"name": "Feed", "url": "https://example.com/hosts.txt"}],
                        "pinned_domains": ["pin.example"],
                        "preferred_block_sink": "127.0.0.1",
                    },
                ],
            },
            os.getcwd(),
            "kids",
        )
        rendered = format_profile_quick_switch_report(report)

        self.assertEqual(report["schema"], "hostsfileget.profile-quick-switch.v1")
        self.assertEqual(report["profile_count"], 2)
        self.assertEqual(report["target_profile_id"], "kids")
        self.assertTrue(report["target_found"])
        self.assertTrue(report["switch_required"])
        self.assertFalse(report["will_write_hosts_file"])
        kids_row = [profile for profile in report["profiles"] if profile["id"] == "kids"][0]
        self.assertEqual(kids_row["whitelist_count"], 2)
        self.assertEqual(kids_row["source_count"], 1)
        self.assertEqual(kids_row["pinned_count"], 1)
        self.assertIn("Hosts-file write: no", rendered)
        self.assertIn("* default", rendered)

    def test_apply_profile_quick_switch_updates_config_only(self):
        config = {
            "whitelist": "default.example",
            "profiles": [
                {"id": "default", "name": "Default", "whitelist": "default.example"},
                {"id": "kids", "name": "Kids", "whitelist": "kids.example", "preferred_block_sink": "::"},
            ],
            "active_profile_id": "default",
        }

        applied, report = apply_profile_quick_switch(config, "kids", os.getcwd())

        self.assertTrue(report["switch_required"])
        self.assertFalse(report["will_write_hosts_file"])
        self.assertEqual(applied["active_profile_id"], "kids")
        self.assertEqual(applied["whitelist"], "kids.example")
        self.assertEqual(applied["preferred_block_sink"], "::")
        with self.assertRaises(ValueError):
            apply_profile_quick_switch(config, "missing", os.getcwd())

    def test_profile_tray_availability_reports_missing_optional_dependency(self):
        def missing_importer(module_name):
            raise ImportError(f"missing {module_name}")

        report = build_profile_tray_availability_report(importer=missing_importer)
        rendered = format_profile_tray_availability_report(report)

        self.assertFalse(report["available"])
        self.assertEqual(len(report["missing"]), 3)
        self.assertIn("pystray", report["install_hint"])
        self.assertIn("Available: no", rendered)
        self.assertIn("PIL.Image", rendered)

    def test_profile_tray_availability_reports_available_with_fake_modules(self):
        seen_modules = []

        def fake_importer(module_name):
            seen_modules.append(module_name)
            return object()

        report = build_profile_tray_availability_report(importer=fake_importer)
        rendered = format_profile_tray_availability_report(report)

        self.assertTrue(report["available"])
        self.assertEqual(seen_modules, ["pystray", "PIL.Image", "PIL.ImageDraw"])
        self.assertEqual(report["missing"], [])
        self.assertIn("Available: yes", rendered)

    def test_cli_declarative_config_apply_and_export_use_app_config_only(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "hosts_editor_config.json"
            source_path = Path(tmpdir) / "profile.yaml"
            export_path = Path(tmpdir) / "profile.toml"
            config_path.write_text(json.dumps({"whitelist": "old.example"}), encoding="utf-8")
            source_path.write_text(
                """
schema: "hostsfileget.declarative.v1"
profile:
  id: "work"
  name: "Work"
  preferred_block_sink: "0.0.0.0"
  whitelist:
    - "safe.example"
  pinned_domains: []
  custom_sources:
    - name: "Feed"
      url: "https://example.com/hosts.txt"
""",
                encoding="utf-8",
            )

            with mock.patch.object(hosts_editor, "get_primary_config_path", return_value=str(config_path)):
                self.assertEqual(hosts_editor._cli_config_apply(str(source_path)), 0)
                written = json.loads(config_path.read_text(encoding="utf-8"))
                self.assertEqual(written["active_profile_id"], "work")
                self.assertEqual(written["whitelist"], "safe.example")

                self.assertEqual(hosts_editor._cli_config_export(str(export_path)), 0)

            exported = parse_declarative_config_text(export_path.read_text(encoding="utf-8"), "toml")
            self.assertEqual(exported["id"], "work")
            self.assertEqual(exported["custom_sources"], [{"name": "Feed", "url": "https://example.com/hosts.txt"}])

    def test_cli_profile_import_apply_and_export_are_explicit_steps(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "hosts_editor_config.json"
            source_path = Path(tmpdir) / "profile.yaml"
            export_path = Path(tmpdir) / "profile.json"
            config_path.write_text(
                json.dumps({
                    "whitelist": "default.example",
                    "profiles": [{"id": "default", "name": "Default", "whitelist": "default.example"}],
                    "active_profile_id": "default",
                }),
                encoding="utf-8",
            )
            source_path.write_text(
                """
schema: "hostsfileget.declarative.v1"
profile:
  id: "work"
  name: "Work"
  whitelist:
    - "work.example"
  custom_sources: []
  pinned_domains: []
""",
                encoding="utf-8",
            )

            with mock.patch.object(hosts_editor, "get_primary_config_path", return_value=str(config_path)):
                self.assertEqual(hosts_editor._cli_profile_import(str(source_path)), 0)
                imported = json.loads(config_path.read_text(encoding="utf-8"))
                self.assertEqual(imported["active_profile_id"], "default")
                self.assertEqual(imported["whitelist"], "default.example")

                self.assertEqual(hosts_editor._cli_profile_apply("work"), 0)
                applied = json.loads(config_path.read_text(encoding="utf-8"))
                self.assertEqual(applied["active_profile_id"], "work")
                self.assertEqual(applied["whitelist"], "work.example")

                self.assertEqual(hosts_editor._cli_profile_list(), 0)
                self.assertEqual(hosts_editor._cli_profile_export("work", str(export_path)), 0)

            exported = parse_declarative_config_text(export_path.read_text(encoding="utf-8"), "json")
            self.assertEqual(exported["id"], "work")
            self.assertEqual(exported["whitelist"], "work.example")

    def test_profile_activation_schedule_sanitizes_and_evaluates_windows(self):
        config = sanitize_config_snapshot(
            {
                "profiles": [
                    {"id": "default", "name": "Default", "whitelist": "default.example"},
                    {"id": "kids", "name": "Kids", "whitelist": "kids.example"},
                ],
                "active_profile_id": "default",
                "profile_activation_fallback_id": "default",
                "profile_activation_schedule": [
                    {
                        "id": "Kids Hours",
                        "name": "Kids block hours",
                        "profile_id": "kids",
                        "days": "weekdays",
                        "start_time": "16:00",
                        "end_time": "20:00",
                    },
                    {
                        "profile_id": "missing",
                        "days": "daily",
                        "start_time": "09:00",
                        "end_time": "10:00",
                    },
                ],
            },
            os.getcwd(),
        )

        self.assertEqual(normalize_profile_activation_days("weekends"), ["sat", "sun"])
        self.assertEqual(len(config["profile_activation_schedule"]), 1)
        self.assertEqual(config["profile_activation_schedule"][0]["id"], "kids-hours")

        report = evaluate_profile_activation_schedule(config, "2026-05-11T17:00:00", os.getcwd())
        rendered = format_profile_activation_schedule_report(report)

        self.assertEqual(report["target_profile_id"], "kids")
        self.assertEqual(report["target_reason"], "matching-window")
        self.assertTrue(report["switch_required"])
        self.assertFalse(report["will_write_hosts_file"])
        self.assertIn("Hosts-file write: no", rendered)

        fallback = evaluate_profile_activation_schedule(config, "2026-05-09T17:00:00", os.getcwd())
        self.assertEqual(fallback["target_profile_id"], "default")
        self.assertEqual(fallback["target_reason"], "fallback")

    def test_apply_profile_activation_schedule_switches_config_only(self):
        config = {
            "whitelist": "default.example",
            "profiles": [
                {"id": "default", "name": "Default", "whitelist": "default.example"},
                {"id": "kids", "name": "Kids", "whitelist": "kids.example", "preferred_block_sink": "127.0.0.1"},
            ],
            "active_profile_id": "default",
            "profile_activation_fallback_id": "default",
            "profile_activation_schedule": [
                {
                    "name": "Kids block hours",
                    "profile_id": "kids",
                    "days": ["mon"],
                    "start_time": "16:00",
                    "end_time": "20:00",
                }
            ],
        }

        applied, report = apply_profile_activation_schedule(config, "2026-05-11T18:00:00", os.getcwd())

        self.assertTrue(report["switch_required"])
        self.assertFalse(report["will_write_hosts_file"])
        self.assertEqual(applied["active_profile_id"], "kids")
        self.assertEqual(applied["whitelist"], "kids.example")
        self.assertEqual(applied["preferred_block_sink"], "127.0.0.1")

    def test_cli_profile_schedule_add_list_apply_are_config_only(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "hosts_editor_config.json"
            config_path.write_text(
                json.dumps({
                    "whitelist": "default.example",
                    "profiles": [
                        {"id": "default", "name": "Default", "whitelist": "default.example"},
                        {"id": "kids", "name": "Kids", "whitelist": "kids.example"},
                    ],
                    "active_profile_id": "default",
                }),
                encoding="utf-8",
            )

            with mock.patch.object(hosts_editor, "get_primary_config_path", return_value=str(config_path)):
                with mock.patch.object(hosts_editor, "_cli_print"):
                    self.assertEqual(
                        hosts_editor._cli_profile_schedule_add(
                            "kids",
                            "16:00",
                            "20:00",
                            "weekdays",
                            "Kids block hours",
                            "default",
                        ),
                        0,
                    )
                    self.assertEqual(hosts_editor._cli_profile_schedule_list("2026-05-11T17:00:00"), 0)
                    self.assertEqual(hosts_editor._cli_profile_schedule_apply("2026-05-11T17:00:00"), 0)

            written = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(written["active_profile_id"], "kids")
            self.assertEqual(written["whitelist"], "kids.example")
            self.assertEqual(written["profile_activation_fallback_id"], "default")
            self.assertEqual(written["profile_activation_schedule"][0]["profile_id"], "kids")

    def test_handle_cli_args_routes_profile_schedule_flags(self):
        with mock.patch.object(hosts_editor, "_cli_profile_schedule_list", return_value=0) as mocked_list:
            self.assertEqual(hosts_editor._handle_cli_args(["--profile-schedule-list"]), 0)
            mocked_list.assert_called_once_with(None)

        with mock.patch.object(hosts_editor, "_cli_profile_schedule_add", return_value=0) as mocked_add:
            self.assertEqual(
                hosts_editor._handle_cli_args([
                    "--profile-schedule-add", "kids", "16:00", "20:00",
                    "--profile-schedule-days", "weekdays",
                    "--profile-schedule-name", "Kids block hours",
                    "--profile-schedule-fallback", "default",
                ]),
                0,
            )
            mocked_add.assert_called_once_with(
                "kids",
                "16:00",
                "20:00",
                "weekdays",
                "Kids block hours",
                "default",
            )

        with mock.patch.object(hosts_editor, "_cli_profile_schedule_apply", return_value=0) as mocked_apply:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--profile-schedule-apply", "--profile-schedule-at", "2026-05-11T17:00:00"]),
                0,
            )
            mocked_apply.assert_called_once_with("2026-05-11T17:00:00")

    def test_config_location_report_switches_sidecars_with_portable_config(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as exe_dir, tempfile.TemporaryDirectory() as app_dir:
            with mock.patch.object(hosts_editor, "_EXE_DIR", exe_dir):
                with mock.patch.object(hosts_editor, "get_app_config_dir", return_value=app_dir):
                    local_report = build_config_location_report()
                    self.assertEqual(local_report["mode"], "local")
                    self.assertEqual(local_report["active_config_path"], os.path.join(app_dir, "hosts_editor_config.json"))
                    self.assertEqual(get_config_root_dir(), app_dir)
                    self.assertEqual(get_git_history_dir(), os.path.join(app_dir, "hosts_history_git"))

                    Path(exe_dir, "hosts_editor_config.json").write_text("{}", encoding="utf-8")
                    portable_report = build_config_location_report()
                    formatted = format_config_location_report(portable_report)

                    self.assertEqual(portable_report["mode"], "portable")
                    self.assertEqual(portable_report["sidecar_root"], exe_dir)
                    self.assertEqual(get_config_root_dir(), exe_dir)
                    self.assertEqual(get_git_history_dir(), os.path.join(exe_dir, "hosts_history_git"))
                    self.assertIn("Portable", formatted)
                    self.assertIn("CLI activity", formatted)

    def test_write_portable_bundle_config_refuses_overwrite_and_writes_readme(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            result = write_portable_bundle_config(
                tmpdir,
                {"whitelist": "keep.example", "active_profile_id": "default"},
                os.path.expanduser("~"),
            )
            config_path = Path(result["config_path"])
            readme_path = Path(result["readme_path"])
            written = json.loads(config_path.read_text(encoding="utf-8"))

            self.assertEqual(written["whitelist"], "keep.example")
            self.assertTrue(readme_path.exists())
            self.assertIn("Portable mode", build_portable_bundle_readme(str(config_path)))
            self.assertIn("Portable Bundle Config", format_portable_bundle_export_summary(result))
            with self.assertRaises(FileExistsError):
                write_portable_bundle_config(tmpdir, {}, os.path.expanduser("~"))

            overwritten = write_portable_bundle_config(
                tmpdir,
                {"whitelist": "new.example"},
                os.path.expanduser("~"),
                overwrite=True,
            )
            self.assertEqual(overwritten["config_path"], str(config_path))

    def test_cli_config_location_and_portable_export(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "current.json"
            bundle_dir = Path(tmpdir) / "bundle"
            config_path.write_text(json.dumps({"whitelist": "cli.example"}), encoding="utf-8")

            with mock.patch.object(hosts_editor, "get_primary_config_path", return_value=str(config_path)):
                self.assertEqual(hosts_editor._cli_config_location(), 0)
                self.assertEqual(hosts_editor._cli_portable_export(str(bundle_dir)), 0)
                self.assertEqual(hosts_editor._cli_portable_export(str(bundle_dir)), 2)
                self.assertEqual(hosts_editor._cli_portable_export(str(bundle_dir), overwrite=True), 0)

            exported = json.loads((bundle_dir / "hosts_editor_config.json").read_text(encoding="utf-8"))
            self.assertEqual(exported["whitelist"], "cli.example")

    def test_cli_integration_export_writes_file_without_remote_writes(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "hosts.txt"
            output_path = Path(tmpdir) / "adguard.txt"
            input_path.write_text(
                "0.0.0.0 ads.example\n0.0.0.0 tracker.example\n192.168.1.10 printer\n",
                encoding="utf-8",
            )

            with mock.patch.object(hosts_editor, "_cli_print"):
                self.assertEqual(hosts_editor._cli_integration_list(), 0)
                self.assertEqual(
                    hosts_editor._cli_integration_export("adguard-home", str(input_path), str(output_path)),
                    0,
                )
                self.assertEqual(
                    hosts_editor._cli_integration_export("unknown", str(input_path), str(output_path)),
                    2,
                )
            self.assertEqual(output_path.read_text(encoding="utf-8").splitlines(), [
                "||ads.example^",
                "||tracker.example^",
            ])

    def test_cli_cloud_adapters_write_plan_and_log_import(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "hosts.txt"
            plan_path = Path(tmpdir) / "nextdns-plan.json"
            log_path = Path(tmpdir) / "controld.csv"
            domains_path = Path(tmpdir) / "domains.txt"
            input_path.write_text(
                "0.0.0.0 ads.example\n0.0.0.0 tracker.example\n192.168.1.10 printer\n",
                encoding="utf-8",
            )
            log_path.write_text(
                "timestamp,question,action\n"
                "2026-05-12T10:00:00Z,ads.example,0\n"
                "2026-05-12T10:01:00Z,allowed.example,1\n",
                encoding="utf-8",
            )

            with mock.patch.object(hosts_editor, "_cli_print"):
                self.assertEqual(hosts_editor._cli_cloud_adapter_list(), 0)
                self.assertEqual(
                    hosts_editor._cli_cloud_adapter_plan(
                        "nextdns", str(input_path), str(plan_path), "profile-1"
                    ),
                    0,
                )
                self.assertEqual(
                    hosts_editor._cli_cloud_log_import("controld", str(log_path), str(domains_path)),
                    0,
                )
                self.assertEqual(
                    hosts_editor._cli_cloud_adapter_plan("unknown", str(input_path), str(plan_path), "profile-1"),
                    2,
                )

            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(plan["adapter_id"], "nextdns-denylist")
            self.assertEqual(plan["requests"][0]["headers"], {"X-Api-Key": "<NEXTDNS_API_KEY>"})
            self.assertEqual(domains_path.read_text(encoding="utf-8").splitlines(), ["ads.example"])

    def test_cli_adblock_lint_and_quarantine_write_review_files(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "filters.txt"
            report_path = Path(tmpdir) / "lint.json"
            output_path = Path(tmpdir) / "quarantined.txt"
            input_path.write_text(
                "0.0.0.0 ads.example\n"
                "||tracker.example^$third-party\n"
                "example.com##.ad-banner\n"
                "||example.com/ads/*\n",
                encoding="utf-8",
            )

            with mock.patch.object(hosts_editor, "_cli_print"):
                self.assertEqual(hosts_editor._cli_adblock_lint(str(input_path), str(report_path)), 1)
                self.assertEqual(hosts_editor._cli_adblock_quarantine(str(input_path), str(output_path)), 0)

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["quarantined"], 2)
            quarantined = output_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(quarantined[0], "0.0.0.0 ads.example")
            self.assertTrue(quarantined[2].startswith("# HostsFileGet quarantined browser-only rule:"))

    def test_cli_rule_tier_report_writes_review_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "rules.txt"
            report_path = Path(tmpdir) / "rule-tiers.json"
            input_path.write_text(
                "0.0.0.0 ads.example\n"
                "||tracker.example^\n"
                "*.tracking.example\n"
                "/ads[0-9]+/\n",
                encoding="utf-8",
            )

            with mock.patch.object(hosts_editor, "_cli_print"):
                self.assertEqual(hosts_editor._cli_rule_tier_report(str(input_path), str(report_path)), 0)

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["hosts_native"], 1)
            self.assertEqual(report["warning_count"], 3)
            self.assertEqual(report["tiers"]["wildcard"], 1)

    def test_cli_idn_homograph_report_writes_review_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "idn.txt"
            report_path = Path(tmpdir) / "idn-report.json"
            input_path.write_text(
                "0.0.0.0 xn--pple-43d.com\n"
                "0.0.0.0 m\u00fcnich.example\n",
                encoding="utf-8",
            )

            with mock.patch.object(hosts_editor, "_cli_print"):
                self.assertEqual(hosts_editor._cli_idn_homograph_report(str(input_path), str(report_path)), 0)

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["candidate_domains"], 2)
            self.assertEqual(report["warning_count"], 1)
            self.assertEqual(report["counts"]["homograph-risk"], 1)

    def test_cli_dns_rebinding_report_writes_review_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "hosts.txt"
            report_path = Path(tmpdir) / "dns-rebinding-report.json"
            input_path.write_text(
                "10.0.0.5 app.example.com\n"
                "192.168.1.20 router.lan\n",
                encoding="utf-8",
            )

            with mock.patch.object(hosts_editor, "_cli_print"):
                self.assertEqual(
                    hosts_editor._cli_dns_rebinding_report(str(input_path), str(report_path), ["lab.example"]),
                    0,
                )

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], "hostsfileget.dns-rebinding-report.v1")
            self.assertEqual(report["summary"]["rebinding_candidates"], 1)
            self.assertEqual(report["summary"]["trusted_local_mappings"], 1)
            self.assertIn(".lab.example", report["trusted_suffixes"])

    def test_cli_threat_feed_plan_writes_review_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            plan_path = Path(tmpdir) / "threat-feed-plan.json"

            with mock.patch.object(hosts_editor, "_cli_print"):
                self.assertEqual(hosts_editor._cli_threat_feed_plan("nrd", str(plan_path)), 0)

            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(plan["schema"], "hostsfileget.threat-feed-pack-plan.v1")
            self.assertEqual(plan["pack_id"], "nrd-review")
            self.assertEqual(plan["source_count"], 2)
            self.assertEqual(plan["freshness"]["stale_after_hours"], 6)
            self.assertIn("A1", plan["references"])

    def test_cli_cname_cloaking_plan_writes_review_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            plan_path = Path(tmpdir) / "cname-plan.json"

            with mock.patch.object(hosts_editor, "_cli_print"):
                self.assertEqual(hosts_editor._cli_cname_cloaking_plan("cname-aware", str(plan_path)), 0)

            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(plan["schema"], "hostsfileget.cname-cloaking-plan.v1")
            self.assertEqual(plan["pack_id"], "cname-aware-dns")
            self.assertFalse(plan["hosts_native"])
            self.assertEqual(plan["source_count"], 2)
            self.assertIn("nextdns-cname-targets", plan["source_ids"])

    def test_cli_encrypted_dns_bypass_plan_writes_review_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            plan_path = Path(tmpdir) / "encrypted-dns-bypass-plan.json"

            with mock.patch.object(hosts_editor, "_cli_print"):
                self.assertEqual(hosts_editor._cli_encrypted_dns_bypass_plan("firewall", str(plan_path)), 0)

            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(plan["schema"], "hostsfileget.encrypted-dns-bypass-plan.v1")
            self.assertEqual(plan["pack_id"], "router-firewall-handoff")
            self.assertFalse(plan["hosts_native"])
            self.assertEqual(plan["source_count"], 3)
            self.assertIn("hagezi-doh-ips", plan["source_ids"])

    def test_cli_safesearch_template_plan_writes_review_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            plan_path = Path(tmpdir) / "safesearch-template-plan.json"

            with mock.patch.object(hosts_editor, "_cli_print"):
                self.assertEqual(hosts_editor._cli_safesearch_template_plan("duckduckgo", str(plan_path)), 0)

            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(plan["schema"], "hostsfileget.safesearch-template-plan.v1")
            self.assertEqual(plan["template_id"], "duckduckgo-strict-dns")
            self.assertFalse(plan["hosts_native"])
            self.assertEqual(plan["hosts_line_templates"], [])
            self.assertEqual(plan["dns_cname_records"][0]["target"], "safe.duckduckgo.com")
            self.assertIn("P4", plan["references"])

    def test_handle_cli_args_routes_integration_flags(self):
        with mock.patch.object(hosts_editor, "_cli_integration_list", return_value=0) as mocked_list:
            self.assertEqual(hosts_editor._handle_cli_args(["--integration-list"]), 0)
            mocked_list.assert_called_once_with()

        with mock.patch.object(hosts_editor, "_cli_integration_export", return_value=0) as mocked_export:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--integration-export", "blocky", "in.txt", "out.txt"]),
                0,
            )
            mocked_export.assert_called_once_with("blocky", "in.txt", "out.txt")

        with mock.patch.object(hosts_editor, "_cli_source_adapter_list", return_value=0) as mocked_adapters:
            self.assertEqual(hosts_editor._handle_cli_args(["--source-adapter-list", "plugins"]), 0)
            mocked_adapters.assert_called_once_with(["plugins"])

        with mock.patch.object(hosts_editor, "_cli_api_serve", return_value=0) as mocked_api:
            self.assertEqual(
                hosts_editor._handle_cli_args([
                    "--api-serve",
                    "--api-host", "127.0.0.1",
                    "--api-port", "0",
                    "--api-token", "0123456789abcdef",
                ]),
                0,
            )
            mocked_api.assert_called_once_with("127.0.0.1", 0, "0123456789abcdef")

        with mock.patch.object(hosts_editor, "_cli_i18n_template", return_value=0) as mocked_template:
            self.assertEqual(hosts_editor._handle_cli_args(["--i18n-template", "de-de", "de-DE.json"]), 0)
            mocked_template.assert_called_once_with("de-de", "de-DE.json")

        with mock.patch.object(hosts_editor, "_cli_i18n_validate", return_value=1) as mocked_validate:
            self.assertEqual(hosts_editor._handle_cli_args(["--i18n-validate", "de-DE.json"]), 1)
            mocked_validate.assert_called_once_with("de-DE.json")

        with mock.patch.object(hosts_editor, "_cli_profile_sync_export", return_value=0) as mocked_sync_export:
            self.assertEqual(
                hosts_editor._handle_cli_args([
                    "--sync-git-export", "sync-repo",
                    "--sync-passphrase-env", "SYNC_SECRET",
                    "--sync-git-push",
                ]),
                0,
            )
            mocked_sync_export.assert_called_once_with("sync-repo", "SYNC_SECRET", True)

        with mock.patch.object(hosts_editor, "_cli_profile_sync_import", return_value=0) as mocked_sync_import:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--sync-git-import", "sync-repo", "--sync-git-pull"]),
                0,
            )
            mocked_sync_import.assert_called_once_with("sync-repo", "HOSTSFILEGET_SYNC_PASSPHRASE", True)

        with mock.patch.object(hosts_editor, "_cli_patch_build_allowlist", return_value=0) as mocked_patch_allow:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--patch-build-allowlist", "domains.txt", "allow.patch.json"]),
                0,
            )
            mocked_patch_allow.assert_called_once_with("domains.txt", "allow.patch.json")

        with mock.patch.object(hosts_editor, "_cli_patch_build_profile", return_value=0) as mocked_patch_profile:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--patch-build-profile", "work", "work.patch.json"]),
                0,
            )
            mocked_patch_profile.assert_called_once_with("work", "work.patch.json")

        with mock.patch.object(hosts_editor, "_cli_patch_sign", return_value=0) as mocked_patch_sign:
            self.assertEqual(
                hosts_editor._handle_cli_args([
                    "--patch-sign", "work.patch.json", "work.patch.json.asc",
                    "--patch-gpg-key", "test@example",
                ]),
                0,
            )
            mocked_patch_sign.assert_called_once_with("work.patch.json", "work.patch.json.asc", "test@example")

        with mock.patch.object(hosts_editor, "_cli_patch_apply", return_value=0) as mocked_patch_apply:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--patch-apply", "work.patch.json", "work.patch.json.asc"]),
                0,
            )
            mocked_patch_apply.assert_called_once_with("work.patch.json", "work.patch.json.asc")

        with mock.patch.object(hosts_editor, "_cli_recovery_plan", return_value=0) as mocked_recovery:
            self.assertEqual(
                hosts_editor._handle_cli_args([
                    "--recovery-plan-output", "recovery.json",
                    "--recovery-plan-description", "Before apply",
                ]),
                0,
            )
            mocked_recovery.assert_called_once_with("recovery.json", "Before apply")

        with mock.patch.object(hosts_editor, "_cli_wfp_blocker_plan", return_value=0) as mocked_wfp:
            self.assertEqual(
                hosts_editor._handle_cli_args([
                    "--wfp-blocker-plan", "ips.txt", "wfp.json",
                    "--wfp-rule-prefix", "Corp Block",
                ]),
                0,
            )
            mocked_wfp.assert_called_once_with("ips.txt", "wfp.json", "Corp Block")

        with mock.patch.object(hosts_editor, "_cli_nrpt_policy_plan", return_value=0) as mocked_nrpt:
            self.assertEqual(
                hosts_editor._handle_cli_args([
                    "--nrpt-plan", "namespaces.txt", "nrpt.json",
                    "--nrpt-name-server", "10.0.0.53",
                    "--nrpt-name-server", "2001:4860:4860::8888",
                    "--nrpt-rule-prefix", "Corp NRPT",
                    "--nrpt-gpo-name", "Corp Policy",
                    "--nrpt-server", "dc01",
                ]),
                0,
            )
            mocked_nrpt.assert_called_once_with(
                "namespaces.txt",
                "nrpt.json",
                ["10.0.0.53", "2001:4860:4860::8888"],
                "Corp NRPT",
                "Corp Policy",
                "dc01",
            )

        with mock.patch.object(hosts_editor, "_cli_sandbox_vm_hosts_plan", return_value=0) as mocked_sandbox:
            self.assertEqual(
                hosts_editor._handle_cli_args([
                    "--sandbox-vm-hosts-plan", "hosts.txt", "bundle",
                    "--sandbox-plan-name", "Lab Bundle",
                    "--sandbox-vm-name", "Lab VM",
                    "--sandbox-networking", "Disable",
                    "--sandbox-vgpu", "Default",
                    "--sandbox-memory-mb", "4096",
                ]),
                0,
            )
            mocked_sandbox.assert_called_once_with(
                "hosts.txt",
                "bundle",
                ["Lab VM"],
                "Lab Bundle",
                "Disable",
                "Default",
                4096,
            )

        with mock.patch.object(hosts_editor, "_cli_router_gateway_adapter_list", return_value=0) as mocked_router_list:
            self.assertEqual(hosts_editor._handle_cli_args(["--router-adapter-list"]), 0)
            mocked_router_list.assert_called_once_with()

        with mock.patch.object(hosts_editor, "_cli_router_gateway_push_plan", return_value=0) as mocked_router_plan:
            self.assertEqual(
                hosts_editor._handle_cli_args([
                    "--router-push-plan", "openwrt-dnsmasq", "hosts.txt", "router-bundle",
                    "--router-host", "router.lan",
                    "--router-user", "root",
                    "--router-remote-path", "/etc/dnsmasq.d/hfg.conf",
                    "--router-label", "Lab Router",
                ]),
                0,
            )
            mocked_router_plan.assert_called_once_with(
                "openwrt-dnsmasq",
                "hosts.txt",
                "router-bundle",
                "router.lan",
                "root",
                "/etc/dnsmasq.d/hfg.conf",
                "Lab Router",
            )

    def test_handle_cli_args_routes_cloud_dns_flags(self):
        with mock.patch.object(hosts_editor, "_cli_cloud_adapter_list", return_value=0) as mocked_list:
            self.assertEqual(hosts_editor._handle_cli_args(["--cloud-adapter-list"]), 0)
            mocked_list.assert_called_once_with()

        with mock.patch.object(hosts_editor, "_cli_cloud_adapter_plan", return_value=0) as mocked_plan:
            self.assertEqual(
                hosts_editor._handle_cli_args([
                    "--cloud-adapter-plan", "nextdns", "in.txt", "plan.json",
                    "--cloud-profile-id", "profile-1",
                ]),
                0,
            )
            mocked_plan.assert_called_once_with("nextdns", "in.txt", "plan.json", "profile-1")

        with mock.patch.object(hosts_editor, "_cli_cloud_log_import", return_value=0) as mocked_import:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--cloud-log-import", "controld", "log.csv", "domains.txt"]),
                0,
            )
            mocked_import.assert_called_once_with("controld", "log.csv", "domains.txt")

    def test_handle_cli_args_routes_threat_feed_flags(self):
        with mock.patch.object(hosts_editor, "_cli_threat_feed_list", return_value=0) as mocked_list:
            self.assertEqual(hosts_editor._handle_cli_args(["--threat-feed-list"]), 0)
            mocked_list.assert_called_once_with()

        with mock.patch.object(hosts_editor, "_cli_threat_feed_plan", return_value=0) as mocked_plan:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--threat-feed-plan", "dga-watch", "plan.json"]),
                0,
            )
            mocked_plan.assert_called_once_with("dga-watch", "plan.json")

    def test_handle_cli_args_routes_cname_cloaking_flags(self):
        with mock.patch.object(hosts_editor, "_cli_cname_cloaking_list", return_value=0) as mocked_list:
            self.assertEqual(hosts_editor._handle_cli_args(["--cname-cloaking-list"]), 0)
            mocked_list.assert_called_once_with()

        with mock.patch.object(hosts_editor, "_cli_cname_cloaking_plan", return_value=0) as mocked_plan:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--cname-cloaking-plan", "rpz", "plan.json"]),
                0,
            )
            mocked_plan.assert_called_once_with("rpz", "plan.json")

    def test_handle_cli_args_routes_encrypted_dns_bypass_flags(self):
        with mock.patch.object(hosts_editor, "_cli_encrypted_dns_bypass_list", return_value=0) as mocked_list:
            self.assertEqual(hosts_editor._handle_cli_args(["--encrypted-dns-bypass-list"]), 0)
            mocked_list.assert_called_once_with()

        with mock.patch.object(hosts_editor, "_cli_encrypted_dns_bypass_plan", return_value=0) as mocked_plan:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--encrypted-dns-bypass-plan", "doh", "plan.json"]),
                0,
            )
            mocked_plan.assert_called_once_with("doh", "plan.json")

    def test_handle_cli_args_routes_safesearch_template_flags(self):
        with mock.patch.object(hosts_editor, "_cli_safesearch_template_list", return_value=0) as mocked_list:
            self.assertEqual(hosts_editor._handle_cli_args(["--safesearch-template-list"]), 0)
            mocked_list.assert_called_once_with()

        with mock.patch.object(hosts_editor, "_cli_safesearch_template_plan", return_value=0) as mocked_plan:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--safesearch-template-plan", "youtube", "plan.json"]),
                0,
            )
            mocked_plan.assert_called_once_with("youtube", "plan.json")

    def test_handle_cli_args_routes_dns_rebinding_flags(self):
        with mock.patch.object(hosts_editor, "_cli_dns_rebinding_report", return_value=0) as mocked_report:
            self.assertEqual(
                hosts_editor._handle_cli_args([
                    "--dns-rebinding-report", "hosts.txt",
                    "--dns-rebinding-output", "rebinding.json",
                    "--dns-rebinding-trusted-suffix", "lab.example",
                ]),
                0,
            )
            mocked_report.assert_called_once_with("hosts.txt", "rebinding.json", ["lab.example"])

    def test_handle_cli_args_routes_adblock_lint_flags(self):
        with mock.patch.object(hosts_editor, "_cli_adblock_lint", return_value=1) as mocked_lint:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--adblock-lint", "filters.txt", "--adblock-lint-output", "lint.json"]),
                1,
            )
            mocked_lint.assert_called_once_with("filters.txt", "lint.json")

        with mock.patch.object(hosts_editor, "_cli_adblock_quarantine", return_value=0) as mocked_quarantine:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--adblock-quarantine", "filters.txt", "quarantined.txt"]),
                0,
            )
            mocked_quarantine.assert_called_once_with("filters.txt", "quarantined.txt")

    def test_handle_cli_args_routes_rule_tier_flags(self):
        with mock.patch.object(hosts_editor, "_cli_rule_tier_report", return_value=0) as mocked_report:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--rule-tier-report", "filters.txt", "--rule-tier-output", "tiers.json"]),
                0,
            )
            mocked_report.assert_called_once_with("filters.txt", "tiers.json")

    def test_handle_cli_args_routes_idn_report_flags(self):
        with mock.patch.object(hosts_editor, "_cli_idn_homograph_report", return_value=0) as mocked_report:
            self.assertEqual(
                hosts_editor._handle_cli_args(["--idn-report", "hosts.txt", "--idn-output", "idn.json"]),
                0,
            )
            mocked_report.assert_called_once_with("hosts.txt", "idn.json")

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

    def test_git_history_ref_sanitizer_rejects_unsafe_refs(self):
        self.assertEqual(sanitize_git_history_ref("abc123"), "abc123")
        self.assertEqual(sanitize_git_history_ref("main/snapshot-1"), "main/snapshot-1")
        for ref in ("", "../main", "abc..def", "HEAD@{1}", "-bad", r"bad\ref"):
            with self.assertRaises(ValueError):
                sanitize_git_history_ref(ref)

    def test_git_history_metadata_tracks_content_shape(self):
        metadata = build_git_history_metadata(
            "0.0.0.0 ads.example\n\n# comment\n",
            source_description="  Test\tSnapshot  ",
        )

        self.assertEqual(metadata["schema"], "hostsfileget.git-history.v1")
        self.assertEqual(metadata["source"], "Test Snapshot")
        self.assertEqual(metadata["line_count"], 3)
        self.assertEqual(metadata["nonempty_line_count"], 2)
        self.assertEqual(len(metadata["sha256"]), 64)

    def test_git_history_status_report_handles_missing_git(self):
        with mock.patch.object(hosts_editor.shutil, "which", return_value=None):
            report = build_git_history_status_report("C:/tmp/history")
        formatted = format_git_history_status_report(report)

        self.assertFalse(report["available"])
        self.assertIn("unavailable", formatted)

    def test_git_history_snapshot_roundtrips_when_git_is_available(self):
        import tempfile
        from pathlib import Path

        git = hosts_editor.resolve_git_executable()
        if not git:
            self.skipTest("git executable not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = str(Path(tmpdir) / "history")
            content = "0.0.0.0 ads.example\n# comment\n"

            result = write_git_history_snapshot(repo_dir, content, "unit test", git_executable=git)
            snapshots = list_git_history_snapshots(repo_dir, git_executable=git)
            restored = read_git_history_snapshot(repo_dir, result["commit"], git_executable=git)
            unchanged = write_git_history_snapshot(repo_dir, content, "unit test", git_executable=git)

        self.assertEqual(result["status"], "committed")
        self.assertEqual(unchanged["status"], "unchanged")
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(restored.splitlines(), content.splitlines())

    def test_profile_sync_payload_applies_profiles_without_operational_metadata(self):
        source_config = {
            "whitelist": "allow.example\n",
            "source_last_fetched": {"https://example.com/hosts.txt": "2026-05-12T12:00:00"},
            "profiles": [
                {
                    "id": "work",
                    "name": "Work",
                    "whitelist": "work.example\n",
                    "custom_sources": [{"name": "Work Feed", "url": "https://example.com/work.txt"}],
                    "pinned_domains": ["Pinned.Example"],
                    "preferred_block_sink": "127.0.0.1",
                }
            ],
            "active_profile_id": "work",
        }
        payload = build_profile_sync_payload(
            source_config,
            os.getcwd(),
            now=datetime.datetime(2026, 5, 12, 9, 30, 0),
        )

        self.assertEqual(payload["schema"], PROFILE_SYNC_PAYLOAD_SCHEMA)
        self.assertEqual(payload["active_profile_id"], "work")
        self.assertNotIn("source_last_fetched", payload)
        sanitized = sanitize_profile_sync_payload(payload)
        target_config = {
            "whitelist": "old.example\n",
            "source_last_fetched": {"https://existing.example/hosts.txt": "2026-05-11T12:00:00"},
        }
        merged = apply_profile_sync_payload_to_config(target_config, sanitized, os.getcwd())

        self.assertEqual(merged["active_profile_id"], "work")
        self.assertEqual(merged["whitelist"], "work.example\n")
        self.assertEqual(merged["pinned_domains"], ["pinned.example"])
        self.assertIn("https://existing.example/hosts.txt", merged["source_last_fetched"])
        self.assertNotIn("https://example.com/hosts.txt", merged["source_last_fetched"])

    def test_profile_sync_git_export_import_roundtrips_with_fake_gpg(self):
        import tempfile
        from pathlib import Path

        git = hosts_editor.resolve_git_executable()
        if not git:
            self.skipTest("git executable not available")

        def fake_gpg(args, input=None, capture_output=None, text=None, timeout=None, check=None):
            output_path = Path(args[args.index("--output") + 1])
            input_path = Path(args[-1])
            if "--decrypt" in args:
                encrypted = input_path.read_text(encoding="utf-8")
                output_path.write_text(encrypted.removeprefix("encrypted:"), encoding="utf-8")
            else:
                output_path.write_text("encrypted:" + input_path.read_text(encoding="utf-8"), encoding="utf-8")
            return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        source_config = {
            "profiles": [
                {
                    "id": "family",
                    "name": "Family",
                    "whitelist": "school.example\n",
                    "pinned_domains": ["ads.example"],
                }
            ],
            "active_profile_id": "family",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = str(Path(tmpdir) / "sync")
            export = write_profile_sync_git_export(
                repo_dir,
                source_config,
                "long-enough-passphrase",
                default_last_open_dir=os.getcwd(),
                git_executable=git,
                gpg_executable="fake-gpg",
                gpg_runner=fake_gpg,
            )
            imported = read_profile_sync_git_import(
                repo_dir,
                {"whitelist": "old.example\n"},
                "long-enough-passphrase",
                default_last_open_dir=os.getcwd(),
                git_executable=git,
                gpg_executable="fake-gpg",
                gpg_runner=fake_gpg,
            )

        self.assertEqual(export["status"], "committed")
        self.assertEqual(imported["config"]["active_profile_id"], "family")
        self.assertEqual(imported["config"]["whitelist"], "school.example\n")
        self.assertIn("Hosts file writes: none", format_profile_sync_report(imported))

    def test_share_patch_payloads_apply_allowlist_and_profile_config_only(self):
        allowlist_patch = build_allowlist_share_patch(
            parse_allowlist_patch_text("Allow.Example\nbad value\nsecond.example\n"),
            author="Ops",
            now=datetime.datetime(2026, 5, 12, 10, 0, 0),
        )
        self.assertEqual(sanitize_share_patch_payload(allowlist_patch)["domains"], ["allow.example", "second.example"])

        config, report = apply_share_patch_payload_to_config(
            {
                "whitelist": "existing.example\n",
                "profiles": [{"id": "default", "name": "Default", "whitelist": "existing.example\n"}],
                "active_profile_id": "default",
            },
            allowlist_patch,
            os.getcwd(),
        )

        self.assertEqual(report["added_count"], 2)
        self.assertIn("allow.example", config["whitelist"])
        self.assertIn("second.example", config["profiles"][0]["whitelist"])

        profile_patch = build_profile_share_patch({
            "id": "shared",
            "name": "Shared",
            "whitelist": "shared.example\n",
            "pinned_domains": ["pin.example"],
        })
        config, profile_report = apply_share_patch_payload_to_config(config, profile_patch, os.getcwd())

        self.assertEqual(profile_report["profile_id"], "shared")
        self.assertEqual(config["active_profile_id"], "default")
        self.assertTrue(any(profile["id"] == "shared" for profile in config["profiles"]))
        self.assertIn("Hosts file writes: none", format_share_patch_summary(profile_report))

    def test_share_patch_file_sign_and_verify_with_fake_gpg(self):
        import tempfile
        from pathlib import Path

        def fake_gpg(args, capture_output=None, text=None, timeout=None, check=None):
            if "--detach-sign" in args:
                signature_path = Path(args[args.index("--output") + 1])
                patch_path = Path(args[-1])
                signature_path.write_text("signature-for:" + patch_path.read_text(encoding="utf-8"), encoding="utf-8")
                return type("Result", (), {"returncode": 0, "stdout": "", "stderr": "signed by test@example"})()
            signature_path = Path(args[-2])
            if not signature_path.read_text(encoding="utf-8").startswith("signature-for:"):
                return type("Result", (), {"returncode": 1, "stdout": "", "stderr": "bad signature"})()
            return type("Result", (), {"returncode": 0, "stdout": "", "stderr": "Good signature from Test"})()

        with tempfile.TemporaryDirectory() as tmpdir:
            patch_path = Path(tmpdir) / "allowlist.patch.json"
            signature_path = Path(tmpdir) / "allowlist.patch.json.asc"
            write_share_patch_payload(
                build_allowlist_share_patch(["allow.example"]),
                str(patch_path),
            )
            signed = sign_share_patch_file(
                str(patch_path),
                str(signature_path),
                gpg_key="test@example",
                gpg_executable="fake-gpg",
                runner=fake_gpg,
            )
            verified = verify_share_patch_signature(
                str(patch_path),
                str(signature_path),
                gpg_executable="fake-gpg",
                runner=fake_gpg,
            )
            loaded = load_share_patch_payload(str(patch_path))

        self.assertEqual(signed["status"], "signed")
        self.assertTrue(verified["verified"])
        self.assertEqual(loaded["domains"], ["allow.example"])

    def test_recovery_apply_plan_is_plan_only_and_formats_commands(self):
        plan = build_recovery_apply_plan(
            r"C:\Windows\System32\drivers\etc\hosts",
            "HostsFileGet before test",
            now=datetime.datetime(2026, 5, 12, 11, 0, 0),
        )
        command = build_restore_point_command("HostsFileGet before test")
        formatted = format_recovery_apply_plan(plan)

        self.assertTrue(plan["plan_only"])
        self.assertEqual(plan["schema"], hosts_editor.RECOVERY_PLAN_SCHEMA)
        self.assertEqual(plan["volume"], "C:\\")
        self.assertIn("Checkpoint-Computer", command[-1])
        self.assertIn("vss-shadow-copy", formatted)
        self.assertIn("This plan does not execute", formatted)

    def test_cli_recovery_plan_writes_json_without_applying(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            plan_path = Path(tmpdir) / "recovery-plan.json"
            with mock.patch.object(hosts_editor, "_cli_print"):
                result = hosts_editor._cli_recovery_plan(str(plan_path), "Before unit test")
            payload = json.loads(plan_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertTrue(payload["plan_only"])
        self.assertEqual(payload["description"], "Before unit test")

    def test_wfp_blocker_companion_plan_is_plan_only_and_chunks_targets(self):
        parsed = parse_wfp_blocker_targets(
            "1.1.1.1\n"
            "8.8.8.0/24 resolver\n"
            "0.0.0.0 sink\n"
            "127.0.0.1 loopback\n"
            "2001:4860:4860::8888\n"
        )
        plan = build_wfp_blocker_companion_plan(
            "\n".join(parsed["targets"]),
            rule_prefix="Test Block",
            now=datetime.datetime(2026, 5, 12, 12, 0, 0),
            chunk_size=2,
        )
        formatted = format_wfp_blocker_companion_plan(plan)

        self.assertEqual(parsed["targets"], ["1.1.1.1", "8.8.8.0/24", "2001:4860:4860::8888"])
        self.assertEqual(len(parsed["rejected"]), 2)
        self.assertEqual(plan["schema"], WFP_BLOCKER_PLAN_SCHEMA)
        self.assertTrue(plan["plan_only"])
        self.assertTrue(plan["companion_required"])
        self.assertEqual(plan["target_count"], 3)
        self.assertEqual(len(plan["commands"]), 3)
        self.assertIn("New-NetFirewallRule", plan["powershell_script"])
        self.assertIn("Remove-NetFirewallRule", plan["powershell_script"])
        self.assertIn("does not ship or load a WFP callout driver", plan["driver_boundary"])
        self.assertIn("S3", plan["references"])
        self.assertIn("Plan only: yes", formatted)

    def test_cli_wfp_blocker_plan_writes_json_without_firewall_changes(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "ips.txt"
            plan_path = Path(tmpdir) / "wfp-plan.json"
            input_path.write_text(
                "1.1.1.1\n192.168.0.0/24\n0.0.0.0\n",
                encoding="utf-8",
            )

            with mock.patch.object(hosts_editor, "_cli_print"):
                result = hosts_editor._cli_wfp_blocker_plan(str(input_path), str(plan_path), "Unit Block")
            payload = json.loads(plan_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertTrue(payload["plan_only"])
        self.assertEqual(payload["target_count"], 2)
        self.assertEqual(payload["rejected_count"], 1)
        self.assertIn("private", payload["risk_summary"])
        self.assertIn("New-NetFirewallRule", payload["powershell_script"])

    def test_nrpt_policy_export_plan_is_plan_only_and_encodes_namespaces(self):
        parsed = parse_nrpt_policy_namespaces(
            ".corp.example.com\n"
            "m\u00fcnich.example\n"
            "*.wild.example\n"
            "10.0.0.0/24\n"
            "corp.example.com\n"
        )
        plan = build_nrpt_policy_export_plan(
            "\n".join(parsed["namespaces"]),
            ["10.0.0.53", "2001:4860:4860::8888"],
            rule_prefix="Test NRPT",
            gpo_name="Corp Policy",
            server="dc01",
            now=datetime.datetime(2026, 5, 12, 13, 0, 0),
            chunk_size=1,
        )
        formatted = format_nrpt_policy_export_plan(plan)

        self.assertEqual(parsed["namespaces"], ["corp.example.com", "xn--mnich-kva.example"])
        self.assertEqual(len(parsed["rejected"]), 2)
        self.assertEqual(plan["schema"], NRPT_POLICY_PLAN_SCHEMA)
        self.assertTrue(plan["plan_only"])
        self.assertEqual(plan["scope"], "group-policy")
        self.assertEqual(plan["namespace_count"], 2)
        self.assertEqual(plan["rule_count"], 2)
        self.assertEqual(len(plan["commands"]), 3)
        self.assertIn("Add-DnsClientNrptRule", plan["powershell_script"])
        self.assertIn("Remove-DnsClientNrptRule", plan["powershell_script"])
        self.assertIn("-NameEncoding 'Punycode'", plan["powershell_script"])
        self.assertIn("-GpoName 'Corp Policy'", plan["powershell_script"])
        self.assertIn("private", plan["resolver_risk_summary"])
        self.assertIn("S1", plan["references"])
        self.assertIn("S2", plan["references"])
        self.assertIn("S16", plan["references"])
        self.assertIn("Plan only: yes", formatted)

    def test_cli_nrpt_policy_plan_writes_json_without_policy_changes(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "namespaces.txt"
            plan_path = Path(tmpdir) / "nrpt-plan.json"
            input_path.write_text(
                "corp.example.com\nm\u00fcnich.example\n*.bad.example\n",
                encoding="utf-8",
            )

            with mock.patch.object(hosts_editor, "_cli_print"):
                result = hosts_editor._cli_nrpt_policy_plan(
                    str(input_path),
                    str(plan_path),
                    ["10.0.0.53"],
                    "Unit NRPT",
                )
            payload = json.loads(plan_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertTrue(payload["plan_only"])
        self.assertEqual(payload["namespace_count"], 2)
        self.assertEqual(payload["rejected_count"], 1)
        self.assertEqual(payload["name_servers"], ["10.0.0.53"])
        self.assertIn("Get-DnsClientNrptRule", payload["powershell_script"])
        self.assertIn("Add-DnsClientNrptRule", payload["powershell_script"])

    def test_sandbox_vm_hosts_plan_builds_bundle_and_review_commands(self):
        plan = build_sandbox_vm_hosts_plan(
            "0.0.0.0 ads.example\n",
            r"C:\Labs\HostsFileGet",
            plan_name="Lab Hosts",
            vm_names=["Lab VM"],
            networking="Disable",
            vgpu="Default",
            memory_mb=4096,
            now=datetime.datetime(2026, 5, 12, 14, 0, 0),
        )
        formatted = format_sandbox_vm_hosts_plan(plan)

        self.assertEqual(plan["schema"], SANDBOX_VM_HOSTS_PLAN_SCHEMA)
        self.assertTrue(plan["plan_only"])
        self.assertTrue(plan["bundle_only"])
        self.assertEqual(plan["hosts_line_count"], 1)
        self.assertIn("<MappedFolder>", plan["windows_sandbox"]["wsb_config"])
        self.assertIn("<ReadOnly>true</ReadOnly>", plan["windows_sandbox"]["wsb_config"])
        self.assertIn("<LogonCommand>", plan["windows_sandbox"]["wsb_config"])
        self.assertIn("Copy-Item -LiteralPath $Source", plan["windows_sandbox"]["setup_script"])
        self.assertEqual(plan["windows_sandbox"]["networking"], "Disable")
        self.assertEqual(plan["windows_sandbox"]["vgpu"], "Default")
        self.assertEqual(plan["windows_sandbox"]["memory_mb"], 4096)
        self.assertEqual(plan["hyperv"]["vm_names"], ["Lab VM"])
        self.assertTrue(all("-WhatIf" in command["command"] for command in plan["hyperv"]["commands"]))
        self.assertIn("Copy-VMFile", plan["powershell_script"])
        self.assertIn("S17", plan["references"])
        self.assertIn("Plan only: yes", formatted)

    def test_cli_sandbox_vm_hosts_plan_writes_artifacts_without_launching(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "hosts.txt"
            output_dir = Path(tmpdir) / "bundle"
            input_path.write_text("0.0.0.0 ads.example\n", encoding="utf-8")

            with mock.patch.object(hosts_editor, "_cli_print"):
                result = hosts_editor._cli_sandbox_vm_hosts_plan(
                    str(input_path),
                    str(output_dir),
                    ["Lab VM"],
                    "Unit Bundle",
                    "Disable",
                    "Disable",
                    2048,
            )
            plan_path = output_dir / "sandbox-vm-hosts-plan.json"
            payload = json.loads(plan_path.read_text(encoding="utf-8"))
            artifacts_exist = [
                (output_dir / "hosts").exists(),
                (output_dir / "Apply-HostsFileGetHosts.ps1").exists(),
                (output_dir / "HostsFileGet-Sandbox.wsb").exists(),
            ]

        self.assertEqual(result, 0)
        self.assertTrue(payload["plan_only"])
        self.assertEqual(payload["hosts_line_count"], 1)
        self.assertEqual(artifacts_exist, [True, True, True])
        self.assertIn("Copy-VMFile", payload["powershell_script"])
        self.assertIn("-WhatIf", payload["powershell_script"])

    def test_router_gateway_push_plan_is_plan_only_and_generates_confirmed_script(self):
        adapters = {adapter["id"] for adapter in list_router_gateway_adapters()}
        self.assertEqual(adapters, {"openwrt-dnsmasq", "generic-dnsmasq", "generic-unbound"})

        plan = build_router_gateway_push_plan(
            [
                "0.0.0.0 ads.example",
                "0.0.0.0 tracker.example",
                "192.168.1.10 printer",
            ],
            "openwrt",
            remote_host="router.lan",
            remote_user="root",
            label="Lab Router",
            now=datetime.datetime(2026, 5, 12, 15, 0, 0),
        )
        formatted = format_router_gateway_push_plan(plan)
        catalog = format_router_gateway_adapter_catalog()

        self.assertEqual(plan["schema"], ROUTER_GATEWAY_PLAN_SCHEMA)
        self.assertTrue(plan["plan_only"])
        self.assertTrue(plan["bundle_only"])
        self.assertEqual(plan["execution"], "not-run")
        self.assertEqual(plan["adapter_id"], "openwrt-dnsmasq")
        self.assertEqual(plan["domain_count"], 2)
        self.assertIn("address=/ads.example/0.0.0.0", plan["config_content"])
        self.assertIn("HOSTSFILEGET_CONFIRM", plan["shell_script"])
        self.assertIn('!= "apply"', plan["shell_script"])
        self.assertIn("scp --", plan["shell_script"])
        self.assertIn("ssh --", plan["shell_script"])
        self.assertIn("dnsmasq --test", plan["shell_script"])
        self.assertIn("router.lan", plan["commands"][0]["command"])
        self.assertIn("S20", plan["references"])
        self.assertIn("Plan only: yes", formatted)
        self.assertIn("openwrt-dnsmasq", catalog)

    def test_cli_router_gateway_push_plan_writes_bundle_without_remote_actions(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "hosts.txt"
            output_dir = Path(tmpdir) / "router-bundle"
            input_path.write_text("0.0.0.0 ads.example\n", encoding="utf-8")

            with mock.patch.object(hosts_editor, "_cli_print"):
                result = hosts_editor._cli_router_gateway_push_plan(
                    "generic-unbound",
                    str(input_path),
                    str(output_dir),
                    "gateway.lan",
                    "admin",
                    None,
                    "Unit Gateway",
                )
            plan_path = output_dir / "router-gateway-push-plan.json"
            config_path = output_dir / "hostsfileget-unbound.conf"
            script_path = output_dir / "hostsfileget-router-push.sh"
            payload = json.loads(plan_path.read_text(encoding="utf-8"))
            config_text = config_path.read_text(encoding="utf-8")
            script_text = script_path.read_text(encoding="utf-8")

        self.assertEqual(result, 0)
        self.assertTrue(payload["plan_only"])
        self.assertEqual(payload["adapter_id"], "generic-unbound")
        self.assertEqual(payload["remote"]["identity"], "admin@gateway.lan")
        self.assertIn('local-zone: "ads.example." always_nxdomain', config_text)
        self.assertIn("HOSTSFILEGET_CONFIRM", script_text)
        self.assertIn("unbound-checkconf", payload["shell_script"])

    def test_cli_history_restore_refuses_when_hosts_file_is_disabled(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_path = Path(tmpdir) / "hosts"
            disabled_path = Path(tmpdir) / "hosts.disabled"
            hosts_path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            disabled_path.write_text("0.0.0.0 preserved.example\n", encoding="utf-8")

            with mock.patch.object(hosts_editor, "_cli_is_admin", return_value=True):
                with mock.patch.object(hosts_editor, "read_git_history_snapshot") as read_mock:
                    result = hosts_editor._cli_history_restore(str(hosts_path), "abc123")

            self.assertEqual(result, 1)
            read_mock.assert_not_called()

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
                import tempfile

                self.import_queue = queue.Queue()
                self.stop_import_flag = threading.Event()
                self.source_cache_metadata = {}
                self._source_cache_tmpdir = tempfile.TemporaryDirectory()
                self.source_cache_dir = self._source_cache_tmpdir.name

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
        editor._source_cache_tmpdir.cleanup()

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

    def test_import_worker_preserves_source_order_after_parallel_fetches(self):
        class FakeEditor:
            def __init__(self):
                import tempfile

                self.import_queue = queue.Queue()
                self.stop_import_flag = threading.Event()
                self.source_cache_metadata = {}
                self._source_cache_tmpdir = tempfile.TemporaryDirectory()
                self.source_cache_dir = self._source_cache_tmpdir.name

            def _apply_import_mode_filter(self, source_name, lines, mode):
                return [f"# {source_name}"] + lines

        def fake_fetch(url, metadata_store, cache_dir=None, timeout=15):
            if url.endswith("/first.txt"):
                hosts_editor.time.sleep(0.02)
                return ["0.0.0.0 first.example"], {"etag": '"first"'}, "network", 1
            return ["0.0.0.0 second.example"], {"etag": '"second"'}, "network", 1

        editor = FakeEditor()
        try:
            with mock.patch("hosts_editor.fetch_source_with_retries", side_effect=fake_fetch):
                HostsFileEditor._import_worker_thread(
                    editor,
                    [
                        ("First", "https://example.com/first.txt"),
                        ("Second", "https://example.com/second.txt"),
                    ],
                    "Raw",
                )
        finally:
            editor._source_cache_tmpdir.cleanup()

        messages = []
        while not editor.import_queue.empty():
            messages.append(editor.import_queue.get_nowait())

        done = [message for message in messages if message[0] == "done"][-1]
        self.assertEqual(
            done[1],
            [
                "# First",
                "0.0.0.0 first.example",
                "# Second",
                "0.0.0.0 second.example",
            ],
        )
        self.assertEqual(done[3], 2)

    def test_import_worker_cancels_if_stop_requested_during_final_download(self):
        class FakeEditor:
            def __init__(self):
                import tempfile

                self.import_queue = queue.Queue()
                self.stop_import_flag = threading.Event()
                self.source_cache_metadata = {}
                self._source_cache_tmpdir = tempfile.TemporaryDirectory()
                self.source_cache_dir = self._source_cache_tmpdir.name

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
        editor._source_cache_tmpdir.cleanup()

        messages = []
        while not editor.import_queue.empty():
            messages.append(editor.import_queue.get_nowait()[0])

        self.assertEqual(messages, ["cancelled"])

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

    # ---- DNS rebinding protection checks ----
    def test_dns_rebinding_report_separates_candidates_local_aliases_and_redirects(self):
        lines = [
            "0.0.0.0 ads.example",
            "127.0.0.1 telemetry.example",
            "192.168.1.10 router.lan",
            "10.0.0.5 api.example.com",
            "172.20.1.1 dev.example.com",
            "172.32.1.1 public.example.com",
            "100.64.0.2 tailscale.example.com",
            "fc00::1 admin.example.com",
            "fe80::1 printer.local",
            "8.8.8.8 www.google.com",
        ]

        report = build_dns_rebinding_report(lines)

        self.assertEqual(report["schema"], "hostsfileget.dns-rebinding-report.v1")
        self.assertEqual(report["summary"]["total_mappings"], 10)
        self.assertEqual(report["summary"]["rebinding_candidates"], 4)
        self.assertEqual(report["summary"]["trusted_local_mappings"], 2)
        self.assertEqual(report["summary"]["public_redirects"], 2)
        self.assertEqual(report["summary"]["blocking_sink_mappings"], 2)

        candidate_domains = {finding["domain"] for finding in report["rebinding_candidates"]}
        self.assertEqual(
            candidate_domains,
            {"api.example.com", "dev.example.com", "tailscale.example.com", "admin.example.com"},
        )
        trusted_domains = {finding["domain"] for finding in report["trusted_local_mappings"]}
        self.assertEqual(trusted_domains, {"router.lan", "printer.local"})
        public_domains = {finding["domain"] for finding in report["public_redirects"]}
        self.assertEqual(public_domains, {"public.example.com", "www.google.com"})

        formatted = format_dns_rebinding_report(report)
        self.assertIn("DNS Rebinding Protection Check", formatted)
        self.assertIn("api.example.com -> 10.0.0.5", formatted)
        self.assertIn("Roadmap source IDs", formatted)

    def test_dns_rebinding_report_honors_extra_trusted_suffixes(self):
        lines = ["10.0.0.5 app.lab.example"]

        default_report = build_dns_rebinding_report(lines)
        trusted_report = build_dns_rebinding_report(lines, trusted_suffixes=["lab.example"])

        self.assertEqual(default_report["summary"]["rebinding_candidates"], 1)
        self.assertEqual(default_report["summary"]["trusted_local_mappings"], 0)
        self.assertEqual(trusted_report["summary"]["rebinding_candidates"], 0)
        self.assertEqual(trusted_report["summary"]["trusted_local_mappings"], 1)
        self.assertIn(".lab.example", trusted_report["trusted_suffixes"])

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
            export_lines_as_format(lines, "adguard-home").splitlines(),
            ["||ads.example^", "||tracker.example^"],
        )
        self.assertEqual(
            export_lines_as_format(lines, "dnsmasq").splitlines(),
            ["address=/ads.example/0.0.0.0", "address=/tracker.example/0.0.0.0"],
        )

    def test_build_export_domain_records_keeps_stable_ir(self):
        records = build_export_domain_records([
            "0.0.0.0 ADS.example",
            "0.0.0.0 tracker.example",
            "192.168.1.10 printer",
            "# 0.0.0.0 ignored.example",
            "0.0.0.0 ads.example",
        ])

        self.assertEqual(records, [
            {"domain": "ads.example", "entry": "0.0.0.0 ads.example"},
            {"domain": "tracker.example", "entry": "0.0.0.0 tracker.example"},
        ])

    def test_export_lines_as_format_supports_dns_integration_formats(self):
        lines = ["0.0.0.0 ads.example", "0.0.0.0 tracker.example"]

        rpz = export_lines_as_format(lines, "rpz")
        self.assertIn("$TTL 2h", rpz)
        self.assertIn("ads.example CNAME .", rpz)
        self.assertIn("tracker.example CNAME .", rpz)

        unbound = export_lines_as_format(lines, "unbound")
        self.assertIn('local-zone: "ads.example." always_nxdomain', unbound)
        self.assertIn('local-zone: "tracker.example." always_nxdomain', unbound)

        privoxy = export_lines_as_format(lines, "privoxy")
        self.assertIn("{+block{HostsFileGet blocked domain}}", privoxy)
        self.assertIn("ads.example/", privoxy)
        self.assertIn("tracker.example/", privoxy)

        self.assertEqual(export_lines_as_format(lines, "technitium-dns").splitlines(), ["ads.example", "tracker.example"])
        self.assertEqual(export_lines_as_format(lines, "blocky").splitlines(), ["ads.example", "tracker.example"])

    def test_dns_integration_pack_report_lists_file_first_presets(self):
        pack_ids = {pack["id"] for pack in list_dns_integration_packs()}
        self.assertEqual(pack_ids, {"pihole", "adguard-home", "adguard-dns", "technitium", "blocky"})

        report = format_dns_integration_pack_report()
        self.assertIn("File-only export", report)
        self.assertIn("pihole", report)
        self.assertIn("technitium", report)
        self.assertIn("blocky", report)

    def test_build_dns_integration_export_uses_pack_format_and_aliases(self):
        lines = [
            "0.0.0.0 ads.example",
            "0.0.0.0 tracker.example",
            "192.168.1.10 printer",
            "0.0.0.0 ads.example",
        ]

        agh = build_dns_integration_export(lines, "agh")
        self.assertEqual(agh["integration_id"], "adguard-home")
        self.assertEqual(agh["content"].splitlines(), ["||ads.example^", "||tracker.example^"])
        self.assertEqual(agh["domain_count"], 2)
        self.assertIn("does not authenticate", "\n".join(agh["warnings"]))

        technitium = build_dns_integration_export(lines, "technitium-dns-server")
        self.assertEqual(technitium["content"].splitlines(), ["ads.example", "tracker.example"])
        self.assertIn("Technitium", format_dns_integration_export_summary(technitium, "out.txt"))

    def test_build_dns_integration_export_rejects_unknown_pack(self):
        with self.assertRaises(ValueError):
            build_dns_integration_export(["0.0.0.0 x.example"], "unknown-dns")

    def test_parse_nextdns_log_csv_extracts_blocked_domains(self):
        csv_text = (
            "Time,Domain,Status\n"
            "2026-05-12T10:00:00Z,Ads.Example.,blocked\n"
            "2026-05-12T10:01:00Z,allowed.example,allowed\n"
            "2026-05-12T10:02:00Z,https://tracker.example/path,Blocked\n"
            "2026-05-12T10:03:00Z,ads.example,blocked\n"
            "2026-05-12T10:04:00Z,not a domain,blocked\n"
        )
        self.assertEqual(parse_nextdns_log_csv(csv_text), ["ads.example", "tracker.example"])
        with self.assertRaises(ValueError):
            parse_nextdns_log_csv("domain,reason\nexample.com,blocked\n")

    def test_parse_controld_activity_csv_extracts_blocked_domains(self):
        csv_text = (
            "timestamp,question,action\n"
            "2026-05-12T10:00:00Z,Ads.Example,0\n"
            "2026-05-12T10:01:00Z,bypass.example,1\n"
            "2026-05-12T10:02:00Z,tracker.example,blocked\n"
            "2026-05-12T10:03:00Z,tracker.example,block\n"
        )
        self.assertEqual(parse_controld_activity_csv(csv_text), ["ads.example", "tracker.example"])

        siem_text = "time,query,controld_action\n2026-05-12T10:00:00Z,siem.example,0\n"
        self.assertEqual(parse_cloud_dns_log_export("control-d", siem_text), ["siem.example"])
        with self.assertRaises(ValueError):
            parse_controld_activity_csv("domain,status\nexample.com,blocked\n")

    def test_cloud_dns_adapter_catalog_lists_plan_only_adapters(self):
        adapter_ids = {adapter["id"] for adapter in list_cloud_dns_adapters()}
        self.assertEqual(adapter_ids, {"nextdns-denylist", "nextdns-allowlist", "controld-block-rules"})

        catalog = format_cloud_dns_adapter_catalog()
        self.assertIn("Plan-only", catalog)
        self.assertIn("nextdns-denylist", catalog)
        self.assertIn("controld-block-rules", catalog)

    def test_build_cloud_dns_adapter_plan_generates_placeholder_requests(self):
        lines = [
            "0.0.0.0 ads.example",
            "0.0.0.0 tracker.example",
            "0.0.0.0 ads.example",
            "192.168.1.10 printer",
        ]

        nextdns = build_cloud_dns_adapter_plan(lines, "nextdns-deny", profile_id="abc 123")
        self.assertEqual(nextdns["adapter_id"], "nextdns-denylist")
        self.assertEqual(nextdns["domain_count"], 2)
        self.assertEqual(nextdns["request_count"], 2)
        self.assertEqual(nextdns["domains"], ["ads.example", "tracker.example"])
        self.assertEqual(nextdns["requests"][0]["headers"], {"X-Api-Key": "<NEXTDNS_API_KEY>"})
        self.assertEqual(nextdns["requests"][0]["json"], {"id": "ads.example", "active": True})
        self.assertIn("/profiles/abc%20123/denylist", nextdns["requests"][0]["url"])
        self.assertNotIn("API_KEY", json.dumps(nextdns["domains"]))
        self.assertIn("Cloud DNS Adapter Plan", format_cloud_dns_adapter_report(nextdns))

        controld = build_cloud_dns_adapter_plan(lines, "control-d", profile_id="profile-1")
        self.assertEqual(controld["adapter_id"], "controld-block-rules")
        self.assertEqual(controld["request_count"], 1)
        self.assertEqual(controld["requests"][0]["headers"], {"Authorization": "Bearer <CONTROL_D_API_TOKEN>"})
        self.assertEqual(controld["requests"][0]["form"]["do"], 0)
        self.assertEqual(controld["requests"][0]["form"]["status"], 1)
        self.assertEqual(controld["requests"][0]["form"]["hostnames[]"], ["ads.example", "tracker.example"])

        with self.assertRaises(ValueError):
            build_cloud_dns_adapter_plan(lines, "unknown-cloud")

    def test_threat_feed_catalog_lists_guarded_packs_and_sources(self):
        pack_ids = {pack["id"] for pack in list_threat_feed_packs()}
        source_ids = {source["id"] for source in list_threat_feed_sources()}

        self.assertEqual(pack_ids, {"security-starter", "dga-watch", "nrd-review", "threat-full-review"})
        self.assertIn("hagezi-dga-7", source_ids)
        self.assertIn("hagezi-nrd-14", source_ids)

        catalog = format_threat_feed_pack_catalog()
        self.assertIn("NRD/DGA threat feed packs", catalog)
        self.assertIn("Plan-only", catalog)
        self.assertIn("does not fetch", catalog)
        self.assertIn("hagezi-tif-mini", catalog)

    def test_build_threat_feed_pack_plan_includes_freshness_and_false_positive_controls(self):
        nrd_plan = build_threat_feed_pack_plan("nrd")
        rendered = format_threat_feed_pack_plan(nrd_plan)

        self.assertEqual(nrd_plan["pack_id"], "nrd-review")
        self.assertEqual(nrd_plan["risk"], "high")
        self.assertEqual(nrd_plan["source_ids"], ["hagezi-nrd-7", "hagezi-nrd-14"])
        self.assertEqual(nrd_plan["freshness"]["stale_after_hours"], 6)
        self.assertTrue(any("false-positive triage" in control for control in nrd_plan["false_positive_controls"]))
        self.assertTrue(all("api" not in json.dumps(source).lower() for source in nrd_plan["sources"]))
        self.assertIn("nrd7.txt", rendered)
        self.assertIn("A2", rendered)

        dga_plan = build_threat_feed_pack_plan("dga-pack")
        self.assertEqual(dga_plan["pack_id"], "dga-watch")
        self.assertIn("S15", dga_plan["references"])

        with self.assertRaises(ValueError):
            build_threat_feed_pack_plan("unknown-threat-pack")

    def test_cname_cloaking_catalog_separates_hosts_and_dns_workflows(self):
        pack_ids = {pack["id"] for pack in list_cname_cloaking_packs()}
        source_ids = {source["id"] for source in list_cname_cloaking_sources()}

        self.assertEqual(pack_ids, {"hosts-disguised-review", "cname-aware-dns", "rpz-dns"})
        self.assertIn("nextdns-cname-targets", source_ids)
        self.assertIn("adguard-cname-disguised-trackers", source_ids)

        catalog = format_cname_cloaking_catalog()
        self.assertIn("CNAME cloaking workflow", catalog)
        self.assertIn("not-native", catalog)
        self.assertIn("review-import", catalog)
        self.assertIn("Hosts files only match", catalog)

    def test_build_cname_cloaking_plan_explains_hosts_boundary(self):
        hosts_plan = build_cname_cloaking_plan("hosts")
        hosts_rendered = format_cname_cloaking_plan(hosts_plan)

        self.assertEqual(hosts_plan["pack_id"], "hosts-disguised-review")
        self.assertTrue(hosts_plan["hosts_native"])
        self.assertIn("adguard-cname-disguised-trackers", hosts_plan["source_ids"])
        self.assertNotIn("nextdns-cname-targets", hosts_plan["source_ids"])
        self.assertIn("Hosts limit", hosts_rendered)
        self.assertIn("combined_disguised_trackers_justdomains.txt", hosts_rendered)
        self.assertIn("A4", hosts_rendered)

        dns_plan = build_cname_cloaking_plan("cname-aware")
        self.assertEqual(dns_plan["pack_id"], "cname-aware-dns")
        self.assertFalse(dns_plan["hosts_native"])
        self.assertIn("nextdns-cname-targets", dns_plan["source_ids"])
        self.assertIn("cannot inspect CNAME response chains", dns_plan["explanation"]["hosts_limit"])
        self.assertIn("C1", dns_plan["references"])

        with self.assertRaises(ValueError):
            build_cname_cloaking_plan("unknown-cname-pack")

    def test_encrypted_dns_bypass_catalog_lists_guarded_packs_and_sources(self):
        pack_ids = {pack["id"] for pack in list_encrypted_dns_bypass_packs()}
        source_ids = {source["id"] for source in list_encrypted_dns_bypass_sources()}

        self.assertEqual(pack_ids, {"doh-hosts-review", "bypass-full-review", "router-firewall-handoff"})
        self.assertIn("hagezi-doh-hosts", source_ids)
        self.assertIn("hagezi-doh-ips", source_ids)

        catalog = format_encrypted_dns_bypass_catalog()
        self.assertIn("Encrypted DNS bypass packs", catalog)
        self.assertIn("firewall-only", catalog)
        self.assertIn("router/firewall handoff", catalog)
        self.assertIn("Hosts files can block known resolver hostnames", catalog)

    def test_build_encrypted_dns_bypass_plan_explains_firewall_boundary(self):
        doh_plan = build_encrypted_dns_bypass_pack_plan("doh")
        doh_rendered = format_encrypted_dns_bypass_pack_plan(doh_plan)

        self.assertEqual(doh_plan["pack_id"], "doh-hosts-review")
        self.assertTrue(doh_plan["hosts_native"])
        self.assertEqual(doh_plan["source_ids"], ["hagezi-doh-hosts"])
        self.assertIn("hosts/doh.txt", doh_rendered)
        self.assertIn("S7", doh_rendered)

        firewall_plan = build_encrypted_dns_bypass_pack_plan("router")
        self.assertEqual(firewall_plan["pack_id"], "router-firewall-handoff")
        self.assertFalse(firewall_plan["hosts_native"])
        self.assertIn("hagezi-doh-ips", firewall_plan["source_ids"])
        self.assertIn("cannot stop IP-literal resolver access", firewall_plan["explanation"]["hosts_limit"])
        self.assertIn("K1", firewall_plan["references"])

        with self.assertRaises(ValueError):
            build_encrypted_dns_bypass_pack_plan("unknown-bypass-pack")

    def test_safesearch_template_catalog_lists_guarded_templates_and_sources(self):
        template_ids = {template["id"] for template in list_safesearch_templates()}
        source_ids = {source["id"] for source in list_safesearch_template_sources()}

        self.assertEqual(
            template_ids,
            {
                "google-safesearch-hosts",
                "bing-strict-hosts",
                "duckduckgo-strict-dns",
                "youtube-strict-dns",
                "youtube-moderate-dns",
            },
        )
        self.assertIn("google-safesearch-vip", source_ids)
        self.assertIn("youtube-restricted-mode", source_ids)
        self.assertIn("duckduckgo-safe-search", source_ids)

        catalog = format_safesearch_template_catalog()
        self.assertIn("SafeSearch and restricted-mode templates", catalog)
        self.assertIn("DNS/provider handoff", catalog)
        self.assertIn("cannot express CNAME records", catalog)

    def test_build_safesearch_template_plan_separates_hosts_and_dns_handoffs(self):
        google_plan = build_safesearch_template_plan("google")
        google_rendered = format_safesearch_template_plan(google_plan)

        self.assertEqual(google_plan["template_id"], "google-safesearch-hosts")
        self.assertTrue(google_plan["hosts_native"])
        self.assertIn("216.239.38.120 www.google.com", google_plan["hosts_line_templates"][0])
        self.assertIn("forcesafesearch.google.com", google_rendered)
        self.assertIn("P1", google_plan["references"])

        youtube_plan = build_safesearch_template_plan("yt-moderate")
        self.assertEqual(youtube_plan["template_id"], "youtube-moderate-dns")
        self.assertFalse(youtube_plan["hosts_native"])
        self.assertEqual(youtube_plan["hosts_line_templates"], [])
        self.assertIn({"hostname": "www.youtube.com", "target": "restrictmoderate.youtube.com", "scope": "DNS resolver"}, youtube_plan["dns_cname_records"])
        self.assertIn("youtube.com", youtube_plan["excluded_hosts"])
        self.assertIn("P2", youtube_plan["references"])

        bing_plan = build_safesearch_template_plan("bing")
        self.assertIn("<resolved strict.bing.com IP> www.bing.com", bing_plan["hosts_line_templates"][0])

        with self.assertRaises(ValueError):
            build_safesearch_template_plan("unknown-safesearch-template")

    def test_export_lines_as_bytes_supports_compressed_hosts(self):
        lines = ["0.0.0.0 ads.example", "# comment", "0.0.0.0 tracker.example"]
        expected = "\n".join(lines)

        gz_bytes = export_lines_as_bytes(lines, "hosts-gzip")
        bz2_bytes = export_lines_as_bytes(lines, "hosts-bzip2")

        self.assertEqual(gzip.decompress(gz_bytes).decode("utf-8"), expected)
        self.assertEqual(bz2.decompress(bz2_bytes).decode("utf-8"), expected)
        self.assertEqual(gz_bytes, export_lines_as_bytes(lines, "hosts.gz"))

    def test_write_bytes_file_atomic_replaces_file_contents(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "hosts.gz"
            write_bytes_file_atomic(str(path), b"old")
            write_bytes_file_atomic(str(path), b"new")

            self.assertEqual(path.read_bytes(), b"new")

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

    def test_build_scheduler_update_command_forces_silent_logging(self):
        command = build_scheduler_update_command(
            r"C:\Python312\python.exe",
            r"C:\Apps\Hosts File Get\hosts_editor.py",
        )

        self.assertIn("--update", command)
        self.assertIn("--silent", command)
        self.assertIn('"C:\\Apps\\Hosts File Get\\hosts_editor.py"', command)

        frozen_command = build_scheduler_update_command(
            "",
            r"C:\Apps\HostsFileGet.exe",
            frozen=True,
        )
        self.assertEqual(frozen_command, r"C:\Apps\HostsFileGet.exe --update --silent")

    def test_scheduler_activity_event_roundtrips_and_formats_report(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            activity_path = os.path.join(tmp, "activity.jsonl")
            log_path = os.path.join(tmp, "cli.log")
            write_text_file_atomic(log_path, "2026-05-12T12:00:00  OK Example\n")
            append_cli_activity_event(
                {
                    "action": "update",
                    "started_at": "2026-05-12T12:00:00Z",
                    "finished_at": "2026-05-12T12:00:03Z",
                    "duration_seconds": 3.2,
                    "exit_code": 0,
                    "summary": "Applied 10 active entries from 1 source(s); 0 failed.",
                    "details": {"successful_sources": 1, "failed_sources": 0},
                },
                activity_path,
            )

            events = read_cli_activity_events(activity_path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["action"], "update")
            self.assertEqual(events[0]["details"]["successful_sources"], 1)

            class Completed:
                returncode = 0
                stdout = (
                    "TaskName: \\HostsFileGet Auto-Update\n"
                    "Status: Ready\n"
                    "Schedule Type: Daily\n"
                    "Next Run Time: 5/13/2026 3:30:00 AM\n"
                    "Last Run Time: 5/12/2026 3:30:00 AM\n"
                    "Last Result: 0\n"
                    "Task To Run: C:\\Apps\\HostsFileGet.exe --update --silent\n"
                )
                stderr = ""

            report = build_scheduler_activity_report(
                activity_path=activity_path,
                log_path=log_path,
                task_query_runner=lambda *_args, **_kwargs: Completed(),
            )
            formatted = format_scheduler_activity_report(report)

            self.assertTrue(report["task"]["registered"])
            self.assertEqual(report["summary"]["success"], 1)
            self.assertIn("Scheduler Activity", formatted)
            self.assertIn("--silent", report["task"]["task_to_run"])
            self.assertIn("OK Example", formatted)

    def test_parse_schtasks_query_output_and_activity_sanitizer_are_bounded(self):
        fields = parse_schtasks_query_output("Status: Ready\nLast Result: 0x0\nIgnored\n")
        self.assertEqual(fields["status"], "Ready")
        self.assertEqual(fields["last result"], "0x0")

        sanitized = sanitize_cli_activity_event({
            "action": "update\nbad",
            "duration_seconds": "bad",
            "exit_code": "not-int",
            "details": {"ok": True, "bad\nkey": "drop", "note": "x" * 700},
        })

        self.assertEqual(sanitized["duration_seconds"], 0.0)
        self.assertEqual(sanitized["exit_code"], 0)
        self.assertIn("ok", sanitized["details"])
        self.assertNotIn("bad\nkey", sanitized["details"])
        self.assertLessEqual(len(sanitized["details"]["note"]), 500)

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

    def test_sanitize_config_snapshot_keeps_valid_source_cache_metadata(self):
        config = {
            "source_cache_metadata": {
                "https://example.com/hosts.txt": {
                    "content_sha256": "b" * 64,
                    "bytes": 42,
                    "etag": '"v1"',
                    "last_modified": "Wed, 21 Oct 2015 07:28:00 GMT",
                    "content_encoding": "",
                    "fetched_at": "2026-05-12T12:00:00",
                    "validated_at": "2026-05-12T12:00:00",
                }
            }
        }

        sanitized = sanitize_config_snapshot(config, os.path.expanduser("~"))

        self.assertIn("https://example.com/hosts.txt", sanitized["source_cache_metadata"])
        self.assertEqual(
            sanitized["source_cache_metadata"]["https://example.com/hosts.txt"]["content_sha256"],
            "b" * 64,
        )

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

    def test_entry_provenance_report_blames_import_source_and_events(self):
        lines = [
            "0.0.0.0 manual.example",
            "# --- Normalized Import Start: BigSource ---",
            "0.0.0.0 ads.example",
            "# --- Normalized Import End: BigSource ---",
        ]
        report = build_entry_provenance_report(
            lines,
            3,
            source_corpus={
                "big": {"name": "BigSource", "text": "0.0.0.0 ads.example\n"},
            },
            provenance_events=[
                {"ts": "2026-05-12T10:00:00", "kind": "pin", "domain": "other.example", "source": "test"},
                {"ts": "2026-05-12T10:01:00", "kind": "whitelist_add", "domain": "ads.example", "source": "triage"},
            ],
        )

        self.assertTrue(report["valid"])
        self.assertEqual(report["line_role"], "inside_import")
        self.assertEqual(report["section"]["name"], "BigSource")
        self.assertEqual(report["entries"][0]["domain"], "ads.example")
        self.assertEqual(report["entries"][0]["source_matches"], ["BigSource"])
        self.assertEqual(len(report["entries"][0]["provenance_events"]), 1)
        formatted = format_entry_provenance_report(report)
        self.assertIn("Import section:", formatted)
        self.assertIn("BigSource", formatted)
        self.assertIn("whitelist_add", formatted)

    def test_entry_provenance_report_handles_marker_and_out_of_range(self):
        lines = [
            "# --- Raw Import Start: Foo ---",
            "0.0.0.0 a.example",
            "# --- Raw Import End: Foo ---",
        ]

        marker_report = build_entry_provenance_report(lines, 1)
        self.assertTrue(marker_report["valid"])
        self.assertEqual(marker_report["line_role"], "import_start_marker")
        self.assertEqual(marker_report["entries"], [])
        self.assertIn("no parseable hosts entries", format_entry_provenance_report(marker_report))

        bad_report = build_entry_provenance_report(lines, 99)
        self.assertFalse(bad_report["valid"])
        self.assertIn("outside the current editor range", format_entry_provenance_report(bad_report))

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

    def test_extract_blocking_domains_from_lines_skips_custom_mappings(self):
        domains = extract_blocking_domains_from_lines([
            "0.0.0.0 ads.example",
            "||tracker.example^",
            "192.168.1.10 printer.example",
            "# 0.0.0.0 ignored.example",
        ])

        self.assertEqual(domains, {"ads.example", "tracker.example"})

    def test_build_source_domain_index_reads_structured_and_legacy_corpus(self):
        index = build_source_domain_index({
            "https://one.example/hosts": {
                "name": "One",
                "url": "https://one.example/hosts",
                "text": "0.0.0.0 a.example\n0.0.0.0 b.example\n",
            },
            "Legacy": "0.0.0.0 c.example\n# 0.0.0.0 ignored.example\n",
        })

        self.assertEqual(index["One"], {"a.example", "b.example"})
        self.assertEqual(index["Legacy"], {"c.example"})

    def test_build_source_overlap_report_ranks_shared_domains(self):
        report = build_source_overlap_report({
            "one": {"name": "One", "text": "0.0.0.0 a.example\n0.0.0.0 b.example\n0.0.0.0 c.example\n"},
            "two": {"name": "Two", "text": "0.0.0.0 b.example\n0.0.0.0 c.example\n0.0.0.0 d.example\n"},
            "three": {"name": "Three", "text": "0.0.0.0 z.example\n"},
        })

        self.assertEqual(report["source_count"], 3)
        self.assertEqual(report["total_unique_domains"], 5)
        self.assertEqual(report["domains_seen_in_multiple_sources"], 2)
        one_row = next(row for row in report["source_rows"] if row["source"] == "One")
        self.assertEqual(one_row["unique_domains"], 1)
        self.assertEqual(one_row["overlap_domains"], 2)
        top_pair = report["pairs"][0]
        self.assertEqual((top_pair["source_a"], top_pair["source_b"]), ("One", "Two"))
        self.assertEqual(top_pair["shared_domains"], 2)
        self.assertEqual(top_pair["sample_domains"], ["b.example", "c.example"])
        formatted = format_source_overlap_report(report)
        self.assertIn("Fetched source overlap matrix", formatted)
        self.assertIn("Top overlapping pairs", formatted)
        self.assertIn("One", formatted)
        self.assertIn("Two", formatted)

    def test_sanitize_source_metrics_history_clamps_and_sorts_points(self):
        history = {
            "https://example.com/hosts.txt": [
                {"ts": "not a date", "domain_count": 999},
                {"ts": "2026-04-18T10:00:00", "name": "Example\nHosts", "domain_count": "5", "line_count": "7"},
                {"ts": "2026-04-19T10:00:00", "name": "Example Hosts", "domain_count": 8, "bytes": -10},
                {"ts": "2026-04-20T10:00:00", "name": "Example Hosts", "domain_count": 13, "bytes": 123},
            ],
            "not a url": [{"ts": "2026-04-20T10:00:00", "domain_count": 1}],
        }

        sanitized = sanitize_source_metrics_history(history, max_points=2)

        self.assertEqual(list(sanitized), ["https://example.com/hosts.txt"])
        points = sanitized["https://example.com/hosts.txt"]
        self.assertEqual([point["domain_count"] for point in points], [8, 13])
        self.assertEqual(points[-1]["bytes"], 123)

    def test_record_source_metrics_snapshot_counts_domains_and_caps_history(self):
        history = {}
        for idx in range(35):
            history = record_source_metrics_snapshot(
                history,
                "Example Hosts",
                "https://example.com/hosts.txt",
                [
                    "0.0.0.0 ads.example",
                    f"0.0.0.0 tracker{idx}.example",
                    "192.168.1.10 printer.example",
                ],
                cache_status="fetched",
                fetched_at=f"2026-04-{(idx % 28) + 1:02d}T10:00:00",
            )

        points = history["https://example.com/hosts.txt"]
        self.assertEqual(len(points), 30)
        self.assertEqual(points[-1]["domain_count"], 2)
        self.assertEqual(points[-1]["line_count"], 3)
        self.assertEqual(points[-1]["cache_status"], "fetched")

    def test_build_and_format_source_metrics_report_shows_growth(self):
        history = {}
        history = record_source_metrics_snapshot(
            history,
            "Example Hosts",
            "https://example.com/hosts.txt",
            ["0.0.0.0 ads.example"],
            cache_status="fetched",
            fetched_at="2026-04-20T09:00:00",
        )
        history = record_source_metrics_snapshot(
            history,
            "Example Hosts",
            "https://example.com/hosts.txt",
            ["0.0.0.0 ads.example", "0.0.0.0 tracker.example"],
            cache_status="not_modified",
            fetched_at="2026-04-20T10:00:00",
        )
        now = datetime.datetime.fromisoformat("2026-04-20T11:00:00").timestamp()

        report = build_source_metrics_report(
            {"https://example.com/hosts.txt": "2026-04-20T10:00:00"},
            {},
            history,
            {},
            {},
            now=now,
        )
        self.assertEqual(report["source_count"], 1)
        self.assertEqual(report["freshness_counts"]["fresh"], 1)
        row = report["rows"][0]
        self.assertEqual(row["latest_domain_count"], 2)
        self.assertEqual(row["delta_previous"], 1)
        self.assertEqual(row["delta_first"], 1)
        formatted = format_source_metrics_report(report)
        self.assertIn("Source Freshness & Growth", formatted)
        self.assertIn("Example Hosts", formatted)
        self.assertIn("Boundary: local metrics only", formatted)

    def test_sanitize_config_snapshot_persists_source_metrics_history(self):
        snapshot = sanitize_config_snapshot(
            {
                "source_metrics_history": {
                    "https://example.com/hosts.txt": [
                        {
                            "ts": "2026-04-20T10:00:00",
                            "name": "Example Hosts",
                            "domain_count": 2,
                            "line_count": 3,
                            "bytes": 42,
                            "cache_status": "fetched",
                        }
                    ]
                }
            },
            os.path.expanduser("~"),
        )

        self.assertEqual(
            snapshot["source_metrics_history"]["https://example.com/hosts.txt"][0]["domain_count"],
            2,
        )

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

    # ---- vNext: migration importers ----
    def test_parse_switchhosts_export_text_accepts_v3_tree(self):
        payload = {
            "version": [3, 0, 0, 0],
            "list": [
                {
                    "id": "local-a",
                    "title": "Local A",
                    "where": "local",
                    "content": "# local\n0.0.0.0 a.example\n",
                },
                {
                    "id": "folder",
                    "title": "Folder",
                    "where": "folder",
                    "children": [
                        {
                            "id": "remote-b",
                            "title": "Remote B",
                            "where": "remote",
                            "content": "0.0.0.0 b.example\n",
                        }
                    ],
                },
            ],
        }

        records = parse_switchhosts_export_text(json.dumps(payload))

        self.assertEqual([record["source"] for record in records], [
            "SwitchHosts local: Local A",
            "SwitchHosts remote: Remote B",
        ])
        self.assertIn("0.0.0.0 a.example", records[0]["lines"])
        self.assertIn("0.0.0.0 b.example", records[1]["lines"])

    def test_parse_switchhosts_export_text_accepts_v4_export_data(self):
        payload = {
            "version": [4, 2, 0, 0],
            "data": {
                "collection": {
                    "hosts": [
                        {"id": "one", "type": "local", "content": "0.0.0.0 one.example\n"}
                    ]
                },
                "list": {"tree": [{"id": "one", "title": "One"}]},
            },
        }

        records = parse_switchhosts_export_text(json.dumps(payload))

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["source"], "SwitchHosts local: One")
        self.assertEqual(records[0]["lines"], ["0.0.0.0 one.example"])

    def test_parse_switchhosts_export_text_rejects_unknown_shape(self):
        with self.assertRaises(ValueError):
            parse_switchhosts_export_text(json.dumps({"list": []}))

    def test_parse_gas_mask_archive_path_expands_combined_profiles(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            local_dir = root / "Local"
            remote_dir = root / "Remote"
            combined_dir = root / "Combined"
            local_dir.mkdir()
            remote_dir.mkdir()
            combined_dir.mkdir()
            (local_dir / "Work.hst").write_text("0.0.0.0 work.example\n", encoding="utf-8")
            (remote_dir / "Shared.hst").write_text("0.0.0.0 shared.example\n", encoding="utf-8")
            (combined_dir / "All.hst").write_text("Local/Work\nRemote/Shared\n", encoding="utf-8")

            records = parse_gas_mask_archive_path(str(root))

        self.assertEqual(
            [record["source"] for record in records],
            ["Gas Mask Local: Work", "Gas Mask Remote: Shared", "Gas Mask Combined: All"],
        )
        combined = records[2]["lines"]
        self.assertIn("# Hosts File: Work", combined)
        self.assertIn("0.0.0.0 work.example", combined)
        self.assertIn("# Hosts File: Shared", combined)
        self.assertIn("0.0.0.0 shared.example", combined)

    def test_parse_hostsfileeditor_archive_path_reads_plain_archive_files(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            archive_dir = Path(tmpdir)
            (archive_dir / "morning").write_text("# saved\n0.0.0.0 morning.example\n", encoding="utf-8")
            (archive_dir / "empty").write_text("# comment only\n", encoding="utf-8")
            (archive_dir / "evening").write_text("0.0.0.0 evening.example\n", encoding="utf-8")

            records = parse_hostsfileeditor_archive_path(str(archive_dir))

        self.assertEqual(
            [record["source"] for record in records],
            ["HostsFileEditor archive: evening", "HostsFileEditor archive: morning"],
        )
        self.assertEqual(records[0]["lines"], ["0.0.0.0 evening.example"])
        self.assertEqual(records[1]["lines"], ["# saved", "0.0.0.0 morning.example"])

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

    # ---- v2.17+: Windows DNS Client Operational events ----
    def test_parse_windows_dns_client_events_xml_extracts_query_names(self):
        xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-DNS-Client" />
            <Computer>workstation.example.local</Computer>
          </System>
          <EventData>
            <Data Name="QueryName">Ads.Example.COM.</Data>
            <Data Name="QueryType">1</Data>
          </EventData>
        </Event>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <UserData>
            <DnsQuery>
              <QueryName>tracker.example</QueryName>
            </DnsQuery>
          </UserData>
        </Event>
        """

        domains = parse_windows_dns_client_events_xml(xml)

        self.assertEqual(domains, ["ads.example.com", "tracker.example"])

    def test_parse_windows_dns_client_events_xml_rejects_malformed_xml(self):
        with self.assertRaises(ValueError):
            parse_windows_dns_client_events_xml("<Event><EventData>")

    def test_windows_dns_client_wevtutil_command_is_bounded(self):
        command = build_windows_dns_client_wevtutil_command(999999)

        self.assertIn("wevtutil", command[0])
        self.assertIn("/rd:true", command)
        self.assertIn("/f:xml", command)
        self.assertIn("/c:5000", command)

    def test_collect_recent_windows_dns_client_queries_uses_runner(self):
        calls = []

        class Completed:
            returncode = 0
            stdout = (
                '<Event><EventData>'
                '<Data Name="QueryName">observed.example</Data>'
                '</EventData></Event>'
            )
            stderr = ""

        def fake_runner(command, **kwargs):
            calls.append((command, kwargs))
            return Completed()

        domains = collect_recent_windows_dns_client_queries(max_events=3, runner=fake_runner)

        self.assertEqual(domains, ["observed.example"])
        self.assertIn("/c:3", calls[0][0])
        self.assertTrue(calls[0][1]["capture_output"])

    def test_collect_recent_windows_dns_client_queries_reports_runner_failure(self):
        class Completed:
            returncode = 5
            stdout = ""
            stderr = "The specified channel could not be found."

        with self.assertRaises(RuntimeError) as ctx:
            collect_recent_windows_dns_client_queries(runner=lambda *_args, **_kwargs: Completed())

        self.assertIn("channel", str(ctx.exception))

    # ---- v2.17+: DNS bypass diagnostics ----
    def test_collect_dns_bypass_policy_snapshot_reads_known_policy_values(self):
        values = {
            ("HKCU", r"Software\Policies\Google\Chrome", "DnsOverHttpsMode"): "secure",
            ("HKLM", r"Software\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled"): 1,
        }

        def fake_reader(root, path, name):
            return values.get((root, path, name))

        snapshot = collect_dns_bypass_policy_snapshot(reader=fake_reader)

        self.assertEqual(len(snapshot), 2)
        self.assertEqual(snapshot[0]["browser"], "Chrome")
        self.assertEqual(snapshot[0]["value"], "secure")
        self.assertEqual(snapshot[1]["browser"], "Firefox")
        self.assertEqual(snapshot[1]["value"], "1")

    def test_dns_bypass_policy_status_classifies_common_values(self):
        self.assertIn("enabled", dns_bypass_policy_status("DnsOverHttpsMode", "secure"))
        self.assertIn("disabled", dns_bypass_policy_status("DnsOverHttpsMode", "off"))
        self.assertIn("custom encrypted DNS endpoint", dns_bypass_policy_status("ProviderURL", "https://dns.example/dns-query"))

    def test_format_dns_bypass_diagnostics_includes_policy_and_proxy_signals(self):
        report = format_dns_bypass_diagnostics(
            [
                {
                    "browser": "Chrome",
                    "scope": "HKCU",
                    "path": r"Software\Policies\Google\Chrome",
                    "name": "DnsOverHttpsMode",
                    "value": "secure",
                }
            ],
            env={"HTTPS_PROXY": "http://proxy.example:8080"},
        )

        self.assertIn("Chrome HKCU DnsOverHttpsMode=secure", report)
        self.assertIn("HTTPS_PROXY is set", report)
        self.assertIn("Hosts entries affect", report)

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

    # ---- v2.17: per-category stats heuristic ----
    def test_categorize_entries_by_domain_hint_buckets_correctly(self):
        lines = [
            "0.0.0.0 doubleclick.net",
            "0.0.0.0 ads.example",
            "0.0.0.0 google-analytics.com",
            "0.0.0.0 telemetry.microsoft.com",
            "0.0.0.0 malware.example",
            "0.0.0.0 phishing.example",
            "0.0.0.0 crypto-miner.example",
            "0.0.0.0 facebook.com",
            "0.0.0.0 lanhost.example",       # falls to 'other'
            "192.168.1.10 printer",          # custom mapping, ignored
            "# comment",                      # ignored
        ]
        counts = categorize_entries_by_domain_hint(lines)
        self.assertGreaterEqual(counts["ads"], 2)
        self.assertGreaterEqual(counts["tracking"], 1)  # analytics + telemetry
        self.assertGreaterEqual(counts["malware"], 2)  # malware + phishing
        self.assertGreaterEqual(counts["crypto"], 1)
        self.assertGreaterEqual(counts["social"], 1)
        self.assertGreaterEqual(counts["other"], 1)
        # Custom IP mapping (192.168.1.10 printer) must not appear in any
        # bucket — only the 9 blocking domains should be counted.
        total = sum(counts.values())
        self.assertEqual(total, 9)

    def test_categorize_entries_dedupes_repeated_domains(self):
        lines = [
            "0.0.0.0 ads.example",
            "0.0.0.0 ads.example",
            "0.0.0.0 ads.example",
        ]
        counts = categorize_entries_by_domain_hint(lines)
        self.assertEqual(counts["ads"], 1)

    def test_domain_category_rules_keywords_are_lowercase(self):
        # Guard rule: all keywords must be lowercase because the matcher
        # compares against a lowercased domain.
        for _, keywords in DOMAIN_CATEGORY_RULES:
            for kw in keywords:
                self.assertEqual(kw, kw.lower(), f"{kw!r} must be lowercase")

    # ---- v2.17: provenance sidecar ----
    def test_provenance_roundtrip_records_valid_events(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.jsonl")
            append_provenance_event(log_path, {"kind": "pin", "domain": "ads.example"})
            append_provenance_event(log_path, {"kind": "unpin", "domain": "ads.example"})
            append_provenance_event(log_path, {"kind": "whitelist_add", "domain": "x.example", "source": "ui"})
            # Unknown kind is silently dropped, not exploded.
            append_provenance_event(log_path, {"kind": "bogus", "domain": "ignored.example"})

            events = read_provenance_events(log_path)
            self.assertEqual(len(events), 3)
            kinds = [e["kind"] for e in events]
            self.assertEqual(kinds, ["pin", "unpin", "whitelist_add"])
            # Schema adds ts, kind, user, app_version.
            for event in events:
                self.assertIn("ts", event)
                self.assertIn("kind", event)
                self.assertIn("app_version", event)

    def test_provenance_event_kinds_guarded(self):
        self.assertIn("pin", PROVENANCE_EVENT_KINDS)
        self.assertIn("unpin", PROVENANCE_EVENT_KINDS)
        self.assertIn("whitelist_add", PROVENANCE_EVENT_KINDS)
        self.assertIn("whitelist_remove", PROVENANCE_EVENT_KINDS)

    def test_provenance_read_tolerates_bad_lines(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            log_path.write_text(
                '\n'.join([
                    '{"kind":"pin","domain":"ok.example","ts":"2026-04-18T10:00:00"}',
                    'not json at all',
                    '{"kind":"bogus","domain":"filtered.example","ts":"2026-04-18T10:01:00"}',
                    '{"kind":"unpin","domain":"still-ok.example","ts":"2026-04-18T10:02:00"}',
                ]),
                encoding="utf-8",
            )
            events = read_provenance_events(str(log_path))
            kinds = [e.get("kind") for e in events]
            self.assertEqual(kinds, ["pin", "unpin"])

    def test_provenance_missing_file_returns_empty_list(self):
        self.assertEqual(read_provenance_events("Z:/definitely/not/here.jsonl"), [])

    def test_filter_provenance_events_matches_kind_domain_source_and_date(self):
        events = [
            {
                "ts": "2026-04-18T09:00:00",
                "kind": "pin",
                "domain": "ads.example",
                "source": "context-menu",
                "user": "alice",
            },
            {
                "ts": "2026-04-19T10:15:00",
                "kind": "whitelist_add",
                "domains": ["tracker.example", "cdn.tracker.example"],
                "source": "triage",
                "user": "bob",
                "note": "approved ticket 42",
            },
            {
                "ts": "2026-04-20T08:00:00",
                "kind": "whitelist_remove",
                "domain": "tracker.example",
                "source": "preferences",
                "user": "bob",
            },
        ]

        matched = filter_provenance_events(
            events,
            kind="whitelist_add",
            domain="tracker.example",
            source="triage",
            since="2026-04-19",
            until="2026-04-19",
        )

        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["note"], "approved ticket 42")

    def test_filter_provenance_events_handles_invalid_kind_text_and_limit(self):
        events = [
            {"ts": "2026-04-18T09:00:00", "kind": "pin", "domain": "one.example", "note": "alpha"},
            {"ts": "2026-04-18T09:01:00", "kind": "unpin", "domain": "two.example", "note": "beta"},
            {"ts": "2026-04-18T09:02:00", "kind": "pin", "domain": "three.example", "note": "alpha"},
        ]

        self.assertEqual(filter_provenance_events(events, kind="bogus"), [])
        limited = filter_provenance_events(events, text="alpha", limit=1)
        self.assertEqual([event["domain"] for event in limited], ["three.example"])

    def test_build_and_format_provenance_log_report_summarizes_filtered_events(self):
        events = [
            {"ts": "2026-04-18T09:00:00", "kind": "pin", "domain": "one.example", "source": "context"},
            {"ts": "2026-04-18T09:01:00", "kind": "pin", "domain": "two.example", "source": "context"},
            {"ts": "2026-04-18T09:02:00", "kind": "unpin", "domain": "three.example", "source": "context"},
        ]

        report = build_provenance_log_report(events, {"kind": "pin"}, display_limit=1)
        self.assertEqual(report["total_events"], 3)
        self.assertEqual(report["matched_count"], 2)
        self.assertEqual(report["displayed_count"], 1)
        self.assertEqual(report["kind_counts"]["pin"], 2)
        formatted = format_provenance_log_report(report)
        self.assertIn("Matched events: 2", formatted)
        self.assertIn("Export includes all matching events", formatted)
        self.assertIn("two.example", formatted)
        self.assertNotIn("one.example", formatted)

    def test_export_provenance_events_supports_json_jsonl_and_csv(self):
        events = [
            {
                "ts": "2026-04-18T09:00:00",
                "kind": "pin",
                "domain": "ads.example",
                "domains": ["ads.example", "cdn.ads.example"],
                "source": "context-menu",
                "user": "alice",
            }
        ]

        json_payload = json.loads(export_provenance_events(events, "json"))
        self.assertEqual(json_payload["schema"], "hostsfileget.provenance-export.v1")
        self.assertEqual(json_payload["event_count"], 1)
        jsonl_payload = export_provenance_events(events, "jsonl")
        self.assertEqual(json.loads(jsonl_payload)["domain"], "ads.example")
        csv_rows = list(csv.DictReader(io.StringIO(export_provenance_events(events, "csv"))))
        self.assertEqual(csv_rows[0]["domain"], "ads.example")
        self.assertIn("cdn.ads.example", csv_rows[0]["domains"])
        with self.assertRaises(ValueError):
            export_provenance_events(events, "xlsx")

    # ---- v2.17: lock_after_save config ----
    def test_sanitize_config_snapshot_persists_lock_after_save(self):
        on = sanitize_config_snapshot({"lock_after_save": True}, os.path.expanduser("~"))
        off = sanitize_config_snapshot({}, os.path.expanduser("~"))
        self.assertTrue(on["lock_after_save"])
        self.assertFalse(off["lock_after_save"])

    def test_sanitize_config_snapshot_persists_update_on_launch(self):
        truthy = sanitize_config_snapshot({"update_on_launch": True}, os.path.expanduser("~"))
        falsy = sanitize_config_snapshot({"update_on_launch": "off"}, os.path.expanduser("~"))
        self.assertTrue(truthy["update_on_launch"])
        # Non-empty string is truthy under bool() — that's the intended shape.
        self.assertTrue(falsy["update_on_launch"])
        default = sanitize_config_snapshot({}, os.path.expanduser("~"))
        self.assertFalse(default["update_on_launch"])

    # ---- v2.21: filter builder and query history ----
    def test_sanitize_filter_query_history_dedupes_and_caps(self):
        history = sanitize_filter_query_history(
            [
                " domain:ads.example ",
                "DOMAIN:ADS.example",
                "line:foo\nbar",
                "",
                None,
                "source:hagezi",
            ],
            max_items=3,
        )
        self.assertEqual(history, ["domain:ads.example", "line:foo bar", "source:hagezi"])

    def test_record_filter_query_history_promotes_recent_query(self):
        history = record_filter_query_history(
            ["line:ads", "source:hagezi", "domain:old.example"],
            " SOURCE:hagezi ",
            max_items=3,
        )
        self.assertEqual(history, ["SOURCE:hagezi", "line:ads", "domain:old.example"])

    def test_sanitize_config_snapshot_persists_filter_query_history(self):
        snapshot = sanitize_config_snapshot(
            {"filter_query_history": ["line:ads", "LINE:ads", "history:foo\tbar"]},
            os.path.expanduser("~"),
        )
        self.assertEqual(snapshot["filter_query_history"], ["line:ads", "history:foo bar"])

    def test_build_filter_builder_report_matches_editor_sources_and_history(self):
        report = build_filter_builder_report(
            "domain:example.com source:hagezi",
            editor_lines=[
                "0.0.0.0 ads.example.com",
                "127.0.0.1 localhost",
                "# comment",
            ],
            source_corpus={
                "hagezi": {
                    "name": "HaGeZi Pro",
                    "url": "https://example.test/hagezi.txt",
                    "text": "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example",
                }
            },
            blocklist_sources={
                "Ads and trackers": [
                    ("HaGeZi Pro", "https://example.test/hagezi.txt", "privacy and tracker source")
                ]
            },
            query_history=["domain:ads.example.com", "source:oisd"],
        )
        self.assertEqual(report["domain_terms"], ["example.com"])
        self.assertEqual(report["editor_match_count"], 1)
        self.assertEqual(report["editor_matches"][0]["line_no"], 1)
        self.assertGreaterEqual(report["source_match_count"], 1)
        self.assertTrue(any(item["name"] == "HaGeZi Pro" for item in report["source_matches"]))
        self.assertIn("domain:ads.example.com", report["history_matches"])

    def test_format_filter_builder_report_lists_sections(self):
        report = build_filter_builder_report(
            "line:ads",
            editor_lines=["0.0.0.0 ads.example"],
            query_history=["line:ads tracker"],
        )
        text = format_filter_builder_report(report)
        self.assertIn("Filter Builder", text)
        self.assertIn("Editor matches: 1", text)
        self.assertIn("Source matches: 0", text)
        self.assertIn("Boundary: local report only", text)

    # ---- v2.21: watch expressions ----
    def test_sanitize_watch_expressions_accepts_strings_dicts_and_dedupes(self):
        watches = sanitize_watch_expressions(
            [
                " domain:ads.example ",
                {"name": "Ads", "query": "DOMAIN:ADS.example", "enabled": False},
                {"name": "Telemetry\nWatch", "query": "line:telemetry"},
                {"name": "", "expression": "source:hagezi"},
                {"query": ""},
                object(),
            ],
            max_items=3,
        )

        self.assertEqual(
            watches,
            [
                {"name": "domain:ads.example", "query": "domain:ads.example", "enabled": True},
                {"name": "Telemetry Watch", "query": "line:telemetry", "enabled": True},
                {"name": "source:hagezi", "query": "source:hagezi", "enabled": True},
            ],
        )

    def test_upsert_and_remove_watch_expression_are_deterministic(self):
        watches = upsert_watch_expression([], "line:ads", "Ads")
        watches = upsert_watch_expression(watches, "source:hagezi", "HaGeZi", enabled=False)
        self.assertEqual([watch["name"] for watch in watches], ["HaGeZi", "Ads"])
        watches = upsert_watch_expression(watches, "line:tracker", "Tracking", index=1)
        self.assertEqual([watch["query"] for watch in watches], ["source:hagezi", "line:tracker"])
        watches = remove_watch_expression(watches, 0)
        self.assertEqual([watch["query"] for watch in watches], ["line:tracker"])

    def test_sanitize_config_snapshot_persists_watch_expressions(self):
        snapshot = sanitize_config_snapshot(
            {
                "watch_expressions": [
                    {"name": "Ads", "query": "line:ads", "enabled": True},
                    {"name": "Duplicate", "query": "LINE:ads", "enabled": False},
                    {"name": "Source", "query": "source:hagezi"},
                ]
            },
            os.path.expanduser("~"),
        )
        self.assertEqual(
            snapshot["watch_expressions"],
            [
                {"name": "Ads", "query": "line:ads", "enabled": True},
                {"name": "Source", "query": "source:hagezi", "enabled": True},
            ],
        )

    def test_build_watch_expression_report_uses_filter_builder_matches(self):
        report = build_watch_expression_report(
            [
                {"name": "Ads", "query": "domain:ads.example", "enabled": True},
                {"name": "Disabled", "query": "line:tracker", "enabled": False},
            ],
            editor_lines=["0.0.0.0 ads.example", "0.0.0.0 other.example"],
            source_corpus={
                "hagezi": {
                    "name": "HaGeZi",
                    "url": "https://example.test/hosts.txt",
                    "text": "0.0.0.0 cdn.ads.example",
                }
            },
            blocklist_sources={},
        )

        self.assertEqual(report["watch_count"], 2)
        self.assertEqual(report["enabled_count"], 1)
        self.assertEqual(report["triggered_count"], 1)
        self.assertEqual(report["watches"][0]["editor_match_count"], 1)
        self.assertEqual(report["watches"][0]["source_match_count"], 1)
        self.assertIn("Watch is disabled.", report["watches"][1]["warnings"])

    def test_format_watch_expression_report_lists_triggered_and_boundary(self):
        report = build_watch_expression_report(
            [{"name": "Ads", "query": "line:ads"}],
            editor_lines=["0.0.0.0 ads.example"],
        )
        text = format_watch_expression_report(report)
        self.assertIn("Watch Expressions", text)
        self.assertIn("Triggered: 1", text)
        self.assertIn("Ads [triggered]", text)
        self.assertIn("Boundary: local watch report only", text)


if __name__ == "__main__":
    unittest.main()
