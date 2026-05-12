import unittest

from benchmarks.large_file_benchmark import (
    format_benchmark_report,
    generate_large_hosts_fixture,
    run_large_file_benchmark,
)


class LargeFileBenchmarkTests(unittest.TestCase):
    def test_large_file_benchmark_smoke(self):
        fixture = generate_large_hosts_fixture(250)
        self.assertEqual(len(fixture["lines"]), 250)
        self.assertGreater(len(fixture["whitelist"]), 0)
        self.assertGreater(len(fixture["pinned_domains"]), 0)

        report = run_large_file_benchmark(entry_count=250, repeats=1)

        self.assertEqual(report["entry_count"], 250)
        self.assertIn("clean", report["operations"])
        self.assertIn("normalize_all_lines", report["operations"])
        self.assertGreaterEqual(report["clean_stats"]["final_active"], 1)
        self.assertGreaterEqual(report["clean_stats"]["total_discarded"], 0)
        self.assertIn("Large-file benchmark", format_benchmark_report(report))


if __name__ == "__main__":
    unittest.main()
