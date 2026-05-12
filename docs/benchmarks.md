# Benchmarks

HostsFileGet includes a deterministic large-file benchmark harness for parser and cleaned-save paths.

Run it from the repository root:

```powershell
python benchmarks\large_file_benchmark.py --entries 100000 --repeats 3 --json-output benchmark-report.json
```

The fixture intentionally mixes comments, blanks, duplicate blocks, URLs, Adblock-style rules, dnsmasq-style rules, custom mappings, whitelist entries, and synthetic pinned domains. This keeps benchmark runs close to real imported blocklist workloads without requiring a checked-in huge hosts file.

The benchmark reports:

- all-line normalization time
- canonical cleaned-output time
- blocking-domain extraction time
- category-count heuristic time
- cleaned-output stats such as `final_active`, `total_discarded`, `transformed`, and `pinned_preserved`

Use `--max-clean-seconds <seconds>` only for local regression checks where the hardware is known. CI runs the benchmark smoke test but does not enforce timing budgets.
