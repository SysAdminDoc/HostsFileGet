"""Internal package for HostsFileGet.

The application started as a single ``hosts_editor.py`` file. Logic is being
progressively extracted into focused submodules under this package so the
monolith shrinks in safe, test-verified phases. ``hosts_editor.py`` remains
the CLI entry point and re-exports the public surface, so existing imports
(both from tests and from external consumers like the launcher) keep working.

Phase 1 extractions (v2.24.0):
    - :mod:`hostsfileget.compression` — gzip/bz2 streaming bomb guard,
      byte->text decoding, HTML-document detection.
    - :mod:`hostsfileget.atomic_io` — sibling-temp + ``os.replace`` writes
      and copies used by hosts-file save, backup rotation, and enable/disable
      transactional handoff.

Phase 2 extractions (v2.25.0):
    - :mod:`hostsfileget.parsing` — leaf-level domain/IP regex, ``looks_like_domain``,
      ``_extract_domain_from_token``, ``_normalize_mapping_ip``, and the IDN
      encoding/decoding primitives that every higher-level parser uses.
    - :mod:`hostsfileget.theme` — ``PALETTE``, the WCAG contrast helpers, and
      the accessibility audit report builder/formatter.
"""

__all__ = ["compression", "atomic_io", "parsing", "theme"]
