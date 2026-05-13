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
"""

__all__ = ["compression", "atomic_io"]
