"""Shared cross-module constants.

A handful of identifiers need to be visible to multiple submodules
(``compression`` re-uses ``MAX_DOWNLOAD_BYTES`` internally, ``fetch``
needs ``APP_SLUG``/``APP_VERSION`` for its ``User-Agent`` header,
``hosts_editor`` exposes them as the canonical public values) without
introducing a circular import via ``hosts_editor``. Keeping them in a
single tiny module avoids that whole class of problem.

The values must stay in sync with the rest of the project — see the
"Release vX.Y.Z" recipe in the repo's working notes for the update
checklist.
"""

from __future__ import annotations


APP_NAME = "Hosts File Get"
APP_SLUG = "HostsFileGet"
APP_VERSION = "2.27.0"
CONFIG_FILENAME = "hosts_editor_config.json"


__all__ = ["APP_NAME", "APP_SLUG", "APP_VERSION", "CONFIG_FILENAME"]
