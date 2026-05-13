"""Sibling-temp + ``os.replace`` writes/copies for hosts-file safety.

Every save, backup rotation, and enable/disable transactional handoff
in HostsFileGet flows through these helpers so a torn write can never
leave the active hosts file or its ``.bak`` companion in a half-written
state. All helpers are pure-stdlib and GUI-free; they are unit-tested
in ``tests/test_hosts_editor_logic.py``.
"""

from __future__ import annotations

import os
import shutil
import tempfile


def write_text_file_atomic(path: str, content: str) -> None:
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(prefix="hosts_editor_", suffix=".tmp", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
            # Ensure a trailing newline. Some POSIX-style tools that consume
            # the hosts file expect one, and hash comparisons here go through
            # splitlines so an added terminator doesn't change equality.
            if content and not content.endswith("\n"):
                f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise


def write_bytes_file_atomic(path: str, content: bytes) -> None:
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(prefix="hosts_editor_", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise


def _allocate_unique_sibling_temp_path(target_path: str, suffix: str) -> str:
    """Reserve a unique temp path next to ``target_path`` and return it."""
    directory = os.path.dirname(target_path) or "."
    prefix = os.path.basename(target_path) + "."
    fd, temp_path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=directory)
    os.close(fd)
    try:
        os.unlink(temp_path)
    except OSError:
        pass
    return temp_path


def copy_file_atomic(source_path: str, target_path: str) -> None:
    """Copy ``source_path`` to ``target_path`` via a sibling temp + os.replace.

    The naive ``shutil.copy2(src, dst)`` writes directly into ``dst`` and can
    leave a half-written, corrupted file if the process is killed or the disk
    fills mid-copy. This matters in particular for the system hosts file and
    its ``.bak`` companions, where a torn write can wedge networking on next
    boot. We stage into a unique sibling temp file, fsync the bytes, then
    rename — which is atomic on POSIX and atomic-equivalent on NTFS.
    """
    directory = os.path.dirname(target_path) or "."
    fd, temp_path = tempfile.mkstemp(prefix="hosts_editor_atomic_", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as dst_f:
            with open(source_path, "rb") as src_f:
                while True:
                    chunk = src_f.read(64 * 1024)
                    if not chunk:
                        break
                    dst_f.write(chunk)
            dst_f.flush()
            os.fsync(dst_f.fileno())
        # Preserve metadata so timestamps/perms continue to match what
        # shutil.copy2 used to provide.
        try:
            shutil.copystat(source_path, temp_path)
        except OSError:
            pass
        os.replace(temp_path, target_path)
    except Exception:
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError:
            pass
        raise


def disable_hosts_file_transactionally(
    hosts_path: str, disabled_path: str, minimal_content: str
) -> None:
    """Disable the hosts file without leaving a stale disabled marker on failure."""
    had_existing_hosts = os.path.exists(hosts_path)
    staged_disabled_path = None

    try:
        if had_existing_hosts:
            staged_disabled_path = _allocate_unique_sibling_temp_path(disabled_path, ".pending")
            copy_file_atomic(hosts_path, staged_disabled_path)

        write_text_file_atomic(hosts_path, minimal_content)

        if staged_disabled_path:
            os.replace(staged_disabled_path, disabled_path)
    except Exception:
        if staged_disabled_path and os.path.exists(staged_disabled_path):
            if had_existing_hosts:
                try:
                    copy_file_atomic(staged_disabled_path, hosts_path)
                except OSError:
                    pass
            try:
                os.unlink(staged_disabled_path)
            except OSError:
                pass
        raise


def enable_hosts_file_transactionally(hosts_path: str, disabled_path: str) -> None:
    """Re-enable the hosts file without leaving ``.disabled`` behind on success."""
    staged_restore_path = _allocate_unique_sibling_temp_path(disabled_path, ".restore")
    os.replace(disabled_path, staged_restore_path)

    try:
        # Atomic copy: a partial write to hosts_path would leave the OS
        # resolver pointing at half-written content until the next save.
        copy_file_atomic(staged_restore_path, hosts_path)
        try:
            os.unlink(staged_restore_path)
        except OSError:
            pass
    except Exception:
        if os.path.exists(staged_restore_path) and not os.path.exists(disabled_path):
            try:
                os.replace(staged_restore_path, disabled_path)
            except OSError:
                pass
        raise


__all__ = [
    "write_text_file_atomic",
    "write_bytes_file_atomic",
    "_allocate_unique_sibling_temp_path",
    "copy_file_atomic",
    "disable_hosts_file_transactionally",
    "enable_hosts_file_transactionally",
]
