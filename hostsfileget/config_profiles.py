"""Config, profile, and portable-mode helpers for HostsFileGet.

This module holds pure config/profile behavior that used to live in
``hosts_editor.py``. It deliberately has no Tkinter dependency so CLI,
unit-test, and future UI surfaces can share the same schema migration,
profile switching, and import/export rules.
"""

from __future__ import annotations

import datetime
import hashlib
import importlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback path
    tomllib = None

from hostsfileget.atomic_io import write_text_file_atomic
from hostsfileget.compression import MAX_DOWNLOAD_BYTES, read_text_file_content
from hostsfileget.constants import APP_SLUG, APP_VERSION, CONFIG_FILENAME
from hostsfileget.fetch import (
    _contains_control_chars,
    _parse_valid_http_source_url,
    normalize_custom_source_url,
    sanitize_custom_sources,
    sanitize_source_cache_metadata,
)
from hostsfileget.parsing import looks_like_domain

CONFIG_SCHEMA_VERSION = 4
PROFILE_SCHEMA_VERSION = 1
DEFAULT_PROFILE_ID = "default"
PROFILE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
PROFILE_ACTIVATION_SCHEDULE_VERSION = 1
PROFILE_ACTIVATION_MAX_WINDOWS = 64
PROFILE_ACTIVATION_WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
PROFILE_ACTIVATION_DAY_ALIASES = {
    "m": "mon",
    "mo": "mon",
    "mon": "mon",
    "monday": "mon",
    "t": "tue",
    "tu": "tue",
    "tue": "tue",
    "tues": "tue",
    "tuesday": "tue",
    "w": "wed",
    "we": "wed",
    "wed": "wed",
    "wednesday": "wed",
    "th": "thu",
    "thu": "thu",
    "thur": "thu",
    "thurs": "thu",
    "thursday": "thu",
    "f": "fri",
    "fr": "fri",
    "fri": "fri",
    "friday": "fri",
    "sa": "sat",
    "sat": "sat",
    "saturday": "sat",
    "su": "sun",
    "sun": "sun",
    "sunday": "sun",
}
PROFILE_ACTIVATION_DAY_GROUPS = {
    "daily": PROFILE_ACTIVATION_WEEKDAYS,
    "all": PROFILE_ACTIVATION_WEEKDAYS,
    "everyday": PROFILE_ACTIVATION_WEEKDAYS,
    "weekdays": ("mon", "tue", "wed", "thu", "fri"),
    "weekday": ("mon", "tue", "wed", "thu", "fri"),
    "workdays": ("mon", "tue", "wed", "thu", "fri"),
    "weekends": ("sat", "sun"),
    "weekend": ("sat", "sun"),
}
DECLARATIVE_CONFIG_SCHEMA = "hostsfileget.declarative.v1"
DECLARATIVE_CONFIG_FORMATS = {"json", "yaml", "toml"}
DECLARATIVE_CONFIG_EXTENSION_FORMATS = {
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
}
SOURCE_CACHE_DIRNAME = "source_cache"
GIT_HISTORY_DIRNAME = "hosts_history_git"
GIT_HISTORY_REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,127}$")
CLI_LOG_FILENAME = "cli.log"
CLI_ACTIVITY_FILENAME = "cli-activity.jsonl"
PORTABLE_BUNDLE_README_FILENAME = "HOSTSFILEGET_PORTABLE.md"
BACKUP_RETENTION = 5
SOURCE_METRICS_HISTORY_MAX_SOURCES = 200
SOURCE_METRICS_HISTORY_MAX_POINTS = 30
FILTER_QUERY_HISTORY_MAX_ITEMS = 25
FILTER_QUERY_MAX_LENGTH = 240
WATCH_EXPRESSIONS_MAX_ITEMS = 50
WATCH_EXPRESSION_NAME_MAX_LENGTH = 80
BLOCK_SINK_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}
PROFILE_SYNC_PAYLOAD_SCHEMA = "hostsfileget.profile-sync.v1"
PROFILE_SYNC_METADATA_SCHEMA = "hostsfileget.profile-sync-metadata.v1"
PROFILE_SYNC_GIT_DIRNAME = "profile_sync_git"
PROFILE_SYNC_BUNDLE_FILENAME = "hostsfileget-profile-sync.json.gpg"
PROFILE_SYNC_METADATA_FILENAME = "hostsfileget-profile-sync.metadata.json"
PROFILE_SYNC_PASSPHRASE_ENV = "HOSTSFILEGET_SYNC_PASSPHRASE"
PROFILE_SYNC_MIN_PASSPHRASE_LENGTH = 16
PROFILE_SYNC_ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
SHARE_PATCH_SCHEMA = "hostsfileget.share-patch.v1"
SHARE_PATCH_TYPES = ("allowlist", "profile")

if getattr(sys, "frozen", False):
    _EXE_DIR = os.path.dirname(sys.executable)
else:
    _EXE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sanitize_pinned_domains(value) -> list[str]:
    """Return a deduplicated, lowercase list of valid domain strings.

    Pinned entries are persisted in config. We accept raw domains only
    (not full hosts lines) to keep the stored shape simple. Invalid
    entries are dropped silently so a hand-edited config can't poison
    the list.
    """
    if not isinstance(value, (list, tuple, set)):
        return []
    seen: set[str] = set()
    pinned: list[str] = []
    for candidate in value:
        if not isinstance(candidate, str):
            continue
        normalized = candidate.strip().lower().lstrip('.')
        if not normalized or normalized in seen:
            continue
        if not looks_like_domain(normalized, allow_single_label=False):
            continue
        seen.add(normalized)
        pinned.append(normalized)
    return pinned

def _sanitize_source_metric_text(value, max_length: int = 160) -> str:
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").replace("\t", " ").split())[:max_length]


def _source_metric_epoch(value) -> float | None:
    text = _sanitize_source_metric_text(value, 80)
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(text)
        return parsed.timestamp()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _source_metric_int(value, default: int = 0, upper: int = 100_000_000) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(0, min(upper, number))


def sanitize_source_metrics_history(
    history,
    *,
    max_sources: int = SOURCE_METRICS_HISTORY_MAX_SOURCES,
    max_points: int = SOURCE_METRICS_HISTORY_MAX_POINTS,
) -> dict[str, list[dict]]:
    """Sanitize compact per-source freshness/growth history."""
    try:
        source_limit = max(0, min(int(max_sources), SOURCE_METRICS_HISTORY_MAX_SOURCES))
    except (TypeError, ValueError):
        source_limit = SOURCE_METRICS_HISTORY_MAX_SOURCES
    try:
        point_limit = max(0, min(int(max_points), SOURCE_METRICS_HISTORY_MAX_POINTS))
    except (TypeError, ValueError):
        point_limit = SOURCE_METRICS_HISTORY_MAX_POINTS
    if source_limit == 0 or point_limit == 0 or not isinstance(history, dict):
        return {}

    sanitized_rows: list[tuple[float, str, list[dict]]] = []
    for raw_url, points in history.items():
        if not isinstance(raw_url, str):
            continue
        url = normalize_custom_source_url(raw_url) or raw_url.strip()
        if _parse_valid_http_source_url(url) is None or not isinstance(points, (list, tuple)):
            continue
        clean_points = []
        for point in points:
            if not isinstance(point, dict):
                continue
            ts = _sanitize_source_metric_text(point.get("ts"), 80)
            epoch = _source_metric_epoch(ts)
            if epoch is None:
                continue
            clean_points.append({
                "ts": ts,
                "name": _sanitize_source_metric_text(point.get("name"), 120),
                "domain_count": _source_metric_int(point.get("domain_count")),
                "line_count": _source_metric_int(point.get("line_count")),
                "bytes": _source_metric_int(point.get("bytes"), upper=MAX_DOWNLOAD_BYTES),
                "cache_status": _sanitize_source_metric_text(point.get("cache_status"), 40),
            })
        if not clean_points:
            continue
        clean_points.sort(key=lambda row: _source_metric_epoch(row.get("ts")) or 0.0)
        clean_points = clean_points[-point_limit:]
        sanitized_rows.append((_source_metric_epoch(clean_points[-1].get("ts")) or 0.0, url, clean_points))

    sanitized_rows.sort(key=lambda row: (-row[0], row[1]))
    return {url: points for _epoch, url, points in sanitized_rows[:source_limit]}

def _normalize_filter_query_text(value: str) -> str:
    candidate = str(value or "").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    candidate = " ".join(candidate.split())
    return candidate[:FILTER_QUERY_MAX_LENGTH]


def sanitize_filter_query_history(history, max_items: int = FILTER_QUERY_HISTORY_MAX_ITEMS) -> list[str]:
    """Return recent filter-builder queries in deterministic, safe display order."""
    try:
        limit = int(max_items)
    except (TypeError, ValueError):
        limit = FILTER_QUERY_HISTORY_MAX_ITEMS
    limit = max(0, min(limit, FILTER_QUERY_HISTORY_MAX_ITEMS))
    if limit == 0 or not isinstance(history, (list, tuple)):
        return []

    sanitized: list[str] = []
    seen: set[str] = set()
    for item in history:
        if not isinstance(item, str):
            continue
        query = _normalize_filter_query_text(item)
        if not query:
            continue
        key = query.casefold()
        if key in seen:
            continue
        seen.add(key)
        sanitized.append(query)
        if len(sanitized) >= limit:
            break
    return sanitized


def record_filter_query_history(
    history,
    query: str,
    max_items: int = FILTER_QUERY_HISTORY_MAX_ITEMS,
) -> list[str]:
    """Move ``query`` to the front of filter-builder history if it is valid."""
    try:
        limit = int(max_items)
    except (TypeError, ValueError):
        limit = FILTER_QUERY_HISTORY_MAX_ITEMS
    limit = max(0, min(limit, FILTER_QUERY_HISTORY_MAX_ITEMS))
    current = sanitize_filter_query_history(history, max_items=limit)
    normalized = _normalize_filter_query_text(query)
    if not normalized or limit == 0:
        return current
    key = normalized.casefold()
    return [normalized] + [item for item in current if item.casefold() != key][: max(0, limit - 1)]


def _normalize_watch_expression_name(value: str, fallback: str = "") -> str:
    name = _normalize_filter_query_text(value)[:WATCH_EXPRESSION_NAME_MAX_LENGTH]
    if name:
        return name
    fallback_name = _normalize_filter_query_text(fallback)[:WATCH_EXPRESSION_NAME_MAX_LENGTH]
    return fallback_name or "Watch expression"


def sanitize_watch_expressions(watches, max_items: int = WATCH_EXPRESSIONS_MAX_ITEMS) -> list[dict]:
    """Return app-level watch expressions in safe, deterministic order."""
    try:
        limit = int(max_items)
    except (TypeError, ValueError):
        limit = WATCH_EXPRESSIONS_MAX_ITEMS
    limit = max(0, min(limit, WATCH_EXPRESSIONS_MAX_ITEMS))
    if limit == 0 or not isinstance(watches, (list, tuple)):
        return []

    sanitized: list[dict] = []
    seen_queries: set[str] = set()
    for item in watches:
        if isinstance(item, str):
            query = _normalize_filter_query_text(item)
            name = _normalize_watch_expression_name("", query)
            enabled = True
        elif isinstance(item, dict):
            query = _normalize_filter_query_text(item.get("query") or item.get("expression") or "")
            name = _normalize_watch_expression_name(item.get("name", ""), query)
            enabled = bool(item.get("enabled", True))
        else:
            continue
        if not query:
            continue
        key = query.casefold()
        if key in seen_queries:
            continue
        seen_queries.add(key)
        sanitized.append({
            "name": name,
            "query": query,
            "enabled": enabled,
        })
        if len(sanitized) >= limit:
            break
    return sanitized


def upsert_watch_expression(
    watches,
    query: str,
    name: str = "",
    *,
    enabled: bool = True,
    index: int | None = None,
    max_items: int = WATCH_EXPRESSIONS_MAX_ITEMS,
) -> list[dict]:
    """Add or replace one watch expression, deduped by query."""
    current = sanitize_watch_expressions(watches, max_items=max_items)
    candidate_rows = sanitize_watch_expressions([{
        "name": name,
        "query": query,
        "enabled": enabled,
    }], max_items=1)
    if not candidate_rows:
        return current
    candidate = candidate_rows[0]

    if isinstance(index, int) and 0 <= index < len(current):
        current[index] = candidate
    else:
        current = [candidate] + [
            item for item in current
            if item.get("query", "").casefold() != candidate["query"].casefold()
        ]
    return sanitize_watch_expressions(current, max_items=max_items)


def remove_watch_expression(watches, index: int) -> list[dict]:
    """Remove a watch expression by display index."""
    current = sanitize_watch_expressions(watches)
    try:
        idx = int(index)
    except (TypeError, ValueError):
        return current
    if 0 <= idx < len(current):
        del current[idx]
    return current

def _portable_config_path_candidate(config_filename: str = CONFIG_FILENAME) -> str:
    """Return the path where a portable-mode config would live.

    Portable mode: if the user ships a ``hosts_editor_config.json`` next to
    the exe / script, we treat that sibling as the live config and skip
    ``%LOCALAPPDATA%`` entirely. Lets USB-stick / team-share deployments
    carry their settings with the binary.
    """
    return os.path.join(_EXE_DIR, config_filename)


def is_portable_mode() -> bool:
    return os.path.isfile(_portable_config_path_candidate())


def get_app_config_dir() -> str:
    if os.name == 'nt':
        base_dir = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base_dir, APP_SLUG)
    return os.path.join(os.path.expanduser("~"), f".{APP_SLUG.lower()}")

def get_primary_config_path(config_filename: str) -> str:
    if is_portable_mode():
        return _portable_config_path_candidate(config_filename)
    return _roaming_config_path(config_filename)


def _roaming_config_path(config_filename: str) -> str:
    return os.path.join(get_app_config_dir(), config_filename)


def get_config_root_dir(config_filename: str = CONFIG_FILENAME) -> str:
    return os.path.dirname(get_primary_config_path(config_filename)) or "."


def get_source_cache_dir() -> str:
    return os.path.join(get_config_root_dir(), SOURCE_CACHE_DIRNAME)


# ``source_cache_key``, ``get_source_cache_body_path``,
# ``prune_orphan_source_cache_files``, ``write_source_cache_body``, and
# ``read_source_cache_body`` now live in ``hostsfileget.fetch``. The
# ``get_source_cache_body_path`` / ``write_source_cache_body`` /
# ``read_source_cache_body`` / ``prune_orphan_source_cache_files`` wrappers
# near the top of this module preserve the legacy "cache_dir defaults to the
# active source cache directory" behaviour for callers that omit it.


def get_git_history_dir(base_dir: str | None = None) -> str:
    root = base_dir or get_config_root_dir()
    return os.path.join(root, GIT_HISTORY_DIRNAME)


def build_config_location_report(config_filename: str = CONFIG_FILENAME) -> dict:
    portable_path = _portable_config_path_candidate(config_filename)
    local_path = _roaming_config_path(config_filename)
    portable_active = os.path.isfile(portable_path)
    active_path = portable_path if portable_active else local_path
    active_root = os.path.dirname(active_path) or "."
    return {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "mode": "portable" if portable_active else "local",
        "reason": (
            "portable config exists beside the executable/script"
            if portable_active
            else "no portable config exists beside the executable/script"
        ),
        "active_config_path": active_path,
        "portable_config_path": portable_path,
        "portable_config_exists": portable_active,
        "local_config_path": local_path,
        "local_config_exists": os.path.isfile(local_path),
        "sidecar_root": active_root,
        "source_cache_dir": os.path.join(active_root, SOURCE_CACHE_DIRNAME),
        "git_history_dir": os.path.join(active_root, GIT_HISTORY_DIRNAME),
        "cli_log_path": os.path.join(active_root, CLI_LOG_FILENAME),
        "cli_activity_path": os.path.join(active_root, CLI_ACTIVITY_FILENAME),
    }


def format_config_location_report(report: dict) -> str:
    return "\n".join([
        "Config Location",
        f"Mode: {report.get('mode', 'unknown')}",
        f"Reason: {report.get('reason') or '-'}",
        f"Active config: {report.get('active_config_path') or '-'}",
        "",
        "Candidates:",
        (
            f"  Portable: {report.get('portable_config_path') or '-'} "
            f"({'exists' if report.get('portable_config_exists') else 'missing'})"
        ),
        (
            f"  Local user: {report.get('local_config_path') or '-'} "
            f"({'exists' if report.get('local_config_exists') else 'missing'})"
        ),
        "",
        "Sidecar paths:",
        f"  Root: {report.get('sidecar_root') or '-'}",
        f"  Source cache: {report.get('source_cache_dir') or '-'}",
        f"  Git history: {report.get('git_history_dir') or '-'}",
        f"  CLI log: {report.get('cli_log_path') or '-'}",
        f"  CLI activity: {report.get('cli_activity_path') or '-'}",
    ])


def build_portable_bundle_readme(config_path: str) -> str:
    return "\n".join([
        "# HostsFileGet Portable Bundle",
        "",
        f"This directory contains `{CONFIG_FILENAME}` for portable mode.",
        "",
        "Portable mode becomes active only when the config file sits beside the executable or script that is launched.",
        f"Config path written: `{config_path}`",
        "",
        "Sidecar files such as source cache, optional Git history, CLI logs, and scheduler activity use the same directory when portable mode is active.",
        "Move or delete the config file to return to the normal per-user config under `%LOCALAPPDATA%\\HostsFileGet`.",
    ]) + "\n"


def write_portable_bundle_config(
    bundle_dir: str,
    config_payload: dict | None,
    default_last_open_dir: str,
    *,
    overwrite: bool = False,
) -> dict:
    if not isinstance(bundle_dir, str) or not bundle_dir.strip():
        raise ValueError("Portable bundle directory is required.")
    target_dir = os.path.abspath(os.path.expanduser(bundle_dir))
    config_path = os.path.join(target_dir, CONFIG_FILENAME)
    readme_path = os.path.join(target_dir, PORTABLE_BUNDLE_README_FILENAME)
    if os.path.exists(config_path) and not overwrite:
        raise FileExistsError(f"Portable config already exists: {config_path}")
    os.makedirs(target_dir, exist_ok=True)
    sanitized = sanitize_config_snapshot(config_payload or {}, default_last_open_dir)
    write_text_file_atomic(config_path, json.dumps(sanitized, indent=2))
    write_text_file_atomic(readme_path, build_portable_bundle_readme(config_path))
    return {
        "bundle_dir": target_dir,
        "config_path": config_path,
        "readme_path": readme_path,
        "profile_count": len(sanitized.get("profiles", [])),
        "active_profile_id": sanitized.get("active_profile_id", DEFAULT_PROFILE_ID),
    }


def format_portable_bundle_export_summary(result: dict) -> str:
    return "\n".join([
        "Portable Bundle Config",
        f"Directory: {result.get('bundle_dir') or '-'}",
        f"Config: {result.get('config_path') or '-'}",
        f"Readme: {result.get('readme_path') or '-'}",
        f"Active profile: {result.get('active_profile_id') or DEFAULT_PROFILE_ID}",
        f"Profiles: {result.get('profile_count', 0)}",
    ])

def resolve_git_executable(git_executable: str | None = None) -> str | None:
    if git_executable:
        return git_executable
    return shutil.which("git")


def sanitize_git_history_ref(ref: str) -> str:
    candidate = str(ref or "").strip()
    if (
        not GIT_HISTORY_REF_PATTERN.match(candidate)
        or ".." in candidate
        or "@{" in candidate
        or "\\" in candidate
        or candidate.startswith("-")
    ):
        raise ValueError("invalid Git history reference")
    return candidate


def _run_git_command(
    repo_dir: str,
    args: list[str],
    git_executable: str | None = None,
    runner=None,
    timeout: int = 15,
    strip_output: bool = True,
) -> str:
    git = resolve_git_executable(git_executable)
    if not git:
        raise OSError("git executable not found")
    run = runner or subprocess.run
    try:
        result = run(
            [git, *args],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise OSError("git executable not found") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise OSError(f"git {' '.join(args)} failed: {detail}")
    output = result.stdout or ""
    return output.strip() if strip_output else output


def ensure_git_history_repo(
    repo_dir: str,
    git_executable: str | None = None,
    runner=None,
) -> str:
    os.makedirs(repo_dir, exist_ok=True)
    git = resolve_git_executable(git_executable)
    if not git:
        raise OSError("git executable not found")
    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        _run_git_command(repo_dir, ["init"], git_executable=git, runner=runner)
    _run_git_command(repo_dir, ["config", "user.name", "HostsFileGet"], git_executable=git, runner=runner)
    _run_git_command(
        repo_dir,
        ["config", "user.email", "hostsfileget@localhost"],
        git_executable=git,
        runner=runner,
    )
    return repo_dir

def _sanitize_whitelist_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, set)):
        return '\n'.join(
            item.strip()
            for item in (str(entry) for entry in value)
            if item.strip()
        )
    return ""


def sanitize_profile_id(value, fallback: str = DEFAULT_PROFILE_ID) -> str:
    candidate = str(value).strip().lower() if isinstance(value, str) else ""
    if PROFILE_ID_PATTERN.match(candidate):
        return candidate

    fallback_candidate = str(fallback).strip().lower() if isinstance(fallback, str) else ""
    if PROFILE_ID_PATTERN.match(fallback_candidate):
        return fallback_candidate

    return DEFAULT_PROFILE_ID


def _sanitize_profile_id_strict(value) -> str:
    candidate = str(value).strip().lower() if isinstance(value, str) else ""
    return candidate if PROFILE_ID_PATTERN.match(candidate) else ""


def _unique_profile_id(profile_id: str, used_ids: set[str]) -> str:
    if profile_id not in used_ids:
        return profile_id

    base = profile_id[:56].rstrip("-_") or DEFAULT_PROFILE_ID
    suffix = 2
    while True:
        suffix_text = f"-{suffix}"
        candidate = f"{base[:64 - len(suffix_text)]}{suffix_text}"
        if candidate not in used_ids:
            return candidate
        suffix += 1


def _profile_name_from_id(profile_id: str) -> str:
    label = profile_id.replace("-", " ").replace("_", " ").strip()
    return label.title() if label else "Default"


def _sanitize_profile_name(value, fallback_id: str) -> str:
    if isinstance(value, str):
        name = re.sub(r"\s+", " ", value.strip())
        if name and not _contains_control_chars(name):
            return name[:80]
    return _profile_name_from_id(fallback_id)


def _profile_preferred_sink(value) -> str:
    return value if value in BLOCK_SINK_IPS else "0.0.0.0"


def build_default_profile_snapshot(config) -> dict:
    if not isinstance(config, dict):
        config = {}
    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "id": DEFAULT_PROFILE_ID,
        "name": "Default",
        "whitelist": _sanitize_whitelist_text(config.get("whitelist", "")),
        "custom_sources": sanitize_custom_sources(config.get("custom_sources", [])),
        "pinned_domains": sanitize_pinned_domains(config.get("pinned_domains", [])),
        "preferred_block_sink": _profile_preferred_sink(config.get("preferred_block_sink", "0.0.0.0")),
    }


def sanitize_profile_snapshot(profile, fallback_id: str = DEFAULT_PROFILE_ID, used_ids: set[str] | None = None) -> dict:
    if not isinstance(profile, dict):
        profile = {}
    used_ids = used_ids if used_ids is not None else set()

    profile_id = sanitize_profile_id(profile.get("id"), fallback_id)
    profile_id = _unique_profile_id(profile_id, used_ids)
    used_ids.add(profile_id)

    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "id": profile_id,
        "name": _sanitize_profile_name(profile.get("name"), profile_id),
        "whitelist": _sanitize_whitelist_text(profile.get("whitelist", "")),
        "custom_sources": sanitize_custom_sources(profile.get("custom_sources", [])),
        "pinned_domains": sanitize_pinned_domains(profile.get("pinned_domains", [])),
        "preferred_block_sink": _profile_preferred_sink(profile.get("preferred_block_sink", "0.0.0.0")),
    }


def _iter_profile_candidates(profiles):
    if isinstance(profiles, list):
        for profile in profiles:
            if isinstance(profile, dict):
                yield profile
        return

    if isinstance(profiles, dict):
        for profile_id, profile in profiles.items():
            if not isinstance(profile, dict):
                continue
            candidate = dict(profile)
            candidate.setdefault("id", profile_id)
            yield candidate


def sanitize_profiles_snapshot(
    profiles,
    active_profile_id: str | None = None,
    fallback_profile: dict | None = None,
) -> tuple[list[dict], str]:
    sanitized_profiles: list[dict] = []
    used_ids: set[str] = set()

    for candidate in _iter_profile_candidates(profiles):
        fallback_id = DEFAULT_PROFILE_ID if not sanitized_profiles else f"profile-{len(sanitized_profiles) + 1}"
        sanitized_profiles.append(
            sanitize_profile_snapshot(candidate, fallback_id=fallback_id, used_ids=used_ids)
        )

    if not sanitized_profiles:
        sanitized_profiles.append(
            sanitize_profile_snapshot(
                fallback_profile or build_default_profile_snapshot({}),
                fallback_id=DEFAULT_PROFILE_ID,
                used_ids=used_ids,
            )
        )

    active_id = sanitize_profile_id(active_profile_id, "")
    profile_ids = {profile["id"] for profile in sanitized_profiles}
    if active_id not in profile_ids:
        active_id = sanitized_profiles[0]["id"]

    return sanitized_profiles, active_id


def update_active_profile_snapshot(
    profiles,
    active_profile_id: str | None,
    current_config: dict,
) -> tuple[list[dict], str]:
    current_profile = build_default_profile_snapshot(current_config)
    sanitized_profiles, active_id = sanitize_profiles_snapshot(
        profiles,
        active_profile_id,
        fallback_profile=current_profile,
    )

    for index, profile in enumerate(sanitized_profiles):
        if profile["id"] != active_id:
            continue
        updated = dict(profile)
        for key in ("whitelist", "custom_sources", "pinned_domains", "preferred_block_sink"):
            updated[key] = current_profile[key]
        sanitized_profiles[index] = updated
        break

    return sanitized_profiles, active_id


def normalize_profile_activation_time(value) -> str:
    if isinstance(value, datetime.time):
        return f"{value.hour:02d}:{value.minute:02d}"
    candidate = str(value or "").strip()
    match = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", candidate)
    if not match:
        raise ValueError("profile activation time must use HH:MM in 24-hour local time")
    hour = int(match.group(1))
    minute = int(match.group(2))
    return f"{hour:02d}:{minute:02d}"


def _profile_activation_minutes(value: str) -> int:
    hour, minute = normalize_profile_activation_time(value).split(":", 1)
    return int(hour) * 60 + int(minute)


def normalize_profile_activation_days(value) -> list[str]:
    if value is None or value == "":
        return list(PROFILE_ACTIVATION_WEEKDAYS)

    if isinstance(value, str):
        candidate = value.strip().lower()
        if candidate in PROFILE_ACTIVATION_DAY_GROUPS:
            return list(PROFILE_ACTIVATION_DAY_GROUPS[candidate])
        parts = [part for part in re.split(r"[\s,;/|]+", candidate) if part]
    elif isinstance(value, (list, tuple, set)):
        parts = []
        for item in value:
            if isinstance(item, str) and item.strip().lower() in PROFILE_ACTIVATION_DAY_GROUPS:
                parts.extend(PROFILE_ACTIVATION_DAY_GROUPS[item.strip().lower()])
            else:
                parts.append(str(item).strip().lower())
    else:
        raise ValueError("profile activation days must be a weekday list or named group")

    normalized: list[str] = []
    for part in parts:
        day = PROFILE_ACTIVATION_DAY_ALIASES.get(part)
        if day is None:
            raise ValueError(f"unsupported profile activation day: {part}")
        if day not in normalized:
            normalized.append(day)

    if not normalized:
        raise ValueError("profile activation days cannot be empty")
    order = {day: index for index, day in enumerate(PROFILE_ACTIVATION_WEEKDAYS)}
    return sorted(normalized, key=order.get)


def parse_profile_activation_when(value) -> datetime.datetime:
    if value is None or value == "":
        return datetime.datetime.now()
    if isinstance(value, datetime.datetime):
        return value
    if isinstance(value, datetime.date):
        return datetime.datetime.combine(value, datetime.time.min)

    candidate = str(value).strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("profile schedule evaluation time must be an ISO local datetime") from exc


def _sanitize_profile_activation_window_id(value, fallback: str, used_ids: set[str] | None = None) -> str:
    candidate = ""
    if isinstance(value, str):
        candidate = re.sub(r"[^a-z0-9_-]+", "-", value.strip().lower()).strip("-_")
    if not candidate:
        candidate = fallback
    window_id = sanitize_profile_id(candidate, fallback)
    if used_ids is None:
        return window_id
    window_id = _unique_profile_id(window_id, used_ids)
    used_ids.add(window_id)
    return window_id


def _coerce_profile_activation_enabled(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        candidate = value.strip().lower()
        if candidate in {"0", "false", "no", "off", "disabled"}:
            return False
        if candidate in {"1", "true", "yes", "on", "enabled"}:
            return True
    return bool(value)


def sanitize_profile_activation_window(
    window,
    valid_profile_ids,
    fallback_index: int = 1,
    used_window_ids: set[str] | None = None,
) -> dict | None:
    if not isinstance(window, dict):
        return None

    valid_ids = {_sanitize_profile_id_strict(profile_id) for profile_id in valid_profile_ids}
    profile_id = _sanitize_profile_id_strict(window.get("profile_id"))
    if profile_id not in valid_ids:
        return None

    try:
        days = normalize_profile_activation_days(window.get("days", "daily"))
        start_time = normalize_profile_activation_time(window.get("start_time"))
        end_time = normalize_profile_activation_time(window.get("end_time"))
    except ValueError:
        return None
    if start_time == end_time:
        return None

    fallback_id = f"schedule-{max(1, fallback_index)}"
    default_id = f"{profile_id}-{'-'.join(days)}-{start_time.replace(':', '')}-{end_time.replace(':', '')}"
    window_id = _sanitize_profile_activation_window_id(
        window.get("id") or default_id,
        fallback_id,
        used_window_ids,
    )
    name = _sanitize_profile_name(
        window.get("name"),
        window_id,
    )

    return {
        "id": window_id,
        "name": name,
        "profile_id": profile_id,
        "days": days,
        "start_time": start_time,
        "end_time": end_time,
        "enabled": _coerce_profile_activation_enabled(window.get("enabled", True)),
    }


def sanitize_profile_activation_schedule(schedule, valid_profile_ids) -> list[dict]:
    if isinstance(schedule, dict):
        schedule = schedule.get("windows", [])
    if not isinstance(schedule, list):
        return []

    sanitized: list[dict] = []
    used_ids: set[str] = set()
    for candidate in schedule:
        window = sanitize_profile_activation_window(
            candidate,
            valid_profile_ids,
            fallback_index=len(sanitized) + 1,
            used_window_ids=used_ids,
        )
        if window is not None:
            sanitized.append(window)
        if len(sanitized) >= PROFILE_ACTIVATION_MAX_WINDOWS:
            break
    return sanitized


def profile_activation_window_matches(window: dict, when) -> bool:
    try:
        evaluated_at = parse_profile_activation_when(when)
        days = normalize_profile_activation_days(window.get("days", []))
        start_minutes = _profile_activation_minutes(window.get("start_time"))
        end_minutes = _profile_activation_minutes(window.get("end_time"))
    except (ValueError, AttributeError):
        return False

    if not _coerce_profile_activation_enabled(window.get("enabled", True)):
        return False

    current_day = PROFILE_ACTIVATION_WEEKDAYS[evaluated_at.weekday()]
    previous_day = PROFILE_ACTIVATION_WEEKDAYS[(evaluated_at.weekday() - 1) % 7]
    current_minutes = evaluated_at.hour * 60 + evaluated_at.minute
    if start_minutes < end_minutes:
        return current_day in days and start_minutes <= current_minutes < end_minutes

    return (
        (current_day in days and current_minutes >= start_minutes)
        or (previous_day in days and current_minutes < end_minutes)
    )


def detect_declarative_config_format(path_or_hint: str) -> str:
    hint = str(path_or_hint or "").strip().lower()
    if not hint:
        raise ValueError("declarative config format is required")
    if hint in DECLARATIVE_CONFIG_FORMATS:
        return hint
    suffix = pathlib.Path(hint).suffix.lower()
    detected = DECLARATIVE_CONFIG_EXTENSION_FORMATS.get(suffix)
    if detected:
        return detected
    raise ValueError("supported declarative config formats are .json, .yaml, .yml, and .toml")


def _parse_declarative_scalar(value: str):
    value = value.strip()
    if value == "":
        return ""
    if value == "[]":
        return []
    if value in {"true", "false"}:
        return value == "true"
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        if value[0] == '"':
            try:
                return json.loads(value)
            except ValueError:
                return value[1:-1]
        return value[1:-1].replace("''", "'")
    return value


def _parse_declarative_key_value(text: str) -> tuple[str, object]:
    if ":" not in text:
        raise ValueError(f"invalid declarative YAML line: {text}")
    key, value = text.split(":", 1)
    key = key.strip()
    if not key:
        raise ValueError("declarative YAML key cannot be empty")
    return key, _parse_declarative_scalar(value)


def parse_declarative_yaml_text(text: str) -> dict:
    """Parse the supported no-dependency YAML subset for profile source-of-truth files.

    The parser is intentionally narrow: top-level scalars, a ``profile`` mapping,
    scalar profile fields, list fields, and ``custom_sources`` objects.
    """
    payload: dict = {}
    profile: dict | None = None
    current_list: str | None = None
    current_source: dict | None = None

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if "\t" in raw_line:
            raise ValueError("declarative YAML must use spaces for indentation")

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()
        if indent == 0:
            current_list = None
            current_source = None
            if stripped == "profile:":
                profile = {}
                payload["profile"] = profile
                continue
            key, value = _parse_declarative_key_value(stripped)
            payload[key] = value
            continue

        if profile is None:
            raise ValueError("declarative YAML nested fields must be under profile")

        if indent == 2:
            current_source = None
            if stripped.startswith("- "):
                raise ValueError("profile must be a mapping, not a list")
            key, value = _parse_declarative_key_value(stripped)
            if value == "" and key in {"whitelist", "pinned_domains", "custom_sources"}:
                profile[key] = []
                current_list = key
            else:
                profile[key] = value
                current_list = None
            continue

        if indent == 4:
            if current_list in {"whitelist", "pinned_domains"} and stripped.startswith("- "):
                profile[current_list].append(_parse_declarative_scalar(stripped[2:]))
                continue
            if current_list == "custom_sources" and stripped.startswith("- "):
                source: dict = {}
                rest = stripped[2:].strip()
                if rest:
                    key, value = _parse_declarative_key_value(rest)
                    source[key] = value
                profile["custom_sources"].append(source)
                current_source = source
                continue
            raise ValueError(f"unsupported declarative YAML list entry: {stripped}")

        if indent == 6 and current_list == "custom_sources" and current_source is not None:
            key, value = _parse_declarative_key_value(stripped)
            current_source[key] = value
            continue

        raise ValueError(f"unsupported declarative YAML indentation at line: {raw_line}")

    return payload


def _parse_toml_scalar(value: str):
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else value
        except ValueError:
            return [
                _parse_declarative_scalar(part.strip())
                for part in value[1:-1].split(",")
                if part.strip()
            ]
    return _parse_declarative_scalar(value)


def parse_declarative_toml_text(text: str) -> dict:
    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"invalid declarative TOML: {exc}") from exc

    payload: dict = {}
    profile: dict | None = None
    current_source: dict | None = None
    section: str | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "[profile]":
            profile = payload.setdefault("profile", {})
            section = "profile"
            current_source = None
            continue
        if stripped == "[[profile.custom_sources]]":
            profile = payload.setdefault("profile", {})
            custom_sources = profile.setdefault("custom_sources", [])
            current_source = {}
            custom_sources.append(current_source)
            section = "custom_source"
            continue
        if "=" not in stripped:
            raise ValueError(f"invalid declarative TOML line: {stripped}")
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = _parse_toml_scalar(value)
        if section == "profile" and profile is not None:
            profile[key] = value
        elif section == "custom_source" and current_source is not None:
            current_source[key] = value
        else:
            payload[key] = value
    return payload


def load_declarative_config_text(text: str, format_hint: str) -> dict:
    fmt = detect_declarative_config_format(format_hint)
    if fmt == "json":
        try:
            payload = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"invalid declarative JSON: {exc}") from exc
    elif fmt == "yaml":
        payload = parse_declarative_yaml_text(text)
    elif fmt == "toml":
        payload = parse_declarative_toml_text(text)
    else:  # pragma: no cover - guarded by detect_declarative_config_format
        raise ValueError(f"unsupported declarative config format: {fmt}")

    if not isinstance(payload, dict):
        raise ValueError("declarative config must be a mapping")
    return payload


def parse_declarative_config_text(text: str, format_hint: str) -> dict:
    payload = load_declarative_config_text(text, format_hint)
    schema = payload.get("schema")
    if schema != DECLARATIVE_CONFIG_SCHEMA:
        raise ValueError(f"declarative config schema must be {DECLARATIVE_CONFIG_SCHEMA}")
    profile = payload.get("profile")
    if not isinstance(profile, dict):
        raise ValueError("declarative config requires a profile mapping")
    fallback_id = sanitize_profile_id(profile.get("id"), DEFAULT_PROFILE_ID)
    return sanitize_profile_snapshot(profile, fallback_id=fallback_id)


def load_declarative_config_file(path: str) -> dict:
    return parse_declarative_config_text(read_text_file_content(path), path)


def build_declarative_config_payload(profile: dict) -> dict:
    sanitized = sanitize_profile_snapshot(
        profile,
        fallback_id=sanitize_profile_id(profile.get("id"), DEFAULT_PROFILE_ID),
    )
    return {
        "schema": DECLARATIVE_CONFIG_SCHEMA,
        "profile": sanitized,
    }


def _declarative_profile_lists(profile: dict) -> tuple[list[str], list[str], list[dict]]:
    whitelist = [line.strip() for line in profile.get("whitelist", "").splitlines() if line.strip()]
    pinned_domains = list(profile.get("pinned_domains", []))
    custom_sources = list(profile.get("custom_sources", []))
    return whitelist, pinned_domains, custom_sources


def _json_string(value) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def format_declarative_config_yaml(profile: dict) -> str:
    payload = build_declarative_config_payload(profile)
    profile = payload["profile"]
    whitelist, pinned_domains, custom_sources = _declarative_profile_lists(profile)
    lines = [
        f"schema: {_json_string(payload['schema'])}",
        "profile:",
        f"  id: {_json_string(profile['id'])}",
        f"  name: {_json_string(profile['name'])}",
        f"  preferred_block_sink: {_json_string(profile['preferred_block_sink'])}",
    ]
    if whitelist:
        lines.append("  whitelist:")
        lines.extend(f"    - {_json_string(value)}" for value in whitelist)
    else:
        lines.append("  whitelist: []")
    if pinned_domains:
        lines.append("  pinned_domains:")
        lines.extend(f"    - {_json_string(value)}" for value in pinned_domains)
    else:
        lines.append("  pinned_domains: []")
    if custom_sources:
        lines.append("  custom_sources:")
        for source in custom_sources:
            lines.append(f"    - name: {_json_string(source['name'])}")
            lines.append(f"      url: {_json_string(source['url'])}")
    else:
        lines.append("  custom_sources: []")
    return "\n".join(lines) + "\n"


def _format_toml_array(values: list[str]) -> str:
    if not values:
        return "[]"
    return "[" + ", ".join(_json_string(value) for value in values) + "]"


def format_declarative_config_toml(profile: dict) -> str:
    payload = build_declarative_config_payload(profile)
    profile = payload["profile"]
    whitelist, pinned_domains, custom_sources = _declarative_profile_lists(profile)
    lines = [
        f"schema = {_json_string(payload['schema'])}",
        "",
        "[profile]",
        f"id = {_json_string(profile['id'])}",
        f"name = {_json_string(profile['name'])}",
        f"preferred_block_sink = {_json_string(profile['preferred_block_sink'])}",
        f"whitelist = {_format_toml_array(whitelist)}",
        f"pinned_domains = {_format_toml_array(pinned_domains)}",
    ]
    for source in custom_sources:
        lines.extend([
            "",
            "[[profile.custom_sources]]",
            f"name = {_json_string(source['name'])}",
            f"url = {_json_string(source['url'])}",
        ])
    return "\n".join(lines) + "\n"


def format_declarative_config_payload(profile: dict, format_hint: str) -> str:
    fmt = detect_declarative_config_format(format_hint)
    payload = build_declarative_config_payload(profile)
    if fmt == "json":
        return json.dumps(payload, indent=2) + "\n"
    if fmt == "yaml":
        return format_declarative_config_yaml(payload["profile"])
    if fmt == "toml":
        return format_declarative_config_toml(payload["profile"])
    raise ValueError(f"unsupported declarative config format: {fmt}")  # pragma: no cover


def upsert_profile_in_config(
    config: dict,
    profile: dict,
    default_last_open_dir: str,
    activate: bool = False,
) -> dict:
    snapshot = sanitize_config_snapshot(config, default_last_open_dir)
    target = sanitize_profile_snapshot(
        profile,
        fallback_id=sanitize_profile_id(profile.get("id"), DEFAULT_PROFILE_ID),
    )
    profiles: list[dict] = []
    replaced = False
    for existing in snapshot.get("profiles", []):
        if existing.get("id") == target["id"]:
            profiles.append(target)
            replaced = True
        else:
            profiles.append(existing)
    if not replaced:
        profiles.append(target)

    snapshot["profiles"] = profiles
    if activate or snapshot.get("active_profile_id") == target["id"]:
        snapshot.update({
            "whitelist": target["whitelist"],
            "custom_sources": target["custom_sources"],
            "pinned_domains": target["pinned_domains"],
            "preferred_block_sink": target["preferred_block_sink"],
            "active_profile_id": target["id"],
        })
    return sanitize_config_snapshot(snapshot, default_last_open_dir)


def apply_declarative_profile_to_config(config: dict, profile: dict, default_last_open_dir: str) -> dict:
    return upsert_profile_in_config(config, profile, default_last_open_dir, activate=True)


def find_profile_snapshot(config: dict, profile_id: str, default_last_open_dir: str | None = None) -> dict:
    sanitized = sanitize_config_snapshot(config, default_last_open_dir or os.path.expanduser("~"))
    safe_id = sanitize_profile_id(profile_id, "")
    for profile in sanitized.get("profiles", []):
        if profile.get("id") == safe_id:
            return sanitize_profile_snapshot(profile, fallback_id=safe_id)
    raise ValueError(f"profile not found: {profile_id}")


def find_active_profile_snapshot(config: dict) -> dict:
    sanitized = sanitize_config_snapshot(config, os.path.expanduser("~"))
    active_id = sanitized.get("active_profile_id", DEFAULT_PROFILE_ID)
    for profile in sanitized.get("profiles", []):
        if profile.get("id") == active_id:
            return sanitize_profile_snapshot(profile, fallback_id=active_id)
    return build_default_profile_snapshot(sanitized)


def set_active_profile_in_config(config: dict, profile_id: str, default_last_open_dir: str) -> dict:
    snapshot = sanitize_config_snapshot(config, default_last_open_dir)
    profile = find_profile_snapshot(snapshot, profile_id, default_last_open_dir)
    snapshot.update({
        "whitelist": profile["whitelist"],
        "custom_sources": profile["custom_sources"],
        "pinned_domains": profile["pinned_domains"],
        "preferred_block_sink": profile["preferred_block_sink"],
        "active_profile_id": profile["id"],
    })
    return sanitize_config_snapshot(snapshot, default_last_open_dir)


def evaluate_profile_activation_schedule(config: dict, when=None, home_dir: str | None = None) -> dict:
    default_home = home_dir or os.path.expanduser("~")
    evaluated_at = parse_profile_activation_when(when)
    snapshot = sanitize_config_snapshot(config, default_home)
    windows = list(snapshot.get("profile_activation_schedule", []))
    active_id = snapshot.get("active_profile_id", DEFAULT_PROFILE_ID)
    fallback_id = snapshot.get("profile_activation_fallback_id", active_id)
    profile_ids = {profile["id"] for profile in snapshot.get("profiles", [])}
    warnings: list[str] = []

    if fallback_id not in profile_ids:
        warnings.append("Configured fallback profile is missing; keeping the current active profile.")
        fallback_id = active_id

    matching_window = None
    for window in windows:
        if profile_activation_window_matches(window, evaluated_at):
            matching_window = window
            break

    if not windows:
        target_id = active_id
        target_reason = "no-schedule"
        warnings.append("No profile activation windows are configured.")
    elif matching_window is not None:
        target_id = matching_window["profile_id"]
        target_reason = "matching-window"
    else:
        target_id = fallback_id
        target_reason = "fallback"

    return {
        "schema": "hostsfileget.profile-activation-report.v1",
        "evaluated_at": evaluated_at.isoformat(timespec="seconds"),
        "active_profile_id": active_id,
        "fallback_profile_id": fallback_id,
        "target_profile_id": target_id,
        "target_reason": target_reason,
        "switch_required": target_id != active_id,
        "will_write_hosts_file": False,
        "matching_window": matching_window,
        "windows": windows,
        "warnings": warnings,
    }


def apply_profile_activation_schedule(config: dict, when=None, home_dir: str | None = None) -> tuple[dict, dict]:
    default_home = home_dir or os.path.expanduser("~")
    snapshot = sanitize_config_snapshot(config, default_home)
    report = evaluate_profile_activation_schedule(snapshot, when=when, home_dir=default_home)
    if report["switch_required"]:
        snapshot = set_active_profile_in_config(snapshot, report["target_profile_id"], default_home)
    return snapshot, report


def format_profile_activation_schedule_report(report: dict) -> str:
    lines = [
        "Profile Activation Schedule",
        f"Evaluated at: {report.get('evaluated_at', '')}",
        f"Active profile: {report.get('active_profile_id', '')}",
        f"Fallback profile: {report.get('fallback_profile_id', '')}",
        f"Target profile: {report.get('target_profile_id', '')} ({report.get('target_reason', '')})",
        "Hosts-file write: no",
    ]
    if report.get("switch_required"):
        lines.append("Config switch required: yes")
    else:
        lines.append("Config switch required: no")

    matching_window = report.get("matching_window")
    if matching_window:
        lines.append(f"Matching window: {matching_window['name']} ({matching_window['id']})")

    warnings = report.get("warnings") or []
    if warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)

    lines.append("")
    lines.append("Windows:")
    windows = report.get("windows") or []
    if not windows:
        lines.append("- None configured.")
    for window in windows:
        status = "enabled" if window.get("enabled", True) else "disabled"
        days = ",".join(window.get("days", []))
        lines.append(
            f"- {window.get('id')}: {window.get('name')} -> {window.get('profile_id')} "
            f"{days} {window.get('start_time')}-{window.get('end_time')} ({status})"
        )
    return "\n".join(lines)


def format_profile_list_summary(config: dict, default_last_open_dir: str | None = None) -> str:
    sanitized = sanitize_config_snapshot(config, default_last_open_dir or os.path.expanduser("~"))
    active_id = sanitized.get("active_profile_id", DEFAULT_PROFILE_ID)
    lines = ["Profiles:"]
    for profile in sanitized.get("profiles", []):
        marker = "*" if profile.get("id") == active_id else " "
        whitelist, pinned_domains, custom_sources = _declarative_profile_lists(profile)
        lines.append(
            f"{marker} {profile['id']}  {profile['name']}  "
            f"whitelist={len(whitelist)} sources={len(custom_sources)} pins={len(pinned_domains)}"
        )
    return "\n".join(lines)


def build_profile_quick_switch_report(
    config: dict,
    default_last_open_dir: str | None = None,
    target_profile_id: str | None = None,
) -> dict:
    default_home = default_last_open_dir or os.path.expanduser("~")
    sanitized = sanitize_config_snapshot(config, default_home)
    active_id = sanitized.get("active_profile_id", DEFAULT_PROFILE_ID)
    profile_rows = []
    profile_ids = set()
    for profile in sanitized.get("profiles", []):
        whitelist, pinned_domains, custom_sources = _declarative_profile_lists(profile)
        profile_id = profile["id"]
        profile_ids.add(profile_id)
        profile_rows.append({
            "id": profile_id,
            "name": profile["name"],
            "active": profile_id == active_id,
            "whitelist_count": len(whitelist),
            "source_count": len(custom_sources),
            "pinned_count": len(pinned_domains),
            "preferred_block_sink": profile["preferred_block_sink"],
        })

    warnings: list[str] = []
    target_id = ""
    target_found = False
    if target_profile_id is not None:
        target_id = _sanitize_profile_id_strict(target_profile_id)
        if not target_id:
            warnings.append(f"Invalid profile id: {target_profile_id}")
        elif target_id in profile_ids:
            target_found = True
        else:
            warnings.append(f"Profile not found: {target_profile_id}")

    return {
        "schema": "hostsfileget.profile-quick-switch.v1",
        "active_profile_id": active_id,
        "target_profile_id": target_id,
        "target_found": target_found,
        "switch_required": bool(target_found and target_id != active_id),
        "will_write_hosts_file": False,
        "profiles": profile_rows,
        "profile_count": len(profile_rows),
        "warnings": warnings,
    }


def apply_profile_quick_switch(
    config: dict,
    profile_id: str,
    default_last_open_dir: str | None = None,
) -> tuple[dict, dict]:
    default_home = default_last_open_dir or os.path.expanduser("~")
    report = build_profile_quick_switch_report(config, default_home, profile_id)
    if not report["target_found"]:
        raise ValueError(f"profile not found: {profile_id}")
    snapshot = sanitize_config_snapshot(config, default_home)
    if report["switch_required"]:
        snapshot = set_active_profile_in_config(snapshot, report["target_profile_id"], default_home)
    return snapshot, report


def format_profile_quick_switch_report(report: dict) -> str:
    lines = [
        "Profile Quick Switch",
        f"Active profile: {report.get('active_profile_id', DEFAULT_PROFILE_ID)}",
        f"Profiles: {report.get('profile_count', 0)}",
        "Hosts-file write: no",
    ]
    target_id = report.get("target_profile_id") or ""
    if target_id:
        lines.append(f"Target profile: {target_id}")
        lines.append(f"Config switch required: {'yes' if report.get('switch_required') else 'no'}")

    warnings = report.get("warnings") or []
    if warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)

    lines.append("")
    lines.append("Saved profiles:")
    profiles = report.get("profiles") or []
    if not profiles:
        lines.append("- None configured.")
    for profile in profiles:
        marker = "*" if profile.get("active") else " "
        lines.append(
            f"{marker} {profile.get('id')}  {profile.get('name')}  "
            f"whitelist={profile.get('whitelist_count', 0)} "
            f"sources={profile.get('source_count', 0)} "
            f"pins={profile.get('pinned_count', 0)} "
            f"sink={profile.get('preferred_block_sink', '0.0.0.0')}"
        )
    return "\n".join(lines)


def build_profile_tray_availability_report(importer=None) -> dict:
    importer = importer or importlib.import_module
    required_modules = [
        ("pystray", "pystray"),
        ("Pillow Image", "PIL.Image"),
        ("Pillow ImageDraw", "PIL.ImageDraw"),
    ]
    missing = []
    for label, module_name in required_modules:
        try:
            importer(module_name)
        except Exception as exc:
            missing.append({
                "package": label,
                "module": module_name,
                "error": str(exc) or exc.__class__.__name__,
            })

    available = not missing
    return {
        "schema": "hostsfileget.profile-tray-availability.v1",
        "available": available,
        "required_modules": [module_name for _, module_name in required_modules],
        "missing": missing,
        "install_hint": "" if available else "python -m pip install pystray Pillow",
        "message": (
            "Optional tray quick switch support is available."
            if available
            else "Optional tray quick switch support requires pystray and Pillow."
        ),
    }


def load_optional_profile_tray_modules() -> tuple[dict | None, dict]:
    report = build_profile_tray_availability_report()
    if not report["available"]:
        return None, report
    modules = {
        "pystray": importlib.import_module("pystray"),
        "Image": importlib.import_module("PIL.Image"),
        "ImageDraw": importlib.import_module("PIL.ImageDraw"),
    }
    return modules, report


def format_profile_tray_availability_report(report: dict) -> str:
    lines = [
        "Profile Tray Quick Switch",
        f"Available: {'yes' if report.get('available') else 'no'}",
        report.get("message", ""),
    ]
    if report.get("install_hint"):
        lines.append(f"Install hint: {report['install_hint']}")
    missing = report.get("missing") or []
    if missing:
        lines.append("")
        lines.append("Missing modules:")
        for item in missing:
            lines.append(f"- {item.get('module')} ({item.get('package')}): {item.get('error')}")
    return "\n".join(lines)


def format_declarative_profile_summary(profile: dict, action: str | None = None) -> str:
    sanitized = sanitize_profile_snapshot(
        profile,
        fallback_id=sanitize_profile_id(profile.get("id"), DEFAULT_PROFILE_ID),
    )
    whitelist, pinned_domains, custom_sources = _declarative_profile_lists(sanitized)
    lines = [
        f"Profile: {sanitized['name']} ({sanitized['id']})",
        f"Whitelist entries: {len(whitelist)}",
        f"Custom sources: {len(custom_sources)}",
        f"Pinned domains: {len(pinned_domains)}",
        f"Preferred block sink: {sanitized['preferred_block_sink']}",
    ]
    if action:
        lines.append(f"Config action: {action}")
    return "\n".join(lines)


def _coerce_config_schema_version(value) -> int:
    if isinstance(value, bool):
        return 0
    try:
        version = int(value)
    except (TypeError, ValueError):
        return 0
    if version < 0 or version > CONFIG_SCHEMA_VERSION:
        return 0
    return version


def migrate_config_snapshot(config) -> dict:
    """Return a config payload upgraded to the current schema shape.

    Older builds did not write an explicit schema version. This migration layer
    keeps the sanitizer as the single gate for persisted config while giving
    future changes a stable place to translate renamed keys.
    """
    if not isinstance(config, dict):
        config = {}

    migrated = dict(config)
    source_version = _coerce_config_schema_version(migrated.get("config_version", 0))

    if source_version == 0:
        legacy_aliases = {
            "sources": "custom_sources",
            "whitelist_domains": "whitelist",
            "last_fetched": "source_last_fetched",
            "block_sink": "preferred_block_sink",
        }
        for legacy_key, current_key in legacy_aliases.items():
            if current_key not in migrated and legacy_key in migrated:
                migrated[current_key] = migrated[legacy_key]

    migrated["config_version"] = CONFIG_SCHEMA_VERSION
    return migrated


def sanitize_config_snapshot(config, default_last_open_dir: str) -> dict:
    config = migrate_config_snapshot(config)
    if not isinstance(config, dict):
        config = {}

    fallback_last_open_dir = default_last_open_dir if isinstance(default_last_open_dir, str) and os.path.isdir(default_last_open_dir) else os.path.expanduser("~")
    if not os.path.isdir(fallback_last_open_dir):
        fallback_last_open_dir = os.getcwd()

    whitelist_text = _sanitize_whitelist_text(config.get("whitelist", ""))

    def _normalize_hash(value):
        # SHA-256 hex digests are exactly 64 lowercase hex characters.
        # Rejecting anything else prevents a corrupted config from putting
        # arbitrary strings into the saved-state comparator where they
        # would never match a real editor hash and would quietly confuse
        # the "unsaved changes" badge.
        if not isinstance(value, str):
            return None
        value = value.strip().lower()
        if len(value) != 64:
            return None
        if not all(ch in "0123456789abcdef" for ch in value):
            return None
        return value

    last_open_dir = config.get("last_open_dir", fallback_last_open_dir)
    if not isinstance(last_open_dir, str) or not os.path.isdir(last_open_dir):
        last_open_dir = fallback_last_open_dir

    raw_last_fetched = config.get("source_last_fetched", {})
    source_last_fetched: dict[str, str] = {}
    if isinstance(raw_last_fetched, dict):
        for url, stamp in raw_last_fetched.items():
            if not isinstance(url, str) or _parse_valid_http_source_url(url) is None:
                continue
            if not isinstance(stamp, str) or len(stamp) > 64:
                continue
            # Reject garbage timestamps so a corrupt config can't poison
            # tooltips with arbitrary strings.
            try:
                datetime.datetime.fromisoformat(stamp)
            except (TypeError, ValueError):
                continue
            source_last_fetched[url] = stamp

    custom_sources = sanitize_custom_sources(config.get("custom_sources", []))
    source_cache_metadata = sanitize_source_cache_metadata(config.get("source_cache_metadata", {}))
    source_metrics_history = sanitize_source_metrics_history(config.get("source_metrics_history", {}))
    filter_query_history = sanitize_filter_query_history(config.get("filter_query_history", []))
    watch_expressions = sanitize_watch_expressions(config.get("watch_expressions", []))

    preferred_sink_raw = config.get("preferred_block_sink", "0.0.0.0")
    preferred_sink = _profile_preferred_sink(preferred_sink_raw)

    raw_retention = config.get("backup_retention", BACKUP_RETENTION)
    try:
        backup_retention = int(raw_retention)
    except (TypeError, ValueError):
        backup_retention = BACKUP_RETENTION
    backup_retention = max(0, min(50, backup_retention))

    has_completed_first_run = bool(config.get("has_completed_first_run", False))
    pinned_domains = sanitize_pinned_domains(config.get("pinned_domains", []))
    fallback_profile = build_default_profile_snapshot({
        "whitelist": whitelist_text,
        "custom_sources": custom_sources,
        "pinned_domains": pinned_domains,
        "preferred_block_sink": preferred_sink,
    })
    profiles, active_profile_id = sanitize_profiles_snapshot(
        config.get("profiles", []),
        config.get("active_profile_id", DEFAULT_PROFILE_ID),
        fallback_profile=fallback_profile,
    )
    profile_ids = {profile["id"] for profile in profiles}
    profile_activation_fallback_id = _sanitize_profile_id_strict(
        config.get("profile_activation_fallback_id")
    )
    if profile_activation_fallback_id not in profile_ids:
        profile_activation_fallback_id = active_profile_id
    profile_activation_schedule = sanitize_profile_activation_schedule(
        config.get("profile_activation_schedule", []),
        profile_ids,
    )

    return {
        "config_version": CONFIG_SCHEMA_VERSION,
        "whitelist": whitelist_text,
        "custom_sources": custom_sources,
        "last_applied_raw_hash": _normalize_hash(config.get("last_applied_raw_hash")),
        "last_applied_cleaned_hash": _normalize_hash(config.get("last_applied_cleaned_hash")),
        "last_open_dir": last_open_dir,
        "source_last_fetched": source_last_fetched,
        "source_cache_metadata": source_cache_metadata,
        "source_metrics_history": source_metrics_history,
        "filter_query_history": filter_query_history,
        "watch_expressions": watch_expressions,
        "preferred_block_sink": preferred_sink,
        "backup_retention": backup_retention,
        "has_completed_first_run": has_completed_first_run,
        "pinned_domains": pinned_domains,
        "update_on_launch": bool(config.get("update_on_launch", False)),
        "lock_after_save": bool(config.get("lock_after_save", False)),
        "profile_schema_version": PROFILE_SCHEMA_VERSION,
        "active_profile_id": active_profile_id,
        "profiles": profiles,
        "profile_activation_schedule_version": PROFILE_ACTIVATION_SCHEDULE_VERSION,
        "profile_activation_fallback_id": profile_activation_fallback_id,
        "profile_activation_schedule": profile_activation_schedule,
    }

def get_profile_sync_git_dir(base_dir: str | None = None) -> str:
    root = base_dir or get_config_root_dir()
    return os.path.join(root, PROFILE_SYNC_GIT_DIRNAME)


def resolve_gpg_executable(gpg_executable: str | None = None) -> str | None:
    if gpg_executable:
        return gpg_executable
    return shutil.which("gpg") or shutil.which("gpg.exe")


def sanitize_profile_sync_env_name(value: str | None) -> str:
    candidate = str(value or PROFILE_SYNC_PASSPHRASE_ENV).strip()
    if not PROFILE_SYNC_ENV_NAME_PATTERN.match(candidate):
        raise ValueError("sync passphrase environment variable name is invalid")
    return candidate


def sanitize_profile_sync_passphrase(value: str | None) -> str:
    if not isinstance(value, str):
        raise ValueError("sync passphrase is required")
    if len(value) < PROFILE_SYNC_MIN_PASSPHRASE_LENGTH or _contains_control_chars(value):
        raise ValueError(
            f"sync passphrase must be at least {PROFILE_SYNC_MIN_PASSPHRASE_LENGTH} characters "
            "and cannot contain control characters"
        )
    return value


def read_profile_sync_passphrase(env_name: str | None = None, environ=None) -> str:
    safe_name = sanitize_profile_sync_env_name(env_name)
    source = os.environ if environ is None else environ
    return sanitize_profile_sync_passphrase(source.get(safe_name))


def build_profile_sync_payload(config: dict, default_last_open_dir: str | None = None, now=None) -> dict:
    sanitized = sanitize_config_snapshot(config, default_last_open_dir or os.path.expanduser("~"))
    created_at = now or datetime.datetime.now()
    if isinstance(created_at, datetime.datetime):
        created_at = created_at.isoformat(timespec="seconds")
    payload = {
        "schema": PROFILE_SYNC_PAYLOAD_SCHEMA,
        "app_version": APP_VERSION,
        "created_at": str(created_at),
        "config_version": CONFIG_SCHEMA_VERSION,
        "profile_schema_version": PROFILE_SCHEMA_VERSION,
        "active_profile_id": sanitized["active_profile_id"],
        "profiles": sanitized["profiles"],
        "profile_activation_schedule_version": PROFILE_ACTIVATION_SCHEDULE_VERSION,
        "profile_activation_fallback_id": sanitized["profile_activation_fallback_id"],
        "profile_activation_schedule": sanitized["profile_activation_schedule"],
    }
    return sanitize_profile_sync_payload(payload)


def sanitize_profile_sync_payload(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("profile sync payload must be a JSON object")
    if payload.get("schema") != PROFILE_SYNC_PAYLOAD_SCHEMA:
        raise ValueError(f"profile sync payload schema must be {PROFILE_SYNC_PAYLOAD_SCHEMA}")
    profiles, active_profile_id = sanitize_profiles_snapshot(
        payload.get("profiles", []),
        payload.get("active_profile_id", DEFAULT_PROFILE_ID),
    )
    profile_ids = {profile["id"] for profile in profiles}
    fallback_id = _sanitize_profile_id_strict(payload.get("profile_activation_fallback_id"))
    if fallback_id not in profile_ids:
        fallback_id = active_profile_id
    schedule = sanitize_profile_activation_schedule(
        payload.get("profile_activation_schedule", []),
        profile_ids,
    )
    created_at = str(payload.get("created_at") or "")
    if not created_at or _contains_control_chars(created_at) or len(created_at) > 80:
        created_at = datetime.datetime.now().isoformat(timespec="seconds")
    return {
        "schema": PROFILE_SYNC_PAYLOAD_SCHEMA,
        "app_version": str(payload.get("app_version") or APP_VERSION)[:40],
        "created_at": created_at,
        "config_version": CONFIG_SCHEMA_VERSION,
        "profile_schema_version": PROFILE_SCHEMA_VERSION,
        "active_profile_id": active_profile_id,
        "profiles": profiles,
        "profile_activation_schedule_version": PROFILE_ACTIVATION_SCHEDULE_VERSION,
        "profile_activation_fallback_id": fallback_id,
        "profile_activation_schedule": schedule,
    }


def apply_profile_sync_payload_to_config(
    config: dict,
    payload: dict,
    default_last_open_dir: str | None = None,
) -> dict:
    default_dir = default_last_open_dir or os.path.expanduser("~")
    current = sanitize_config_snapshot(config, default_dir)
    synced = sanitize_profile_sync_payload(payload)
    current["profiles"] = synced["profiles"]
    current["active_profile_id"] = synced["active_profile_id"]
    current["profile_activation_fallback_id"] = synced["profile_activation_fallback_id"]
    current["profile_activation_schedule"] = synced["profile_activation_schedule"]
    current["profile_activation_schedule_version"] = PROFILE_ACTIVATION_SCHEDULE_VERSION
    return set_active_profile_in_config(current, synced["active_profile_id"], default_dir)


def build_profile_sync_metadata(payload: dict, encrypted_filename: str = PROFILE_SYNC_BUNDLE_FILENAME) -> dict:
    sanitized = sanitize_profile_sync_payload(payload)
    canonical = json.dumps(sanitized, sort_keys=True, separators=(",", ":"))
    return {
        "schema": PROFILE_SYNC_METADATA_SCHEMA,
        "app_version": APP_VERSION,
        "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "payload_schema": sanitized["schema"],
        "payload_created_at": sanitized["created_at"],
        "active_profile_id": sanitized["active_profile_id"],
        "profile_count": len(sanitized["profiles"]),
        "encrypted_file": encrypted_filename,
        "encryption": "gpg symmetric AES256",
        "payload_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def _run_gpg_transform(
    input_path: str,
    output_path: str,
    passphrase: str,
    decrypt: bool = False,
    gpg_executable: str | None = None,
    runner=None,
    timeout: int = 60,
) -> None:
    gpg = resolve_gpg_executable(gpg_executable)
    if not gpg:
        raise OSError("gpg executable not found")
    safe_passphrase = sanitize_profile_sync_passphrase(passphrase)
    args = [
        gpg,
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase-fd",
        "0",
        "--output",
        output_path,
    ]
    if decrypt:
        args.extend(["--decrypt", input_path])
    else:
        args.extend(["--symmetric", "--cipher-algo", "AES256", input_path])
    run = runner or subprocess.run
    try:
        result = run(
            args,
            input=f"{safe_passphrase}\n",
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise OSError("gpg executable not found") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise OSError(f"gpg {'decrypt' if decrypt else 'encrypt'} failed: {detail}")


def encrypt_profile_sync_payload(
    payload: dict,
    output_path: str,
    passphrase: str,
    gpg_executable: str | None = None,
    runner=None,
) -> dict:
    sanitized = sanitize_profile_sync_payload(payload)
    output_dir = os.path.dirname(os.path.abspath(output_path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        plain_path = os.path.join(tmpdir, "hostsfileget-profile-sync.json")
        write_text_file_atomic(plain_path, json.dumps(sanitized, indent=2, sort_keys=True))
        _run_gpg_transform(
            plain_path,
            output_path,
            passphrase,
            decrypt=False,
            gpg_executable=gpg_executable,
            runner=runner,
        )
    return build_profile_sync_metadata(sanitized, os.path.basename(output_path))


def decrypt_profile_sync_payload(
    input_path: str,
    passphrase: str,
    gpg_executable: str | None = None,
    runner=None,
) -> dict:
    if not os.path.isfile(input_path):
        raise OSError(f"profile sync bundle not found: {input_path}")
    with tempfile.TemporaryDirectory() as tmpdir:
        plain_path = os.path.join(tmpdir, "hostsfileget-profile-sync.json")
        _run_gpg_transform(
            input_path,
            plain_path,
            passphrase,
            decrypt=True,
            gpg_executable=gpg_executable,
            runner=runner,
        )
        try:
            payload = json.loads(read_text_file_content(plain_path))
        except json.JSONDecodeError as exc:
            raise ValueError(f"profile sync payload JSON is invalid: {exc}") from exc
    return sanitize_profile_sync_payload(payload)


def ensure_profile_sync_git_repo(
    repo_dir: str,
    git_executable: str | None = None,
    runner=None,
) -> str:
    return ensure_git_history_repo(repo_dir, git_executable=git_executable, runner=runner)


def _profile_sync_commit_message(payload: dict) -> str:
    synced = sanitize_profile_sync_payload(payload)
    return f"profile sync: {synced['active_profile_id']}"


def write_profile_sync_git_export(
    repo_dir: str,
    config: dict,
    passphrase: str,
    default_last_open_dir: str | None = None,
    git_executable: str | None = None,
    git_runner=None,
    gpg_executable: str | None = None,
    gpg_runner=None,
    push: bool = False,
) -> dict:
    ensure_profile_sync_git_repo(repo_dir, git_executable=git_executable, runner=git_runner)
    payload = build_profile_sync_payload(config, default_last_open_dir)
    bundle_path = os.path.join(repo_dir, PROFILE_SYNC_BUNDLE_FILENAME)
    metadata_path = os.path.join(repo_dir, PROFILE_SYNC_METADATA_FILENAME)
    metadata = encrypt_profile_sync_payload(
        payload,
        bundle_path,
        passphrase,
        gpg_executable=gpg_executable,
        runner=gpg_runner,
    )
    write_text_file_atomic(metadata_path, json.dumps(metadata, indent=2))
    _run_git_command(
        repo_dir,
        ["add", "--", PROFILE_SYNC_BUNDLE_FILENAME, PROFILE_SYNC_METADATA_FILENAME],
        git_executable=git_executable,
        runner=git_runner,
    )
    status = _run_git_command(
        repo_dir,
        ["status", "--porcelain", "--", PROFILE_SYNC_BUNDLE_FILENAME, PROFILE_SYNC_METADATA_FILENAME],
        git_executable=git_executable,
        runner=git_runner,
    )
    commit_status = "unchanged"
    if status:
        _run_git_command(
            repo_dir,
            ["commit", "-m", _profile_sync_commit_message(payload)],
            git_executable=git_executable,
            runner=git_runner,
        )
        commit_status = "committed"
    try:
        commit = _run_git_command(repo_dir, ["rev-parse", "--short=12", "HEAD"], git_executable=git_executable, runner=git_runner)
    except OSError:
        commit = None
    pushed = False
    if push:
        _run_git_command(repo_dir, ["push", "origin", "HEAD"], git_executable=git_executable, runner=git_runner, timeout=60)
        pushed = True
    return {
        "action": "export",
        "status": commit_status,
        "repo_dir": repo_dir,
        "bundle_path": bundle_path,
        "metadata_path": metadata_path,
        "commit": commit,
        "pushed": pushed,
        "active_profile_id": payload["active_profile_id"],
        "profile_count": len(payload["profiles"]),
    }


def read_profile_sync_git_import(
    repo_dir: str,
    current_config: dict,
    passphrase: str,
    default_last_open_dir: str | None = None,
    git_executable: str | None = None,
    git_runner=None,
    gpg_executable: str | None = None,
    gpg_runner=None,
    pull: bool = False,
) -> dict:
    if pull:
        if not os.path.isdir(os.path.join(repo_dir, ".git")):
            raise OSError("profile sync Git repository has not been initialized")
        _run_git_command(repo_dir, ["pull", "--ff-only"], git_executable=git_executable, runner=git_runner, timeout=60)
    bundle_path = os.path.join(repo_dir, PROFILE_SYNC_BUNDLE_FILENAME)
    payload = decrypt_profile_sync_payload(
        bundle_path,
        passphrase,
        gpg_executable=gpg_executable,
        runner=gpg_runner,
    )
    merged_config = apply_profile_sync_payload_to_config(
        current_config,
        payload,
        default_last_open_dir,
    )
    return {
        "action": "import",
        "status": "imported",
        "repo_dir": repo_dir,
        "bundle_path": bundle_path,
        "config": merged_config,
        "active_profile_id": payload["active_profile_id"],
        "profile_count": len(payload["profiles"]),
        "pulled": bool(pull),
    }


def format_profile_sync_report(report: dict) -> str:
    lines = [
        "Encrypted Profile Sync",
        f"Action: {report.get('action', '-')}",
        f"Status: {report.get('status', '-')}",
        f"Repository: {report.get('repo_dir') or '-'}",
        f"Encrypted bundle: {report.get('bundle_path') or '-'}",
        f"Active profile: {report.get('active_profile_id') or DEFAULT_PROFILE_ID}",
        f"Profiles: {report.get('profile_count', 0)}",
    ]
    if report.get("metadata_path"):
        lines.append(f"Metadata: {report.get('metadata_path')}")
    if report.get("commit"):
        lines.append(f"Commit: {report.get('commit')}")
    if report.get("pushed"):
        lines.append("Pushed: yes")
    if report.get("pulled"):
        lines.append("Pulled: yes")
    lines.append("Hosts file writes: none")
    return "\n".join(lines)


def _share_patch_timestamp(now=None) -> str:
    value = now or datetime.datetime.now()
    if isinstance(value, datetime.datetime):
        return value.isoformat(timespec="seconds")
    return str(value)


def _sanitize_share_patch_author(value) -> str:
    if not isinstance(value, str):
        return ""
    author = re.sub(r"\s+", " ", value.strip())
    if _contains_control_chars(author):
        return ""
    return author[:120]


def _normalize_allowlist_patch_domains(values) -> list[str]:
    if isinstance(values, str):
        raw_values = [line.strip() for line in values.splitlines()]
    elif isinstance(values, (list, tuple, set)):
        raw_values = [str(value).strip() for value in values]
    else:
        raw_values = []
    return sanitize_pinned_domains(raw_values)


def parse_allowlist_patch_text(text: str) -> list[str]:
    return _normalize_allowlist_patch_domains(_sanitize_whitelist_text(text).splitlines())


def build_allowlist_share_patch(domains, author: str | None = None, now=None) -> dict:
    normalized_domains = _normalize_allowlist_patch_domains(domains)
    if not normalized_domains:
        raise ValueError("allowlist patch must contain at least one valid domain")
    return {
        "schema": SHARE_PATCH_SCHEMA,
        "patch_type": "allowlist",
        "app_version": APP_VERSION,
        "created_at": _share_patch_timestamp(now),
        "author": _sanitize_share_patch_author(author),
        "domains": normalized_domains,
    }


def build_profile_share_patch(profile: dict, author: str | None = None, now=None) -> dict:
    sanitized = sanitize_profile_snapshot(
        profile,
        fallback_id=sanitize_profile_id(profile.get("id"), DEFAULT_PROFILE_ID) if isinstance(profile, dict) else DEFAULT_PROFILE_ID,
    )
    return {
        "schema": SHARE_PATCH_SCHEMA,
        "patch_type": "profile",
        "app_version": APP_VERSION,
        "created_at": _share_patch_timestamp(now),
        "author": _sanitize_share_patch_author(author),
        "profile": sanitized,
    }


def sanitize_share_patch_payload(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("share patch must be a JSON object")
    if payload.get("schema") != SHARE_PATCH_SCHEMA:
        raise ValueError(f"share patch schema must be {SHARE_PATCH_SCHEMA}")
    patch_type = str(payload.get("patch_type") or "").strip().lower()
    if patch_type not in SHARE_PATCH_TYPES:
        raise ValueError(f"share patch type must be one of {', '.join(SHARE_PATCH_TYPES)}")
    created_at = str(payload.get("created_at") or "")
    if not created_at or _contains_control_chars(created_at) or len(created_at) > 80:
        created_at = datetime.datetime.now().isoformat(timespec="seconds")
    base = {
        "schema": SHARE_PATCH_SCHEMA,
        "patch_type": patch_type,
        "app_version": str(payload.get("app_version") or APP_VERSION)[:40],
        "created_at": created_at,
        "author": _sanitize_share_patch_author(payload.get("author")),
    }
    if patch_type == "allowlist":
        domains = _normalize_allowlist_patch_domains(payload.get("domains", []))
        if not domains:
            raise ValueError("allowlist patch must contain at least one valid domain")
        base["domains"] = domains
    else:
        profile_payload = payload.get("profile")
        if not isinstance(profile_payload, dict):
            raise ValueError("profile patch requires a profile object")
        base["profile"] = sanitize_profile_snapshot(
            profile_payload,
            fallback_id=sanitize_profile_id(profile_payload.get("id"), DEFAULT_PROFILE_ID),
        )
    return base


def _merge_domains_into_whitelist_text(whitelist_text: str, domains: list[str]) -> str:
    existing = [line for line in _sanitize_whitelist_text(whitelist_text).splitlines() if line.strip()]
    seen = {line.casefold() for line in existing}
    merged = list(existing)
    for domain in domains:
        key = domain.casefold()
        if key in seen:
            continue
        seen.add(key)
        merged.append(domain)
    return "\n".join(merged) + ("\n" if merged else "")


def apply_share_patch_payload_to_config(
    config: dict,
    payload: dict,
    default_last_open_dir: str | None = None,
) -> tuple[dict, dict]:
    default_dir = default_last_open_dir or os.path.expanduser("~")
    current = sanitize_config_snapshot(config, default_dir)
    patch = sanitize_share_patch_payload(payload)
    if patch["patch_type"] == "allowlist":
        before = len([line for line in current.get("whitelist", "").splitlines() if line.strip()])
        current["whitelist"] = _merge_domains_into_whitelist_text(current.get("whitelist", ""), patch["domains"])
        current["profiles"], current["active_profile_id"] = update_active_profile_snapshot(
            current.get("profiles", []),
            current.get("active_profile_id", DEFAULT_PROFILE_ID),
            current,
        )
        merged = sanitize_config_snapshot(current, default_dir)
        after = len([line for line in merged.get("whitelist", "").splitlines() if line.strip()])
        report = {
            "action": "apply",
            "patch_type": "allowlist",
            "status": "applied",
            "added_count": max(0, after - before),
            "domain_count": len(patch["domains"]),
            "active_profile_id": merged.get("active_profile_id"),
        }
        return merged, report
    merged = upsert_profile_in_config(current, patch["profile"], default_dir, activate=False)
    report = {
        "action": "apply",
        "patch_type": "profile",
        "status": "applied",
        "profile_id": patch["profile"]["id"],
        "active_profile_id": merged.get("active_profile_id"),
    }
    return merged, report


def format_share_patch_summary(report: dict) -> str:
    lines = [
        "Signed Share Patch",
        f"Action: {report.get('action', '-')}",
        f"Type: {report.get('patch_type', '-')}",
        f"Status: {report.get('status', '-')}",
    ]
    if report.get("patch_path"):
        lines.append(f"Patch: {report.get('patch_path')}")
    if report.get("signature_path"):
        lines.append(f"Signature: {report.get('signature_path')}")
    if report.get("verified") is not None:
        lines.append(f"Signature verified: {'yes' if report.get('verified') else 'no'}")
    if report.get("domain_count") is not None:
        lines.append(f"Domains: {report.get('domain_count')}")
    if report.get("added_count") is not None:
        lines.append(f"Added domains: {report.get('added_count')}")
    if report.get("profile_id"):
        lines.append(f"Profile: {report.get('profile_id')}")
    if report.get("active_profile_id"):
        lines.append(f"Active profile: {report.get('active_profile_id')}")
    if report.get("signer"):
        lines.append(f"Signer: {report.get('signer')}")
    lines.append("Hosts file writes: none")
    return "\n".join(lines)


def write_share_patch_payload(payload: dict, output_path: str) -> dict:
    sanitized = sanitize_share_patch_payload(payload)
    output_dir = os.path.dirname(os.path.abspath(output_path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    write_text_file_atomic(output_path, json.dumps(sanitized, indent=2, sort_keys=True))
    summary = {
        "action": "build",
        "patch_type": sanitized["patch_type"],
        "status": "written",
        "patch_path": output_path,
    }
    if sanitized["patch_type"] == "allowlist":
        summary["domain_count"] = len(sanitized["domains"])
    else:
        summary["profile_id"] = sanitized["profile"]["id"]
    return summary


def load_share_patch_payload(path: str) -> dict:
    try:
        payload = json.loads(read_text_file_content(path))
    except json.JSONDecodeError as exc:
        raise ValueError(f"share patch JSON is invalid: {exc}") from exc
    return sanitize_share_patch_payload(payload)


def sign_share_patch_file(
    patch_path: str,
    signature_path: str,
    gpg_key: str | None = None,
    gpg_executable: str | None = None,
    runner=None,
) -> dict:
    if not os.path.isfile(patch_path):
        raise OSError(f"share patch not found: {patch_path}")
    gpg = resolve_gpg_executable(gpg_executable)
    if not gpg:
        raise OSError("gpg executable not found")
    output_dir = os.path.dirname(os.path.abspath(signature_path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    args = [
        gpg,
        "--batch",
        "--yes",
        "--armor",
        "--detach-sign",
        "--output",
        signature_path,
    ]
    if gpg_key:
        args.extend(["--local-user", str(gpg_key)])
    args.append(patch_path)
    run = runner or subprocess.run
    try:
        result = run(args, capture_output=True, text=True, timeout=60, check=False)
    except FileNotFoundError as exc:
        raise OSError("gpg executable not found") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise OSError(f"gpg sign failed: {detail}")
    payload = load_share_patch_payload(patch_path)
    report = {
        "action": "sign",
        "patch_type": payload["patch_type"],
        "status": "signed",
        "patch_path": patch_path,
        "signature_path": signature_path,
    }
    if payload["patch_type"] == "allowlist":
        report["domain_count"] = len(payload["domains"])
    else:
        report["profile_id"] = payload["profile"]["id"]
    return report


def verify_share_patch_signature(
    patch_path: str,
    signature_path: str,
    gpg_executable: str | None = None,
    runner=None,
) -> dict:
    if not os.path.isfile(patch_path):
        raise OSError(f"share patch not found: {patch_path}")
    if not os.path.isfile(signature_path):
        raise OSError(f"share patch signature not found: {signature_path}")
    gpg = resolve_gpg_executable(gpg_executable)
    if not gpg:
        raise OSError("gpg executable not found")
    run = runner or subprocess.run
    args = [gpg, "--batch", "--verify", signature_path, patch_path]
    try:
        result = run(args, capture_output=True, text=True, timeout=60, check=False)
    except FileNotFoundError as exc:
        raise OSError("gpg executable not found") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise OSError(f"gpg verify failed: {detail}")
    payload = load_share_patch_payload(patch_path)
    signer = (result.stderr or result.stdout or "").strip()
    report = {
        "action": "verify",
        "patch_type": payload["patch_type"],
        "status": "verified",
        "patch_path": patch_path,
        "signature_path": signature_path,
        "verified": True,
        "signer": re.sub(r"\s+", " ", signer)[:240],
    }
    if payload["patch_type"] == "allowlist":
        report["domain_count"] = len(payload["domains"])
    else:
        report["profile_id"] = payload["profile"]["id"]
    return report
