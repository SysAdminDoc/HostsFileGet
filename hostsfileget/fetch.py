"""HTTP fetch, redirect guard, and source-body cache.

Owns the entire network ingress surface for HostsFileGet downloads:

- :class:`_HttpsOnlyRedirectHandler` + :func:`safe_urlopen` reject
  redirects to non-``http``/``https`` schemes so a malicious feed
  mirror cannot bounce a blocklist download to ``file://`` or to an
  internal ``ftp://`` service for SSRF probing.
- URL validators (:func:`_parse_valid_http_source_url`,
  :func:`normalize_custom_source_url`) and the control-byte rejecter
  (:func:`_contains_control_chars`).
- ETag / Last-Modified-aware cache (read/write/prune) keyed by SHA-256
  of the normalised URL, including the orphan-blob pruner.
- Retry loop with bounded attempts (:data:`IMPORT_FETCH_MAX_ATTEMPTS`)
  and a small back-off (:data:`IMPORT_FETCH_RETRY_DELAY_SECONDS`).

Pure-stdlib. No GUI dependency. The cache directory is *not* derived
inside this module — callers in ``hosts_editor.py`` pass it in
explicitly so this module does not have to know about portable-mode
config-path resolution.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from .compression import (
    MAX_DOWNLOAD_BYTES,
    decode_downloaded_lines,
    read_http_body_limited,
)
from .constants import APP_SLUG, APP_VERSION


IMPORT_FETCH_MAX_WORKERS = 4
IMPORT_FETCH_MAX_ATTEMPTS = 3
IMPORT_FETCH_RETRY_DELAY_SECONDS = 0.25


# ---------------------------- URL validation --------------------------------

def _parse_valid_http_source_url(url: str):
    """Return a parsed URL only when it is a direct http(s) URL with a host."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None

    if parsed.scheme.lower() not in ("http", "https"):
        return None
    if not parsed.hostname:
        return None
    return parsed


def normalize_custom_source_url(url: str) -> str:
    candidate = url.strip()
    if not candidate:
        return ""

    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return candidate.rstrip("/").lower()

    if not parsed.scheme or not parsed.netloc:
        return candidate.rstrip("/").lower()

    normalized_path = parsed.path.rstrip("/")

    return urllib.parse.urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        normalized_path,
        parsed.query,
        "",
    ))


def _contains_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 for ch in value)


def sanitize_custom_sources(custom_sources) -> list[dict[str, str]]:
    if not isinstance(custom_sources, list):
        return []

    sanitized_sources: list[dict[str, str]] = []
    seen_names: set[str] = set()
    seen_urls: set[str] = set()

    for source in custom_sources:
        if not isinstance(source, dict):
            continue

        name = str(source.get("name", "")).strip()
        url = str(source.get("url", "")).strip()
        if not name or not url or not url.lower().startswith(("http://", "https://")):
            continue

        # Reject names or URLs containing control bytes (tab, newline, ESC,
        # etc.). A legacy config with a malformed entry could otherwise
        # corrupt the import marker comments or the sidebar layout.
        if _contains_control_chars(name) or _contains_control_chars(url):
            continue

        # Cap sizes defensively; see AddSourceDialog for rationale.
        if len(name) > 120 or len(url) > 2083:
            continue
        if _parse_valid_http_source_url(url) is None:
            continue

        normalized_name = name.lower()
        normalized_url = normalize_custom_source_url(url)
        if normalized_name in seen_names or normalized_url in seen_urls:
            continue

        seen_names.add(normalized_name)
        seen_urls.add(normalized_url)
        sanitized_sources.append({"name": name, "url": url})

    return sanitized_sources


# ---------------------------- Response helpers ------------------------------

def _response_status_code(response) -> int | None:
    try:
        status = response.getcode()
    except Exception:
        status = getattr(response, "status", None)
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _response_header(response, name: str) -> str:
    headers = getattr(response, "headers", None)
    if headers is None:
        return ""
    try:
        value = headers.get(name, "")
    except Exception:
        return ""
    return str(value or "")


# ---------------------------- Cache metadata --------------------------------

def _valid_iso_timestamp(value: str) -> bool:
    try:
        datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except (TypeError, ValueError):
        return False


def _normalize_cache_header(value, max_length: int = 512) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value or len(value) > max_length or _contains_control_chars(value):
        return ""
    return value


def _normalize_sha256(value) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip().lower()
    if len(value) != 64 or not all(ch in "0123456789abcdef" for ch in value):
        return ""
    return value


def source_cache_key(url: str) -> str:
    normalized = normalize_custom_source_url(url) or str(url).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def get_source_cache_body_path(url: str, cache_dir: str) -> str:
    if not cache_dir:
        raise ValueError("cache_dir is required for source cache body paths")
    return os.path.join(cache_dir, f"{source_cache_key(url)}.bin")


def sanitize_source_cache_metadata(metadata) -> dict[str, dict[str, str | int]]:
    if not isinstance(metadata, dict):
        return {}

    sanitized: dict[str, dict[str, str | int]] = {}
    for url, entry in metadata.items():
        if not isinstance(url, str) or _parse_valid_http_source_url(url) is None:
            continue
        if not isinstance(entry, dict):
            continue

        content_sha256 = _normalize_sha256(entry.get("content_sha256"))
        if not content_sha256:
            continue

        try:
            byte_count = int(entry.get("bytes", 0))
        except (TypeError, ValueError):
            byte_count = 0
        if byte_count < 0 or byte_count > MAX_DOWNLOAD_BYTES:
            byte_count = 0

        fetched_at = entry.get("fetched_at", "")
        if not isinstance(fetched_at, str) or len(fetched_at) > 64 or not _valid_iso_timestamp(fetched_at):
            fetched_at = ""
        validated_at = entry.get("validated_at", "")
        if not isinstance(validated_at, str) or len(validated_at) > 64 or not _valid_iso_timestamp(validated_at):
            validated_at = ""

        sanitized[url] = {
            "cache_key": source_cache_key(url),
            "content_sha256": content_sha256,
            "bytes": byte_count,
            "etag": _normalize_cache_header(entry.get("etag")),
            "last_modified": _normalize_cache_header(entry.get("last_modified")),
            "content_encoding": _normalize_cache_header(entry.get("content_encoding"), max_length=120),
            "fetched_at": fetched_at,
            "validated_at": validated_at,
        }

    return sanitized


def build_source_request_headers(cache_metadata: dict | None = None) -> dict[str, str]:
    headers = {"User-Agent": f"Mozilla/5.0 ({APP_SLUG}/{APP_VERSION})"}
    cache_metadata = cache_metadata if isinstance(cache_metadata, dict) else {}
    etag = _normalize_cache_header(cache_metadata.get("etag"))
    last_modified = _normalize_cache_header(cache_metadata.get("last_modified"))
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    return headers


def build_source_cache_metadata(
    url: str, response, raw_bytes: bytes, fetched_at: str | None = None
) -> dict[str, str | int]:
    fetched_at = fetched_at or datetime.datetime.now().isoformat(timespec="seconds")
    return {
        "cache_key": source_cache_key(url),
        "content_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "bytes": len(raw_bytes),
        "etag": _normalize_cache_header(_response_header(response, "ETag")),
        "last_modified": _normalize_cache_header(_response_header(response, "Last-Modified")),
        "content_encoding": _normalize_cache_header(
            _response_header(response, "Content-Encoding"), max_length=120
        ),
        "fetched_at": fetched_at,
        "validated_at": fetched_at,
    }


# ---------------------------- Cache I/O ------------------------------------

def write_source_cache_body(url: str, raw_bytes: bytes, cache_dir: str) -> None:
    path = get_source_cache_body_path(url, cache_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix="source_cache_", suffix=".tmp", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise


def read_source_cache_body(url: str, metadata: dict, cache_dir: str) -> bytes:
    content_sha256 = _normalize_sha256(
        metadata.get("content_sha256") if isinstance(metadata, dict) else None
    )
    if not content_sha256:
        raise FileNotFoundError("source cache metadata does not include a valid content hash")
    path = get_source_cache_body_path(url, cache_dir)
    with open(path, "rb") as f:
        raw_bytes = f.read(MAX_DOWNLOAD_BYTES + 1)
    if len(raw_bytes) > MAX_DOWNLOAD_BYTES:
        raise ValueError("cached source body exceeds the download size cap")
    actual_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    if actual_sha256 != content_sha256:
        raise ValueError("cached source body hash does not match metadata")
    return raw_bytes


def prune_orphan_source_cache_files(metadata: dict[str, dict], cache_dir: str) -> dict:
    """Delete cached source body blobs that no longer have a metadata entry.

    The source cache historically grew unbounded: when the user removed a
    custom source or a curated source's URL changed, the corresponding
    ``<sha256>.bin`` file in ``%LOCALAPPDATA%/HostsFileGet/source_cache/``
    was left behind. Over months of use this can accumulate tens of MB
    that have no live referrer. Build the set of cache keys that are still
    referenced by ``metadata`` and unlink everything else under the cache
    directory.

    Returns a dict report with ``{removed, retained, freed_bytes,
    errors}`` so callers can surface progress in the status bar or CLI
    output.
    """
    report = {"removed": 0, "retained": 0, "freed_bytes": 0, "errors": 0}
    if not cache_dir or not os.path.isdir(cache_dir):
        return report
    live_keys: set[str] = set()
    if isinstance(metadata, dict):
        for url, entry in metadata.items():
            try:
                live_keys.add(source_cache_key(str(url)))
            except Exception:
                continue
            if isinstance(entry, dict):
                fingerprint = str(entry.get("cache_key") or "").strip().lower()
                if fingerprint:
                    live_keys.add(fingerprint)
    try:
        entries = list(os.scandir(cache_dir))
    except OSError:
        return report
    for entry in entries:
        if not entry.is_file():
            continue
        name = entry.name
        # Only touch our own ``<hex>.bin`` files - leave foreign blobs and
        # other auxiliary files (e.g. README, .gitkeep) alone.
        if not name.endswith(".bin"):
            continue
        key = name[:-4]
        if len(key) != 64 or not all(ch in "0123456789abcdef" for ch in key):
            continue
        if key in live_keys:
            report["retained"] += 1
            continue
        try:
            size = entry.stat().st_size
        except OSError:
            size = 0
        try:
            os.unlink(entry.path)
        except OSError:
            report["errors"] += 1
            continue
        report["removed"] += 1
        report["freed_bytes"] += size
    return report


# ---------------------------- Redirect-locked opener -----------------------

class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject HTTP redirects to non-``http``/``https`` schemes.

    Python's stock handler already refuses ``file://`` targets on modern
    builds, but older 3.x releases were laxer and ``ftp://`` is still
    technically permitted there. We explicitly whitelist only ``http`` and
    ``https`` so a malicious feed mirror cannot bounce a blocklist download
    to ``file:///etc/...`` or an internal FTP service for SSRF probing.
    """

    _ALLOWED_REDIRECT_SCHEMES = ("http", "https")

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        scheme = urllib.parse.urlsplit(newurl).scheme.lower()
        if scheme not in self._ALLOWED_REDIRECT_SCHEMES:
            raise urllib.error.HTTPError(
                newurl,
                code,
                f"Redirect to disallowed scheme {scheme!r} blocked.",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_SAFE_URL_OPENER = urllib.request.build_opener(_HttpsOnlyRedirectHandler())


def safe_urlopen(request, timeout: float = 15):
    """Open ``request`` through the redirect-scheme-restricted opener.

    Centralizing the opener keeps the SSRF guard consistent across the
    curated-source fetch path, the whitelist web import, the preview
    pre-fetcher, and the source-health probe. All of these accept user-
    configured URLs and would otherwise expose the local machine to
    arbitrary HTTP server behavior.
    """
    return _SAFE_URL_OPENER.open(request, timeout=timeout)


# ---------------------------- Fetch loop ------------------------------------

def fetch_source_with_cache(
    url: str,
    metadata_store: dict[str, dict] | None = None,
    cache_dir: str | None = None,
    timeout: float = 15,
    opener=None,
) -> tuple[list[str], dict[str, str | int], str]:
    if opener is None:
        opener = safe_urlopen
    metadata_store = metadata_store if isinstance(metadata_store, dict) else {}
    cache_metadata = metadata_store.get(url, {})
    request = urllib.request.Request(url, headers=build_source_request_headers(cache_metadata))
    try:
        with opener(request, timeout=timeout) as response:
            status = _response_status_code(response)
            if status == 304:
                raw_bytes = read_source_cache_body(url, cache_metadata, cache_dir)
                refreshed_metadata = dict(cache_metadata)
                refreshed_metadata["validated_at"] = datetime.datetime.now().isoformat(timespec="seconds")
                lines = decode_downloaded_lines(url, raw_bytes, str(refreshed_metadata.get("content_encoding", "")))
                return lines, refreshed_metadata, "not_modified"
            if status != 200:
                raise urllib.error.HTTPError(url, status or 0, f"HTTP {status}", response.info(), response.fp)
            raw_bytes = read_http_body_limited(response)
            metadata = build_source_cache_metadata(url, response, raw_bytes)
            lines = decode_downloaded_lines(url, raw_bytes, str(metadata.get("content_encoding", "")))
            write_source_cache_body(url, raw_bytes, cache_dir)
            return lines, metadata, "network"
    except urllib.error.HTTPError as e:
        if getattr(e, "code", None) == 304:
            raw_bytes = read_source_cache_body(url, cache_metadata, cache_dir)
            refreshed_metadata = dict(cache_metadata)
            refreshed_metadata["validated_at"] = datetime.datetime.now().isoformat(timespec="seconds")
            lines = decode_downloaded_lines(url, raw_bytes, str(refreshed_metadata.get("content_encoding", "")))
            return lines, refreshed_metadata, "not_modified"
        raise
    except Exception:
        if cache_metadata:
            try:
                raw_bytes = read_source_cache_body(url, cache_metadata, cache_dir)
                lines = decode_downloaded_lines(url, raw_bytes, str(cache_metadata.get("content_encoding", "")))
                return lines, dict(cache_metadata), "cache_fallback"
            except Exception:
                pass
        raise


def resolve_import_fetch_worker_count(source_count, max_workers=IMPORT_FETCH_MAX_WORKERS) -> int:
    try:
        source_count = int(source_count)
    except (TypeError, ValueError):
        return 0
    if source_count <= 0:
        return 0
    try:
        max_workers = int(max_workers)
    except (TypeError, ValueError):
        max_workers = IMPORT_FETCH_MAX_WORKERS
    return max(1, min(source_count, max_workers))


def fetch_source_with_retries(
    url: str,
    metadata_store: dict[str, dict] | None = None,
    cache_dir: str | None = None,
    timeout: float = 15,
    max_attempts: int = IMPORT_FETCH_MAX_ATTEMPTS,
    retry_delay: float = IMPORT_FETCH_RETRY_DELAY_SECONDS,
    sleep_fn=time.sleep,
    fetch_fn=fetch_source_with_cache,
) -> tuple[list[str], dict[str, str | int], str, int]:
    try:
        attempt_limit = int(max_attempts)
    except (TypeError, ValueError):
        attempt_limit = IMPORT_FETCH_MAX_ATTEMPTS
    attempt_limit = max(1, attempt_limit)
    metadata_snapshot = dict(metadata_store) if isinstance(metadata_store, dict) else {}

    for attempt in range(1, attempt_limit + 1):
        try:
            raw_lines, cache_metadata, cache_status = fetch_fn(
                url,
                metadata_snapshot,
                cache_dir=cache_dir,
                timeout=timeout,
            )
            return raw_lines, cache_metadata, cache_status, attempt
        except Exception:
            if attempt >= attempt_limit:
                raise
            try:
                delay = float(retry_delay)
            except (TypeError, ValueError):
                delay = 0
            if delay > 0 and sleep_fn is not None:
                sleep_fn(delay)

    raise RuntimeError("source fetch retry loop exited unexpectedly")


__all__ = [
    "IMPORT_FETCH_MAX_WORKERS",
    "IMPORT_FETCH_MAX_ATTEMPTS",
    "IMPORT_FETCH_RETRY_DELAY_SECONDS",
    "_HttpsOnlyRedirectHandler",
    "_SAFE_URL_OPENER",
    "safe_urlopen",
    "_parse_valid_http_source_url",
    "normalize_custom_source_url",
    "_contains_control_chars",
    "sanitize_custom_sources",
    "_response_status_code",
    "_response_header",
    "_valid_iso_timestamp",
    "_normalize_cache_header",
    "_normalize_sha256",
    "source_cache_key",
    "get_source_cache_body_path",
    "sanitize_source_cache_metadata",
    "build_source_request_headers",
    "build_source_cache_metadata",
    "write_source_cache_body",
    "read_source_cache_body",
    "prune_orphan_source_cache_files",
    "fetch_source_with_cache",
    "fetch_source_with_retries",
    "resolve_import_fetch_worker_count",
]
