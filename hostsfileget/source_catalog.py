"""Curated source manifest, bundle, lifecycle, and health helpers.

This module is the source-catalog boundary for HostsFileGet. It owns the
bundled blocklist manifest schema, lifecycle metadata, bundle expansion, and
bounded source-health probes while staying free of GUI and config-path state.
``hosts_editor.py`` re-exports these names for compatibility with older
callers that import everything from the historical monolith.
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import datetime
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from .compression import (
    decode_downloaded_lines,
    decode_text_bytes,
    looks_like_html_document,
    read_http_body_limited,
    read_text_file_content,
)
from .constants import APP_SLUG, APP_VERSION
from .fetch import (
    _contains_control_chars,
    _parse_valid_http_source_url,
    _response_header,
    _response_status_code,
    normalize_custom_source_url,
    safe_urlopen,
)
from .normalize import normalize_line_to_hosts_entries


SOURCE_MANIFEST_SCHEMA_VERSION = 1
SOURCE_MANIFEST_RELATIVE_PATH = os.path.join("data", "blocklist_sources.json")
SOURCE_LIFECYCLE_STATES = ("active", "warning", "deprecated", "retired")
SOURCE_BUNDLE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SOURCE_BUNDLE_RISK_LEVELS = ("low", "medium", "high", "guarded")
SOURCE_HEALTH_REPORT_SCHEMA_VERSION = 1
SOURCE_HEALTH_SAMPLE_BYTES = 256 * 1024
SOURCE_HEALTH_TIMEOUT_SECONDS = 15
SOURCE_HEALTH_DEFAULT_WORKERS = 8
SOURCE_HEALTH_SUMMARY_STATUSES = ("healthy", "warning", "failed", "retired")
SOURCE_HEALTH_REMEDIATION_GROUPS = {
    "http-error": {
        "title": "HTTP Error",
        "description": "The upstream server returned an HTTP error or access/range response.",
        "action": "Review upstream status, rate limits, and direct raw-list URLs before importing.",
    },
    "download-cap": {
        "title": "Download Cap Warning",
        "description": "The source is reachable but exceeded the bounded source-health sample.",
        "action": "Keep guarded and review manually before adding it to recurring imports.",
    },
    "non-host-syntax": {
        "title": "Non-Host Syntax",
        "description": "The sample did not look like hosts/domain-list content.",
        "action": "Run syntax lint or replace the source with a hosts-compatible feed.",
    },
    "domain-list-moved": {
        "title": "Domain List Moved",
        "description": "The URL appears to return an HTML/landing page instead of a raw list.",
        "action": "Search for the provider's current raw hosts or domain-list URL.",
    },
    "unsafe-scheme": {
        "title": "Unsafe Or Invalid URL",
        "description": "The source URL is invalid or not a direct HTTP(S) feed URL.",
        "action": "Fix the manifest URL or retire the source until a safe replacement exists.",
    },
    "timeout": {
        "title": "Timeout",
        "description": "The source did not respond within the bounded health-check timeout.",
        "action": "Retry later and avoid unattended imports until reachability is stable.",
    },
    "retired": {
        "title": "Retired",
        "description": "The curated manifest already marks the source as retired.",
        "action": "Use the documented replacement or reactivate only after a URL audit.",
    },
    "other": {
        "title": "Manual Review",
        "description": "The source needs manual review before routine use.",
        "action": "Inspect the diagnostic and keep the source out of default bundles until resolved.",
    },
}
SOURCE_HEALTH_DIAGNOSTIC_GROUPS = {
    "http-gone": "http-error",
    "http-access": "http-error",
    "http-error": "http-error",
    "sample-cap": "download-cap",
    "non-host-like": "non-host-syntax",
    "empty-sample": "non-host-syntax",
    "html-response": "domain-list-moved",
    "invalid-url": "unsafe-scheme",
    "timeout": "timeout",
    "network-error": "timeout",
    "retired": "retired",
}


def _default_bundle_dir() -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _coerce_source_manifest_schema_version(value) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def utc_timestamp() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class SourceEntry(tuple):
    """3-tuple source entry with optional manifest metadata attached."""

    def __new__(cls, name: str, url: str, description: str, metadata: dict | None = None):
        entry = super().__new__(cls, (name, url, description))
        entry.metadata = dict(metadata or {})
        return entry


@dataclasses.dataclass(frozen=True)
class SourceRecord:
    """Stable normalized source shape used by catalog, bundles, and health."""

    category: str
    name: str
    url: str
    description: str = ""
    lifecycle: str = "active"
    metadata: dict = dataclasses.field(default_factory=dict)

    @classmethod
    def from_entry(cls, category: str, source) -> "SourceRecord | None":
        if isinstance(source, SourceRecord):
            return source
        if isinstance(source, dict):
            name = str(source.get("name", "")).strip()
            url = str(source.get("url", "")).strip()
            description = str(source.get("description", "")).strip()
            if not name or not url:
                return None
            metadata = source_entry_metadata(source)
            return cls(
                category=str(source.get("category") or category),
                name=name,
                url=url,
                description=description,
                lifecycle=source_lifecycle_state(source),
                metadata=metadata,
            )
        if not isinstance(source, (list, tuple)) or len(source) < 2:
            return None
        name = str(source[0]).strip()
        url = str(source[1]).strip()
        description = str(source[2]).strip() if len(source) > 2 else ""
        if not name or not url:
            return None
        metadata = source_entry_metadata(source)
        return cls(
            category=str(category),
            name=name,
            url=url,
            description=description,
            lifecycle=source_lifecycle_state(source),
            metadata=metadata,
        )

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "name": self.name,
            "url": self.url,
            "description": self.description,
            "lifecycle": self.lifecycle,
            "metadata": dict(self.metadata or {}),
        }


@dataclasses.dataclass(frozen=True)
class SourceHealthRecord:
    """Stable JSON-compatible source-health result shape."""

    category: str
    name: str
    url: str
    lifecycle: str
    lifecycle_reason: str = ""
    checked_at: str = ""
    status: str = "failed"
    http_status: int | None = None
    content_type: str = ""
    bytes_read: int = 0
    sample_lines: int = 0
    elapsed_ms: int = 0
    diagnostic_class: str = "unknown"
    diagnostic: str = ""
    remediation: str = ""

    @classmethod
    def from_dict(cls, payload: dict) -> "SourceHealthRecord":
        return cls(
            category=str(payload.get("category", "")).strip(),
            name=str(payload.get("name", "")).strip(),
            url=str(payload.get("url", "")).strip(),
            lifecycle=str(payload.get("lifecycle", "active")).strip() or "active",
            lifecycle_reason=str(payload.get("lifecycle_reason", "")).strip(),
            checked_at=str(payload.get("checked_at", "")).strip(),
            status=str(payload.get("status", "failed")).strip() or "failed",
            http_status=payload.get("http_status"),
            content_type=str(payload.get("content_type", "")).strip(),
            bytes_read=int(payload.get("bytes_read") or 0),
            sample_lines=int(payload.get("sample_lines") or 0),
            elapsed_ms=int(payload.get("elapsed_ms") or 0),
            diagnostic_class=str(payload.get("diagnostic_class", "unknown")).strip() or "unknown",
            diagnostic=str(payload.get("diagnostic", "")).strip(),
            remediation=str(payload.get("remediation", "")).strip(),
        )

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def sanitize_source_lifecycle(value) -> str:
    lifecycle = str(value or "active").strip().lower()
    if lifecycle not in SOURCE_LIFECYCLE_STATES:
        raise ValueError(
            f"Source lifecycle {value!r} is invalid; expected one of "
            f"{', '.join(SOURCE_LIFECYCLE_STATES)}."
        )
    return lifecycle


def source_entry_metadata(source) -> dict:
    if isinstance(source, SourceRecord):
        metadata = dict(source.metadata or {})
        metadata.setdefault("lifecycle", source.lifecycle)
        return metadata
    if isinstance(source, dict):
        metadata = source.get("metadata")
        if isinstance(metadata, dict):
            base = dict(metadata)
        else:
            base = {}
        for key in (
            "lifecycle",
            "lifecycle_reason",
            "lifecycle_checked_at",
            "replacement_url",
            "replacement_source",
            "notes",
        ):
            if key in source:
                base[key] = source.get(key)
        return base
    metadata = getattr(source, "metadata", None)
    return dict(metadata or {}) if isinstance(metadata, dict) else {}


def source_lifecycle_state(source) -> str:
    try:
        return sanitize_source_lifecycle(source_entry_metadata(source).get("lifecycle"))
    except ValueError:
        return "active"


def format_source_lifecycle_label(metadata: dict | None) -> str:
    metadata = dict(metadata or {})
    lifecycle = sanitize_source_lifecycle(metadata.get("lifecycle"))
    if lifecycle == "active":
        return "Lifecycle: active"
    reason = str(metadata.get("lifecycle_reason", "")).strip()
    if reason:
        return f"Lifecycle: {lifecycle} - {reason}"
    return f"Lifecycle: {lifecycle}"


def format_source_lifecycle_details(metadata: dict | None) -> str:
    metadata = dict(metadata or {})
    lifecycle = sanitize_source_lifecycle(metadata.get("lifecycle"))
    lines = [format_source_lifecycle_label(metadata)]
    replacement = str(metadata.get("replacement_source") or metadata.get("replacement_url") or "").strip()
    notes = str(metadata.get("notes", "")).strip()
    checked_at = str(metadata.get("lifecycle_checked_at", "")).strip()
    if replacement:
        lines.append(f"Replacement: {replacement}")
    if checked_at:
        lines.append(f"Lifecycle evidence: {checked_at}")
    if notes:
        lines.append(f"Notes: {notes}")
    if lifecycle == "retired":
        lines.append("Retired sources are shown for history but are disabled for one-click import and bundle selection.")
    return "\n".join(lines)


def sanitize_source_manifest_records(manifest) -> dict[str, list[SourceEntry]]:
    """Validate and normalize the bundled curated-source manifest with metadata."""
    if not isinstance(manifest, dict):
        raise ValueError("Source manifest must be a JSON object.")

    version = _coerce_source_manifest_schema_version(manifest.get("schema_version"))
    if version != SOURCE_MANIFEST_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported source manifest schema_version {manifest.get('schema_version')!r}; "
            f"expected {SOURCE_MANIFEST_SCHEMA_VERSION}."
        )

    categories = manifest.get("categories")
    if not isinstance(categories, list) or not categories:
        raise ValueError("Source manifest must contain a non-empty categories list.")

    sanitized: dict[str, list[SourceEntry]] = {}
    seen_categories = set()
    seen_source_names = set()
    seen_source_urls = set()

    for category_index, category_payload in enumerate(categories, start=1):
        if not isinstance(category_payload, dict):
            raise ValueError(f"Source manifest category {category_index} must be an object.")

        category_name = str(category_payload.get("name", "")).strip()
        if not category_name:
            raise ValueError(f"Source manifest category {category_index} is missing a name.")
        if len(category_name) > 120 or _contains_control_chars(category_name):
            raise ValueError(f"Source manifest category {category_name!r} has an invalid name.")

        normalized_category_name = category_name.lower()
        if normalized_category_name in seen_categories:
            raise ValueError(f"Source manifest category {category_name!r} is duplicated.")
        seen_categories.add(normalized_category_name)

        sources = category_payload.get("sources")
        if not isinstance(sources, list) or not sources:
            raise ValueError(f"Source manifest category {category_name!r} must contain sources.")

        sanitized_sources: list[SourceEntry] = []
        for source_index, source_payload in enumerate(sources, start=1):
            if not isinstance(source_payload, dict):
                raise ValueError(
                    f"Source manifest entry {category_name!r} #{source_index} must be an object."
                )

            source_name = str(source_payload.get("name", "")).strip()
            source_url = str(source_payload.get("url", "")).strip()
            source_description = str(source_payload.get("description", "")).strip()
            lifecycle = sanitize_source_lifecycle(source_payload.get("lifecycle", "active"))
            lifecycle_reason = str(source_payload.get("lifecycle_reason", "")).strip()
            lifecycle_checked_at = str(source_payload.get("lifecycle_checked_at", "")).strip()
            replacement_url = str(source_payload.get("replacement_url", "")).strip()
            replacement_source = str(source_payload.get("replacement_source", "")).strip()
            notes = str(source_payload.get("notes", "")).strip()

            if not source_name or len(source_name) > 120 or _contains_control_chars(source_name):
                raise ValueError(
                    f"Source manifest entry {category_name!r} #{source_index} has an invalid name."
                )
            if (
                not source_url
                or len(source_url) > 2083
                or _contains_control_chars(source_url)
                or _parse_valid_http_source_url(source_url) is None
            ):
                raise ValueError(f"Source manifest entry {source_name!r} has an invalid URL.")
            if len(source_description) > 500 or _contains_control_chars(source_description):
                raise ValueError(f"Source manifest entry {source_name!r} has an invalid description.")
            if len(lifecycle_reason) > 300 or _contains_control_chars(lifecycle_reason):
                raise ValueError(f"Source manifest entry {source_name!r} has an invalid lifecycle_reason.")
            if len(lifecycle_checked_at) > 40 or _contains_control_chars(lifecycle_checked_at):
                raise ValueError(f"Source manifest entry {source_name!r} has an invalid lifecycle_checked_at.")
            if (
                replacement_url
                and (
                    len(replacement_url) > 2083
                    or _contains_control_chars(replacement_url)
                    or _parse_valid_http_source_url(replacement_url) is None
                )
            ):
                raise ValueError(f"Source manifest entry {source_name!r} has an invalid replacement_url.")
            if len(replacement_source) > 120 or _contains_control_chars(replacement_source):
                raise ValueError(f"Source manifest entry {source_name!r} has an invalid replacement_source.")
            if len(notes) > 500 or _contains_control_chars(notes):
                raise ValueError(f"Source manifest entry {source_name!r} has invalid notes.")

            normalized_source_name = source_name.lower()
            normalized_source_url = normalize_custom_source_url(source_url)
            if normalized_source_name in seen_source_names:
                raise ValueError(f"Source manifest entry {source_name!r} is duplicated.")
            if normalized_source_url in seen_source_urls:
                raise ValueError(f"Source manifest URL {source_url!r} is duplicated.")

            seen_source_names.add(normalized_source_name)
            seen_source_urls.add(normalized_source_url)
            metadata = {
                "lifecycle": lifecycle,
                "lifecycle_reason": lifecycle_reason,
                "lifecycle_checked_at": lifecycle_checked_at,
                "replacement_url": replacement_url,
                "replacement_source": replacement_source,
                "notes": notes,
            }
            sanitized_sources.append(SourceEntry(source_name, source_url, source_description, metadata))

        sanitized[category_name] = sanitized_sources

    return sanitized


def sanitize_source_manifest(manifest) -> dict[str, list[tuple[str, str, str]]]:
    """Validate and normalize the bundled curated-source manifest."""
    return sanitize_source_manifest_records(manifest)


def load_blocklist_sources_manifest(path: str | None = None) -> dict[str, list[tuple[str, str, str]]]:
    manifest_path = path or os.path.join(_default_bundle_dir(), SOURCE_MANIFEST_RELATIVE_PATH)
    try:
        payload = json.loads(read_text_file_content(manifest_path))
    except json.JSONDecodeError as e:
        raise ValueError(f"Source manifest JSON is invalid: {e}") from e
    except OSError as e:
        raise ValueError(f"Source manifest could not be read from {manifest_path!r}: {e}") from e

    return sanitize_source_manifest(payload)


def build_source_manifest_index(blocklist_sources) -> dict[str, dict]:
    """Index sanitized curated source tuples by their display name."""
    index: dict[str, dict] = {}
    if not isinstance(blocklist_sources, dict):
        return index
    for category, sources in blocklist_sources.items():
        if not isinstance(sources, (list, tuple)):
            continue
        for source in sources:
            record = SourceRecord.from_entry(str(category), source)
            if record is None or record.name in index:
                continue
            index[record.name] = record.to_dict()
    return index


def iter_curated_source_records(blocklist_sources: dict[str, list[tuple[str, str, str]]]):
    if not isinstance(blocklist_sources, dict):
        return
    for category, sources in blocklist_sources.items():
        if not isinstance(sources, (list, tuple)):
            continue
        for source in sources:
            record = SourceRecord.from_entry(str(category), source)
            if record is not None:
                yield record.to_dict()


def sanitize_source_bundle_id(value) -> str:
    bundle_id = str(value or "").strip().lower()
    if not SOURCE_BUNDLE_ID_PATTERN.match(bundle_id):
        raise ValueError(f"Source bundle id {value!r} is invalid.")
    return bundle_id


def sanitize_source_bundle_catalog(manifest, blocklist_sources=None) -> list[dict]:
    """Validate optional import bundles that reference manifest source names."""
    if not isinstance(manifest, dict):
        raise ValueError("Source manifest must be a JSON object.")

    version = _coerce_source_manifest_schema_version(manifest.get("schema_version"))
    if version != SOURCE_MANIFEST_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported source manifest schema_version {manifest.get('schema_version')!r}; "
            f"expected {SOURCE_MANIFEST_SCHEMA_VERSION}."
        )

    if blocklist_sources is None:
        blocklist_sources = sanitize_source_manifest(manifest)
    source_index = build_source_manifest_index(blocklist_sources)
    source_index_by_name = {name.lower(): record for name, record in source_index.items()}

    bundles = manifest.get("bundles", [])
    if bundles in (None, ""):
        return []
    if not isinstance(bundles, list):
        raise ValueError("Source manifest bundles must be a list when present.")

    sanitized: list[dict] = []
    seen_bundle_ids = set()
    seen_bundle_names = set()
    for bundle_index, bundle_payload in enumerate(bundles, start=1):
        if not isinstance(bundle_payload, dict):
            raise ValueError(f"Source bundle {bundle_index} must be an object.")

        bundle_id = sanitize_source_bundle_id(bundle_payload.get("id"))
        name = str(bundle_payload.get("name", "")).strip()
        description = str(bundle_payload.get("description", "")).strip()
        risk = str(bundle_payload.get("risk", "medium")).strip().lower()

        if not name or len(name) > 120 or _contains_control_chars(name):
            raise ValueError(f"Source bundle {bundle_id!r} has an invalid name.")
        if len(description) > 700 or _contains_control_chars(description):
            raise ValueError(f"Source bundle {bundle_id!r} has an invalid description.")
        if risk not in SOURCE_BUNDLE_RISK_LEVELS:
            raise ValueError(
                f"Source bundle {bundle_id!r} has unsupported risk {risk!r}; "
                f"expected one of {', '.join(SOURCE_BUNDLE_RISK_LEVELS)}."
            )

        normalized_name = name.lower()
        if bundle_id in seen_bundle_ids:
            raise ValueError(f"Source bundle id {bundle_id!r} is duplicated.")
        if normalized_name in seen_bundle_names:
            raise ValueError(f"Source bundle name {name!r} is duplicated.")
        seen_bundle_ids.add(bundle_id)
        seen_bundle_names.add(normalized_name)

        source_names = bundle_payload.get("source_names")
        if not isinstance(source_names, list) or not source_names:
            raise ValueError(f"Source bundle {bundle_id!r} must contain source_names.")

        sources: list[dict] = []
        seen_sources = set()
        for source_index_in_bundle, raw_source_name in enumerate(source_names, start=1):
            source_name = str(raw_source_name or "").strip()
            if (
                not source_name
                or len(source_name) > 120
                or _contains_control_chars(source_name)
            ):
                raise ValueError(
                    f"Source bundle {bundle_id!r} source #{source_index_in_bundle} "
                    "has an invalid name."
                )
            normalized_source_name = source_name.lower()
            if normalized_source_name in seen_sources:
                raise ValueError(f"Source bundle {bundle_id!r} repeats source {source_name!r}.")
            source_record = source_index_by_name.get(normalized_source_name)
            if source_record is None:
                raise ValueError(f"Source bundle {bundle_id!r} references unknown source {source_name!r}.")
            if source_record.get("lifecycle") == "retired":
                raise ValueError(f"Source bundle {bundle_id!r} references retired source {source_name!r}.")
            seen_sources.add(normalized_source_name)
            sources.append(dict(source_record))

        sanitized.append({
            "id": bundle_id,
            "name": name,
            "description": description,
            "risk": risk,
            "source_count": len(sources),
            "sources": sources,
        })

    return sanitized


def load_source_bundle_catalog(path: str | None = None, blocklist_sources=None) -> list[dict]:
    manifest_path = path or os.path.join(_default_bundle_dir(), SOURCE_MANIFEST_RELATIVE_PATH)
    try:
        payload = json.loads(read_text_file_content(manifest_path))
    except json.JSONDecodeError as e:
        raise ValueError(f"Source manifest JSON is invalid: {e}") from e
    except OSError as e:
        raise ValueError(f"Source manifest could not be read from {manifest_path!r}: {e}") from e

    return sanitize_source_bundle_catalog(payload, blocklist_sources=blocklist_sources)


def find_source_bundle(bundle_catalog, bundle_id_or_name: str) -> dict | None:
    needle = str(bundle_id_or_name or "").strip().lower()
    if not needle:
        return None
    for bundle in bundle_catalog or []:
        if not isinstance(bundle, dict):
            continue
        if str(bundle.get("id", "")).lower() == needle:
            return bundle
        if str(bundle.get("name", "")).lower() == needle:
            return bundle
    return None


def source_bundle_to_import_sources(bundle: dict) -> list[tuple[str, str]]:
    return [
        (str(source.get("name", "")), str(source.get("url", "")))
        for source in (bundle or {}).get("sources", [])
        if isinstance(source, dict) and source.get("name") and source.get("url")
    ]


def format_source_bundle_catalog(bundle_catalog) -> str:
    bundles = [bundle for bundle in (bundle_catalog or []) if isinstance(bundle, dict)]
    lines = [
        "Source Bundle Catalog",
        f"Bundles: {len(bundles)}",
    ]
    if not bundles:
        lines.extend(["", "- No source bundles are configured."])
        return "\n".join(lines)

    for bundle in bundles:
        lines.append("")
        lines.append(
            f"- {bundle.get('name', 'Unnamed bundle')} "
            f"({bundle.get('id', '')}; risk: {bundle.get('risk', 'medium')}; "
            f"sources: {int(bundle.get('source_count') or 0)})"
        )
        description = str(bundle.get("description", "")).strip()
        if description:
            lines.append(f"  {description}")
        source_names = [
            str(source.get("name", "")).strip()
            for source in bundle.get("sources", [])
            if isinstance(source, dict) and source.get("name")
        ]
        if source_names:
            lines.append(f"  Sources: {', '.join(source_names)}")
    return "\n".join(lines)


def format_source_bundle_report(bundle: dict | None) -> str:
    if not bundle:
        return "Source Bundle\n(no bundle selected)"

    lines = [
        f"Source Bundle: {bundle.get('name', 'Unnamed bundle')}",
        f"ID: {bundle.get('id', '')}",
        f"Risk: {bundle.get('risk', 'medium')}",
        f"Sources: {int(bundle.get('source_count') or 0)}",
    ]
    description = str(bundle.get("description", "")).strip()
    if description:
        lines.extend(["", description])

    lines.append("")
    lines.append("Import sources:")
    sources = [source for source in bundle.get("sources", []) if isinstance(source, dict)]
    if not sources:
        lines.append("- None")
        return "\n".join(lines)
    for source in sources:
        category = str(source.get("category", "")).strip()
        suffix = f" [{category}]" if category else ""
        lifecycle = str(source.get("lifecycle", "active")).strip().lower() or "active"
        lifecycle_suffix = "" if lifecycle == "active" else f" ({lifecycle})"
        lines.append(f"- {source.get('name', 'Unnamed source')}{suffix}{lifecycle_suffix}")
        source_description = str(source.get("description", "")).strip()
        if source_description:
            lines.append(f"  {source_description}")
        metadata = source_entry_metadata(source)
        if lifecycle != "active":
            lines.append(f"  {format_source_lifecycle_label(metadata)}")
    return "\n".join(lines)


def _sample_contains_host_like_content(lines: list[str]) -> bool:
    for line in lines[:200]:
        entries, domains, _ = normalize_line_to_hosts_entries(line)
        if entries or domains:
            return True
    return False


def _source_health_base_result(source: dict, checked_at: str) -> dict:
    metadata = source_entry_metadata(source)
    lifecycle = source_lifecycle_state(source)
    return SourceHealthRecord(
        category=str(source.get("category", "")).strip(),
        name=str(source.get("name", "")).strip(),
        url=str(source.get("url", "")).strip(),
        lifecycle=lifecycle,
        lifecycle_reason=str(metadata.get("lifecycle_reason", "")).strip(),
        checked_at=checked_at,
    ).to_dict()


def classify_source_health_diagnostic(
    status: str,
    diagnostic: str,
    http_status: int | None = None,
) -> tuple[str, str]:
    status = str(status or "").strip().lower()
    diagnostic_text = str(diagnostic or "")
    diagnostic_lower = diagnostic_text.lower()
    if status == "healthy":
        return "ok", "No action needed."
    if status == "retired":
        return (
            "retired",
            "Retired sources are disabled; choose the documented replacement or reactivate only after a URL audit.",
        )
    if "invalid source url" in diagnostic_lower:
        return "invalid-url", "Fix or retire the manifest URL."
    if "exceeded the cap" in diagnostic_lower:
        return "sample-cap", "Reachable but too large for the bounded health sample; keep guarded and review before scheduling."
    if "html page" in diagnostic_lower:
        return "html-response", "Replace landing-page URLs with a direct raw list URL."
    if "empty sample" in diagnostic_lower:
        return "empty-sample", "Review whether the upstream list is intentionally empty or should be retired."
    if "did not contain host-like" in diagnostic_lower:
        return "non-host-like", "Run syntax lint or replace with a hosts/domain-compatible source."
    if "timeout" in diagnostic_lower:
        return "timeout", "Retry later and avoid unattended use until the source is consistently reachable."
    if "network error" in diagnostic_lower:
        return "network-error", "Retry later and keep the source guarded until the network failure is understood."
    if (http_status is not None and http_status >= 400) or diagnostic_lower.startswith("http "):
        if http_status in {404, 410}:
            return "http-gone", "Retire the source or replace it with a currently maintained URL."
        if http_status in {401, 403, 416, 429}:
            return "http-access", "Review provider access, range support, or rate limits before using this source in bundles."
        return "http-error", "Review the upstream status and keep the source out of default bundles until it is healthy."
    return "unknown", "Review the source manually before using it in recurring imports."


def check_source_health_record(
    source: dict,
    opener=None,
    timeout: float = SOURCE_HEALTH_TIMEOUT_SECONDS,
    sample_bytes: int = SOURCE_HEALTH_SAMPLE_BYTES,
) -> dict:
    """Fetch a bounded sample from one curated source and classify reachability."""
    if opener is None:
        opener = safe_urlopen
    checked_at = utc_timestamp()
    result = _source_health_base_result(source, checked_at)
    started = time.monotonic()

    def finish(status: str, diagnostic: str) -> dict:
        result["status"] = status
        result["diagnostic"] = diagnostic
        diagnostic_class, remediation = classify_source_health_diagnostic(
            status,
            diagnostic,
            result.get("http_status"),
        )
        result["diagnostic_class"] = diagnostic_class
        result["remediation"] = remediation
        result["elapsed_ms"] = max(0, int((time.monotonic() - started) * 1000))
        return result

    if result["lifecycle"] == "retired":
        reason = result.get("lifecycle_reason") or "Source is marked retired in the curated manifest."
        return finish("retired", reason)

    parsed = _parse_valid_http_source_url(result["url"])
    if parsed is None:
        return finish("failed", "Invalid source URL.")

    try:
        timeout = max(1.0, float(timeout))
    except (TypeError, ValueError):
        timeout = SOURCE_HEALTH_TIMEOUT_SECONDS
    try:
        sample_bytes = max(1024, int(sample_bytes))
    except (TypeError, ValueError):
        sample_bytes = SOURCE_HEALTH_SAMPLE_BYTES

    request = urllib.request.Request(
        result["url"],
        headers={
            "User-Agent": f"{APP_SLUG}/{APP_VERSION} source-health",
            "Accept": "text/plain,*/*;q=0.5",
            "Range": f"bytes=0-{sample_bytes - 1}",
        },
    )

    try:
        with opener(request, timeout=timeout) as response:
            result["http_status"] = _response_status_code(response)
            result["content_type"] = _response_header(response, "Content-Type")
            content_encoding = _response_header(response, "Content-Encoding")
            if result["http_status"] and result["http_status"] >= 400:
                return finish("failed", f"HTTP {result['http_status']}.")

            try:
                raw = read_http_body_limited(response, sample_bytes)
            except ValueError as e:
                return finish("warning", f"Source is reachable, but the sample exceeded the cap: {e}")
            result["bytes_read"] = len(raw)
            if not raw:
                return finish("warning", "Source responded with an empty sample.")

            try:
                lines = decode_downloaded_lines(result["url"], raw, content_encoding)
            except Exception:
                lines = decode_text_bytes(raw).splitlines()

            result["sample_lines"] = len(lines)
            if looks_like_html_document(lines):
                return finish("failed", "Source returned an HTML page instead of a list sample.")
            if not _sample_contains_host_like_content(lines):
                return finish("warning", "Source is reachable, but the sample did not contain host-like entries.")

            return finish("healthy", "Source is reachable and returned host-like content.")
    except urllib.error.HTTPError as e:
        result["http_status"] = getattr(e, "code", None)
        return finish("failed", f"HTTP {getattr(e, 'code', 'error')}.")
    except urllib.error.URLError as e:
        return finish("failed", f"Network error: {getattr(e, 'reason', e)}")
    except TimeoutError:
        return finish("failed", "Network timeout.")
    except Exception as e:
        return finish("failed", f"Health check failed: {e}")


def check_source_health_records(
    records: list[dict],
    opener=None,
    timeout: float = SOURCE_HEALTH_TIMEOUT_SECONDS,
    sample_bytes: int = SOURCE_HEALTH_SAMPLE_BYTES,
    max_workers: int = SOURCE_HEALTH_DEFAULT_WORKERS,
) -> list[dict]:
    records = list(records)
    if not records:
        return []
    try:
        worker_count = int(max_workers)
    except (TypeError, ValueError):
        worker_count = SOURCE_HEALTH_DEFAULT_WORKERS
    worker_count = max(1, min(worker_count, len(records)))

    if worker_count == 1:
        return [
            check_source_health_record(record, opener=opener, timeout=timeout, sample_bytes=sample_bytes)
            for record in records
        ]

    results: list[dict | None] = [None] * len(records)
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_index = {
            executor.submit(check_source_health_record, record, opener, timeout, sample_bytes): index
            for index, record in enumerate(records)
        }
        for future in concurrent.futures.as_completed(future_to_index):
            results[future_to_index[future]] = future.result()

    return [result for result in results if result is not None]


def summarize_source_health_results(results: list[dict]) -> dict:
    summary = {"total": len(results)}
    for status in SOURCE_HEALTH_SUMMARY_STATUSES:
        summary[status] = 0
    for result in results:
        status = result.get("status")
        if status in summary:
            summary[status] += 1
        else:
            summary["failed"] += 1
    return summary


def source_health_remediation_group_id(source: dict) -> str:
    diagnostic_class = str(source.get("diagnostic_class", "")).strip().lower()
    if diagnostic_class in SOURCE_HEALTH_DIAGNOSTIC_GROUPS:
        return SOURCE_HEALTH_DIAGNOSTIC_GROUPS[diagnostic_class]
    diagnostic = str(source.get("diagnostic", "")).lower()
    if diagnostic.startswith("http ") or " http " in diagnostic:
        return "http-error"
    if "exceeded the cap" in diagnostic:
        return "download-cap"
    if "html" in diagnostic:
        return "domain-list-moved"
    if "invalid source url" in diagnostic or "invalid url" in diagnostic:
        return "unsafe-scheme"
    if "did not contain host-like" in diagnostic or "empty sample" in diagnostic:
        return "non-host-syntax"
    if "timeout" in diagnostic:
        return "timeout"
    if str(source.get("status", "")).strip().lower() == "retired":
        return "retired"
    return "other"


def build_source_health_replacement_search_terms(source: dict) -> str:
    name = " ".join(str(source.get("name") or "").split())
    url = str(source.get("url") or "").strip()
    host = ""
    try:
        host = urllib.parse.urlparse(url).netloc
    except Exception:
        host = ""
    diagnostic_class = str(source.get("diagnostic_class") or "").strip()
    terms = [value for value in (name, host, "hosts file", "raw domain list", diagnostic_class) if value]
    return " ".join(dict.fromkeys(terms))


def build_source_health_remediation_report(health_report: dict) -> dict:
    groups = {
        group_id: {
            "id": group_id,
            "title": metadata["title"],
            "description": metadata["description"],
            "action": metadata["action"],
            "sources": [],
        }
        for group_id, metadata in SOURCE_HEALTH_REMEDIATION_GROUPS.items()
    }
    summary = {
        "total": 0,
        "healthy": 0,
        "warning": 0,
        "failed": 0,
        "retired": 0,
        "grouped": 0,
    }
    for source in health_report.get("sources", []):
        if not isinstance(source, dict):
            continue
        status = str(source.get("status") or "failed").strip().lower()
        summary["total"] += 1
        if status in summary:
            summary[status] += 1
        if status == "healthy":
            continue
        group_id = source_health_remediation_group_id(source)
        if group_id not in groups:
            group_id = "other"
        row = dict(source)
        row["search_terms"] = build_source_health_replacement_search_terms(row)
        groups[group_id]["sources"].append(row)
        summary["grouped"] += 1

    ordered_groups = [
        groups[group_id]
        for group_id in (
            "http-error",
            "domain-list-moved",
            "download-cap",
            "non-host-syntax",
            "unsafe-scheme",
            "timeout",
            "retired",
            "other",
        )
        if groups[group_id]["sources"]
    ]
    return {
        "schema": "hostsfileget.source-health-remediation.v1",
        "checked_at": health_report.get("checked_at", ""),
        "summary": summary,
        "groups": ordered_groups,
        "search_terms": [
            source["search_terms"]
            for group in ordered_groups
            for source in group["sources"]
            if source.get("search_terms")
        ],
        "failed_urls": [
            source.get("url", "")
            for source in health_report.get("sources", [])
            if isinstance(source, dict) and source.get("status") == "failed" and source.get("url")
        ],
    }


def format_source_health_remediation_report(report: dict) -> str:
    summary = report.get("summary") or {}
    lines = [
        "Source Health Remediation",
        f"Checked at: {report.get('checked_at') or '(unknown)'}",
        (
            "Summary: "
            f"{summary.get('healthy', 0)} healthy, "
            f"{summary.get('warning', 0)} warning, "
            f"{summary.get('failed', 0)} failed, "
            f"{summary.get('retired', 0)} retired."
        ),
    ]
    groups = report.get("groups") or []
    if not groups:
        lines.append("")
        lines.append("No unhealthy sources were found.")
        return "\n".join(lines)
    for group in groups:
        sources = group.get("sources") or []
        lines.extend([
            "",
            f"{group.get('title', 'Manual Review')} ({len(sources)})",
            str(group.get("description") or "").strip(),
            f"Action: {group.get('action') or '-'}",
        ])
        for source in sources[:25]:
            lines.append(
                f"- {source.get('name', '')} [{source.get('status', '')}] "
                f"{source.get('diagnostic', '')}"
            )
            if source.get("remediation"):
                lines.append(f"  Remediation: {source.get('remediation')}")
            if source.get("search_terms"):
                lines.append(f"  Search: {source.get('search_terms')}")
        if len(sources) > 25:
            lines.append(f"- ...and {len(sources) - 25} more source(s).")
    return "\n".join(lines)


def _source_health_diff_key(source: dict) -> tuple[str, str]:
    name = str(source.get("name", "")).strip().lower()
    url = normalize_custom_source_url(str(source.get("url", "")).strip()) or str(source.get("url", "")).strip()
    return name, url.lower()


def build_source_health_diff(current_report: dict, baseline_report: dict) -> dict:
    current_sources = {
        _source_health_diff_key(source): source
        for source in current_report.get("sources", [])
        if isinstance(source, dict)
    }
    baseline_sources = {
        _source_health_diff_key(source): source
        for source in baseline_report.get("sources", [])
        if isinstance(source, dict)
    }
    severity = {"healthy": 0, "retired": 0, "warning": 1, "failed": 2}
    changes: list[dict] = []
    summary = {
        "new": 0,
        "removed": 0,
        "status_changed": 0,
        "improved": 0,
        "regressed": 0,
        "unchanged": 0,
    }

    for key in sorted(set(current_sources) | set(baseline_sources)):
        current = current_sources.get(key)
        baseline = baseline_sources.get(key)
        if current is None:
            summary["removed"] += 1
            changes.append({
                "change": "removed",
                "name": baseline.get("name", ""),
                "url": baseline.get("url", ""),
                "baseline_status": baseline.get("status", ""),
                "current_status": "",
                "baseline_diagnostic": baseline.get("diagnostic", ""),
                "current_diagnostic": "",
            })
            continue
        if baseline is None:
            summary["new"] += 1
            changes.append({
                "change": "new",
                "name": current.get("name", ""),
                "url": current.get("url", ""),
                "baseline_status": "",
                "current_status": current.get("status", ""),
                "baseline_diagnostic": "",
                "current_diagnostic": current.get("diagnostic", ""),
            })
            continue

        baseline_status = str(baseline.get("status", "failed"))
        current_status = str(current.get("status", "failed"))
        if baseline_status == current_status:
            summary["unchanged"] += 1
            continue

        summary["status_changed"] += 1
        baseline_severity = severity.get(baseline_status, 2)
        current_severity = severity.get(current_status, 2)
        if current_severity > baseline_severity:
            change = "regressed"
            summary["regressed"] += 1
        elif current_severity < baseline_severity:
            change = "improved"
            summary["improved"] += 1
        else:
            change = "changed"
        changes.append({
            "change": change,
            "name": current.get("name", baseline.get("name", "")),
            "url": current.get("url", baseline.get("url", "")),
            "baseline_status": baseline_status,
            "current_status": current_status,
            "baseline_diagnostic": baseline.get("diagnostic", ""),
            "current_diagnostic": current.get("diagnostic", ""),
        })

    return {
        "schema": "hostsfileget.source-health-diff.v1",
        "baseline_checked_at": baseline_report.get("checked_at", ""),
        "current_checked_at": current_report.get("checked_at", ""),
        "summary": summary,
        "changes": changes,
    }


def format_source_health_diff(diff: dict) -> str:
    summary = diff.get("summary") or {}
    lines = [
        "Source Health Diff",
        f"Baseline checked at: {diff.get('baseline_checked_at', '') or '(unknown)'}",
        f"Current checked at: {diff.get('current_checked_at', '') or '(unknown)'}",
        (
            "Summary: "
            f"{summary.get('improved', 0)} improved, "
            f"{summary.get('regressed', 0)} regressed, "
            f"{summary.get('status_changed', 0)} status changed, "
            f"{summary.get('new', 0)} new, "
            f"{summary.get('removed', 0)} removed."
        ),
    ]
    changes = diff.get("changes") or []
    if not changes:
        lines.append("No source-health status changes.")
        return "\n".join(lines)
    lines.append("")
    lines.append("Changes:")
    for change in changes[:50]:
        lines.append(
            f"- {change.get('name', '')}: "
            f"{change.get('baseline_status', '') or '(missing)'} -> "
            f"{change.get('current_status', '') or '(missing)'} "
            f"({change.get('change', 'changed')})"
        )
        current_diagnostic = str(change.get("current_diagnostic", "")).strip()
        if current_diagnostic:
            lines.append(f"  Current: {current_diagnostic}")
    if len(changes) > 50:
        lines.append(f"- ...and {len(changes) - 50} more change(s).")
    return "\n".join(lines)


def build_source_health_report(
    blocklist_sources: dict[str, list[tuple[str, str, str]]],
    opener=None,
    timeout: float = SOURCE_HEALTH_TIMEOUT_SECONDS,
    sample_bytes: int = SOURCE_HEALTH_SAMPLE_BYTES,
    max_workers: int = SOURCE_HEALTH_DEFAULT_WORKERS,
) -> dict:
    records = list(iter_curated_source_records(blocklist_sources))
    results = check_source_health_records(
        records,
        opener=opener,
        timeout=timeout,
        sample_bytes=sample_bytes,
        max_workers=max_workers,
    )
    return {
        "schema_version": SOURCE_HEALTH_REPORT_SCHEMA_VERSION,
        "checked_at": utc_timestamp(),
        "summary": summarize_source_health_results(results),
        "sources": results,
    }


__all__ = [
    "SOURCE_MANIFEST_SCHEMA_VERSION",
    "SOURCE_MANIFEST_RELATIVE_PATH",
    "SOURCE_LIFECYCLE_STATES",
    "SOURCE_BUNDLE_ID_PATTERN",
    "SOURCE_BUNDLE_RISK_LEVELS",
    "SOURCE_HEALTH_REPORT_SCHEMA_VERSION",
    "SOURCE_HEALTH_SAMPLE_BYTES",
    "SOURCE_HEALTH_TIMEOUT_SECONDS",
    "SOURCE_HEALTH_DEFAULT_WORKERS",
    "SOURCE_HEALTH_SUMMARY_STATUSES",
    "SOURCE_HEALTH_REMEDIATION_GROUPS",
    "SOURCE_HEALTH_DIAGNOSTIC_GROUPS",
    "SourceEntry",
    "SourceRecord",
    "SourceHealthRecord",
    "_coerce_source_manifest_schema_version",
    "utc_timestamp",
    "sanitize_source_lifecycle",
    "source_entry_metadata",
    "source_lifecycle_state",
    "format_source_lifecycle_label",
    "format_source_lifecycle_details",
    "sanitize_source_manifest_records",
    "sanitize_source_manifest",
    "load_blocklist_sources_manifest",
    "build_source_manifest_index",
    "iter_curated_source_records",
    "sanitize_source_bundle_id",
    "sanitize_source_bundle_catalog",
    "load_source_bundle_catalog",
    "find_source_bundle",
    "source_bundle_to_import_sources",
    "format_source_bundle_catalog",
    "format_source_bundle_report",
    "classify_source_health_diagnostic",
    "check_source_health_record",
    "check_source_health_records",
    "summarize_source_health_results",
    "source_health_remediation_group_id",
    "build_source_health_replacement_search_terms",
    "build_source_health_remediation_report",
    "format_source_health_remediation_report",
    "build_source_health_diff",
    "format_source_health_diff",
    "build_source_health_report",
]
