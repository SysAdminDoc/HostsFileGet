"""Streaming decompression, byte->text decoding, and HTML detection.

All helpers are pure functions with no GUI dependencies. The streaming
``_decompress_with_cap`` enforces a hard size ceiling so a gzip-bomb feed
cannot inflate to multi-GB in memory before the post-hoc cap fires.
"""

from __future__ import annotations

import bz2
import gzip
import io

# Hard cap for any single downloaded feed/whitelist payload (50 MB decompressed).
# Even the biggest public blocklists are well under 20 MB; this guards against
# runaway servers streaming gigabytes and OOMing the GUI process.
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024

TEXT_FILE_ENCODINGS = ("utf-8", "utf-8-sig", "cp1252", "latin-1")


def _format_size_limit(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes // (1024 * 1024)} MB"
    if size_bytes >= 1024:
        return f"{size_bytes // 1024} KB"
    return f"{size_bytes} bytes"


def read_http_body_limited(response, max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    """Read an HTTP response with a hard ceiling on total bytes.

    ``response.read(max_bytes + 1)`` is used so we can detect overruns without
    paying for an unbounded read. Returning the body as-is lets callers decode
    and normalize it through the existing pipeline.
    """
    data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(
            f"Response exceeded {_format_size_limit(max_bytes)} size cap "
            "(feed too large or server is streaming non-hosts content)."
        )
    return data


def decode_text_bytes(raw_bytes: bytes) -> str:
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        return raw_bytes.decode("utf-8-sig")

    if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw_bytes.decode("utf-16")

    null_bytes = raw_bytes.count(b"\x00")
    if raw_bytes and null_bytes and (null_bytes / len(raw_bytes)) > 0.15:
        for encoding in ("utf-16-le", "utf-16-be"):
            try:
                return raw_bytes.decode(encoding)
            except UnicodeDecodeError:
                continue

    for encoding in TEXT_FILE_ENCODINGS:
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="ignore")


def read_text_file_lines(path: str) -> list[str]:
    with open(path, "rb") as f:
        return decode_text_bytes(f.read()).splitlines()


def read_text_file_content(path: str) -> str:
    return "\n".join(read_text_file_lines(path))


def _decompress_with_cap(
    raw_bytes: bytes,
    decompressor_factory,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
    chunk_size: int = 64 * 1024,
) -> bytes:
    """Stream-decompress ``raw_bytes`` while enforcing a hard output cap.

    The previous implementation called the eager ``gzip.decompress`` /
    ``bz2.decompress`` helpers which would happily materialize a multi-GB
    decompression bomb into memory before the post-hoc size check could fire.
    Streaming through a fileobj with a per-chunk read cap lets us bail out as
    soon as we cross ``max_bytes`` without ever holding the unsafe payload.
    """
    if not raw_bytes:
        return raw_bytes

    decompressor = decompressor_factory(io.BytesIO(raw_bytes))
    output = bytearray()
    overflow_probe = max_bytes + 1
    try:
        while True:
            chunk = decompressor.read(chunk_size)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > overflow_probe:
                raise ValueError(
                    f"Decompressed payload exceeded {_format_size_limit(max_bytes)} size cap."
                )
    finally:
        try:
            decompressor.close()
        except Exception:
            pass
    if len(output) > max_bytes:
        raise ValueError(
            f"Decompressed payload exceeded {_format_size_limit(max_bytes)} size cap."
        )
    return bytes(output)


def decode_downloaded_lines(url: str, raw_bytes: bytes, content_encoding: str = "") -> list[str]:
    lowered_url = url.lower()
    lowered_encoding = content_encoding.lower()

    try:
        if lowered_url.endswith(".bz2"):
            raw_bytes = _decompress_with_cap(raw_bytes, bz2.BZ2File)
        elif lowered_url.endswith(".gz") or "gzip" in lowered_encoding:
            raw_bytes = _decompress_with_cap(
                raw_bytes,
                lambda fileobj: gzip.GzipFile(fileobj=fileobj, mode="rb"),
            )
    except (OSError, EOFError):
        # Some mirrors advertise compression inconsistently; fall back to raw
        # bytes only when decompression itself failed (truncated stream, bad
        # magic, etc.). A size-cap overflow re-raises ValueError below so the
        # bomb guard cannot be silently bypassed.
        pass

    # Defensive second guard: a non-compressed raw_bytes path could in theory
    # still exceed the cap if a caller bypassed read_http_body_limited.
    if len(raw_bytes) > MAX_DOWNLOAD_BYTES:
        raise ValueError(
            f"Decompressed payload exceeded {_format_size_limit(MAX_DOWNLOAD_BYTES)} size cap."
        )

    return decode_text_bytes(raw_bytes).splitlines()


def looks_like_html_document(lines: list[str]) -> bool:
    significant_lines = [line.strip().lower() for line in lines if line.strip()][:20]
    if not significant_lines:
        return False

    combined = "\n".join(significant_lines[:10])
    html_markers = ("<!doctype html", "<html", "<head", "<body", "</html>", "<title", "<meta ")
    if significant_lines[0].startswith(("<!doctype html", "<html")):
        return True

    marker_hits = sum(1 for marker in html_markers if marker in combined)
    return marker_hits >= 2


__all__ = [
    "MAX_DOWNLOAD_BYTES",
    "TEXT_FILE_ENCODINGS",
    "_format_size_limit",
    "_decompress_with_cap",
    "read_http_body_limited",
    "decode_text_bytes",
    "read_text_file_lines",
    "read_text_file_content",
    "decode_downloaded_lines",
    "looks_like_html_document",
]
