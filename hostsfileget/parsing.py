"""Leaf-level domain and hosts-line parsing helpers.

This module owns the small, dependency-free building blocks that every
higher-level normalizer, importer, and report uses:

- the regex/tuple constants that recognise hosts entries, comments,
  wildcard rules, and dnsmasq syntax;
- the per-token domain inspection helpers
  (``looks_like_domain``, ``_extract_domain_from_token``, etc.);
- the IDN/IDNA primitives used by the homograph detector and several
  downstream sanitizers.

The bigger ``parse_hosts_line_entries`` / ``normalize_line_to_hosts_entries``
helpers still live in ``hosts_editor.py`` because they reach into the
adblock classifier and rule-tier subsystems that have not yet been
extracted. A later phase can pull those in once the adblock layer is
factored out into its own submodule.
"""

from __future__ import annotations

import re
import unicodedata
import urllib.parse


# Hostname grammar. ``DOMAIN_REGEX`` requires at least one ``.label``
# suffix; ``HOST_LABEL_REGEX`` accepts a bare single label for callers
# (allow_single_label=True) that want to permit Windows-style local
# names. ``IPV4_REGEX`` was historically broken for octets >= 200 until
# v2.9.0 and is the canonical "is this an IPv4 literal" check.
DOMAIN_REGEX = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
IPV6_REGEX = re.compile(r"^[\da-fA-F:.]+$")
WILDCARD_STRIPPER = re.compile(r"^\*\.?(.*)")
TOKEN_SPLITTER = re.compile(r"[\s,;]+")
DNSMASQ_RULE_REGEX = re.compile(r"^(?:address|local)=/([^/]+)/?", re.IGNORECASE)
HOST_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# A hosts line whose first non-blank character is one of these is a
# comment as far as our parser is concerned. ``[`` covers Windows-INI
# style section headers shipped in a few legacy blocklists.
COMMENT_PREFIXES = ("#", "!", "[")

LOCAL_DOMAINS = {"localhost", "localhost.localdomain", "::1"}
STANDARD_BLOCKING_IPS = {"0.0.0.0", "127.0.0.1", "::1"}


def looks_like_domain(token: str, allow_single_label: bool = False) -> bool:
    if len(token) > 253:
        return False
    if token.startswith(("-", ".")) or token.endswith(("-", ".")):
        return False
    if IPV4_REGEX.match(token) or (IPV6_REGEX.match(token) and ":" in token):
        return False
    if allow_single_label and "." not in token:
        return bool(HOST_LABEL_REGEX.match(token)) and any(ch.isalpha() for ch in token)
    return bool(DOMAIN_REGEX.match(token))


def _looks_like_ip_token(token: str) -> bool:
    return bool(IPV4_REGEX.match(token) or (IPV6_REGEX.match(token) and ":" in token))


def _is_comment_line(stripped: str) -> bool:
    return stripped.startswith(COMMENT_PREFIXES)


def _normalize_mapping_ip(token: str) -> tuple[str, bool, bool]:
    """Canonicalize the IP half of a hosts mapping.

    Returns ``(normalized_ip, was_transformed, is_block_entry)``. Standard
    blocking IPs (``0.0.0.0``, ``127.0.0.1``, ``::1``) all canonicalize to
    ``0.0.0.0`` so cleaned output is consistent regardless of which sentinel
    the upstream feed picked.
    """
    candidate = token.strip()
    normalized = candidate.lower() if ":" in candidate else candidate
    if normalized in STANDARD_BLOCKING_IPS:
        return "0.0.0.0", normalized != "0.0.0.0", True
    return normalized, normalized != candidate, False


def _extract_domain_from_token(token: str, allow_single_label: bool = False) -> tuple[str | None, bool]:
    candidate = token.strip().strip("'\"()[]{}<>")
    transformed = candidate != token.strip()
    if not candidate:
        return None, transformed

    if candidate.startswith("@@"):
        return None, True

    dnsmasq_match = DNSMASQ_RULE_REGEX.match(candidate)
    if dnsmasq_match:
        candidate = dnsmasq_match.group(1)
        transformed = True

    if candidate.startswith("||"):
        candidate = candidate[2:]
        transformed = True
    elif candidate.startswith("|"):
        candidate = candidate[1:]
        transformed = True

    for delimiter in ("^", "$"):
        if delimiter in candidate:
            candidate = candidate.split(delimiter, 1)[0]
            transformed = True

    if candidate.lower().startswith(("http://", "https://", "ftp://")):
        hostname = urllib.parse.urlsplit(candidate).hostname
        transformed = True
        if not hostname:
            return None, transformed
        candidate = hostname
    elif any(separator in candidate for separator in ("/", "?", ":")):
        try:
            hostname = urllib.parse.urlsplit(f"http://{candidate}").hostname
        except ValueError:
            hostname = None
        if hostname:
            candidate = hostname
            transformed = True

    wildcard_match = WILDCARD_STRIPPER.match(candidate)
    if wildcard_match:
        candidate = wildcard_match.group(1)
        transformed = True

    if candidate.endswith("."):
        candidate = candidate[:-1]
        transformed = True

    domain = candidate.lower()
    if domain in LOCAL_DOMAINS or not looks_like_domain(domain, allow_single_label=allow_single_label):
        return None, transformed

    return domain, transformed


def _domain_shape_matches(domain: str, allow_single_label: bool = False) -> bool:
    if allow_single_label and "." not in domain:
        return bool(HOST_LABEL_REGEX.match(domain)) and any(ch.isalpha() for ch in domain)
    return looks_like_domain(domain, allow_single_label=False)


def _contains_non_ascii(value: str) -> bool:
    return any(ord(ch) > 127 for ch in value)


def _decode_idna_domain(domain: str) -> tuple[str | None, str | None]:
    """Round-trip an ASCII-encoded IDN label back to its Unicode form."""
    try:
        return domain.encode("ascii").decode("idna"), None
    except (UnicodeError, UnicodeEncodeError) as exc:
        return None, str(exc)


def _encode_idna_domain(domain: str) -> tuple[str | None, str | None]:
    """Encode a Unicode hostname into its ASCII (Punycode) representation."""
    try:
        return domain.encode("idna").decode("ascii").lower(), None
    except UnicodeError as exc:
        return None, str(exc)


__all__ = [
    "DOMAIN_REGEX",
    "IPV4_REGEX",
    "IPV6_REGEX",
    "WILDCARD_STRIPPER",
    "TOKEN_SPLITTER",
    "DNSMASQ_RULE_REGEX",
    "HOST_LABEL_REGEX",
    "COMMENT_PREFIXES",
    "LOCAL_DOMAINS",
    "STANDARD_BLOCKING_IPS",
    "looks_like_domain",
    "_looks_like_ip_token",
    "_is_comment_line",
    "_normalize_mapping_ip",
    "_extract_domain_from_token",
    "_domain_shape_matches",
    "_contains_non_ascii",
    "_decode_idna_domain",
    "_encode_idna_domain",
]
# ``unicodedata`` is imported for parity with the original module; future
# IDN homograph extraction will consume it directly.
_ = unicodedata  # silences linters that flag the import as unused.
