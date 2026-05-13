"""Per-line hosts entry normalization.

``parse_hosts_line_entries`` is the single canonical "turn one raw line
into a list of ``(normalised_entry, domain, is_block)`` tuples" entry
point. The cleaner, the canonical-output builder, the migration
importers, and the live editor stats all funnel through here so the
exact rules (quarantining browser-only adblock lines, normalising the
mapping IP, deduplicating within a single line, supporting bare domain
shorthand vs. explicit IP-and-host pairs) are defined exactly once.
"""

from __future__ import annotations

from .adblock import classify_adblock_rule_line
from .parsing import (
    TOKEN_SPLITTER,
    _extract_domain_from_token,
    _is_comment_line,
    _looks_like_ip_token,
    _normalize_mapping_ip,
)


def parse_hosts_line_entries(line: str) -> tuple[list[tuple[str, str, bool]], bool]:
    stripped = line.strip()
    if not stripped or _is_comment_line(stripped):
        return [], False

    lint = classify_adblock_rule_line(line)
    if lint.get("quarantine"):
        return [], True

    processed = stripped.split("#", 1)[0].strip()
    if not processed:
        return [], False

    tokens = [token for token in TOKEN_SPLITTER.split(processed) if token]
    if not tokens:
        return [], False

    if _looks_like_ip_token(tokens[0]):
        mapping_ip, ip_transformed, is_block_entry = _normalize_mapping_ip(tokens[0])
        candidate_tokens = tokens[1:]
        transformed = ip_transformed or len(candidate_tokens) != 1
        allow_single_label = True
    else:
        mapping_ip = "0.0.0.0"
        is_block_entry = True
        candidate_tokens = tokens
        transformed = True
        allow_single_label = False

    parsed_entries: list[tuple[str, str, bool]] = []
    seen_in_line: set[str] = set()

    for token in candidate_tokens:
        domain, token_transformed = _extract_domain_from_token(token, allow_single_label=allow_single_label)
        transformed = transformed or token_transformed
        if not domain:
            continue

        normalized = f"{mapping_ip} {domain}"
        if normalized in seen_in_line:
            transformed = True
            continue

        seen_in_line.add(normalized)
        parsed_entries.append((normalized, domain, is_block_entry))

    return parsed_entries, transformed


def normalize_line_to_hosts_entries(line: str) -> tuple[list[str], list[str], bool]:
    parsed_entries, transformed = parse_hosts_line_entries(line)
    return [entry[0] for entry in parsed_entries], [entry[1] for entry in parsed_entries], transformed


def normalize_line_to_hosts_entry(line: str) -> tuple[str | None, str | None, bool]:
    normalized_entries, domains, transformed = normalize_line_to_hosts_entries(line)
    if normalized_entries:
        return normalized_entries[0], domains[0], transformed
    return None, None, False


__all__ = [
    "parse_hosts_line_entries",
    "normalize_line_to_hosts_entries",
    "normalize_line_to_hosts_entry",
]
