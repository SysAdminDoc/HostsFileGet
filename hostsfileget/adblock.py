"""Adblock-syntax classification, quarantine, and reporting.

Browsers consume Adblock Plus / uBlock Origin / Adguard filter syntax
directly, but a hosts file can only express exact-domain block entries.
This module decides — line by line — which rules are safely representable
as ``0.0.0.0 domain`` and which would over-block or have no hosts-file
equivalent (cosmetic, scriptlet, exception, regex, path-anchored).

Pure functions; no GUI dependencies. Used by both the importer (to
quarantine browser-only rules instead of broadening them) and by the
report dialog under Tools > Adblock Syntax Lint.
"""

from __future__ import annotations

import urllib.parse

from .parsing import (
    TOKEN_SPLITTER,
    _extract_domain_from_token,
    _is_comment_line,
    _looks_like_ip_token,
    _normalize_mapping_ip,
)


ADBLOCK_COSMETIC_MARKERS: tuple[tuple[str, str], ...] = (
    ("#@%#", "scriptlet exception"),
    ("#%#", "scriptlet"),
    ("#@?#", "extended cosmetic exception"),
    ("#?#", "extended cosmetic"),
    ("#@#", "cosmetic exception"),
    ("#$#", "CSS injection"),
    ("##", "cosmetic"),
)
ADBLOCK_QUARANTINE_COMMENT_PREFIX = "# HostsFileGet quarantined browser-only rule:"


def _find_adblock_cosmetic_marker(stripped: str) -> tuple[str, str] | None:
    matches = []
    for marker, label in ADBLOCK_COSMETIC_MARKERS:
        index = stripped.find(marker)
        if index >= 0:
            matches.append((index, -len(marker), marker, label))
    if not matches:
        return None
    _, _, marker, label = sorted(matches)[0]
    return marker, label


def _adblock_pattern_has_url_path(pattern: str) -> bool:
    candidate = pattern.strip().strip("|")
    if not candidate:
        return False
    if candidate.lower().startswith(("http://", "https://", "ftp://")):
        try:
            parsed = urllib.parse.urlsplit(candidate)
        except ValueError:
            return False
        return bool(parsed.hostname and parsed.path and parsed.path != "/")
    host_mask = candidate.split("^", 1)[0]
    return "/" in host_mask


def classify_adblock_rule_line(line: str) -> dict:
    """Classify a line by how safely it can be represented in a hosts file."""
    stripped = (line or "").strip()
    result = {
        "line": line,
        "category": "blank",
        "severity": "info",
        "dns_compatible": False,
        "quarantine": False,
        "domain": None,
        "normalized": None,
        "reason": "Blank line.",
    }
    if not stripped:
        return result

    if stripped.startswith(ADBLOCK_QUARANTINE_COMMENT_PREFIX):
        result.update({
            "category": "quarantine-comment",
            "reason": "Already marked as a HostsFileGet quarantine comment.",
        })
        return result

    cosmetic_marker = _find_adblock_cosmetic_marker(stripped)
    if cosmetic_marker:
        marker, label = cosmetic_marker
        result.update({
            "category": "browser-only",
            "severity": "warning",
            "quarantine": True,
            "reason": f"Browser-only {label} rule uses {marker}; hosts files cannot hide page elements or run scriptlets.",
        })
        return result

    if _is_comment_line(stripped):
        result.update({"category": "comment", "reason": "Comment or metadata line."})
        return result

    if stripped.startswith("@@"):
        result.update({
            "category": "exception",
            "severity": "warning",
            "quarantine": True,
            "reason": "Adblock exception/allow rules cannot be represented as blocking hosts entries.",
        })
        return result

    pattern = stripped.split("$", 1)[0].strip()
    if pattern.startswith("||") and _adblock_pattern_has_url_path(pattern[2:]):
        result.update({
            "category": "path-network",
            "severity": "warning",
            "quarantine": True,
            "reason": "Path-level network filter would over-block if reduced to a hosts domain.",
        })
        return result
    if pattern.startswith("|") and _adblock_pattern_has_url_path(pattern):
        result.update({
            "category": "path-network",
            "severity": "warning",
            "quarantine": True,
            "reason": "URL-anchored network filter has path semantics that hosts files cannot express.",
        })
        return result

    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
        result.update({
            "category": "regex",
            "severity": "warning",
            "quarantine": True,
            "reason": "Regex filter can be DNS-provider syntax, but hosts files cannot represent regex matching.",
        })
        return result

    domain, transformed = _extract_domain_from_token(stripped, allow_single_label=False)
    if domain:
        category = (
            "adblock-dns"
            if transformed or stripped.startswith(("||", "|")) or "$" in stripped
            else "domain"
        )
        result.update({
            "category": category,
            "dns_compatible": True,
            "domain": domain,
            "normalized": f"0.0.0.0 {domain}",
            "reason": "Exact or hostname-scoped rule can be represented as a hosts entry.",
        })
        return result

    tokens = [token for token in TOKEN_SPLITTER.split(stripped.split("#", 1)[0].strip()) if token]
    if tokens and _looks_like_ip_token(tokens[0]):
        domains = []
        for token in tokens[1:]:
            token_domain, _ = _extract_domain_from_token(token, allow_single_label=True)
            if token_domain:
                domains.append(token_domain)
        if domains:
            result.update({
                "category": "hosts",
                "dns_compatible": True,
                "domain": domains[0],
                "normalized": f"{_normalize_mapping_ip(tokens[0])[0]} {domains[0]}",
                "reason": "Hosts-style mapping can be represented directly.",
            })
            return result

    result.update({
        "category": "invalid",
        "severity": "warning",
        "quarantine": True,
        "reason": "Line is not a valid hosts entry or exact DNS-compatible filter rule.",
    })
    return result


def build_adblock_syntax_report(lines: list[str], max_findings: int = 50) -> dict:
    counts: dict[str, int] = {}
    findings: list[dict] = []
    dns_compatible = 0
    quarantined = 0
    for index, line in enumerate(lines, start=1):
        classification = classify_adblock_rule_line(line)
        category = classification["category"]
        counts[category] = counts.get(category, 0) + 1
        if classification.get("dns_compatible"):
            dns_compatible += 1
        if classification.get("quarantine"):
            quarantined += 1
            if len(findings) < max_findings:
                findings.append({
                    "line_number": index,
                    "category": category,
                    "reason": classification["reason"],
                    "line": line,
                    "domain": classification.get("domain"),
                })
    return {
        "schema": "hostsfileget.adblock-syntax-report.v1",
        "total_lines": len(lines),
        "dns_compatible": dns_compatible,
        "quarantined": quarantined,
        "counts": counts,
        "findings": findings,
        "finding_limit": max_findings,
        "truncated_findings": max(0, quarantined - len(findings)),
        "warnings": [
            "Browser cosmetic, scriptlet, exception, regex, and path-level adblock rules are not hosts-file entries.",
            "Path-level rules are quarantined because reducing them to a domain can over-block unrelated content.",
            "DNS-compatible adblock domain rules can be normalized to exact hosts entries, but provider-only modifiers are stripped.",
        ],
    }


def format_adblock_syntax_report(report: dict) -> str:
    counts = report.get("counts") or {}
    lines = [
        "Adblock syntax lint",
        f"Lines: {int(report.get('total_lines') or 0):,}",
        f"DNS-compatible / hosts-compatible: {int(report.get('dns_compatible') or 0):,}",
        f"Quarantined candidates: {int(report.get('quarantined') or 0):,}",
        "",
        "Counts:",
    ]
    for category in sorted(counts):
        lines.append(f"- {category}: {int(counts[category]):,}")
    lines.extend(["", "Warnings:"])
    for warning in report.get("warnings") or []:
        lines.append(f"- {warning}")
    findings = report.get("findings") or []
    if findings:
        lines.extend(["", "Findings:"])
        for finding in findings:
            line_preview = str(finding.get("line") or "").strip()
            if len(line_preview) > 140:
                line_preview = line_preview[:137] + "..."
            lines.append(
                f"- Line {finding.get('line_number')}: {finding.get('category')} - "
                f"{finding.get('reason')} [{line_preview}]"
            )
        truncated = int(report.get("truncated_findings") or 0)
        if truncated:
            lines.append(f"- ... {truncated:,} additional finding(s) omitted.")
    else:
        lines.extend(["", "Findings: none"])
    return "\n".join(lines)


def quarantine_adblock_rule_lines(lines: list[str]) -> tuple[list[str], dict]:
    quarantined_lines: list[str] = []
    changed = 0
    report = build_adblock_syntax_report(lines)
    for line in lines:
        classification = classify_adblock_rule_line(line)
        if classification.get("quarantine"):
            stripped = line.strip()
            if stripped.startswith(ADBLOCK_QUARANTINE_COMMENT_PREFIX):
                quarantined_lines.append(line)
                continue
            quarantined_lines.append(f"{ADBLOCK_QUARANTINE_COMMENT_PREFIX} {stripped}")
            changed += 1
        else:
            quarantined_lines.append(line)
    report["changed_lines"] = changed
    return quarantined_lines, report


__all__ = [
    "ADBLOCK_COSMETIC_MARKERS",
    "ADBLOCK_QUARANTINE_COMMENT_PREFIX",
    "_find_adblock_cosmetic_marker",
    "_adblock_pattern_has_url_path",
    "classify_adblock_rule_line",
    "build_adblock_syntax_report",
    "format_adblock_syntax_report",
    "quarantine_adblock_rule_lines",
]
