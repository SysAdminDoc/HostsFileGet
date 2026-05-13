"""IDN/Punycode and Unicode-homograph detection for hosts entries.

This subsystem flags entries that look ASCII but are actually built from
Cyrillic/Greek/etc. look-alikes ("homograph spoofing") and surfaces
Unicode IDN candidates so reviewers can confirm both forms (U-label and
A-label) before trusting an internationalised blocklist line.

The logic is deterministic and conservative — it is not a complete
Unicode security engine, just a smoke-test that catches the cheap
cyrillic-`a`-in-an-ASCII-domain trick.
"""

from __future__ import annotations

import re
import unicodedata
import urllib.parse

from .adblock import _find_adblock_cosmetic_marker
from .parsing import (
    DNSMASQ_RULE_REGEX,
    LOCAL_DOMAINS,
    WILDCARD_STRIPPER,
    _contains_non_ascii,
    _decode_idna_domain,
    _domain_shape_matches,
    _encode_idna_domain,
    _is_comment_line,
    _looks_like_ip_token,
)


IDN_WARNING_CATEGORIES = {"homograph-risk", "invalid-punycode"}
IDN_LABEL_TOKEN_SPLITTER = re.compile(r"[\s,;]+")

# A small curated map of Cyrillic/Greek letters that visually masquerade
# as ASCII. Used to compute a "confusable skeleton" so we can flag a
# Unicode domain whose lookalike form is a plausible ASCII domain.
CONFUSABLE_ASCII_MAP = {
    "\u0430": "a", "\u0410": "A",
    "\u0435": "e", "\u0415": "E",
    "\u043e": "o", "\u041e": "O",
    "\u0440": "p", "\u0420": "P",
    "\u0441": "c", "\u0421": "C",
    "\u0445": "x", "\u0425": "X",
    "\u0443": "y", "\u0423": "Y",
    "\u0456": "i", "\u0406": "I",
    "\u0458": "j", "\u0408": "J",
    "\u0455": "s", "\u0405": "S",
    "\u03b1": "a", "\u0391": "A",
    "\u03bf": "o", "\u039f": "O",
    "\u03c1": "p", "\u03a1": "P",
    "\u03b5": "e", "\u0395": "E",
    "\u03c7": "x", "\u03a7": "X",
    "\u03bd": "v", "\u039d": "N",
    "\u03b9": "i", "\u0399": "I",
}


def _script_bucket(character: str) -> str | None:
    if character in ".-" or character.isdigit() or unicodedata.category(character).startswith("M"):
        return None
    if "A" <= character <= "Z" or "a" <= character <= "z":
        return "Latin"
    name = unicodedata.name(character, "")
    if not name:
        return "Other"
    for prefix, bucket in (
        ("LATIN", "Latin"),
        ("CYRILLIC", "Cyrillic"),
        ("GREEK", "Greek"),
        ("HEBREW", "Hebrew"),
        ("ARABIC", "Arabic"),
        ("DEVANAGARI", "Devanagari"),
        ("CJK", "CJK"),
        ("HIRAGANA", "Hiragana"),
        ("KATAKANA", "Katakana"),
        ("HANGUL", "Hangul"),
    ):
        if name.startswith(prefix):
            return bucket
    return "Other"


def _label_scripts(label: str) -> list[str]:
    scripts = {
        script
        for character in label
        for script in [_script_bucket(character)]
        if script
    }
    return sorted(scripts)


def _confusable_ascii_skeleton(domain: str) -> str:
    return "".join(CONFUSABLE_ASCII_MAP.get(character, character) for character in domain).lower()


def _extract_idn_candidate_from_token(token: str, allow_single_label: bool = False) -> str | None:
    candidate = token.strip().strip("'\"()[]{}<>")
    if not candidate:
        return None
    if candidate.startswith("@@"):
        candidate = candidate[2:]

    dnsmasq_match = DNSMASQ_RULE_REGEX.match(candidate)
    if dnsmasq_match:
        candidate = dnsmasq_match.group(1)

    pattern = candidate.split("$", 1)[0].strip()
    if pattern.startswith("||"):
        pattern = pattern[2:]
    elif pattern.startswith("|"):
        pattern = pattern[1:]
    pattern = pattern.rstrip("|")
    pattern = pattern.split("^", 1)[0].strip()

    if pattern.lower().startswith(("http://", "https://", "ftp://")):
        try:
            hostname = urllib.parse.urlsplit(pattern).hostname
        except ValueError:
            hostname = None
        if not hostname:
            return None
        pattern = hostname
    elif any(separator in pattern for separator in ("/", "?", ":")):
        try:
            hostname = urllib.parse.urlsplit(f"http://{pattern}").hostname
        except ValueError:
            hostname = None
        if hostname:
            pattern = hostname

    wildcard_match = WILDCARD_STRIPPER.match(pattern)
    if wildcard_match:
        pattern = wildcard_match.group(1)

    candidate = pattern.strip().strip(".").lower()
    if not candidate or candidate in LOCAL_DOMAINS or _looks_like_ip_token(candidate):
        return None

    has_idn_signal = _contains_non_ascii(candidate) or any(
        label.startswith("xn--") for label in candidate.split(".")
    )
    if not has_idn_signal:
        return None

    ascii_domain, _ = _encode_idna_domain(candidate)
    if ascii_domain and _domain_shape_matches(ascii_domain, allow_single_label=allow_single_label):
        return candidate
    if any(label.startswith("xn--") for label in candidate.split(".")):
        return candidate
    return None


def extract_idn_domain_candidates(lines: list[str]) -> list[dict]:
    candidates: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for line_number, line in enumerate(lines, start=1):
        stripped = (line or "").strip()
        if not stripped or _is_comment_line(stripped):
            continue
        body = stripped
        if "#" in body and not _find_adblock_cosmetic_marker(body):
            body = body.split("#", 1)[0]
        tokens = [token for token in IDN_LABEL_TOKEN_SPLITTER.split(body) if token]
        allow_single_label = bool(tokens and _looks_like_ip_token(tokens[0]))
        for token in tokens:
            candidate = _extract_idn_candidate_from_token(token, allow_single_label=allow_single_label)
            if not candidate:
                continue
            key = (line_number, candidate)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({"line_number": line_number, "domain": candidate, "line": line})
    return candidates


def classify_idn_domain(domain: str) -> dict:
    normalized = (domain or "").strip().strip(".").lower()
    result = {
        "domain": normalized,
        "category": "ascii",
        "severity": "info",
        "ascii": normalized if not _contains_non_ascii(normalized) else None,
        "unicode": normalized,
        "scripts": [],
        "mixed_script_labels": [],
        "confusable_skeleton": None,
        "warnings": [],
    }
    if not normalized:
        result["category"] = "invalid"
        result["severity"] = "warning"
        result["warnings"].append("Empty domain candidate.")
        return result

    has_punycode = any(label.startswith("xn--") for label in normalized.split("."))
    has_non_ascii = _contains_non_ascii(normalized)
    unicode_domain = normalized
    ascii_domain = normalized

    if has_punycode:
        decoded, decode_error = _decode_idna_domain(normalized)
        if decode_error or not decoded:
            result.update({
                "category": "invalid-punycode",
                "severity": "warning",
                "ascii": normalized,
                "unicode": None,
            })
            result["warnings"].append(f"Punycode label could not be decoded as valid IDNA: {decode_error}")
            return result
        unicode_domain = decoded.lower()

    encoded, encode_error = _encode_idna_domain(unicode_domain)
    if encode_error or not encoded:
        result.update({
            "category": "invalid-idn",
            "severity": "warning",
            "unicode": unicode_domain,
        })
        result["warnings"].append(f"Unicode domain could not be encoded as IDNA: {encode_error}")
        return result
    ascii_domain = encoded

    label_script_rows = []
    mixed_labels = []
    for label in unicode_domain.split("."):
        scripts = _label_scripts(label)
        label_script_rows.append({"label": label, "scripts": scripts})
        if len(scripts) > 1:
            mixed_labels.append({"label": label, "scripts": scripts})

    skeleton = _confusable_ascii_skeleton(unicode_domain)
    skeleton_is_ascii = skeleton != unicode_domain.lower() and all(ord(character) < 128 for character in skeleton)
    if mixed_labels or skeleton_is_ascii:
        result["category"] = "homograph-risk"
        result["severity"] = "warning"
        if mixed_labels:
            result["warnings"].append(
                "At least one label mixes writing systems; review before trusting or broadening this rule."
            )
        if skeleton_is_ascii:
            result["confusable_skeleton"] = skeleton
            result["warnings"].append(
                f"Known Cyrillic/Greek confusables resemble ASCII domain '{skeleton}'."
            )
    elif has_punycode:
        result["category"] = "punycode"
        result["warnings"].append("Punycode A-label decodes to a Unicode IDN; review the displayed Unicode form.")
    elif has_non_ascii:
        result["category"] = "idn"
        result["warnings"].append("Unicode IDN label is validly encodable; keep the ASCII A-label nearby for audits.")

    result.update({
        "ascii": ascii_domain,
        "unicode": unicode_domain,
        "scripts": label_script_rows,
        "mixed_script_labels": mixed_labels,
    })
    return result


def build_idn_homograph_report(lines: list[str], max_findings: int = 50) -> dict:
    counts: dict[str, int] = {}
    findings: list[dict] = []
    warning_count = 0
    punycode_count = 0
    idn_count = 0
    candidates = extract_idn_domain_candidates(lines)
    for candidate in candidates:
        classification = classify_idn_domain(candidate["domain"])
        category = classification["category"]
        counts[category] = counts.get(category, 0) + 1
        if category in {"idn", "punycode", "homograph-risk"}:
            idn_count += 1
        if any(label.startswith("xn--") for label in str(classification.get("ascii") or "").split(".")):
            punycode_count += 1
        if classification["severity"] == "warning":
            warning_count += 1
        if category != "ascii" and len(findings) < max_findings:
            findings.append({
                "line_number": candidate["line_number"],
                "domain": candidate["domain"],
                "category": category,
                "severity": classification["severity"],
                "ascii": classification.get("ascii"),
                "unicode": classification.get("unicode"),
                "confusable_skeleton": classification.get("confusable_skeleton"),
                "warnings": classification.get("warnings") or [],
                "line": candidate["line"],
            })
    return {
        "schema": "hostsfileget.idn-homograph-report.v1",
        "total_lines": len(lines),
        "candidate_domains": len(candidates),
        "idn_domains": idn_count,
        "punycode_domains": punycode_count,
        "warning_count": warning_count,
        "counts": counts,
        "findings": findings,
        "finding_limit": max_findings,
        "truncated_findings": max(0, len(candidates) - len(findings)),
        "warnings": [
            "This report is advisory; HostsFileGet does not automatically block or rewrite IDNs.",
            "Punycode A-labels and Unicode U-labels can be equivalent under IDNA, but visual spoofing is a separate security problem.",
            "Mixed-script and small confusable checks are deterministic heuristics, not a complete Unicode security engine.",
        ],
    }


def format_idn_homograph_report(report: dict) -> str:
    counts = report.get("counts") or {}
    lines = [
        "IDN and homograph report",
        f"Lines: {int(report.get('total_lines') or 0):,}",
        f"IDN/Punycode candidates: {int(report.get('candidate_domains') or 0):,}",
        f"Valid IDN domains: {int(report.get('idn_domains') or 0):,}",
        f"Punycode A-labels: {int(report.get('punycode_domains') or 0):,}",
        f"Warning candidates: {int(report.get('warning_count') or 0):,}",
        "",
        "Counts:",
    ]
    if counts:
        for category in sorted(counts):
            lines.append(f"- {category}: {int(counts[category]):,}")
    else:
        lines.append("- none: 0")
    lines.extend(["", "Warnings:"])
    for warning in report.get("warnings") or []:
        lines.append(f"- {warning}")
    findings = report.get("findings") or []
    if findings:
        lines.extend(["", "Findings:"])
        for finding in findings:
            details = []
            if finding.get("ascii"):
                details.append(f"ASCII={finding.get('ascii')}")
            if finding.get("unicode"):
                details.append(f"Unicode={finding.get('unicode')}")
            if finding.get("confusable_skeleton"):
                details.append(f"Skeleton={finding.get('confusable_skeleton')}")
            detail_text = "; ".join(details)
            warning_text = " ".join(finding.get("warnings") or [])
            line_preview = str(finding.get("line") or "").strip()
            if len(line_preview) > 120:
                line_preview = line_preview[:117] + "..."
            lines.append(
                f"- Line {finding.get('line_number')}: {finding.get('category')} "
                f"{detail_text} - {warning_text} [{line_preview}]"
            )
        truncated = int(report.get("truncated_findings") or 0)
        if truncated:
            lines.append(f"- ... {truncated:,} additional candidate(s) omitted.")
    else:
        lines.extend(["", "Findings: none"])
    return "\n".join(lines)


__all__ = [
    "IDN_WARNING_CATEGORIES",
    "IDN_LABEL_TOKEN_SPLITTER",
    "CONFUSABLE_ASCII_MAP",
    "_script_bucket",
    "_label_scripts",
    "_confusable_ascii_skeleton",
    "_extract_idn_candidate_from_token",
    "extract_idn_domain_candidates",
    "classify_idn_domain",
    "build_idn_homograph_report",
    "format_idn_homograph_report",
]
