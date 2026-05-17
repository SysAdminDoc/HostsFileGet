"""Validate release-facing version and build-tool identity.

This script is intentionally lightweight: it uses only the standard library and
the in-repo ``hostsfileget.constants`` module so it can run before build or
security dependencies are installed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hostsfileget.constants import APP_VERSION


RELEASE_FACING_DOCS = (
    "README.md",
    "docs/release.md",
    "docs/package-managers.md",
    "docs/managed-package-exports.md",
)
RELEASE_CHECKLIST_TERMS = (
    "PyInstaller",
    "pip-audit",
    "SHA-256",
    "SBOM",
    "package manager",
    "GHSA-p2xp-xx3r-mffc",
)
MIN_SAFE_PYINSTALLER = (6, 0, 0)


def _version_tuple(value: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _read(repo_root: Path, relative_path: str) -> str:
    return (repo_root / relative_path).read_text(encoding="utf-8")


def _release_doc_app_version_tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    patterns = (
        r"releases/download/(v?\d+\.\d+\.\d+)/HostsFileGet\.exe",
        r"--version\s+(v?\d+\.\d+\.\d+)",
        r"--managed-package-version\s+(v?\d+\.\d+\.\d+)",
        r"version-(v?\d+\.\d+\.\d+)-",
    )
    for pattern in patterns:
        tokens.update(re.findall(pattern, text))
    return tokens


def check_release_identity(repo_root: Path) -> list[str]:
    errors: list[str] = []
    expected_version_tokens = {APP_VERSION, f"v{APP_VERSION}"}
    expected_badge = f"https://img.shields.io/badge/version-v{APP_VERSION}-"

    readme = _read(repo_root, "README.md")
    if expected_badge not in readme:
        errors.append(f"README.md version badge must use v{APP_VERSION}.")

    for relative_path in RELEASE_FACING_DOCS:
        text = _read(repo_root, relative_path)
        if "version-preview" in text:
            errors.append(f"{relative_path} still contains version-preview.")
        stale_tokens = {
            token
            for token in _release_doc_app_version_tokens(text)
            if token not in expected_version_tokens
        }
        if stale_tokens:
            errors.append(
                f"{relative_path} contains stale release version token(s): "
                f"{', '.join(sorted(stale_tokens))}."
            )

    release_doc = _read(repo_root, "docs/release.md")
    for term in RELEASE_CHECKLIST_TERMS:
        if term not in release_doc:
            errors.append(f"docs/release.md release checklist is missing {term!r}.")

    build_requirements = _read(repo_root, "requirements-build.txt")
    match = re.search(r"(?im)^pyinstaller==([0-9]+(?:\.[0-9]+){2})\s*$", build_requirements)
    if not match:
        errors.append("requirements-build.txt must pin pyinstaller with ==X.Y.Z.")
    else:
        pinned = _version_tuple(match.group(1))
        if pinned is None or pinned < MIN_SAFE_PYINSTALLER:
            errors.append(
                "requirements-build.txt must pin pyinstaller >= 6.0.0 "
                "for GHSA-p2xp-xx3r-mffc."
            )

    security_requirements = _read(repo_root, "requirements-security.txt")
    if not re.search(r"(?im)^pip-audit==[0-9]+(?:\.[0-9]+){2}\s*$", security_requirements):
        errors.append("requirements-security.txt must pin pip-audit with ==X.Y.Z.")

    workflow = _read(repo_root, ".github/workflows/release.yml")
    if "scripts\\check_release_identity.py" not in workflow and "scripts/check_release_identity.py" not in workflow:
        errors.append(".github/workflows/release.yml must run scripts/check_release_identity.py.")

    return errors


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    repo_root = Path(argv[0]).resolve() if argv else Path(__file__).resolve().parents[1]
    errors = check_release_identity(repo_root)
    if errors:
        for error in errors:
            print(f"release-identity: {error}", file=sys.stderr)
        return 1
    print(f"Release identity OK for v{APP_VERSION}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
