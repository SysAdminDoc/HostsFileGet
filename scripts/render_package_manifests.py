#!/usr/bin/env python3
"""Render Winget and Chocolatey manifest templates for a HostsFileGet release."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?$")
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")


TEMPLATE_FILES = {
    "packaging/winget/HostsFileGet.yaml.template": "winget/SysAdminDoc.HostsFileGet.yaml",
    "packaging/winget/HostsFileGet.installer.yaml.template": "winget/SysAdminDoc.HostsFileGet.installer.yaml",
    "packaging/winget/HostsFileGet.locale.en-US.yaml.template": "winget/SysAdminDoc.HostsFileGet.locale.en-US.yaml",
    "packaging/chocolatey/hostsfileget.nuspec.template": "chocolatey/hostsfileget/hostsfileget.nuspec",
    "packaging/chocolatey/tools/chocolateyInstall.ps1.template": "chocolatey/hostsfileget/tools/chocolateyInstall.ps1",
    "packaging/chocolatey/tools/chocolateyUninstall.ps1.template": "chocolatey/hostsfileget/tools/chocolateyUninstall.ps1",
}


def validate_release_inputs(version: str, installer_url: str, sha256: str) -> dict[str, str]:
    version = str(version or "").strip().lstrip("v")
    installer_url = str(installer_url or "").strip()
    sha256 = str(sha256 or "").strip().lower()
    if not VERSION_RE.match(version):
        raise ValueError("version must look like MAJOR.MINOR.PATCH")
    if not installer_url.startswith("https://"):
        raise ValueError("installer URL must use https")
    if not SHA256_RE.match(sha256):
        raise ValueError("sha256 must be a 64-character hex digest")
    return {
        "VERSION": version,
        "INSTALLER_URL": installer_url,
        "SHA256": sha256.upper(),
    }


def render_template(text: str, values: dict[str, str]) -> str:
    rendered = text
    for key, value in values.items():
        rendered = rendered.replace("{{" + key + "}}", value)
    unresolved = re.findall(r"{{[A-Z0-9_]+}}", rendered)
    if unresolved:
        raise ValueError(f"unresolved template token(s): {', '.join(sorted(set(unresolved)))}")
    return rendered


def render_package_manifests(
    repo_root: Path,
    output_dir: Path,
    version: str,
    installer_url: str,
    sha256: str,
) -> list[Path]:
    values = validate_release_inputs(version, installer_url, sha256)
    written: list[Path] = []
    for template_rel, output_rel in TEMPLATE_FILES.items():
        template_path = repo_root / template_rel
        output_path = output_dir / output_rel
        rendered = render_template(template_path.read_text(encoding="utf-8"), values)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8", newline="\n")
        written.append(output_path)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render Winget and Chocolatey release manifests.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--installer-url", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args(argv)

    try:
        written = render_package_manifests(
            Path(args.repo_root),
            Path(args.output_dir),
            args.version,
            args.installer_url,
            args.sha256,
        )
    except (OSError, ValueError) as exc:
        print(f"Package manifest render failed: {exc}")
        return 2

    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
