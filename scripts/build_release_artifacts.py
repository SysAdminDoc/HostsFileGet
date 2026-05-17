"""Build deterministic release-side artifacts for a HostsFileGet executable."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.render_package_manifests import render_package_manifests


REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REPRODUCIBLE_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksum_file(exe_path: Path, output_dir: Path, digest: str) -> Path:
    checksum_path = output_dir / f"{exe_path.name}.sha256"
    checksum_path.write_text(f"{digest.upper()}  {exe_path.name}\n", encoding="ascii")
    return checksum_path


def write_reproducible_zip(source_dir: Path, zip_path: Path) -> Path:
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(p for p in source_dir.rglob("*") if p.is_file()):
            relative_name = path.relative_to(source_dir).as_posix()
            info = zipfile.ZipInfo(relative_name, REPRODUCIBLE_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
    return zip_path


def build_release_artifacts(
    repo_root: Path,
    exe_path: Path,
    version: str,
    tag: str,
    repository: str,
    output_dir: Path,
) -> dict:
    repo_root = repo_root.resolve()
    exe_path = exe_path.resolve()
    output_dir = output_dir.resolve()
    version = str(version or "").strip().lstrip("v")
    tag = str(tag or "").strip() or f"v{version}"
    repository = str(repository or "").strip()

    if not exe_path.is_file():
        raise FileNotFoundError(f"Executable not found: {exe_path}")
    if not REPOSITORY_RE.match(repository):
        raise ValueError("repository must be in owner/name form")
    if not tag.startswith("v"):
        tag = f"v{tag}"

    output_dir.mkdir(parents=True, exist_ok=True)
    digest = sha256_file(exe_path)
    checksum_path = write_checksum_file(exe_path, output_dir, digest)
    installer_url = f"https://github.com/{repository}/releases/download/{tag}/{exe_path.name}"

    package_manifest_dir = output_dir / "package-manifests"
    if package_manifest_dir.exists():
        shutil.rmtree(package_manifest_dir)
    package_manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_files = render_package_manifests(
        repo_root,
        package_manifest_dir,
        version,
        installer_url,
        digest,
    )
    package_zip_path = write_reproducible_zip(
        package_manifest_dir,
        output_dir / "HostsFileGet.package-manifests.zip",
    )

    artifact_manifest = {
        "schema": "hostsfileget.release-artifacts.v1",
        "version": version,
        "tag": tag,
        "repository": repository,
        "installer_url": installer_url,
        "executable": exe_path.name,
        "sha256": digest.upper(),
        "checksum_file": str(checksum_path),
        "package_manifest_dir": str(package_manifest_dir),
        "package_manifest_zip": str(package_zip_path),
        "package_manifest_files": [
            path.relative_to(package_manifest_dir).as_posix()
            for path in sorted(manifest_files)
        ],
    }
    artifact_manifest_path = output_dir / "HostsFileGet.release-artifacts.json"
    artifact_manifest["artifact_manifest"] = str(artifact_manifest_path)
    artifact_manifest_path.write_text(
        json.dumps(artifact_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return artifact_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate HostsFileGet release checksum and manifest artifacts.")
    parser.add_argument("--exe", required=True, help="Path to the built HostsFileGet executable.")
    parser.add_argument("--version", required=True, help="Release version, with or without a leading v.")
    parser.add_argument("--tag", required=True, help="Release tag, with or without a leading v.")
    parser.add_argument("--repository", required=True, help="GitHub repository in owner/name form.")
    parser.add_argument("--output-dir", default="dist", help="Directory for generated release artifacts.")
    parser.add_argument("--repo-root", default=str(REPO_ROOT), help="Repository root containing packaging templates.")
    args = parser.parse_args(argv)

    manifest = build_release_artifacts(
        Path(args.repo_root),
        Path(args.exe),
        args.version,
        args.tag,
        args.repository,
        Path(args.output_dir),
    )
    print(f"Wrote checksum: {manifest['checksum_file']}")
    print(f"Wrote package manifests: {manifest['package_manifest_dir']}")
    print(f"Wrote package manifest zip: {manifest['package_manifest_zip']}")
    print(f"Wrote artifact manifest: {manifest['artifact_manifest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
