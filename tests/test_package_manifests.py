import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.build_release_artifacts import build_release_artifacts
from scripts.render_package_manifests import (
    render_package_manifests,
    validate_release_inputs,
)
from scripts.check_release_identity import check_release_identity
from scripts.verify_release_artifact import (
    ReleaseArtifactVerificationError,
    run_release_artifact_check,
)


class PackageManifestTests(unittest.TestCase):
    def test_validate_release_inputs_normalizes_version_and_hash(self):
        values = validate_release_inputs(
            "v2.20.0",
            "https://github.com/SysAdminDoc/HostsFileGet/releases/download/v2.20.0/HostsFileGet.exe",
            "a" * 64,
        )

        self.assertEqual(values["VERSION"], "2.20.0")
        self.assertEqual(values["SHA256"], "A" * 64)

    def test_validate_release_inputs_rejects_unsafe_values(self):
        with self.assertRaises(ValueError):
            validate_release_inputs("2", "https://example.com/HostsFileGet.exe", "a" * 64)
        with self.assertRaises(ValueError):
            validate_release_inputs("2.20.0", "http://example.com/HostsFileGet.exe", "a" * 64)
        with self.assertRaises(ValueError):
            validate_release_inputs("2.20.0", "https://example.com/HostsFileGet.exe", "bad")

    def test_render_package_manifests_writes_winget_and_chocolatey_files(self):
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmpdir:
            written = render_package_manifests(
                repo_root,
                Path(tmpdir),
                "2.20.0",
                "https://github.com/SysAdminDoc/HostsFileGet/releases/download/v2.20.0/HostsFileGet.exe",
                "b" * 64,
            )
            relative_paths = {path.relative_to(tmpdir).as_posix() for path in written}

            self.assertIn("winget/SysAdminDoc.HostsFileGet.installer.yaml", relative_paths)
            self.assertIn("chocolatey/hostsfileget/hostsfileget.nuspec", relative_paths)
            installer = Path(tmpdir, "winget", "SysAdminDoc.HostsFileGet.installer.yaml").read_text(encoding="utf-8")
            chocolatey = Path(tmpdir, "chocolatey", "hostsfileget", "tools", "chocolateyInstall.ps1").read_text(encoding="utf-8")

        self.assertIn("InstallerSha256: " + "B" * 64, installer)
        self.assertIn("PackageVersion: 2.20.0", installer)
        self.assertIn("ChecksumType64 'sha256'", chocolatey)
        self.assertNotIn("{{", installer + chocolatey)

    def test_release_identity_docs_are_current(self):
        repo_root = Path(__file__).resolve().parents[1]
        self.assertEqual(check_release_identity(repo_root), [])

    def test_build_release_artifacts_writes_checksum_zip_and_manifest(self):
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            exe_path = output_dir / "HostsFileGet.exe"
            exe_path.write_bytes(b"release-bytes")

            manifest = build_release_artifacts(
                repo_root,
                exe_path,
                "2.20.0",
                "v2.20.0",
                "SysAdminDoc/HostsFileGet",
                output_dir,
            )

            expected_digest = hashlib.sha256(b"release-bytes").hexdigest().upper()
            checksum_text = Path(manifest["checksum_file"]).read_text(encoding="ascii")
            manifest_json = json.loads(Path(manifest["artifact_manifest"]).read_text(encoding="utf-8"))
            with zipfile.ZipFile(manifest["package_manifest_zip"]) as archive:
                zipped_names = set(archive.namelist())
                zip_timestamps = {info.date_time for info in archive.infolist()}

        self.assertEqual(checksum_text, f"{expected_digest}  HostsFileGet.exe\n")
        self.assertEqual(manifest_json["sha256"], expected_digest)
        self.assertEqual(
            manifest_json["installer_url"],
            "https://github.com/SysAdminDoc/HostsFileGet/releases/download/v2.20.0/HostsFileGet.exe",
        )
        self.assertEqual(manifest_json["artifact_manifest"], manifest["artifact_manifest"])
        self.assertIn("winget/SysAdminDoc.HostsFileGet.installer.yaml", zipped_names)
        self.assertIn("chocolatey/hostsfileget/hostsfileget.nuspec", zipped_names)
        self.assertEqual(zip_timestamps, {(1980, 1, 1, 0, 0, 0)})

    def test_verify_release_artifact_checks_version_and_help_without_gui(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_cli = Path(tmpdir) / "fake_hostsfileget.py"
            fake_cli.write_text(
                "\n".join([
                    "import sys",
                    "if '--version' in sys.argv:",
                    "    print('Hosts File Get v2.20.0')",
                    "    raise SystemExit(0)",
                    "if '--help' in sys.argv:",
                    "    print('usage: HostsFileGet [--version]')",
                    "    raise SystemExit(0)",
                    "raise SystemExit(2)",
                ]),
                encoding="utf-8",
            )

            result = run_release_artifact_check(
                [sys.executable, str(fake_cli)],
                "2.20.0",
                timeout=5,
            )
            with self.assertRaises(ReleaseArtifactVerificationError):
                run_release_artifact_check(
                    [sys.executable, str(fake_cli)],
                    "9.99.0",
                    timeout=5,
                )

        self.assertIn("v2.20.0", result["version_output"])
        self.assertIn("usage:", result["help_first_line"])


if __name__ == "__main__":
    unittest.main()
