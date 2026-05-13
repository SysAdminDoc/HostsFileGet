import tempfile
import unittest
from pathlib import Path

from scripts.render_package_manifests import (
    render_package_manifests,
    validate_release_inputs,
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


if __name__ == "__main__":
    unittest.main()
