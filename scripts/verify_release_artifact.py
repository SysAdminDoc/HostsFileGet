"""Smoke-check a built HostsFileGet executable without opening the GUI."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


class ReleaseArtifactVerificationError(RuntimeError):
    """Raised when a release executable does not satisfy the CLI smoke contract."""


def _run_command(command: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _combined_output(result: subprocess.CompletedProcess) -> str:
    return "\n".join(part for part in (result.stdout, result.stderr) if part)


def run_release_artifact_check(
    command_prefix: list[str],
    expected_version: str,
    timeout: float = 15.0,
) -> dict:
    command_prefix = [str(part) for part in command_prefix if str(part)]
    expected_version = str(expected_version or "").strip().lstrip("v")
    if not command_prefix:
        raise ReleaseArtifactVerificationError("release command is empty")
    if not expected_version:
        raise ReleaseArtifactVerificationError("expected version is empty")

    version_result = _run_command(command_prefix + ["--version"], timeout)
    version_output = _combined_output(version_result)
    if version_result.returncode != 0:
        raise ReleaseArtifactVerificationError(
            f"--version exited {version_result.returncode}: {version_output.strip()}"
        )
    if expected_version not in version_output:
        raise ReleaseArtifactVerificationError(
            f"--version output did not contain {expected_version!r}: {version_output.strip()}"
        )

    help_result = _run_command(command_prefix + ["--help"], timeout)
    help_output = _combined_output(help_result)
    if help_result.returncode != 0:
        raise ReleaseArtifactVerificationError(
            f"--help exited {help_result.returncode}: {help_output.strip()}"
        )
    help_lower = help_output.lower()
    if "usage:" not in help_lower or "--version" not in help_output:
        raise ReleaseArtifactVerificationError("--help output did not look like the CLI help screen")

    return {
        "version_output": version_output.strip(),
        "help_first_line": next((line for line in help_output.splitlines() if line.strip()), ""),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a built HostsFileGet executable through non-GUI CLI flags.")
    parser.add_argument("--exe", required=True, help="Path to HostsFileGet.exe.")
    parser.add_argument("--expected-version", required=True, help="Expected application version.")
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-command timeout in seconds.")
    args = parser.parse_args(argv)

    exe_path = Path(args.exe)
    if not exe_path.is_file():
        print(f"release-artifact: executable not found: {exe_path}", file=sys.stderr)
        return 1

    try:
        result = run_release_artifact_check([str(exe_path)], args.expected_version, args.timeout)
    except (OSError, subprocess.TimeoutExpired, ReleaseArtifactVerificationError) as exc:
        print(f"release-artifact: {exc}", file=sys.stderr)
        return 1

    print(f"Version check: {result['version_output']}")
    print(f"Help check: {result['help_first_line']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
