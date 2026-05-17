"""Audit automation-facing CLI help and routing contracts without starting Tk."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import hosts_editor


SNAPSHOT_RELATIVE_PATH = Path("tests") / "fixtures" / "cli_contract_snapshot.json"
SNAPSHOT_SCHEMA = "hostsfileget.cli-contract-snapshot.v1"


def load_cli_contract_snapshot(repo_root: Path) -> dict:
    snapshot_path = repo_root / SNAPSHOT_RELATIVE_PATH
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if snapshot.get("schema") != SNAPSHOT_SCHEMA:
        raise ValueError(
            f"{snapshot_path} must use schema {SNAPSHOT_SCHEMA}, got {snapshot.get('schema')!r}."
        )
    return snapshot


def render_cli_help() -> str:
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        try:
            result = hosts_editor._handle_cli_args(["--help"])
        except SystemExit as exc:
            if exc.code not in (0, None):
                raise RuntimeError(f"--help exited with unexpected status {exc.code!r}.") from exc
        else:
            if result is None:
                raise RuntimeError("--help did not route through CLI argument handling.")
    return stream.getvalue()


def audit_help_sections(snapshot: dict, help_text: str) -> list[str]:
    errors: list[str] = []
    for section in snapshot.get("help_sections", []):
        section_id = section.get("id", "<unnamed>")
        for phrase in section.get("required_phrases", []):
            if phrase not in help_text:
                errors.append(f"help section {section_id!r} is missing {phrase!r}.")
    return errors


def audit_pure_cli_route_probes(snapshot: dict) -> list[str]:
    errors: list[str] = []
    tk_patch = mock.patch.object(
        hosts_editor.tk,
        "Tk",
        side_effect=AssertionError("Tk must not start for CLI probes"),
    )
    editor_patch = mock.patch.object(
        hosts_editor,
        "HostsFileEditor",
        side_effect=AssertionError("HostsFileEditor must not initialize for CLI probes"),
    )
    with tk_patch, editor_patch:
        for probe in snapshot.get("pure_cli_route_probes", []):
            probe_id = probe.get("id", "<unnamed>")
            handler_name = probe.get("handler")
            argv = list(probe.get("argv", []))
            if not handler_name or not hasattr(hosts_editor, handler_name):
                errors.append(f"route probe {probe_id!r} references missing handler {handler_name!r}.")
                continue
            with mock.patch.object(hosts_editor, handler_name, return_value=0) as handler:
                try:
                    result = hosts_editor._handle_cli_args(argv)
                except SystemExit as exc:
                    errors.append(f"route probe {probe_id!r} exited through argparse with {exc.code!r}.")
                    continue
            if result is None:
                errors.append(f"route probe {probe_id!r} did not route and would fall through to GUI startup.")
            elif result != 0:
                errors.append(f"route probe {probe_id!r} returned {result!r}, expected mocked handler status 0.")
            elif not handler.called:
                errors.append(f"route probe {probe_id!r} returned without calling {handler_name}.")
    return errors


def audit_cli_contract(repo_root: Path) -> list[str]:
    snapshot = load_cli_contract_snapshot(repo_root)
    errors = audit_help_sections(snapshot, render_cli_help())
    errors.extend(audit_pure_cli_route_probes(snapshot))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit HostsFileGet CLI automation contracts.")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--print-help", action="store_true", help="Print the captured HostsFileGet CLI help text.")
    args = parser.parse_args(argv)

    if args.print_help:
        print(render_cli_help(), end="")
        return 0

    repo_root = Path(args.repo_root).resolve()
    errors = audit_cli_contract(repo_root)
    if errors:
        for error in errors:
            print(f"cli-contract: {error}", file=sys.stderr)
        return 1
    print("CLI contract snapshot OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
