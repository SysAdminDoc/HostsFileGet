# Runtime Compatibility

This matrix records what HostsFileGet supports, tests, and packages as of 2026-05-17.

## Current Local Evidence

Local verification for this roadmap pass ran on:

```text
Python 3.12.10
3.12.10 (tags/v3.12.10:0cc8128, Apr  8 2025, 12:21:36) [MSC v.1943 64 bit (AMD64)]
Windows-11-10.0.26100-SP0
```

The local validation command was:

```powershell
python -m py_compile hosts_editor.py hostsfileget\source_catalog.py hostsfileget\config_profiles.py tests\test_source_catalog.py tests\test_config_profiles.py tests\test_hosts_editor_logic.py tests\test_gui_smoke.py tests\test_benchmarks.py tests\test_package_manifests.py benchmarks\large_file_benchmark.py scripts\render_package_manifests.py scripts\build_release_artifacts.py scripts\verify_release_artifact.py scripts\check_release_identity.py
python -m unittest discover -s tests -v
python scripts\check_release_identity.py
python -m pip_audit -r requirements-build.txt --strict
```

## Support Matrix

| Runtime | Direct GUI/CLI | Unit tests | PyInstaller release build | Optional TUI | Launcher bootstrap | Current status |
| --- | --- | --- | --- | --- | --- | --- |
| Python 3.8-3.11 | Expected for direct run where Tkinter is present | Not in current CI | Not used for official release builds | `prompt_toolkit>=3.0.52,<4` declares `>=3.8` | Launcher may use an existing install if it can run the app | Compatible by dependency metadata, not actively tested |
| Python 3.12 | Supported | CI and local validation target | Official release workflow target | Supported when optional requirement is installed | Preferred tested baseline | Actively tested |
| Python 3.13 | Expected | Not in current CI | Expected by PyInstaller metadata | Expected by optional TUI metadata | Should work if installed and Tkinter is present | Compatibility candidate, not actively tested |
| Python 3.14 | Expected | CI matrix target | Supported by PyInstaller metadata, but not the release build baseline | Expected by optional TUI metadata | Should work if installed and Tkinter is present | Actively tested in CI matrix once workflow runs |
| Python 3.15+ | Not supported yet | Not tested | PyInstaller 6.20.0 metadata excludes Python 3.15 | Unknown | Not supported | Out of support until dependencies publish support |

## CI Targets

`.github/workflows/ci.yml` validates on Windows with:

- Python 3.12
- Python 3.14

Each matrix run prints `sys.version` and `platform.platform()` before validation so workflow logs record the exact interpreter and runner image.

`.github/workflows/release.yml` remains pinned to Python 3.12 for release builds. Release builds should stay on the stable baseline until a dedicated PyInstaller smoke build has been reviewed on a newer runtime.

`.github/workflows/source-health.yml` remains pinned to Python 3.12 because source-health is a scheduled operational check, not the compatibility matrix.

## Dependency Evidence

- PyInstaller 6.20.0 on PyPI declares `Requires: Python <3.15, >=3.8`: <https://pypi.org/project/pyinstaller/>
- The PyInstaller 6.20.0 manual says PyInstaller supports Python 3.8 and newer: <https://pyinstaller.org/en/v6.20.0/>
- `prompt_toolkit` 3.0.52 on PyPI declares `Requires: Python >=3.8`: <https://pypi.org/project/prompt-toolkit/3.0.52/>
- Python.org lists Python 3.14.5 as the current Python 3 release dated 2026-05-10: <https://www.python.org/downloads/release/python-3145/>

## Maintenance Rules

- Keep release builds pinned to one Python minor version at a time.
- Add a PyInstaller smoke build before moving the release workflow from Python 3.12 to 3.14.
- Keep `requirements-build.txt` pinned to a PyInstaller release that supports every CI Python target.
- Keep optional TUI support documented as optional; default GUI, CLI, release build, and scheduled source-health checks must not require `prompt_toolkit`.
- When changing CI Python minors, update this file, `docs/release.md`, `README.md`, and `PROJECT_CONTEXT.md`.
