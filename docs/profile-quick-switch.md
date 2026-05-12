# Profile Quick Switch

HostsFileGet supports saved-profile switching from the GUI without writing the system hosts file.

Source basis: SwitchHosts tray switching (O1), HostsFileEditor tray behavior (O2), and Gas Mask menu-bar switching (O3) in `ROADMAP.md`.

## Behavior

- **Tools > Profile Quick Switch...** lists saved app-config profiles, marks the active profile, and can activate another profile.
- **Tools > Start Tray Quick Switch...** starts an optional system-tray menu with one item per saved profile.
- Profile switching updates app config only: active profile ID, whitelist, custom sources, pinned domains, and preferred block sink.
- The system hosts file is not read, written, disabled, enabled, or flushed by quick switching.
- The current active profile is mirrored into the saved profile list before another profile is activated, matching the normal config-save behavior.
- Switching is blocked while imports are running or while unsaved editor changes are pending.

## Optional Tray Dependency

Tkinter has no native Windows tray API. Tray quick switch is therefore optional and loaded dynamically.

Install the optional packages only if tray support is needed:

```powershell
python -m pip install pystray Pillow
```

If those packages are absent, HostsFileGet still starts normally and **Profile Quick Switch...** remains available. **Start Tray Quick Switch...** shows a dependency report instead of failing app startup.

Frozen PyInstaller builds keep tray modules out of the default executable. To bundle tray support into a release artifact, install `pystray` and Pillow in the build environment and set `HOSTSFILEGET_BUNDLE_TRAY=1` before running PyInstaller. Builds without that variable still succeed and keep the tray path disabled at runtime.

## Safety Boundaries

- Quick switching is not a parental-control enforcer by itself.
- Switching profiles changes future import/clean behavior because whitelist, source, pin, and block-sink settings change.
- After a successful profile switch, saved-hosts hash markers are cleared so the UI does not imply that the current editor text was saved under the newly active profile.
- Use **Save Raw** or **Save Cleaned** explicitly when the active profile should affect the real hosts file.

## Test Coverage

Regression coverage includes:

- profile quick-switch report formatting and counts
- config-only profile activation through the quick-switch helper
- optional tray dependency missing-module reporting
- optional tray dependency available-module reporting
