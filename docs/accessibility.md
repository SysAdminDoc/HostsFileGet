# Accessibility Audit

HostsFileGet keeps a lightweight accessibility audit in code so contrast regressions fail in the normal test suite.

Run the audit coverage with:

```powershell
python -m unittest tests.test_hosts_editor_logic.HostsEditorLogicTests.test_accessibility_contrast_audit_passes_tracked_pairs -v
```

Open the in-app report from **Tools > Accessibility Audit...**.

## Covered Automatically

- WCAG-style contrast ratios for primary body text, muted labels, code/editor surfaces, focus rings, command buttons, and inline warning highlights.
- Font assumptions: Segoe UI for primary controls, Consolas for code/editor surfaces, and DPI awareness before Tk root creation.
- Assistive-technology notes that keep primary actions text-labeled and tooltips supplemental.

## Manual Windows Checks

Run these before a release that changes layout, colors, fonts, menus, dialogs, or editor focus behavior:

- Windows high contrast mode: launch the app, verify text remains readable, focus rings remain visible, and dialogs do not hide action buttons.
- Narrator or NVDA: traverse the menu bar, sidebar actions, editor, About dialog, Preferences dialog, and Accessibility Audit dialog.
- Keyboard-only pass: open menus with `Alt`, move through controls with `Tab` / `Shift+Tab`, close dialogs with `Esc`, and verify `Ctrl+F`, `Ctrl+S`, `Ctrl+Shift+S`, and `F5`.
- Font scaling: test at 125% and 150% display scale; confirm buttons and status text do not clip.

## Known Limits

Tk does not expose a full modern accessibility tree for every custom-styled surface. Prefer native `ttk` controls for new interactions, keep visible text labels on commands, and do not rely on color alone for critical state.
