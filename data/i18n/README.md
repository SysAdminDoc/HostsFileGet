# Translation Catalogs

`en-US.json` is the canonical fallback catalog.

To start a new locale:

```powershell
python hosts_editor.py --i18n-template es-MX data/i18n/es-MX.json
```

Before submitting changes:

```powershell
python hosts_editor.py --i18n-validate data/i18n/es-MX.json
```

Keep message keys unchanged and preserve format placeholders such as `{count}`.
