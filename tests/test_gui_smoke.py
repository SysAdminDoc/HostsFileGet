import tkinter as tk
import unittest
from unittest import mock

import hosts_editor
from hosts_editor import APP_NAME, APP_VERSION, HostsFileEditor


class HostsEditorGuiSmokeTests(unittest.TestCase):
    def _build_smoke_editor(self):
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"Tk root unavailable in this environment: {exc}")

        root.withdraw()
        self.addCleanup(self._destroy_root, root)

        patches = [
            mock.patch.object(HostsFileEditor, "check_admin_privileges", return_value=True),
            mock.patch.object(HostsFileEditor, "load_config", return_value=None),
            mock.patch.object(HostsFileEditor, "load_file", return_value=None),
            mock.patch.object(HostsFileEditor, "maybe_show_first_run_wizard", return_value=None),
            mock.patch.object(HostsFileEditor, "maybe_auto_update_on_launch", return_value=None),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

        editor = HostsFileEditor(root)
        root.update_idletasks()
        return root, editor

    def _destroy_root(self, root):
        try:
            if root.winfo_exists():
                root.destroy()
        except tk.TclError:
            pass

    def _destroy_toplevels(self, root):
        for child in root.winfo_children():
            if isinstance(child, tk.Toplevel):
                child.destroy()
        root.update_idletasks()

    def test_main_window_builds_core_widgets(self):
        root, editor = self._build_smoke_editor()

        self.assertEqual(root.title(), f"{APP_NAME} v{APP_VERSION}")
        self.assertTrue(editor.text_area.winfo_exists())
        self.assertTrue(editor.whitelist_text_area.winfo_exists())
        self.assertTrue(editor.btn_save_cleaned.winfo_exists())
        self.assertEqual(editor.status_label.cget("text"), "Loading...")

    def test_about_and_preferences_dialogs_open(self):
        root, editor = self._build_smoke_editor()

        editor.show_about_dialog()
        root.update_idletasks()
        titles = [child.title() for child in root.winfo_children() if isinstance(child, tk.Toplevel)]
        self.assertIn(f"About {hosts_editor.APP_NAME}", titles)
        self._destroy_toplevels(root)

        editor.show_preferences()
        root.update_idletasks()
        titles = [child.title() for child in root.winfo_children() if isinstance(child, tk.Toplevel)]
        self.assertIn("Preferences", titles)
        self._destroy_toplevels(root)


if __name__ == "__main__":
    unittest.main()
