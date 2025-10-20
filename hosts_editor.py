# hosts_editor_v2_6.py
# Hosts File Management Tool — v2.6
# Changes vs v2.5:
# - True dark modern ttk theme
# - Two-column layout: fixed-width scrollable sidebar (left), full-height editor (right)
# - "Revert to Backup" with diff preview before restore
# - All original features preserved: pfSense import, imports, cleaning/dedup, preview, whitelist persistence, DNS flush, backup on save
#
# Standard library only. Tested on Windows (tkinter included with Python).

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font, filedialog, simpledialog
import os
import ctypes
import difflib
import subprocess
import urllib.request
import urllib.error
import json
import webbrowser

# ----------------------------- Tooltip Helper -------------------------------
class ToolTip:
    """Creates a tooltip for a given widget."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        try:
            x, y, _, _ = self.widget.bbox("insert")
        except Exception:
            x, y = (0, 0)
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25

        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self.tooltip_window,
            text=self.text,
            justify="left",
            background="#1A1A1A",
            foreground="#DADADA",
            relief="solid",
            borderwidth=1,
            font=("Segoe UI", 9),
        )
        label.pack(ipadx=6, ipady=3)

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
        self.tooltip_window = None


# ------------------------------ Preview Window ------------------------------
class PreviewWindow(tk.Toplevel):
    def __init__(self, parent, original_lines, new_lines, title="Preview Changes", on_apply_callback=None):
        super().__init__(parent.root)
        self.parent_editor = parent
        self.new_lines = new_lines
        self.on_apply_callback = on_apply_callback

        self.title(title)
        self.geometry("900x650")
        self.configure(bg="#121212")
        self.transient(parent.root)
        self.grab_set()

        text_frame = ttk.Frame(self, padding=(10, 10, 10, 0))
        text_frame.pack(expand=True, fill='both')
        self.preview_text = scrolledtext.ScrolledText(
            text_frame, wrap=tk.WORD, font=("Consolas", 11),
            bg="#0F0F0F", fg="#E6E6E6", insertbackground="#FFFFFF",
            selectbackground="#0A84FF", relief="flat"
        )
        self.preview_text.pack(expand=True, fill='both')

        button_frame = ttk.Frame(self, padding=10)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)

        legend_frame = ttk.Frame(button_frame)
        legend_frame.pack(side=tk.LEFT)
        tk.Label(legend_frame, text="■ Added", fg="#89D68D", bg="#121212").pack(side=tk.LEFT)
        tk.Label(legend_frame, text="■ Removed", fg="#FF7B72", bg="#121212").pack(side=tk.LEFT, padx=10)

        ttk.Button(button_frame, text="Apply Changes", command=self.apply_changes, style="Accent.TButton").pack(side=tk.RIGHT, padx=6)
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=6)

        self.preview_text.tag_config('added', foreground="#89D68D")
        self.preview_text.tag_config('removed', foreground="#FF7B72")
        self.display_diff(original_lines, new_lines)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def display_diff(self, original, new):
        diff = difflib.ndiff(original, new)
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete('1.0', tk.END)
        for line in diff:
            line_content = line[2:] + '\n'
            if line.startswith('+ '):
                self.preview_text.insert(tk.END, line_content, 'added')
            elif line.startswith('- '):
                self.preview_text.insert(tk.END, line_content, 'removed')
            elif not line.startswith('? '):
                self.preview_text.insert(tk.END, line_content)
        self.preview_text.config(state=tk.DISABLED)

    def apply_changes(self):
        if self.on_apply_callback:
            self.on_apply_callback(self.new_lines)
        else:
            self.parent_editor.set_text(self.new_lines)
            self.parent_editor.update_status(f"Changes from '{self.title()}' applied.")
        self.destroy()


# -------------------------- Add Custom Source Dialog -------------------------
class AddSourceDialog(simpledialog.Dialog):
    def body(self, master):
        self.title("Add Custom Blacklist Source")
        ttk.Label(master, text="Button Name:").grid(row=0, sticky='w', pady=5)
        ttk.Label(master, text="Source URL:").grid(row=1, sticky='w', pady=5)
        self.name_entry = ttk.Entry(master, width=40)
        self.url_entry = ttk.Entry(master, width=40)
        self.name_entry.grid(row=0, column=1, padx=5)
        self.url_entry.grid(row=1, column=1, padx=5)
        return self.name_entry

    def apply(self):
        name, url = self.name_entry.get().strip(), self.url_entry.get().strip()
        if name and url:
            if not url.lower().startswith(('http://', 'https://')):
                messagebox.showerror("Invalid URL", "URL must start with http:// or https://", parent=self)
                self.result = None
            else:
                self.result = (name, url)
        else:
            messagebox.showwarning("Input Required", "Both name and URL are required.", parent=self)
            self.result = None


# ------------------------------- Main App -----------------------------------
class HostsFileEditor:
    HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"
    CONFIG_FILE = "hosts_editor_config.json"

    def __init__(self, root):
        self.root = root
        self.root.title("Hosts File Management Tool v2.6")
        self.root.geometry("1360x880")
        self.root.configure(bg="#121212")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.default_font = font.Font(family="Segoe UI", size=10)
        self.title_font = font.Font(family="Segoe UI", size=11, weight="bold")
        self.custom_sources = []

        # ---- True Dark Theme for ttk ----------------------------------------
        style = ttk.Style()
        style.theme_use("clam")
        # Base colors
        DARK_BG = "#121212"
        PANEL_BG = "#1E1E1E"
        SUBPANEL_BG = "#252526"
        TEXT_FG = "#E6E6E6"
        MUTED_FG = "#C0C0C0"
        BTN_BG = "#2B2B2B"
        BTN_BG_HOVER = "#373737"
        ACCENT_BG = "#0A84FF"
        ACCENT_BG_HOVER = "#086BD1"
        BORDER = "#2A2A2A"

        style.configure(".", background=DARK_BG, foreground=TEXT_FG, fieldbackground=SUBPANEL_BG)
        style.configure("TFrame", background=DARK_BG)
        style.configure("TLabel", background=DARK_BG, foreground=TEXT_FG)
        style.configure("TSeparator", background=BORDER)
        style.configure("TLabelFrame", background=PANEL_BG, foreground=TEXT_FG, borderwidth=0, relief="flat")
        style.configure("TLabelframe.Label", background=PANEL_BG, foreground=TEXT_FG, font=self.title_font)

        style.configure("TButton",
                        background=BTN_BG, foreground=TEXT_FG,
                        padding=(10, 6), relief="flat", borderwidth=0)
        style.map("TButton",
                  background=[("active", BTN_BG_HOVER)],
                  relief=[("pressed", "sunken")])

        style.configure("Accent.TButton",
                        background=ACCENT_BG, foreground="#FFFFFF",
                        padding=(10, 6), relief="flat", borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", ACCENT_BG_HOVER)])

        # ---- Root layout: Sidebar (fixed width) + Editor --------------------
        root_container = ttk.Frame(root, padding=8)
        root_container.pack(fill="both", expand=True)

        # Left sidebar (fixed width) with vertical scrolling
        sidebar_outer = ttk.Frame(root_container)
        sidebar_outer.pack(side="left", fill="y")
        # Fix width
        SIDEBAR_WIDTH = 380
        sidebar_outer.configure(width=SIDEBAR_WIDTH)
        sidebar_outer.pack_propagate(False)

        # Scrollable sidebar content
        sidebar_canvas = tk.Canvas(sidebar_outer, bg=PANEL_BG, highlightthickness=0, bd=0, relief="flat")
        sidebar_vscroll = ttk.Scrollbar(sidebar_outer, orient="vertical", command=sidebar_canvas.yview)
        self.sidebar_inner = ttk.Frame(sidebar_canvas)  # real content frame

        self.sidebar_inner.bind(
            "<Configure>",
            lambda e: sidebar_canvas.configure(scrollregion=sidebar_canvas.bbox("all"))
        )
        sidebar_canvas.create_window((0, 0), window=self.sidebar_inner, anchor="nw", width=SIDEBAR_WIDTH)
        sidebar_canvas.configure(yscrollcommand=sidebar_vscroll.set)

        sidebar_canvas.pack(side="left", fill="y", expand=False)
        sidebar_vscroll.pack(side="right", fill="y")

        # Right editor area
        right_area = ttk.Frame(root_container, padding=(8, 0, 0, 0))
        right_area.pack(side="left", fill="both", expand=True)

        # ------------------------ Menu Bar -----------------------------------
        menu_bar = tk.Menu(self.root, tearoff=0, bg=PANEL_BG, fg=TEXT_FG, activebackground=ACCENT_BG, activeforeground="#FFFFFF")
        self.root.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0, bg=PANEL_BG, fg=TEXT_FG, activebackground=ACCENT_BG, activeforeground="#FFFFFF")
        file_menu.add_command(label="Save Changes", command=self.save_file)
        file_menu.add_command(label="Refresh", command=self.load_file)
        file_menu.add_command(label="Revert to Backup", command=self.revert_to_backup)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)
        menu_bar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menu_bar, tearoff=0, bg=PANEL_BG, fg=TEXT_FG, activebackground=ACCENT_BG, activeforeground="#FFFFFF")
        tools_menu.add_command(label="Clean", command=self.auto_clean)
        tools_menu.add_command(label="Deduplicate", command=self.deduplicate)
        tools_menu.add_command(label="Flush DNS", command=self.flush_dns)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menu_bar, tearoff=0, bg=PANEL_BG, fg=TEXT_FG, activebackground=ACCENT_BG, activeforeground="#FFFFFF")
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo(
            "About",
            "Hosts File Management Tool v2.6\nTrue dark UI, sidebar layout, and Revert to Backup.\nCreated by Steve. Enhanced by ChatGPT."
        ))
        help_menu.add_command(label="GitHub (HOSTShield)", command=lambda: webbrowser.open("https://github.com/SysAdminDoc/HOSTShield"))
        menu_bar.add_cascade(label="Help", menu=help_menu)

        # ------------------- Sidebar Sections (Left) -------------------------
        # Section: File Ops
        file_ops = ttk.LabelFrame(self.sidebar_inner, text="File")
        file_ops.pack(fill="x", padx=8, pady=(8, 4))
        self._btn(file_ops, "Save Changes", self.save_file, "Clean, whitelist, preview, then save.", accent=True).pack(fill="x", pady=4)
        self._btn(file_ops, "Refresh", self.load_file, "Reload hosts file from disk.").pack(fill="x", pady=4)
        self._btn(file_ops, "Revert to Backup", self.revert_to_backup, "Preview and restore from .bak if available.", accent=False).pack(fill="x", pady=4)

        # Section: Search / Filter
        search_frame = ttk.LabelFrame(self.sidebar_inner, text="Search / Filter")
        search_frame.pack(fill="x", padx=8, pady=4)
        self.search_var = tk.StringVar()
        entry = ttk.Entry(search_frame, textvariable=self.search_var)
        entry.pack(fill="x", padx=8, pady=(8, 4))
        btns = ttk.Frame(search_frame)
        btns.pack(fill="x", padx=8, pady=(0, 8))
        self._btn(btns, "Find", self.search_find, "Find first match (case-insensitive).").pack(side="left", expand=True, fill="x", padx=(0, 4))
        self._btn(btns, "Prev", self.search_prev, "Find previous match.").pack(side="left", expand=True, fill="x", padx=4)
        self._btn(btns, "Next", self.search_next, "Find next match.").pack(side="left", expand=True, fill="x", padx=4)
        self._btn(btns, "Clear", self.search_clear, "Clear highlights.").pack(side="left", expand=True, fill="x", padx=(4, 0))

        # Section: Import Blacklists
        import_frame = ttk.LabelFrame(self.sidebar_inner, text="Import Blacklists")
        import_frame.pack(fill="x", padx=8, pady=4)

        local_import_frame = ttk.LabelFrame(import_frame, text="Import From File")
        local_import_frame.pack(fill="x", padx=8, pady=(8, 4))
        self._btn(local_import_frame, "From pfSense Log", self.import_pfsense_log, "Import domains from pfSense DNSBL log.").pack(fill="x", pady=2)

        web_import_frame = ttk.LabelFrame(import_frame, text="Universal Blacklists")
        web_import_frame.pack(fill="x", padx=8, pady=4)
        self._btn(web_import_frame, "HOSTShield", self.import_hostshield, "Append HOSTShield blocklist.").pack(fill="x", pady=2)
        self._btn(web_import_frame, "StevenBlack", self.import_stevenblack, "Append StevenBlack unified blocklist.").pack(fill="x", pady=2)
        self._btn(web_import_frame, "HaGezi Ultimate", self.import_hagezi, "Append HaGezi Ultimate DNS blocklist.").pack(fill="x", pady=2)
        self._btn(web_import_frame, "AdAway", self.import_adaway, "Append AdAway mobile ad blocklist.").pack(fill="x", pady=2)

        specific_import_frame = ttk.LabelFrame(import_frame, text="Specific Blacklists")
        specific_import_frame.pack(fill="x", padx=8, pady=4)
        self._btn(specific_import_frame, "Block Adobe", self.import_adobe, "Block Adobe activation servers.").pack(fill="x", pady=2)
        self._btn(specific_import_frame, "Block CCleaner", self.import_ccleaner, "Block CCleaner telemetry.").pack(fill="x", pady=2)
        self._btn(specific_import_frame, "Block Microsoft", self.import_microsoft, "Block Microsoft telemetry.").pack(fill="x", pady=2)

        # Section: Custom Sources
        self.custom_sources_frame = ttk.LabelFrame(self.sidebar_inner, text="Custom Blacklists")
        self.custom_sources_frame.pack(fill="x", padx=8, pady=4)
        self._btn(self.custom_sources_frame, "+ Add Source", self.show_add_source_dialog, "Add a new custom URL source.", accent=True).pack(fill="x", pady=2)

        # Section: Utilities
        utilities_frame = ttk.LabelFrame(self.sidebar_inner, text="Utilities")
        utilities_frame.pack(fill="x", padx=8, pady=4)
        util_row = ttk.Frame(utilities_frame)
        util_row.pack(fill="x", padx=8, pady=8)
        self._btn(util_row, "Clean", self.auto_clean, "Clean and format hosts file.").pack(side="left", expand=True, fill="x", padx=(0, 6))
        self._btn(util_row, "Deduplicate", self.deduplicate, "Remove duplicate entries.").pack(side="left", expand=True, fill="x", padx=6)
        self._btn(util_row, "Flush DNS", self.flush_dns, "Flush Windows DNS cache.", accent=True).pack(side="left", expand=True, fill="x", padx=(6, 0))

        # Section: Whitelist
        whitelist_frame = ttk.LabelFrame(self.sidebar_inner, text="Persistent Whitelist (Auto-Applied)")
        whitelist_frame.pack(fill="both", padx=8, pady=(4, 8))
        self.whitelist_text_area = scrolledtext.ScrolledText(
            whitelist_frame, wrap=tk.WORD, height=10, font=("Consolas", 10),
            bg="#0F0F0F", fg="#E6E6E6", insertbackground="#FFFFFF",
            selectbackground="#0A84FF", relief="flat"
        )
        self.whitelist_text_area.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        w_btns = ttk.Frame(whitelist_frame)
        w_btns.pack(fill="x", padx=8, pady=(0, 8))
        self._btn(w_btns, "Load from File", self.load_whitelist_from_file, "Load whitelist from a text file.").pack(side="left", expand=True, fill="x", padx=(0, 6))
        self._btn(w_btns, "Import from Web", self.import_whitelist_from_web, "Import default HOSTShield whitelist.", accent=True).pack(side="left", expand=True, fill="x", padx=(6, 0))

        # -------------------- Editor Area (Right) -----------------------------
        editor_panel = ttk.Frame(right_area)
        editor_panel.pack(fill="both", expand=True)

        # Main text editor takes full height on the right
        self.text_area = scrolledtext.ScrolledText(
            editor_panel, wrap=tk.WORD, font=("Consolas", 12),
            bg="#0F0F0F", fg="#E6E6E6", insertbackground="#FFFFFF",
            selectbackground="#0A84FF", relief="flat"
        )
        self.text_area.pack(expand=True, fill='both')

        # Status bar across the bottom
        status_frame = ttk.Frame(root, padding=(10, 6, 10, 10))
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = ttk.Label(status_frame, text="Loading...", font=self.default_font, foreground=MUTED_FG)
        self.status_label.pack(side=tk.LEFT)

        # Search highlighting setup
        self._search_matches = []
        self._search_index = -1
        self.text_area.tag_configure("search_match", background="#0A84FF", foreground="#FFFFFF")
        self.text_area.tag_configure("search_current", background="#89D68D", foreground="#000000")

        # Finish init
        self.check_admin_privileges()
        self.load_config()
        self.load_file(is_initial_load=True)

    # ----------------------------- UI Helpers --------------------------------
    def _btn(self, parent, text, command, tooltip, accent=False):
        style = "Accent.TButton" if accent else "TButton"
        btn = ttk.Button(parent, text=text, command=command, style=style)
        ToolTip(btn, tooltip)
        return btn

    def update_status(self, message, is_error=False):
        color = "#FF6B6B" if is_error else "#C0C0C0"
        self.status_label.config(text=message, foreground=color)
        # fade back to neutral after delay
        self.root.after(4000, lambda: self.status_label.config(foreground="#C0C0C0"))

    def on_closing(self):
        self.save_config()
        self.root.destroy()

    # --------------------------- Admin Check ---------------------------------
    def check_admin_privileges(self):
        try:
            is_admin = (os.getuid() == 0)
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            self.update_status("Warning: Not running as Administrator. You cannot save.", is_error=True)
            messagebox.showwarning("Admin Rights Required", "Run as Administrator to save changes.")

    # ------------------------- Config Persistence ----------------------------
    def load_config(self):
        try:
            if os.path.exists(self.CONFIG_FILE):
                with open(self.CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                self.whitelist_text_area.delete('1.0', tk.END)
                self.whitelist_text_area.insert('1.0', config.get("whitelist", ""))
                self.custom_sources = config.get("custom_sources", [])
                for source in self.custom_sources:
                    self._create_custom_source_button(source['name'], source['url'])
                self.update_status("Configuration loaded.")
        except Exception as e:
            self.update_status(f"Could not load config: {e}", is_error=True)

    def save_config(self):
        config = {
            "whitelist": self.whitelist_text_area.get('1.0', tk.END).strip(),
            "custom_sources": self.custom_sources
        }
        try:
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4)
        except IOError as e:
            print(f"Error saving config: {e}")

    # ----------------------------- File Ops ----------------------------------
    def get_lines(self):
        return self.text_area.get('1.0', tk.END).splitlines()

    def set_text(self, lines):
        self.text_area.delete('1.0', tk.END)
        self.text_area.insert(tk.END, '\n'.join(lines))

    def load_file(self, is_initial_load=False):
        try:
            if os.path.exists(self.HOSTS_FILE_PATH):
                with open(self.HOSTS_FILE_PATH, 'r', encoding='utf-8') as f:
                    self.set_text(f.read().splitlines())
                self.update_status(f"Loaded '{self.HOSTS_FILE_PATH}'")
            else:
                self.update_status("Hosts file not found.", is_error=True)
        except Exception as e:
            self.update_status(f"Error loading file: {e}", is_error=True)
            messagebox.showerror("Error", f"Error loading file:\n{e}")

    def save_file(self):
        original_lines = self.get_lines()
        whitelisted_lines = self._get_filtered_lines_by_whitelist(original_lines)
        final_lines = self._get_cleaned_lines(whitelisted_lines)

        if original_lines != final_lines:
            def proceed_with_save(approved_lines):
                self._execute_save('\n'.join(approved_lines))
                num_removed = len(original_lines) - len(whitelisted_lines)
                self.update_status(f"{num_removed} entries removed by whitelist. File cleaned and saved.")
            PreviewWindow(self, original_lines, final_lines, title="Preview: Final Changes (Cleaned & Whitelisted)", on_apply_callback=proceed_with_save)
        else:
            self._execute_save('\n'.join(original_lines))

    def _execute_save(self, content_to_save):
        if not content_to_save.strip():
            if not messagebox.askyesno("Confirm Empty Save", "Content is empty. Clear hosts file?"):
                return

        backup_path = self.HOSTS_FILE_PATH + ".bak"
        # Create/update backup
        try:
            if os.path.exists(self.HOSTS_FILE_PATH):
                with open(self.HOSTS_FILE_PATH, 'r', encoding='utf-8') as f_in, open(backup_path, 'w', encoding='utf-8') as f_out:
                    f_out.write(f_in.read())
        except Exception as e:
            if not messagebox.askyesno("Backup Failed", f"Could not create backup.\nError: {e}\n\nSave anyway?"):
                return

        try:
            with open(self.HOSTS_FILE_PATH, 'w', encoding='utf-8') as f:
                f.write(content_to_save)
            self.update_status(f"Saved successfully. Backup created: '{backup_path}'")
            messagebox.showinfo("Success", "Hosts file saved successfully!")
        except PermissionError:
            self.update_status("Save failed: Permission denied.", is_error=True)
            messagebox.showerror("Error", "Permission denied. Run as Administrator.")
        except Exception as e:
            self.update_status(f"Save error: {e}", is_error=True)

    # ----------------------- Revert to Backup (NEW) --------------------------
    def revert_to_backup(self):
        backup_path = self.HOSTS_FILE_PATH + ".bak"
        if not os.path.exists(backup_path):
            messagebox.showinfo("Revert to Backup", "No backup file found. Save once to create a backup.")
            return

        try:
            with open(self.HOSTS_FILE_PATH, 'r', encoding='utf-8') as current_f:
                current_lines = current_f.read().splitlines()
        except Exception as e:
            self.update_status(f"Error reading current hosts: {e}", is_error=True)
            messagebox.showerror("Error", f"Error reading current hosts:\n{e}")
            return

        try:
            with open(backup_path, 'r', encoding='utf-8') as bak_f:
                backup_lines = bak_f.read().splitlines()
        except Exception as e:
            self.update_status(f"Error reading backup: {e}", is_error=True)
            messagebox.showerror("Error", f"Error reading backup:\n{e}")
            return

        def do_restore(approved_lines):
            try:
                with open(self.HOSTS_FILE_PATH, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(approved_lines))
                self.set_text(approved_lines)
                self.update_status("Backup restored successfully.")
                messagebox.showinfo("Restored", "Hosts file restored from backup.")
            except PermissionError:
                self.update_status("Restore failed: Permission denied.", is_error=True)
                messagebox.showerror("Error", "Permission denied. Run as Administrator.")
            except Exception as e:
                self.update_status(f"Restore error: {e}", is_error=True)

        # Show preview diff: current -> backup
        PreviewWindow(self, current_lines, backup_lines, title="Preview: Restore from Backup", on_apply_callback=do_restore)

    # ----------------------------- Imports -----------------------------------
    def fetch_and_append_hosts(self, source_name, url=None, lines_to_add=None):
        self.update_status(f"Importing from {source_name}...")
        self.root.update_idletasks()
        try:
            if url:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req) as response:
                    new_lines = response.read().decode('utf-8', errors='ignore').splitlines()
            elif lines_to_add:
                new_lines = lines_to_add
            else:
                raise ValueError("Either url or lines_to_add must be provided.")

            if not new_lines:
                self.update_status(f"No content from {source_name}.", is_error=True)
                return

            current_lines = self.get_lines()
            if current_lines and current_lines[-1].strip() != "":
                current_lines.append("")
            current_lines.append(f"# --- Imported from {source_name} ---")
            current_lines.extend(new_lines)
            self.set_text(current_lines)

            num_removed = self.run_auto_whitelist_filter()
            self.update_status(f"Imported from {source_name}. Removed {num_removed} entries via whitelist.")
            messagebox.showinfo("Import Successful", f"Added content from {source_name}.\n{num_removed} whitelisted entries removed.")
        except Exception as e:
            self.update_status(f"Import failed: {e}", is_error=True)
            messagebox.showerror("Import Error", f"Failed to import from {source_name}:\n{e}")

    def import_pfsense_log(self):
        """Allows the user to import a pfSense DNSBL log file by extracting domains."""
        filepath = filedialog.askopenfilename(
            title="Select pfSense DNSBL Log File",
            filetypes=(("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*"))
        )
        if not filepath:
            return

        self.update_status(f"Importing from {os.path.basename(filepath)}...")
        self.root.update_idletasks()

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                log_lines = f.readlines()

            extracted_domains = set()
            for line in log_lines:
                parts = line.strip().split(',')
                if len(parts) > 2 and "DNSBL" in parts[0]:
                    domain = parts[2].strip()
                    if domain:
                        extracted_domains.add(domain)

            if not extracted_domains:
                self.update_status(f"No valid DNSBL domains found in '{os.path.basename(filepath)}'.")
                messagebox.showinfo("Import Info", "No valid DNSBL domains were found in the selected file.")
                return

            new_domains_to_add = sorted(list(extracted_domains))
            self.fetch_and_append_hosts(os.path.basename(filepath), lines_to_add=new_domains_to_add)

        except Exception as e:
            self.update_status(f"Error importing log file: {e}", is_error=True)
            messagebox.showerror("Import Error", f"An unexpected error occurred while processing the log file:\n{e}")

    def import_hostshield(self):
        self.fetch_and_append_hosts("HOSTShield", url="https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/HOSTS.txt")

    def import_stevenblack(self):
        self.fetch_and_append_hosts("StevenBlack", url="https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts")

    def import_hagezi(self):
        self.fetch_and_append_hosts("HaGezi Ultimate", url="https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/ultimate.txt")

    def import_adaway(self):
        self.fetch_and_append_hosts("AdAway", url="https://adaway.org/hosts.txt")

    def import_adobe(self):
        self.fetch_and_append_hosts("Adobe Blocklist", url="https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/AdobeHosts.txt")

    def import_ccleaner(self):
        ccleaner_hosts = [
            "0.0.0.0 ncc.avast.com", "0.0.0.0 ncc.avast.com.edgesuite.net", "0.0.0.0 license.piriform.com",
            "0.0.0.0 ipm-provider.ff.avast.com", "0.0.0.0 shepherd.ff.avast.com",
            "0.0.0.0 ip-info.ff.avast.com", "0.0.0.0 analytics.ff.avast.com"
        ]
        self.fetch_and_append_hosts("CCleaner Blocklist", lines_to_add=ccleaner_hosts)

    def import_microsoft(self):
        self.fetch_and_append_hosts("Microsoft Blocklist", url="https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Microsoft.txt")

    # ------------------------- Custom Sources ---------------------------------
    def show_add_source_dialog(self):
        dialog = AddSourceDialog(self.root)
        if dialog.result:
            name, url = dialog.result
            if any(s['name'] == name for s in self.custom_sources):
                messagebox.showerror("Error", "Source name already exists.")
                return
            self.custom_sources.append({'name': name, 'url': url})
            self._create_custom_source_button(name, url)
            self.update_status(f"Added custom source: {name}")

    def _create_custom_source_button(self, name, url):
        tooltip = f"Appends the custom '{name}' blocklist."
        btn = self._btn(self.custom_sources_frame, name, lambda u=url, n=name: self.fetch_and_append_hosts(n, url=u), tooltip, accent=False)
        btn.pack(side=tk.TOP, fill=tk.X, pady=2)

    # ----------------------- Whitelist & Filtering ---------------------------
    def load_whitelist_from_file(self):
        filepath = filedialog.askopenfilename(title="Select Whitelist File", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if not filepath:
            return
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self.whitelist_text_area.delete('1.0', tk.END)
            self.whitelist_text_area.insert('1.0', content)
            self.update_status(f"Loaded whitelist from '{os.path.basename(filepath)}'.")
        except Exception as e:
            messagebox.showerror("File Error", f"Could not load whitelist:\n{e}")

    def import_whitelist_from_web(self):
        url = "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Whitelist.txt"
        self.update_status("Importing whitelist...")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                content = response.read().decode('utf-8', errors='ignore')
            self.whitelist_text_area.delete('1.0', tk.END)
            self.whitelist_text_area.insert('1.0', content)
            self.update_status("Whitelist imported from HOSTShield.")
        except Exception as e:
            messagebox.showerror("Network Error", f"Could not fetch whitelist:\n{e}")

    def _get_filtered_lines_by_whitelist(self, lines):
        whitelist_content = self.whitelist_text_area.get('1.0', tk.END)
        whitelist = {line.strip().lower().lstrip('.') for line in whitelist_content.splitlines() if line.strip()}
        if not whitelist:
            return lines

        final_lines = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                final_lines.append(line)
                continue
            parts = stripped.split()
            if len(parts) < 2 or parts[1].lower() not in whitelist:
                final_lines.append(line)
        return final_lines

    def run_auto_whitelist_filter(self):
        original = self.get_lines()
        filtered = self._get_filtered_lines_by_whitelist(original)
        if original != filtered:
            self.set_text(filtered)
        return len(original) - len(filtered)

    # ------------------------------ Utilities --------------------------------
    def flush_dns(self):
        try:
            if os.name == 'nt':
                subprocess.run(['ipconfig', '/flushdns'], capture_output=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                messagebox.showinfo("DNS Flushed", "DNS resolver cache flushed.")
            else:
                messagebox.showwarning("Unsupported OS", "Only available on Windows.")
        except Exception as e:
            self.update_status(f"Error flushing DNS: {e}", is_error=True)

    def process_and_preview(self, processor, title):
        original = self.get_lines()
        processed = processor(original)
        if original != processed:
            PreviewWindow(self, original, processed, title=title)
        else:
            self.update_status("No changes to apply.")

    def deduplicate(self):
        def processor(lines):
            seen, unique = set(), []
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    lowered = stripped.lower()
                    if lowered not in seen:
                        seen.add(lowered)
                        unique.append(line)
                else:
                    unique.append(line)
            return unique
        self.process_and_preview(processor, "Preview: Deduplicate")

    def auto_clean(self):
        self.process_and_preview(self._get_cleaned_lines, "Preview: Clean")

    def _get_cleaned_lines(self, lines):
        seen, final_lines = set(), []
        preserved_lines = [line for line in lines if line.strip().startswith('#') or not line.strip()]

        for line in lines:
            processed = line.split('#', 1)[0].strip()
            if not processed:
                continue
            parts = processed.split()
            if not parts:
                continue
            hostname = parts[-1].lower()
            if hostname in ('127.0.0.1', '0.0.0.0', 'localhost'):
                continue
            clean_line = f"0.0.0.0 {hostname}"
            if clean_line not in seen:
                seen.add(clean_line)
                final_lines.append(clean_line)

        return sorted(list(set(preserved_lines))) + [""] + sorted(final_lines)

    # ----------------------------- Search ------------------------------------
    def search_clear(self):
        self.text_area.tag_remove("search_match", "1.0", tk.END)
        self.text_area.tag_remove("search_current", "1.0", tk.END)
        self._search_matches = []
        self._search_index = -1
        self.update_status("Search cleared.")

    def _recompute_search_matches(self, query):
        self.search_clear()
        if not query:
            return
        start = "1.0"
        while True:
            pos = self.text_area.search(query, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            self.text_area.tag_add("search_match", pos, end)
            self._search_matches.append((pos, end))
            start = end
        if self._search_matches:
            self._search_index = 0
            self._focus_current_match()
            self.update_status(f"Found {len(self._search_matches)} matches.")

    def _focus_current_match(self):
        self.text_area.tag_remove("search_current", "1.0", tk.END)
        if 0 <= self._search_index < len(self._search_matches):
            pos, end = self._search_matches[self._search_index]
            self.text_area.tag_add("search_current", pos, end)
            self.text_area.see(pos)

    def search_find(self):
        query = self.search_var.get().strip()
        if not query:
            self.update_status("Enter a search term.", is_error=True)
            return
        self._recompute_search_matches(query)

    def search_next(self):
        if not self._search_matches:
            self.search_find()
            return
        self._search_index = (self._search_index + 1) % len(self._search_matches)
        self._focus_current_match()

    def search_prev(self):
        if not self._search_matches:
            self.search_find()
            return
        self._search_index = (self._search_index - 1) % len(self._search_matches)
        self._focus_current_match()


if __name__ == "__main__":
    root = tk.Tk()
    app = HostsFileEditor(root)
    root.mainloop()
