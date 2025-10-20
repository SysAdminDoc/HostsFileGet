# hosts_editor_v2_7.py
# Hosts File Management Tool — v2.7
# Upgrades vs v2.6:
# - Catppuccin Mocha theme (embedded) across the entire UI
# - Smart button states: action buttons green; after successful apply (save or revert),
#   the "Save Changes" button stays red and looks pushed-in until the text is edited again
# - Kept all features: fixed-width left sidebar, full-height editor, diff preview windows,
#   "Revert to Backup" with preview, pfSense import, imports, whitelist persistence,
#   cleaning/dedup, DNS flush, save backup

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
import hashlib

# ----------------------------- Theme (Catppuccin Mocha) ----------------------
PALETTE = {
    "base": "#1e1e2e",    # window background
    "mantle": "#181825",  # very dark panels
    "crust": "#11111b",   # darkest
    "text": "#cdd6f4",
    "subtext": "#a6adc8",
    "surface0": "#313244",  # panel inner
    "surface1": "#45475a",
    "overlay0": "#6c7086",
    "overlay1": "#7f849c",
    "blue": "#89b4fa",
    "green": "#a6e3a1",
    "green_hover": "#b6f3b1",
    "green_press": "#8dcf87",
    "red": "#f38ba8",
    "red_hover": "#ff9fb5",
    "red_press": "#d9778f",
    "accent": "#b4befe",
}

# ----------------------------- Tooltip Helper --------------------------------
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
            background=PALETTE["mantle"],
            foreground=PALETTE["text"],
            relief="solid",
            borderwidth=1,
            font=("Segoe UI", 9),
        )
        label.pack(ipadx=6, ipady=3)

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
        self.tooltip_window = None

# ------------------------------ Preview Window --------------------------------
class PreviewWindow(tk.Toplevel):
    def __init__(self, parent, original_lines, new_lines, title="Preview Changes", on_apply_callback=None):
        super().__init__(parent.root)
        self.parent_editor = parent
        self.new_lines = new_lines
        self.on_apply_callback = on_apply_callback

        self.title(title)
        self.geometry("900x650")
        self.configure(bg=PALETTE["base"])
        self.transient(parent.root)
        self.grab_set()

        text_frame = ttk.Frame(self, padding=(10, 10, 10, 0))
        text_frame.pack(expand=True, fill='both')
        self.preview_text = scrolledtext.ScrolledText(
            text_frame, wrap=tk.WORD, font=("Consolas", 11),
            bg=PALETTE["crust"], fg=PALETTE["text"], insertbackground=PALETTE["text"],
            selectbackground=PALETTE["blue"], relief="flat"
        )
        self.preview_text.pack(expand=True, fill='both')

        button_frame = ttk.Frame(self, padding=10)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)

        legend_frame = ttk.Frame(button_frame)
        legend_frame.pack(side=tk.LEFT)
        tk.Label(legend_frame, text="■ Added", fg="#89D68D", bg=PALETTE["base"]).pack(side=tk.LEFT)
        tk.Label(legend_frame, text="■ Removed", fg=PALETTE["red"], bg=PALETTE["base"]).pack(side=tk.LEFT, padx=10)

        ttk.Button(button_frame, text="Apply Changes", command=self.apply_changes, style="Accent.TButton").pack(side=tk.RIGHT, padx=6)
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=6)

        self.preview_text.tag_config('added', foreground="#89D68D")
        self.preview_text.tag_config('removed', foreground=PALETTE["red"])
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

# -------------------------- Add Custom Source Dialog --------------------------
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

# -------------------------------- Main App -----------------------------------
class HostsFileEditor:
    HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"
    CONFIG_FILE = "hosts_editor_config.json"

    def __init__(self, root):
        self.root = root
        self.root.title("Hosts File Management Tool v2.7")
        self.root.geometry("1360x880")
        self.root.configure(bg=PALETTE["base"])
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.default_font = font.Font(family="Segoe UI", size=10)
        self.title_font = font.Font(family="Segoe UI", size=11, weight="bold")
        self.custom_sources = []

        # Tracks whether current editor content equals last applied content
        self._last_applied_hash = None
        self._suppress_modified_handler = False

        self._init_styles()
        self._init_menubar()

        # Root layout: Sidebar (fixed width) + Editor
        root_container = ttk.Frame(root, padding=8)
        root_container.pack(fill="both", expand=True)

        # Sidebar (fixed width, scrollable)
        sidebar_outer = ttk.Frame(root_container)
        sidebar_outer.pack(side="left", fill="y")
        SIDEBAR_WIDTH = 380
        sidebar_outer.configure(width=SIDEBAR_WIDTH)
        sidebar_outer.pack_propagate(False)

        sidebar_canvas = tk.Canvas(sidebar_outer, bg=PALETTE["mantle"], highlightthickness=0, bd=0, relief="flat")
        sidebar_vscroll = ttk.Scrollbar(sidebar_outer, orient="vertical", command=sidebar_canvas.yview)
        self.sidebar_inner = ttk.Frame(sidebar_canvas)

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

        # ---- Sidebar Sections ----
        # File Ops
        file_ops = ttk.LabelFrame(self.sidebar_inner, text="File")
        file_ops.pack(fill="x", padx=8, pady=(8, 4))
        self.btn_save = self._btn(file_ops, "Save Changes", self.save_file, "Clean, whitelist, preview, then save.", style="Action.TButton")
        self.btn_save.pack(fill="x", pady=4)
        self._btn(file_ops, "Refresh", self.load_file, "Reload hosts file from disk.").pack(fill="x", pady=4)
        self._btn(file_ops, "Revert to Backup", self.revert_to_backup, "Preview and restore from .bak if available.", style="Danger.TButton").pack(fill="x", pady=4)

        # Search / Filter
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

        # Import Blacklists
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

        # Custom Sources
        self.custom_sources_frame = ttk.LabelFrame(self.sidebar_inner, text="Custom Blacklists")
        self.custom_sources_frame.pack(fill="x", padx=8, pady=4)
        self._btn(self.custom_sources_frame, "+ Add Source", self.show_add_source_dialog, "Add a new custom URL source.", style="Accent.TButton").pack(fill="x", pady=2)

        # Utilities
        utilities_frame = ttk.LabelFrame(self.sidebar_inner, text="Utilities")
        utilities_frame.pack(fill="x", padx=8, pady=4)
        util_row = ttk.Frame(utilities_frame)
        util_row.pack(fill="x", padx=8, pady=8)
        self._btn(util_row, "Clean", self.auto_clean, "Clean and format hosts file.").pack(side="left", expand=True, fill="x", padx=(0, 6))
        self._btn(util_row, "Deduplicate", self.deduplicate, "Remove duplicate entries.").pack(side="left", expand=True, fill="x", padx=6)
        self._btn(util_row, "Flush DNS", self.flush_dns, "Flush Windows DNS cache.", style="Accent.TButton").pack(side="left", expand=True, fill="x", padx=(6, 0))

        # Whitelist
        whitelist_frame = ttk.LabelFrame(self.sidebar_inner, text="Persistent Whitelist (Auto-Applied)")
        whitelist_frame.pack(fill="both", padx=8, pady=(4, 8))
        self.whitelist_text_area = scrolledtext.ScrolledText(
            whitelist_frame, wrap=tk.WORD, height=10, font=("Consolas", 10),
            bg=PALETTE["crust"], fg=PALETTE["text"], insertbackground=PALETTE["text"],
            selectbackground=PALETTE["blue"], relief="flat"
        )
        self.whitelist_text_area.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        w_btns = ttk.Frame(whitelist_frame)
        w_btns.pack(fill="x", padx=8, pady=(0, 8))
        self._btn(w_btns, "Load from File", self.load_whitelist_from_file, "Load whitelist from a text file.").pack(side="left", expand=True, fill="x", padx=(0, 6))
        self._btn(w_btns, "Import from Web", self.import_whitelist_from_web, "Import default HOSTShield whitelist.", style="Accent.TButton").pack(side="left", expand=True, fill="x", padx=(6, 0))

        # ---- Editor (Right) ----
        editor_panel = ttk.Frame(right_area)
        editor_panel.pack(fill="both", expand=True)

        self.text_area = scrolledtext.ScrolledText(
            editor_panel, wrap=tk.WORD, font=("Consolas", 12),
            bg=PALETTE["crust"], fg=PALETTE["text"], insertbackground=PALETTE["text"],
            selectbackground=PALETTE["blue"], relief="flat"
        )
        self.text_area.pack(expand=True, fill='both')

        # Status bar
        status_frame = ttk.Frame(root, padding=(10, 6, 10, 10))
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = ttk.Label(status_frame, text="Loading...", font=self.default_font, foreground=PALETTE["subtext"])
        self.status_label.pack(side=tk.LEFT)

        # Search highlighting setup
        self._search_matches = []
        self._search_index = -1
        self.text_area.tag_configure("search_match", background=PALETTE["blue"], foreground=PALETTE["crust"])
        self.text_area.tag_configure("search_current", background=PALETTE["green"], foreground=PALETTE["crust"])

        # Listen to editor modifications to update Save button state
        self.text_area.bind("<<Modified>>", self._on_text_modified)

        # Init
        self.check_admin_privileges()
        self.load_config()
        self.load_file(is_initial_load=True)

    # ----------------------------- Styles & Menus -----------------------------
    def _init_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Base
        style.configure(".", background=PALETTE["base"], foreground=PALETTE["text"], fieldbackground=PALETTE["surface0"])
        style.configure("TFrame", background=PALETTE["base"])
        style.configure("TLabel", background=PALETTE["base"], foreground=PALETTE["text"])
        style.configure("TSeparator", background=PALETTE["surface0"])
        style.configure("TLabelFrame", background=PALETTE["mantle"], foreground=PALETTE["text"], borderwidth=0, relief="flat")
        style.configure("TLabelframe.Label", background=PALETTE["mantle"], foreground=PALETTE["text"], font=self.title_font)
        style.configure("TEntry", fieldbackground=PALETTE["crust"], foreground=PALETTE["text"])
        style.map("TEntry",
                  fieldbackground=[("focus", PALETTE["crust"])],
                  bordercolor=[("focus", PALETTE["blue"])])

        # Neutral Button
        style.configure("TButton",
                        background=PALETTE["surface0"], foreground=PALETTE["text"],
                        padding=(10, 6), relief="flat", borderwidth=0, focusthickness=1, focuscolor=PALETTE["blue"])
        style.map("TButton",
                  background=[("active", PALETTE["surface1"])],
                  relief=[("pressed", "sunken")])

        # Accent Button (blue)
        style.configure("Accent.TButton",
                        background=PALETTE["blue"], foreground="#0b1020",
                        padding=(10, 6), relief="flat", borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", "#a3c7ff")])

        # Action Button (green default)
        style.configure("Action.TButton",
                        background=PALETTE["green"], foreground="#0b1020",
                        padding=(10, 6), relief="flat", borderwidth=0)
        style.map("Action.TButton",
                  background=[("active", PALETTE["green_hover"])],
                  relief=[("pressed", "sunken")])

        # Action Applied Button (red persistent + sunken look)
        style.configure("ActionApplied.TButton",
                        background=PALETTE["red"], foreground="#1b0e13",
                        padding=(10, 6), relief="sunken", borderwidth=1)
        style.map("ActionApplied.TButton",
                  background=[("active", PALETTE["red_hover"])])

        # Danger Button (revert, destructive-ish)
        style.configure("Danger.TButton",
                        background=PALETTE["red"], foreground="#1b0e13",
                        padding=(10, 6), relief="flat", borderwidth=0)
        style.map("Danger.TButton",
                  background=[("active", PALETTE["red_hover"])],
                  relief=[("pressed", "sunken")])

        # Scrollbar to better match dark scheme
        style.configure("Vertical.TScrollbar", background=PALETTE["mantle"], troughcolor=PALETTE["crust"], arrowcolor=PALETTE["text"])
        style.configure("Horizontal.TScrollbar", background=PALETTE["mantle"], troughcolor=PALETTE["crust"], arrowcolor=PALETTE["text"])

        # Menus (tk classic widgets)
        self.root.option_add('*Menu.background', PALETTE["mantle"])
        self.root.option_add('*Menu.foreground', PALETTE["text"])
        self.root.option_add('*Menu.activeBackground', PALETTE["blue"])
        self.root.option_add('*Menu.activeForeground', "#0b1020")

    def _init_menubar(self):
        menu_bar = tk.Menu(self.root, tearoff=0, bg=PALETTE["mantle"], fg=PALETTE["text"],
                           activebackground=PALETTE["blue"], activeforeground="#0b1020")
        self.root.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0, bg=PALETTE["mantle"], fg=PALETTE["text"],
                            activebackground=PALETTE["blue"], activeforeground="#0b1020")
        file_menu.add_command(label="Save Changes", command=self.save_file)
        file_menu.add_command(label="Refresh", command=self.load_file)
        file_menu.add_command(label="Revert to Backup", command=self.revert_to_backup)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)
        menu_bar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menu_bar, tearoff=0, bg=PALETTE["mantle"], fg=PALETTE["text"],
                             activebackground=PALETTE["blue"], activeforeground="#0b1020")
        tools_menu.add_command(label="Clean", command=self.auto_clean)
        tools_menu.add_command(label="Deduplicate", command=self.deduplicate)
        tools_menu.add_command(label="Flush DNS", command=self.flush_dns)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menu_bar, tearoff=0, bg=PALETTE["mantle"], fg=PALETTE["text"],
                            activebackground=PALETTE["blue"], activeforeground="#0b1020")
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo(
            "About",
            "Hosts File Management Tool v2.7\nCatppuccin Mocha theme, smart buttons, and modern UX.\nCreated by Steve. Enhanced by ChatGPT."
        ))
        help_menu.add_command(label="GitHub (Hosts File Management Tool)", command=lambda: webbrowser.open("https://github.com/SysAdminDoc/Hosts-File-Management-Tool"))
        menu_bar.add_cascade(label="Help", menu=help_menu)

    # ----------------------------- UI Helpers ---------------------------------
    def _btn(self, parent, text, command, tooltip, style="TButton"):
        btn = ttk.Button(parent, text=text, command=command, style=style)
        ToolTip(btn, tooltip)
        return btn

    def update_status(self, message, is_error=False):
        color = PALETTE["red"] if is_error else PALETTE["subtext"]
        self.status_label.config(text=message, foreground=color)
        # fade back to neutral after delay
        self.root.after(4000, lambda: self.status_label.config(foreground=PALETTE["subtext"]))

    def on_closing(self):
        self.save_config()
        self.root.destroy()

    # --------------------------- Admin Check ----------------------------------
    def check_admin_privileges(self):
        try:
            is_admin = (os.getuid() == 0)
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            self.update_status("Warning: Not running as Administrator. You cannot save.", is_error=True)
            messagebox.showwarning("Admin Rights Required", "Run as Administrator to save changes.")

    # ------------------------- Config Persistence -----------------------------
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

    # ----------------------------- File Ops -----------------------------------
    def get_lines(self):
        return self.text_area.get('1.0', tk.END).splitlines()

    def set_text(self, lines):
        # avoid triggering modified handler during programmatic updates
        self._suppress_modified_handler = True
        self.text_area.delete('1.0', tk.END)
        self.text_area.insert(tk.END, '\n'.join(lines))
        self.text_area.edit_modified(False)
        self._suppress_modified_handler = False
        self._update_save_button_state_for_current_text()

    def _hash_lines(self, lines):
        return hashlib.sha256('\n'.join(lines).encode('utf-8')).hexdigest()

    def _set_applied_hash_now(self):
        self._last_applied_hash = self._hash_lines(self.get_lines())

    def _on_text_modified(self, event=None):
        if self._suppress_modified_handler:
            return
        if self.text_area.edit_modified():
            self.text_area.edit_modified(False)
            self._update_save_button_state_for_current_text()

    def _update_save_button_state_for_current_text(self):
        current = self._hash_lines(self.get_lines())
        if self._last_applied_hash is not None and current == self._last_applied_hash:
            # content matches applied version -> show applied state (red, sunken)
            self.btn_save.configure(style="ActionApplied.TButton")
        else:
            # changes not applied -> show actionable (green)
            self.btn_save.configure(style="Action.TButton")

    def load_file(self, is_initial_load=False):
        try:
            if os.path.exists(self.HOSTS_FILE_PATH):
                with open(self.HOSTS_FILE_PATH, 'r', encoding='utf-8') as f:
                    lines = f.read().splitlines()
                self.set_text(lines)
                # On initial load, treat current file as "applied"
                if is_initial_load:
                    self._last_applied_hash = self._hash_lines(lines)
                self._update_save_button_state_for_current_text()
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
                # mark applied and update button style
                self._set_applied_hash_now()
                self._update_save_button_state_for_current_text()
            PreviewWindow(self, original_lines, final_lines, title="Preview: Final Changes (Cleaned & Whitelisted)", on_apply_callback=proceed_with_save)
        else:
            self._execute_save('\n'.join(original_lines))
            self._set_applied_hash_now()
            self._update_save_button_state_for_current_text()

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

    # ----------------------- Revert to Backup (Preview + Apply) ----------------
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
                self._set_applied_hash_now()
                self._update_save_button_state_for_current_text()
                self.update_status("Backup restored successfully.")
                messagebox.showinfo("Restored", "Hosts file restored from backup.")
            except PermissionError:
                self.update_status("Restore failed: Permission denied.", is_error=True)
                messagebox.showerror("Error", "Permission denied. Run as Administrator.")
            except Exception as e:
                self.update_status(f"Restore error: {e}", is_error=True)

        PreviewWindow(self, current_lines, backup_lines, title="Preview: Restore from Backup", on_apply_callback=do_restore)

    # ----------------------------- Imports ------------------------------------
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
        """Import a pfSense DNSBL log file by extracting domains."""
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

    # ------------------------- Custom Sources ----------------------------------
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
        btn = self._btn(self.custom_sources_frame, name, lambda u=url, n=name: self.fetch_and_append_hosts(n, url=u), tooltip, style="TButton")
        btn.pack(side=tk.TOP, fill=tk.X, pady=2)

    # ----------------------- Whitelist & Filtering ----------------------------
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

    # ------------------------------ Utilities ---------------------------------
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

    # ----------------------------- Search -------------------------------------
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
