# hosts_editor_v2_7.py
# Hosts File Management Tool — v2.7
# Upgrades vs v2.6:
# - Catppuccin Mocha theme (embedded) across the entire UI
# - Smart button states: action buttons green; after successful apply (save or revert),
#   the "Save Changes" button stays red and looks pushed-in until the text is edited again
# - Blocklist imports centralized and organized into categories.
# - ADDED: Dynamic removal mechanism for Custom Blacklist Sources.
# - ADDED: Dedicated Manual List Input area to paste and append hosts.
# - FIXED: Widen left sidebar to 420px.
# - FIXED: Initialized status_label and right_area correctly.
# - FIXED: Moved 'Utilities' section to the top beneath 'File'.
# - FIXED: Enhanced 'Clean' logic to remove ALL comments/headers.
# - **FEATURE ADDED**: Non-interactive status updates for imports and utilities (removes popups).
# - **FEATURE ADDED**: Persistent search highlighting on editor modification.
# - **FIXED**: Improved error reporting for failed imports.
# - **FEATURE ADDED**: NextDNS CSV Log Import for blocked domains.
# - **FIXED**: Modified Admin Relaunch logic to automatically attempt relaunch if not running as Admin.

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
import sys
import csv
import io

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
        self.title("Add Custom Blocklist Source")
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
    
    SIDEBAR_WIDTH = 420 # Increased width for better button layout

    # Blocklist Definitions (New centralized structure)
    BLOCKLIST_SOURCES = {
        "Major Unified": [
            ("HOSTShield (Main)", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/HOSTS.txt", "Append the main HOSTShield blocklist."),
            ("StevenBlack", "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts", "Append StevenBlack unified blocklist."),
            ("HaGezi Ultimate", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/ultimate.txt", "Append HaGezi Ultimate DNS blocklist."),
            ("AdAway", "https://adaway.org/hosts.txt", "Append AdAway mobile ad blocklist."),
        ],
        "Specific/Telemetry": [
            ("Adobe Activation", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/AdobeHosts.txt", "Block Adobe activation servers."),
            ("Ads, Tracking, Analytics", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/AdsTrackingAnalytics.txt", "Block common ads, tracking, and analytics domains."),
            ("Amazon", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Amazon.txt", "Block Amazon telemetry and tracking."),
            ("Apple", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Apple.txt", "Block Apple telemetry and tracking."),
            ("Brave", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Brave.txt", "Block Brave browser telemetry."),
            ("CCleaner", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/CCleaner.txt", "Block CCleaner telemetry."),
            ("Dell", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Dell.txt", "Block Dell support and telemetry."),
            ("Dropbox", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Dropbox.txt", "Block Dropbox telemetry and tracking."),
            ("Facebook", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Facebook.txt", "Block Facebook tracking and social domains."),
            ("Firefox", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Firefox.txt", "Block Firefox browser telemetry."),
            ("Google", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Google.txt", "Block Google telemetry and tracking."),
            ("Hubspot", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Hubspot.txt", "Block Hubspot tracking domains."),
            ("Malwarebytes", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Malwarebytes.txt", "Block Malwarebytes telemetry."),
            ("Microsoft", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Microsoft.txt", "Block Microsoft telemetry."),
            ("Paypal", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Paypal.txt", "Block Paypal tracking."),
            ("Samsung", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Samsung.txt", "Block Samsung telemetry."),
            ("Tiktok", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Tiktok.txt", "Block TikTok and ByteDance tracking."),
            ("Twitter", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Twitter.txt", "Block Twitter/X tracking and social domains."),
        ]
    }

    def __init__(self, root):
        self.root = root
        self.root.title("Hosts File Management Tool v2.7")
        self.root.geometry("1360x880")
        self.root.configure(bg=PALETTE["base"])
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.default_font = font.Font(family="Segoe UI", size=10)
        self.title_font = font.Font(family="Segoe UI", size=11, weight="bold")
        self.custom_sources = []
        self._custom_source_widgets = {} # To store frames/widgets for removal

        # Tracks whether current editor content equals last applied content
        self._last_applied_hash = None
        self._suppress_modified_handler = False

        self._init_styles()
        self._init_menubar()
        
        # 1. Initialize Status Bar FIRST
        status_frame = ttk.Frame(root, padding=(10, 6, 10, 10))
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = ttk.Label(status_frame, text="Loading...", font=self.default_font, foreground=PALETTE["subtext"])
        self.status_label.pack(side=tk.LEFT)
        
        # 2. Run Admin Check & Relaunch Logic
        if not self.check_admin_privileges():
             # If check_admin_privileges returns False, it means a relaunch was requested, and we should exit.
             sys.exit()

        # Root layout: Sidebar (fixed width) + Editor
        root_container = ttk.Frame(root, padding=8)
        root_container.pack(fill="both", expand=True)

        # Sidebar (fixed width, scrollable)
        sidebar_outer = ttk.Frame(root_container)
        sidebar_outer.pack(side="left", fill="y")
        sidebar_outer.configure(width=self.SIDEBAR_WIDTH)
        sidebar_outer.pack_propagate(False) # Prevent frame from shrinking below size

        # Canvas for scrollable content
        sidebar_canvas = tk.Canvas(sidebar_outer, bg=PALETTE["mantle"], highlightthickness=0, bd=0, relief="flat", yscrollincrement=10)
        sidebar_vscroll = ttk.Scrollbar(sidebar_outer, orient="vertical", command=sidebar_canvas.yview)
        
        # Inner frame to hold all sidebar content
        self.sidebar_inner = ttk.Frame(sidebar_canvas, padding=(0, 0, 10, 0)) 

        # Bind the inner frame's size changes to update the scroll region
        self.sidebar_inner.bind(
            "<Configure>",
            lambda e: sidebar_canvas.configure(scrollregion=sidebar_canvas.bbox("all"))
        )
        
        # Bind mouse wheel for scrolling on the canvas
        def _on_mousewheel(event):
            # Windows scrolls 120 units per notch
            sidebar_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            
        sidebar_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Create the window inside the canvas to hold the content
        canvas_width = self.SIDEBAR_WIDTH - sidebar_vscroll.winfo_reqwidth()
        sidebar_canvas.create_window((0, 0), window=self.sidebar_inner, anchor="nw", width=canvas_width)
        sidebar_canvas.configure(yscrollcommand=sidebar_vscroll.set)

        sidebar_canvas.pack(side="left", fill="y", expand=False)
        sidebar_vscroll.pack(side="right", fill="y")
        
        # 3. Define right_area before using it
        # Right editor area
        right_area = ttk.Frame(root_container, padding=(8, 0, 0, 0))
        right_area.pack(side="left", fill="both", expand=True)

        # --- Sidebar Content Starts Here ---
        
        # File Ops (Top)
        file_ops = ttk.LabelFrame(self.sidebar_inner, text="File")
        file_ops.pack(fill="x", padx=8, pady=(8, 4))
        self.btn_save = self._btn(file_ops, "Save Changes", self.save_file, "Clean, whitelist, preview, then save.", style="Action.TButton")
        self.btn_save.pack(fill="x", pady=4)
        self._btn(file_ops, "Refresh", self.load_file, "Reload hosts file from disk.").pack(fill="x", pady=4)
        self._btn(file_ops, "Revert to Backup", self.revert_to_backup, "Preview and restore from .bak if available.", style="Danger.TButton").pack(fill="x", pady=4)
        
        # Utilities (Moved directly beneath File)
        utilities_frame = ttk.LabelFrame(self.sidebar_inner, text="Utilities")
        utilities_frame.pack(fill="x", padx=8, pady=4)
        util_row = ttk.Frame(utilities_frame)
        util_row.pack(fill="x", padx=8, pady=8)
        self._btn(util_row, "Clean", self.auto_clean, "Clean and format hosts file (removes ALL comments/headers).").pack(side="left", expand=True, fill="x", padx=(0, 6))
        self._btn(util_row, "Deduplicate", self.deduplicate, "Remove duplicate entries.").pack(side="left", expand=True, fill="x", padx=6)
        self._btn(util_row, "Flush DNS", self.flush_dns, "Flush Windows DNS cache.", style="Accent.TButton").pack(side="left", expand=True, fill="x", padx=(6, 0))


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

        # Local Import
        local_import_frame = ttk.LabelFrame(import_frame, text="Import From File")
        local_import_frame.pack(fill="x", padx=8, pady=(8, 4))
        self._btn(local_import_frame, "From pfSense Log", self.import_pfsense_log, "Import domains from pfSense DNSBL log.").pack(fill="x", pady=2)
        # ADDED: NextDNS Import Button
        self._btn(local_import_frame, "From NextDNS Log (CSV)", self.import_nextdns_log, "Import blocked domains from a NextDNS Query Log CSV.").pack(fill="x", pady=2)


        # Dynamic Web Imports
        for category, sources in self.BLOCKLIST_SOURCES.items():
            web_import_frame = ttk.LabelFrame(import_frame, text=category)
            web_import_frame.pack(fill="x", padx=8, pady=4)
            for name, url, tooltip in sources:
                self._btn(web_import_frame, name, lambda u=url, n=name: self.fetch_and_append_hosts(n, url=u), tooltip).pack(fill="x", pady=2)
        
        # Custom Sources
        self.custom_sources_frame = ttk.LabelFrame(self.sidebar_inner, text="Custom Blacklists (Persistent)")
        self.custom_sources_frame.pack(fill="x", padx=8, pady=4)
        
        # CREATE THE BUTTON AFTER THE FRAME IS DEFINED, BUT BEFORE LOADING CONFIG
        self.btn_add_custom = self._btn(self.custom_sources_frame, "+ Add Custom Source", self.show_add_source_dialog, "Add a new custom URL source.", style="Accent.TButton")
        self.btn_add_custom.pack(fill=tk.X, pady=2, side=tk.BOTTOM) # Pack at the bottom

        # Manual Input
        manual_frame = ttk.LabelFrame(self.sidebar_inner, text="Manual List Input (Paste Hosts)")
        manual_frame.pack(fill="x", padx=8, pady=4)
        self.manual_text_area = scrolledtext.ScrolledText(
            manual_frame, wrap=tk.WORD, height=10, font=("Consolas", 10),
            bg=PALETTE["crust"], fg=PALETTE["text"], insertbackground=PALETTE["text"],
            selectbackground=PALETTE["blue"], relief="flat"
        )
        self.manual_text_area.pack(fill="x", padx=8, pady=(8, 4))
        self._btn(manual_frame, "Append Manual List to Editor", self.append_manual_list, 
                  "Append the content from the text area to the main hosts file.", style="Action.TButton").pack(fill="x", padx=8, pady=(0, 8))

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

        # Search highlighting setup
        self._search_matches = []
        self._search_index = -1
        self.text_area.tag_configure("search_match", background=PALETTE["blue"], foreground=PALETTE["crust"])
        self.text_area.tag_configure("search_current", background=PALETTE["green"], foreground=PALETTE["crust"])

        # Listen to editor modifications to update Save button state and persist search
        self.text_area.bind("<<Modified>>", self._on_text_modified)

        # Init
        # USE TRY/EXCEPT FOR LAUNCH ROBUSTNESS
        try:
            self.load_config()
        except Exception as e:
            messagebox.showerror("Configuration Error", f"Failed to load or initialize configuration. Application will launch without custom settings.\nError: {e}")
            self.custom_sources = [] # Ensure custom sources is clean list if loading failed
            self.whitelist_text_area.delete('1.0', tk.END)
        
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
        
        # Remove Button (Small)
        style.configure("Remove.TButton",
                        background=PALETTE["red"], foreground="#1b0e13",
                        padding=(4, 2), relief="flat", borderwidth=0, font=("Segoe UI", 8, "bold"))
        style.map("Remove.TButton",
                  background=[("active", PALETTE["red_hover"])],
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
        help_menu.add_command(label="About", command=lambda: self.update_status(
            "Hosts File Management Tool v2.7. Created by Steve. Enhanced by Gemini.", is_error=False
        ))
        help_menu.add_command(label="GitHub (Hosts File Management Tool)", command=lambda: webbrowser.open("https://github.com/SysAdminDoc/Hosts-File-Management-Tool"))
        menu_bar.add_cascade(label="Help", menu=help_menu)

    # ----------------------------- UI Helpers ---------------------------------
    def _btn(self, parent, text, command, tooltip, style="TButton"):
        btn = ttk.Button(parent, text=text, command=command, style=style)
        ToolTip(btn, tooltip)
        return btn

    def update_status(self, message, is_error=False):
        color = PALETTE["red"] if is_error else PALETTE["green"] if message.lower().startswith(("success", "imported", "loaded", "restored", "saved")) else PALETTE["subtext"]
        self.status_label.config(text=message, foreground=color)
        # fade back to neutral after delay
        self.root.after(4000, lambda: self.status_label.config(foreground=PALETTE["subtext"]))

    def on_closing(self):
        self.save_config()
        self.root.destroy()

    # --------------------------- Admin Check (Automatic Relaunch Logic) ----------------------------------
    def check_admin_privileges(self):
        """
        Checks for admin privileges. If running on Windows without admin, it attempts 
        to relaunch the script with elevated privileges and instructs the current 
        process to exit.
        """
        try:
            is_admin = (os.getuid() == 0)
        except AttributeError:
            try:
                # Windows check
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                is_admin = False # Assume not admin if check fails

        if is_admin:
            # Use root.after here to ensure the status bar is actually drawn before updating it
            self.root.after(100, lambda: self.update_status("Success: Running with Administrator privileges.", is_error=False))
            return True
        else:
            if os.name == 'nt':
                # Attempt silent relaunch as administrator
                try:
                    script = os.path.abspath(sys.argv[0])
                    params = ' '.join(['"%s"' % arg for arg in sys.argv[1:]])
                    
                    # Use sys.executable for the Python interpreter path
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, f'"{script}" {params}', None, 1
                    )
                    # Exit the non-admin instance
                    return False 
                except Exception as e:
                    # Inform user if relaunch fails, then proceed non-admin
                    messagebox.showerror(
                        "Relaunch Failed", 
                        f"Could not relaunch as administrator. Saving the hosts file will fail due to permission error.\nError: {e}"
                    )
            
            # If not Windows or relaunch failed, notify and continue non-admin
            self.root.after(100, lambda: self.update_status("Warning: Not running as Administrator. Read/write to hosts file will fail.", is_error=True))
            return True
            

    # ------------------------- Config Persistence -----------------------------
    def load_config(self):
        try:
            if os.path.exists(self.CONFIG_FILE):
                with open(self.CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                self.whitelist_text_area.delete('1.0', tk.END)
                self.whitelist_text_area.insert('1.0', config.get("whitelist", ""))
                self.custom_sources = config.get("custom_sources", [])
                
                self.update_status("Configuration loaded.")
                self._rebuild_custom_source_buttons()
                
        except Exception as e:
            # Re-raise the exception if the outer try/except block doesn't handle it
            raise e

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
            
            # --- FEATURE: Re-run search to maintain highlights ---
            query = self.search_var.get().strip()
            if query:
                # Recompute search matches (but keep current index selection if possible)
                self._recompute_search_matches(query, preserve_index=True)


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
                self.update_status(f"Loaded hosts file: '{self.HOSTS_FILE_PATH}'")
            else:
                self.update_status("Hosts file not found.", is_error=True)
        except Exception as e:
            self.update_status(f"Error loading file: {e}", is_error=True)
            # Retain interactive pop-up for file system errors
            messagebox.showerror("Error", f"Error loading file:\n{e}")

    def save_file(self):
        original_lines = self.get_lines()
        whitelisted_lines = self._get_filtered_lines_by_whitelist(original_lines)
        final_lines = self._get_cleaned_lines(whitelisted_lines)

        if original_lines != final_lines:
            def proceed_with_save(approved_lines):
                self._execute_save('\n'.join(approved_lines))
                # Count removed lines based on filtering and cleaning
                removed_by_whitelist = len(original_lines) - len(whitelisted_lines)
                removed_by_cleaning = len(whitelisted_lines) - len(approved_lines)
                
                # Non-interactive success feedback
                self.update_status(f"Saved (Cleaned & Whitelisted). Removed {removed_by_whitelist} (whitelist) + {removed_by_cleaning} (clean/dedup) entries.")
                # mark applied and update button style
                self._set_applied_hash_now()
                self._update_save_button_state_for_current_text()
                
            PreviewWindow(self, original_lines, final_lines, title="Preview: Final Changes (Cleaned & Whitelisted)", on_apply_callback=proceed_with_save)
        else:
            self._execute_save('\n'.join(original_lines))
            self._set_applied_hash_now()
            self._update_save_button_state_for_current_text()
            self.update_status("Saved successfully (No changes detected).")


    def _execute_save(self, content_to_save):
        if not content_to_save.strip():
            # Mandatory interactive confirmation for clearing the file
            if not messagebox.askyesno("Confirm Empty Save", "Content is empty. Clear hosts file?"):
                return

        backup_path = self.HOSTS_FILE_PATH + ".bak"
        # Create/update backup
        try:
            if os.path.exists(self.HOSTS_FILE_PATH):
                with open(self.HOSTS_FILE_PATH, 'r', encoding='utf-8') as f_in, open(backup_path, 'w', encoding='utf-8') as f_out:
                    f_out.write(f_in.read())
        except Exception as e:
            # Mandatory interactive confirmation for failed backup
            if not messagebox.askyesno("Backup Failed", f"Could not create backup.\nError: {e}\n\nSave anyway?"):
                return

        try:
            with open(self.HOSTS_FILE_PATH, 'w', encoding='utf-8') as f:
                f.write(content_to_save)
            self.update_status(f"Saved successfully. Backup created: '{backup_path}'")
        except PermissionError:
            self.update_status("Save failed: Permission denied. Run as Administrator.", is_error=True)
            # Retain interactive pop-up for critical failure
            messagebox.showerror("Error", "Permission denied. Run as Administrator.")
        except Exception as e:
            self.update_status(f"Save error: {e}", is_error=True)
            messagebox.showerror("Error", f"Save error: {e}")


    # ----------------------- Revert to Backup (Preview + Apply) ----------------
    def revert_to_backup(self):
        backup_path = self.HOSTS_FILE_PATH + ".bak"
        if not os.path.exists(backup_path):
            self.update_status("No backup file found. Save once to create a backup.", is_error=True)
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
                # The PreviewWindow returns backup_lines here
                with open(self.HOSTS_FILE_PATH, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(approved_lines))
                self.set_text(approved_lines)
                self._set_applied_hash_now()
                self._update_save_button_state_for_current_text()
                # Non-interactive success feedback
                self.update_status("Restored successfully from backup.")
            except PermissionError:
                self.update_status("Restore failed: Permission denied. Run as Administrator.", is_error=True)
                messagebox.showerror("Error", "Permission denied. Run as Administrator.")
            except Exception as e:
                self.update_status(f"Restore error: {e}", is_error=True)
                messagebox.showerror("Error", f"Restore error: {e}")

        PreviewWindow(self, current_lines, backup_lines, title="Preview: Restore from Backup", on_apply_callback=do_restore)

    # ----------------------------- Imports ------------------------------------
    def fetch_and_append_hosts(self, source_name, url=None, lines_to_add=None):
        self.update_status(f"Importing from {source_name}...")
        self.root.update_idletasks()
        
        new_lines = None
        
        try:
            if url:
                # Use urllib to fetch content
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req) as response:
                    # Check for non-OK status codes before reading
                    if response.getcode() != 200:
                        raise urllib.error.HTTPError(url, response.getcode(), f"HTTP Error: {response.getcode()}", response.info(), response.fp)

                    new_lines = response.read().decode('utf-8', errors='ignore').splitlines()
            elif lines_to_add:
                # Ensure lines_to_add is a list of strings
                new_lines = [str(line) for line in lines_to_add if str(line).strip()]
            else:
                raise ValueError("Either url or lines_to_add must be provided.")

            if not new_lines:
                self.update_status(f"Imported from {source_name}, but source was empty.", is_error=True)
                return

            current_lines = self.get_lines()
            if current_lines and current_lines[-1].strip() != "":
                current_lines.append("")
            
            # Use the actual filename/source name in the marker
            if url:
                marker = url.split('/')[-1]
                marker = marker.split('?')[0] # Remove query parameters if any
            else:
                marker = source_name
                
            current_lines.append(f"# --- Imported from {marker} ---")
            current_lines.extend(new_lines)
            self.set_text(current_lines)

            num_removed = self.run_auto_whitelist_filter()
            # Non-interactive success feedback
            self.update_status(f"Imported from {source_name} successfully. Removed {num_removed} entries via whitelist.")

        except urllib.error.HTTPError as e:
            self.update_status(f"Import failed for {source_name}: HTTP Error {e.code} ({e.reason})", is_error=True)
        except urllib.error.URLError as e:
            self.update_status(f"Import failed for {source_name}: Network error ({e.reason})", is_error=True)
        except Exception as e:
            self.update_status(f"Import failed for {source_name}: An unexpected error occurred: {type(e).__name__}", is_error=True)
            

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
                # Basic check for a typical pfSense DNSBL format, e.g., 'May 1 10:00:00 dnsbl: x.x.x.x,domain.com,y.y.y.y'
                parts = line.strip().split(',')
                if len(parts) > 2 and ("dnsbl" in parts[0] or "DNSBL" in parts[0]):
                    domain = parts[2].strip()
                    if domain:
                        extracted_domains.add(domain)

            if not extracted_domains:
                self.update_status(f"No valid DNSBL domains found in '{os.path.basename(filepath)}'.", is_error=True)
                return

            new_domains_to_add = sorted(list(extracted_domains))
            self.fetch_and_append_hosts(os.path.basename(filepath), lines_to_add=new_domains_to_add)

        except Exception as e:
            self.update_status(f"Error importing log file: {e}", is_error=True)
            # Retain interactive pop-up for file system errors
            messagebox.showerror("Import Error", f"An unexpected error occurred while processing the log file:\n{e}")
            
    def import_nextdns_log(self):
        """Import a NextDNS Query Log CSV file to extract blocked domains."""
        filepath = filedialog.askopenfilename(
            title="Select NextDNS Query Log CSV File",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )
        if not filepath:
            return

        filename = os.path.basename(filepath)
        self.update_status(f"Importing blocked domains from NextDNS log: {filename}...")
        self.root.update_idletasks()

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                # Read content first, replace the non-standard header delimiter `` if present
                content = f.read().replace('', '').strip()
            
            # Use io.StringIO to treat the string content as a file for csv.DictReader
            reader = csv.DictReader(io.StringIO(content))
            
            extracted_domains = set()
            
            # Identify required column names (case-insensitive mapping)
            # Note: DictReader fieldnames might contain whitespace/non-printable chars if poorly formatted.
            fieldnames = [name.strip().lower() for name in reader.fieldnames or []]
            
            # Check for the minimum required columns based on the sample file
            if 'domain' not in fieldnames or 'status' not in fieldnames:
                self.update_status(f"CSV format error: Missing 'domain' or 'status' column in {filename}.", is_error=True)
                messagebox.showerror("CSV Format Error", f"The NextDNS CSV file '{filename}' appears to be missing required columns ('domain', 'status').")
                return
            
            # Normalize column names to map to the correct key in the row dictionary
            domain_key = reader.fieldnames[fieldnames.index('domain')]
            status_key = reader.fieldnames[fieldnames.index('status')]

            for row in reader:
                domain = row.get(domain_key, '').strip()
                status = row.get(status_key, '').strip().lower()

                if domain and status == 'blocked':
                    # Extract only the domain for blocking (NextDNS logs already contain subdomain details)
                    extracted_domains.add(domain)

            if not extracted_domains:
                self.update_status(f"No blocked domains found in '{filename}'.", is_error=True)
                return

            new_domains_to_add = sorted(list(extracted_domains))
            self.fetch_and_append_hosts(f"NextDNS Log: {filename}", lines_to_add=new_domains_to_add)

        except Exception as e:
            self.update_status(f"Error importing NextDNS log file: {e}", is_error=True)
            # Retain interactive pop-up for file system errors
            messagebox.showerror("Import Error", f"An unexpected error occurred while processing the NextDNS log file:\n{e}")
            
    def append_manual_list(self):
        """Appends content from the manual list input area to the editor."""
        content = self.manual_text_area.get('1.0', tk.END).strip()
        if not content:
            self.update_status("Manual list is empty.", is_error=True)
            return
        
        lines = content.splitlines()
        self.fetch_and_append_hosts("Manual List Input", lines_to_add=lines)
        # Clear the input area after successful append
        self.manual_text_area.delete('1.0', tk.END)


    # ------------------------- Custom Sources ----------------------------------
    def _clear_custom_source_widgets(self):
        """Removes all custom source widgets (frames) except the static '+ Add' button."""
        
        # Get all children
        children = self.custom_sources_frame.winfo_children()
        
        # Check if the '+ Add Custom Source' button exists and is the last child.
        if children and children[-1] == self.btn_add_custom:
            widgets_to_destroy = children[:-1]
        else:
            # Fallback: destroy all widgets that aren't the static button
            widgets_to_destroy = [w for w in children if w != getattr(self, 'btn_add_custom', None)]
        
        for widget in widgets_to_destroy:
            widget.destroy()
            
        self._custom_source_widgets = {} # Reset internal widget tracker

    def _rebuild_custom_source_buttons(self):
        """Clears existing dynamic buttons and redraws them based on self.custom_sources."""
        self._clear_custom_source_widgets()
        
        # Pack custom buttons before the fixed "+ Add Custom Source" button.
        for source in self.custom_sources:
            self._create_custom_source_button(source['name'], source['url'])
        
        # Ensure the Add button is packed last (at the bottom of the frame)
        self.btn_add_custom.pack_forget()
        self.btn_add_custom.pack(fill=tk.X, pady=2, side=tk.BOTTOM)


    def _create_custom_source_button(self, name, url):
        tooltip = f"Appends the custom '{name}' blocklist."

        # Create a container frame for the button and the remove button
        frame = ttk.Frame(self.custom_sources_frame)
        
        # Pack this new frame immediately before the fixed Add button (which is tk.BOTTOM).
        frame.pack(fill=tk.X, pady=2, before=self.btn_add_custom) 
        
        self._custom_source_widgets[name] = frame

        # Remove button (packed right)
        remove_btn = ttk.Button(
            frame, 
            text="✕", 
            command=lambda n=name, f=frame: self.remove_custom_source(n, f), 
            style="Remove.TButton"
        )
        ToolTip(remove_btn, f"Remove the '{name}' source from configuration.")
        remove_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Import button (packed left, expands to fill remaining space)
        import_btn = self._btn(
            frame, 
            text=name, 
            command=lambda u=url, n=name: self.fetch_and_append_hosts(n, url=u), 
            tooltip=tooltip, 
            style="TButton"
        )
        import_btn.pack(side=tk.LEFT, expand=True, fill=tk.X)


    def show_add_source_dialog(self):
        dialog = AddSourceDialog(self.root)
        if dialog.result:
            name, url = dialog.result
            if any(s['name'] == name for s in self.custom_sources):
                self.update_status("Error: Source name already exists.", is_error=True)
                return
            source_data = {'name': name, 'url': url}
            self.custom_sources.append(source_data)
            self._create_custom_source_button(name, url) # Create button immediately
            self.update_status(f"Added custom source: {name}")
            self.save_config() # Save immediately after adding


    def remove_custom_source(self, name, widget_frame):
        """Removes a custom source from the list and UI."""
        
        # 1. Remove from data structure
        self.custom_sources = [s for s in self.custom_sources if s['name'] != name]
        
        # 2. Remove from widget tracker and destroy frame
        if name in self._custom_source_widgets:
            widget_frame.destroy()
            del self._custom_source_widgets[name]
            
        # 3. Save config
        self.save_config()
        self.update_status(f"Removed custom source: {name}")


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
            # Retain interactive pop-up for file system errors
            messagebox.showerror("File Error", f"Could not load whitelist:\n{e}")

    def import_whitelist_from_web(self):
        # This URL is explicitly kept from the request list as the dedicated whitelist URL
        url = "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Whitelist.txt"
        self.update_status("Importing whitelist...")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                content = response.read().decode('utf-8', errors='ignore')
            self.whitelist_text_area.delete('1.0', tk.END)
            self.whitelist_text_area.insert('1.0', content)
            self.update_status("Imported whitelist from HOSTShield.")
        except Exception as e:
            self.update_status(f"Could not fetch whitelist: {type(e).__name__}", is_error=True)
            

    def _get_filtered_lines_by_whitelist(self, lines):
        whitelist_content = self.whitelist_text_area.get('1.0', tk.END)
        # Prepare whitelist for case-insensitive, domain-only matching
        whitelist = {line.strip().lower().lstrip('.') for line in whitelist_content.splitlines() if line.strip()}
        if not whitelist:
            return lines

        final_lines = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                final_lines.append(line)
                continue
            
            # Simple check for 'IP domain' format. We only care about the domain part.
            parts = stripped.split()
            if len(parts) >= 2:
                # Take the second part (index 1) as the domain, assuming standard 'IP domain' format
                domain = parts[1].lower() 
                
                # Check for exact match in whitelist (e.g., 'example.com')
                # Also check for subdomain match (e.g., '.example.com') in whitelist
                if domain in whitelist or domain.lstrip('.') in whitelist:
                    continue # Skip this line, it is whitelisted
            
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
                # Use subprocess.run for simple commands, creationflags=subprocess.CREATE_NO_WINDOW prevents a console window from flashing
                subprocess.run(['ipconfig', '/flushdns'], capture_output=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                self.update_status("Successfully flushed DNS resolver cache.")
            else:
                self.update_status("Unsupported OS: DNS flushing is only available on Windows.", is_error=True)
        except Exception as e:
            self.update_status(f"Error flushing DNS: {e}", is_error=True)

    def process_and_preview(self, processor, title):
        original = self.get_lines()
        processed = processor(original)
        if original != processed:
            # We don't need a callback here since we are just updating the editor content
            def apply_to_editor(approved_lines):
                self.set_text(approved_lines)
                self.update_status(f"Success: {title} changes applied.")

            PreviewWindow(self, original, processed, title=title, on_apply_callback=apply_to_editor)
        else:
            self.update_status(f"No changes to apply for '{title}'.")

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
        """
        Cleans the hosts file lines by removing ALL comments and non-active lines,
        standardizing entries to '0.0.0.0 domain', and sorting/deduplicating.
        """
        seen = set()
        final_entries = []

        # 1. Process all lines, ignoring anything starting with '#' or being empty
        for line in lines:
            stripped = line.strip()
            
            # Skip any line that is empty or starts with '#' (removing all headers/comments/separators)
            if not stripped or stripped.startswith('#'):
                continue
            
            # Process active lines (IP domain [comment])
            
            # Remove inline comments if present
            processed = stripped.split('#', 1)[0].strip()
            if not processed:
                continue
            
            parts = processed.split()
            if len(parts) < 2:
                continue

            # We assume IP is parts[0] and domain is parts[1] for standardization
            domain = parts[1].lower() # Normalize domain to lowercase
            
            # Skip localhost entries 
            if domain in ('localhost', '::1'):
                continue

            # Standardize entry format
            clean_line = f"0.0.0.0 {domain}"
            
            # Use the standardized line for de-duplication check
            if clean_line not in seen:
                seen.add(clean_line)
                final_entries.append(clean_line)

        # 2. Construct final content: standard Windows header + sorted unique entries
        windows_header = [
            "# Copyright (c) 1993-2009 Microsoft Corp.",
            "#",
            "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.",
            "#",
            "# This file contains the mappings of IP addresses to host names. Each",
            "# entry should be kept on an individual line. The IP address should",
            "# be placed in the first column followed by the corresponding host name.",
            "# The IP address and the host name should be separated by at least one space.",
            "#",
            "# Additionally, comments (such as these) may be inserted on individual",
            "# lines or following the machine name denoted by a '#' symbol.",
            "#",
            "# For example:",
            "#",
            "#      102.54.94.97     rhino.acme.com          # source server",
            "#       38.25.63.10     x.acme.com              # x client host",
            "#",
            "# localhost name resolution is handled within DNS itself.",
            "#	127.0.0.1       localhost",
            "#	::1             localhost",
            "",
            "# --- Active Blocklist Entries (Cleaned & Sorted by Hosts File Editor) ---"
        ]
        
        combined = windows_header + sorted(final_entries)
        
        # Add a final newline if the list isn't empty
        if combined and combined[-1].strip():
            combined.append("")

        return combined

    # ----------------------------- Search -------------------------------------
    def search_clear(self):
        self.text_area.tag_remove("search_match", "1.0", tk.END)
        self.text_area.tag_remove("search_current", "1.0", tk.END)
        self._search_matches = []
        self._search_index = -1
        self.update_status("Search cleared.")

    def _recompute_search_matches(self, query, preserve_index=False):
        """
        Recomputes search matches and re-applies highlights.
        If preserve_index is True, it tries to keep the current selection focused.
        """
        old_current_match = None
        if preserve_index and 0 <= self._search_index < len(self._search_matches):
            pos, end = self._search_matches[self._search_index]
            old_current_match = self.text_area.get(pos, end)

        self.search_clear()
        if not query:
            return

        matches = []
        start = "1.0"
        while True:
            # Search with case-insensitivity (nocase=True)
            pos = self.text_area.search(query, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            self.text_area.tag_add("search_match", pos, end)
            matches.append((pos, end))
            start = end
            
        self._search_matches = matches
        
        if self._search_matches:
            new_index = 0
            # Try to find the old text/index if it existed and is still present
            if preserve_index and old_current_match:
                try:
                    # Find the first occurrence of the old matched text in the new matches
                    for i, (pos, end) in enumerate(self._search_matches):
                        if self.text_area.get(pos, end) == old_current_match:
                            new_index = i
                            break
                except Exception:
                    # If fetching the text fails for any reason, default to 0
                    new_index = 0
            
            self._search_index = new_index
            self._focus_current_match()
            self.update_status(f"Found {len(self._search_matches)} matches.")
        else:
            self.update_status(f"No matches found for '{query}'.", is_error=True)


    def _focus_current_match(self):
        self.text_area.tag_remove("search_current", "1.0", tk.END)
        if 0 <= self._search_index < len(self._search_matches):
            pos, end = self._search_matches[self._search_index]
            self.text_area.tag_add("search_current", pos, end)
            # Center the view on the match
            self.text_area.see(pos)

    def search_find(self):
        query = self.search_var.get().strip()
        if not query:
            self.update_status("Enter a search term.", is_error=True)
            return
        # Do not preserve index when actively searching
        self._recompute_search_matches(query, preserve_index=False)

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
