#!/usr/bin/env python3
# Hosts File Get

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font, filedialog, simpledialog
import os
import ctypes
import difflib
import subprocess
import shutil
import urllib.request
import urllib.error
import urllib.parse
import json
import webbrowser
import hashlib
import sys
import csv
import io
import re
import tempfile
import threading
import queue
import gzip
import bz2
import datetime
import argparse
import glob

APP_NAME = "Hosts File Get"
APP_SLUG = "HostsFileGet"
APP_VERSION = "2.14.0"
ELEVATION_ATTEMPT_FLAG = "--hostsfileget-elevation-attempted"

# Hard cap for any single downloaded feed/whitelist payload (50 MB decompressed).
# Even the biggest public blocklists are well under 20 MB; this guards against
# runaway servers streaming gigabytes and OOMing the GUI process.
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024

# Preview windows use difflib.ndiff which is O(n*m). On very large editors
# (200K+ lines) ndiff can hang the UI for many seconds. Above this threshold
# we switch to a cheaper, non-character-aligned unified diff for the preview.
NDIFF_LINE_LIMIT = 10_000

# Number of timestamped backup snapshots to retain alongside the rolling
# ``hosts.bak`` latest-copy. Older ones are pruned oldest-first.
BACKUP_RETENTION = 5

# Cap for a "preview source" pre-fetch. We only need a few dozen lines to let
# a user decide whether to import the whole feed, so a small cap keeps the
# popup snappy and avoids burning bandwidth for a feature that's purely
# advisory.
SOURCE_PREVIEW_MAX_BYTES = 96 * 1024
SOURCE_PREVIEW_MAX_LINES = 80

# Loopback / block-style IPs that the "change block target" tool treats as
# equivalent and will rewrite to the user's chosen sink. :: is the IPv6 null
# address used by some DoH-aware stubs; ::1 is IPv6 loopback.
BLOCK_SINK_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}


def _default_hosts_file_path() -> str:
    """Resolve the real Windows hosts file path from %SystemRoot% when possible.

    Hard-coding ``C:\\Windows`` breaks on installs where Windows lives on a
    non-C drive (IoT images, WinPE, forensic mounts). Fall back to the classic
    path only if the environment variable is missing.
    """
    if os.name == 'nt':
        system_root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or r"C:\Windows"
        return os.path.join(system_root, "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"

# PyInstaller support: resolve bundled asset directory vs. script directory
if getattr(sys, 'frozen', False):
    _BUNDLE_DIR = sys._MEIPASS
    _EXE_DIR = os.path.dirname(sys.executable)
else:
    _BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__))
    _EXE_DIR = _BUNDLE_DIR


def _enable_windows_dpi_awareness() -> None:
    """Tell Windows this process understands high-DPI displays.

    Without this, Tk fonts and icons are bitmap-stretched by the shell
    compatibility layer, which looks blurry on 125%+ displays (the default
    scaling on most modern laptops). The SetProcessDpiAwareness call is
    the modern API; SetProcessDPIAware is the fallback for older Windows.
    Both are idempotent and safe to call even when already set.
    """
    if os.name != 'nt':
        return
    try:
        # 2 = Per-monitor DPI aware (Windows 8.1+).
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except (AttributeError, OSError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass


_enable_windows_dpi_awareness()

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
    "yellow": "#f9e2af",
    "yellow_ink": "#3b2f13",
    "accent": "#b4befe",
}

# ----------------------------- Tooltip Helper --------------------------------
class ToolTip:
    """Creates a tooltip for a given widget.

    Tooltips show after a short hover delay (450ms) to avoid flashing
    on every transient mouse-over, and hide on click or when the widget
    is destroyed.
    """
    _SHOW_DELAY_MS = 450

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self._show_job = None
        self.widget.bind("<Enter>", self._schedule_show, add="+")
        self.widget.bind("<Leave>", self.hide_tooltip, add="+")
        self.widget.bind("<Destroy>", self.hide_tooltip, add="+")
        # Clicking or keyboard-activating the widget should dismiss any
        # lingering tooltip immediately so it doesn't hover over a just-
        # pressed button.
        self.widget.bind("<ButtonPress>", self.hide_tooltip, add="+")
        self.widget.bind("<KeyPress>", self.hide_tooltip, add="+")

    def _schedule_show(self, event=None):
        self._cancel_pending_show()
        try:
            self._show_job = self.widget.after(self._SHOW_DELAY_MS, self.show_tooltip)
        except tk.TclError:
            self._show_job = None

    def _cancel_pending_show(self):
        if self._show_job is not None:
            try:
                self.widget.after_cancel(self._show_job)
            except (tk.TclError, ValueError):
                pass
            self._show_job = None

    def show_tooltip(self, event=None):
        self._show_job = None
        if self.tooltip_window:
            return
        # Any of these widget calls can raise if the widget was destroyed
        # between scheduling and firing (e.g. during a config reload).
        try:
            if not self.widget.winfo_exists():
                return
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
        except tk.TclError:
            self.tooltip_window = None

    def hide_tooltip(self, event=None):
        self._cancel_pending_show()
        if self.tooltip_window:
            try:
                self.tooltip_window.destroy()
            except tk.TclError:
                pass
        self.tooltip_window = None

# ------------------------------ Preview Window --------------------------------
class PreviewWindow(tk.Toplevel):
    def __init__(
        self,
        parent,
        original_lines,
        new_lines,
        title="Preview Changes",
        on_apply_callback=None,
        stats=None,
        apply_label="Apply Changes",
        cancel_label="Keep Current",
    ):
        super().__init__(parent.root)
        self.parent_editor = parent
        self.new_lines = new_lines
        self.on_apply_callback = on_apply_callback
        self.stats = stats or {}
        self._is_applying = False
        self._added_lines = 0
        self._removed_lines = 0

        self.title(title)
        # Clamp to available screen so the preview never opens larger than
        # the user's display (common on 1366x768 laptops where 900x650 +
        # window chrome overflows).
        try:
            screen_w = parent.root.winfo_screenwidth()
            screen_h = parent.root.winfo_screenheight()
        except Exception:
            screen_w, screen_h = 900, 650
        width = min(900, max(640, screen_w - 80))
        height = min(650, max(420, screen_h - 120))
        self.geometry(f"{width}x{height}")
        self.configure(bg=PALETTE["base"])
        self.transient(parent.root)
        self.grab_set()

        header_frame = ttk.Frame(self, padding=(14, 14, 14, 0))
        header_frame.pack(fill='x', side=tk.TOP)
        ttk.Label(header_frame, text=title, font=("Segoe UI Semibold", 14)).pack(anchor='w')
        ttk.Label(
            header_frame,
            text="Review the exact before-and-after output before applying it to the editor or disk.",
            foreground=PALETTE["subtext"]
        ).pack(anchor='w', pady=(4, 0))

        # Top stats/warning frame
        if self.stats:
            stats_frame = ttk.Frame(self, padding=(14, 12, 14, 0))
            stats_frame.pack(fill='x', side=tk.TOP)
            self._add_stat_banner(stats_frame)
        
        top_padding = 4 if self.stats else 12
        text_frame = ttk.Frame(self, padding=(14, top_padding, 14, 0))
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
        self.preview_summary_label = ttk.Label(legend_frame, text="", foreground=PALETTE["subtext"])
        self.preview_summary_label.pack(anchor='w')
        self.preview_legend_label = ttk.Label(legend_frame, text="", foreground=PALETTE["overlay1"])
        self.preview_legend_label.pack(anchor='w', pady=(2, 0))

        self.apply_button = ttk.Button(button_frame, text=apply_label, command=self.apply_changes, style="Accent.TButton")
        self.apply_button.pack(side=tk.RIGHT, padx=6)
        ttk.Button(button_frame, text=cancel_label, command=self.destroy, style="Secondary.TButton").pack(side=tk.RIGHT, padx=6)

        self.preview_text.tag_config('added', foreground="#89D68D")
        self.preview_text.tag_config('removed', foreground=PALETTE["red"])
        self.display_diff(original_lines, new_lines)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.bind("<Escape>", lambda _event: self.destroy(), add="+")
        # Return/Enter confirms the preview without forcing the user to
        # mouse over to the button. Bound on the window so it works from
        # wherever focus sits (scrolling, header, etc.).
        self.bind("<Return>", lambda _event: self.apply_changes(), add="+")
        self.bind("<KP_Enter>", lambda _event: self.apply_changes(), add="+")
        # Focus the apply button so keyboard activation is predictable and
        # screen readers pick up the primary action.
        self.apply_button.focus_set()

    def _add_stat_banner(self, parent):
        total_discarded = self.stats.get('total_discarded', 0)
        transformed_count = self.stats.get('transformed', 0)

        if total_discarded > 0 and transformed_count > 0:
            warning_text = f"Cleaned Save will remove {total_discarded} entries and normalize {transformed_count} line(s)."
            warning_color = PALETTE["red"]
        elif total_discarded > 0:
            warning_text = f"Cleaned Save will remove {total_discarded} entries."
            warning_color = PALETTE["red"]
        elif transformed_count > 0:
            warning_text = f"Cleaned Save will normalize {transformed_count} line(s) without discarding any entries."
            warning_color = PALETTE["yellow"]
        else:
            warning_text = "Cleaned Save will preserve every current entry."
            warning_color = PALETTE["green"]

        warn_label = ttk.Label(parent, text=warning_text, foreground=warning_color, font=("Segoe UI", 11, "bold"))
        warn_label.pack(fill='x', pady=(0, 5))
        ttk.Label(
            parent,
            text="Review the categories below if you want to confirm why lines will change or be removed.",
            foreground=PALETTE["subtext"]
        ).pack(fill='x', pady=(0, 6))

        detail_frame = ttk.Frame(parent)
        detail_frame.pack(fill='x')

        detail_items = [
            ("Whitelist", self.stats.get('removed_whitelist', 0), PALETTE["blue"]),
            ("Invalid", self.stats.get('removed_invalid', 0), PALETTE["red"]),
            ("Duplicates", self.stats.get('removed_duplicates', 0), PALETTE["red"]),
            ("Comments", self.stats.get('removed_comments', 0), PALETTE["overlay1"]),
            ("Blanks", self.stats.get('removed_blanks', 0), PALETTE["overlay1"]),
        ]
        for column, (label, value, color) in enumerate(detail_items):
            chip = tk.Label(
                detail_frame,
                text=f"{label}: {value}",
                bg=PALETTE["surface0"],
                fg=color,
                font=("Segoe UI", 9, "bold"),
                padx=8,
                pady=4,
                bd=0
            )
            chip.grid(row=0, column=column, padx=(0, 6), pady=(0, 2), sticky="w")

        for column in range(len(detail_items)):
            detail_frame.grid_columnconfigure(column, weight=1)


    def display_diff(self, original, new):
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete('1.0', tk.END)
        self._added_lines = 0
        self._removed_lines = 0

        # difflib.ndiff is O(n*m). For very large editors (hundreds of
        # thousands of lines) it can hang the preview dialog for tens of
        # seconds. Fall back to unified_diff above the threshold — it still
        # classifies every line as added/removed/context, just without the
        # character-level hint lines.
        use_ndiff = max(len(original), len(new)) <= NDIFF_LINE_LIMIT

        if use_ndiff:
            for line in difflib.ndiff(original, new):
                line_content = line[2:] + '\n'
                if line.startswith('+ '):
                    self._added_lines += 1
                    self.preview_text.insert(tk.END, line_content, 'added')
                elif line.startswith('- '):
                    self._removed_lines += 1
                    self.preview_text.insert(tk.END, line_content, 'removed')
                elif not line.startswith('? '):
                    self.preview_text.insert(tk.END, line_content)
        else:
            for line in difflib.unified_diff(original, new, n=3, lineterm=""):
                if line.startswith("+++") or line.startswith("---"):
                    continue
                if line.startswith('@@'):
                    self.preview_text.insert(tk.END, line + '\n')
                    continue
                if line.startswith('+'):
                    self._added_lines += 1
                    self.preview_text.insert(tk.END, line[1:] + '\n', 'added')
                elif line.startswith('-'):
                    self._removed_lines += 1
                    self.preview_text.insert(tk.END, line[1:] + '\n', 'removed')
                else:
                    self.preview_text.insert(tk.END, line[1:] + '\n' if line.startswith(' ') else line + '\n')

        self.preview_text.config(state=tk.DISABLED)
        self.preview_summary_label.config(
            text=f"{self._added_lines:,} line(s) added, {self._removed_lines:,} removed"
        )
        legend = "Green lines are new. Red lines will be removed."
        if not use_ndiff:
            legend += " (Compact diff used for large files.)"
        self.preview_legend_label.config(text=legend)

    def apply_changes(self):
        if self._is_applying:
            return

        self._is_applying = True
        self.apply_button.configure(state="disabled")
        try:
            if self.on_apply_callback:
                self.on_apply_callback(self.new_lines)
            else:
                self.parent_editor.set_text(self.new_lines)
                self.parent_editor.update_status(f"Changes from '{self.title()}' applied.")
        except Exception as e:
            self._is_applying = False
            self.apply_button.configure(state="normal")
            messagebox.showerror("Apply Failed", f"Could not apply preview changes:\n{e}", parent=self)
            return

        self.destroy()

# -------------------------- Add Custom Source Dialog --------------------------
class AddSourceDialog(simpledialog.Dialog):
    def __init__(self, parent, initial_name="", initial_url=""):
        self.initial_name = initial_name
        self.initial_url = initial_url
        super().__init__(parent)

    def body(self, master):
        self.title("Add Custom Blocklist Source")
        master.columnconfigure(1, weight=1)
        ttk.Label(
            master,
            text="Save a reusable feed so it appears in Custom Sources for one-click imports.",
            foreground=PALETTE["subtext"],
            wraplength=360,
            justify="left"
        ).grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 10))
        ttk.Label(master, text="Display Name:").grid(row=1, sticky='w', pady=5)
        ttk.Label(master, text="Source URL:").grid(row=2, sticky='w', pady=5)
        self.name_entry = ttk.Entry(master, width=40)
        self.url_entry = ttk.Entry(master, width=40)
        self.name_entry.grid(row=1, column=1, padx=5, sticky="ew")
        self.url_entry.grid(row=2, column=1, padx=5, sticky="ew")
        if self.initial_name:
            self.name_entry.insert(0, self.initial_name)
        if self.initial_url:
            self.url_entry.insert(0, self.initial_url)
        return self.name_entry

    # Upper bound on any custom source URL. 2083 is the practical browser
    # limit (IE/Edge legacy); anything longer is almost certainly pasted
    # junk or a prompt-injection attempt against the sidebar text.
    _URL_MAX_LEN = 2083
    _NAME_MAX_LEN = 120

    def validate(self):
        name, url = self.name_entry.get().strip(), self.url_entry.get().strip()
        if not name or not url:
            messagebox.showwarning("Input Required", "Both name and URL are required.", parent=self)
            if not name:
                self.name_entry.focus_set()
            else:
                self.url_entry.focus_set()
            return False

        if len(name) > self._NAME_MAX_LEN:
            messagebox.showerror(
                "Name Too Long",
                f"Display names are capped at {self._NAME_MAX_LEN} characters.",
                parent=self,
            )
            self.name_entry.focus_set()
            return False

        if any(ord(ch) < 32 for ch in name + url):
            # Embedded tabs / newlines / control bytes would corrupt the
            # sidebar display and the sanitized marker comments. Reject
            # rather than silently stripping.
            messagebox.showerror(
                "Invalid Characters",
                "Name and URL must not contain tabs, newlines, or control characters.",
                parent=self,
            )
            self.url_entry.focus_set()
            return False

        if not url.lower().startswith(('http://', 'https://')):
            messagebox.showerror("Invalid URL", "URL must start with http:// or https://", parent=self)
            self.url_entry.focus_set()
            self.url_entry.selection_range(0, tk.END)
            return False

        if len(url) > self._URL_MAX_LEN:
            messagebox.showerror(
                "URL Too Long",
                f"URLs are capped at {self._URL_MAX_LEN} characters.",
                parent=self,
            )
            self.url_entry.focus_set()
            return False

        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            messagebox.showerror("Invalid URL", "URL could not be parsed.", parent=self)
            self.url_entry.focus_set()
            return False
        if not parsed.netloc:
            messagebox.showerror("Invalid URL", "URL is missing a host name.", parent=self)
            self.url_entry.focus_set()
            return False

        self.result = (name, url)
        return True

    def apply(self):
        name, url = self.name_entry.get().strip(), self.url_entry.get().strip()
        self.result = (name, url)

# -------------------------- Bulk Selection Dialog (New in v2.8.5) ----------------
class BulkSelectionDialog(tk.Toplevel):
    def __init__(self, parent, blocklist_sources, custom_sources):
        super().__init__(parent)
        self.title("Select Lists to Import")
        self.geometry("600x700")
        self.configure(bg=PALETTE["base"])
        self.transient(parent)
        self.grab_set()
        self.bind("<Escape>", lambda _event: self.destroy(), add="+")
        
        self.result = None
        self.checkbox_vars = [] # List of tuples: (name, url, tk.BooleanVar)
        
        # --- Header ---
        header_frame = ttk.Frame(self, padding=(14, 14, 14, 0))
        header_frame.pack(fill='x')
        ttk.Label(header_frame, text="Choose the sources you want to import in this batch.", font=("Segoe UI Semibold", 12)).pack(anchor='w')
        ttk.Label(
            header_frame,
            text="Selections are downloaded one at a time so progress, failures, and cancellation stay predictable.",
            foreground=PALETTE["subtext"],
            wraplength=540,
            justify="left"
        ).pack(anchor='w', pady=(4, 0))
        self.selection_summary_label = ttk.Label(header_frame, foreground=PALETTE["overlay1"])
        self.selection_summary_label.pack(anchor='w', pady=(6, 0))
        
        # --- Scrollable Area ---
        container = ttk.Frame(self)
        container.pack(fill='both', expand=True, padx=10, pady=5)
        
        canvas = tk.Canvas(container, bg=PALETTE["mantle"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        # Mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<Enter>", lambda _event: canvas.bind_all("<MouseWheel>", _on_mousewheel))
        canvas.bind("<Leave>", lambda _event: canvas.unbind_all("<MouseWheel>"))
        self.bind("<Destroy>", lambda _event: canvas.unbind_all("<MouseWheel>"), add="+")
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # --- Populate Lists ---
        # 1. Standard Sources
        for category, sources in blocklist_sources.items():
            self._add_category_header(category)
            for name, url, tooltip in sources:
                self._add_checkbox(name, url, tooltip)
                
        # 2. Custom Sources
        if custom_sources:
            self._add_category_header("Custom Sources")
            for src in custom_sources:
                self._add_checkbox(src['name'], src['url'], "Custom Source")
                
        # --- Footer Buttons ---
        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(fill='x', side='bottom')
        
        left_btns = ttk.Frame(btn_frame)
        left_btns.pack(side='left')
        ttk.Button(left_btns, text="Select All", command=self.select_all).pack(side='left', padx=2)
        ttk.Button(left_btns, text="Select None", command=self.select_none).pack(side='left', padx=2)
        
        right_btns = ttk.Frame(btn_frame)
        right_btns.pack(side='right')
        ttk.Button(right_btns, text="Import Selected", command=self.confirm, style="Accent.TButton").pack(side='left', padx=5)
        ttk.Button(right_btns, text="Keep Current", command=self.destroy, style="Secondary.TButton").pack(side='left')
        self._update_selection_summary()

    def _add_category_header(self, text):
        f = ttk.Frame(self.scrollable_frame, padding=(5, 10, 5, 2))
        f.pack(fill='x')
        ttk.Label(f, text=text, font=("Segoe UI", 10, "bold"), foreground=PALETTE["blue"]).pack(anchor='w')
        ttk.Separator(f, orient='horizontal').pack(fill='x')

    def _add_checkbox(self, name, url, tooltip):
        var = tk.BooleanVar(value=True) # Default to checked
        frame = ttk.Frame(self.scrollable_frame, padding=(15, 2, 5, 2))
        frame.pack(fill='x')
        
        cb = ttk.Checkbutton(frame, text=name, variable=var, command=self._update_selection_summary)
        cb.pack(side='left', fill='x', expand=True)
        source_host = urllib.parse.urlparse(url).netloc or url
        ttk.Label(frame, text=source_host, foreground=PALETTE["subtext"]).pack(side='right', padx=(8, 0))
        
        # Determine tooltip text
        url_short = (url[:50] + '..') if len(url) > 50 else url
        tip_text = f"{tooltip}\nURL: {url_short}"
        ToolTip(cb, tip_text)
        
        self.checkbox_vars.append((name, url, var))

    def _update_selection_summary(self):
        total = len(self.checkbox_vars)
        selected_count = sum(1 for _, _, var in self.checkbox_vars if var.get())
        self.selection_summary_label.config(text=f"{selected_count} of {total} source(s) selected")

    def select_all(self):
        for _, _, var in self.checkbox_vars:
            var.set(True)
        self._update_selection_summary()

    def select_none(self):
        for _, _, var in self.checkbox_vars:
            var.set(False)
        self._update_selection_summary()

    def confirm(self):
        selected = []
        for name, url, var in self.checkbox_vars:
            if var.get():
                selected.append((name, url))
        
        if not selected:
            messagebox.showwarning("Selection Empty", "Please select at least one list to import.", parent=self)
            return
            
        self.result = selected
        self.destroy()

# Hard limit on the number of checkboxes the removal dialog will render at
# once. Above this, Tk's layout engine takes many seconds to pack the widgets
# and the resulting scrollable frame becomes unusable on slower machines.
MATCH_REMOVAL_DIALOG_LIMIT = 2000

# Hard cap on the number of in-editor search matches we will highlight.
# A common one-letter query against a multi-megabyte hosts file could
# otherwise produce hundreds of thousands of matches and hang Tk while it
# tried to add that many tag ranges.
SEARCH_MATCH_LIMIT = 50_000


class MatchRemovalDialog(tk.Toplevel):
    def __init__(self, parent, query: str, matching_lines: list[tuple[int, str]]):
        super().__init__(parent)
        self.title(f"Remove Matches for '{query}'")
        self.geometry("760x620")
        self.configure(bg=PALETTE["base"])
        self.transient(parent)
        self.grab_set()
        self.bind("<Escape>", lambda _event: self.destroy(), add="+")

        self.result = None
        self.checkbox_vars = []

        header_frame = ttk.Frame(self, padding=(14, 14, 14, 0))
        header_frame.pack(fill="x")
        ttk.Label(
            header_frame,
            text=f"Review which matches to remove for '{query}'.",
            font=("Segoe UI Semibold", 12)
        ).pack(anchor="w")
        self.selection_summary_label = ttk.Label(
            header_frame,
            text="",
            foreground=PALETTE["subtext"]
        )
        self.selection_summary_label.pack(anchor="w", pady=(4, 0))
        ttk.Label(
            header_frame,
            text="Unchecked lines stay in the editor.",
            foreground=PALETTE["overlay1"]
        ).pack(anchor="w", pady=(4, 0))

        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=10, pady=5)

        canvas = tk.Canvas(container, bg=PALETTE["mantle"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind("<Enter>", lambda _event: canvas.bind_all("<MouseWheel>", _on_mousewheel))
        canvas.bind("<Leave>", lambda _event: canvas.unbind_all("<MouseWheel>"))
        self.bind("<Destroy>", lambda _event: canvas.unbind_all("<MouseWheel>"), add="+")

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for line_index, line in matching_lines:
            var = tk.BooleanVar(value=True)
            frame = ttk.Frame(self.scrollable_frame, padding=(10, 4))
            frame.pack(fill="x")

            cb = ttk.Checkbutton(
                frame,
                text=f"Line {line_index + 1}: {line}",
                variable=var,
                command=self._update_selection_summary,
                wraplength=690,
                justify="left"
            )
            cb.pack(side="left", fill="x", expand=True)
            self.checkbox_vars.append((line_index, var))

        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(fill="x", side="bottom")

        left_btns = ttk.Frame(btn_frame)
        left_btns.pack(side="left")
        ttk.Button(left_btns, text="Select All", command=self.select_all).pack(side="left", padx=2)
        ttk.Button(left_btns, text="Select None", command=self.select_none).pack(side="left", padx=2)

        right_btns = ttk.Frame(btn_frame)
        right_btns.pack(side="right")
        ttk.Button(right_btns, text="Remove Selected", command=self.confirm, style="Danger.TButton").pack(side="left", padx=5)
        ttk.Button(right_btns, text="Keep Remaining", command=self.destroy, style="Secondary.TButton").pack(side="left")
        self._update_selection_summary()

    def _update_selection_summary(self):
        total = len(self.checkbox_vars)
        selected_count = sum(1 for _, var in self.checkbox_vars if var.get())
        self.selection_summary_label.config(text=f"{selected_count} of {total} removable line(s) currently selected")

    def select_all(self):
        for _, var in self.checkbox_vars:
            var.set(True)
        self._update_selection_summary()

    def select_none(self):
        for _, var in self.checkbox_vars:
            var.set(False)
        self._update_selection_summary()

    def confirm(self):
        selected_indices = {line_index for line_index, var in self.checkbox_vars if var.get()}
        if not selected_indices:
            messagebox.showwarning("Selection Empty", "Select at least one matching line to remove.", parent=self)
            return

        self.result = selected_indices
        self.destroy()

# -------------------------------- Domain & Hosts Helpers -----------------------------------

DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$')
IPV4_REGEX = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
IPV6_REGEX = re.compile(r'^[\da-fA-F:.]+$')
WILDCARD_STRIPPER = re.compile(r'^\*\.?(.*)')
TOKEN_SPLITTER = re.compile(r'[\s,;]+')
DNSMASQ_RULE_REGEX = re.compile(r'^(?:address|local)=/([^/]+)/?', re.IGNORECASE)
COMMENT_PREFIXES = ('#', '!', '[')
LOCAL_DOMAINS = {'localhost', 'localhost.localdomain', '::1'}
HOST_LABEL_REGEX = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
STANDARD_BLOCKING_IPS = {"0.0.0.0", "127.0.0.1", "::1"}

def looks_like_domain(token: str, allow_single_label: bool = False) -> bool:
    if len(token) > 253: return False
    if token.startswith(('-', '.')) or token.endswith(('-', '.')): return False
    if IPV4_REGEX.match(token) or (IPV6_REGEX.match(token) and ':' in token): return False
    if allow_single_label and '.' not in token:
        return bool(HOST_LABEL_REGEX.match(token)) and any(character.isalpha() for character in token)
    return bool(DOMAIN_REGEX.match(token))

def _looks_like_ip_token(token: str) -> bool:
    return bool(IPV4_REGEX.match(token) or (IPV6_REGEX.match(token) and ':' in token))

def _is_comment_line(stripped: str) -> bool:
    return stripped.startswith(COMMENT_PREFIXES)

def _normalize_mapping_ip(token: str) -> tuple[str, bool, bool]:
    candidate = token.strip()
    normalized = candidate.lower() if ':' in candidate else candidate
    if normalized in STANDARD_BLOCKING_IPS:
        return "0.0.0.0", normalized != "0.0.0.0", True
    return normalized, normalized != candidate, False

def _extract_domain_from_token(token: str, allow_single_label: bool = False) -> tuple[str | None, bool]:
    candidate = token.strip().strip('\'"()[]{}<>')
    transformed = candidate != token.strip()
    if not candidate:
        return None, transformed

    if candidate.startswith('@@'):
        return None, True

    dnsmasq_match = DNSMASQ_RULE_REGEX.match(candidate)
    if dnsmasq_match:
        candidate = dnsmasq_match.group(1)
        transformed = True

    if candidate.startswith('||'):
        candidate = candidate[2:]
        transformed = True
    elif candidate.startswith('|'):
        candidate = candidate[1:]
        transformed = True

    for delimiter in ('^', '$'):
        if delimiter in candidate:
            candidate = candidate.split(delimiter, 1)[0]
            transformed = True

    if candidate.lower().startswith(('http://', 'https://', 'ftp://')):
        hostname = urllib.parse.urlsplit(candidate).hostname
        transformed = True
        if not hostname:
            return None, transformed
        candidate = hostname
    elif any(separator in candidate for separator in ('/', '?', ':')):
        try:
            hostname = urllib.parse.urlsplit(f"http://{candidate}").hostname
        except ValueError:
            hostname = None
        if hostname:
            candidate = hostname
            transformed = True

    wildcard_match = WILDCARD_STRIPPER.match(candidate)
    if wildcard_match:
        candidate = wildcard_match.group(1)
        transformed = True

    if candidate.endswith('.'):
        candidate = candidate[:-1]
        transformed = True

    domain = candidate.lower()
    if domain in LOCAL_DOMAINS or not looks_like_domain(domain, allow_single_label=allow_single_label):
        return None, transformed

    return domain, transformed

def parse_hosts_line_entries(line: str) -> tuple[list[tuple[str, str, bool]], bool]:
    stripped = line.strip()
    if not stripped or _is_comment_line(stripped):
        return [], False

    processed = stripped.split('#', 1)[0].strip()
    if not processed:
        return [], False

    tokens = [token for token in TOKEN_SPLITTER.split(processed) if token]
    if not tokens:
        return [], False

    if _looks_like_ip_token(tokens[0]):
        mapping_ip, ip_transformed, is_block_entry = _normalize_mapping_ip(tokens[0])
        candidate_tokens = tokens[1:]
        transformed = ip_transformed or len(candidate_tokens) != 1
        allow_single_label = True
    else:
        mapping_ip = "0.0.0.0"
        is_block_entry = True
        candidate_tokens = tokens
        transformed = True
        allow_single_label = False

    parsed_entries = []
    seen_in_line = set()

    for token in candidate_tokens:
        domain, token_transformed = _extract_domain_from_token(token, allow_single_label=allow_single_label)
        transformed = transformed or token_transformed
        if not domain:
            continue

        normalized = f"{mapping_ip} {domain}"
        if normalized in seen_in_line:
            transformed = True
            continue

        seen_in_line.add(normalized)
        parsed_entries.append((normalized, domain, is_block_entry))

    return parsed_entries, transformed

def normalize_line_to_hosts_entries(line: str) -> tuple[list[str], list[str], bool]:
    parsed_entries, transformed = parse_hosts_line_entries(line)
    return [entry[0] for entry in parsed_entries], [entry[1] for entry in parsed_entries], transformed

def normalize_line_to_hosts_entry(line: str) -> tuple[str | None, str | None, bool]:
    normalized_entries, domains, transformed = normalize_line_to_hosts_entries(line)
    if normalized_entries:
        return normalized_entries[0], domains[0], transformed
    return None, None, False

# -------------------------------- Canonical Output Builder -----------------------------------

WINDOWS_HEADER = [
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
    "#"
]


def _get_canonical_cleaned_output_and_stats(original_lines: list[str], whitelist_set: set) -> tuple[list[str], dict]:
    stats = {
        "lines_total": len(original_lines),
        "removed_blanks": 0,
        "removed_comments": 0,
        "removed_whitelist": 0,
        "removed_duplicates": 0,
        "removed_invalid": 0, 
        "transformed": 0, 
    }
    
    seen_normalized = set()
    active_entries_to_keep = []
    
    for line in original_lines:
        stripped = line.strip()
        
        if not stripped:
            stats["removed_blanks"] += 1
            continue
        
        if _is_comment_line(stripped):
            stats["removed_comments"] += 1
            continue

        parsed_entries, transformed = parse_hosts_line_entries(line)
        if not parsed_entries:
            stats["removed_invalid"] += 1
            continue

        kept_from_line = 0
        for normalized, domain, is_block_entry in parsed_entries:
            if is_block_entry and (domain in whitelist_set or domain.lstrip('.') in whitelist_set):
                stats["removed_whitelist"] += 1
                continue

            if normalized in seen_normalized:
                stats["removed_duplicates"] += 1
                continue

            seen_normalized.add(normalized)
            active_entries_to_keep.append(normalized)
            kept_from_line += 1

        if kept_from_line > 0 and transformed:
            stats["transformed"] += 1

    final_header = WINDOWS_HEADER + [
        f"#\t127.0.0.1       localhost ({len(active_entries_to_keep)} active entries prepared by editor)",
        "#\t::1             localhost",
        "",
        f"# --- Active Hosts Entries (Cleaned & Sorted by {APP_NAME} v{APP_VERSION}) ---"
    ]
    
    cleaned_lines = final_header + sorted(active_entries_to_keep)
    
    if cleaned_lines and cleaned_lines[-1].strip():
        cleaned_lines.append("")

    stats["final_active"] = len(active_entries_to_keep)
    stats["final_total"] = len(cleaned_lines)
    stats["total_discarded"] = (
        stats["removed_whitelist"] + 
        stats["removed_duplicates"] + 
        stats["removed_invalid"] +
        stats["removed_comments"] +
        stats["removed_blanks"]
    )

    return cleaned_lines, stats

def compute_clean_impact_stats(original_lines: list[str], whitelist_set: set) -> dict:
    _, stats = _get_canonical_cleaned_output_and_stats(original_lines, whitelist_set)
    return stats

TEXT_FILE_ENCODINGS = ("utf-8", "utf-8-sig", "cp1252", "latin-1")

def decode_text_bytes(raw_bytes: bytes) -> str:
    if raw_bytes.startswith(b'\xef\xbb\xbf'):
        return raw_bytes.decode("utf-8-sig")

    if raw_bytes.startswith((b'\xff\xfe', b'\xfe\xff')):
        return raw_bytes.decode("utf-16")

    null_bytes = raw_bytes.count(b"\x00")
    if raw_bytes and null_bytes and (null_bytes / len(raw_bytes)) > 0.15:
        for encoding in ("utf-16-le", "utf-16-be"):
            try:
                return raw_bytes.decode(encoding)
            except UnicodeDecodeError:
                continue

    for encoding in TEXT_FILE_ENCODINGS:
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode('utf-8', errors='ignore')

def read_text_file_lines(path: str) -> list[str]:
    with open(path, 'rb') as f:
        return decode_text_bytes(f.read()).splitlines()

def read_text_file_content(path: str) -> str:
    return '\n'.join(read_text_file_lines(path))

def write_text_file_atomic(path: str, content: str):
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(prefix="hosts_editor_", suffix=".tmp", dir=directory, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            f.write(content)
            # Ensure a trailing newline. Some POSIX-style tools that consume
            # the hosts file expect one, and hash comparisons here go through
            # splitlines so an added terminator doesn't change equality.
            if content and not content.endswith('\n'):
                f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise

def read_http_body_limited(response, max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    """Read an HTTP response with a hard ceiling on total bytes.

    ``response.read(max_bytes + 1)`` is used so we can detect overruns without
    paying for an unbounded read. Returning the body as-is lets callers decode
    and normalize it through the existing pipeline.
    """
    data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(
            f"Response exceeded {max_bytes // (1024 * 1024)} MB size cap "
            "(feed too large or server is streaming non-hosts content)."
        )
    return data


def decode_downloaded_lines(url: str, raw_bytes: bytes, content_encoding: str = "") -> list[str]:
    lowered_url = url.lower()
    lowered_encoding = content_encoding.lower()

    try:
        if lowered_url.endswith(".bz2"):
            raw_bytes = bz2.decompress(raw_bytes)
        elif lowered_url.endswith(".gz") or "gzip" in lowered_encoding:
            raw_bytes = gzip.decompress(raw_bytes)
    except OSError:
        # Some mirrors advertise compression inconsistently; fall back to raw bytes.
        pass

    # After decompression, re-check the size so a 1 KB gzip bomb can't expand
    # into hundreds of MB in memory undetected.
    if len(raw_bytes) > MAX_DOWNLOAD_BYTES:
        raise ValueError(
            f"Decompressed payload exceeded {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB size cap."
        )

    return decode_text_bytes(raw_bytes).splitlines()

def looks_like_html_document(lines: list[str]) -> bool:
    significant_lines = [line.strip().lower() for line in lines if line.strip()][:20]
    if not significant_lines:
        return False

    combined = '\n'.join(significant_lines[:10])
    html_markers = ("<!doctype html", "<html", "<head", "<body", "</html>", "<title", "<meta ")
    if significant_lines[0].startswith(("<!doctype html", "<html")):
        return True

    marker_hits = sum(1 for marker in html_markers if marker in combined)
    return marker_hits >= 2

def _portable_config_path_candidate() -> str:
    """Return the path where a portable-mode config would live.

    Portable mode: if the user ships a ``hosts_editor_config.json`` next to
    the exe / script, we treat that sibling as the live config and skip
    ``%LOCALAPPDATA%`` entirely. Lets USB-stick / team-share deployments
    carry their settings with the binary.
    """
    return os.path.join(_EXE_DIR, "hosts_editor_config.json")


def is_portable_mode() -> bool:
    return os.path.isfile(_portable_config_path_candidate())


def get_app_config_dir() -> str:
    if os.name == 'nt':
        base_dir = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base_dir, APP_SLUG)
    return os.path.join(os.path.expanduser("~"), f".{APP_SLUG.lower()}")

def get_primary_config_path(config_filename: str) -> str:
    if is_portable_mode():
        return _portable_config_path_candidate()
    return _roaming_config_path(config_filename)


def _roaming_config_path(config_filename: str) -> str:
    return os.path.join(get_app_config_dir(), config_filename)

def normalize_custom_source_url(url: str) -> str:
    candidate = url.strip()
    if not candidate:
        return ""

    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return candidate.rstrip('/').lower()

    if not parsed.scheme or not parsed.netloc:
        return candidate.rstrip('/').lower()

    normalized_path = parsed.path.rstrip('/')

    return urllib.parse.urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        normalized_path,
        parsed.query,
        "",
    ))

def sanitize_custom_sources(custom_sources) -> list[dict[str, str]]:
    if not isinstance(custom_sources, list):
        return []

    sanitized_sources = []
    seen_names = set()
    seen_urls = set()

    for source in custom_sources:
        if not isinstance(source, dict):
            continue

        name = str(source.get("name", "")).strip()
        url = str(source.get("url", "")).strip()
        if not name or not url or not url.lower().startswith(("http://", "https://")):
            continue

        # Reject names or URLs containing control bytes (tab, newline, ESC,
        # etc.). A legacy config with a malformed entry could otherwise
        # corrupt the import marker comments or the sidebar layout.
        if any(ord(ch) < 32 for ch in name) or any(ord(ch) < 32 for ch in url):
            continue

        # Cap sizes defensively; see AddSourceDialog for rationale.
        if len(name) > 120 or len(url) > 2083:
            continue

        normalized_name = name.lower()
        normalized_url = normalize_custom_source_url(url)
        if normalized_name in seen_names or normalized_url in seen_urls:
            continue

        seen_names.add(normalized_name)
        seen_urls.add(normalized_url)
        sanitized_sources.append({"name": name, "url": url})

    return sanitized_sources

def sanitize_config_snapshot(config, default_last_open_dir: str) -> dict:
    if not isinstance(config, dict):
        config = {}

    fallback_last_open_dir = default_last_open_dir if isinstance(default_last_open_dir, str) and os.path.isdir(default_last_open_dir) else os.path.expanduser("~")
    if not os.path.isdir(fallback_last_open_dir):
        fallback_last_open_dir = os.getcwd()

    whitelist_value = config.get("whitelist", "")
    if isinstance(whitelist_value, str):
        whitelist_text = whitelist_value
    elif isinstance(whitelist_value, (list, tuple, set)):
        whitelist_text = '\n'.join(
            item.strip()
            for item in (str(entry) for entry in whitelist_value)
            if item.strip()
        )
    else:
        whitelist_text = ""

    def _normalize_hash(value):
        # SHA-256 hex digests are exactly 64 lowercase hex characters.
        # Rejecting anything else prevents a corrupted config from putting
        # arbitrary strings into the saved-state comparator where they
        # would never match a real editor hash and would quietly confuse
        # the "unsaved changes" badge.
        if not isinstance(value, str):
            return None
        value = value.strip().lower()
        if len(value) != 64:
            return None
        if not all(ch in "0123456789abcdef" for ch in value):
            return None
        return value

    last_open_dir = config.get("last_open_dir", fallback_last_open_dir)
    if not isinstance(last_open_dir, str) or not os.path.isdir(last_open_dir):
        last_open_dir = fallback_last_open_dir

    raw_last_fetched = config.get("source_last_fetched", {})
    source_last_fetched: dict[str, str] = {}
    if isinstance(raw_last_fetched, dict):
        for url, stamp in raw_last_fetched.items():
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue
            if not isinstance(stamp, str) or len(stamp) > 64:
                continue
            # Reject garbage timestamps so a corrupt config can't poison
            # tooltips with arbitrary strings.
            try:
                datetime.datetime.fromisoformat(stamp)
            except (TypeError, ValueError):
                continue
            source_last_fetched[url] = stamp

    preferred_sink_raw = config.get("preferred_block_sink", "0.0.0.0")
    preferred_sink = preferred_sink_raw if preferred_sink_raw in BLOCK_SINK_IPS else "0.0.0.0"

    raw_retention = config.get("backup_retention", BACKUP_RETENTION)
    try:
        backup_retention = int(raw_retention)
    except (TypeError, ValueError):
        backup_retention = BACKUP_RETENTION
    backup_retention = max(0, min(50, backup_retention))

    has_completed_first_run = bool(config.get("has_completed_first_run", False))

    return {
        "whitelist": whitelist_text,
        "custom_sources": sanitize_custom_sources(config.get("custom_sources", [])),
        "last_applied_raw_hash": _normalize_hash(config.get("last_applied_raw_hash")),
        "last_applied_cleaned_hash": _normalize_hash(config.get("last_applied_cleaned_hash")),
        "last_open_dir": last_open_dir,
        "source_last_fetched": source_last_fetched,
        "preferred_block_sink": preferred_sink,
        "backup_retention": backup_retention,
        "has_completed_first_run": has_completed_first_run,
    }

def resolve_saved_state_hashes(current_hash: str, saved_raw_hash, saved_cleaned_hash) -> tuple[str | None, str | None]:
    normalized_raw_hash = saved_raw_hash if isinstance(saved_raw_hash, str) and saved_raw_hash else None
    normalized_cleaned_hash = saved_cleaned_hash if isinstance(saved_cleaned_hash, str) and saved_cleaned_hash else None

    if normalized_cleaned_hash and current_hash == normalized_cleaned_hash:
        return None, normalized_cleaned_hash

    if normalized_raw_hash and current_hash == normalized_raw_hash:
        return normalized_raw_hash, None

    return current_hash, None

def find_keyword_match_line_indices(lines: list[str], query: str) -> list[int]:
    normalized_query = query.strip().lower()
    if not normalized_query:
        return []

    return [
        index
        for index, line in enumerate(lines)
        if line.strip() and not _is_comment_line(line.strip()) and normalized_query in line.lower()
    ]

def remove_lines_by_indices(lines: list[str], line_indices: set[int]) -> list[str]:
    return [line for index, line in enumerate(lines) if index not in line_indices]

def summarize_clean_changes(total_discarded: int, transformed: int) -> str:
    if total_discarded > 0 and transformed > 0:
        return f"Removed {total_discarded} entries and normalized {transformed} line(s)."
    if total_discarded > 0:
        return f"Removed {total_discarded} entries."
    if transformed > 0:
        return f"Normalized {transformed} line(s)."
    return "No normalization changes were needed."

def count_nonempty_lines(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip())


def rewrite_block_sink_ip(lines: list[str], target_ip: str) -> tuple[list[str], int]:
    """Rewrite loopback-style mapping IPs to ``target_ip``.

    Only touches lines that already start with a recognized blocking-sink IP
    (``BLOCK_SINK_IPS``). Custom-IP mappings like ``192.168.1.10 nas`` are
    untouched so LAN aliases survive the conversion. Returns the new line
    list and the number of lines that actually changed.
    """
    if target_ip not in BLOCK_SINK_IPS:
        raise ValueError(f"Unsupported target IP: {target_ip!r}")

    changed = 0
    new_lines: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        leading_ws = line[: len(line) - len(stripped)]
        if not stripped or _is_comment_line(stripped):
            new_lines.append(line)
            continue

        content, sep, trailing_comment = stripped.partition('#')
        tokens = content.split(None, 1)
        if len(tokens) < 2:
            new_lines.append(line)
            continue

        first_ip = tokens[0].lower() if ':' in tokens[0] else tokens[0]
        if first_ip not in BLOCK_SINK_IPS or first_ip == target_ip:
            new_lines.append(line)
            continue

        remainder = tokens[1]
        rebuilt = f"{target_ip} {remainder}"
        if sep:
            rebuilt = f"{rebuilt} #{trailing_comment}".rstrip() if trailing_comment.strip() else f"{rebuilt} #"
        new_lines.append(f"{leading_ws}{rebuilt}")
        changed += 1

    return new_lines, changed


def scan_suspicious_redirects(lines: list[str]) -> list[tuple[int, str, str]]:
    """Flag entries that map well-known domains to non-loopback IPs.

    A hosts file with an entry like ``1.2.3.4 www.google.com`` is a classic
    malware-or-hijack indicator: the attacker steers traffic to a server
    they control. We return ``(line_index, ip, domain)`` for every mapping
    whose IP is NOT a loopback/blocking sink and NOT a private LAN range
    (those are intentional local aliases that we must not false-flag).
    """
    private_prefixes = ("10.", "172.", "192.168.", "127.", "169.254.", "0.0.0.0")
    findings: list[tuple[int, str, str]] = []

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or _is_comment_line(stripped):
            continue

        content = stripped.split('#', 1)[0].strip()
        tokens = [token for token in TOKEN_SPLITTER.split(content) if token]
        if len(tokens) < 2:
            continue

        ip_token = tokens[0]
        if not _looks_like_ip_token(ip_token):
            continue

        ip_lower = ip_token.lower() if ':' in ip_token else ip_token
        if ip_lower in BLOCK_SINK_IPS:
            continue

        if ip_token.startswith(private_prefixes):
            # 172.16.0.0/12 is the classic RFC1918 block, but we can't tell
            # from a prefix alone — treat the full 172.x as private-ish to
            # avoid false positives on home LAN mappings.
            if ip_token.startswith("172."):
                try:
                    second = int(ip_token.split('.')[1])
                    if 16 <= second <= 31:
                        continue
                except (IndexError, ValueError):
                    pass
            else:
                continue

        for token in tokens[1:]:
            domain, _ = _extract_domain_from_token(token, allow_single_label=False)
            if domain:
                findings.append((idx, ip_token, domain))

    return findings


def find_sources_containing_domain(domain: str, source_corpus: dict[str, str]) -> list[str]:
    """Return the names of sources whose corpus contains ``domain``.

    ``source_corpus`` maps a display name to the raw text of a previously
    fetched blocklist. Match is exact-suffix (``example.com`` also matches
    ``sub.example.com``) so that aggregate lists surface correctly.
    """
    target = domain.strip().lower().lstrip('.')
    if not target:
        return []

    matches: list[str] = []
    for name, text in source_corpus.items():
        if not text:
            continue
        lowered = text.lower()
        # Fast-path substring check first; confirm with a word-boundary
        # pass so we don't hit "notexample.com" when searching "example.com".
        if target not in lowered:
            continue
        needle = re.compile(
            rf'(?:^|[\s\t,/|^=])(?:\*\.)?(?:[a-z0-9][a-z0-9-]*\.)*{re.escape(target)}(?:$|[\s\t,/|^#$])',
            re.IGNORECASE | re.MULTILINE,
        )
        if needle.search(text):
            matches.append(name)
    return matches


def export_lines_as_format(lines: list[str], export_format: str) -> str:
    """Convert cleaned hosts lines to one of the supported export formats.

    Supported formats:
        hosts       — as-is hosts file content (what Cleaned Save writes)
        domains     — one domain per line, no IP
        adblock     — ``||domain^`` uBlock/AdGuard syntax
        dnsmasq     — ``address=/domain/0.0.0.0``
        pihole      — pi-hole gravity-style plain domain list (same as domains)
    """
    export_format = (export_format or "").strip().lower()
    if export_format == "hosts":
        return '\n'.join(lines)

    domains: list[str] = []
    seen: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or _is_comment_line(stripped):
            continue
        parsed, _ = parse_hosts_line_entries(line)
        for _, domain, is_block_entry in parsed:
            if not is_block_entry:
                continue
            if domain in seen:
                continue
            seen.add(domain)
            domains.append(domain)

    if export_format in ("domains", "pihole"):
        return '\n'.join(domains)
    if export_format == "adblock":
        return '\n'.join(f"||{domain}^" for domain in domains)
    if export_format == "dnsmasq":
        return '\n'.join(f"address=/{domain}/0.0.0.0" for domain in domains)
    raise ValueError(f"Unknown export format: {export_format!r}")


STOCK_MICROSOFT_HOSTS = (
    "# Copyright (c) 1993-2009 Microsoft Corp.\n"
    "#\n"
    "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n"
    "#\n"
    "# This file contains the mappings of IP addresses to host names. Each\n"
    "# entry should be kept on an individual line. The IP address should\n"
    "# be placed in the first column followed by the corresponding host name.\n"
    "# The IP address and the host name should be separated by at least one\n"
    "# space.\n"
    "#\n"
    "# Additionally, comments (such as these) may be inserted on individual\n"
    "# lines or following the machine name denoted by a '#' symbol.\n"
    "#\n"
    "# For example:\n"
    "#\n"
    "#      102.54.94.97     rhino.acme.com          # source server\n"
    "#       38.25.63.10     x.acme.com              # x client host\n"
    "\n"
    "# localhost name resolution is handled within DNS itself.\n"
    "#\t127.0.0.1       localhost\n"
    "#\t::1             localhost\n"
)


def strip_lines_by_category(
    lines: list[str],
    drop_comments: bool = False,
    drop_blanks: bool = False,
    drop_invalid: bool = False,
) -> tuple[list[str], dict[str, int]]:
    """Return ``lines`` with selected noise categories removed, plus counts.

    Unlike the full Cleaned Save, this is surgical — the caller picks which
    category to remove and nothing else. Normalization and deduplication are
    intentionally skipped. Returned stats:
        ``{"removed_comments": int, "removed_blanks": int, "removed_invalid": int}``
    An "invalid" line is anything that isn't a comment, isn't blank, and
    produces zero parsed hosts entries.
    """
    kept: list[str] = []
    stats = {"removed_comments": 0, "removed_blanks": 0, "removed_invalid": 0}
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if drop_blanks:
                stats["removed_blanks"] += 1
                continue
            kept.append(line)
            continue
        if _is_comment_line(stripped):
            if drop_comments:
                stats["removed_comments"] += 1
                continue
            kept.append(line)
            continue
        if drop_invalid:
            parsed, _ = parse_hosts_line_entries(line)
            if not parsed:
                stats["removed_invalid"] += 1
                continue
        kept.append(line)
    return kept, stats


IMPORT_START_RE = re.compile(
    r'^#\s*---\s*(Raw|Normalized)\s+Import\s+Start:\s*(.+?)\s*---\s*$',
    re.IGNORECASE,
)
IMPORT_END_RE = re.compile(
    r'^#\s*---\s*(Raw|Normalized)\s+Import\s+End:\s*(.+?)\s*---\s*$',
    re.IGNORECASE,
)


def summarize_source_contributions(lines: list[str]) -> list[dict]:
    """Report per-import-section contribution stats.

    For every `# --- Start/End ---` marker pair in ``lines``, tally how many
    lines are inside the block and how many of those are blocking entries.
    Lines outside any marker are collected under a synthetic "(outside
    imports)" entry so the editor's manual edits and pre-existing hosts
    entries are still visible. Used by the Sources Report dialog.
    """
    sections_info = discover_import_sections(lines)
    buckets: list[dict] = []
    covered: set[int] = set()

    for section in sections_info:
        inside = lines[section["start"] + 1 : section["end"]]
        block_count = 0
        total = len(inside)
        for line in inside:
            parsed, _ = parse_hosts_line_entries(line)
            if any(entry[2] for entry in parsed):
                block_count += 1
        buckets.append({
            "name": f"{section['name']} [{section['mode']}]",
            "total_lines": total,
            "blocking_entries": block_count,
            "start": section["start"],
            "end": section["end"],
        })
        covered.update(range(section["start"], section["end"] + 1))

    outside_lines = [line for idx, line in enumerate(lines) if idx not in covered]
    outside_block_count = 0
    outside_total = 0
    for line in outside_lines:
        stripped = line.strip()
        if not stripped or _is_comment_line(stripped):
            continue
        outside_total += 1
        parsed, _ = parse_hosts_line_entries(line)
        if any(entry[2] for entry in parsed):
            outside_block_count += 1

    if outside_total:
        buckets.insert(0, {
            "name": "(outside imports / manual edits)",
            "total_lines": outside_total,
            "blocking_entries": outside_block_count,
            "start": None,
            "end": None,
        })

    buckets.sort(key=lambda b: b["blocking_entries"], reverse=True)
    return buckets


def fuzzy_score(query: str, target: str) -> int:
    """Score a target string against a query, higher = better match.

    Ordered-subsequence scorer — every query character must appear in the
    target in order. Consecutive matches and matches at word boundaries are
    weighted higher. Returns -1 on no match.
    """
    if not query:
        return 0
    q = query.lower()
    t = target.lower()
    score = 0
    qi = 0
    prev_matched = False
    for ti, ch in enumerate(t):
        if qi < len(q) and ch == q[qi]:
            bonus = 3 if ti == 0 or not t[ti - 1].isalnum() else 1
            if prev_matched:
                bonus += 2
            score += bonus
            qi += 1
            prev_matched = True
        else:
            prev_matched = False
    if qi < len(q):
        return -1
    return score


def discover_import_sections(lines: list[str]) -> list[dict]:
    """Locate every ``# --- {Raw|Normalized} Import Start/End: NAME ---`` block.

    Returns a list of ``{"name", "mode", "start", "end"}`` (inclusive indices).
    Unmatched start markers are skipped silently so a malformed editor can't
    crash the UI — the caller just won't see that block as a whole section.
    """
    sections: list[dict] = []
    pending: dict | None = None
    for idx, line in enumerate(lines):
        start_match = IMPORT_START_RE.match(line.rstrip())
        if start_match:
            pending = {
                "name": start_match.group(2).strip(),
                "mode": start_match.group(1).strip(),
                "start": idx,
            }
            continue
        if pending is None:
            continue
        end_match = IMPORT_END_RE.match(line.rstrip())
        if end_match and end_match.group(2).strip() == pending["name"]:
            pending["end"] = idx
            sections.append(pending)
            pending = None
    return sections


def remove_import_section(lines: list[str], section: dict) -> list[str]:
    """Delete an entire import block including its Start/End markers."""
    start = section.get("start", -1)
    end = section.get("end", -1)
    if start < 0 or end < start or end >= len(lines):
        return list(lines)
    return lines[:start] + lines[end + 1 :]


def format_relative_time(iso_timestamp: str, now: float | None = None) -> str:
    """Render an ISO 8601 timestamp as a short relative string.

    Used in source tooltips to show "Last fetched: 3 hours ago" without
    requiring the user to parse a timestamp. Returns an empty string on
    invalid input so callers can short-circuit cleanly. ``now`` is a unix
    epoch override exposed so tests can pin the reference point.
    """
    if not iso_timestamp:
        return ""
    try:
        when = datetime.datetime.fromisoformat(iso_timestamp)
    except (TypeError, ValueError):
        return ""

    if now is not None:
        reference = datetime.datetime.fromtimestamp(now, when.tzinfo) if when.tzinfo else datetime.datetime.fromtimestamp(now)
    else:
        reference = datetime.datetime.now(when.tzinfo) if when.tzinfo else datetime.datetime.now()
    delta_seconds = (reference - when).total_seconds()
    if delta_seconds < 0:
        return "just now"
    if delta_seconds < 60:
        return "just now"
    if delta_seconds < 3600:
        minutes = int(delta_seconds // 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    if delta_seconds < 86400:
        hours = int(delta_seconds // 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    if delta_seconds < 86400 * 30:
        days = int(delta_seconds // 86400)
        return f"{days} day{'s' if days != 1 else ''} ago"
    if delta_seconds < 86400 * 365:
        months = int(delta_seconds // (86400 * 30))
        return f"{months} month{'s' if months != 1 else ''} ago"
    years = int(delta_seconds // (86400 * 365))
    return f"{years} year{'s' if years != 1 else ''} ago"

# -------------------------------- Main App -----------------------------------
class HostsFileEditor:
    HOSTS_FILE_PATH = _default_hosts_file_path()
    CONFIG_FILENAME = "hosts_editor_config.json"
    
    SIDEBAR_WIDTH = 420

    # Extended Blocklist Definitions
    BLOCKLIST_SOURCES = {
        "Major / Unified / Aggregated": [
            ("HaGezi Ultimate", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/ultimate.txt", "Ultimate protection. Very aggressive."),
            ("HaGezi Pro Plus", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt", "Aggressive HaGezi Pro with extra telemetry/metrics blocking."),
            ("HaGezi Pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt", "Balanced HaGezi tier: ads + tracking + metrics."),
            ("HaGezi Multi", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt", "HaGezi Multi Pro+ + TIF + threat-intel rollup."),
            ("HaGezi Light", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/light.txt", "HaGezi false-positive-free starter list."),
            ("HaGezi TIF", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/tif.txt", "Threat Intelligence Feeds only."),
            ("1Hosts Lite", "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt", "badmojr conservative ads + tracking."),
            ("1Hosts Pro", "https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/hosts.txt", "badmojr balanced ads/tracking/metrics."),
            ("1Hosts Xtra", "https://raw.githubusercontent.com/badmojr/1Hosts/master/Xtra/hosts.txt", "badmojr maximum-coverage tier; breakage risk."),
            ("hBlock Aggregate", "https://hblock.molinero.dev/hosts", "Auto-aggregated 50+ upstream sources, daily rebuild."),
            ("Ultimate Hosts Blacklist", "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts0", "Mega-aggregate over 100 ads/malware/tracking lists."),
            ("BlockConvert Aggregate", "https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.txt", "Cross-validated aggregate of mainstream blocklists."),
            ("StevenBlack Unified", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "Classic unified hosts list."),
            ("StevenBlack Data", "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts", "StevenBlack Data Base."),
            ("OISD Full", "https://hosts.oisd.nl/", "Huge, false-positive free blocklist."),
            ("OISD DBL", "https://dbl.oisd.nl/", "OISD Domain Blocklist."),
            ("MVPS Hosts", "https://winhelp2002.mvps.org/hosts.txt", "Long-standing Windows hosts file."),
            ("SomeoneWhoCares Zero", "https://someonewhocares.org/hosts/zero/hosts", "Classic zero-based hosts file."),
            ("SomeoneWhoCares 127", "https://someonewhocares.org/hosts/hosts", "Classic 127.0.0.1 hosts file."),
            ("HOSTShield Combined", "https://github.com/SysAdminDoc/HOSTShield/releases/download/v.1/CombinedAll.txt", "Massive combined list."),
            ("The Great Wall", "https://raw.githubusercontent.com/Sekhan/TheGreatWall/master/TheGreatWall.txt", "Comprehensive aggregator."),
            ("NeoHosts Basic", "https://cdn.jsdelivr.net/gh/neoFelhz/neohosts@gh-pages/basic/hosts", "NeoHosts Basic List."),
            ("NeoDev Host", "https://raw.githubusercontent.com/neodevpro/neodevhost/master/host", "Actively maintained ads + tracker + malware aggregate."),
        ],
        "Ads / Tracking / Analytics": [
            ("Disconnect Tracking", "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt", "Basic tracking protection."),
            ("Disconnect Ads", "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt", "Basic ad protection."),
            ("DevDan Ads & Tracking", "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt", "Extended protection."),
            ("EasyList Hosts", "https://v.firebog.net/hosts/Easylist.txt", "AdBlock EasyList converted to hosts."),
            ("EasyPrivacy Hosts", "https://v.firebog.net/hosts/Easyprivacy.txt", "AdBlock EasyPrivacy converted to hosts."),
            ("EasyList Privacy Orig", "https://easylist.to/easylist/easyprivacy.txt", "Original EasyPrivacy."),
            ("EasyList NoElemHide", "https://easylist-downloads.adblockplus.org/easylist_noelemhide.txt", "EasyList without element hiding."),
            ("Prigent Ads", "https://v.firebog.net/hosts/Prigent-Ads.txt", "Ads & trackers list."),
            ("W3KBL", "https://v.firebog.net/hosts/static/w3kbl.txt", "Adblock list."),
            ("Yoyo Ad Servers (Plain)", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", "Classic ad server list."),
            ("Yoyo Ad Servers (NoHTML)", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml", "Yoyo No HTML format."),
            ("Anudeep Ad Servers", "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt", "Anudeep's ad server list."),
            ("AdAway", "https://adaway.org/hosts.txt", "Mobile ad blocker hosts."),
            ("AdGuard DNS", "https://v.firebog.net/hosts/AdguardDNS.txt", "AdGuard DNS filter."),
            ("Admiral Anti-Adblock", "https://v.firebog.net/hosts/Admiral.txt", "Blocks anti-adblock scripts."),
            ("YouTube Ads Blacklist", "https://raw.githubusercontent.com/anudeepND/youtubeadsblacklist/master/domainlist.txt", "Attempts to block YT ads."),
            ("JDlingyu Ad Wars", "https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts", "Comprehensive Chinese ad blocklist."),
            ("Yhonay Antipopads", "https://raw.githubusercontent.com/Yhonay/antipopads/master/hosts", "Pop-up ads blocker."),
            ("Hoshsadiq NoCoin", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", "Adblock plus NoCoin."),
            ("HOSTShield Ads", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/AdsTrackingAnalytics.txt", "HOSTShield Ads & Tracking."),
            ("Adobe Hosts", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/AdobeHosts.txt", "Blocks Adobe verification."),
            ("ShadowWhisperer Ads", "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Ads", "Hand-audited ad domains, very low false positives."),
            ("ShadowWhisperer Tracking", "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking", "Hand-audited tracker/analytics list."),
            ("Lightswitch05 AMP Extended", "https://www.github.developerdan.com/hosts/lists/amp-hosts-extended.txt", "Google AMP cache / proxy URL blocklist."),
            ("Lightswitch05 FB Extended", "https://www.github.developerdan.com/hosts/lists/facebook-extended.txt", "Extended Meta/Instagram/WhatsApp tracking."),
            ("Lightswitch05 Tracking Aggressive", "https://www.github.developerdan.com/hosts/lists/tracking-aggressive-extended.txt", "Aggressive tracker list beyond the default extended."),
            ("GoodbyeAds", "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt", "Mobile ads + YouTube/Spotify/Hulu ad sponsors."),
            ("AdGuard Mobile Ads (r-a-y)", "https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardMobileAds.txt", "AdGuard mobile ad filter in hosts format."),
            ("AdGuard Mobile Spyware (r-a-y)", "https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardMobileSpyware.txt", "AdGuard mobile spyware filter in hosts format."),
            ("CombinedPrivacyBlockLists", "https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/NoFormatting/cpbl-ctld.txt", "Curated combined privacy aggregate, cross-TLD-checked."),
            ("MobileAdTrackers (jawz101)", "https://raw.githubusercontent.com/jawz101/MobileAdTrackers/master/hosts", "Mobile SDK trackers from Exodus Privacy reports."),
            ("DandelionSprout URL Shorteners", "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt", "URL shortener neutralizer to kill redirect tracking."),
            ("BlocklistProject Tracking", "https://blocklistproject.github.io/Lists/tracking.txt", "Community-maintained tracking domain list."),
        ],
        "Telemetry / Privacy / Spyware": [
            ("Windows Spy Blocker", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", "Blocks Windows telemetry."),
            ("Windows Spy Extra", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/extra.txt", "WindowsSpyBlocker extra telemetry beyond the core spy list."),
            ("Windows Spy Update", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/update.txt", "Windows Update / delivery-optimization telemetry."),
            ("jmdugan Microsoft", "https://raw.githubusercontent.com/jmdugan/blocklists/master/corporations/microsoft/all", "Broad Microsoft corporate telemetry + services."),
            ("jmdugan Facebook", "https://raw.githubusercontent.com/jmdugan/blocklists/master/corporations/facebook/all", "Meta/Facebook corporate domain blocklist."),
            ("Frogeye 1st Party", "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt", "First-party trackers."),
            ("Frogeye Multi Party", "https://hostfiles.frogeye.fr/multiparty-trackers-hosts.txt", "Multi-party trackers."),
            ("Matomo Referrer Spam", "https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt", "Referrer spam blockers."),
            ("Piwik Referrer Spam", "https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt", "Piwik spam blockers."),
            ("NoTrack Tracking", "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt", "NoTrack tracking list."),
            ("Perflyst Android", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt", "Android tracking."),
            ("Perflyst SmartTV", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt", "Smart TV tracking."),
            ("Perflyst FireTV", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt", "FireTV tracking."),
            ("Perflyst Session Replay", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SessionReplay.txt", "Session-replay/heatmap vendors (Hotjar, FullStory)."),
            ("TrackersList All", "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt", "Torrent trackers list."),
        ],
        "Malware / Phishing / Scam": [
            ("MalwareDomains", "https://mirror1.malwaredomains.com/files/justdomains", "Known malware domains."),
            ("NoTrack Malware", "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt", "NoTrack malware list."),
            ("Spam404", "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt", "Spam and scam sites."),
            ("DandelionSprout Anti-Mal", "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt", "Anti-malware hosts."),
            ("Prigent Malware", "https://v.firebog.net/hosts/Prigent-Malware.txt", "Malware list."),
            ("Prigent Crypto", "https://v.firebog.net/hosts/Prigent-Crypto.txt", "Crypto mining domains."),
            ("RPiList Malware", "https://v.firebog.net/hosts/RPiList-Malware.txt", "Raspberry Pi list malware."),
            ("RPiList Phishing", "https://v.firebog.net/hosts/RPiList-Phishing.txt", "Raspberry Pi list phishing."),
            ("Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt", "Phishing Army."),
            ("URLHaus Malware", "https://urlhaus.abuse.ch/downloads/hostfile/", "Abuse.ch malware."),
            ("CyberHost Malware", "https://lists.cyberhost.uk/malware.txt", "CyberHost malware."),
            ("Malware Filter Phishing", "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt", "Phishing filter."),
            ("Scam Domains Wildcard", "https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/wildcard_domains/scams.txt", "Scam domains."),
            ("PhishTank Domains", "https://raw.githubusercontent.com/tg12/pihole-phishtank-list/master/list/phish_domains.txt", "PhishTank data."),
            ("PhishTank Data (CSV)", "https://data.phishtank.com/data/online-valid.csv.bz2", "Official PhishTank CSV (Requires Processing)."),
            ("DigitalSide Threat Intel", "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt", "OSINT threat intelligence."),
            ("VXVault", "http://vxvault.net/URL_List.php", "VX Vault URL List."),
            ("CyberCrime Tracker", "https://cybercrime-tracker.net/all.php", "CyberCrime Tracker."),
            ("BBCan177 Feed", "https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw", "Threat intel feed."),
            ("OpenPhish", "https://openphish.com/feed.txt", "OpenPhish feed."),
            ("BarbBlock", "https://paulgb.github.io/BarbBlock/blacklists/hosts-file.txt", "BarbBlock hosts."),
            ("Bambenek DoH", "https://raw.githubusercontent.com/bambenek/block-doh/master/doh-hosts.txt", "DoH servers."),
            ("MinerChk", "https://raw.githubusercontent.com/Hestat/minerchk/master/hostslist.txt", "Crypto miner check."),
            ("Badd Boyz", "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts", "Bad domains."),
            ("Stamparm Maltrail", "https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt", "Maltrail malware."),
            ("Stamparm Blackbook", "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt", "Blackbook."),
            ("Disconnect Malvertising", "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt", "Disconnect Malvertising."),
            ("Disconnect Malware", "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt", "Disconnect Malware."),
            ("AntiSocial Engineer", "https://theantisocialengineer.com/AntiSocial_Blacklist_Community_V1.txt", "Social engineering blocklist."),
            ("Botvrij IOC", "https://www.botvrij.eu/data/ioclist.domain.raw", "Botvrij IoCs."),
            ("JoeWein Domains", "https://www.joewein.net/dl/bl/dom-bl.txt", "JoeWein spam/scam."),
            ("JoeWein Base", "https://www.joewein.net/dl/bl/dom-bl-base.txt", "JoeWein base."),
            ("Toxic Domains", "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt", "StopForumSpam toxic."),
            ("ShadowWhisperer Malware", "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware", "Hand-audited malware domain list."),
            ("ShadowWhisperer Scam", "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Scam", "Curated scam / fraud domain list."),
            ("ThreatFox abuse.ch", "https://threatfox.abuse.ch/downloads/hostfile/", "abuse.ch live malware IOC feed in hosts format."),
            ("CERT.pl Warning List", "https://hole.cert.pl/domains/domains_hosts.txt", "Polish national CERT phishing feed (EU-focused)."),
            ("Phishing Army Extended", "https://phishing.army/download/phishing_army_blocklist_extended.txt", "Extended Phishing Army feed (adds recent hits)."),
            ("Durable Napkin Scam", "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt", "Curated scam / tech-support / fake-shop blocklist."),
            ("GlobalAntiScamOrg", "https://raw.githubusercontent.com/elliotwutingfeng/GlobalAntiScamOrg-blocklist/main/global-anti-scam-org-scam-urls-pihole.txt", "Global Anti-Scam Org reports reformatted for Pi-hole."),
            ("Inversion DNS Blocklist", "https://raw.githubusercontent.com/elliotwutingfeng/inversion-dnsblocklist/main/inversion-dnsblocklist-pihole.txt", "Crowd-sourced active-phish domain feed."),
            ("Curbengh Phishing Filter", "https://raw.githubusercontent.com/curbengh/phishing-filter/master/phishing-filter-hosts.txt", "Aggregated phishing feed (OpenPhish, PhishTank, etc)."),
            ("CoinBlockerLists", "https://raw.githubusercontent.com/ZeroDot1/CoinBlockerLists/master/hosts", "ZeroDot1 comprehensive cryptominer hosts."),
            ("CoinBlockerLists Browser", "https://raw.githubusercontent.com/ZeroDot1/CoinBlockerLists/master/hosts_browser", "In-browser-mining subset from CoinBlockerLists."),
            ("BlocklistProject Fraud", "https://blocklistproject.github.io/Lists/fraud.txt", "Fraud / scam-focused subset."),
            ("BlocklistProject Ransomware", "https://blocklistproject.github.io/Lists/ransomware.txt", "Ransomware C2 / dropper domains."),
        ],
        "Spam / Abuse / Misc": [
            ("KAD Hosts (Polish)", "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt", "Polish focused filters."),
            ("KAD Hosts (Azet12)", "https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt", "Alternative KADHosts mirror."),
            ("MajkiIT Polish Adservers", "https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/hosts-based-list/adservers.txt", "Polish ad-server hosts list."),
            ("Cats-Team AdRules (CN)", "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules_domainset.txt", "Chinese-language ads / tracker aggregate."),
            ("Schakal (Russian)", "https://schakal.ru/hosts/hosts_adblock.txt", "Russian ad / tracker block list."),
            ("FadeMind Spam", "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts", "Spam hosts."),
            ("FadeMind Risk", "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts", "Risky hosts."),
            ("FadeMind Unchecky", "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts", "Unchecky ads."),
            ("FadeMind 2o7", "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts", "Adobe analytics."),
            ("BigDargon Hosts VN", "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts", "Vietnamese hosts."),
            ("SNAFU Blocklist", "https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt", "Misc blocklist."),
            ("Public Stun", "http://enumer.org/public-stun.txt", "Public STUN servers."),
            ("Fritzbox List", "https://list.kwbt.de/fritzboxliste.txt", "Fritzbox specific."),
            ("OneOffDallas DoH", "https://raw.githubusercontent.com/oneoffdallas/dohservers/master/list.txt", "DoH servers."),
            ("Dawsey21 Blacklist", "https://raw.githubusercontent.com/Dawsey21/Lists/master/main-blacklist.txt", "General blacklist."),
            ("Vokins YHosts", "https://raw.githubusercontent.com/vokins/yhosts/master/hosts.txt", "YHosts."),
        ],
        "Category Filters (Opt-in)": [
            ("BlocklistProject Gambling", "https://blocklistproject.github.io/Lists/gambling.txt", "Online gambling / casino / sportsbook domains."),
            ("BlocklistProject Porn", "https://blocklistproject.github.io/Lists/porn.txt", "Adult content top-1M style blocklist."),
            ("Sinfonietta Pornography", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts", "Curated adult-content hosts, broad coverage."),
            ("Sinfonietta Social", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/social-hosts", "Social media domain list (opt-in distraction blocking)."),
            ("Sinfonietta Gambling", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/gambling-hosts", "Curated gambling hosts (smaller alternative)."),
            ("Tiuxo Porn", "https://raw.githubusercontent.com/tiuxo/hosts/master/porn", "Minimal adult-content hosts list."),
            ("Tiuxo Social", "https://raw.githubusercontent.com/tiuxo/hosts/master/social", "Minimal social-media hosts list."),
            ("RPiList Gambling", "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Gambling.txt", "German-maintained gambling blocklist, EU coverage."),
            ("RPiList Fake Science", "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Fake-Science.txt", "Predatory journals / junk-science publishers."),
        ],
        "Vendor / Platform": [
            ("Amazon Native", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.amazon.txt", "Block Amazon devices telemetry."),
            ("Apple Native", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.apple.txt", "Block Apple devices telemetry."),
            ("Huawei Native", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.huawei.txt", "Block Huawei devices telemetry."),
            ("Windows Office Native", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.winoffice.txt", "Block MS Office telemetry."),
            ("Samsung Native", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.samsung.txt", "Block Samsung devices telemetry."),
            ("TikTok Native", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.tiktok.txt", "Block TikTok."),
            ("TikTok Native Ext", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.tiktok.extended.txt", "Block TikTok (Extended)."),
            ("LG WebOS Native", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.lgwebos.txt", "Block LG TV telemetry."),
            ("Roku Native", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.roku.txt", "Block Roku telemetry."),
            ("Vivo Native", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.vivo.txt", "Block Vivo telemetry."),
            ("Oppo / Realme Native", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.oppo-realme.txt", "Block Oppo/Realme telemetry."),
            ("Xiaomi Native", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.xiaomi.txt", "Block Xiaomi telemetry."),
            ("HOSTShield Apple", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Apple.txt", "HOSTShield Apple."),
            ("HOSTShield Brave", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Brave.txt", "HOSTShield Brave."),
            ("HOSTShield Microsoft", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Microsoft.txt", "HOSTShield Microsoft."),
            ("HOSTShield TikTok", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Tiktok.txt", "HOSTShield TikTok."),
            ("HOSTShield Twitter", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Twitter.txt", "HOSTShield Twitter."),
            ("Perflyst Vivo Telemetry", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/Vivotelemetry.txt", "Vivo / BBK Android phone telemetry."),
            ("Perflyst Samsung Smart", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SamsungSmart.txt", "Samsung Smart TV / Tizen telemetry & ads."),
            ("llacb47 Smart TV", "https://raw.githubusercontent.com/llacb47/mischosts/main/smart-tv", "Generic smart-TV telemetry (Sony/Philips/Panasonic/Vizio)."),
            ("llacb47 LG WebOS", "https://raw.githubusercontent.com/llacb47/mischosts/main/lgwebos-hosts", "LG WebOS smart-TV telemetry supplement."),
            ("llacb47 Disney", "https://raw.githubusercontent.com/llacb47/mischosts/main/disney-hosts", "Disney+ / ESPN / Hulu tracker + ad infrastructure."),
        ]
    }

    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.configure(bg=PALETTE["base"])
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self._icon_image = None
        self._apply_window_branding()

        self.default_font = font.Font(family="Segoe UI", size=10)
        self.title_font = font.Font(family="Segoe UI", size=11, weight="bold")
        self.custom_sources = []
        self._custom_source_widgets = {} 
        
        # Threading & Import State
        self.import_queue = queue.Queue()
        self.is_importing = False
        self.stop_import_flag = threading.Event()
        self.current_import_thread = None
        self.import_action_widgets = []

        # --- State Tracking ---
        self.is_admin = False 
        self._last_applied_raw_hash = None
        self._last_applied_cleaned_hash = None
        self._suppress_modified_handler = False
        self._update_ui_job = None
        self._source_filter_job = None
        self._status_reset_job = None
        self._last_saved_whitelist_text = ""
        self._cached_whitelist_text = None
        self._cached_whitelist_set = frozenset()
        self.config_path = get_primary_config_path(self.CONFIG_FILENAME)
        self.last_open_dir = os.path.expanduser("~")

        # Per-session cache of raw source text (keyed by display name) used
        # by the "Check Domain" cross-reference so the user can ask which
        # curated sources contain a given domain without re-fetching.
        # Capped per entry to keep memory sane on aggregate lists.
        self._source_corpus_cache: dict[str, str] = {}
        # Persisted across sessions: URL → ISO timestamp of last successful
        # fetch. Lets source tooltips surface how stale a feed is.
        self.source_last_fetched: dict[str, str] = {}
        self._preferred_block_sink = "0.0.0.0"
        self._backup_retention = BACKUP_RETENTION
        self._has_completed_first_run = False
        
        self.import_mode = tk.StringVar(value="Normalized") 
        self.dry_run_mode = tk.BooleanVar(value=False)
        self.dry_run_mode.trace_add('write', lambda *args: self._check_dry_run_warning()) 
        self.source_filter_var = tk.StringVar()
        self.source_filter_var.trace_add('write', lambda *args: self._on_source_filter_changed())

        self._init_styles()
        self._init_menubar()
        
        # 1. Initialize Status Bar FIRST
        self.default_status_hint = "Ctrl+S Save Cleaned   Ctrl+Shift+S Save Raw   F5 Reload"
        status_frame = ttk.Frame(root, padding=(10, 6, 10, 10))
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = ttk.Label(status_frame, text="Loading...", font=self.default_font, foreground=PALETTE["subtext"])
        self.status_label.pack(side=tk.LEFT)
        self.status_hint_label = ttk.Label(
            status_frame,
            text=self.default_status_hint,
            style="StatusMeta.TLabel"
        )
        self.status_hint_label.pack(side=tk.LEFT, padx=(18, 0))
        
        # Progress Bar
        self.progress_bar = ttk.Progressbar(status_frame, orient="horizontal", mode="determinate", length=300)
        self.progress_bar.pack(side=tk.RIGHT, padx=10)
        self.progress_bar.pack_forget() # Hide initially
        
        self.stop_btn = ttk.Button(status_frame, text="Stop Import", command=self.cancel_import, style="Remove.TButton")
        self.stop_btn.pack(side=tk.RIGHT, padx=5)
        self.stop_btn.pack_forget() # Hide initially

        
        # 2. Run Admin Check & Relaunch Logic
        if not self.check_admin_privileges():
             sys.exit()

        # Root layout: Sidebar (fixed width) + Editor
        root_container = ttk.Frame(root, padding=8)
        root_container.pack(fill="both", expand=True)

        # Sidebar setup
        sidebar_outer = ttk.Frame(root_container)
        sidebar_outer.pack(side="left", fill="y")
        sidebar_outer.configure(width=self.SIDEBAR_WIDTH)
        sidebar_outer.pack_propagate(False)

        sidebar_canvas = tk.Canvas(sidebar_outer, bg=PALETTE["mantle"], highlightthickness=0, bd=0, relief="flat", yscrollincrement=10)
        sidebar_vscroll = ttk.Scrollbar(sidebar_outer, orient="vertical", command=sidebar_canvas.yview)
        self.sidebar_inner = ttk.Frame(sidebar_canvas, padding=(0, 0, 10, 0)) 
        self.sidebar_inner.bind(
            "<Configure>",
            lambda e: sidebar_canvas.configure(scrollregion=sidebar_canvas.bbox("all"))
        )
        def _on_mousewheel(event):
            sidebar_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

        sidebar_canvas.bind("<Enter>", lambda _event: sidebar_canvas.bind_all("<MouseWheel>", _on_mousewheel))
        sidebar_canvas.bind("<Leave>", lambda _event: sidebar_canvas.unbind_all("<MouseWheel>"))
        self.root.bind("<Destroy>", lambda _event: sidebar_canvas.unbind_all("<MouseWheel>"), add="+")

        canvas_width = self.SIDEBAR_WIDTH - sidebar_vscroll.winfo_reqwidth()
        sidebar_canvas.create_window((0, 0), window=self.sidebar_inner, anchor="nw", width=canvas_width)
        sidebar_canvas.configure(yscrollcommand=sidebar_vscroll.set)

        sidebar_canvas.pack(side="left", fill="y", expand=False)
        sidebar_vscroll.pack(side="right", fill="y")
        
        # Right editor area
        right_area = ttk.Frame(root_container, padding=(8, 0, 0, 0))
        right_area.pack(side="left", fill="both", expand=True)

        hero_frame = ttk.Frame(right_area, padding=(18, 16), style="Panel.TFrame")
        hero_frame.pack(fill="x", pady=(0, 8))

        hero_copy = ttk.Frame(hero_frame, style="Panel.TFrame")
        hero_copy.pack(side="left", fill="x", expand=True)
        ttk.Label(hero_copy, text=APP_NAME, font=("Segoe UI Semibold", 20), style="Panel.TLabel").pack(anchor='w')
        ttk.Label(
            hero_copy,
            text="Cleaner imports, safer saves, and live visibility into what will change before you touch the system hosts file.",
            wraplength=760,
            style="PanelMuted.TLabel"
        ).pack(anchor='w', pady=(4, 0))
        ttk.Label(hero_copy, text=self.HOSTS_FILE_PATH, style="PanelSubtle.TLabel").pack(anchor='w', pady=(8, 0))

        hero_badges = ttk.Frame(hero_frame, style="Panel.TFrame")
        hero_badges.pack(side="right", anchor='n', padx=(20, 0))
        self.admin_badge_label = tk.Label(hero_badges, font=("Segoe UI", 9, "bold"), padx=10, pady=5, bd=0)
        self.admin_badge_label.pack(anchor='e', pady=(0, 6))
        self.editor_state_badge_label = tk.Label(hero_badges, font=("Segoe UI", 9, "bold"), padx=10, pady=5, bd=0)
        self.editor_state_badge_label.pack(anchor='e', pady=(0, 6))
        self.mode_badge_label = tk.Label(hero_badges, font=("Segoe UI", 9, "bold"), padx=10, pady=5, bd=0)
        self.mode_badge_label.pack(anchor='e', pady=(0, 6))
        self.dry_run_badge_label = tk.Label(hero_badges, font=("Segoe UI", 9, "bold"), padx=10, pady=5, bd=0)
        self.dry_run_badge_label.pack(anchor='e')

        # --- Sidebar Content Starts Here ---
        
        # File Ops (Top)
        file_ops = ttk.LabelFrame(self.sidebar_inner, text="File Operations")
        file_ops.pack(fill="x", padx=8, pady=(8, 4))
        
        # Dry-Run Toggle
        dry_run_frame = ttk.Frame(file_ops)
        dry_run_frame.pack(fill="x", pady=(0, 4))
        self.chk_dry_run = ttk.Checkbutton(dry_run_frame, text="Dry-run only (NO disk writes)", variable=self.dry_run_mode)
        self.chk_dry_run.pack(side=tk.LEFT, padx=8)
        ToolTip(self.chk_dry_run, "If checked, 'Save Raw' and 'Save Cleaned' perform previews and compute stats but DO NOT write to disk.")

        # Save Buttons (Split)
        save_btns_frame = ttk.Frame(file_ops)
        save_btns_frame.pack(fill="x", pady=4)

        self.btn_save_raw = self._btn(save_btns_frame, "Save Raw", self.save_raw_file, 
                                      "Saves editor content exactly as-is. No cleaning, no filtering.", style="Secondary.TButton")
        self.btn_save_raw.pack(side=tk.LEFT, fill="x", expand=True, padx=(0, 4))

        self.btn_save_cleaned = self._btn(save_btns_frame, "Save Cleaned", self.save_cleaned_file, 
                                          "Applies Whitelist, Normalization, Cleaning, and Deduplication before saving.", style="Action.TButton")
        self.btn_save_cleaned.pack(side=tk.LEFT, fill="x", expand=True, padx=(4, 0))
        ttk.Label(
            file_ops,
            text="Cleaned Save is the safer default. Raw Save writes the editor exactly as shown.",
            style="Hint.TLabel",
            wraplength=360,
            justify="left"
        ).pack(fill="x", padx=8, pady=(0, 8))

        self._btn(file_ops, "Refresh", self.load_file, "Reload hosts file from disk.").pack(fill="x", pady=4)
        self._btn(file_ops, "Revert to Backup", self.revert_to_backup, "Preview and restore from .bak if available.", style="Danger.TButton").pack(fill="x", pady=4)
        
        # Utilities
        utilities_frame = ttk.LabelFrame(self.sidebar_inner, text="Utilities")
        utilities_frame.pack(fill="x", padx=8, pady=4)
        util_row = ttk.Frame(utilities_frame)
        util_row.pack(fill="x", padx=8, pady=(8, 4))
        self._btn(util_row, "Clean", self.auto_clean, "Clean and format hosts file (removes ALL comments/headers).").pack(side="left", expand=True, fill="x", padx=(0, 6))
        self._btn(util_row, "Normalize & Deduplicate", self.deduplicate, "Standardize entries and remove duplicates across the full editor.", style="Action.TButton").pack(side="left", expand=True, fill="x", padx=6)
        self._btn(util_row, "Flush DNS", self.flush_dns, "Flush Windows DNS cache.", style="Accent.TButton").pack(side="left", expand=True, fill="x", padx=(6, 0))

        # --- Emergency DNS Unlock Button ---
        emerg_row = ttk.Frame(utilities_frame)
        emerg_row.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Label(emerg_row, text="Recovery", foreground=PALETTE["red"], font=("Segoe UI", 9, "bold")).pack(anchor='w', pady=(0, 4))
        ttk.Label(
            emerg_row,
            text="Use the recovery path only if Windows is already locked up because of an oversized hosts file.",
            foreground=PALETTE["subtext"],
            wraplength=360
        ).pack(anchor='w', pady=(0, 6))
        self._btn(emerg_row, "Emergency DNS Recovery", self.emergency_dns_stop, 
                  "Brute-force kill DNS Client and reset hosts file to fix CPU lockups.", style="Danger.TButton").pack(fill="x")


        # Search / Filter / Warnings
        search_frame = ttk.LabelFrame(self.sidebar_inner, text="Search / Filter / Warnings")
        search_frame.pack(fill="x", padx=8, pady=4)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(fill="x", padx=8, pady=(8, 4))
        ttk.Label(
            search_frame,
            text="Find a term, step through every hit, or review matched active entries before removing them.",
            style="Hint.TLabel",
            wraplength=360,
            justify="left"
        ).pack(fill="x", padx=8, pady=(0, 6))
        self.search_entry.bind("<Return>", lambda event: self.search_find())
        btns = ttk.Frame(search_frame)
        btns.pack(fill="x", padx=8, pady=(0, 8))
        self._btn(btns, "Find", self.search_find, "Find first match (case-insensitive).").pack(side="left", expand=True, fill="x", padx=(0, 4))
        self._btn(btns, "Prev", self.search_prev, "Find previous match.").pack(side="left", expand=True, fill="x", padx=4)
        self._btn(btns, "Next", self.search_next, "Find next match.").pack(side="left", expand=True, fill="x", padx=4)
        self._btn(btns, "Remove", self.remove_matching_lines, "Remove matching non-comment entries with a selection preview.", style="Danger.TButton").pack(side="left", expand=True, fill="x", padx=4)
        self._btn(btns, "Clear", self.search_clear, "Clear highlights.").pack(side="left", expand=True, fill="x", padx=(4, 0))
        
        self.warning_status_label = ttk.Label(
            search_frame,
            text="Cleaned Save is already aligned. No removals or normalization are pending.",
            style="Hint.TLabel",
            foreground=PALETTE["green"]
        )
        self.warning_status_label.pack(fill="x", padx=8, pady=(4, 8))
        self._btn(search_frame, "Re-scan Warnings", self._trigger_ui_update, "Recompute which lines will be discarded or transformed by Cleaned Save.").pack(fill="x", padx=8, pady=(0, 8))


        # Import Blacklists
        import_frame = ttk.LabelFrame(self.sidebar_inner, text="Import Blacklists")
        import_frame.pack(fill="x", padx=8, pady=4)
        ttk.Label(
            import_frame,
            text="Bring in curated feeds, local logs, or pasted content without leaving the editor.",
            style="Hint.TLabel",
            wraplength=360,
            justify="left"
        ).pack(fill="x", padx=8, pady=(8, 0))
        
        # Import Mode Selector
        mode_frame = ttk.LabelFrame(import_frame, text="Import Mode")
        mode_frame.pack(fill="x", padx=8, pady=(4, 8))
        mode_row = ttk.Frame(mode_frame)
        mode_row.pack(fill="x", padx=8, pady=8)
        
        self.radio_raw = ttk.Radiobutton(mode_row, text="Raw", variable=self.import_mode, value="Raw",
                        command=lambda: self._set_import_mode_status("Raw"))
        self.radio_raw.pack(side=tk.LEFT, padx=15)
        self._register_import_widget(self.radio_raw)
        self.radio_normalized = ttk.Radiobutton(mode_row, text="Normalized", variable=self.import_mode, value="Normalized",
                        command=lambda: self._set_import_mode_status("Normalized"))
        self.radio_normalized.pack(side=tk.LEFT, padx=15)
        self._register_import_widget(self.radio_normalized)
        ttk.Label(
            mode_frame,
            text="Normalized converts domains into standard 0.0.0.0 entries. Raw keeps the original formatting and comments.",
            style="Hint.TLabel",
            wraplength=340,
            justify="left"
        ).pack(fill="x", padx=8, pady=(0, 8))
        
        # --- Import All Lists Button ---
        self.btn_import_all = self._btn(import_frame, "Batch Import from Sources", self.start_import_all, 
                  "Open dialog to select and sequentially download multiple blocklists.", style="Accent.TButton")
        self.btn_import_all.pack(fill="x", padx=8, pady=(4, 8))
        self._register_import_widget(self.btn_import_all)

        # Local Import
        local_import_frame = ttk.LabelFrame(import_frame, text="Import From File")
        local_import_frame.pack(fill="x", padx=8, pady=(8, 4))
        self._register_import_widget(
            self._btn(local_import_frame, "From pfSense Log", self.import_pfsense_log, "Import domains from pfSense DNSBL log.")
        ).pack(fill="x", pady=2)
        self._register_import_widget(
            self._btn(local_import_frame, "From NextDNS Log (CSV)", self.import_nextdns_log, "Import blocked domains from a NextDNS Query Log CSV.")
        ).pack(fill="x", pady=2)

        source_catalog = ttk.LabelFrame(import_frame, text="Source Catalog")
        source_catalog.pack(fill="x", padx=8, pady=4)
        ttk.Label(source_catalog, text="Filter by name, category, or feed URL", style="Hint.TLabel").pack(anchor='w', padx=8, pady=(8, 4))
        self.source_filter_entry = ttk.Entry(source_catalog, textvariable=self.source_filter_var)
        self.source_filter_entry.pack(fill="x", padx=8, pady=(0, 6))
        # Escape clears the filter while focus is inside the entry — quick
        # way to reset back to the full catalog without mouse travel.
        self.source_filter_entry.bind(
            "<Escape>",
            lambda _event: (self.source_filter_var.set(""), "break")[-1],
        )
        self._register_import_widget(self.source_filter_entry)
        self.catalog_summary_label = ttk.Label(source_catalog, text="", style="Hint.TLabel")
        self.catalog_summary_label.pack(anchor='w', padx=8, pady=(0, 6))
        self.web_catalog_frame = ttk.Frame(source_catalog)
        self.web_catalog_frame.pack(fill="x", padx=8, pady=(0, 8))
        self._populate_blocklist_source_buttons()
        
        # Custom Sources
        self.custom_sources_frame = ttk.LabelFrame(self.sidebar_inner, text="Custom Blacklists (Persistent)")
        self.custom_sources_frame.pack(fill="x", padx=8, pady=4)
        self.custom_sources_help_label = ttk.Label(
            self.custom_sources_frame,
            text="Save your own feeds here for one-click imports later.",
            style="Hint.TLabel",
            wraplength=340,
            justify="left"
        )
        self.custom_sources_help_label.pack(fill="x", padx=8, pady=(8, 2))
        self.custom_sources_summary_label = ttk.Label(
            self.custom_sources_frame,
            text="0 saved sources ready for import.",
            style="Hint.TLabel",
        )
        self.custom_sources_summary_label.pack(fill="x", padx=8, pady=(0, 2))
        self.custom_sources_empty_label = ttk.Label(
            self.custom_sources_frame,
            text="No custom sources saved yet. Add a trusted blocklist URL to keep it ready for future sessions.",
            style="Hint.TLabel",
            wraplength=340,
            justify="left"
        )
        self.custom_sources_empty_label.pack(fill="x", padx=8, pady=(0, 6))
        
        self.btn_add_custom = self._btn(self.custom_sources_frame, "+ Add Custom Source", self.show_add_source_dialog, "Add a new custom URL source.", style="Accent.TButton")
        self.btn_add_custom.pack(fill=tk.X, pady=2, side=tk.BOTTOM)
        self._register_import_widget(self.btn_add_custom)

        # Manual Input
        manual_frame = ttk.LabelFrame(self.sidebar_inner, text="Manual List Input (Paste Hosts)")
        manual_frame.pack(fill="x", padx=8, pady=4)
        ttk.Label(
            manual_frame,
            text="Paste hosts lines, domains, or feed fragments. They will follow the currently selected import mode when appended.",
            style="Hint.TLabel",
            wraplength=360,
            justify="left"
        ).pack(fill="x", padx=8, pady=(8, 0))
        self.manual_text_area = scrolledtext.ScrolledText(
            manual_frame, wrap=tk.WORD, height=10, font=("Consolas", 10),
            bg=PALETTE["crust"], fg=PALETTE["text"], insertbackground=PALETTE["text"],
            selectbackground=PALETTE["blue"], relief="flat"
        )
        self.manual_text_area.pack(fill="x", padx=8, pady=(8, 4))
        self.manual_summary_label = ttk.Label(
            manual_frame,
            text="0 non-empty lines ready to append.",
            style="Hint.TLabel",
            wraplength=360,
            justify="left"
        )
        self.manual_summary_label.pack(fill="x", padx=8, pady=(0, 6))
        self._register_import_widget(self.manual_text_area)
        self._register_import_widget(
            self._btn(manual_frame, "Append Manual List to Editor", self.append_manual_list, 
                      "Append the content from the text area to the main hosts file.", style="Action.TButton")
        ).pack(fill="x", padx=8, pady=(0, 8))

        # Whitelist
        whitelist_frame = ttk.LabelFrame(self.sidebar_inner, text="Persistent Whitelist (Auto-Applied)")
        whitelist_frame.pack(fill="both", padx=8, pady=(4, 8))
        ttk.Label(
            whitelist_frame,
            text="One entry per line. Cleaned Save removes matching blocking entries and previews the result before writing.",
            style="Hint.TLabel",
            wraplength=360,
            justify="left"
        ).pack(fill="x", padx=8, pady=(8, 0))
        self.whitelist_text_area = scrolledtext.ScrolledText(
            whitelist_frame, wrap=tk.WORD, height=10, font=("Consolas", 10),
            bg=PALETTE["crust"], fg=PALETTE["text"], insertbackground=PALETTE["text"],
            selectbackground=PALETTE["blue"], relief="flat"
        )
        self.whitelist_text_area.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        self.whitelist_summary_label = ttk.Label(
            whitelist_frame,
            text="0 whitelist entries. Saved copy matches the editor.",
            style="Hint.TLabel",
            wraplength=360,
            justify="left"
        )
        self.whitelist_summary_label.pack(fill="x", padx=8, pady=(0, 6))
        w_btns = ttk.Frame(whitelist_frame)
        w_btns.pack(fill="x", padx=8, pady=(0, 8))
        self._btn(w_btns, "Load from File", self.load_whitelist_from_file, "Load whitelist from a text file.").pack(side="left", expand=True, fill="x", padx=(0, 6))
        self._btn(w_btns, "Import from Web", self.import_whitelist_from_web, "Import default HOSTShield whitelist.", style="Accent.TButton").pack(side="left", expand=True, fill="x", padx=(6, 0))

        # ---- Editor (Right) ----
        editor_panel = ttk.Frame(right_area)
        editor_panel.pack(fill="both", expand=True)
        
        # Diff Stats Panel
        self.stats_panel = ttk.LabelFrame(editor_panel, text="Current Content Stats")
        self.stats_panel.pack(fill="x", padx=4, pady=(0, 4))
        self._init_stats_panel(self.stats_panel)

        editor_container = ttk.Frame(editor_panel)
        editor_container.pack(expand=True, fill='both', padx=4, pady=(0, 4))

        self.line_gutter = tk.Canvas(
            editor_container, width=52, bg=PALETTE["mantle"],
            highlightthickness=0, bd=0, relief="flat",
        )
        self.line_gutter.pack(side="left", fill="y")

        editor_scroll = ttk.Scrollbar(editor_container, orient="vertical")
        editor_scroll.pack(side="right", fill="y")

        self.text_area = tk.Text(
            editor_container, wrap=tk.WORD, font=("Consolas", 12),
            bg=PALETTE["crust"], fg=PALETTE["text"], insertbackground=PALETTE["text"],
            selectbackground=PALETTE["blue"], relief="flat",
            yscrollcommand=lambda first, last: self._on_editor_scroll(editor_scroll, first, last),
        )
        self.text_area.pack(side="left", expand=True, fill='both')
        editor_scroll.config(command=self.text_area.yview)

        self._gutter_last_line_count = -1
        self._gutter_redraw_job = None
        # Any visual change that can shift line numbers triggers a redraw.
        for seq in ("<KeyRelease>", "<MouseWheel>", "<Button-4>", "<Button-5>",
                    "<Configure>", "<ButtonRelease-1>"):
            self.text_area.bind(seq, self._schedule_gutter_redraw, add="+")

        # Search highlighting setup
        self._search_matches = []
        self._search_index = -1
        self.text_area.tag_configure("search_match", background=PALETTE["blue"], foreground=PALETTE["crust"])
        self.text_area.tag_configure("search_current", background=PALETTE["green"], foreground=PALETTE["crust"])

        # Syntax highlighting tags. Using `foreground` only (no background)
        # keeps warning overlays (red/yellow) readable when they coexist
        # on the same line.
        self.text_area.tag_configure("syntax_ip", foreground=PALETTE["blue"])
        self.text_area.tag_configure("syntax_comment", foreground=PALETTE["overlay1"])
        self.text_area.tag_configure("syntax_marker", foreground=PALETTE["accent"])
        
        # Warning highlighting setup
        self.text_area.tag_configure("warning_discard", background=PALETTE["red_press"], foreground=PALETTE["text"]) 
        self.text_area.tag_configure("warning_transform", background="#a38900", foreground=PALETTE["text"])

        # Listen to editor modifications
        self.text_area.bind("<<Modified>>", self._on_text_modified_debounced)
        self.manual_text_area.bind("<<Modified>>", self._on_manual_modified)
        self.whitelist_text_area.bind("<<Modified>>", self._on_whitelist_modified)
        self.root.bind("<Control-f>", self._focus_search_shortcut)
        self.root.bind("<Control-s>", self._save_cleaned_shortcut)
        self.root.bind("<Control-Shift-s>", self._save_raw_shortcut)
        self.root.bind("<Control-Shift-S>", self._save_raw_shortcut)
        self.root.bind("<F5>", self._refresh_shortcut)

        # Editor context menu + comment-toggle shortcut.
        self._build_editor_context_menu()
        # Windows fires Button-3 for right-click; Mac uses Button-2.
        self.text_area.bind("<Button-3>", self._show_editor_context_menu)
        self.text_area.bind("<Button-2>", self._show_editor_context_menu)
        self.text_area.bind("<Control-slash>", self.toggle_selection_comment)
        self.root.bind("<Control-p>", self.show_goto_anything)

        # Init
        try:
            self.load_config()
        except Exception as e:
            messagebox.showerror("Configuration Error", f"Failed to load or initialize configuration. Application will launch without custom settings.\nError: {e}", parent=self.root)
            self.custom_sources = []
            self.whitelist_text_area.delete('1.0', tk.END)
        
        self.load_file(is_initial_load=True)
        self._update_custom_source_summary()
        self._update_manual_summary()
        self._update_whitelist_summary()
        self._refresh_mode_badges()
        self.maybe_show_first_run_wizard()

    # ----------------------------- UI Helpers & Panels ---------------------------------
    def _apply_window_branding(self):
        try:
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
        except tk.TclError:
            screen_width, screen_height = 1280, 800
        # Remote desktop / headless sessions can report zero or negative
        # screen dimensions. Fall back to sane minimums instead of asking
        # Tk to size a 0x0 window.
        if screen_width <= 0 or screen_height <= 0:
            screen_width, screen_height = 1280, 800
        width = min(1360, max(screen_width - 80, min(screen_width, 900)))
        height = min(900, max(screen_height - 120, min(screen_height, 680)))
        width = max(640, width)
        height = max(480, height)
        x_pos = max((screen_width - width) // 2, 0)
        y_pos = max((screen_height - height) // 2, 0)
        self.root.geometry(f"{width}x{height}+{x_pos}+{y_pos}")
        self.root.minsize(min(width, 1040), min(height, 740))

        assets_dir = _BUNDLE_DIR
        icon_ico = os.path.join(assets_dir, "icon.ico")
        icon_png = os.path.join(assets_dir, "icon.png")

        try:
            if os.name == 'nt' and os.path.exists(icon_ico):
                self.root.iconbitmap(icon_ico)
            elif os.path.exists(icon_png):
                self._icon_image = tk.PhotoImage(file=icon_png)
                self.root.iconphoto(True, self._icon_image)
        except Exception:
            # Branding assets should never block the editor from launching.
            self._icon_image = None

    def _init_stats_panel(self, parent):
        # StringVars let us format large counts with thousand separators —
        # hosts files with 150K+ entries were previously shown as an
        # unreadable wall of digits.
        self.stat_vars = {
            "total": tk.StringVar(value="0"),
            "final_active": tk.StringVar(value="0"),
            "removed_comments": tk.StringVar(value="0"),
            "removed_duplicates": tk.StringVar(value="0"),
            "total_discarded": tk.StringVar(value="0"),
            "transformed": tk.StringVar(value="0"),
            "removed_whitelist": tk.StringVar(value="0"),
        }

        ttk.Label(
            parent,
            text="Live preview of what Cleaned Save will keep, normalize, or remove.",
            style="Hint.TLabel"
        ).pack(anchor='w', padx=8, pady=(8, 0))
        
        grid_frame = ttk.Frame(parent, padding=5)
        grid_frame.pack(fill='x')
        
        # Row 1
        self._create_stat_label(grid_frame, "Total Input Lines:", self.stat_vars["total"], row=0, col=0)
        self._create_stat_label(grid_frame, "Removed During Clean:", self.stat_vars["total_discarded"], row=0, col=2, color=PALETTE["red"])
        self._create_stat_label(grid_frame, "Final Active Entries:", self.stat_vars["final_active"], row=0, col=4, color=PALETTE["green"])
        
        # Row 2
        self._create_stat_label(grid_frame, "Duplicate Entries Removed:", self.stat_vars["removed_duplicates"], row=1, col=0, color=PALETTE["red"])
        self._create_stat_label(grid_frame, "Whitelisted Entries Removed:", self.stat_vars["removed_whitelist"], row=1, col=2, color=PALETTE["blue"])
        self._create_stat_label(grid_frame, "Lines Normalized:", self.stat_vars["transformed"], row=1, col=4, color="#ffd700")

        # Row 3
        self._create_stat_label(grid_frame, "Comment / Blank Lines Removed:", self.stat_vars["removed_comments"], row=2, col=0)
        
        grid_frame.grid_columnconfigure(1, weight=1)
        grid_frame.grid_columnconfigure(3, weight=1)
        grid_frame.grid_columnconfigure(5, weight=1)

    def _create_stat_label(self, parent, text, var, row, col, color=PALETTE["text"]):
        ttk.Label(parent, text=text).grid(row=row, column=col, sticky='w', padx=(10, 2), pady=2)
        ttk.Label(parent, textvariable=var, foreground=color, font=("Segoe UI", 10, "bold")).grid(row=row, column=col+1, sticky='w', padx=(0, 10), pady=2)

    def _refresh_mode_badges(self, _lines=None, _current_hash=None):
        if not hasattr(self, "admin_badge_label"):
            return

        admin_ready = self.is_admin
        dry_run = self.dry_run_mode.get()
        import_mode = self.import_mode.get()

        self.admin_badge_label.config(
            text="Admin Ready" if admin_ready else "Read-Only Session",
            bg=PALETTE["green"] if admin_ready else PALETTE["red"],
            fg="#0b1020" if admin_ready else "#1b0e13"
        )
        editor_state_text = "Session Ready"
        editor_state_bg = PALETTE["surface1"]
        editor_state_fg = PALETTE["text"]
        if hasattr(self, "text_area"):
            lines = _lines if _lines is not None else self.get_lines()
            has_content = any(line.strip() for line in lines)
            current_hash = _current_hash if _current_hash is not None else self._hash_lines(lines)
            if self._has_unsaved_changes(_lines=lines, _current_hash=current_hash):
                editor_state_text = "Unsaved Editor Changes"
                editor_state_bg = PALETTE["yellow"]
                editor_state_fg = PALETTE["yellow_ink"]
            elif self._last_applied_cleaned_hash is not None and current_hash == self._last_applied_cleaned_hash:
                editor_state_text = "Saved Cleaned Snapshot"
                editor_state_bg = PALETTE["green"]
                editor_state_fg = "#0b1020"
            elif self._last_applied_raw_hash is not None and current_hash == self._last_applied_raw_hash:
                editor_state_text = "Matches Disk Copy"
                editor_state_bg = PALETTE["surface1"]
                editor_state_fg = PALETTE["text"]
            elif not has_content:
                editor_state_text = "Empty Editor"
                editor_state_bg = PALETTE["surface0"]
                editor_state_fg = PALETTE["text"]
        self.editor_state_badge_label.config(
            text=editor_state_text,
            bg=editor_state_bg,
            fg=editor_state_fg
        )
        self.mode_badge_label.config(
            text=f"Import Mode: {import_mode}",
            bg=PALETTE["blue"],
            fg="#0b1020"
        )
        self.dry_run_badge_label.config(
            text="Dry-Run Enabled" if dry_run else "Disk Writes Enabled",
            bg=PALETTE["accent"] if dry_run else PALETTE["surface1"],
            fg="#0b1020" if dry_run else PALETTE["text"]
        )

    def _set_import_mode_status(self, mode):
        self._refresh_mode_badges()
        self._update_manual_summary()
        if mode == "Raw":
            self.update_status("Import mode set to Raw. Original formatting, comments, and markers will be preserved.")
        else:
            self.update_status("Import mode set to Normalized. Domains will be standardized into clean 0.0.0.0 entries.")

    def _on_source_filter_changed(self):
        self._cancel_after_job("_source_filter_job")
        self._source_filter_job = self._safe_after(200, self._populate_blocklist_source_buttons)

    def _populate_blocklist_source_buttons(self):
        self._source_filter_job = None
        if not hasattr(self, "web_catalog_frame"):
            return
        try:
            if not self.web_catalog_frame.winfo_exists():
                return
        except tk.TclError:
            return

        for child in self.web_catalog_frame.winfo_children():
            child.destroy()
        self.import_action_widgets = [item for item in self.import_action_widgets if item and item.winfo_exists()]

        query = self.source_filter_var.get().strip().lower()
        matched_categories = 0
        matched_sources = 0

        for category, sources in self.BLOCKLIST_SOURCES.items():
            filtered_sources = [
                (name, url, tooltip)
                for name, url, tooltip in sources
                if not query or query in category.lower() or query in name.lower() or query in tooltip.lower() or query in url.lower()
            ]
            if not filtered_sources:
                continue

            matched_categories += 1
            matched_sources += len(filtered_sources)

            web_import_frame = ttk.LabelFrame(self.web_catalog_frame, text=category)
            web_import_frame.pack(fill="x", pady=4)
            for name, url, tooltip in filtered_sources:
                row = ttk.Frame(web_import_frame)
                row.pack(fill="x", pady=2)
                last_stamp = self.source_last_fetched.get(url, "") if hasattr(self, "source_last_fetched") else ""
                stamp_hint = format_relative_time(last_stamp)
                tooltip_full = f"{tooltip}\n\nLast fetched: {stamp_hint}" if stamp_hint else tooltip
                import_btn = self._btn(
                    row, name,
                    lambda u=url, n=name: self.start_single_import(n, u),
                    tooltip_full,
                )
                self._register_import_widget(import_btn)
                import_btn.pack(side="left", fill="x", expand=True)
                preview_btn = self._btn(
                    row, "Peek",
                    lambda u=url, n=name: self.preview_blocklist_source(n, u),
                    f"Preview the first entries of {name} without importing.",
                    style="Secondary.TButton",
                )
                self._register_import_widget(preview_btn)
                preview_btn.pack(side="right", padx=(4, 0))

        if matched_sources == 0:
            ttk.Label(
                self.web_catalog_frame,
                text="No sources matched the current filter. Try a broader keyword like ads, malware, or TikTok.",
                style="Hint.TLabel",
                wraplength=340
            ).pack(anchor='w', pady=4)
            self.catalog_summary_label.config(text="0 sources shown. Clear or broaden the filter to browse everything.")
        else:
            self.catalog_summary_label.config(text=f"Showing {matched_sources} sources across {matched_categories} categories")

    def _focus_search_shortcut(self, event=None):
        self.search_entry.focus_set()
        self.search_entry.selection_range(0, tk.END)
        return "break"

    def _save_cleaned_shortcut(self, event=None):
        self.save_cleaned_file()
        return "break"

    def _save_raw_shortcut(self, event=None):
        self.save_raw_file()
        return "break"

    def _refresh_shortcut(self, event=None):
        self.load_file()
        return "break"

    def _update_diff_stats(self, lines):
        stats = compute_clean_impact_stats(lines, self._get_whitelist_set())

        self.stat_vars["total"].set(f"{stats['lines_total']:,}")
        self.stat_vars["final_active"].set(f"{stats['final_active']:,}")
        self.stat_vars["removed_comments"].set(f"{stats['removed_comments'] + stats['removed_blanks']:,}")
        self.stat_vars["removed_duplicates"].set(f"{stats['removed_duplicates']:,}")
        self.stat_vars["transformed"].set(f"{stats['transformed']:,}")
        self.stat_vars["removed_whitelist"].set(f"{stats['removed_whitelist']:,}")
        self.stat_vars["total_discarded"].set(f"{stats['total_discarded']:,}")

        discard_count = stats["removed_invalid"] + stats["removed_duplicates"] + stats["removed_whitelist"]

        if discard_count > 0:
            self.warning_status_label.config(
                text=f"Cleaned Save will remove {discard_count:,} entries and normalize {stats['transformed']:,} line(s).",
                foreground=PALETTE["red"]
            )
        elif stats["transformed"] > 0:
            self.warning_status_label.config(
                text=f"Cleaned Save will normalize {stats['transformed']:,} line(s). No entries will be removed.",
                foreground=PALETTE["yellow"]
            )
        else:
            self.warning_status_label.config(
                text="Cleaned Save is already aligned. No removals or normalization are pending.",
                foreground=PALETTE["green"]
            )


    # ----------------------------- Styles & Menus -----------------------------
    def _init_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Base
        style.configure(".", background=PALETTE["base"], foreground=PALETTE["text"], fieldbackground=PALETTE["surface0"])
        style.configure("TFrame", background=PALETTE["base"])
        style.configure("TLabel", background=PALETTE["base"], foreground=PALETTE["text"])
        style.configure("Panel.TFrame", background=PALETTE["mantle"])
        style.configure("Panel.TLabel", background=PALETTE["mantle"], foreground=PALETTE["text"])
        style.configure("PanelMuted.TLabel", background=PALETTE["mantle"], foreground=PALETTE["subtext"])
        style.configure("PanelSubtle.TLabel", background=PALETTE["mantle"], foreground=PALETTE["overlay1"])
        style.configure("Hint.TLabel", background=PALETTE["mantle"], foreground=PALETTE["subtext"])
        style.configure("StatusMeta.TLabel", background=PALETTE["base"], foreground=PALETTE["overlay1"])
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

        style.configure("Secondary.TButton",
                        background=PALETTE["surface1"], foreground=PALETTE["text"],
                        padding=(10, 6), relief="flat", borderwidth=0)
        style.map("Secondary.TButton",
                  background=[("active", PALETTE["overlay0"])],
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

        style.configure("Saved.TButton",
                        background=PALETTE["yellow"], foreground=PALETTE["yellow_ink"],
                        padding=(10, 6), relief="flat", borderwidth=0)
        style.map("Saved.TButton",
                  background=[("active", "#f5d58b")],
                  relief=[("pressed", "sunken")])

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

        # Menus
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
        file_menu.add_command(label="Save Raw", command=self.save_raw_file)
        file_menu.add_command(label="Save Cleaned", command=self.save_cleaned_file)
        file_menu.add_command(label="Refresh", command=self.load_file)
        file_menu.add_command(label="Revert to Backup", command=self.revert_to_backup)
        file_menu.add_command(label="Panic Restore (Microsoft default)", command=self.panic_restore_stock)
        file_menu.add_separator()
        file_menu.add_command(label="Export Cleaned As…", command=self.show_export_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Disable / Enable Hosts", command=self.toggle_hosts_enabled)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        menu_bar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menu_bar, tearoff=0, bg=PALETTE["mantle"], fg=PALETTE["text"],
                             activebackground=PALETTE["blue"], activeforeground="#0b1020")
        tools_menu.add_command(label="Clean", command=self.auto_clean)
        tools_menu.add_command(label="Normalize & Deduplicate", command=self.deduplicate)
        tools_menu.add_command(label="Flush DNS", command=self.flush_dns)
        tools_menu.add_separator()
        cleanup_menu = tk.Menu(tools_menu, tearoff=0, bg=PALETTE["mantle"], fg=PALETTE["text"],
                               activebackground=PALETTE["blue"], activeforeground="#0b1020")
        cleanup_menu.add_command(label="Remove Comments Only", command=self.cleanup_comments_only)
        cleanup_menu.add_command(label="Remove Blank Lines Only", command=self.cleanup_blanks_only)
        cleanup_menu.add_command(label="Remove Invalid Lines Only", command=self.cleanup_invalid_only)
        cleanup_menu.add_separator()
        cleanup_menu.add_command(label="Remove Import Section…", command=self.show_remove_import_section)
        tools_menu.add_cascade(label="Targeted Cleanup", menu=cleanup_menu)
        tools_menu.add_separator()
        tools_menu.add_command(label="Check Domain…", command=self.show_check_domain)
        tools_menu.add_command(label="Hosts Health Scan…", command=self.show_health_scan)
        tools_menu.add_command(label="Sources Report…", command=self.show_sources_report)
        tools_menu.add_command(label="Goto Anything…", command=self.show_goto_anything)
        tools_menu.add_separator()
        tools_menu.add_command(label="Schedule Auto-Update…", command=self.show_schedule_wizard)
        tools_menu.add_command(label="Preferences…", command=self.show_preferences)
        tools_menu.add_separator()
        convert_menu = tk.Menu(tools_menu, tearoff=0, bg=PALETTE["mantle"], fg=PALETTE["text"],
                               activebackground=PALETTE["blue"], activeforeground="#0b1020")
        convert_menu.add_command(label="Use 0.0.0.0 (fastest on Windows)", command=lambda: self.convert_block_ips("0.0.0.0"))
        convert_menu.add_command(label="Use 127.0.0.1", command=lambda: self.convert_block_ips("127.0.0.1"))
        convert_menu.add_command(label="Use :: (IPv6 null)", command=lambda: self.convert_block_ips("::"))
        tools_menu.add_cascade(label="Convert Block IPs", menu=convert_menu)
        tools_menu.add_separator()
        tools_menu.add_checkbutton(label="Dry-run only", variable=self.dry_run_mode, command=self._check_dry_run_warning)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menu_bar, tearoff=0, bg=PALETTE["mantle"], fg=PALETTE["text"],
                            activebackground=PALETTE["blue"], activeforeground="#0b1020")
        help_menu.add_command(label="About", command=self.show_about_dialog)
        help_menu.add_command(label="Open Config Folder", command=self.open_config_folder)
        help_menu.add_separator()
        help_menu.add_command(label="Project on GitHub", command=lambda: webbrowser.open("https://github.com/SysAdminDoc/HostsFileGet"))
        menu_bar.add_cascade(label="Help", menu=help_menu)

    def _btn(self, parent, text, command, tooltip, style="TButton"):
        btn = ttk.Button(parent, text=text, command=command, style=style)
        ToolTip(btn, tooltip)
        return btn

    def _register_import_widget(self, widget):
        self.import_action_widgets = [item for item in self.import_action_widgets if item and item.winfo_exists()]
        if widget not in self.import_action_widgets:
            self.import_action_widgets.append(widget)
        return widget

    def _set_import_controls_enabled(self, enabled: bool):
        desired_state = "normal" if enabled else "disabled"
        entry_state = "normal" if enabled else "disabled"

        for widget in list(self.import_action_widgets):
            if not widget or not widget.winfo_exists():
                continue

            widget_class = widget.winfo_class()
            try:
                if widget_class == "Entry":
                    widget.configure(state=entry_state)
                else:
                    widget.configure(state=desired_state)
            except tk.TclError:
                continue

        self.import_action_widgets = [item for item in self.import_action_widgets if item and item.winfo_exists()]

    def _reset_status_color(self):
        try:
            if self.status_label.winfo_exists():
                self.status_label.config(foreground=PALETTE["subtext"])
        except tk.TclError:
            pass

    def _set_status_hint(self, text=None):
        try:
            if hasattr(self, "status_hint_label") and self.status_hint_label.winfo_exists():
                self.status_hint_label.config(text=text or self.default_status_hint)
        except tk.TclError:
            pass

    _STATUS_MESSAGE_MAX_LEN = 220

    def update_status(self, message, is_error=False):
        self._cancel_after_job("_status_reset_job")
        # Collapse newlines and truncate so a multi-line exception message
        # can't distort the status bar layout or push the hint label off
        # the window edge.
        if message is None:
            message = ""
        message = str(message).replace("\r", " ").replace("\n", " ")
        if len(message) > self._STATUS_MESSAGE_MAX_LEN:
            message = message[: self._STATUS_MESSAGE_MAX_LEN - 1] + "…"
        message_lower = message.lower()
        if is_error:
            color = PALETTE["red"]
        elif message_lower.startswith(("success", "imported", "loaded", "restored", "saved")):
            color = PALETTE["green"]
        elif message_lower.startswith("warning") or "dry-run" in message_lower:
            color = PALETTE["yellow"]
        else:
            color = PALETTE["subtext"]
        try:
            self.status_label.config(text=message, foreground=color)
        except tk.TclError:
            return
        if not self.is_importing:
            self._status_reset_job = self._safe_after(4000, self._reset_status_color)

    def open_config_folder(self):
        """Open the per-user config directory in the OS file manager.

        Useful when the user wants to inspect or back up
        ``hosts_editor_config.json`` manually, or manually clean a corrupt
        config entry the app can't surface through the UI.
        """
        folder = os.path.dirname(self.config_path) if is_portable_mode() else get_app_config_dir()
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError as e:
            messagebox.showerror("Error", f"Could not create config folder:\n{e}", parent=self.root)
            return

        try:
            if os.name == 'nt':
                os.startfile(folder)
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', folder])
            else:
                subprocess.Popen(['xdg-open', folder])
            self.update_status(f"Opened config folder: {folder}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open config folder:\n{e}", parent=self.root)

    def show_about_dialog(self):
        messagebox.showinfo(
            f"About {APP_NAME}",
            (
                f"{APP_NAME} v{APP_VERSION}\n\n"
                "Windows-first hosts file editing with curated imports, previewed cleaning, safer save flows, and recovery tools.\n\n"
                "Highlights\n"
                "- Save Cleaned previews normalization and whitelist filtering before write\n"
                "- Save Raw preserves the editor exactly as shown\n"
                "- Batch imports stay sequential so progress and failures are easier to trust\n"
                "- Dry-run mode lets you validate changes without touching disk\n\n"
                "Shortcuts\n"
                "Ctrl+F   Focus search\n"
                "Ctrl+S   Save Cleaned\n"
                "Ctrl+Shift+S   Save Raw\n"
                "F5   Reload from disk"
            ),
            parent=self.root,
        )

    def _on_editor_scroll(self, scrollbar, first, last):
        """Keep the scrollbar and the line-number gutter in sync with the text.

        Tk `yscrollcommand` fires whenever the viewport moves, so we hook it
        to redraw line numbers lazily via ``after_idle`` — redrawing here
        directly would flicker badly during rapid paging.
        """
        try:
            scrollbar.set(first, last)
        except tk.TclError:
            return
        self._schedule_gutter_redraw()

    def _schedule_gutter_redraw(self, _event=None):
        if self._gutter_redraw_job is not None:
            return
        self._gutter_redraw_job = self._safe_after(16, self._redraw_gutter)

    def _redraw_gutter(self):
        self._gutter_redraw_job = None
        if not hasattr(self, "line_gutter"):
            return
        try:
            if not self.line_gutter.winfo_exists():
                return
            self.line_gutter.delete("all")
            # Walk visible lines from the first displayed to the last.
            index = self.text_area.index("@0,0")
            while True:
                dline = self.text_area.dlineinfo(index)
                if dline is None:
                    break
                y = dline[1]
                line_no = int(index.split('.')[0])
                self.line_gutter.create_text(
                    46, y + 2,
                    anchor="ne",
                    text=str(line_no),
                    fill=PALETTE["overlay1"],
                    font=("Consolas", 10),
                )
                index = self.text_area.index(f"{index}+1line")
                # Defensive guard: if Tk returns the same index twice (EOF),
                # break so we don't spin.
                next_line_no = int(index.split('.')[0])
                if next_line_no <= line_no:
                    break
        except tk.TclError:
            return

    def _safe_after(self, delay_ms: int, callback):
        """Schedule a Tk callback, swallowing errors when root is torn down.

        Background threads that post work onto the Tk main loop via ``after``
        can fire after the window has been destroyed (e.g. whitelist web fetch
        racing with app close). Without this wrapper those calls raise
        TclError, which surfaces as a noisy stderr stack trace on exit.
        """
        try:
            if self.root and self.root.winfo_exists():
                return self.root.after(delay_ms, callback)
        except tk.TclError:
            pass
        return None

    def _cancel_after_job(self, attr_name: str):
        job = getattr(self, attr_name, None)
        if job:
            try:
                self.root.after_cancel(job)
            except (tk.TclError, ValueError):
                pass
            setattr(self, attr_name, None)

    def on_closing(self):
        should_cancel_import = False
        if self.is_importing:
            if not messagebox.askyesno("Close During Import", "A batch import is still running. Close the app and stop that import?", parent=self.root):
                return
            should_cancel_import = True

        if self._has_unsaved_changes():
            if not messagebox.askyesno("Discard Unsaved Changes", "You have unsaved editor changes. Close without saving them?", parent=self.root):
                return

        if should_cancel_import:
            self.stop_import_flag.set()

        # Cancel pending Tk ``after`` callbacks so they don't try to touch
        # widgets after we destroy the root window.
        for attr in ("_update_ui_job", "_source_filter_job", "_status_reset_job"):
            self._cancel_after_job(attr)

        try:
            self.save_config()
        except Exception:
            # Never block shutdown because of a config save failure — the
            # user is trying to exit and the error is non-recoverable at
            # this point.
            pass
        self.root.destroy()

    # --------------------------- Admin Check & Dry Run ----------------------------------
    def check_admin_privileges(self):
        try:
            is_admin = (os.getuid() == 0)
        except AttributeError:
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except (AttributeError, OSError):
                is_admin = False 

        if is_admin:
            self.is_admin = True
            self.root.after(100, lambda: self.update_status("Success: Running with Administrator privileges.", is_error=False))
            return True
        else:
            self.is_admin = False
            if os.name == 'nt' and ELEVATION_ATTEMPT_FLAG not in sys.argv:
                try:
                    relaunch_args = sys.argv[1:] + [ELEVATION_ATTEMPT_FLAG]
                    if getattr(sys, 'frozen', False):
                        exe = sys.executable
                        params = ' '.join(['"%s"' % arg for arg in relaunch_args])
                    else:
                        exe = sys.executable
                        script = os.path.abspath(sys.argv[0])
                        params = f'"{script}" ' + ' '.join(['"%s"' % arg for arg in relaunch_args])
                    launch_result = ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", exe, params, None, 1
                    )
                    if launch_result > 32:
                        return False
                except Exception as e:
                    messagebox.showerror(
                        "Relaunch Failed", 
                        f"Could not relaunch as administrator. Saving the hosts file will fail due to permission error.\nError: {e}",
                        parent=self.root,
                    )
            
            self.root.after(100, lambda: self.update_status("Warning: Not running as Administrator. Saving will fail unless Dry-run is enabled.", is_error=True))
            return True
    
    def _check_dry_run_warning(self):
        self._refresh_mode_badges()
        if self.dry_run_mode.get():
            self.update_status("Dry-run mode is ACTIVE. No file writes will occur.", is_error=False)
        elif not self.is_admin:
            self.update_status("Warning: Not running as Administrator. Saving will fail unless Dry-run is enabled.", is_error=True)
        else:
            self.update_status("Dry-run mode DISABLED. Saving to disk is enabled.", is_error=False)

    # ------------------------- Config Persistence -----------------------------
    def _get_legacy_config_paths(self):
        script_dir = _EXE_DIR
        candidates = []
        for base_dir in (os.getcwd(), script_dir):
            candidate = os.path.join(base_dir, self.CONFIG_FILENAME)
            if candidate != self.config_path and candidate not in candidates:
                candidates.append(candidate)
        return candidates

    def _write_config_payload(self, config: dict):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        write_text_file_atomic(self.config_path, json.dumps(config, indent=4))

    def _choose_file(self, title, filetypes):
        initial_dir = self.last_open_dir if os.path.isdir(self.last_open_dir) else os.path.expanduser("~")
        selected_path = filedialog.askopenfilename(
            title=title,
            filetypes=filetypes,
            initialdir=initial_dir,
        )
        if selected_path:
            self.last_open_dir = os.path.dirname(selected_path)
        return selected_path

    def load_config(self):
        config_source_path = None
        if os.path.exists(self.config_path):
            config_source_path = self.config_path
        else:
            for legacy_path in self._get_legacy_config_paths():
                if os.path.exists(legacy_path):
                    config_source_path = legacy_path
                    break

        if not config_source_path:
            return

        try:
            config = json.loads(read_text_file_content(config_source_path))
        except (json.JSONDecodeError, ValueError):
            self.update_status("Config file is corrupt — using defaults.", is_error=True)
            return
        except OSError as e:
            self.update_status(f"Config read failed: {e}", is_error=True)
            return

        sanitized_config = sanitize_config_snapshot(config, self.last_open_dir)

        # Set the saved-hash markers BEFORE writing to the whitelist widget so
        # the transient <<Modified>> event triggered by insert() sees the
        # correct "saved copy matches editor" state instead of briefly
        # flashing "Unsaved changes are pending".
        self.custom_sources = sanitized_config["custom_sources"]
        self._last_applied_raw_hash = sanitized_config["last_applied_raw_hash"]
        self._last_applied_cleaned_hash = sanitized_config["last_applied_cleaned_hash"]
        self._last_saved_whitelist_text = sanitized_config["whitelist"]
        self.last_open_dir = sanitized_config["last_open_dir"]
        self.source_last_fetched = sanitized_config.get("source_last_fetched", {})
        self._preferred_block_sink = sanitized_config.get("preferred_block_sink", "0.0.0.0")
        self._backup_retention = sanitized_config.get("backup_retention", BACKUP_RETENTION)
        self._has_completed_first_run = sanitized_config.get("has_completed_first_run", False)

        self.whitelist_text_area.delete('1.0', tk.END)
        self.whitelist_text_area.insert('1.0', sanitized_config["whitelist"])
        self.whitelist_text_area.edit_modified(False)

        self.update_status("Configuration loaded.")
        self._rebuild_custom_source_buttons()
        self._update_whitelist_summary()

        if config_source_path != self.config_path:
            self._write_config_payload(sanitized_config)
            # Clean up the legacy file so we don't keep re-reading it on
            # future launches. Failures here are non-fatal — the primary
            # path now exists and will be preferred regardless.
            try:
                os.unlink(config_source_path)
            except OSError:
                pass

    def save_config(self):
        # When called from `on_closing`, the Tk widget tree may already be
        # partially torn down. Guard the widget read so shutdown continues
        # cleanly; without this guard a stray TclError surfaced as a stderr
        # traceback for users closing the app during an active import.
        try:
            whitelist_text = self.whitelist_text_area.get('1.0', tk.END).strip()
        except tk.TclError:
            whitelist_text = self._last_saved_whitelist_text or ""

        config = sanitize_config_snapshot({
            "whitelist": whitelist_text,
            "custom_sources": self.custom_sources,
            "last_applied_raw_hash": self._last_applied_raw_hash,
            "last_applied_cleaned_hash": self._last_applied_cleaned_hash,
            "last_open_dir": self.last_open_dir,
            "source_last_fetched": self.source_last_fetched,
            "preferred_block_sink": self._preferred_block_sink,
            "backup_retention": self._backup_retention,
            "has_completed_first_run": self._has_completed_first_run,
        }, self.last_open_dir)
        try:
            self._write_config_payload(config)
            self._last_saved_whitelist_text = config["whitelist"]
            self._update_whitelist_summary()
        except OSError as e:
            self.update_status(f"Config save failed: {e}", is_error=True)
        except tk.TclError:
            # Widget torn down between payload write and summary refresh —
            # the config IS on disk, nothing else to do.
            pass

    # ----------------------------- File Ops & State Tracking -----------------------------------
    def get_lines(self):
        return self.text_area.get('1.0', tk.END).splitlines()

    def set_text(self, lines, update_hash=False, is_cleaned=False):
        self._suppress_modified_handler = True
        self.text_area.delete('1.0', tk.END)
        # Performance: Join lines once and insert as one block
        self.text_area.insert(tk.END, '\n'.join(lines))
        # After a bulk insert Tk positions the view at the end of the text.
        # For load/import/clean flows the user expects to see the top of
        # the file first.
        try:
            self.text_area.mark_set('insert', '1.0')
            self.text_area.see('1.0')
        except tk.TclError:
            pass
        self.text_area.edit_modified(False)
        self._suppress_modified_handler = False

        current_hash = self._hash_lines(lines)
        if update_hash:
            if is_cleaned:
                self._last_applied_cleaned_hash = current_hash
                self._last_applied_raw_hash = None
            else:
                self._last_applied_raw_hash = current_hash
                self._last_applied_cleaned_hash = None

        self._update_save_button_state()
        self._trigger_ui_update()
        self._schedule_gutter_redraw()

    def _hash_lines(self, lines):
        return hashlib.sha256('\n'.join(lines).encode('utf-8')).hexdigest()

    def _has_unsaved_changes(self, _lines=None, _current_hash=None):
        lines = _lines if _lines is not None else self.get_lines()
        if self._last_applied_raw_hash is None and self._last_applied_cleaned_hash is None:
            return any(line.strip() for line in lines)

        current_hash = _current_hash if _current_hash is not None else self._hash_lines(lines)
        return current_hash not in {self._last_applied_raw_hash, self._last_applied_cleaned_hash}

    def _on_whitelist_modified(self, event=None):
        if self.whitelist_text_area.edit_modified():
            self.whitelist_text_area.edit_modified(False)
            self._update_whitelist_summary()
            self._trigger_ui_update()

    def _trigger_ui_update(self):
        self._cancel_after_job("_update_ui_job")
        self._update_ui_job = self._safe_after(300, self._on_text_modified_handler)


    def _on_text_modified_debounced(self, event=None):
        if self._suppress_modified_handler:
            return
        self._trigger_ui_update()

    def _on_text_modified_handler(self):
        self._update_ui_job = None
        try:
            if not self.text_area.winfo_exists():
                return
            if self.text_area.edit_modified():
                self.text_area.edit_modified(False)

            lines = self.get_lines()
        except tk.TclError:
            return

        current_hash = self._hash_lines(lines)
        self._update_save_button_state(_lines=lines, _current_hash=current_hash)
        self._update_diff_stats(lines)
        self._apply_inline_warnings(lines)
        self._apply_syntax_highlighting(lines)

        query = self.search_var.get().strip()
        if query:
            self._recompute_search_matches(query, preserve_index=True)


    def _update_save_button_state(self, _lines=None, _current_hash=None):
        lines = _lines if _lines is not None else self.get_lines()
        current_hash = _current_hash if _current_hash is not None else self._hash_lines(lines)

        if self._last_applied_raw_hash is not None and current_hash == self._last_applied_raw_hash:
            self.btn_save_raw.configure(style="Saved.TButton")
        else:
            self.btn_save_raw.configure(style="Secondary.TButton")

        if self._last_applied_cleaned_hash is not None and current_hash == self._last_applied_cleaned_hash:
            self.btn_save_cleaned.configure(style="Saved.TButton")
        else:
            self.btn_save_cleaned.configure(style="Action.TButton")
        self._refresh_mode_badges(_lines=lines, _current_hash=current_hash)

    def _update_custom_source_summary(self):
        if not hasattr(self, "custom_sources_summary_label"):
            return

        count = len(self.custom_sources)
        if count == 0:
            text = "0 saved sources ready for import."
        elif count == 1:
            text = "1 saved source ready for import."
        else:
            text = f"{count} saved sources ready for import."
        self.custom_sources_summary_label.config(text=text)

    def _update_manual_summary(self):
        if not hasattr(self, "manual_summary_label"):
            return

        count = count_nonempty_lines(self.manual_text_area.get('1.0', tk.END))
        mode = self.import_mode.get()
        if count == 0:
            text = "0 non-empty lines ready to append."
        elif count == 1:
            text = f"1 non-empty line ready to append in {mode} mode."
        else:
            text = f"{count:,} non-empty lines ready to append in {mode} mode."
        self.manual_summary_label.config(text=text)

    def _update_whitelist_summary(self):
        if not hasattr(self, "whitelist_summary_label"):
            return

        count = len(self._get_whitelist_set())
        dirty_suffix = " Unsaved changes are pending." if self._has_unsaved_whitelist_changes() else " Saved copy matches the editor."
        if count == 1:
            text = "1 whitelist entry." + dirty_suffix
        else:
            text = f"{count:,} whitelist entries." + dirty_suffix
        self.whitelist_summary_label.config(text=text)

    def _on_manual_modified(self, event=None):
        if self.manual_text_area.edit_modified():
            self.manual_text_area.edit_modified(False)
            self._update_manual_summary()


    # ----------------------------- Backup Rotation ---------------------------
    def _rotate_backups(self) -> str | None:
        """Create a timestamped backup and prune old ones.

        In addition to the rolling ``hosts.bak`` that "Revert to Backup" has
        always used, we now persist up to ``BACKUP_RETENTION`` timestamped
        snapshots alongside it (``hosts.YYYYMMDD-HHMMSS.bak``). Returns the
        path of the newly created timestamped backup, or ``None`` if the
        hosts file does not exist yet (first save on a fresh install).
        """
        if not os.path.exists(self.HOSTS_FILE_PATH):
            return None

        latest_bak = self.HOSTS_FILE_PATH + ".bak"
        shutil.copy2(self.HOSTS_FILE_PATH, latest_bak)

        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        timestamped = f"{self.HOSTS_FILE_PATH}.{stamp}.bak"
        try:
            shutil.copy2(self.HOSTS_FILE_PATH, timestamped)
        except OSError:
            # Timestamped copy is a convenience layer — the rolling .bak
            # is still in place so a failure here is non-fatal.
            return None

        self._prune_old_backups()
        return timestamped

    def _prune_old_backups(self) -> None:
        """Keep only the newest ``self._backup_retention`` timestamped snapshots."""
        pattern = f"{self.HOSTS_FILE_PATH}.*.bak"
        try:
            candidates = glob.glob(pattern)
        except OSError:
            return

        # Exclude the rolling latest-copy from timestamped pruning — it
        # matches the same wildcard but is managed separately.
        latest_bak = os.path.normcase(self.HOSTS_FILE_PATH + ".bak")
        timestamped = [
            path for path in candidates
            if os.path.normcase(path) != latest_bak
        ]
        retention = getattr(self, "_backup_retention", BACKUP_RETENTION)
        if len(timestamped) <= retention:
            return

        timestamped.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for stale in timestamped[retention:]:
            try:
                os.unlink(stale)
            except OSError:
                pass

    def list_backup_snapshots(self) -> list[str]:
        pattern = f"{self.HOSTS_FILE_PATH}.*.bak"
        try:
            candidates = glob.glob(pattern)
        except OSError:
            return []
        latest_bak = os.path.normcase(self.HOSTS_FILE_PATH + ".bak")
        timestamped = [
            path for path in candidates
            if os.path.normcase(path) != latest_bak
        ]
        timestamped.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return timestamped

    # ----------------------------- Enable / Disable --------------------------
    DISABLED_MARKER_PATH_ATTR = None

    def _disabled_sibling_path(self) -> str:
        return self.HOSTS_FILE_PATH + ".disabled"

    def is_hosts_disabled(self) -> bool:
        return os.path.exists(self._disabled_sibling_path())

    def toggle_hosts_enabled(self):
        """Flip between the user's hosts file and a minimal Microsoft default.

        When disabling: the active hosts is copied to ``hosts.disabled`` and
        the active file is replaced with the stock Windows template.
        When re-enabling: we swap them back. This is a common pattern in
        SwitchHosts / HostsMan for quickly turning blocklists off to
        troubleshoot broken sites without losing any data.
        """
        if self._block_during_import("Disable/Enable Hosts"):
            return
        if not self.is_admin:
            messagebox.showerror(
                "Administrator Required",
                "Disabling or re-enabling the hosts file requires Administrator privileges.",
                parent=self.root,
            )
            self.update_status("Disable/Enable blocked: Admin rights required.", is_error=True)
            return

        disabled_path = self._disabled_sibling_path()
        try:
            if self.is_hosts_disabled():
                # Re-enable: restore the previously-stashed user file.
                try:
                    self._rotate_backups()
                except OSError:
                    pass
                if os.path.exists(self.HOSTS_FILE_PATH):
                    # Preserve the current minimal file as a backup too, so
                    # the user can always get back to "stock Windows".
                    shutil.copy2(self.HOSTS_FILE_PATH, self.HOSTS_FILE_PATH + ".bak")
                shutil.copy2(disabled_path, self.HOSTS_FILE_PATH)
                os.unlink(disabled_path)
                self.update_status("Success: Hosts file re-enabled. Blocklists are active again.")
            else:
                if not messagebox.askyesno(
                    "Disable Hosts File",
                    "Disabling temporarily replaces the hosts file with the minimal Microsoft default so every blocklist is bypassed.\n\n"
                    "Your current file is preserved alongside it and can be re-enabled from this menu.\n\n"
                    "Continue?",
                    parent=self.root,
                ):
                    return
                try:
                    self._rotate_backups()
                except OSError:
                    pass
                if os.path.exists(self.HOSTS_FILE_PATH):
                    shutil.copy2(self.HOSTS_FILE_PATH, disabled_path)
                minimal = (
                    "# Copyright (c) 1993-2009 Microsoft Corp.\n"
                    "#\n"
                    "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n"
                    "127.0.0.1       localhost\n"
                    "::1             localhost\n"
                )
                write_text_file_atomic(self.HOSTS_FILE_PATH, minimal)
                self.update_status("Success: Hosts file disabled. Minimal Microsoft template is active.")
            self.flush_dns_silent()
            self.load_file(is_initial_load=False)
            self._refresh_mode_badges()
        except Exception as e:
            self.update_status(f"Disable/Enable error: {e}", is_error=True)
            messagebox.showerror("Error", f"Could not toggle hosts file:\n{e}", parent=self.root)

    def flush_dns_silent(self):
        if os.name != 'nt':
            return
        try:
            subprocess.run(['ipconfig', '/flushdns'], capture_output=True, check=False, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    # ----------------------------- IP target conversion ----------------------
    def convert_block_ips(self, target: str):
        if target not in BLOCK_SINK_IPS:
            return
        if self._block_during_import("Convert Block IPs"):
            return
        original = self.get_lines()
        rewritten, changed = rewrite_block_sink_ip(original, target)
        if not changed:
            self.update_status(f"All blocking entries already use {target}. No changes made.")
            return

        def apply_to_editor(approved_lines):
            self.set_text(approved_lines)
            self.update_status(f"Rewrote {changed} blocking entr{'y' if changed == 1 else 'ies'} to {target}.")
            self._preferred_block_sink = target

        PreviewWindow(
            self,
            original,
            rewritten,
            title=f"Preview: Convert Block IPs to {target}",
            on_apply_callback=apply_to_editor,
            apply_label=f"Use {target}",
        )

    # ----------------------------- Health Scan -------------------------------
    def show_health_scan(self):
        lines = self.get_lines()
        findings = scan_suspicious_redirects(lines)
        dialog = tk.Toplevel(self.root)
        dialog.title("Hosts Health Scan")
        dialog.configure(bg=PALETTE["base"])
        dialog.transient(self.root)
        dialog.geometry("720x520")

        header = ttk.Label(
            dialog,
            text="Hosts Health Scan",
            font=("Segoe UI Semibold", 14),
        )
        header.pack(anchor='w', padx=16, pady=(16, 4))

        if not findings:
            ttk.Label(
                dialog,
                text="No suspicious redirects detected. Every non-loopback mapping is on a private LAN range.",
                wraplength=660,
                justify="left",
                style="Hint.TLabel",
            ).pack(anchor='w', padx=16, pady=(0, 12))
        else:
            ttk.Label(
                dialog,
                text=(
                    f"Found {len(findings)} entr{'y' if len(findings) == 1 else 'ies'} mapping domains to "
                    "non-loopback, non-LAN IPs. These are a classic malware/hijack indicator — "
                    "verify each one against a legitimate source before keeping it."
                ),
                wraplength=660,
                justify="left",
                foreground=PALETTE["yellow"],
            ).pack(anchor='w', padx=16, pady=(0, 12))

        body = scrolledtext.ScrolledText(
            dialog, wrap=tk.WORD, font=("Consolas", 10),
            bg=PALETTE["crust"], fg=PALETTE["text"], relief="flat",
        )
        body.pack(expand=True, fill='both', padx=16, pady=(0, 12))
        if findings:
            body.insert(tk.END, "Line    IP                  Domain\n")
            body.insert(tk.END, "-----   -----------------   -----------------------------\n")
            for line_idx, ip, domain in findings:
                body.insert(tk.END, f"{line_idx + 1:>5}   {ip:<17}   {domain}\n")
        else:
            body.insert(tk.END, "(clean)\n")
        body.configure(state="disabled")

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(btn_row, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        dialog.grab_set()

    # ----------------------------- Check Domain ------------------------------
    def show_check_domain(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Check Domain")
        dialog.configure(bg=PALETTE["base"])
        dialog.transient(self.root)
        dialog.geometry("720x560")

        ttk.Label(dialog, text="Check Domain", font=("Segoe UI Semibold", 14)).pack(anchor='w', padx=16, pady=(16, 2))
        ttk.Label(
            dialog,
            text="Enter a domain to see whether it's blocked by the editor, on your whitelist, and which curated sources we've fetched that contain it.",
            wraplength=660, justify="left", style="Hint.TLabel",
        ).pack(anchor='w', padx=16, pady=(0, 10))

        query_frame = ttk.Frame(dialog)
        query_frame.pack(fill="x", padx=16)
        query_var = tk.StringVar()
        entry = ttk.Entry(query_frame, textvariable=query_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.focus_set()

        output = scrolledtext.ScrolledText(
            dialog, wrap=tk.WORD, font=("Consolas", 10),
            bg=PALETTE["crust"], fg=PALETTE["text"], relief="flat",
        )
        output.pack(expand=True, fill='both', padx=16, pady=12)
        output.configure(state="disabled")

        def write_output(text):
            output.configure(state="normal")
            output.delete('1.0', tk.END)
            output.insert(tk.END, text)
            output.configure(state="disabled")

        def run_check(_event=None):
            domain = query_var.get().strip().lower().lstrip('.')
            if not domain:
                write_output("Enter a domain to check.")
                return
            if not looks_like_domain(domain, allow_single_label=False):
                write_output(f"'{domain}' does not look like a valid multi-label domain.")
                return

            lines = self.get_lines()
            blocked_on_lines = []
            for idx, line in enumerate(lines):
                parsed, _ = parse_hosts_line_entries(line)
                for _, entry_domain, is_block in parsed:
                    if is_block and (entry_domain == domain or entry_domain.endswith('.' + domain)):
                        blocked_on_lines.append((idx + 1, entry_domain, line.strip()))

            whitelist = self._get_whitelist_set()
            on_whitelist = domain in whitelist or any(
                domain.endswith('.' + w) for w in whitelist
            )

            source_matches = find_sources_containing_domain(domain, self._source_corpus_cache)
            not_yet_fetched = [
                name for category in self.BLOCKLIST_SOURCES.values()
                for name, _, _ in category
                if name not in self._source_corpus_cache
            ]

            buf = [f"Domain: {domain}", ""]
            if blocked_on_lines:
                buf.append(f"BLOCKED in current editor on {len(blocked_on_lines)} line(s):")
                for line_no, matched, raw in blocked_on_lines[:30]:
                    buf.append(f"  line {line_no}: {raw}  ({matched})")
                if len(blocked_on_lines) > 30:
                    buf.append(f"  ...and {len(blocked_on_lines) - 30} more")
            else:
                buf.append("NOT blocked in current editor.")
            buf.append("")
            buf.append(f"Whitelist: {'YES' if on_whitelist else 'no'}")
            buf.append("")
            if source_matches:
                buf.append(f"Found in {len(source_matches)} previously-fetched source(s):")
                for name in source_matches:
                    buf.append(f"  - {name}")
            else:
                buf.append("Not present in any previously-fetched curated source.")
            if not_yet_fetched:
                buf.append("")
                buf.append(f"({len(not_yet_fetched)} source(s) not yet fetched this session — import them to include in this lookup.)")
            write_output('\n'.join(buf))

        ttk.Button(query_frame, text="Check", command=run_check, style="Action.TButton").pack(side="left", padx=(8, 0))
        entry.bind("<Return>", run_check)

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(btn_row, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        dialog.grab_set()

    # ----------------------------- Export ------------------------------------
    def show_export_dialog(self):
        original = self.get_lines()
        whitelist_set = self._get_whitelist_set()
        cleaned, _ = _get_canonical_cleaned_output_and_stats(original, whitelist_set)

        dialog = tk.Toplevel(self.root)
        dialog.title("Export Cleaned Hosts")
        dialog.configure(bg=PALETTE["base"])
        dialog.transient(self.root)
        dialog.geometry("460x260")

        ttk.Label(dialog, text="Export Cleaned Hosts", font=("Segoe UI Semibold", 13)).pack(anchor='w', padx=16, pady=(16, 2))
        ttk.Label(
            dialog,
            text="Choose a format to save the cleaned view under. Whitelist and deduplication are applied first.",
            wraplength=420, justify="left", style="Hint.TLabel",
        ).pack(anchor='w', padx=16, pady=(0, 10))

        format_var = tk.StringVar(value="hosts")
        formats = [
            ("hosts", "Hosts file (what Cleaned Save writes)"),
            ("domains", "Plain domains, one per line"),
            ("adblock", "Adblock / uBlock (||domain^)"),
            ("dnsmasq", "dnsmasq (address=/domain/0.0.0.0)"),
            ("pihole", "Pi-hole gravity (plain domains)"),
        ]
        for value, label in formats:
            ttk.Radiobutton(dialog, text=label, variable=format_var, value=value).pack(anchor='w', padx=20)

        def do_export():
            fmt = format_var.get()
            default_ext = {
                "hosts": ".txt", "domains": ".txt", "adblock": ".txt",
                "dnsmasq": ".conf", "pihole": ".txt",
            }.get(fmt, ".txt")
            path = filedialog.asksaveasfilename(
                parent=dialog,
                title="Export As",
                defaultextension=default_ext,
                initialdir=self.last_open_dir,
                filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            )
            if not path:
                return
            try:
                content = export_lines_as_format(cleaned, fmt)
                write_text_file_atomic(path, content)
                self.last_open_dir = os.path.dirname(path) or self.last_open_dir
                self.update_status(f"Exported {fmt} format to {path}")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Export Error", f"Could not export:\n{e}", parent=dialog)

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=16, pady=(12, 16))
        ttk.Button(btn_row, text="Export…", command=do_export, style="Action.TButton").pack(side="right")
        ttk.Button(btn_row, text="Cancel", command=dialog.destroy, style="Secondary.TButton").pack(side="right", padx=(0, 8))
        dialog.grab_set()

    # ----------------------------- Preferences -------------------------------
    def show_preferences(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Preferences")
        dialog.configure(bg=PALETTE["base"])
        dialog.transient(self.root)
        dialog.geometry("480x260")

        ttk.Label(dialog, text="Preferences", font=("Segoe UI Semibold", 14)).pack(anchor='w', padx=20, pady=(20, 2))
        ttk.Label(
            dialog,
            text="Settings roam via the persistent config file.",
            wraplength=440, justify="left", style="Hint.TLabel",
        ).pack(anchor='w', padx=20, pady=(0, 12))

        row = ttk.Frame(dialog)
        row.pack(fill='x', padx=20, pady=6)
        ttk.Label(row, text="Timestamped backup retention (0-50):").pack(side='left')
        retention_var = tk.IntVar(value=self._backup_retention)
        spin = tk.Spinbox(
            row, from_=0, to=50, textvariable=retention_var, width=6,
            bg=PALETTE["crust"], fg=PALETTE["text"], insertbackground=PALETTE["text"],
            buttonbackground=PALETTE["surface0"], highlightthickness=0, relief="flat",
        )
        spin.pack(side='right')

        row2 = ttk.Frame(dialog)
        row2.pack(fill='x', padx=20, pady=6)
        ttk.Label(row2, text="Default block-sink IP:").pack(side='left')
        sink_var = tk.StringVar(value=self._preferred_block_sink)
        sink_menu = ttk.OptionMenu(row2, sink_var, self._preferred_block_sink, *sorted(BLOCK_SINK_IPS))
        sink_menu.pack(side='right')

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill='x', padx=20, pady=(16, 20))

        def do_save():
            try:
                new_ret = max(0, min(50, int(retention_var.get())))
            except (TypeError, tk.TclError, ValueError):
                new_ret = BACKUP_RETENTION
            self._backup_retention = new_ret
            chosen = sink_var.get()
            if chosen in BLOCK_SINK_IPS:
                self._preferred_block_sink = chosen
            self.save_config()
            dialog.destroy()
            self.update_status(f"Preferences saved: retention={new_ret}, sink={self._preferred_block_sink}.")

        ttk.Button(btn_row, text="Cancel", command=dialog.destroy, style="Secondary.TButton").pack(side="right", padx=(0, 8))
        ttk.Button(btn_row, text="Save", command=do_save, style="Action.TButton").pack(side="right")
        dialog.grab_set()

    # ----------------------------- Scheduled Auto-Update ---------------------
    def show_schedule_wizard(self):
        if os.name != 'nt':
            messagebox.showinfo("Not Supported", "Scheduled auto-update uses Windows Task Scheduler.", parent=self.root)
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Schedule Auto-Update")
        dialog.configure(bg=PALETTE["base"])
        dialog.transient(self.root)
        dialog.geometry("560x340")

        ttk.Label(dialog, text="Schedule Auto-Update", font=("Segoe UI Semibold", 14)).pack(anchor='w', padx=20, pady=(20, 2))
        ttk.Label(
            dialog,
            text=(
                "Registers a Windows Scheduled Task that runs "
                f"`{APP_SLUG} --update` at your chosen interval. The task runs with the highest "
                "privilege level so it can write the hosts file unattended."
            ),
            wraplength=520, justify="left", style="Hint.TLabel",
        ).pack(anchor='w', padx=20, pady=(0, 12))

        freq_frame = ttk.Frame(dialog)
        freq_frame.pack(fill='x', padx=20, pady=6)
        ttk.Label(freq_frame, text="Interval:").pack(side='left')
        freq_var = tk.StringVar(value="DAILY")
        ttk.OptionMenu(freq_frame, freq_var, "DAILY", "DAILY", "WEEKLY", "ONLOGON").pack(side='left', padx=(8, 0))

        time_frame = ttk.Frame(dialog)
        time_frame.pack(fill='x', padx=20, pady=6)
        ttk.Label(time_frame, text="Time (HH:MM, 24h):").pack(side='left')
        time_var = tk.StringVar(value="03:30")
        ttk.Entry(time_frame, textvariable=time_var, width=8).pack(side='left', padx=(8, 0))

        status = ttk.Label(dialog, text="", style="Hint.TLabel", wraplength=520)
        status.pack(anchor='w', padx=20, pady=(8, 0))

        def do_register():
            task_name = "HostsFileGet Auto-Update"
            interpreter = sys.executable
            script = os.path.abspath(sys.argv[0] if not getattr(sys, 'frozen', False) else sys.executable)
            command = f'"{interpreter}" "{script}" --update' if not getattr(sys, 'frozen', False) else f'"{script}" --update'
            tr = command
            freq = freq_var.get()
            args = [
                'schtasks', '/Create', '/TN', task_name, '/TR', tr,
                '/SC', freq, '/RL', 'HIGHEST', '/F',
            ]
            if freq in ("DAILY", "WEEKLY"):
                args += ['/ST', time_var.get().strip() or "03:30"]
            try:
                proc = subprocess.run(args, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if proc.returncode == 0:
                    status.config(text=f"Task '{task_name}' registered successfully.", foreground=PALETTE["green"])
                    self.update_status(f"Scheduled auto-update: {freq} @ {time_var.get()}.")
                else:
                    err = (proc.stderr or proc.stdout or "").strip() or f"schtasks exit {proc.returncode}"
                    status.config(text=err, foreground=PALETTE["red"])
            except Exception as e:
                status.config(text=f"Failed to register task: {e}", foreground=PALETTE["red"])

        def do_unregister():
            task_name = "HostsFileGet Auto-Update"
            try:
                proc = subprocess.run(
                    ['schtasks', '/Delete', '/TN', task_name, '/F'],
                    capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if proc.returncode == 0:
                    status.config(text="Task removed.", foreground=PALETTE["yellow"])
                else:
                    status.config(text=(proc.stderr or proc.stdout).strip(), foreground=PALETTE["red"])
            except Exception as e:
                status.config(text=f"Failed to remove task: {e}", foreground=PALETTE["red"])

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill='x', padx=20, pady=(16, 20))
        ttk.Button(btn_row, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        ttk.Button(btn_row, text="Remove Schedule", command=do_unregister, style="Danger.TButton").pack(side="right", padx=(0, 8))
        ttk.Button(btn_row, text="Register / Replace", command=do_register, style="Action.TButton").pack(side="right", padx=(0, 8))
        dialog.grab_set()

    # ----------------------------- Goto Anything -----------------------------
    def show_goto_anything(self, _event=None):
        lines = self.get_lines()
        # Collect candidates: every domain in editor + source name + custom source name.
        candidates: list[tuple[str, str, int | None]] = []
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            if _is_comment_line(stripped):
                continue
            parsed, _ = parse_hosts_line_entries(line)
            for _, domain, _ in parsed:
                candidates.append((domain, "editor domain", idx + 1))
        seen: set[str] = set()
        unique_candidates: list[tuple[str, str, int | None]] = []
        for domain, kind, ln in candidates:
            if domain in seen:
                continue
            seen.add(domain)
            unique_candidates.append((domain, kind, ln))
        for category, sources in self.BLOCKLIST_SOURCES.items():
            for name, _url, _tooltip in sources:
                unique_candidates.append((f"{name} — {category}", "curated source", None))
        for entry in self.custom_sources:
            unique_candidates.append((entry["name"], "custom source", None))

        dialog = tk.Toplevel(self.root)
        dialog.title("Goto Anything")
        dialog.configure(bg=PALETTE["base"])
        dialog.transient(self.root)
        dialog.geometry("640x440")

        query_var = tk.StringVar()
        entry = ttk.Entry(dialog, textvariable=query_var, font=("Segoe UI", 11))
        entry.pack(fill='x', padx=12, pady=(12, 4))
        entry.focus_set()

        listbox = tk.Listbox(
            dialog, bg=PALETTE["crust"], fg=PALETTE["text"],
            selectbackground=PALETTE["blue"], selectforeground=PALETTE["crust"],
            font=("Consolas", 10), relief="flat", highlightthickness=0, borderwidth=0, activestyle="none",
        )
        listbox.pack(expand=True, fill='both', padx=12, pady=(0, 12))

        current_results: list[tuple[str, str, int | None]] = []

        def refresh(*_a):
            query = query_var.get().strip()
            listbox.delete(0, tk.END)
            current_results.clear()
            if not query:
                ranked = [(c, 0) for c in unique_candidates[:200]]
            else:
                scored = [(c, fuzzy_score(query, c[0])) for c in unique_candidates]
                ranked = [pair for pair in scored if pair[1] >= 0]
                ranked.sort(key=lambda p: p[1], reverse=True)
                ranked = ranked[:200]
            for (label, kind, ln), _score in ranked:
                suffix = f" (line {ln})" if ln else ""
                listbox.insert(tk.END, f"[{kind}] {label}{suffix}")
                current_results.append((label, kind, ln))

        def on_enter(_event=None):
            try:
                sel = listbox.curselection()
                if not sel and current_results:
                    sel = (0,)
                if not sel:
                    return
                label, kind, ln = current_results[sel[0]]
                dialog.destroy()
                if ln:
                    self.text_area.mark_set('insert', f"{ln}.0")
                    self.text_area.see(f"{ln}.0")
                elif kind == "curated source":
                    self.source_filter_var.set(label.split(" — ")[0])
                return "break"
            except (IndexError, tk.TclError):
                return

        query_var.trace_add('write', refresh)
        entry.bind("<Down>", lambda e: (listbox.focus_set(), listbox.selection_set(0) if listbox.size() else None, "break")[-1])
        entry.bind("<Return>", on_enter)
        listbox.bind("<Return>", on_enter)
        listbox.bind("<Double-Button-1>", on_enter)
        dialog.bind("<Escape>", lambda _e: dialog.destroy())
        refresh()
        dialog.grab_set()

    # ----------------------------- Sources Report ----------------------------
    def show_sources_report(self):
        lines = self.get_lines()
        buckets = summarize_source_contributions(lines)
        dialog = tk.Toplevel(self.root)
        dialog.title("Sources Report")
        dialog.configure(bg=PALETTE["base"])
        dialog.transient(self.root)
        dialog.geometry("720x520")

        ttk.Label(dialog, text="Sources Report", font=("Segoe UI Semibold", 14)).pack(anchor='w', padx=16, pady=(16, 2))
        ttk.Label(
            dialog,
            text="Ranked by blocking-entry contribution. Use this to prune bloated or redundant feeds.",
            wraplength=660, justify="left", style="Hint.TLabel",
        ).pack(anchor='w', padx=16, pady=(0, 10))

        body = scrolledtext.ScrolledText(
            dialog, wrap=tk.NONE, font=("Consolas", 10),
            bg=PALETTE["crust"], fg=PALETTE["text"], relief="flat",
        )
        body.pack(expand=True, fill='both', padx=16, pady=(0, 12))

        if not buckets:
            body.insert(tk.END, "(editor is empty)\n")
        else:
            total_blocks = sum(b["blocking_entries"] for b in buckets) or 1
            body.insert(tk.END, f"{'Source':<50} {'Blocks':>10} {'Lines':>10} {'Share':>8}\n")
            body.insert(tk.END, "-" * 80 + "\n")
            for b in buckets:
                share = 100.0 * b["blocking_entries"] / total_blocks
                name = b["name"][:49]
                body.insert(tk.END, f"{name:<50} {b['blocking_entries']:>10,} {b['total_lines']:>10,} {share:>7.1f}%\n")
        body.configure(state="disabled")

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(btn_row, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        dialog.grab_set()

    # ----------------------------- First-Run Wizard --------------------------
    FIRST_RUN_BUNDLES = [
        ("Ads & tracking", True, [
            ("HaGezi Pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt"),
            ("StevenBlack Unified", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
            ("EasyList Hosts", "https://v.firebog.net/hosts/Easylist.txt"),
        ]),
        ("Malware & phishing", True, [
            ("URLHaus Malware", "https://urlhaus.abuse.ch/downloads/hostfile/"),
            ("Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt"),
            ("Scam Domains Wildcard", "https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/wildcard_domains/scams.txt"),
        ]),
        ("Windows / Microsoft telemetry", False, [
            ("Windows Spy Blocker", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"),
            ("jmdugan Microsoft", "https://raw.githubusercontent.com/jmdugan/blocklists/master/corporations/microsoft/all"),
        ]),
        ("Adult / NSFW", False, [
            ("Sinfonietta Pornography", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts"),
            ("BlocklistProject Porn", "https://blocklistproject.github.io/Lists/porn.txt"),
        ]),
        ("Gambling", False, [
            ("BlocklistProject Gambling", "https://blocklistproject.github.io/Lists/gambling.txt"),
        ]),
        ("Social media (opt-in distraction block)", False, [
            ("Sinfonietta Social", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/social-hosts"),
        ]),
    ]

    def maybe_show_first_run_wizard(self):
        if self._has_completed_first_run:
            return
        # Don't show if user already has an existing whitelist or custom
        # sources — those signal returning users whose config predated
        # v2.14 where this flag was introduced.
        if self.custom_sources or self._last_saved_whitelist_text.strip():
            self._has_completed_first_run = True
            self.save_config()
            return
        self._safe_after(400, self.show_first_run_wizard)

    def show_first_run_wizard(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Welcome to HostsFileGet")
        dialog.configure(bg=PALETTE["base"])
        dialog.transient(self.root)
        dialog.geometry("640x560")

        ttk.Label(dialog, text=f"Welcome to {APP_NAME}", font=("Segoe UI Semibold", 16)).pack(anchor='w', padx=20, pady=(20, 2))
        ttk.Label(
            dialog,
            text=(
                "Pick the categories you want blocked and we'll import a small curated starter set "
                "for each one. You can always add more sources later from the sidebar."
            ),
            wraplength=600, justify="left", style="Hint.TLabel",
        ).pack(anchor='w', padx=20, pady=(0, 12))

        body = ttk.Frame(dialog)
        body.pack(expand=True, fill='both', padx=20)

        vars_by_category: dict[str, tk.BooleanVar] = {}
        for label, default_on, _ in self.FIRST_RUN_BUNDLES:
            var = tk.BooleanVar(value=default_on)
            vars_by_category[label] = var
            ttk.Checkbutton(body, text=label, variable=var).pack(anchor='w', pady=2)

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=20, pady=(12, 20))

        def do_apply():
            selected: list[tuple[str, str]] = []
            for label, _, sources in self.FIRST_RUN_BUNDLES:
                if vars_by_category[label].get():
                    selected.extend(sources)
            self._has_completed_first_run = True
            self.save_config()
            dialog.destroy()
            if selected:
                self.start_import_worker(selected)

        def do_skip():
            self._has_completed_first_run = True
            self.save_config()
            dialog.destroy()

        ttk.Button(btn_row, text="Skip for now", command=do_skip, style="Secondary.TButton").pack(side="left")
        ttk.Button(btn_row, text="Import Selected", command=do_apply, style="Action.TButton").pack(side="right")
        dialog.grab_set()

    # ----------------------------- Panic Restore -----------------------------
    def panic_restore_stock(self):
        """Replace the editor with the stock Microsoft default hosts.

        Unlike ``revert_to_backup`` this does not depend on any user-created
        snapshot — handy when every backup is also broken or when the user
        just wants the original Windows baseline back.
        """
        if self._block_during_import("Panic Restore"):
            return
        if not messagebox.askyesno(
            "Panic Restore",
            "Replace the editor with the Microsoft default hosts file?\n\n"
            "Your current editor content is discarded. Use File > Save Raw "
            "to commit the stock template to disk.",
            parent=self.root,
        ):
            return
        lines = STOCK_MICROSOFT_HOSTS.splitlines()
        self.set_text(lines)
        self.update_status("Panic Restore: loaded Microsoft default into editor. Save Raw to apply.")

    # ----------------------------- Granular Cleanup --------------------------
    def _granular_cleanup(self, *, drop_comments=False, drop_blanks=False, drop_invalid=False, label: str = "Cleanup"):
        if self._block_during_import(label):
            return
        original = self.get_lines()
        cleaned, stats = strip_lines_by_category(
            original,
            drop_comments=drop_comments,
            drop_blanks=drop_blanks,
            drop_invalid=drop_invalid,
        )
        total_removed = sum(stats.values())
        if total_removed == 0:
            self.update_status(f"{label}: nothing to remove — editor is already clean.")
            return

        def apply_to_editor(approved_lines):
            self.set_text(approved_lines)
            parts = []
            if stats["removed_comments"]:
                parts.append(f"{stats['removed_comments']:,} comments")
            if stats["removed_blanks"]:
                parts.append(f"{stats['removed_blanks']:,} blank lines")
            if stats["removed_invalid"]:
                parts.append(f"{stats['removed_invalid']:,} invalid lines")
            self.update_status(f"{label}: removed " + ", ".join(parts) + ".")

        PreviewWindow(
            self,
            original,
            cleaned,
            title=f"Preview: {label}",
            on_apply_callback=apply_to_editor,
            apply_label="Apply",
        )

    def cleanup_comments_only(self):
        self._granular_cleanup(drop_comments=True, label="Remove Comments")

    def cleanup_blanks_only(self):
        self._granular_cleanup(drop_blanks=True, label="Remove Blank Lines")

    def cleanup_invalid_only(self):
        self._granular_cleanup(drop_invalid=True, label="Remove Invalid Lines")

    # ----------------------------- Kill Import Section -----------------------
    def show_remove_import_section(self):
        if self._block_during_import("Remove Import Section"):
            return
        lines = self.get_lines()
        sections = discover_import_sections(lines)
        if not sections:
            self.update_status("No import sections detected. Sections require `# --- Raw|Normalized Import Start/End: NAME ---` markers.")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Remove Import Section")
        dialog.configure(bg=PALETTE["base"])
        dialog.transient(self.root)
        dialog.geometry("620x480")

        ttk.Label(dialog, text="Remove Import Section", font=("Segoe UI Semibold", 13)).pack(anchor='w', padx=16, pady=(16, 2))
        ttk.Label(
            dialog,
            text="Each row is an imported source block detected in the editor. Removing a section deletes every line between its Start and End markers, including the markers themselves.",
            wraplength=580, justify="left", style="Hint.TLabel",
        ).pack(anchor='w', padx=16, pady=(0, 10))

        list_frame = ttk.Frame(dialog)
        list_frame.pack(expand=True, fill='both', padx=16, pady=(0, 12))

        selected = {idx: tk.BooleanVar(value=False) for idx, _ in enumerate(sections)}
        for idx, section in enumerate(sections):
            label = (
                f"[{section['mode']}] {section['name']}  "
                f"(lines {section['start']+1:,} - {section['end']+1:,}, "
                f"{section['end'] - section['start'] + 1:,} lines)"
            )
            ttk.Checkbutton(list_frame, text=label, variable=selected[idx]).pack(anchor='w', padx=4, pady=2)

        def do_remove():
            targets = [sections[i] for i, var in selected.items() if var.get()]
            if not targets:
                dialog.destroy()
                return
            # Delete in reverse index order so later sections' indices stay valid.
            new_lines = list(lines)
            for section in sorted(targets, key=lambda s: s["start"], reverse=True):
                new_lines = remove_import_section(new_lines, section)

            def apply_to_editor(approved_lines):
                self.set_text(approved_lines)
                self.update_status(
                    f"Removed {len(targets)} import section(s), "
                    f"{len(lines) - len(approved_lines):,} line(s) deleted."
                )
                dialog.destroy()

            PreviewWindow(
                self,
                lines,
                new_lines,
                title="Preview: Remove Import Section(s)",
                on_apply_callback=apply_to_editor,
                apply_label="Remove Section(s)",
            )

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(btn_row, text="Remove Selected", command=do_remove, style="Danger.TButton").pack(side="right")
        ttk.Button(btn_row, text="Cancel", command=dialog.destroy, style="Secondary.TButton").pack(side="right", padx=(0, 8))
        dialog.grab_set()

    # ----------------------------- DNS Resolver / Ping -----------------------
    def _ctx_resolve_domain(self):
        _, _, domain = self._ctx_line_info()
        if not domain:
            self.update_status("No domain detected at cursor.", is_error=True)
            return
        import socket
        try:
            infos = socket.getaddrinfo(domain, None)
        except socket.gaierror as e:
            messagebox.showinfo("Resolve Domain", f"{domain}\n\nResolution failed: {e}", parent=self.root)
            return
        addrs = sorted({info[4][0] for info in infos})
        messagebox.showinfo(
            "Resolve Domain",
            f"{domain}\n\n" + "\n".join(addrs) if addrs else f"{domain}\n\n(no addresses)",
            parent=self.root,
        )

    def _ctx_ping_domain(self):
        _, _, domain = self._ctx_line_info()
        if not domain:
            self.update_status("No domain detected at cursor.", is_error=True)
            return
        if os.name != 'nt':
            self.update_status("Ping is only wired for Windows in this build.", is_error=True)
            return

        def worker():
            try:
                proc = subprocess.run(
                    ['ping', '-n', '4', '-w', '1500', domain],
                    capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                output = proc.stdout.strip() or proc.stderr.strip() or "(no output)"
            except Exception as e:
                output = f"Ping failed: {e}"
            self._safe_after(0, lambda o=output: messagebox.showinfo(f"Ping {domain}", o, parent=self.root))

        threading.Thread(target=worker, daemon=True).start()
        self.update_status(f"Pinging {domain}…")

    # ----------------------------- Editor Context Menu -----------------------
    def _build_editor_context_menu(self):
        menu = tk.Menu(
            self.text_area, tearoff=0,
            bg=PALETTE["mantle"], fg=PALETTE["text"],
            activebackground=PALETTE["blue"], activeforeground="#0b1020",
        )
        menu.add_command(label="Whitelist this domain", command=self._ctx_whitelist_domain)
        menu.add_command(label="Copy domain", command=self._ctx_copy_domain)
        menu.add_separator()
        menu.add_command(label="Toggle comment on selection", command=self.toggle_selection_comment)
        menu.add_command(label="Remove this line", command=self._ctx_remove_line)
        menu.add_separator()
        menu.add_command(label="Resolve domain (real DNS)", command=self._ctx_resolve_domain)
        menu.add_command(label="Ping domain", command=self._ctx_ping_domain)
        menu.add_separator()
        menu.add_command(label="Check this domain…", command=self._ctx_check_domain)
        self._editor_context_menu = menu

    def _ctx_line_info(self):
        try:
            idx = self.text_area.index("insert")
            line_no = int(idx.split('.')[0])
            line = self.text_area.get(f"{line_no}.0", f"{line_no}.end")
        except tk.TclError:
            return None, None, None
        parsed, _ = parse_hosts_line_entries(line)
        domain = parsed[0][1] if parsed else None
        return line_no, line, domain

    def _ctx_whitelist_domain(self):
        _, _, domain = self._ctx_line_info()
        if not domain:
            self.update_status("No domain detected at cursor.", is_error=True)
            return
        current = self.whitelist_text_area.get('1.0', tk.END).strip()
        entries = set(line.strip().lower() for line in current.splitlines() if line.strip())
        if domain in entries:
            self.update_status(f"'{domain}' is already in the whitelist.")
            return
        new_text = (current + '\n' + domain).strip() if current else domain
        self.whitelist_text_area.delete('1.0', tk.END)
        self.whitelist_text_area.insert('1.0', new_text + '\n')
        self._cached_whitelist_text = None  # invalidate
        self._trigger_ui_update()
        self.update_status(f"Added '{domain}' to whitelist.")

    def _ctx_copy_domain(self):
        _, _, domain = self._ctx_line_info()
        if not domain:
            self.update_status("No domain detected at cursor.", is_error=True)
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(domain)
            self.update_status(f"Copied '{domain}' to clipboard.")
        except tk.TclError:
            self.update_status("Clipboard unavailable.", is_error=True)

    def _ctx_remove_line(self):
        line_no, _, _ = self._ctx_line_info()
        if line_no is None:
            return
        try:
            self.text_area.delete(f"{line_no}.0", f"{line_no + 1}.0")
            self._trigger_ui_update()
            self.update_status(f"Removed line {line_no}.")
        except tk.TclError:
            pass

    def _ctx_check_domain(self):
        _, _, domain = self._ctx_line_info()
        self.show_check_domain()
        # Best-effort: prefill the dialog's query. We rely on it being the
        # topmost Toplevel that just opened.
        if domain:
            try:
                top = self.root.tk.call('winfo', 'children', '.')
                # Can't reliably prefill without refactoring the dialog to
                # return its entry. Status message is the minimum signal.
            except tk.TclError:
                pass

    def toggle_selection_comment(self, _event=None):
        try:
            if self.text_area.tag_ranges("sel"):
                first = self.text_area.index("sel.first")
                last = self.text_area.index("sel.last")
            else:
                cursor = self.text_area.index("insert")
                first = f"{cursor.split('.')[0]}.0"
                last = f"{int(cursor.split('.')[0]) + 1}.0"
            start_line = int(first.split('.')[0])
            end_line = int(last.split('.')[0])
            if last.endswith('.0') and end_line > start_line:
                end_line -= 1
        except tk.TclError:
            return "break"

        lines = [self.text_area.get(f"{ln}.0", f"{ln}.end") for ln in range(start_line, end_line + 1)]
        all_commented = all(not line.strip() or line.lstrip().startswith('#') for line in lines)
        new_lines = []
        for line in lines:
            if all_commented:
                stripped = line.lstrip()
                if stripped.startswith('#'):
                    lead = line[: len(line) - len(stripped)]
                    after = stripped[1:]
                    if after.startswith(' '):
                        after = after[1:]
                    new_lines.append(lead + after)
                else:
                    new_lines.append(line)
            else:
                if line.strip():
                    new_lines.append('# ' + line)
                else:
                    new_lines.append(line)

        self.text_area.delete(f"{start_line}.0", f"{end_line}.end")
        self.text_area.insert(f"{start_line}.0", '\n'.join(new_lines))
        self._trigger_ui_update()
        return "break"

    def _show_editor_context_menu(self, event):
        try:
            self.text_area.mark_set("insert", f"@{event.x},{event.y}")
            self._editor_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._editor_context_menu.grab_release()

    # ----------------------------- Preview Source ----------------------------
    def preview_blocklist_source(self, name: str, url: str):
        if not url:
            return
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Preview Source: {name}")
        dialog.configure(bg=PALETTE["base"])
        dialog.transient(self.root)
        dialog.geometry("760x540")

        ttk.Label(dialog, text=f"Preview: {name}", font=("Segoe UI Semibold", 13)).pack(anchor='w', padx=16, pady=(16, 2))
        ttk.Label(
            dialog,
            text=f"{url}\nFirst ~{SOURCE_PREVIEW_MAX_LINES} lines fetched below. This does NOT import; use the source button to import.",
            wraplength=720, justify="left", style="Hint.TLabel",
        ).pack(anchor='w', padx=16, pady=(0, 8))

        body = scrolledtext.ScrolledText(
            dialog, wrap=tk.NONE, font=("Consolas", 10),
            bg=PALETTE["crust"], fg=PALETTE["text"], relief="flat",
        )
        body.pack(expand=True, fill='both', padx=16, pady=(0, 12))
        body.insert(tk.END, "Fetching…\n")
        body.configure(state="disabled")

        def write_body(text: str):
            try:
                if not dialog.winfo_exists():
                    return
                body.configure(state="normal")
                body.delete('1.0', tk.END)
                body.insert(tk.END, text)
                body.configure(state="disabled")
            except tk.TclError:
                pass

        def worker():
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as response:
                    if response.getcode() != 200:
                        raise urllib.error.HTTPError(url, response.getcode(), f"HTTP {response.getcode()}", response.info(), response.fp)
                    raw = read_http_body_limited(response, max_bytes=SOURCE_PREVIEW_MAX_BYTES)
                    lines = decode_downloaded_lines(
                        url, raw, response.headers.get("Content-Encoding", "")
                    )
                if looks_like_html_document(lines):
                    self._safe_after(0, lambda: write_body(
                        "This URL returned HTML rather than a hosts list — the feed may be behind a captive page or has moved."
                    ))
                    return
                snippet = '\n'.join(lines[:SOURCE_PREVIEW_MAX_LINES])
                truncated = len(lines) > SOURCE_PREVIEW_MAX_LINES
                if truncated:
                    snippet += f"\n\n… ({len(lines) - SOURCE_PREVIEW_MAX_LINES} more lines not shown)"
                self._safe_after(0, lambda: write_body(snippet or "(empty)"))
            except Exception as e:
                self._safe_after(0, lambda err=e: write_body(f"Could not fetch preview:\n{err}"))

        threading.Thread(target=worker, daemon=True).start()

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(btn_row, text="Import This Source", command=lambda: (dialog.destroy(), self.start_single_import(name, url)), style="Action.TButton").pack(side="right")
        ttk.Button(btn_row, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right", padx=(0, 8))

    def load_file(self, is_initial_load=False):
        if not is_initial_load and self._block_during_import("Refresh"):
            return
        try:
            if os.path.exists(self.HOSTS_FILE_PATH):
                if not is_initial_load and self._has_unsaved_changes():
                    if not messagebox.askyesno("Reload From Disk", "Reload from disk and discard the current unsaved editor changes?", parent=self.root):
                        return

                lines = read_text_file_lines(self.HOSTS_FILE_PATH)

                file_hash = self._hash_lines(lines)
                self._last_applied_raw_hash, self._last_applied_cleaned_hash = resolve_saved_state_hashes(
                    file_hash,
                    self._last_applied_raw_hash,
                    self._last_applied_cleaned_hash,
                )
                self.set_text(lines)

                self.update_status(f"Loaded hosts file: '{self.HOSTS_FILE_PATH}'")
            else:
                if is_initial_load:
                    self._last_applied_raw_hash = None
                    self._last_applied_cleaned_hash = None
                    self._update_save_button_state()
                self.update_status("Hosts file not found.", is_error=True)
        except Exception as e:
            self.update_status(f"Error loading file: {e}", is_error=True)
            messagebox.showerror("Error", f"Error loading file:\n{e}", parent=self.root)

    # ----------------------------- Save Logic (Split) -----------------------------------
    
    def _block_during_import(self, action_label: str) -> bool:
        """Return True and show a warning if a batch import is running.

        Saving or reloading while an import is mid-flight writes a
        partial/inconsistent snapshot of the editor. Rather than silently
        allowing it, surface a clear status message and tell the user to
        wait or Stop Import.
        """
        if self.is_importing:
            self.update_status(
                f"{action_label} blocked: a batch import is running. "
                "Wait for it to finish or click Stop Import.",
                is_error=True,
            )
            return True
        return False

    def save_raw_file(self):
        if self._block_during_import("Save Raw"):
            return
        lines = self.get_lines()
        content = '\n'.join(lines)

        if self.dry_run_mode.get():
            self.update_status(f"Dry-run: Reviewed Raw Save for {len(lines)} line(s). No file write performed.")
            return

        if not self._execute_save(content, source_description="Raw Save"):
            return

        self._last_applied_raw_hash = self._hash_lines(lines)
        self._last_applied_cleaned_hash = None
        self._update_save_button_state(_lines=lines, _current_hash=self._last_applied_raw_hash)
        self.update_status(f"Success: Saved Raw hosts file ({len(lines)} line(s)).")


    def save_cleaned_file(self):
        if self._block_during_import("Save Cleaned"):
            return
        original_lines = self.get_lines()
        whitelist_set = self._get_whitelist_set()
        
        final_lines, stats = _get_canonical_cleaned_output_and_stats(original_lines, whitelist_set)
        total_discarded = stats["total_discarded"]
        change_summary = summarize_clean_changes(total_discarded, stats["transformed"])

        def proceed_with_save(approved_lines):
            content = '\n'.join(approved_lines)
            
            if self.dry_run_mode.get():
                self.update_status(f"Dry-run: Applied the cleaned preview to the editor only. No file write performed. {change_summary}")
                self.set_text(approved_lines, update_hash=False, is_cleaned=True)
                return
            
            if not self._execute_save(content, source_description="Cleaned Save"):
                return
            
            self.set_text(approved_lines, update_hash=True, is_cleaned=True)
            self.update_status(f"Success: Saved Cleaned hosts file. {change_summary}")
            
        if original_lines != final_lines:
            PreviewWindow(
                self,
                original_lines,
                final_lines,
                title="Preview: Final Changes (Cleaned, Normalized & Whitelisted)",
                on_apply_callback=proceed_with_save,
                stats=stats,
                apply_label="Save Cleaned",
            )
        else:
            content = '\n'.join(original_lines)
            if self.dry_run_mode.get():
                 self.update_status("Dry-run: Save Cleaned detected no changes. No write performed.")
                 return
            if not self._execute_save(content, source_description="Cleaned Save (No Changes)"):
                return
            self._last_applied_cleaned_hash = self._hash_lines(original_lines)
            self._last_applied_raw_hash = None
            self._update_save_button_state(_lines=original_lines, _current_hash=self._last_applied_cleaned_hash)
            self.update_status("Success: Saved Cleaned hosts file. No normalization changes were needed.")


    def _execute_save(self, content_to_save, source_description):
        if not self.is_admin:
            messagebox.showerror("Error", f"{source_description} failed: Permission denied. Run as Administrator.", parent=self.root)
            self.update_status(f"{source_description} failed: Permission denied.", is_error=True)
            return False

        if not content_to_save.strip():
            if not messagebox.askyesno("Save Empty Hosts File", "The editor is empty. Replace the current hosts file with an empty one?", parent=self.root):
                return False

        try:
            self._rotate_backups()
        except Exception as e:
            if not messagebox.askyesno("Backup Could Not Be Created", f"Could not create a backup before saving.\nError: {e}\n\nContinue anyway?", parent=self.root):
                return False

        try:
            write_text_file_atomic(self.HOSTS_FILE_PATH, content_to_save)
            return True
        except PermissionError as e:
            # On Windows this usually means the hosts file has its
            # read-only attribute set or is currently locked by security
            # software. Give the user an actionable hint instead of a
            # bare PermissionError traceback.
            hint = ""
            if os.name == 'nt':
                hint = (
                    "\n\nCommon causes on Windows:\n"
                    "- The hosts file is set read-only (attrib -R to clear).\n"
                    "- Security software is holding a lock on the file.\n"
                    "- An earlier import is still being indexed."
                )
            self.update_status(f"{source_description} permission denied: {e}", is_error=True)
            messagebox.showerror("Permission Denied", f"{source_description} could not write the hosts file:\n{e}{hint}", parent=self.root)
            return False
        except Exception as e:
            self.update_status(f"{source_description} error: {e}", is_error=True)
            messagebox.showerror("Error", f"{source_description} error: {e}", parent=self.root)
            return False

    # ----------------------- Revert to Backup (Preview + Apply) ----------------
    def revert_to_backup(self):
        if self._block_during_import("Revert to Backup"):
            return
        backup_path = self.HOSTS_FILE_PATH + ".bak"
        if not os.path.exists(backup_path):
            self.update_status("No backup is available yet. Save once to create one.", is_error=True)
            return

        try:
            current_lines = read_text_file_lines(self.HOSTS_FILE_PATH)
        except Exception as e:
            self.update_status(f"Error reading current hosts: {e}", is_error=True)
            messagebox.showerror("Error", f"Error reading current hosts:\n{e}", parent=self.root)
            return

        try:
            backup_lines = read_text_file_lines(backup_path)
        except Exception as e:
            self.update_status(f"Error reading backup: {e}", is_error=True)
            messagebox.showerror("Error", f"Error reading backup:\n{e}", parent=self.root)
            return

        def do_restore(approved_lines):
            try:
                if self._has_unsaved_changes():
                    if not messagebox.askyesno(
                        "Discard Unsaved Changes",
                        "Restoring from backup will replace your current unsaved editor content. Continue?",
                        parent=self.root,
                    ):
                        # Give the user visible feedback that the whole
                        # revert flow was cancelled. Without this the
                        # preview window vanishes silently and it looks
                        # like the app did nothing.
                        self.update_status("Restore from backup cancelled.")
                        return

                if self.dry_run_mode.get():
                    self.update_status("Dry-run: Would have restored from backup.")
                    self.set_text(approved_lines, update_hash=False, is_cleaned=False)
                    return
                
                if not self._execute_save('\n'.join(approved_lines), source_description="Restore from Backup"):
                    return
                self.set_text(approved_lines, update_hash=True, is_cleaned=False) 
                self.update_status("Success: Restored the hosts file from backup.")
            except Exception as e:
                self.update_status(f"Restore error: {e}", is_error=True)
                messagebox.showerror("Error", f"Restore error: {e}", parent=self.root)

        PreviewWindow(
            self,
            current_lines,
            backup_lines,
            title="Preview: Restore from Backup",
            on_apply_callback=do_restore,
            apply_label="Restore Backup",
        )

    # ----------------------------- Threaded Imports -----------------------------
    
    def _apply_import_mode_filter(self, source_name: str, lines: list[str], import_mode: str) -> list[str]:
        # Scrub newlines and control characters out of the source name so a
        # malicious or malformed source label can't inject extra lines into
        # the generated Start/End markers.
        safe_name = re.sub(r'[\r\n\t]+', ' ', str(source_name)).strip() or "Imported Source"

        if import_mode == "Normalized":
            normalized_lines = []
            seen_entries = set()
            for line in lines:
                line_entries, _, _ = normalize_line_to_hosts_entries(line)
                for normalized in line_entries:
                    if normalized not in seen_entries:
                        normalized_lines.append(normalized)
                        seen_entries.add(normalized)

            if not normalized_lines:
                return []

            normalized_lines.insert(0, f"# --- Normalized Import Start: {safe_name} ---")
            normalized_lines.append(f"# --- Normalized Import End: {safe_name} ---")
            return normalized_lines
        else:
            if not lines:
                return []
            raw_lines = [f"# --- Raw Import Start: {safe_name} ---"]
            raw_lines.extend(lines)
            raw_lines.append(f"# --- Raw Import End: {safe_name} ---")
            return raw_lines

    def start_single_import(self, name, url):
        self.start_import_worker([(name, url)])

    def start_import_all(self):
        # Trigger the new Selection Dialog
        dialog = BulkSelectionDialog(self.root, self.BLOCKLIST_SOURCES, self.custom_sources)
        self.root.wait_window(dialog)
        
        if dialog.result:
            self.start_import_worker(dialog.result)

    def start_import_worker(self, sources):
        if not sources:
             self.update_status("No import sources were selected.", is_error=True)
             return

        if self.is_importing:
             self.update_status("An import is already in progress.", is_error=True)
             return
             
        self.is_importing = True
        self.stop_import_flag.clear()
        self._set_import_controls_enabled(False)
        self.stop_btn.configure(state="normal")
        self._set_status_hint("Batch imports run sequentially. Stop waits for the current download step.")
        
        # UI Prep
        self.progress_bar.pack(side=tk.RIGHT, padx=10)
        self.stop_btn.pack(side=tk.RIGHT, padx=5)
        self.progress_bar['value'] = 0
        self.progress_bar['maximum'] = len(sources)
        
        mode = self.import_mode.get()
        self.update_status(f"Preparing {len(sources)} source(s) for import in {mode} mode.")
        self.current_import_thread = threading.Thread(target=self._import_worker_thread, args=(sources, mode), daemon=True)
        self.current_import_thread.start()

        self._safe_after(100, self._check_import_queue)

    def _summarize_failure_messages(self, failure_messages, limit=6):
        preview_lines = failure_messages[:limit]
        summary = "\n".join(f"- {line}" for line in preview_lines)
        remaining = len(failure_messages) - len(preview_lines)
        if remaining > 0:
            summary += f"\n- ...and {remaining} more"
        return summary

    def _finish_import_ui(self):
        self.is_importing = False
        self.current_import_thread = None
        self.progress_bar.pack_forget()
        self.stop_btn.pack_forget()
        self.stop_btn.configure(state="normal")
        self._set_import_controls_enabled(True)
        self._set_status_hint()

    def cancel_import(self):
        if not self.is_importing or self.stop_import_flag.is_set():
            return

        self.stop_import_flag.set()
        self.stop_btn.configure(state="disabled")
        self.update_status("Warning: Stopping import after the current download step.", is_error=False)

    def _import_worker_thread(self, sources, mode):
        accumulated_lines = []
        total = len(sources)
        success_count = 0
        failure_messages = []
        
        for i, (name, url) in enumerate(sources):
            if self.stop_import_flag.is_set():
                self.import_queue.put(("cancelled",))
                return

            self.import_queue.put(("progress", i, total, name))
            
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                # Use timeout to prevent hanging
                with urllib.request.urlopen(req, timeout=15) as response:
                    if response.getcode() != 200:
                         raise urllib.error.HTTPError(url, response.getcode(), f"HTTP {response.getcode()}", response.info(), response.fp)
                    raw_lines = decode_downloaded_lines(
                        url,
                        read_http_body_limited(response),
                        response.headers.get("Content-Encoding", "")
                    )
                    if looks_like_html_document(raw_lines):
                        raise ValueError("Received HTML instead of a hosts list.")
                    if self.stop_import_flag.is_set():
                        self.import_queue.put(("cancelled",))
                        return

                # Record success metadata so the "Check Domain" tool can
                # cross-reference without re-fetching, and tooltips can show
                # freshness.
                self.import_queue.put(("source_fetched", name, url, raw_lines))

                processed = self._apply_import_mode_filter(name, raw_lines, mode)
                if self.stop_import_flag.is_set():
                    self.import_queue.put(("cancelled",))
                    return
                accumulated_lines.extend(processed)
                success_count += 1
                
            except Exception as e:
                failure_messages.append(f"{name}: {e}")
                self.import_queue.put(("log", f"Failed to import {name}: {e}", True))
                # Continue to next list even if one fails
        
        self.import_queue.put(("done", accumulated_lines, total, success_count, failure_messages))

    def _check_import_queue(self):
        # Root may already be destroyed if the user closed the app mid-import.
        try:
            if not self.root.winfo_exists():
                return
        except tk.TclError:
            return

        try:
            while True:
                msg = self.import_queue.get_nowait()
                msg_type = msg[0]
                
                if msg_type == "progress":
                    i, total, name = msg[1], msg[2], msg[3]
                    self.progress_bar['value'] = i + 1
                    self.update_status(f"Importing source {i+1} of {total}: {name}...")

                elif msg_type == "source_fetched":
                    name, url, raw_lines = msg[1], msg[2], msg[3]
                    # Cap per-source corpus at ~2 MB of text so a huge
                    # aggregate list can't balloon the session cache.
                    text = '\n'.join(raw_lines)
                    if len(text) > 2 * 1024 * 1024:
                        text = text[: 2 * 1024 * 1024]
                    self._source_corpus_cache[name] = text
                    self.source_last_fetched[url] = datetime.datetime.now().isoformat(timespec='seconds')

                elif msg_type == "log":
                    text, is_err = msg[1], msg[2]
                    # Only show log if it's an error, otherwise it flickers too fast
                    if is_err: self.update_status(text, is_error=True)
                
                elif msg_type == "cancelled":
                    self._finish_import_ui()
                    self.update_status("Warning: Batch import cancelled.")
                    return # Stop checking
                 
                elif msg_type == "done":
                    new_lines, total, success_count, failure_messages = msg[1], msg[2], msg[3], msg[4]
                    self._finish_import_ui()
                     
                    if not new_lines:
                        if failure_messages:
                            self.update_status(f"Import finished with {len(failure_messages)} failed source(s) and no usable entries.", is_error=True)
                            messagebox.showerror(
                                "Import Failed",
                                "No usable entries were imported.\n\nFailed sources:\n"
                                f"{self._summarize_failure_messages(failure_messages)}",
                                parent=self.root,
                            )
                        else:
                            self.update_status("Import finished, but no usable data was retrieved.", is_error=True)
                    else:
                        current_lines = self.get_lines()
                        if current_lines and current_lines[-1].strip() != "":
                            current_lines.append("")
                        
                        # Bulk merge
                        current_lines.extend(new_lines)
                        
                        self.update_status(f"Processing {len(new_lines)} imported lines into editor...")
                        self.root.update_idletasks() # Allow UI to render status
                        
                        # This triggers the heavy lifting (stats calc) only once at the end
                        self.set_text(current_lines) 
                        failure_suffix = f" {len(failure_messages)} source(s) failed." if failure_messages else ""
                        self.update_status(f"Success: Imported {len(new_lines)} lines from {success_count}/{total} source(s).{failure_suffix}")
                        if failure_messages:
                            messagebox.showwarning(
                                "Import Completed with Warnings",
                                "Some sources could not be imported.\n\nFailed sources:\n"
                                f"{self._summarize_failure_messages(failure_messages)}",
                                parent=self.root,
                            )
                    return # Stop checking

        except queue.Empty:
            pass
        except tk.TclError:
            # Widget was destroyed mid-drain (e.g. window closed). Stop
            # polling so we don't spin forever on a torn-down root.
            return

        if self.is_importing:
            self._safe_after(100, self._check_import_queue)

    # ----------------------------- File Imports -------------------
            
    def import_pfsense_log(self):
        filepath = self._choose_file(
            title="Select pfSense DNSBL Log File",
            filetypes=(("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*"))
        )
        if not filepath:
            return

        filename = os.path.basename(filepath)
        try:
            log_lines = read_text_file_lines(filepath)

            extracted_domains = set()
            for line in log_lines:
                parts = line.strip().split(',')
                if len(parts) > 2 and "dnsbl" in parts[0].lower():
                    domain = parts[2].strip()
                    if domain:
                        extracted_domains.add(domain)

            if not extracted_domains:
                self.update_status(f"No blocked domains were detected in '{filename}'.", is_error=True)
                return

            self.fetch_and_append_hosts(filename, lines_to_add=sorted(list(extracted_domains)))

        except Exception as e:
            self.update_status(f"Error importing log file: {e}", is_error=True)
            messagebox.showerror("Import Error", f"An unexpected error occurred while processing the log file:\n{e}", parent=self.root)
            
    def import_nextdns_log(self):
        filepath = self._choose_file(
            title="Select NextDNS Query Log CSV File",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )
        if not filepath:
            return

        filename = os.path.basename(filepath)
        try:
            content = read_text_file_content(filepath).strip()
            if not content:
                raise ValueError("The selected CSV file is empty.")

            reader = csv.DictReader(io.StringIO(content))
            extracted_domains = set()

            raw_fieldnames = reader.fieldnames or []
            fieldnames = [name.strip().lower() if name else "" for name in raw_fieldnames]
            if 'domain' not in fieldnames or 'status' not in fieldnames:
                raise ValueError("Missing required CSV columns ('domain', 'status').")

            domain_key = raw_fieldnames[fieldnames.index('domain')]
            status_key = raw_fieldnames[fieldnames.index('status')]

            for row in reader:
                domain = row.get(domain_key, '').strip()
                status = row.get(status_key, '').strip().lower()

                if domain and status == 'blocked':
                    extracted_domains.add(domain)

            if not extracted_domains:
                self.update_status(f"No blocked domains were detected in '{filename}'.", is_error=True)
                return

            self.fetch_and_append_hosts(f"NextDNS Log: {filename}", lines_to_add=sorted(list(extracted_domains)))

        except Exception as e:
            self.update_status(f"Error importing NextDNS log file: {e}", is_error=True)
            messagebox.showerror("Import Error", f"An unexpected error occurred while processing the NextDNS log file:\n{e}", parent=self.root)
            
    def append_manual_list(self):
        content = self.manual_text_area.get('1.0', tk.END).strip()
        if not content:
            self.update_status("Paste a manual list before appending it to the editor.", is_error=True)
            return
        
        lines = content.splitlines()
        if self.fetch_and_append_hosts("Manual List Input", lines_to_add=lines):
            self.manual_text_area.delete('1.0', tk.END)
            self.manual_text_area.edit_modified(False)
            self._update_manual_summary()
        
    def fetch_and_append_hosts(self, source_name, url=None, lines_to_add=None):
        # Compatibility wrapper for existing non-threaded logic (for manual/file imports)
        # For URL buttons, we redirect to start_single_import which is threaded.
        if url:
             self.start_single_import(source_name, url)
             return True

        # Fallback for manual content (already in memory, no need to thread)
        import_mode = self.import_mode.get()
        if lines_to_add:
            processed_lines = self._apply_import_mode_filter(source_name, lines_to_add, import_mode)
            if not processed_lines:
                self.update_status(f"No usable entries were found in {source_name}.", is_error=True)
                return False
            current_lines = self.get_lines()
            if current_lines and current_lines[-1].strip() != "":
                current_lines.append("")
            current_lines.extend(processed_lines)
            self.set_text(current_lines)
            self.update_status(f"Success: Added entries from {source_name} to the editor.")
            return True

        return False


    # ------------------------- Custom Sources & UI ------------------------------
    def _clear_custom_source_widgets(self):
        children = self.custom_sources_frame.winfo_children()
        preserved_widgets = {
            getattr(self, 'btn_add_custom', None),
            getattr(self, 'custom_sources_help_label', None),
            getattr(self, 'custom_sources_summary_label', None),
            getattr(self, 'custom_sources_empty_label', None),
        }
        widgets_to_destroy = [widget for widget in children if widget not in preserved_widgets]
        
        for widget in widgets_to_destroy:
            widget.destroy()
            
        self._custom_source_widgets = {}
        self.import_action_widgets = [item for item in self.import_action_widgets if item and item.winfo_exists()]

    def _update_custom_source_empty_state(self):
        if not hasattr(self, "custom_sources_empty_label"):
            return

        if self.custom_sources:
            if self.custom_sources_empty_label.winfo_manager():
                self.custom_sources_empty_label.pack_forget()
        else:
            if not self.custom_sources_empty_label.winfo_manager():
                self.custom_sources_empty_label.pack(fill="x", padx=8, pady=(0, 6), before=self.btn_add_custom)
        self._update_custom_source_summary()

    def _rebuild_custom_source_buttons(self):
        self._clear_custom_source_widgets()
        for source in self.custom_sources:
            self._create_custom_source_button(source['name'], source['url'])
        self._update_custom_source_empty_state()
        self.btn_add_custom.pack_forget()
        self.btn_add_custom.pack(fill=tk.X, pady=2, side=tk.BOTTOM)

    def _create_custom_source_button(self, name, url):
        tooltip = f"Appends the custom '{name}' blocklist."
        frame = ttk.Frame(self.custom_sources_frame)
        frame.pack(fill=tk.X, pady=2, before=self.btn_add_custom) 
        self._custom_source_widgets[name] = frame

        remove_btn = ttk.Button(
            frame, 
            text="✕", 
            command=lambda n=name, f=frame: self.remove_custom_source(n, f), 
            style="Remove.TButton"
        )
        ToolTip(remove_btn, f"Remove the '{name}' source from configuration.")
        remove_btn.pack(side=tk.RIGHT, padx=(5, 0))

        import_btn = self._btn(
            frame, 
            text=name, 
            command=lambda u=url, n=name: self.start_single_import(n, u), 
            tooltip=tooltip, 
            style="TButton"
        )
        self._register_import_widget(import_btn)
        import_btn.pack(side=tk.LEFT, expand=True, fill=tk.X)


    def show_add_source_dialog(self):
        draft_name = ""
        draft_url = ""

        while True:
            dialog = AddSourceDialog(self.root, initial_name=draft_name, initial_url=draft_url)
            if not dialog.result:
                return

            name, url = dialog.result
            draft_name, draft_url = name, url
            normalized_url = normalize_custom_source_url(url)
            if any(s['name'].lower() == name.lower() for s in self.custom_sources):
                messagebox.showwarning("Duplicate Name", "A custom source with that name already exists. Choose a different label.", parent=self.root)
                self.update_status("Error: Source name already exists.", is_error=True)
                continue
            if any(normalize_custom_source_url(s['url']) == normalized_url for s in self.custom_sources):
                messagebox.showwarning("Duplicate URL", "That custom source URL is already configured.", parent=self.root)
                self.update_status("Error: Source URL already exists.", is_error=True)
                continue
            source_data = {'name': name, 'url': url}
            self.custom_sources.append(source_data)
            self._create_custom_source_button(name, url)
            self._update_custom_source_empty_state()
            self.update_status(f"Added custom source: {name}")
            self.save_config()
            return


    def remove_custom_source(self, name, widget_frame):
        if not messagebox.askyesno(
            "Remove Custom Source",
            f"Remove the custom source '{name}' from saved configuration?",
            parent=self.root,
        ):
            return

        self.custom_sources = [s for s in self.custom_sources if s['name'] != name]
        if name in self._custom_source_widgets:
            widget_frame.destroy()
            del self._custom_source_widgets[name]
        self._update_custom_source_empty_state()
        self.save_config()
        self.update_status(f"Removed custom source: {name}")


    # ----------------------- Whitelist & Filtering ----------------------------
    def _get_current_whitelist_text(self):
        return self.whitelist_text_area.get('1.0', tk.END).strip()

    def _has_unsaved_whitelist_changes(self):
        return self._get_current_whitelist_text() != self._last_saved_whitelist_text

    def _confirm_whitelist_replacement(self, source_name: str):
        if not self._has_unsaved_whitelist_changes():
            return True

        return messagebox.askyesno(
            "Replace Whitelist",
            f"You have unsaved whitelist edits. Replace them with content from {source_name}?",
            parent=self.root,
        )

    def load_whitelist_from_file(self):
        filepath = self._choose_file(
            title="Select Whitelist File",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        if not filepath:
            return
        if not self._confirm_whitelist_replacement(f"'{os.path.basename(filepath)}'"):
            self.update_status("Whitelist import cancelled. Existing entries kept.")
            return
        try:
            content = read_text_file_content(filepath)
            self.whitelist_text_area.delete('1.0', tk.END)
            self.whitelist_text_area.insert('1.0', content)
            self._update_whitelist_summary()
            self.update_status(f"Loaded whitelist from '{os.path.basename(filepath)}'.")
            self._trigger_ui_update()
        except Exception as e:
            messagebox.showerror("File Error", f"Could not load whitelist:\n{e}", parent=self.root)

    def import_whitelist_from_web(self):
        if getattr(self, "_whitelist_web_fetch_active", False):
            self.update_status("A whitelist import is already running.", is_error=True)
            return
        url = "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Whitelist.txt"
        if not self._confirm_whitelist_replacement("the HOSTShield web feed"):
            self.update_status("Whitelist import cancelled. Existing entries kept.")
            return
        self.update_status("Importing whitelist from HOSTShield…")

        self._whitelist_web_fetch_active = True

        def _fetch():
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as response:
                    if response.getcode() != 200:
                        raise urllib.error.HTTPError(
                            url, response.getcode(), f"HTTP {response.getcode()}",
                            response.info(), response.fp,
                        )
                    lines = decode_downloaded_lines(
                        url,
                        read_http_body_limited(response),
                        response.headers.get("Content-Encoding", ""),
                    )
                    if looks_like_html_document(lines):
                        raise ValueError("Received HTML instead of a whitelist.")
                    content = '\n'.join(lines)
                self._safe_after(0, lambda: self._apply_whitelist_web_result(content))
            except Exception as e:
                # Capture the exception by value so the closure doesn't lose it
                # after the except block exits.
                error = e
                self._safe_after(0, lambda: self._apply_whitelist_web_error(error))

        threading.Thread(target=_fetch, daemon=True).start()

    def _apply_whitelist_web_result(self, content):
        self._whitelist_web_fetch_active = False
        self.whitelist_text_area.delete('1.0', tk.END)
        self.whitelist_text_area.insert('1.0', content)
        self._update_whitelist_summary()
        self.update_status("Imported whitelist from HOSTShield.")
        self._trigger_ui_update()

    def _apply_whitelist_web_error(self, error):
        self._whitelist_web_fetch_active = False
        self.update_status(f"Could not fetch whitelist: {type(error).__name__}", is_error=True)
        messagebox.showerror("Whitelist Import Error", f"Could not fetch whitelist:\n{error}", parent=self.root)
            
    def _get_whitelist_set(self):
        whitelist_content = self.whitelist_text_area.get('1.0', tk.END)
        if whitelist_content == self._cached_whitelist_text:
            return self._cached_whitelist_set

        whitelist = set()
        for line in whitelist_content.splitlines():
            stripped = line.strip()
            if not stripped or _is_comment_line(stripped):
                continue

            _, domains, _ = normalize_line_to_hosts_entries(line)
            if domains:
                whitelist.update(domain.lstrip('.') for domain in domains)
                continue

            domain, _ = _extract_domain_from_token(stripped, allow_single_label=True)
            if domain:
                whitelist.add(domain.lstrip('.'))

        self._cached_whitelist_text = whitelist_content
        self._cached_whitelist_set = whitelist
        return whitelist

    # ------------------------------ Utilities & Clean Logic ---------------------------------
    
    def auto_clean(self):
        if self._block_during_import("Clean"):
            return
        original = self.get_lines()
        whitelist_set = self._get_whitelist_set()
        
        final_lines, stats = _get_canonical_cleaned_output_and_stats(original, whitelist_set)
        
        if original != final_lines:
            def apply_to_editor(approved_lines):
                self.set_text(approved_lines)
                self.update_status(f"Success: Applied the cleaned version to the editor. {summarize_clean_changes(stats['total_discarded'], stats['transformed'])}")

            PreviewWindow(
                self,
                original,
                final_lines,
                title="Preview: Clean",
                on_apply_callback=apply_to_editor,
                stats=stats,
                apply_label="Apply Cleaned Version",
            )
        else:
            self.update_status("No clean-up changes were needed. The editor is already aligned.")

    def deduplicate(self):
        self.auto_clean()


    def flush_dns(self):
        try:
            if os.name == 'nt':
                subprocess.run(['ipconfig', '/flushdns'], capture_output=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                self.update_status("Success: Flushed the DNS resolver cache.")
            else:
                self.update_status("Unsupported OS: DNS flushing is only available on Windows.", is_error=True)
        except Exception as e:
            self.update_status(f"Error flushing DNS: {e}", is_error=True)
            
    # ----------------------------- Emergency DNS Unlock -----------------
    def emergency_dns_stop(self):
        if not messagebox.askyesno(
            "Emergency DNS Recovery",
            "This launches a last-resort recovery script that force-stops the DNS Client service and overwrites the hosts file with a minimal safe copy.\n\n"
            "Use it only if Windows is already locked up because the hosts file is too large or corrupted.\n\n"
            "Continue?",
            parent=self.root,
        ):
            return

        bat_content = r"""
@echo off
setlocal EnableExtensions DisableDelayedExpansion
title DNS EMERGENCY UNLOCKER

:: SELF-ELEVATION
fsutil dirty query %systemdrive% >nul
if %errorlevel% NEQ 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "HOSTS_DIR=%SystemRoot%\System32\drivers\etc"
set "TARGET_FILE=%HOSTS_DIR%\hosts"
set "TEMP_FILE=%TEMP%\hosts_clean.tmp"

:: Create a clean hosts file
echo # Copyright (c) 1993-2009 Microsoft Corp. > "%TEMP_FILE%"
echo # >> "%TEMP_FILE%"
echo # This is a sample HOSTS file used by Microsoft TCP/IP for Windows. >> "%TEMP_FILE%"
echo 127.0.0.1       localhost >> "%TEMP_FILE%"
echo ::1             localhost >> "%TEMP_FILE%"

echo.
echo ====================================================
echo   EMERGENCY DNS STOP ENGAGED
echo ====================================================
echo   Action: Force Kill Dnscache + Inject Blank File
echo.

set RETRIES=0

:KILL_LOOP
copy /Y "%TEMP_FILE%" "%TARGET_FILE%" >nul 2>&1
if %errorlevel% EQU 0 goto :SUCCESS

set /a RETRIES+=1
if %RETRIES% GEQ 30 (
    echo [FAIL] Could not replace hosts file after %RETRIES% attempts.
    goto :FAIL
)

for /f "tokens=2" %%a in ('tasklist /svc /fi "services eq dnscache" /nh 2^>nul') do (
    taskkill /F /PID %%a >nul 2>&1
)
goto :KILL_LOOP

:FAIL
echo.
echo ====================================================
echo   RECOVERY FAILED
echo ====================================================
echo The hosts file could not be replaced after multiple attempts.
echo Try running this script again or manually edit the hosts file.
del "%TEMP_FILE%" >nul 2>&1
pause
exit /b 1

:SUCCESS
echo.
echo [OK] Lock broken. Blank hosts file installed.
echo [INFO] Flushing DNS Cache...
ipconfig /flushdns
echo [INFO] Restoring Service Stability...
net start dnscache >nul 2>&1
del "%TEMP_FILE%" >nul 2>&1

echo.
echo ====================================================
echo   MISSION COMPLETE: DNS UNLOCKED
echo ====================================================
echo You may close this window.
pause
"""
        fd = None
        path = None
        try:
            fd, path = tempfile.mkstemp(suffix=".bat", text=True)
            with os.fdopen(fd, 'w') as f:
                f.write(bat_content)
            fd = None  # fd is owned by the context manager now

            if os.name == 'nt':
                os.startfile(path)
            else:
                subprocess.Popen(['sh', path])
            self.update_status("Launched Emergency Unlock script in new window.", is_error=False)

        except Exception as e:
            # Launch failed — remove the orphaned temp script so it doesn't
            # linger in %TEMP%. On success we intentionally leave it; the
            # launched cmd.exe needs it to survive.
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if path and os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass
            messagebox.showerror("Error", f"Failed to launch emergency script: {e}", parent=self.root)


    # ----------------------------- Editor Warnings -------------------------------------
    
    def _apply_inline_warnings(self, lines: list[str]):
        try:
            if not self.text_area.winfo_exists():
                return
            self.text_area.tag_remove("warning_discard", "1.0", tk.END)
            self.text_area.tag_remove("warning_transform", "1.0", tk.END)
        except tk.TclError:
            return

        if not lines:
            return

        whitelist = self._get_whitelist_set()
        seen_normalized = set()

        for i, line in enumerate(lines):
            line_number = i + 1
            start_index = f"{line_number}.0"
            end_index = f"{line_number}.end"

            stripped = line.strip()

            if not stripped or _is_comment_line(stripped):
                continue

            parsed_entries, transformed = parse_hosts_line_entries(line)

            try:
                if not parsed_entries:
                    self.text_area.tag_add("warning_discard", start_index, end_index)
                    continue

                discarded_from_line = False
                kept_from_line = 0

                for normalized, domain, is_block_entry in parsed_entries:
                    if is_block_entry and (domain in whitelist or domain.lstrip('.') in whitelist):
                        discarded_from_line = True
                        continue

                    if normalized in seen_normalized:
                        discarded_from_line = True
                        continue

                    seen_normalized.add(normalized)
                    kept_from_line += 1

                if discarded_from_line or kept_from_line == 0:
                    self.text_area.tag_add("warning_discard", start_index, end_index)
                    continue

                if transformed:
                    self.text_area.tag_add("warning_transform", start_index, end_index)
            except tk.TclError:
                # Widget torn down during tagging — stop gracefully.
                return


    def _apply_syntax_highlighting(self, lines: list[str]):
        """Color IPs, comments, and import-section markers.

        Kept cheap: only three tags, no per-domain coloring (which would
        require O(n) regex scans and isn't legible at 10pt anyway). Runs in
        the same debounced path as `_apply_inline_warnings` so we share the
        O(n) line walk.
        """
        try:
            if not self.text_area.winfo_exists():
                return
            self.text_area.tag_remove("syntax_ip", "1.0", tk.END)
            self.text_area.tag_remove("syntax_comment", "1.0", tk.END)
            self.text_area.tag_remove("syntax_marker", "1.0", tk.END)
        except tk.TclError:
            return

        if not lines:
            return

        try:
            for i, line in enumerate(lines):
                ln = i + 1
                stripped = line.lstrip()
                if not stripped:
                    continue
                leading = len(line) - len(stripped)

                if _is_comment_line(stripped):
                    tag = "syntax_marker" if (
                        IMPORT_START_RE.match(stripped) or IMPORT_END_RE.match(stripped)
                    ) else "syntax_comment"
                    self.text_area.tag_add(tag, f"{ln}.0", f"{ln}.end")
                    continue

                # Highlight the leading IP token if present.
                content = stripped.split('#', 1)[0]
                first = content.split(None, 1)[0] if content.split() else ""
                if first and _looks_like_ip_token(first):
                    col_start = leading
                    col_end = leading + len(first)
                    self.text_area.tag_add("syntax_ip", f"{ln}.{col_start}", f"{ln}.{col_end}")
        except tk.TclError:
            return

    # ----------------------------- Search -------------------------------------
    def search_clear(self, announce=True):
        self.text_area.tag_remove("search_match", "1.0", tk.END)
        self.text_area.tag_remove("search_current", "1.0", tk.END)
        self._search_matches = []
        self._search_index = -1
        if announce:
            self.update_status("Search cleared.")

    def _recompute_search_matches(self, query, preserve_index=False):
        old_current_match = None
        if preserve_index and 0 <= self._search_index < len(self._search_matches):
            pos, end = self._search_matches[self._search_index]
            old_current_match = self.text_area.get(pos, end)

        self.search_clear(announce=False)
        if not query:
            return

        matches = []
        start = "1.0"
        truncated = False
        while True:
            pos = self.text_area.search(query, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            self.text_area.tag_add("search_match", pos, end)
            matches.append((pos, end))
            start = end
            if len(matches) >= SEARCH_MATCH_LIMIT:
                truncated = True
                break

        self._search_matches = matches

        if self._search_matches:
            new_index = 0
            if preserve_index and old_current_match:
                try:
                    for i, (pos, end) in enumerate(self._search_matches):
                        if self.text_area.get(pos, end) == old_current_match:
                            new_index = i
                            break
                except Exception:
                    new_index = 0

            self._search_index = new_index
            self._focus_current_match()
            if truncated:
                self.update_status(
                    f"Found {len(self._search_matches):,}+ matches "
                    f"(capped at {SEARCH_MATCH_LIMIT:,}). Narrow your query to see the rest."
                )
            else:
                self.update_status(f"Found {len(self._search_matches):,} matches.")
        else:
            self.update_status(f"No matches found for '{query}'.", is_error=True)


    def _focus_current_match(self):
        try:
            self.text_area.tag_remove("search_current", "1.0", tk.END)
            if 0 <= self._search_index < len(self._search_matches):
                pos, end = self._search_matches[self._search_index]
                self.text_area.tag_add("search_current", pos, end)
                self.text_area.see(pos)
                self.update_status(
                    f"Search match {self._search_index + 1:,} of {len(self._search_matches):,}."
                )
        except tk.TclError:
            # Text widget torn down (e.g. shutdown during a search cycle) —
            # quietly give up instead of raising.
            return

    def remove_matching_lines(self):
        query = self.search_var.get().strip()
        if not query:
            self.update_status("Enter a search term before removing matches.", is_error=True)
            return

        current_lines = self.get_lines()
        matching_indices = find_keyword_match_line_indices(current_lines, query)
        if not matching_indices:
            self.update_status(f"No removable entries found for '{query}'.", is_error=True)
            return

        if len(matching_indices) > MATCH_REMOVAL_DIALOG_LIMIT:
            proceed = messagebox.askyesno(
                "Too Many Matches",
                f"Your search matched {len(matching_indices):,} lines. "
                f"Building an individual checkbox for each would freeze the UI.\n\n"
                f"Remove ALL {len(matching_indices):,} matching lines in one step instead? "
                f"(A preview will still be shown before the editor is changed.)",
                parent=self.root,
            )
            if not proceed:
                return
            selected_indices = set(matching_indices)
        else:
            dialog = MatchRemovalDialog(
                self.root,
                query,
                [(line_index, current_lines[line_index]) for line_index in matching_indices],
            )
            self.root.wait_window(dialog)
            if not dialog.result:
                return
            selected_indices = dialog.result

        updated_lines = remove_lines_by_indices(current_lines, selected_indices)
        removed_count = len(selected_indices)

        def apply_to_editor(approved_lines):
            self.set_text(approved_lines)
            self.update_status(f"Removed {removed_count:,} matching line(s) for '{query}'.")

        PreviewWindow(
            self,
            current_lines,
            updated_lines,
            title=f"Preview: Remove Matches for '{query}'",
            on_apply_callback=apply_to_editor,
            apply_label="Remove Selected",
            cancel_label="Keep Remaining",
        )

    def search_find(self):
        query = self.search_var.get().strip()
        if not query:
            self.update_status("Enter a search term.", is_error=True)
            return
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


def _cli_hosts_path() -> str:
    return _default_hosts_file_path()


def _cli_print(msg: str):
    # Use stderr so GUI-less automation can redirect cleanly.
    print(msg, file=sys.stderr)


def _cli_is_admin() -> bool:
    if os.name != 'nt':
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _cli_backup(hosts_path: str) -> int:
    if not os.path.exists(hosts_path):
        _cli_print(f"hosts file not found: {hosts_path}")
        return 2
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = f"{hosts_path}.{stamp}.bak"
    shutil.copy2(hosts_path, f"{hosts_path}.bak")
    shutil.copy2(hosts_path, dest)
    _cli_print(f"Backup created: {dest}")
    # Prune old ones.
    try:
        candidates = [p for p in glob.glob(f"{hosts_path}.*.bak")
                      if os.path.normcase(p) != os.path.normcase(f"{hosts_path}.bak")]
        candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for stale in candidates[BACKUP_RETENTION:]:
            try:
                os.unlink(stale)
            except OSError:
                pass
    except OSError:
        pass
    return 0


def _cli_disable(hosts_path: str) -> int:
    if not _cli_is_admin():
        _cli_print("Administrator privileges required.")
        return 1
    disabled = hosts_path + ".disabled"
    if os.path.exists(disabled):
        _cli_print("hosts file is already disabled.")
        return 0
    _cli_backup(hosts_path)
    if os.path.exists(hosts_path):
        shutil.copy2(hosts_path, disabled)
    minimal = (
        "# Copyright (c) 1993-2009 Microsoft Corp.\n#\n"
        "127.0.0.1       localhost\n"
        "::1             localhost\n"
    )
    write_text_file_atomic(hosts_path, minimal)
    _cli_print("hosts file disabled; minimal template is active.")
    return 0


def _cli_enable(hosts_path: str) -> int:
    if not _cli_is_admin():
        _cli_print("Administrator privileges required.")
        return 1
    disabled = hosts_path + ".disabled"
    if not os.path.exists(disabled):
        _cli_print("no disabled sibling found; hosts file is already enabled.")
        return 0
    _cli_backup(hosts_path)
    shutil.copy2(disabled, hosts_path)
    os.unlink(disabled)
    _cli_print("hosts file re-enabled.")
    return 0


def _cli_apply(hosts_path: str, source_file: str) -> int:
    if not _cli_is_admin():
        _cli_print("Administrator privileges required.")
        return 1
    if not os.path.isfile(source_file):
        _cli_print(f"source file not found: {source_file}")
        return 2
    _cli_backup(hosts_path)
    content = read_text_file_content(source_file)
    write_text_file_atomic(hosts_path, content)
    _cli_print(f"Applied {source_file} to {hosts_path}")
    return 0


def _cli_update(hosts_path: str) -> int:
    """Re-fetch every source the GUI has fetched before, cleaned-save the result.

    Reads ``source_last_fetched`` from the persisted config to discover which
    sources this install has used. Skips if the user has never imported
    anything (nothing to update).
    """
    if not _cli_is_admin():
        _cli_print("Administrator privileges required.")
        return 1

    config_path = get_primary_config_path("hosts_editor_config.json")
    if not os.path.isfile(config_path):
        _cli_print("No config found; nothing to update.")
        return 2
    try:
        config = json.loads(read_text_file_content(config_path))
    except (OSError, ValueError) as e:
        _cli_print(f"Config read failed: {e}")
        return 2
    sanitized = sanitize_config_snapshot(config, os.path.expanduser("~"))
    last_fetched = sanitized.get("source_last_fetched", {})
    if not last_fetched:
        _cli_print("No previously-imported sources recorded; nothing to update.")
        return 0

    # Reverse-map URL -> display name from the bundled catalog so the output
    # comments look like a GUI batch import.
    reverse: dict[str, str] = {}
    for sources in HostsFileEditor.BLOCKLIST_SOURCES.values():
        for name, url, _ in sources:
            reverse[url] = name
    for entry in sanitized.get("custom_sources", []):
        reverse[entry["url"]] = entry["name"]

    _cli_backup(hosts_path)
    collected: list[str] = []
    updated_stamps: dict[str, str] = dict(last_fetched)
    now_iso = datetime.datetime.now().isoformat(timespec='seconds')
    successes, failures = 0, []
    for url in last_fetched:
        name = reverse.get(url, url)
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=20) as response:
                if response.getcode() != 200:
                    raise urllib.error.HTTPError(url, response.getcode(), f"HTTP {response.getcode()}", response.info(), response.fp)
                raw_lines = decode_downloaded_lines(
                    url,
                    read_http_body_limited(response),
                    response.headers.get("Content-Encoding", ""),
                )
            if looks_like_html_document(raw_lines):
                raise ValueError("received HTML instead of hosts list")
            safe_name = re.sub(r'[\r\n\t]+', ' ', name).strip() or "Imported Source"
            collected.append(f"# --- Normalized Import Start: {safe_name} ---")
            seen_entries: set[str] = set()
            for line in raw_lines:
                entries, _, _ = normalize_line_to_hosts_entries(line)
                for normalized in entries:
                    if normalized not in seen_entries:
                        collected.append(normalized)
                        seen_entries.add(normalized)
            collected.append(f"# --- Normalized Import End: {safe_name} ---")
            collected.append("")
            updated_stamps[url] = now_iso
            successes += 1
            _cli_print(f"OK  {name}")
        except Exception as e:
            failures.append(f"{name}: {e}")
            _cli_print(f"ERR {name}: {e}")

    if not collected:
        _cli_print("No content successfully fetched; hosts file left unchanged.")
        return 1

    existing_lines: list[str] = []
    if os.path.exists(hosts_path):
        existing_lines = read_text_file_lines(hosts_path)
    whitelist_text = sanitized.get("whitelist", "")
    whitelist_set: set[str] = set()
    for wline in whitelist_text.splitlines():
        entries, domains, _ = normalize_line_to_hosts_entries(wline)
        whitelist_set.update(domain.lstrip('.') for domain in domains)

    # Merge: drop everything between existing Start/End markers (previous
    # imports), then append the freshly-fetched bundle, then Cleaned-Save.
    previous_sections = discover_import_sections(existing_lines)
    trimmed = list(existing_lines)
    for section in sorted(previous_sections, key=lambda s: s["start"], reverse=True):
        trimmed = remove_import_section(trimmed, section)
    merged = trimmed + [""] + collected
    cleaned, stats = _get_canonical_cleaned_output_and_stats(merged, whitelist_set)
    write_text_file_atomic(hosts_path, '\n'.join(cleaned))

    # Persist new timestamps.
    try:
        snapshot = dict(sanitized)
        snapshot["source_last_fetched"] = updated_stamps
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        write_text_file_atomic(config_path, json.dumps(snapshot, indent=2))
    except OSError:
        pass

    _cli_print(f"Applied {stats['final_active']:,} active entries from {successes} source(s); {len(failures)} failed.")
    return 0 if successes and not failures else (0 if successes else 1)


def _handle_cli_args(argv: list[str]) -> int | None:
    """Return an exit code when a CLI action was performed; else ``None`` to
    continue launching the GUI.
    """
    # Strip the elevation-probe flag so argparse doesn't choke on it; the
    # flag exists only to keep us from UAC-looping.
    argv = [arg for arg in argv if arg != ELEVATION_ATTEMPT_FLAG]
    cli_flags = {"--version", "--disable", "--enable", "--backup", "--apply", "--update", "-h", "--help"}
    if not any(arg in cli_flags or arg.startswith("--apply=") for arg in argv):
        return None

    parser = argparse.ArgumentParser(
        prog=APP_SLUG,
        description=f"{APP_NAME} v{APP_VERSION} -- scriptable hosts-file actions.",
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit.")
    parser.add_argument("--disable", action="store_true", help="Replace hosts file with minimal template; stash current as .disabled.")
    parser.add_argument("--enable", action="store_true", help="Restore hosts file from .disabled sibling.")
    parser.add_argument("--backup", action="store_true", help="Create a timestamped backup of the current hosts file.")
    parser.add_argument("--apply", metavar="PATH", help="Overwrite the hosts file with the contents of PATH (creates backup first).")
    parser.add_argument("--update", action="store_true", help="Re-fetch every source previously imported in the GUI and apply a Cleaned Save of the merged result.")

    args = parser.parse_args(argv)

    if args.version:
        print(f"{APP_NAME} v{APP_VERSION}")
        return 0

    hosts_path = _cli_hosts_path()
    if args.disable:
        return _cli_disable(hosts_path)
    if args.enable:
        return _cli_enable(hosts_path)
    if args.backup:
        return _cli_backup(hosts_path)
    if args.apply:
        return _cli_apply(hosts_path, args.apply)
    if args.update:
        return _cli_update(hosts_path)
    return None


if __name__ == "__main__":
    exit_code = _handle_cli_args(sys.argv[1:])
    if exit_code is not None:
        sys.exit(exit_code)

    root = tk.Tk()
    app = HostsFileEditor(root)
    root.mainloop()
