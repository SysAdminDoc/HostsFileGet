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
import pathlib
import datetime
import argparse
import glob

APP_NAME = "Hosts File Get"
APP_SLUG = "HostsFileGet"
APP_VERSION = "2.15.0"
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

# The imported-source corpus cache powers "Check Domain" and "Sources Report".
# Keep it bounded so a marathon import session does not quietly accumulate tens
# of megabytes of text in RAM.
SOURCE_CORPUS_CACHE_MAX_ENTRY_BYTES = 2 * 1024 * 1024
SOURCE_CORPUS_CACHE_MAX_TOTAL_BYTES = 16 * 1024 * 1024
SOURCE_CORPUS_CACHE_MAX_ENTRIES = 24

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

# ----------------------------- Theme -----------------------------------------
# A restrained palette keeps the interface calm and scannable. We still use
# color for priority and state, but most surfaces stay close together so the
# eye lands on structure and content instead of decoration.
PALETTE = {
    "base": "#0f1318",
    "mantle": "#141a20",
    "panel": "#171e26",
    "panel_alt": "#1b2430",
    "crust": "#0c1117",
    "text": "#edf2f7",
    "subtext": "#a0acb8",
    "surface0": "#202935",
    "surface1": "#293444",
    "surface2": "#354255",
    "overlay0": "#5d6977",
    "overlay1": "#7d8896",
    "border": "#273241",
    "focus": "#7ea8ff",
    "blue": "#8fb2ff",
    "blue_hover": "#a5c1ff",
    "green": "#8fc4a1",
    "green_hover": "#a4d0b3",
    "green_press": "#72b387",
    "red": "#e8a1aa",
    "red_hover": "#efb0b8",
    "red_press": "#d38993",
    "yellow": "#d8c08b",
    "yellow_ink": "#2e2410",
    "accent": "#8fb2ff",
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
        if hasattr(parent, "_configure_modal_window"):
            parent._configure_modal_window(
                self,
                title=title,
                size=f"{width}x{height}",
                min_size=(640, 420),
            )
        else:
            self.title(title)
            self.geometry(f"{width}x{height}")
            self.configure(bg=PALETTE["base"])
            self.transient(parent.root)
        self.grab_set()

        header_frame = ttk.Frame(self, padding=(16, 16, 16, 0))
        header_frame.pack(fill='x', side=tk.TOP)
        ttk.Label(header_frame, text="Preview changes", style="Eyebrow.TLabel").pack(anchor='w')
        ttk.Label(header_frame, text=title, font=("Segoe UI Semibold", 14)).pack(anchor='w', pady=(4, 0))
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
        text_frame = ttk.Frame(self, padding=(16, top_padding, 16, 0))
        text_frame.pack(expand=True, fill='both')
        self.preview_text = scrolledtext.ScrolledText(
            text_frame, wrap=tk.NONE, font=("Consolas", 11),
        )
        if hasattr(parent, "_style_code_surface"):
            parent._style_code_surface(self.preview_text, font_spec=("Consolas", 11))
        self.preview_text.pack(expand=True, fill='both')

        ttk.Separator(self, orient="horizontal").pack(fill="x", pady=(12, 0))

        button_frame = ttk.Frame(self, padding=(16, 12, 16, 14))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)

        legend_frame = ttk.Frame(button_frame)
        legend_frame.pack(side=tk.LEFT)
        self.preview_summary_label = ttk.Label(legend_frame, text="", foreground=PALETTE["subtext"])
        self.preview_summary_label.pack(anchor='w')
        self.preview_legend_label = ttk.Label(legend_frame, text="", foreground=PALETTE["overlay1"])
        self.preview_legend_label.pack(anchor='w', pady=(2, 0))

        self.apply_button = ttk.Button(button_frame, text=apply_label, command=self.apply_changes, style="Action.TButton")
        self.apply_button.pack(side=tk.RIGHT, padx=6)
        ttk.Button(button_frame, text=cancel_label, command=self.destroy, style="Secondary.TButton").pack(side=tk.RIGHT, padx=6)

        self.preview_text.tag_config('added', foreground="#89D68D")
        self.preview_text.tag_config('removed', foreground=PALETTE["red"])
        self.preview_text.tag_config('header', foreground=PALETTE["blue"])
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
        # seconds. Fall back to unified_diff above the threshold - it still
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
                    self.preview_text.insert(tk.END, line + '\n', 'header')
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
            self.parent_editor._show_notice_dialog(
                "Could not apply preview changes",
                "The approved preview could not be applied to the editor.",
                tone="error",
                details=str(e),
            )
            return

        self.destroy()

# -------------------------- Add Custom Source Dialog --------------------------
class AddSourceDialog(simpledialog.Dialog):
    def __init__(self, editor, initial_name="", initial_url=""):
        self.editor = editor
        self.initial_name = initial_name
        self.initial_url = initial_url
        self.feedback_var = tk.StringVar(value="")
        super().__init__(editor.root)

    def body(self, master):
        self.title("Add Custom Blocklist Source")
        self.configure(bg=PALETTE["base"])
        master.columnconfigure(1, weight=1)
        try:
            master.configure(padx=18, pady=16)
        except tk.TclError:
            pass
        ttk.Label(
            master,
            text="Save a reusable feed so it appears in Saved Sources for one-click imports later.",
            foreground=PALETTE["subtext"],
            wraplength=360,
            justify="left"
        ).grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 10))
        ttk.Label(master, text="Display Name").grid(row=1, sticky='w', pady=5)
        ttk.Label(master, text="Source URL").grid(row=2, sticky='w', pady=5)
        self.name_entry = ttk.Entry(master, width=40)
        self.url_entry = ttk.Entry(master, width=40)
        self.name_entry.grid(row=1, column=1, padx=5, sticky="ew")
        self.url_entry.grid(row=2, column=1, padx=5, sticky="ew")
        ttk.Label(
            master,
            text="Use a short, recognizable label such as the publisher or use case.",
            foreground=PALETTE["overlay1"],
            wraplength=360,
            justify="left",
        ).grid(row=3, column=1, sticky="w", padx=5, pady=(0, 6))
        ttk.Label(
            master,
            text="Only direct `http://` or `https://` feed URLs are accepted.",
            foreground=PALETTE["overlay1"],
            wraplength=360,
            justify="left",
        ).grid(row=4, column=1, sticky="w", padx=5, pady=(0, 0))
        self.feedback_shell = tk.Frame(
            master,
            bg=PALETTE["panel_alt"],
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
            highlightcolor=PALETTE["focus"],
            bd=0,
        )
        self.feedback_shell.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        self.feedback_label = tk.Label(
            self.feedback_shell,
            textvariable=self.feedback_var,
            bg=PALETTE["panel_alt"],
            fg=PALETTE["yellow"],
            justify="left",
            wraplength=360,
            anchor="w",
            padx=12,
            pady=10,
        )
        self.feedback_label.pack(fill="x")
        self.feedback_shell.grid_remove()
        if self.initial_name:
            self.name_entry.insert(0, self.initial_name)
        if self.initial_url:
            self.url_entry.insert(0, self.initial_url)
        self.name_entry.bind("<KeyRelease>", lambda _event: self._clear_feedback(), add="+")
        self.url_entry.bind("<KeyRelease>", lambda _event: self._clear_feedback(), add="+")
        return self.name_entry

    # Upper bound on any custom source URL. 2083 is the practical browser
    # limit (IE/Edge legacy); anything longer is almost certainly pasted
    # junk or a prompt-injection attempt against the sidebar text.
    _URL_MAX_LEN = 2083
    _NAME_MAX_LEN = 120

    def _set_feedback(self, message: str, *, tone: str = "warning"):
        accent = {
            "warning": PALETTE["yellow"],
            "error": PALETTE["red"],
        }.get(tone, PALETTE["yellow"])
        self.feedback_var.set(message)
        self.feedback_label.configure(fg=accent)
        self.feedback_shell.configure(highlightbackground=accent, highlightcolor=accent)
        self.feedback_shell.grid()
        self.bell()

    def _clear_feedback(self):
        if hasattr(self, "feedback_shell"):
            self.feedback_var.set("")
            self.feedback_shell.grid_remove()

    def validate(self):
        self._clear_feedback()
        name, url = self.name_entry.get().strip(), self.url_entry.get().strip()
        if not name or not url:
            self._set_feedback(
                "Enter both a display name and a direct feed URL before saving this source.",
                tone="warning",
            )
            if not name:
                self.name_entry.focus_set()
            else:
                self.url_entry.focus_set()
            return False

        if len(name) > self._NAME_MAX_LEN:
            self._set_feedback(
                f"Display names are capped at {self._NAME_MAX_LEN} characters so the saved-sources list stays readable.",
                tone="error",
            )
            self.name_entry.focus_set()
            return False

        if any(ord(ch) < 32 for ch in name + url):
            # Embedded tabs / newlines / control bytes would corrupt the
            # sidebar display and the sanitized marker comments. Reject
            # rather than silently stripping.
            self._set_feedback(
                "Display names and URLs cannot contain tabs, newlines, or other control characters.",
                tone="error",
            )
            (self.url_entry if any(ord(ch) < 32 for ch in url) else self.name_entry).focus_set()
            return False

        if not url.lower().startswith(('http://', 'https://')):
            self._set_feedback(
                "Use a direct http:// or https:// URL for the feed you want to save.",
                tone="error",
            )
            self.url_entry.focus_set()
            self.url_entry.selection_range(0, tk.END)
            return False

        if len(url) > self._URL_MAX_LEN:
            self._set_feedback(
                f"Feed URLs are capped at {self._URL_MAX_LEN} characters.",
                tone="error",
            )
            self.url_entry.focus_set()
            return False

        parsed = _parse_valid_http_source_url(url)
        if parsed is None:
            self._set_feedback("That URL could not be parsed. Double-check the address and try again.", tone="error")
            self.url_entry.focus_set()
            return False

        self.result = (name, url)
        return True

    def apply(self):
        name, url = self.name_entry.get().strip(), self.url_entry.get().strip()
        self.result = (name, url)

    def buttonbox(self):
        box = ttk.Frame(self)
        box.configure(padding=(18, 8, 18, 18))
        ttk.Button(box, text="Cancel", width=14, command=self.cancel, style="Secondary.TButton").pack(side="right", padx=(0, 8))
        ttk.Button(box, text="Save Source", width=14, command=self.ok, style="Action.TButton").pack(side="right")
        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)
        box.pack(fill="x")

# -------------------------- Bulk Selection Dialog (New in v2.8.5) ----------------
class BulkSelectionDialog(tk.Toplevel):
    def __init__(self, editor, blocklist_sources, custom_sources):
        self.editor = editor
        super().__init__(editor.root)
        editor._configure_modal_window(
            self,
            title="Select Lists to Import",
            size="700x760",
            min_size=(620, 560),
        )
        self.grab_set()

        self.result = None
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_args: self._rebuild_source_rows())
        self._all_sources: list[tuple[str, str, str, str]] = []
        self._selection_state: dict[tuple[str, str], bool] = {}
        for category, sources in blocklist_sources.items():
            for name, url, tooltip in sources:
                self._all_sources.append((category, name, url, tooltip))
                self._selection_state[(name, url)] = True
        for src in custom_sources:
            name = src["name"]
            url = src["url"]
            self._all_sources.append(("Custom Sources", name, url, "Custom source"))
            self._selection_state[(name, url)] = True
        self._visible_source_keys: list[tuple[str, str]] = []

        header_frame = ttk.Frame(self, padding=(18, 18, 18, 0))
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text="Batch import", style="Eyebrow.TLabel").pack(anchor="w")
        ttk.Label(header_frame, text="Choose the sources you want to import together.", font=("Segoe UI Semibold", 13)).pack(anchor="w", pady=(4, 0))
        ttk.Label(
            header_frame,
            text="Selections are downloaded one at a time so progress, failures, and cancellation stay predictable.",
            foreground=PALETTE["subtext"],
            wraplength=640,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))
        self.selection_summary_label = ttk.Label(header_frame, foreground=PALETTE["overlay1"])
        self.selection_summary_label.pack(anchor="w", pady=(8, 0))
        self.feedback_label = ttk.Label(
            header_frame,
            text="",
            foreground=PALETTE["yellow"],
            wraplength=640,
            justify="left",
        )
        self.feedback_label.pack(anchor="w", pady=(6, 0))

        filter_row = ttk.Frame(self, padding=(18, 14, 18, 0))
        filter_row.pack(fill="x")
        ttk.Label(filter_row, text="Filter", style="SectionTitle.TLabel").pack(side="left")
        self.filter_entry = ttk.Entry(filter_row, textvariable=self.filter_var)
        self.filter_entry.pack(side="left", fill="x", expand=True, padx=(10, 0))
        self.filter_entry.bind("<Escape>", lambda _event: (self.filter_var.set(""), "break")[-1])

        container = ttk.Frame(self, padding=(18, 14, 18, 0))
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container, bg=PALETTE["base"], highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas, padding=(0, 0, 2, 0))

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind("<Enter>", lambda _event: canvas.bind_all("<MouseWheel>", _on_mousewheel))
        canvas.bind("<Leave>", lambda _event: canvas.unbind_all("<MouseWheel>"))
        self.bind("<Destroy>", lambda _event: canvas.unbind_all("<MouseWheel>"), add="+")

        canvas.bind("<Configure>", lambda e: canvas.itemconfigure("bulk-frame", width=e.width))
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw", width=652, tags=("bulk-frame",))
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.empty_state_label = None

        btn_frame = ttk.Frame(self, padding=(18, 14, 18, 18))
        btn_frame.pack(fill="x", side="bottom")

        left_btns = ttk.Frame(btn_frame)
        left_btns.pack(side="left")
        ttk.Button(left_btns, text="Select All Shown", command=self.select_all).pack(side="left", padx=(0, 6))
        ttk.Button(left_btns, text="Clear Shown", command=self.select_none).pack(side="left")

        right_btns = ttk.Frame(btn_frame)
        right_btns.pack(side="right")
        ttk.Button(right_btns, text="Import Selected Sources", command=self.confirm, style="Action.TButton").pack(side="left", padx=5)
        ttk.Button(right_btns, text="Cancel", command=self.destroy, style="Secondary.TButton").pack(side="left")

        self.filter_entry.focus_set()
        self._rebuild_source_rows()

    def _rebuild_source_rows(self):
        for child in self.scrollable_frame.winfo_children():
            child.destroy()
        self.empty_state_label = None
        self._clear_feedback()

        query = self.filter_var.get().strip().lower()
        self._visible_source_keys.clear()
        grouped: dict[str, list[tuple[str, str, str]]] = {}
        for category, name, url, tooltip in self._all_sources:
            haystack = f"{category} {name} {url} {tooltip}".lower()
            if query and query not in haystack:
                continue
            grouped.setdefault(category, []).append((name, url, tooltip))

        if not grouped:
            self.empty_state_label = ttk.Label(
                self.scrollable_frame,
                text="No sources match the current filter.",
                style="SectionBody.TLabel",
                wraplength=600,
                justify="left",
            )
            self.empty_state_label.pack(anchor="w", pady=(6, 0))
            self._update_selection_summary()
            return

        for category, sources in grouped.items():
            self._add_category_header(category, len(sources))
            for name, url, tooltip in sources:
                self._add_checkbox(name, url, tooltip)
        self._update_selection_summary()

    def _add_category_header(self, text, count):
        shell = tk.Frame(
            self.scrollable_frame,
            bg=PALETTE["panel"],
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
            highlightcolor=PALETTE["focus"],
            bd=0,
        )
        shell.pack(fill="x", pady=(0, 6))
        inner = ttk.Frame(shell, style="Section.TFrame", padding=(14, 10, 14, 10))
        inner.pack(fill="both", expand=True)
        ttk.Label(inner, text=text, style="SectionTitle.TLabel").pack(side="left")
        ttk.Label(inner, text=f"{count} shown", style="SectionBody.TLabel").pack(side="right")

    def _add_checkbox(self, name, url, tooltip):
        key = (name, url)
        var = tk.BooleanVar(value=self._selection_state.get(key, True))
        shell = tk.Frame(
            self.scrollable_frame,
            bg=PALETTE["panel_alt"],
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
            highlightcolor=PALETTE["focus"],
            bd=0,
        )
        shell.pack(fill="x", pady=(0, 6))
        frame = ttk.Frame(shell, style="Inset.TFrame", padding=(12, 10, 12, 10))
        frame.pack(fill="both", expand=True)

        row = ttk.Frame(frame, style="Inset.TFrame")
        row.pack(fill="x")
        cb = ttk.Checkbutton(
            row,
            text=name,
            variable=var,
            command=lambda k=key, v=var: self._toggle_selection(k, v),
        )
        cb.pack(side="left", fill="x", expand=True)
        source_host = urllib.parse.urlparse(url).netloc or url
        ttk.Label(row, text=source_host, foreground=PALETTE["subtext"]).pack(side="right", padx=(8, 0))
        ttk.Label(
            frame,
            text=tooltip,
            style="SectionBody.TLabel",
            wraplength=600,
            justify="left",
        ).pack(anchor="w", pady=(6, 0))

        url_short = (url[:72] + "..") if len(url) > 72 else url
        ToolTip(cb, f"{tooltip}\nURL: {url_short}")

        self._visible_source_keys.append(key)

    def _toggle_selection(self, key, var):
        self._selection_state[key] = bool(var.get())
        self._clear_feedback()
        self._update_selection_summary()

    def _set_feedback(self, message: str):
        self.feedback_label.config(text=message)
        self.bell()

    def _clear_feedback(self):
        self.feedback_label.config(text="")

    def _update_selection_summary(self):
        total = len(self._all_sources)
        shown = len(self._visible_source_keys)
        selected_count = sum(1 for selected in self._selection_state.values() if selected)
        visible_selected = sum(1 for key in self._visible_source_keys if self._selection_state.get(key))
        if shown == total:
            self.selection_summary_label.config(text=f"{selected_count} of {total} source(s) selected.")
        else:
            self.selection_summary_label.config(
                text=f"{selected_count} of {total} selected overall. {visible_selected} of {shown} currently shown."
            )

    def select_all(self):
        targets = self._visible_source_keys if self._visible_source_keys else (
            [] if self.filter_var.get().strip() else list(self._selection_state.keys())
        )
        for key in targets:
            self._selection_state[key] = True
        self._clear_feedback()
        self._rebuild_source_rows()

    def select_none(self):
        targets = self._visible_source_keys if self._visible_source_keys else (
            [] if self.filter_var.get().strip() else list(self._selection_state.keys())
        )
        for key in targets:
            self._selection_state[key] = False
        self._clear_feedback()
        self._rebuild_source_rows()

    def confirm(self):
        selected = [
            (name, url)
            for (_category, name, url, _tooltip) in self._all_sources
            if self._selection_state.get((name, url))
        ]

        if not selected:
            self._set_feedback("Select at least one source before starting a batch import.")
            return

        self._clear_feedback()
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
    def __init__(self, editor, query: str, matching_lines: list[tuple[int, str]]):
        self.editor = editor
        super().__init__(editor.root)
        editor._configure_modal_window(
            self,
            title=f"Remove Matches for '{query}'",
            size="820x680",
            min_size=(700, 520),
        )
        self.grab_set()

        self.result = None
        self.checkbox_vars = []

        header_frame = ttk.Frame(self, padding=(18, 18, 18, 0))
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text="Selective removal", style="Eyebrow.TLabel").pack(anchor="w")
        ttk.Label(
            header_frame,
            text=f"Review which matches to remove for '{query}'.",
            font=("Segoe UI Semibold", 13)
        ).pack(anchor="w", pady=(4, 0))
        self.selection_summary_label = ttk.Label(
            header_frame,
            text="",
            foreground=PALETTE["subtext"]
        )
        self.selection_summary_label.pack(anchor="w", pady=(6, 0))
        self.feedback_label = ttk.Label(
            header_frame,
            text="",
            foreground=PALETTE["yellow"],
            wraplength=760,
            justify="left",
        )
        self.feedback_label.pack(anchor="w", pady=(6, 0))
        ttk.Label(
            header_frame,
            text="Unchecked lines stay in the editor. You'll still get a full preview before anything changes.",
            foreground=PALETTE["overlay1"],
            wraplength=760,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

        container = ttk.Frame(self, padding=(18, 14, 18, 0))
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container, bg=PALETTE["base"], highlightthickness=0, bd=0)
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
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure("match-frame", width=e.width))

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw", tags=("match-frame",))
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for line_index, line in matching_lines:
            var = tk.BooleanVar(value=True)
            shell = tk.Frame(
                self.scrollable_frame,
                bg=PALETTE["panel_alt"],
                highlightthickness=1,
                highlightbackground=PALETTE["border"],
                highlightcolor=PALETTE["focus"],
                bd=0,
            )
            shell.pack(fill="x", pady=(0, 6))
            frame = ttk.Frame(shell, style="Inset.TFrame", padding=(12, 10, 12, 10))
            frame.pack(fill="both", expand=True)

            row = ttk.Frame(frame, style="Inset.TFrame")
            row.pack(fill="x")
            cb = ttk.Checkbutton(
                row,
                text=f"Line {line_index + 1:,}",
                variable=var,
                command=self._on_selection_changed,
            )
            cb.pack(side="left")
            ttk.Label(row, text=f"{len(line):,} chars", style="SectionBody.TLabel").pack(side="right")
            ttk.Label(
                frame,
                text=line,
                style="SectionBody.TLabel",
                wraplength=740,
                justify="left",
            ).pack(anchor="w", pady=(8, 0))
            self.checkbox_vars.append((line_index, var))

        btn_frame = ttk.Frame(self, padding=(18, 14, 18, 18))
        btn_frame.pack(fill="x", side="bottom")

        left_btns = ttk.Frame(btn_frame)
        left_btns.pack(side="left")
        ttk.Button(left_btns, text="Select All", command=self.select_all).pack(side="left", padx=(0, 6))
        ttk.Button(left_btns, text="Select None", command=self.select_none).pack(side="left")

        right_btns = ttk.Frame(btn_frame)
        right_btns.pack(side="right")
        ttk.Button(right_btns, text="Remove Selected", command=self.confirm, style="Danger.TButton").pack(side="left", padx=5)
        ttk.Button(right_btns, text="Cancel", command=self.destroy, style="Secondary.TButton").pack(side="left")
        self._update_selection_summary()

    def _update_selection_summary(self):
        total = len(self.checkbox_vars)
        selected_count = sum(1 for _, var in self.checkbox_vars if var.get())
        self.selection_summary_label.config(text=f"{selected_count} of {total} removable line(s) currently selected")

    def _set_feedback(self, message: str):
        self.feedback_label.config(text=message)
        self.bell()

    def _clear_feedback(self):
        self.feedback_label.config(text="")

    def _on_selection_changed(self):
        self._clear_feedback()
        self._update_selection_summary()

    def select_all(self):
        for _, var in self.checkbox_vars:
            var.set(True)
        self._clear_feedback()
        self._update_selection_summary()

    def select_none(self):
        for _, var in self.checkbox_vars:
            var.set(False)
        self._clear_feedback()
        self._update_selection_summary()

    def confirm(self):
        selected_indices = {line_index for line_index, var in self.checkbox_vars if var.get()}
        if not selected_indices:
            self._set_feedback("Select at least one matching line before continuing.")
            return

        self._clear_feedback()
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


def _get_canonical_cleaned_output_and_stats(
    original_lines: list[str],
    whitelist_set: set,
    pinned_domains: set | None = None,
) -> tuple[list[str], dict]:
    stats = {
        "lines_total": len(original_lines),
        "removed_blanks": 0,
        "removed_comments": 0,
        "removed_whitelist": 0,
        "removed_duplicates": 0,
        "removed_invalid": 0,
        "transformed": 0,
        "pinned_preserved": 0,
    }

    pinned = {p.lstrip('.') for p in (pinned_domains or set())}
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
            bare_domain = domain.lstrip('.')
            if is_block_entry and (domain in whitelist_set or bare_domain in whitelist_set):
                # Pinned entries outrank the whitelist — a user who pinned
                # a domain wants it kept blocked even when the same domain
                # is (e.g.) on a shared whitelist feed.
                if bare_domain not in pinned:
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

    # Ensure every pinned domain is present even if the editor never had it.
    for bare in sorted(pinned):
        synthetic = f"0.0.0.0 {bare}"
        if synthetic in seen_normalized:
            continue
        seen_normalized.add(synthetic)
        active_entries_to_keep.append(synthetic)
        stats["pinned_preserved"] += 1

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

def compute_clean_impact_stats(
    original_lines: list[str],
    whitelist_set: set,
    pinned_domains: set | None = None,
) -> dict:
    _, stats = _get_canonical_cleaned_output_and_stats(original_lines, whitelist_set, pinned_domains)
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


def _allocate_unique_sibling_temp_path(target_path: str, suffix: str) -> str:
    """Reserve a unique temp path next to ``target_path`` and return it."""
    directory = os.path.dirname(target_path) or "."
    prefix = os.path.basename(target_path) + "."
    fd, temp_path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=directory)
    os.close(fd)
    try:
        os.unlink(temp_path)
    except OSError:
        pass
    return temp_path


def disable_hosts_file_transactionally(hosts_path: str, disabled_path: str, minimal_content: str) -> None:
    """Disable the hosts file without leaving a stale disabled marker on failure."""
    had_existing_hosts = os.path.exists(hosts_path)
    staged_disabled_path = None

    try:
        if had_existing_hosts:
            staged_disabled_path = _allocate_unique_sibling_temp_path(disabled_path, ".pending")
            shutil.copy2(hosts_path, staged_disabled_path)

        write_text_file_atomic(hosts_path, minimal_content)

        if staged_disabled_path:
            os.replace(staged_disabled_path, disabled_path)
    except Exception:
        if staged_disabled_path and os.path.exists(staged_disabled_path):
            if had_existing_hosts:
                try:
                    shutil.copy2(staged_disabled_path, hosts_path)
                except OSError:
                    pass
            try:
                os.unlink(staged_disabled_path)
            except OSError:
                pass
        raise


def enable_hosts_file_transactionally(hosts_path: str, disabled_path: str) -> None:
    """Re-enable the hosts file without leaving ``.disabled`` behind on success."""
    staged_restore_path = _allocate_unique_sibling_temp_path(disabled_path, ".restore")
    os.replace(disabled_path, staged_restore_path)

    try:
        shutil.copy2(staged_restore_path, hosts_path)
        try:
            os.unlink(staged_restore_path)
        except OSError:
            pass
    except Exception:
        if os.path.exists(staged_restore_path) and not os.path.exists(disabled_path):
            try:
                os.replace(staged_restore_path, disabled_path)
            except OSError:
                pass
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


def _parse_valid_http_source_url(url: str):
    """Return a parsed URL only when it is a direct http(s) URL with a host."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None

    if parsed.scheme.lower() not in ("http", "https"):
        return None
    if not parsed.hostname:
        return None
    return parsed


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
        if _parse_valid_http_source_url(url) is None:
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
            if not isinstance(url, str) or _parse_valid_http_source_url(url) is None:
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
        "pinned_domains": sanitize_pinned_domains(config.get("pinned_domains", [])),
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
            # from a prefix alone - treat the full 172.x as private-ish to
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


def find_sources_containing_domain(domain: str, source_corpus: dict[str, object]) -> list[str]:
    """Return source names whose cached corpus contains ``domain``.

    ``source_corpus`` may be either the legacy ``{name: text}`` shape or the
    newer ``{cache_key: {"name": name, "text": text}}`` shape used to avoid
    collisions between sources that share the same display label.
    """
    target = domain.strip().lower().lstrip('.')
    if not target:
        return []

    needle = re.compile(
        rf'(?:^|[\s\t,/|^=])(?:\*\.)?(?:[a-z0-9][a-z0-9-]*\.)*{re.escape(target)}(?:$|[\s\t,/|^#$])',
        re.IGNORECASE | re.MULTILINE,
    )
    matches: list[str] = []
    seen_names: set[str] = set()
    for cache_key, payload in source_corpus.items():
        if isinstance(payload, dict):
            name = str(payload.get("name") or cache_key)
            text = payload.get("text", "")
        else:
            name = str(cache_key)
            text = payload
        if not text:
            continue
        lowered = text.lower()
        # Fast-path substring check first; confirm with a word-boundary
        # pass so we don't hit "notexample.com" when searching "example.com".
        if target not in lowered:
            continue
        if needle.search(text) and name not in seen_names:
            seen_names.add(name)
            matches.append(name)
    return matches


SCHEDULE_WEEKDAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")
SCHEDULE_WEEKDAY_LABELS = {
    "MON": "Monday",
    "TUE": "Tuesday",
    "WED": "Wednesday",
    "THU": "Thursday",
    "FRI": "Friday",
    "SAT": "Saturday",
    "SUN": "Sunday",
}


def normalize_scheduler_start_time(value: str, default: str = "03:30") -> str:
    candidate = (value or "").strip()
    if not candidate:
        candidate = default

    match = re.fullmatch(r"(\d{1,2}):(\d{2})", candidate)
    if not match:
        raise ValueError("Use a valid 24-hour time in HH:MM format.")

    hour = int(match.group(1))
    minute = int(match.group(2))
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError("Time must be between 00:00 and 23:59.")

    return f"{hour:02d}:{minute:02d}"


def build_schtasks_create_command(
    task_name: str,
    task_command: str,
    frequency: str,
    *,
    start_time: str = "03:30",
    weekday: str = "MON",
) -> tuple[list[str], str]:
    task_name = (task_name or "").strip()
    task_command = (task_command or "").strip()
    frequency = (frequency or "").strip().upper()

    if not task_name:
        raise ValueError("Task name is required.")
    if not task_command:
        raise ValueError("Task command is required.")
    if frequency not in {"DAILY", "WEEKLY", "ONLOGON"}:
        raise ValueError("Unsupported schedule frequency.")

    args = [
        "schtasks", "/Create", "/TN", task_name, "/TR", task_command,
        "/SC", frequency, "/RL", "HIGHEST", "/F",
    ]

    if frequency == "ONLOGON":
        return args, "Runs at sign-in."

    normalized_time = normalize_scheduler_start_time(start_time)
    args += ["/ST", normalized_time]

    if frequency == "WEEKLY":
        normalized_weekday = (weekday or "").strip().upper()
        if normalized_weekday not in SCHEDULE_WEEKDAYS:
            raise ValueError("Choose a weekday for weekly schedules.")
        args += ["/D", normalized_weekday]
        return args, f"Runs every {SCHEDULE_WEEKDAY_LABELS[normalized_weekday]} at {normalized_time}."

    return args, f"Runs daily at {normalized_time}."


def export_lines_as_format(lines: list[str], export_format: str) -> str:
    """Convert cleaned hosts lines to one of the supported export formats.

    Supported formats:
        hosts       - as-is hosts file content (what Cleaned Save writes)
        domains     - one domain per line, no IP
        adblock     - ``||domain^`` uBlock/AdGuard syntax
        dnsmasq     - ``address=/domain/0.0.0.0``
        pihole      - pi-hole gravity-style plain domain list (same as domains)
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

    Unlike the full Cleaned Save, this is surgical - the caller picks which
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

    Ordered-subsequence scorer - every query character must appear in the
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


def sanitize_pinned_domains(value) -> list[str]:
    """Return a deduplicated, lowercase list of valid domain strings.

    Pinned entries are persisted in config. We accept raw domains only
    (not full hosts lines) to keep the stored shape simple. Invalid
    entries are dropped silently so a hand-edited config can't poison
    the list.
    """
    if not isinstance(value, (list, tuple, set)):
        return []
    seen: set[str] = set()
    pinned: list[str] = []
    for candidate in value:
        if not isinstance(candidate, str):
            continue
        normalized = candidate.strip().lower().lstrip('.')
        if not normalized or normalized in seen:
            continue
        if not looks_like_domain(normalized, allow_single_label=False):
            continue
        seen.add(normalized)
        pinned.append(normalized)
    return pinned


# Pi-hole FTL stores per-query rows with integer status codes. Codes 1,4,5,
# 6,7,8,9,10,11 all represent some form of block (upstream block, regex
# match, gravity, wildcard, external block, etc.). Codes 2,3,12 are allow
# decisions. See FTL commit history / pihole-FTL.db schema for the full
# enum.
FTL_BLOCKED_STATUS_CODES = (1, 4, 5, 6, 7, 8, 9, 10, 11)


def _sqlite_readonly_uri(path: str) -> str:
    """Build a SQLite ``file:`` URI that opens ``path`` read-only.

    SQLite URI paths must start with ``/`` for absolute paths. ``pathlib``
    on Windows yields ``C:/foo/bar.db`` (no leading slash), which SQLite
    treats as a relative URI fragment. Prepend a slash for absolute paths.
    """
    posix = pathlib.Path(path).as_posix()
    if not posix.startswith('/'):
        posix = '/' + posix
    return f"file:{posix}?mode=ro"


def parse_pihole_ftl_blocked_domains(sqlite_path: str, max_rows: int = 50_000) -> list[str]:
    """Return blocked domains from a Pi-hole FTL ``pihole-FTL.db`` file.

    Reads the ``queries`` table in read-only mode and keeps only rows where
    the query was blocked (see ``FTL_BLOCKED_STATUS_CODES``). Caller is
    expected to pass a valid path — we raise ``OSError`` subclasses or
    ``sqlite3.Error`` on failure.
    """
    import sqlite3

    if not os.path.isfile(sqlite_path):
        raise FileNotFoundError(f"FTL database not found: {sqlite_path}")

    uri = _sqlite_readonly_uri(sqlite_path)
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as e:
        raise OSError(f"Could not open FTL DB: {e}") from e
    try:
        placeholders = ",".join("?" * len(FTL_BLOCKED_STATUS_CODES))
        cursor = conn.execute(
            f"SELECT DISTINCT domain FROM queries "
            f"WHERE status IN ({placeholders}) "
            f"ORDER BY timestamp DESC LIMIT ?",
            (*FTL_BLOCKED_STATUS_CODES, int(max_rows)),
        )
        rows = cursor.fetchall()
    finally:
        conn.close()

    out: list[str] = []
    seen: set[str] = set()
    for row in rows:
        domain = (row[0] or "").strip().lower().lstrip('.')
        if not domain or domain in seen:
            continue
        if not looks_like_domain(domain, allow_single_label=False):
            continue
        seen.add(domain)
        out.append(domain)
    return out


# AdGuard Home reason codes: only the "Filtered*" family represents an
# actual block decision. Earlier drafts of this parser also accepted 1
# (NotFilteredAllowList) and 9/10 (Rewrite/RewriteAutoHosts), which would
# have imported explicitly-allowed and rewrite-target domains as if they
# were blocks.
AGH_BLOCK_REASONS = frozenset({3, 4, 5, 7, 8, 12})


def parse_adguard_home_querylog(text: str) -> list[str]:
    """Extract blocked domains from an AdGuard Home ``querylog.json`` stream.

    AGH writes NDJSON (one JSON object per line). We pull the ``QH`` field
    (question hostname) from entries where ``Result.Reason`` is one of the
    Filtered* codes (``AGH_BLOCK_REASONS``). ``IsFiltered`` alone is accepted
    as a fallback for log versions where ``Reason`` is missing or 0. If
    ``text`` is a JSON array instead of NDJSON we walk it directly.
    """
    candidates: list[dict] = []
    text = text.strip()
    if not text:
        return []
    if text.startswith('['):
        try:
            loaded = json.loads(text)
            if isinstance(loaded, list):
                candidates = [item for item in loaded if isinstance(item, dict)]
        except ValueError:
            return []
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                candidates.append(obj)

    out: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        result_raw = item.get("Result")
        result = result_raw if isinstance(result_raw, dict) else {}
        reason = result.get("Reason")
        is_filtered = bool(result.get("IsFiltered"))
        if reason in AGH_BLOCK_REASONS:
            pass  # definitely a block
        elif reason is None and is_filtered:
            pass  # missing Reason but IsFiltered=true → legacy log, accept
        else:
            continue
        domain = (item.get("QH") or item.get("Q") or "").strip().lower().rstrip('.')
        if not domain or domain in seen:
            continue
        if not looks_like_domain(domain, allow_single_label=False):
            continue
        seen.add(domain)
        out.append(domain)
    return out


def apply_find_replace(
    lines: list[str],
    pattern: str,
    replacement: str,
    *,
    use_regex: bool = False,
    case_sensitive: bool = False,
) -> tuple[list[str], int]:
    """Plain-text or regex find/replace across all lines. Returns (new_lines, count)."""
    if not pattern:
        return list(lines), 0
    if use_regex:
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            compiled = re.compile(pattern, flags)
        except re.error as e:
            raise ValueError(f"Invalid regex: {e}") from e
        new_lines: list[str] = []
        count = 0
        for line in lines:
            new_line, n = compiled.subn(replacement, line)
            count += n
            new_lines.append(new_line)
        return new_lines, count

    # Literal replace: case-insensitive impl hand-rolled so we preserve
    # original case of *surrounding* text even when matching case-folded.
    if case_sensitive:
        new_lines = []
        count = 0
        for line in lines:
            n = line.count(pattern)
            if n:
                line = line.replace(pattern, replacement)
                count += n
            new_lines.append(line)
        return new_lines, count

    needle = pattern.lower()
    new_lines = []
    count = 0
    for line in lines:
        lowered = line.lower()
        if needle not in lowered:
            new_lines.append(line)
            continue
        # Walk indices to replace in the original case.
        rebuilt: list[str] = []
        i = 0
        while i < len(line):
            j = lowered.find(needle, i)
            if j < 0:
                rebuilt.append(line[i:])
                break
            rebuilt.append(line[i:j])
            rebuilt.append(replacement)
            count += 1
            i = j + len(pattern)
        new_lines.append(''.join(rebuilt))
    return new_lines, count


def discover_import_sections(lines: list[str]) -> list[dict]:
    """Locate every ``# --- {Raw|Normalized} Import Start/End: NAME ---`` block.

    Returns a list of ``{"name", "mode", "start", "end"}`` (inclusive indices).
    Unmatched start markers are skipped silently so a malformed editor can't
    crash the UI - the caller just won't see that block as a whole section.
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
        self.title_font = font.Font(family="Segoe UI Semibold", size=11)
        self.subtitle_font = font.Font(family="Segoe UI", size=9)
        self.hero_font = font.Font(family="Segoe UI Semibold", size=21)
        self.metric_font = font.Font(family="Segoe UI Semibold", size=16)
        self.mono_font = font.Font(family="Consolas", size=11)
        self.mono_small_font = font.Font(family="Consolas", size=10)
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

        # Per-session cache of fetched source text keyed by URL so custom
        # sources cannot collide with curated sources that share a label.
        self._source_corpus_cache: dict[str, dict[str, str]] = {}
        # Persisted across sessions: URL -> ISO timestamp of last successful
        # fetch. Lets source tooltips surface how stale a feed is.
        self.source_last_fetched: dict[str, str] = {}
        self._source_metadata_dirty = False
        self._preferred_block_sink = "0.0.0.0"
        self._backup_retention = BACKUP_RETENTION
        self._has_completed_first_run = False
        # Persistent pinned-domain allowlist. Pinned domains survive Cleaned
        # Save as "keep no matter what", separate from the whitelist which
        # strips entries. Used for the Starred smart view.
        self.pinned_domains: set[str] = set()
        
        self.import_mode = tk.StringVar(value="Normalized") 
        self.dry_run_mode = tk.BooleanVar(value=False)
        self.dry_run_mode.trace_add('write', lambda *args: self._check_dry_run_warning()) 
        self.source_filter_var = tk.StringVar()
        self.source_filter_var.trace_add('write', lambda *args: self._on_source_filter_changed())

        self._init_styles()
        self._init_menubar()
        
        # 1. Initialize Status Bar FIRST
        self.default_status_hint = "Ctrl+S Cleaned Save   Ctrl+Shift+S Raw Save   F5 Reload"
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
        self.progress_status_label = ttk.Label(status_frame, text="", style="StatusMeta.TLabel")
        self.progress_status_label.pack(side=tk.RIGHT, padx=(0, 8))
        self.progress_status_label.pack_forget()
        self.progress_bar = ttk.Progressbar(status_frame, orient="horizontal", mode="determinate", length=300)
        self.progress_bar.pack(side=tk.RIGHT, padx=10)
        self.progress_bar.pack_forget() # Hide initially
        
        self.stop_btn = ttk.Button(status_frame, text="Stop Import", command=self.cancel_import, style="Remove.TButton")
        self.stop_btn.pack(side=tk.RIGHT, padx=5)
        self.stop_btn.pack_forget() # Hide initially

        
        # 2. Run Admin Check & Relaunch Logic
        if not self.check_admin_privileges():
             sys.exit()

        # Root layout: resizable sidebar + primary editor workspace
        root_container = ttk.Frame(root, padding=(10, 0, 10, 10))
        root_container.pack(fill="both", expand=True)
        layout_pane = ttk.Panedwindow(root_container, orient="horizontal", style="Workspace.TPanedwindow")
        layout_pane.pack(fill="both", expand=True)

        # Sidebar setup
        sidebar_outer = ttk.Frame(layout_pane)
        sidebar_outer.configure(width=self.SIDEBAR_WIDTH)
        sidebar_outer.pack_propagate(False)
        layout_pane.add(sidebar_outer, weight=0)

        sidebar_canvas = tk.Canvas(
            sidebar_outer,
            bg=PALETTE["base"],
            highlightthickness=0,
            bd=0,
            relief="flat",
            yscrollincrement=10,
        )
        sidebar_vscroll = ttk.Scrollbar(sidebar_outer, orient="vertical", command=sidebar_canvas.yview)
        self.sidebar_inner = ttk.Frame(sidebar_canvas, padding=(0, 4, 10, 4)) 
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
        right_area = ttk.Frame(layout_pane, padding=(10, 0, 0, 0))
        layout_pane.add(right_area, weight=1)

        hero_frame = ttk.Frame(right_area, padding=(18, 16, 18, 14), style="Panel.TFrame")
        hero_frame.pack(fill="x", pady=(0, 8))

        hero_top = ttk.Frame(hero_frame, style="Panel.TFrame")
        hero_top.pack(fill="x")

        hero_copy = ttk.Frame(hero_top, style="Panel.TFrame")
        hero_copy.pack(side="left", fill="x", expand=True)
        ttk.Label(hero_copy, text=APP_NAME, font=self.hero_font, style="PanelHero.TLabel").pack(anchor='w')
        ttk.Label(
            hero_copy,
            text="Edit the hosts file, import trusted sources, and save with a cleaned default.",
            wraplength=700,
            style="PanelMuted.TLabel"
        ).pack(anchor='w', pady=(4, 0))
        ttk.Label(hero_copy, text=self.HOSTS_FILE_PATH, style="PanelSubtle.TLabel").pack(anchor='w', pady=(8, 0))

        hero_actions = ttk.Frame(hero_top, style="Panel.TFrame")
        hero_actions.pack(side="right", anchor="n", padx=(16, 0))
        self._btn(
            hero_actions,
            "Save Cleaned",
            self.save_cleaned_file,
            "Apply whitelist filtering, cleanup, and deduplication before saving.",
            style="Action.TButton",
        ).pack(side="left", padx=(0, 6))
        self._btn(
            hero_actions,
            "Refresh",
            self.load_file,
            "Reload the current hosts file from disk.",
            style="Secondary.TButton",
        ).pack(side="left", padx=(0, 6))
        self._btn(
            hero_actions,
            "Check Domain",
            self.show_check_domain,
            "Check whether a domain is blocked, whitelisted, or present in fetched sources.",
            style="Accent.TButton",
        ).pack(side="left", padx=(0, 6))
        self._btn(
            hero_actions,
            "Import Sources",
            self.start_import_all,
            "Open the curated picker and import one or more sources.",
            style="Secondary.TButton",
        ).pack(side="left")

        hero_status = ttk.Frame(hero_frame, style="Panel.TFrame")
        hero_status.pack(fill="x", pady=(12, 0))
        self.admin_badge_label = tk.Label(hero_status, font=("Segoe UI Semibold", 9), padx=10, pady=4, bd=0, anchor="w")
        self.admin_badge_label.pack(side="left", padx=(0, 6))
        self.editor_state_badge_label = tk.Label(hero_status, font=("Segoe UI Semibold", 9), padx=10, pady=4, bd=0, anchor="w")
        self.editor_state_badge_label.pack(side="left", padx=(0, 6))
        self.mode_badge_label = tk.Label(hero_status, font=("Segoe UI Semibold", 9), padx=10, pady=4, bd=0, anchor="w")
        self.mode_badge_label.pack(side="left", padx=(0, 6))
        self.dry_run_badge_label = tk.Label(hero_status, font=("Segoe UI Semibold", 9), padx=10, pady=4, bd=0, anchor="w")
        self.dry_run_badge_label.pack(side="left")

        # --- Sidebar Content Starts Here ---
        
        # Workspace actions
        file_ops, _ = self._create_sidebar_card(
            self.sidebar_inner,
            "Save & Refresh",
            "Use Cleaned Save by default, or write the editor exactly as shown.",
        )
        
        # Dry-Run Toggle
        dry_run_frame = ttk.Frame(file_ops)
        dry_run_frame.pack(fill="x", pady=(0, 6))
        self.chk_dry_run = ttk.Checkbutton(dry_run_frame, text="Dry-run only", variable=self.dry_run_mode)
        self.chk_dry_run.pack(side=tk.LEFT)
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

        self._btn(file_ops, "Refresh", self.load_file, "Reload hosts file from disk.").pack(fill="x", pady=(0, 4))
        self._btn(file_ops, "Revert to Backup", self.revert_to_backup, "Preview and restore from .bak if available.", style="Danger.TButton").pack(fill="x")
        
        # Utilities
        utilities_frame, _ = self._create_sidebar_card(
            self.sidebar_inner,
            "Repair",
            "Cleanup, DNS tools, and the last-resort recovery path.",
        )
        util_row = ttk.Frame(utilities_frame)
        util_row.pack(fill="x", pady=(0, 6))
        self._btn(util_row, "Clean", self.auto_clean, "Clean and format hosts file (removes ALL comments/headers).").pack(side="left", expand=True, fill="x", padx=(0, 6))
        self._btn(util_row, "Normalize", self.deduplicate, "Standardize entries and remove duplicates across the full editor.", style="Action.TButton").pack(side="left", expand=True, fill="x", padx=6)
        self._btn(util_row, "Flush DNS", self.flush_dns, "Flush Windows DNS cache.", style="Accent.TButton").pack(side="left", expand=True, fill="x", padx=(6, 0))

        # --- Emergency DNS Unlock Button ---
        emerg_row = ttk.Frame(utilities_frame)
        emerg_row.pack(fill="x", pady=(2, 0))
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
        search_frame, _ = self._create_sidebar_card(
            self.sidebar_inner,
            "Find",
            "Locate domains fast, then step through or remove exact matches.",
        )
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(fill="x", pady=(0, 6))
        self.search_entry.bind("<Return>", lambda event: self.search_find())
        btns = ttk.Frame(search_frame)
        btns.pack(fill="x", pady=(0, 8))
        self._btn(btns, "Find", self.search_find, "Find first match (case-insensitive).").pack(side="left", expand=True, fill="x", padx=(0, 4))
        self._btn(btns, "Prev", self.search_prev, "Find previous match.").pack(side="left", expand=True, fill="x", padx=4)
        self._btn(btns, "Next", self.search_next, "Find next match.").pack(side="left", expand=True, fill="x", padx=4)
        self._btn(btns, "Remove", self.remove_matching_lines, "Remove matching non-comment entries with a selection preview.", style="Danger.TButton").pack(side="left", expand=True, fill="x", padx=4)
        self._btn(btns, "Clear", self.search_clear, "Clear highlights.").pack(side="left", expand=True, fill="x", padx=(4, 0))
        
        self.warning_status_label = tk.Label(
            search_frame,
            text="No cleanup changes are pending.",
            font=("Segoe UI", 9),
            justify="left",
            wraplength=340,
            anchor="w",
            bg=PALETTE["panel"],
            fg=PALETTE["overlay1"],
            padx=0,
            pady=0,
        )
        self.warning_status_label.pack(fill="x", pady=(0, 8))
        self._btn(search_frame, "Re-scan Warnings", self._trigger_ui_update, "Recompute which lines will be discarded or transformed by Cleaned Save.").pack(fill="x")


        # Import Blacklists
        import_frame, _ = self._create_sidebar_card(
            self.sidebar_inner,
            "Import",
            "Browse curated feeds, local logs, and saved URLs.",
        )
        
        # Import Mode Selector
        mode_frame, _ = self._create_inset_section_card(
            import_frame,
            "Import Mode",
            "Choose whether imports should preserve their original structure or be normalized into a cleaner hosts format.",
            accent=PALETTE["blue"],
        )
        mode_row = ttk.Frame(mode_frame, style="Inset.TFrame")
        mode_row.pack(fill="x")

        self.radio_raw = ttk.Radiobutton(
            mode_row,
            text="Raw",
            variable=self.import_mode,
            value="Raw",
            command=lambda: self._set_import_mode_status("Raw"),
        )
        self.radio_raw.pack(side=tk.LEFT, padx=(0, 18))
        self._register_import_widget(self.radio_raw)
        self.radio_normalized = ttk.Radiobutton(
            mode_row,
            text="Normalized",
            variable=self.import_mode,
            value="Normalized",
            command=lambda: self._set_import_mode_status("Normalized"),
        )
        self.radio_normalized.pack(side=tk.LEFT)
        self._register_import_widget(self.radio_normalized)
        self.import_mode_detail_label = ttk.Label(
            mode_frame,
            style="Hint.TLabel",
            wraplength=320,
            justify="left",
        )
        self.import_mode_detail_label.pack(fill="x", pady=(10, 0))
        self._refresh_import_mode_detail()
        
        # --- Import All Lists Button ---
        self.btn_import_all = self._btn(
            import_frame,
            "Browse Sources",
            self.start_import_all,
            "Open a curated picker and import multiple sources in one controlled run.",
            style="Accent.TButton",
        )
        self.btn_import_all.pack(fill="x", pady=(0, 10))
        self._register_import_widget(self.btn_import_all)

        # Local Import
        local_import_frame, _ = self._create_inset_section_card(
            import_frame,
            "Import From File",
            "Turn exported DNS logs into hosts entries.",
            accent=PALETTE["green"],
        )
        self._register_import_widget(
            self._btn(local_import_frame, "From pfSense Log", self.import_pfsense_log, "Import domains from pfSense DNSBL log.")
        ).pack(fill="x", pady=2)
        self._register_import_widget(
            self._btn(local_import_frame, "From NextDNS Log (CSV)", self.import_nextdns_log, "Import blocked domains from a NextDNS Query Log CSV.")
        ).pack(fill="x", pady=2)

        source_catalog, _ = self._create_inset_section_card(
            import_frame,
            "Source Catalog",
            "Filter curated feeds, then preview or import.",
            accent=PALETTE["accent"],
        )
        ttk.Label(source_catalog, text="Filter by name, category, or feed URL", style="Hint.TLabel").pack(anchor='w', pady=(0, 4))
        self.source_filter_entry = ttk.Entry(source_catalog, textvariable=self.source_filter_var)
        self.source_filter_entry.pack(fill="x", pady=(0, 6))
        # Escape clears the filter while focus is inside the entry - quick
        # way to reset back to the full catalog without mouse travel.
        self.source_filter_entry.bind(
            "<Escape>",
            lambda _event: (self.source_filter_var.set(""), "break")[-1],
        )
        self._register_import_widget(self.source_filter_entry)
        self.catalog_summary_label = ttk.Label(source_catalog, text="", style="Hint.TLabel")
        self.catalog_summary_label.pack(anchor='w', pady=(0, 6))
        self.web_catalog_frame = ttk.Frame(source_catalog, style="Inset.TFrame")
        self.web_catalog_frame.pack(fill="x")
        self._populate_blocklist_source_buttons()
        
        # Custom Sources
        self.custom_sources_frame, _ = self._create_sidebar_card(
            self.sidebar_inner,
            "Saved Feeds",
            "Keep your trusted URLs ready for future imports.",
        )
        self.custom_sources_help_label = ttk.Label(
            self.custom_sources_frame,
            text="Saved feeds stay available across sessions.",
            style="Hint.TLabel",
            wraplength=340,
            justify="left"
        )
        self.custom_sources_help_label.pack(fill="x", pady=(0, 2))
        self.custom_sources_summary_label = ttk.Label(
            self.custom_sources_frame,
            text="0 saved feeds.",
            style="Hint.TLabel",
        )
        self.custom_sources_summary_label.pack(fill="x", pady=(0, 2))
        self.custom_sources_empty_label = ttk.Label(
            self.custom_sources_frame,
            text="No saved feeds yet.",
            style="Hint.TLabel",
            wraplength=340,
            justify="left"
        )
        self.custom_sources_empty_label.pack(fill="x", pady=(0, 6))
        
        self.btn_add_custom = self._btn(self.custom_sources_frame, "Add Feed", self.show_add_source_dialog, "Add a new custom URL source.", style="Accent.TButton")
        self.btn_add_custom.pack(fill=tk.X, pady=2, side=tk.BOTTOM)
        self._register_import_widget(self.btn_add_custom)

        # Manual Input
        manual_frame, _ = self._create_sidebar_card(
            self.sidebar_inner,
            "Paste",
            "Append pasted domains or hosts lines using the current import mode.",
        )
        self.manual_text_area = scrolledtext.ScrolledText(
            manual_frame, wrap=tk.WORD, height=8, font=self.mono_small_font
        )
        self._style_code_surface(self.manual_text_area, font_spec=self.mono_small_font)
        self.manual_text_area.pack(fill="x", pady=(10, 4))
        self.manual_summary_label = ttk.Label(
            manual_frame,
            text="0 non-empty lines ready to append.",
            style="Hint.TLabel",
            wraplength=360,
            justify="left"
        )
        self.manual_summary_label.pack(fill="x", pady=(0, 6))
        self._register_import_widget(self.manual_text_area)
        self._register_import_widget(
            self._btn(manual_frame, "Append to Editor", self.append_manual_list, 
                      "Append the content from the text area to the main hosts file.", style="Action.TButton")
        ).pack(fill="x")

        # Whitelist
        whitelist_frame, _ = self._create_sidebar_card(
            self.sidebar_inner,
            "Allowlist",
            "Domains here stay unblocked when you use Cleaned Save.",
        )
        ttk.Label(
            whitelist_frame,
            text="One entry per line.",
            style="Hint.TLabel",
            wraplength=360,
            justify="left"
        ).pack(fill="x", pady=(0, 0))
        self.whitelist_text_area = scrolledtext.ScrolledText(
            whitelist_frame, wrap=tk.WORD, height=8, font=self.mono_small_font
        )
        self._style_code_surface(self.whitelist_text_area, font_spec=self.mono_small_font)
        self.whitelist_text_area.pack(fill="both", expand=True, pady=(10, 4))
        self.whitelist_summary_label = ttk.Label(
            whitelist_frame,
            text="0 allowlist entries. Saved.",
            style="Hint.TLabel",
            wraplength=360,
            justify="left"
        )
        self.whitelist_summary_label.pack(fill="x", pady=(0, 6))
        w_btns = ttk.Frame(whitelist_frame)
        w_btns.pack(fill="x")
        self._btn(w_btns, "Load from File", self.load_whitelist_from_file, "Load whitelist from a text file.").pack(side="left", expand=True, fill="x", padx=(0, 6))
        self._btn(w_btns, "Import Web", self.import_whitelist_from_web, "Import default HOSTShield whitelist.", style="Accent.TButton").pack(side="left", expand=True, fill="x", padx=(6, 0))

        # ---- Editor (Right) ----
        editor_panel = ttk.Frame(right_area)
        editor_panel.pack(fill="both", expand=True)
        
        # Diff Stats Panel
        self.stats_panel = ttk.Frame(editor_panel, style="Panel.TFrame", padding=(16, 14, 16, 14))
        self.stats_panel.pack(fill="x", pady=(0, 8))
        self._init_stats_panel(self.stats_panel)

        editor_shell = tk.Frame(
            editor_panel,
            bg=PALETTE["panel"],
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
            highlightcolor=PALETTE["focus"],
            bd=0,
        )
        editor_shell.pack(expand=True, fill='both')

        editor_toolbar = ttk.Frame(editor_shell, style="Metric.TFrame", padding=(16, 12, 16, 10))
        editor_toolbar.pack(fill="x")
        editor_toolbar_copy = ttk.Frame(editor_toolbar, style="Metric.TFrame")
        editor_toolbar_copy.pack(side="left", fill="x", expand=True)
        ttk.Label(editor_toolbar_copy, text="Editor", style="SectionTitle.TLabel").pack(anchor="w")
        ttk.Label(
            editor_toolbar_copy,
            text="Edit directly, then save either the exact file or the cleaned result.",
            style="ToolbarMeta.TLabel",
            wraplength=720,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))
        editor_toolbar_actions = ttk.Frame(editor_toolbar, style="Metric.TFrame")
        editor_toolbar_actions.pack(side="right", anchor="n")
        self._btn(editor_toolbar_actions, "Goto Anything", self.show_goto_anything, "Jump to a domain, source, or editor line.", style="Secondary.TButton").pack(side="left", padx=(0, 6))
        self._btn(editor_toolbar_actions, "Export Cleaned", self.show_export_dialog, "Export the cleaned hosts view in another format.", style="Secondary.TButton").pack(side="left", padx=(0, 6))
        self._btn(editor_toolbar_actions, "Sources Report", self.show_sources_report, "See which imported sources contribute the most blocking entries.", style="TButton").pack(side="left")
        ttk.Separator(editor_shell, orient="horizontal").pack(fill="x")

        editor_container = ttk.Frame(editor_shell, style="Metric.TFrame", padding=(14, 0, 14, 14))
        editor_container.pack(expand=True, fill='both')

        self.line_gutter = tk.Canvas(
            editor_container, width=58, bg=PALETTE["mantle"],
            highlightthickness=0, bd=0, relief="flat",
        )
        self.line_gutter.pack(side="left", fill="y")

        editor_scroll = ttk.Scrollbar(editor_container, orient="vertical")
        editor_scroll.pack(side="right", fill="y")
        editor_scroll_x = ttk.Scrollbar(editor_container, orient="horizontal")
        editor_scroll_x.pack(side="bottom", fill="x", padx=(8, 0))

        self.text_area = tk.Text(
            editor_container, wrap=tk.NONE, font=self.mono_font,
            yscrollcommand=lambda first, last: self._on_editor_scroll(editor_scroll, first, last),
            xscrollcommand=editor_scroll_x.set,
        )
        self.text_area.pack(side="left", expand=True, fill='both')
        editor_scroll.config(command=self.text_area.yview)
        editor_scroll_x.config(command=self.text_area.xview)
        self._style_code_surface(self.text_area, font_spec=self.mono_font)

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
        self.root.bind("<Control-h>", self.show_find_replace_dialog)
        self.root.bind("<Control-H>", self.show_find_replace_dialog)

        # Init
        try:
            self.load_config()
        except Exception as e:
            self._show_notice_dialog(
                "Configuration could not be loaded",
                "The app will continue with safe defaults for this session because the saved configuration could not be loaded cleanly.",
                tone="error",
                details=str(e),
            )
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

    def _configure_modal_window(
        self,
        dialog: tk.Toplevel,
        *,
        title: str,
        size: str,
        min_size: tuple[int, int] | None = None,
    ) -> tk.Toplevel:
        """Apply consistent chrome to in-app dialogs."""
        dialog.title(title)
        dialog.configure(bg=PALETTE["base"])
        dialog.transient(self.root)
        dialog.geometry(size)
        if min_size:
            dialog.minsize(*min_size)
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        return dialog

    def _create_sidebar_card(
        self,
        parent,
        title: str,
        description: str | None = None,
        *,
        accent: str | None = None,
    ):
        """Create a compact sidebar section with a short header and body."""
        shell = tk.Frame(
            parent,
            bg=PALETTE["panel"],
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
            highlightcolor=PALETTE["focus"],
            bd=0,
        )
        shell.pack(fill="x", padx=10, pady=(0, 8))

        inner = ttk.Frame(shell, style="Section.TFrame", padding=(14, 12, 14, 14))
        inner.pack(fill="both", expand=True)

        header = ttk.Frame(inner, style="Section.TFrame")
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text=title, style="SectionTitle.TLabel").pack(anchor="w")
        if description:
            ttk.Label(
                header,
                text=description,
                style="SectionBody.TLabel",
                wraplength=320,
                justify="left",
            ).pack(anchor="w", pady=(4, 0))

        body = ttk.Frame(inner, style="Section.TFrame")
        body.pack(fill="both", expand=True)
        return body, shell

    def _create_inset_section_card(
        self,
        parent,
        title: str,
        description: str | None = None,
        *,
        accent: str | None = None,
    ):
        """Create a compact grouped section inside a larger sidebar card."""
        shell = tk.Frame(
            parent,
            bg=PALETTE["panel_alt"],
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
            highlightcolor=PALETTE["focus"],
            bd=0,
        )
        shell.pack(fill="x", pady=(0, 6))

        inner = ttk.Frame(shell, style="Inset.TFrame", padding=(12, 10, 12, 12))
        inner.pack(fill="both", expand=True)

        header = ttk.Frame(inner, style="Inset.TFrame")
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text=title, style="InsetTitle.TLabel").pack(anchor="w")
        if description:
            ttk.Label(
                header,
                text=description,
                style="InsetBody.TLabel",
                wraplength=320,
                justify="left",
            ).pack(anchor="w", pady=(4, 0))

        body = ttk.Frame(inner, style="Inset.TFrame")
        body.pack(fill="both", expand=True)
        return body, shell

    def _style_code_surface(self, widget, *, font_spec=None):
        """Give editable text surfaces a calmer, higher-contrast treatment."""
        widget.configure(
            bg=PALETTE["crust"],
            fg=PALETTE["text"],
            insertbackground=PALETTE["text"],
            insertwidth=2,
            selectbackground=PALETTE["blue"],
            selectforeground=PALETTE["crust"],
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
            highlightcolor=PALETTE["focus"],
            padx=10,
            pady=10,
        )
        if font_spec is not None:
            widget.configure(font=font_spec)

    def _style_listbox_surface(self, widget, *, font_spec=None):
        """Apply the same contrast and focus language to list surfaces."""
        widget.configure(
            bg=PALETTE["crust"],
            fg=PALETTE["text"],
            selectbackground=PALETTE["blue"],
            selectforeground=PALETTE["crust"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
            highlightcolor=PALETTE["focus"],
            borderwidth=0,
            activestyle="none",
        )
        if font_spec is not None:
            widget.configure(font=font_spec)

    def _create_metric_tile(self, parent, title, var, row, col, color=PALETTE["text"]):
        card = tk.Frame(
            parent,
            bg=PALETTE["panel_alt"],
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
            highlightcolor=PALETTE["focus"],
            bd=0,
        )
        card.grid(row=row, column=col, sticky="nsew", padx=4, pady=4)
        ttk.Frame(card, style="Inset.TFrame", padding=(12, 10, 12, 10)).pack(fill="both", expand=True)
        inner = card.winfo_children()[0]
        ttk.Label(inner, text=title, style="MetricLabel.TLabel", wraplength=150, justify="left").pack(anchor="w")
        ttk.Label(inner, textvariable=var, style="MetricValue.TLabel", foreground=color).pack(anchor="w", pady=(6, 0))
        return card

    def _dialog_accent_for_tone(self, tone: str) -> str:
        return {
            "info": PALETTE["blue"],
            "success": PALETTE["green"],
            "warning": PALETTE["yellow"],
            "error": PALETTE["red"],
        }.get(tone, PALETTE["blue"])

    def _show_notice_dialog(
        self,
        title: str,
        message: str,
        *,
        tone: str = "info",
        details: str | None = None,
        width: int = 560,
        height: int | None = None,
        action_text: str = "Close",
    ) -> None:
        dialog = tk.Toplevel(self.root)
        body_height = height or (520 if details else 320)
        self._configure_modal_window(
            dialog,
            title=title,
            size=f"{width}x{body_height}",
            min_size=(min(width, 520), 280 if not details else 420),
        )
        intro, _ = self._create_sidebar_card(
            dialog,
            title,
            message,
            accent=self._dialog_accent_for_tone(tone),
        )
        if details:
            details_box = scrolledtext.ScrolledText(dialog, wrap=tk.WORD)
            self._style_code_surface(details_box, font_spec=self.mono_small_font)
            details_box.pack(expand=True, fill="both", padx=20, pady=(0, 12))
            details_box.insert(tk.END, details)
            details_box.configure(state="disabled")

        footer = ttk.Frame(dialog)
        footer.pack(fill="x", padx=20, pady=(0, 20))
        ttk.Button(footer, text=action_text, command=dialog.destroy, style="Action.TButton").pack(side="right")
        dialog.grab_set()
        self.root.wait_window(dialog)

    def _confirm_dialog(
        self,
        title: str,
        message: str,
        *,
        tone: str = "warning",
        confirm_text: str = "Continue",
        cancel_text: str = "Cancel",
        details: str | None = None,
        width: int = 580,
    ) -> bool:
        dialog = tk.Toplevel(self.root)
        body_height = 520 if details else 320
        self._configure_modal_window(
            dialog,
            title=title,
            size=f"{width}x{body_height}",
            min_size=(min(width, 540), 280 if not details else 420),
        )
        result = {"value": False}
        intro, _ = self._create_sidebar_card(
            dialog,
            title,
            message,
            accent=self._dialog_accent_for_tone(tone),
        )
        ttk.Label(
            intro,
            text="Review the impact before you continue.",
            style="SectionBody.TLabel",
            wraplength=max(420, width - 80),
            justify="left",
        ).pack(anchor="w")

        if details:
            details_box = scrolledtext.ScrolledText(dialog, wrap=tk.WORD)
            self._style_code_surface(details_box, font_spec=self.mono_small_font)
            details_box.pack(expand=True, fill="both", padx=20, pady=(0, 12))
            details_box.insert(tk.END, details)
            details_box.configure(state="disabled")

        footer = ttk.Frame(dialog)
        footer.pack(fill="x", padx=20, pady=(0, 20))

        def accept():
            result["value"] = True
            dialog.destroy()

        ttk.Button(footer, text=cancel_text, command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        ttk.Button(
            footer,
            text=confirm_text,
            command=accept,
            style="Danger.TButton" if tone in {"warning", "error"} else "Action.TButton",
        ).pack(side="right", padx=(0, 8))
        dialog.grab_set()
        self.root.wait_window(dialog)
        return result["value"]

    def _show_text_report_dialog(
        self,
        title: str,
        intro_text: str,
        body_text: str,
        *,
        tone: str = "info",
        width: int = 720,
        height: int = 560,
    ) -> None:
        dialog = tk.Toplevel(self.root)
        self._configure_modal_window(
            dialog,
            title=title,
            size=f"{width}x{height}",
            min_size=(min(width, 620), min(height, 460)),
        )
        intro, _ = self._create_sidebar_card(
            dialog,
            title,
            intro_text,
            accent=self._dialog_accent_for_tone(tone),
        )
        ttk.Label(intro, text="Details", style="SectionTitle.TLabel").pack(anchor="w")
        text_box = scrolledtext.ScrolledText(dialog, wrap=tk.WORD)
        self._style_code_surface(text_box, font_spec=self.mono_small_font)
        text_box.pack(expand=True, fill="both", padx=20, pady=(0, 12))
        text_box.insert(tk.END, body_text)
        text_box.configure(state="disabled")
        footer = ttk.Frame(dialog)
        footer.pack(fill="x", padx=20, pady=(0, 20))
        ttk.Button(footer, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        dialog.grab_set()

    def _init_stats_panel(self, parent):
        # StringVars let us format large counts with thousand separators -
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

        header = ttk.Frame(parent, style="Panel.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Cleanup summary", style="SectionTitle.TLabel").pack(anchor="w")
        self.clean_overview_label = ttk.Label(
            header,
            text="Cleaned Save tracks the main changes live while you edit.",
            style="SectionBody.TLabel",
            wraplength=920,
            justify="left",
        )
        self.clean_overview_label.pack(anchor="w", pady=(4, 0))

        grid_frame = ttk.Frame(parent, style="Panel.TFrame")
        grid_frame.pack(fill="x", pady=(10, 0))

        self._create_metric_tile(grid_frame, "Input lines", self.stat_vars["total"], row=0, col=0)
        self._create_metric_tile(grid_frame, "Final active", self.stat_vars["final_active"], row=0, col=1, color=PALETTE["green"])
        self._create_metric_tile(grid_frame, "Will remove", self.stat_vars["total_discarded"], row=0, col=2, color=PALETTE["red"])
        self._create_metric_tile(grid_frame, "Will normalize", self.stat_vars["transformed"], row=0, col=3, color=PALETTE["yellow"])

        for column in range(4):
            grid_frame.grid_columnconfigure(column, weight=1)

    def _refresh_mode_badges(self, _lines=None, _current_hash=None):
        if not hasattr(self, "admin_badge_label"):
            return

        admin_ready = self.is_admin
        dry_run = self.dry_run_mode.get()
        import_mode = self.import_mode.get()

        self.admin_badge_label.config(
            text="Administrator" if admin_ready else "Read-only",
            bg=PALETTE["panel_alt"],
            fg=PALETTE["green"] if admin_ready else PALETTE["red"]
        )
        editor_state_text = "Editor ready"
        editor_state_bg = PALETTE["panel_alt"]
        editor_state_fg = PALETTE["overlay1"]
        if hasattr(self, "text_area"):
            lines = _lines if _lines is not None else self.get_lines()
            has_content = any(line.strip() for line in lines)
            current_hash = _current_hash if _current_hash is not None else self._hash_lines(lines)
            if self._has_unsaved_changes(_lines=lines, _current_hash=current_hash):
                editor_state_text = "Unsaved changes"
                editor_state_fg = PALETTE["yellow"]
            elif self._last_applied_cleaned_hash is not None and current_hash == self._last_applied_cleaned_hash:
                editor_state_text = "Matches cleaned save"
                editor_state_fg = PALETTE["green"]
            elif self._last_applied_raw_hash is not None and current_hash == self._last_applied_raw_hash:
                editor_state_text = "Matches disk copy"
                editor_state_fg = PALETTE["overlay1"]
            elif not has_content:
                editor_state_text = "Editor is empty"
                editor_state_fg = PALETTE["overlay1"]
        self.editor_state_badge_label.config(
            text=editor_state_text,
            bg=editor_state_bg,
            fg=editor_state_fg
        )
        self.mode_badge_label.config(
            text=f"Mode: {import_mode}",
            bg=PALETTE["panel_alt"],
            fg=PALETTE["blue"]
        )
        self.dry_run_badge_label.config(
            text="Dry-run enabled" if dry_run else "Disk writes enabled",
            bg=PALETTE["panel_alt"],
            fg=PALETTE["blue"] if dry_run else PALETTE["overlay1"]
        )

    def _set_import_mode_status(self, mode):
        self._refresh_mode_badges()
        self._refresh_import_mode_detail()
        self._update_manual_summary()
        if mode == "Raw":
            self.update_status("Import mode set to Raw.")
        else:
            self.update_status("Import mode set to Normalized.")

    def _refresh_import_mode_detail(self):
        if not hasattr(self, "import_mode_detail_label"):
            return

        if self.import_mode.get() == "Raw":
            text = (
                "Keeps source formatting, comments, and markers."
            )
        else:
            text = (
                "Converts entries into clean 0.0.0.0 hosts lines."
            )
        self.import_mode_detail_label.config(text=text)

    def _iter_known_sources(self):
        for category, sources in self.BLOCKLIST_SOURCES.items():
            for name, url, _tooltip in sources:
                yield {"name": name, "url": url, "category": category, "kind": "curated"}
        for entry in self.custom_sources:
            yield {
                "name": entry["name"],
                "url": entry["url"],
                "category": "Saved Sources",
                "kind": "saved",
            }

    def _cache_source_corpus(self, name: str, url: str, raw_lines: list[str]):
        cache_key = normalize_custom_source_url(url) or url
        text = '\n'.join(raw_lines)
        if len(text) > SOURCE_CORPUS_CACHE_MAX_ENTRY_BYTES:
            text = text[:SOURCE_CORPUS_CACHE_MAX_ENTRY_BYTES]

        if cache_key in self._source_corpus_cache:
            self._source_corpus_cache.pop(cache_key, None)
        self._source_corpus_cache[cache_key] = {"name": name, "url": url, "text": text}

        total_bytes = sum(len(entry.get("text", "")) for entry in self._source_corpus_cache.values())
        while (
            len(self._source_corpus_cache) > SOURCE_CORPUS_CACHE_MAX_ENTRIES
            or total_bytes > SOURCE_CORPUS_CACHE_MAX_TOTAL_BYTES
        ):
            oldest_key = next(iter(self._source_corpus_cache))
            removed = self._source_corpus_cache.pop(oldest_key, {})
            total_bytes -= len(removed.get("text", ""))

    def _persist_source_metadata_if_needed(self):
        if not getattr(self, "_source_metadata_dirty", False):
            return
        if self.save_config():
            self._source_metadata_dirty = False

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

            category_frame = ttk.Frame(self.web_catalog_frame, style="Inset.TFrame", padding=(0, 0, 0, 8))
            category_frame.pack(fill="x", pady=(0, 8))
            category_header = ttk.Frame(category_frame, style="Inset.TFrame")
            category_header.pack(fill="x", pady=(0, 6))
            ttk.Label(category_header, text=category, style="InsetTitle.TLabel").pack(side="left")
            ttk.Label(category_header, text=f"{len(filtered_sources)} source(s)", style="InsetBody.TLabel").pack(side="right")
            ttk.Separator(category_frame, orient="horizontal").pack(fill="x", pady=(0, 4))
            rows_container = ttk.Frame(category_frame, style="Inset.TFrame")
            rows_container.pack(fill="x")
            for index, (name, url, tooltip) in enumerate(filtered_sources):
                row = ttk.Frame(rows_container, style="Inset.TFrame", padding=(0, 8, 0, 8))
                row.pack(fill="x")

                copy = ttk.Frame(row, style="Inset.TFrame")
                copy.pack(side="left", fill="x", expand=True)
                last_stamp = self.source_last_fetched.get(url, "") if hasattr(self, "source_last_fetched") else ""
                stamp_hint = format_relative_time(last_stamp)
                source_host = urllib.parse.urlparse(url).netloc or url
                freshness = f"Fetched {stamp_hint}" if stamp_hint else "Not fetched yet"
                tooltip_full = f"{tooltip}\n\nLast fetched: {stamp_hint}" if stamp_hint else tooltip
                ttk.Label(copy, text=name, style="InsetTitle.TLabel").pack(anchor="w")
                ttk.Label(copy, text=f"{source_host}  |  {freshness}", style="InsetBody.TLabel", wraplength=260, justify="left").pack(anchor="w", pady=(3, 0))
                ttk.Label(copy, text=tooltip, style="InsetBody.TLabel", wraplength=250, justify="left").pack(anchor="w", pady=(3, 0))

                action_row = ttk.Frame(row, style="Inset.TFrame")
                action_row.pack(side="right", padx=(12, 0))
                import_btn = self._btn(
                    action_row, "Import",
                    lambda u=url, n=name: self.start_single_import(n, u),
                    tooltip_full,
                    style="Action.TButton",
                )
                self._register_import_widget(import_btn)
                import_btn.pack(side="left")
                preview_btn = self._btn(
                    action_row, "Peek",
                    lambda u=url, n=name: self.preview_blocklist_source(n, u),
                    f"Preview the first entries of {name} without importing.",
                    style="TButton",
                )
                self._register_import_widget(preview_btn)
                preview_btn.pack(side="left", padx=(6, 0))

                if index < len(filtered_sources) - 1:
                    ttk.Separator(rows_container, orient="horizontal").pack(fill="x")

        if matched_sources == 0:
            ttk.Label(
                self.web_catalog_frame,
                text="No sources matched the current filter.",
                style="Hint.TLabel",
                wraplength=340
            ).pack(anchor='w', pady=4)
            self.catalog_summary_label.config(text="0 sources shown. Clear or broaden the filter.")
        else:
            suffix = f" for '{query}'" if query else ""
            self.catalog_summary_label.config(text=f"Showing {matched_sources} sources across {matched_categories} categories{suffix}.")

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
        stats = compute_clean_impact_stats(lines, self._get_whitelist_set(), self.pinned_domains)

        self.stat_vars["total"].set(f"{stats['lines_total']:,}")
        self.stat_vars["final_active"].set(f"{stats['final_active']:,}")
        self.stat_vars["removed_comments"].set(f"{stats['removed_comments'] + stats['removed_blanks']:,}")
        self.stat_vars["removed_duplicates"].set(f"{stats['removed_duplicates']:,}")
        self.stat_vars["transformed"].set(f"{stats['transformed']:,}")
        self.stat_vars["removed_whitelist"].set(f"{stats['removed_whitelist']:,}")
        self.stat_vars["total_discarded"].set(f"{stats['total_discarded']:,}")

        discard_count = stats["removed_invalid"] + stats["removed_duplicates"] + stats["removed_whitelist"]

        if discard_count > 0:
            overview_text = (
                f"Cleaned Save keeps {stats['final_active']:,} active entr"
                f"{'y' if stats['final_active'] == 1 else 'ies'}, removes {discard_count:,}, "
                f"and normalizes {stats['transformed']:,} line(s)."
            )
            self.warning_status_label.config(
                text=f"Will remove {discard_count:,} entries and normalize {stats['transformed']:,} line(s).",
                foreground=PALETTE["red"]
            )
        elif stats["transformed"] > 0:
            overview_text = (
                f"Cleaned Save preserves every entry and standardizes "
                f"{stats['transformed']:,} line(s)."
            )
            self.warning_status_label.config(
                text=f"Will normalize {stats['transformed']:,} line(s). No entries will be removed.",
                foreground=PALETTE["yellow"]
            )
        else:
            overview_text = (
                "The editor already matches the cleaned result."
            )
            self.warning_status_label.config(
                text="No cleanup changes are pending.",
                foreground=PALETTE["green"]
            )
        if hasattr(self, "clean_overview_label"):
            self.clean_overview_label.config(text=overview_text)


    # ----------------------------- Styles & Menus -----------------------------
    def _init_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Base
        style.configure(".", background=PALETTE["base"], foreground=PALETTE["text"], fieldbackground=PALETTE["surface0"])
        style.configure("TFrame", background=PALETTE["base"])
        style.configure("TLabel", background=PALETTE["base"], foreground=PALETTE["text"])
        style.configure("Workspace.TPanedwindow", background=PALETTE["base"])
        style.configure("Panel.TFrame", background=PALETTE["mantle"])
        style.configure("Panel.TLabel", background=PALETTE["mantle"], foreground=PALETTE["text"])
        style.configure("PanelHero.TLabel", background=PALETTE["mantle"], foreground=PALETTE["text"])
        style.configure("PanelMuted.TLabel", background=PALETTE["mantle"], foreground=PALETTE["subtext"])
        style.configure("PanelSubtle.TLabel", background=PALETTE["mantle"], foreground=PALETTE["overlay1"])
        style.configure("Hint.TLabel", background=PALETTE["panel"], foreground=PALETTE["overlay1"])
        style.configure("Section.TFrame", background=PALETTE["panel"])
        style.configure("SectionTitle.TLabel", background=PALETTE["panel"], foreground=PALETTE["text"], font=self.title_font)
        style.configure("SectionBody.TLabel", background=PALETTE["panel"], foreground=PALETTE["subtext"])
        style.configure("Inset.TFrame", background=PALETTE["panel_alt"])
        style.configure("InsetTitle.TLabel", background=PALETTE["panel_alt"], foreground=PALETTE["text"], font=self.title_font)
        style.configure("InsetBody.TLabel", background=PALETTE["panel_alt"], foreground=PALETTE["subtext"])
        style.configure("Metric.TFrame", background=PALETTE["panel"])
        style.configure("MetricLabel.TLabel", background=PALETTE["panel_alt"], foreground=PALETTE["subtext"], font=self.subtitle_font)
        style.configure("MetricValue.TLabel", background=PALETTE["panel_alt"], foreground=PALETTE["text"], font=("Segoe UI Semibold", 15))
        style.configure("ToolbarMeta.TLabel", background=PALETTE["panel"], foreground=PALETTE["subtext"], font=self.subtitle_font)
        style.configure("Eyebrow.TLabel", background=PALETTE["mantle"], foreground=PALETTE["overlay1"], font=self.subtitle_font)
        style.configure("EyebrowOnInset.TLabel", background=PALETTE["panel_alt"], foreground=PALETTE["overlay1"], font=self.subtitle_font)
        style.configure("StatusMeta.TLabel", background=PALETTE["base"], foreground=PALETTE["overlay1"])
        style.configure("TSeparator", background=PALETTE["border"])
        style.configure(
            "TLabelFrame",
            background=PALETTE["panel_alt"],
            foreground=PALETTE["text"],
            borderwidth=1,
            relief="solid",
            bordercolor=PALETTE["border"],
        )
        style.configure("TLabelframe.Label", background=PALETTE["panel_alt"], foreground=PALETTE["text"], font=self.title_font)
        style.configure(
            "TEntry",
            fieldbackground=PALETTE["crust"],
            foreground=PALETTE["text"],
            insertcolor=PALETTE["text"],
            padding=(9, 7),
            borderwidth=1,
            relief="flat",
        )
        style.map("TEntry",
                  fieldbackground=[("focus", PALETTE["crust"])],
                  bordercolor=[("focus", PALETTE["focus"])])
        style.configure("TCheckbutton", background=PALETTE["panel"], foreground=PALETTE["text"])
        style.map("TCheckbutton",
                  background=[("active", PALETTE["panel"])],
                  indicatorcolor=[("selected", PALETTE["blue"])])
        style.configure("TRadiobutton", background=PALETTE["panel_alt"], foreground=PALETTE["text"])
        style.map("TRadiobutton",
                  background=[("active", PALETTE["panel_alt"])],
                  indicatorcolor=[("selected", PALETTE["blue"])])
        style.configure(
            "TMenubutton",
            background=PALETTE["surface0"],
            foreground=PALETTE["text"],
            padding=(10, 7),
            relief="flat",
            borderwidth=1,
            arrowcolor=PALETTE["text"],
        )
        style.map("TMenubutton", background=[("active", PALETTE["surface1"])])

        # Neutral Button
        style.configure("TButton",
                        background=PALETTE["surface0"], foreground=PALETTE["text"],
                        padding=(10, 7), relief="flat", borderwidth=0, focusthickness=1, focuscolor=PALETTE["focus"])
        style.map("TButton",
                  background=[("active", PALETTE["surface1"])],
                  relief=[("pressed", "sunken")])

        style.configure("Secondary.TButton",
                        background=PALETTE["surface1"], foreground=PALETTE["text"],
                        padding=(10, 7), relief="flat", borderwidth=0)
        style.map("Secondary.TButton",
                  background=[("active", PALETTE["surface2"])],
                  relief=[("pressed", "sunken")])
        
        # Remove Button (Small)
        style.configure("Remove.TButton",
                        background=PALETTE["red"], foreground="#1b0e13",
                        padding=(6, 3), relief="flat", borderwidth=0, font=("Segoe UI", 8, "bold"))
        style.map("Remove.TButton",
                  background=[("active", PALETTE["red_hover"])],
                  relief=[("pressed", "sunken")])

        # Accent Button (blue)
        style.configure("Accent.TButton",
                        background=PALETTE["surface1"], foreground=PALETTE["text"],
                        padding=(10, 7), relief="flat", borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", PALETTE["surface2"])])

        # Action Button (primary)
        style.configure("Action.TButton",
                        background=PALETTE["blue"], foreground="#0b1020",
                        padding=(10, 7), relief="flat", borderwidth=0)
        style.map("Action.TButton",
                  background=[("active", PALETTE["blue_hover"])],
                  relief=[("pressed", "sunken")])

        style.configure("Saved.TButton",
                        background=PALETTE["green"], foreground="#0b1020",
                        padding=(10, 6), relief="flat", borderwidth=0)
        style.map("Saved.TButton",
                  background=[("active", PALETTE["green_hover"])],
                  relief=[("pressed", "sunken")])

        # Danger Button (revert, destructive-ish)
        style.configure("Danger.TButton",
                        background=PALETTE["red"], foreground="#1b0e13",
                        padding=(10, 7), relief="flat", borderwidth=0)
        style.map("Danger.TButton",
                  background=[("active", PALETTE["red_hover"])],
                  relief=[("pressed", "sunken")])

        # Scrollbar to better match dark scheme
        style.configure("Vertical.TScrollbar", background=PALETTE["panel"], troughcolor=PALETTE["crust"], arrowcolor=PALETTE["text"])
        style.configure("Horizontal.TScrollbar", background=PALETTE["panel"], troughcolor=PALETTE["crust"], arrowcolor=PALETTE["text"])
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=PALETTE["panel_alt"],
            background=PALETTE["blue"],
            bordercolor=PALETTE["panel_alt"],
            lightcolor=PALETTE["blue_hover"],
            darkcolor=PALETTE["blue"],
        )

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
        file_menu.add_command(label="Compare Backups...", command=self.show_backup_diff_viewer)
        file_menu.add_command(label="Panic Restore (Microsoft default)", command=self.panic_restore_stock)
        file_menu.add_separator()
        file_menu.add_command(label="Export Cleaned As...", command=self.show_export_dialog)
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
        cleanup_menu.add_command(label="Remove Import Section...", command=self.show_remove_import_section)
        tools_menu.add_cascade(label="Targeted Cleanup", menu=cleanup_menu)
        tools_menu.add_separator()
        tools_menu.add_command(label="Check Domain...", command=self.show_check_domain)
        tools_menu.add_command(label="Hosts Health Scan...", command=self.show_health_scan)
        tools_menu.add_command(label="Sources Report...", command=self.show_sources_report)
        tools_menu.add_command(label="Goto Anything...", command=self.show_goto_anything)
        tools_menu.add_command(label="Find and Replace...", command=self.show_find_replace_dialog)
        tools_menu.add_command(label="Pinned Domains...", command=self.show_pinned_domains)
        tools_menu.add_separator()
        import_menu = tk.Menu(tools_menu, tearoff=0, bg=PALETTE["mantle"], fg=PALETTE["text"],
                              activebackground=PALETTE["blue"], activeforeground="#0b1020")
        import_menu.add_command(label="From pfSense DNSBL log...", command=self.import_pfsense_log)
        import_menu.add_command(label="From NextDNS query log (CSV)...", command=self.import_nextdns_log)
        import_menu.add_command(label="From Pi-hole FTL (pihole-FTL.db)...", command=self.import_pihole_ftl)
        import_menu.add_command(label="From AdGuard Home query log...", command=self.import_adguard_home_querylog)
        tools_menu.add_cascade(label="Import Blocked Queries From Log", menu=import_menu)
        tools_menu.add_separator()
        tools_menu.add_command(label="Schedule Auto-Update...", command=self.show_schedule_wizard)
        tools_menu.add_command(label="Preferences...", command=self.show_preferences)
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
            overflow_suffix = "..."
            message = message[: self._STATUS_MESSAGE_MAX_LEN - len(overflow_suffix)] + overflow_suffix
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
            self._show_notice_dialog(
                "Could not create config folder",
                "The app was unable to create the configuration directory needed for local settings.",
                tone="error",
                details=str(e),
            )
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
            self._show_notice_dialog(
                "Could not open config folder",
                "The configuration directory exists, but the operating system refused to open it in the file manager.",
                tone="error",
                details=str(e),
            )

    def show_about_dialog(self):
        dialog = tk.Toplevel(self.root)
        self._configure_modal_window(
            dialog,
            title=f"About {APP_NAME}",
            size="620x470",
            min_size=(560, 420),
        )

        hero, _ = self._create_sidebar_card(
            dialog,
            f"{APP_NAME} {APP_VERSION}",
            "Windows-first hosts file editing with curated imports, previewed cleaning, safer save flows, and recovery tools.",
            accent=PALETTE["blue"],
        )
        ttk.Label(hero, text="Why people trust it", style="SectionTitle.TLabel").pack(anchor="w")
        for bullet in (
            "Save Cleaned previews normalization and whitelist filtering before write.",
            "Save Raw preserves the editor exactly as shown.",
            "Batch imports stay sequential so progress and failures are easier to trust.",
            "Dry-run mode lets you validate changes without touching disk.",
        ):
            ttk.Label(hero, text=f"- {bullet}", style="SectionBody.TLabel", wraplength=520, justify="left").pack(anchor="w", pady=(6, 0))

        shortcuts, _ = self._create_sidebar_card(
            dialog,
            "Keyboard shortcuts",
            "The fastest path through the workspace.",
            accent=PALETTE["green"],
        )
        for shortcut, label in (
            ("Ctrl+F", "Focus search"),
            ("Ctrl+S", "Save Cleaned"),
            ("Ctrl+Shift+S", "Save Raw"),
            ("F5", "Reload from disk"),
            ("Ctrl+P", "Goto Anything"),
        ):
            row = ttk.Frame(shortcuts, style="Section.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=shortcut, style="SectionTitle.TLabel").pack(side="left")
            ttk.Label(row, text=label, style="SectionBody.TLabel").pack(side="right")

        footer = ttk.Frame(dialog)
        footer.pack(fill="x", padx=20, pady=(0, 20))
        ttk.Button(
            footer,
            text="Project on GitHub",
            command=lambda: webbrowser.open("https://github.com/SysAdminDoc/HostsFileGet"),
            style="Secondary.TButton",
        ).pack(side="left")
        ttk.Button(footer, text="Close", command=dialog.destroy, style="Action.TButton").pack(side="right")
        dialog.grab_set()

    def _on_editor_scroll(self, scrollbar, first, last):
        """Keep the scrollbar and the line-number gutter in sync with the text.

        Tk `yscrollcommand` fires whenever the viewport moves, so we hook it
        to redraw line numbers lazily via ``after_idle`` - redrawing here
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
        confirm_dialog = getattr(self, "_confirm_dialog", None)

        def confirm_close(title, message, *, confirm_text, cancel_text):
            if callable(confirm_dialog):
                return confirm_dialog(
                    title,
                    message,
                    tone="warning",
                    confirm_text=confirm_text,
                    cancel_text=cancel_text,
                )
            return messagebox.askyesno(title, message)

        should_cancel_import = False
        if self.is_importing:
            if not confirm_close(
                "Close during import?",
                "A batch import is still running. Closing now will stop it after the current download step.",
                confirm_text="Close and stop import",
                cancel_text="Keep app open",
            ):
                return
            should_cancel_import = True

        if self._has_unsaved_changes():
            if not confirm_close(
                "Discard unsaved changes?",
                "You have unsaved editor changes. Closing now will discard them.",
                confirm_text="Discard and close",
                cancel_text="Keep editing",
            ):
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
            # Never block shutdown because of a config save failure - the
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
                    self._show_notice_dialog(
                        "Could not relaunch as administrator",
                        "The app could not restart itself with elevated rights, so saving the real hosts file will fail unless you relaunch it manually as Administrator.",
                        tone="error",
                        details=str(e),
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
        candidates = []
        # Legacy builds wrote config next to the script / executable. Avoid
        # probing the current working directory because shortcuts, schedulers,
        # and shells can set that arbitrarily, which risks adopting an
        # unrelated ``hosts_editor_config.json`` by accident.
        candidate = os.path.join(_EXE_DIR, self.CONFIG_FILENAME)
        if candidate != self.config_path:
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
            self.update_status("Config file is corrupt - using defaults.", is_error=True)
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
        self.pinned_domains = set(sanitized_config.get("pinned_domains", []))

        self.whitelist_text_area.delete('1.0', tk.END)
        self.whitelist_text_area.insert('1.0', sanitized_config["whitelist"])
        self.whitelist_text_area.edit_modified(False)

        self.update_status("Configuration loaded.")
        self._rebuild_custom_source_buttons()
        self._update_whitelist_summary()

        if config_source_path != self.config_path:
            self._write_config_payload(sanitized_config)
            # Clean up the legacy file so we don't keep re-reading it on
            # future launches. Failures here are non-fatal - the primary
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
            "pinned_domains": sorted(self.pinned_domains),
        }, self.last_open_dir)
        try:
            self._write_config_payload(config)
            self._last_saved_whitelist_text = config["whitelist"]
            self._source_metadata_dirty = False
            self._update_whitelist_summary()
            return True
        except OSError as e:
            self.update_status(f"Config save failed: {e}", is_error=True)
            return False
        except tk.TclError:
            # Widget torn down between payload write and summary refresh -
            # the config IS on disk, nothing else to do.
            return True

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
            text = "0 saved feeds."
        elif count == 1:
            text = "1 saved feed."
        else:
            text = f"{count} saved feeds."
        self.custom_sources_summary_label.config(text=text)

    def _update_manual_summary(self):
        if not hasattr(self, "manual_summary_label"):
            return

        count = count_nonempty_lines(self.manual_text_area.get('1.0', tk.END))
        mode = self.import_mode.get()
        if count == 0:
            text = "Nothing ready to append."
        elif count == 1:
            text = f"1 line ready to append in {mode} mode."
        else:
            text = f"{count:,} lines ready to append in {mode} mode."
        self.manual_summary_label.config(text=text)

    def _update_whitelist_summary(self):
        if not hasattr(self, "whitelist_summary_label"):
            return

        count = len(self._get_whitelist_set())
        dirty_suffix = " Unsaved edits." if self._has_unsaved_whitelist_changes() else " Saved."
        if count == 1:
            text = "1 allowlist entry." + dirty_suffix
        else:
            text = f"{count:,} allowlist entries." + dirty_suffix
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
            # Timestamped copy is a convenience layer - the rolling .bak
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

        # Exclude the rolling latest-copy from timestamped pruning - it
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
            self._show_notice_dialog(
                "Administrator privileges required",
                "Disabling or re-enabling the hosts file requires Administrator rights.",
                tone="error",
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
                enable_hosts_file_transactionally(self.HOSTS_FILE_PATH, disabled_path)
                self.update_status("Success: Hosts file re-enabled. Blocklists are active again.")
            else:
                if not self._confirm_dialog(
                    "Disable hosts file?",
                    "Disabling temporarily replaces the hosts file with the minimal Microsoft default so every blocklist is bypassed.",
                    tone="warning",
                    confirm_text="Disable hosts file",
                    cancel_text="Keep hosts active",
                    details=(
                        "Your current file is preserved alongside it and can be re-enabled later from the same menu.\n\n"
                        "Use this when you need a quick troubleshooting baseline without losing your current setup."
                    ),
                ):
                    return
                try:
                    self._rotate_backups()
                except OSError:
                    pass
                minimal = (
                    "# Copyright (c) 1993-2009 Microsoft Corp.\n"
                    "#\n"
                    "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n"
                    "127.0.0.1       localhost\n"
                    "::1             localhost\n"
                )
                disable_hosts_file_transactionally(self.HOSTS_FILE_PATH, disabled_path, minimal)
                self.update_status("Success: Hosts file disabled. Minimal Microsoft template is active.")
            self.flush_dns_silent()
            self.load_file(is_initial_load=False)
            self._refresh_mode_badges()
        except Exception as e:
            self.update_status(f"Disable/Enable error: {e}", is_error=True)
            self._show_notice_dialog(
                "Could not toggle the hosts file",
                "The enable or disable operation failed before the new state could be applied.",
                tone="error",
                details=str(e),
            )

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
        self._configure_modal_window(
            dialog,
            title="Hosts Health Scan",
            size="760x560",
            min_size=(680, 500),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            "Hosts health scan",
            "Check the live editor for suspicious redirects to non-loopback, non-private IP addresses.",
            accent=PALETTE["yellow"],
        )
        if not findings:
            ttk.Label(
                intro,
                text="No suspicious redirects detected. Every non-loopback mapping is on a private LAN range.",
                wraplength=660,
                justify="left",
                style="SectionBody.TLabel",
            ).pack(anchor='w')
        else:
            ttk.Label(
                intro,
                text=(
                    f"Found {len(findings)} entr{'y' if len(findings) == 1 else 'ies'} mapping domains to "
                    "non-loopback, non-LAN IPs. These are a classic malware or hijack signal, so verify each one before keeping it."
                ),
                wraplength=660,
                justify="left",
                foreground=PALETTE["yellow"],
            ).pack(anchor='w')

        body = scrolledtext.ScrolledText(dialog, wrap=tk.NONE)
        self._style_code_surface(body, font_spec=self.mono_small_font)
        body.pack(expand=True, fill='both', padx=20, pady=(0, 12))
        if findings:
            body.insert(tk.END, "Line    IP                  Domain\n")
            body.insert(tk.END, "-----   -----------------   -----------------------------\n")
            for line_idx, ip, domain in findings:
                body.insert(tk.END, f"{line_idx + 1:>5}   {ip:<17}   {domain}\n")
        else:
            body.insert(tk.END, "(clean)\n")
        body.configure(state="disabled")

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=20, pady=(0, 20))
        if findings:
            ttk.Button(
                btn_row,
                text="Jump to first finding",
                command=lambda line_no=findings[0][0] + 1: (
                    self.text_area.mark_set('insert', f"{line_no}.0"),
                    self.text_area.see(f"{line_no}.0"),
                    dialog.destroy(),
                ),
                style="TButton",
            ).pack(side="left")
        ttk.Button(btn_row, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        dialog.grab_set()

    # ----------------------------- Check Domain ------------------------------
    def show_check_domain(self, initial_domain: str | None = None):
        dialog = tk.Toplevel(self.root)
        self._configure_modal_window(
            dialog,
            title="Check Domain",
            size="780x620",
            min_size=(700, 540),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            "Check a domain",
            "See whether a domain is blocked by the current editor, covered by your whitelist, or present in sources already fetched this session.",
            accent=PALETTE["blue"],
        )
        ttk.Label(
            intro,
            text="Examples: `ads.example.com`, `telemetry.vendor.com`, `doubleclick.net`",
            style="SectionBody.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w")

        query_frame = ttk.Frame(dialog, padding=(20, 0, 20, 0))
        query_frame.pack(fill="x")
        query_var = tk.StringVar()
        entry = ttk.Entry(query_frame, textvariable=query_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.focus_set()
        ttk.Button(query_frame, text="Check", command=lambda: run_check(), style="Action.TButton").pack(side="left", padx=(8, 0))

        output = scrolledtext.ScrolledText(dialog, wrap=tk.WORD)
        self._style_code_surface(output, font_spec=self.mono_small_font)
        output.pack(expand=True, fill='both', padx=20, pady=12)
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
            cached_urls = {
                normalize_custom_source_url(entry.get("url", "")) or entry.get("url", "")
                for entry in self._source_corpus_cache.values()
            }
            not_yet_fetched = [
                source["name"]
                for source in self._iter_known_sources()
                if (normalize_custom_source_url(source["url"]) or source["url"]) not in cached_urls
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
                buf.append("Not present in any previously-fetched source.")
            if not_yet_fetched:
                buf.append("")
                buf.append(f"({len(not_yet_fetched)} source(s) not yet fetched this session - import them to include in this lookup.)")
            write_output('\n'.join(buf))

        entry.bind("<Return>", run_check)
        if initial_domain:
            query_var.set(initial_domain)
            self._safe_after(50, run_check)

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=20, pady=(0, 20))
        ttk.Button(btn_row, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        dialog.grab_set()

    # ----------------------------- Export ------------------------------------
    def show_export_dialog(self):
        original = self.get_lines()
        whitelist_set = self._get_whitelist_set()
        cleaned, stats = _get_canonical_cleaned_output_and_stats(original, whitelist_set, self.pinned_domains)

        dialog = tk.Toplevel(self.root)
        self._configure_modal_window(
            dialog,
            title="Export Cleaned Hosts",
            size="560x430",
            min_size=(520, 380),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            "Export cleaned output",
            "Choose a format to save the cleaned view under. Whitelist filtering and deduplication are applied first.",
            accent=PALETTE["green"],
        )
        ttk.Label(
            intro,
            text=(
                f"Preview summary: {stats['final_active']:,} active entr"
                f"{'y' if stats['final_active'] == 1 else 'ies'} ready for export after removing "
                f"{stats['total_discarded']:,} line(s)."
            ),
            style="SectionBody.TLabel",
            wraplength=480,
            justify="left",
        ).pack(anchor="w")

        format_var = tk.StringVar(value="hosts")
        formats = [
            ("hosts", "Hosts file (what Cleaned Save writes)"),
            ("domains", "Plain domains, one per line"),
            ("adblock", "Adblock / uBlock (||domain^)"),
            ("dnsmasq", "dnsmasq (address=/domain/0.0.0.0)"),
            ("pihole", "Pi-hole gravity (plain domains)"),
        ]
        options, _ = self._create_sidebar_card(
            dialog,
            "Export format",
            "Pick the shape best suited for the downstream tool you want to feed.",
            accent=PALETTE["blue"],
        )
        for value, label in formats:
            ttk.Radiobutton(options, text=label, variable=format_var, value=value).pack(anchor='w', pady=2)

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
                self._show_notice_dialog(
                    "Export failed",
                    "The cleaned output could not be written to the selected destination.",
                    tone="error",
                    details=str(e),
                )

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=20, pady=(6, 20))
        ttk.Button(btn_row, text="Export...", command=do_export, style="Action.TButton").pack(side="right")
        ttk.Button(btn_row, text="Cancel", command=dialog.destroy, style="Secondary.TButton").pack(side="right", padx=(0, 8))
        dialog.grab_set()

    # ----------------------------- Preferences -------------------------------
    def show_preferences(self):
        dialog = tk.Toplevel(self.root)
        self._configure_modal_window(
            dialog,
            title="Preferences",
            size="560x390",
            min_size=(520, 360),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            "Preferences",
            "Tune the default safety rails for backup retention and block-target rewriting. Settings roam with the persistent config file.",
            accent=PALETTE["blue"],
        )
        ttk.Label(intro, text="These defaults shape how future saves and conversion tools behave.", style="SectionBody.TLabel", wraplength=460, justify="left").pack(anchor="w")

        retention_card, _ = self._create_sidebar_card(
            dialog,
            "Backups",
            "Keep a rolling set of timestamped safety snapshots next to the live hosts file.",
            accent=PALETTE["green"],
        )
        row = ttk.Frame(retention_card, style="Section.TFrame")
        row.pack(fill='x', pady=(0, 6))
        ttk.Label(row, text="Timestamped backup retention", style="SectionTitle.TLabel").pack(side='left')
        retention_var = tk.IntVar(value=self._backup_retention)
        spin = tk.Spinbox(
            row, from_=0, to=50, textvariable=retention_var, width=6,
            bg=PALETTE["crust"], fg=PALETTE["text"], insertbackground=PALETTE["text"],
            buttonbackground=PALETTE["surface0"], highlightthickness=1, highlightbackground=PALETTE["border"], relief="flat",
        )
        spin.pack(side='right')
        ttk.Label(
            retention_card,
            text="Set this to 0 if you only want the rolling latest backup. Higher values preserve more history for rollback confidence.",
            style="SectionBody.TLabel",
            wraplength=460,
            justify="left",
        ).pack(anchor="w")

        sink_card, _ = self._create_sidebar_card(
            dialog,
            "Block target",
            "Choose the default sink used by the Convert Block IPs tool.",
            accent=PALETTE["yellow"],
        )
        row2 = ttk.Frame(sink_card, style="Section.TFrame")
        row2.pack(fill='x', pady=(0, 6))
        ttk.Label(row2, text="Default block-sink IP", style="SectionTitle.TLabel").pack(side='left')
        sink_var = tk.StringVar(value=self._preferred_block_sink)
        sink_menu = ttk.OptionMenu(row2, sink_var, self._preferred_block_sink, *sorted(BLOCK_SINK_IPS))
        sink_menu.pack(side='right')
        ttk.Label(
            sink_card,
            text="`0.0.0.0` is the fastest Windows-friendly default for most blocking workflows. Use another target only if you need a specific resolver behavior.",
            style="SectionBody.TLabel",
            wraplength=460,
            justify="left",
        ).pack(anchor="w")

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill='x', padx=20, pady=(6, 20))

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
        ttk.Button(btn_row, text="Save preferences", command=do_save, style="Action.TButton").pack(side="right")
        dialog.grab_set()

    # ----------------------------- Scheduled Auto-Update ---------------------
    def show_schedule_wizard(self):
        if os.name != 'nt':
            self._show_notice_dialog(
                "Not supported on this OS",
                "Scheduled auto-update currently depends on Windows Task Scheduler.",
                tone="info",
            )
            return

        dialog = tk.Toplevel(self.root)
        self._configure_modal_window(
            dialog,
            title="Schedule Auto-Update",
            size="620x430",
            min_size=(580, 390),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            "Schedule Auto-Update",
            (
                "Register a Windows Scheduled Task that runs "
                f"`{APP_SLUG} --update` at the interval you choose. "
                "The task runs with the highest privilege level so unattended updates can still write the hosts file."
            ),
            accent=PALETTE["blue"],
        )
        ttk.Label(
            intro,
            text="Use this when you want a trusted background refresh without opening the editor manually.",
            style="SectionBody.TLabel",
            wraplength=520,
            justify="left",
        ).pack(anchor="w")
        ttk.Label(
            intro,
            text="If the hosts file is temporarily disabled, scheduled updates now skip safely until you re-enable it.",
            style="SectionBody.TLabel",
            wraplength=520,
            justify="left",
        ).pack(anchor="w", pady=(8, 0))

        schedule_card, _ = self._create_sidebar_card(
            dialog,
            "Task cadence",
            "Pick how often Windows Task Scheduler should run the updater.",
            accent=PALETTE["green"],
        )
        weekday_default = SCHEDULE_WEEKDAYS[min(datetime.datetime.now().weekday(), len(SCHEDULE_WEEKDAYS) - 1)]
        freq_frame = ttk.Frame(schedule_card, style="Section.TFrame")
        freq_frame.pack(fill='x', pady=(0, 8))
        ttk.Label(freq_frame, text="Interval", style="SectionTitle.TLabel").pack(side='left')
        freq_var = tk.StringVar(value="DAILY")
        ttk.OptionMenu(freq_frame, freq_var, "DAILY", "DAILY", "WEEKLY", "ONLOGON").pack(side='left', padx=(8, 0))

        time_frame = ttk.Frame(schedule_card, style="Section.TFrame")
        time_frame.pack(fill='x', pady=(0, 6))
        ttk.Label(time_frame, text="Time (HH:MM, 24h)", style="SectionTitle.TLabel").pack(side='left')
        time_var = tk.StringVar(value="03:30")
        time_entry = ttk.Entry(time_frame, textvariable=time_var, width=8)
        time_entry.pack(side='left', padx=(8, 0))

        weekday_frame = ttk.Frame(schedule_card, style="Section.TFrame")
        weekday_frame.pack(fill='x', pady=(0, 8))
        ttk.Label(weekday_frame, text="Weekday", style="SectionTitle.TLabel").pack(side='left')
        weekday_var = tk.StringVar(value=weekday_default)
        weekday_menu = ttk.OptionMenu(weekday_frame, weekday_var, weekday_default, *SCHEDULE_WEEKDAYS)
        weekday_menu.pack(side='left', padx=(8, 0))

        ttk.Label(
            schedule_card,
            text="Daily and weekly tasks use the selected time. On-logon tasks run as soon as you sign in, so the time value is ignored.",
            style="SectionBody.TLabel",
            wraplength=520,
            justify="left",
        ).pack(anchor="w")
        cadence_summary_var = tk.StringVar(value="Runs daily at 03:30.")
        ttk.Label(
            schedule_card,
            textvariable=cadence_summary_var,
            style="StatusMeta.TLabel",
            wraplength=520,
            justify="left",
        ).pack(anchor="w", pady=(10, 0))

        status_card, _ = self._create_sidebar_card(
            dialog,
            "Status",
            "Registration results appear here so you get immediate confirmation or actionable errors.",
            accent=PALETTE["yellow"],
        )
        status = ttk.Label(status_card, text="No task changes yet.", style="SectionBody.TLabel", wraplength=520, justify="left")
        status.pack(anchor='w')

        def set_status_message(message: str, *, tone: str = "info"):
            color = {
                "info": PALETTE["subtext"],
                "success": PALETTE["green"],
                "warning": PALETTE["yellow"],
                "error": PALETTE["red"],
            }.get(tone, PALETTE["subtext"])
            status.config(text=message, foreground=color)

        def refresh_schedule_controls(*_args):
            freq = freq_var.get().strip().upper()
            uses_time = freq in {"DAILY", "WEEKLY"}
            uses_weekday = freq == "WEEKLY"

            time_entry.configure(state="normal" if uses_time else "disabled")
            weekday_menu.configure(state="normal" if uses_weekday else "disabled")

            try:
                _, summary = build_schtasks_create_command(
                    "Preview",
                    "python.exe hosts_editor.py --update",
                    freq,
                    start_time=time_var.get(),
                    weekday=weekday_var.get(),
                )
                cadence_summary_var.set(summary)
            except ValueError as exc:
                cadence_summary_var.set(str(exc))

        freq_var.trace_add("write", refresh_schedule_controls)
        time_var.trace_add("write", refresh_schedule_controls)
        weekday_var.trace_add("write", refresh_schedule_controls)
        refresh_schedule_controls()

        def do_register():
            task_name = "HostsFileGet Auto-Update"
            interpreter = sys.executable
            script = os.path.abspath(sys.argv[0] if not getattr(sys, 'frozen', False) else sys.executable)
            command = f'"{interpreter}" "{script}" --update' if not getattr(sys, 'frozen', False) else f'"{script}" --update'
            freq = freq_var.get()
            try:
                args, cadence_summary = build_schtasks_create_command(
                    task_name,
                    command,
                    freq,
                    start_time=time_var.get(),
                    weekday=weekday_var.get(),
                )
            except ValueError as exc:
                set_status_message(str(exc), tone="error")
                self.update_status(f"Scheduled auto-update not registered: {exc}", is_error=True)
                if "weekday" in str(exc).lower():
                    weekday_menu.focus_set()
                else:
                    time_entry.focus_set()
                    time_entry.selection_range(0, tk.END)
                return
            try:
                proc = subprocess.run(args, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if proc.returncode == 0:
                    set_status_message(f"Task '{task_name}' registered successfully. {cadence_summary}", tone="success")
                    self.update_status(f"Scheduled auto-update registered. {cadence_summary}")
                else:
                    err = (proc.stderr or proc.stdout or "").strip() or f"schtasks exit {proc.returncode}"
                    set_status_message(err, tone="error")
                    self.update_status(f"Scheduled auto-update failed: {err}", is_error=True)
            except Exception as e:
                set_status_message(f"Failed to register task: {e}", tone="error")
                self.update_status(f"Scheduled auto-update failed: {e}", is_error=True)

        def do_unregister():
            task_name = "HostsFileGet Auto-Update"
            try:
                proc = subprocess.run(
                    ['schtasks', '/Delete', '/TN', task_name, '/F'],
                    capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if proc.returncode == 0:
                    set_status_message("Task removed.", tone="warning")
                    self.update_status("Scheduled auto-update removed.")
                else:
                    err = (proc.stderr or proc.stdout or "").strip()
                    if "cannot find the file specified" in err.lower():
                        err = "No scheduled auto-update task was registered."
                        set_status_message(err, tone="warning")
                        self.update_status(err)
                    else:
                        set_status_message(err or "Could not remove the scheduled task.", tone="error")
                        self.update_status(f"Scheduled auto-update removal failed: {err or 'unknown error'}", is_error=True)
            except Exception as e:
                set_status_message(f"Failed to remove task: {e}", tone="error")
                self.update_status(f"Scheduled auto-update removal failed: {e}", is_error=True)

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill='x', padx=20, pady=(6, 20))
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
                unique_candidates.append((f"{name} - {category}", "curated source", None))
        for entry in self.custom_sources:
            unique_candidates.append((entry["name"], "custom source", None))

        dialog = tk.Toplevel(self.root)
        self._configure_modal_window(
            dialog,
            title="Goto Anything",
            size="700x520",
            min_size=(620, 420),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            "Goto Anything",
            "Jump to a domain in the editor or narrow the source catalog from one fast command palette.",
            accent=PALETTE["accent"],
        )
        ttk.Label(
            intro,
            text="Type a few characters to search domains, curated sources, or saved custom sources.",
            style="SectionBody.TLabel",
            wraplength=620,
            justify="left",
        ).pack(anchor="w")

        query_var = tk.StringVar()
        query_row = ttk.Frame(dialog, padding=(20, 0, 20, 0))
        query_row.pack(fill="x")
        entry = ttk.Entry(query_row, textvariable=query_var, font=("Segoe UI", 11))
        entry.pack(fill='x', expand=True, side="left")
        entry.focus_set()
        summary_label = ttk.Label(dialog, text="", style="StatusMeta.TLabel")
        summary_label.pack(anchor="w", padx=20, pady=(8, 0))

        listbox = tk.Listbox(
            dialog,
        )
        self._style_listbox_surface(listbox, font_spec=self.mono_small_font)
        listbox.pack(expand=True, fill='both', padx=20, pady=(12, 12))

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
            summary_label.config(text=f"{len(current_results)} result(s) shown.")

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
                    self.source_filter_var.set(label.split(" - ")[0])
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
        self._configure_modal_window(
            dialog,
            title="Sources Report",
            size="760x580",
            min_size=(680, 520),
        )

        total_blocks = sum(b["blocking_entries"] for b in buckets)
        intro, _ = self._create_sidebar_card(
            dialog,
            "Sources report",
            "Ranked by blocking-entry contribution so you can spot bloated, redundant, or low-value imports faster.",
            accent=PALETTE["accent"],
        )
        ttk.Label(
            intro,
            text=(
                f"{len(buckets):,} source bucket{'s' if len(buckets) != 1 else ''} detected. "
                f"{total_blocks:,} blocking entr{'y' if total_blocks == 1 else 'ies'} accounted for in the current editor."
            ),
            style="SectionBody.TLabel",
            wraplength=680,
            justify="left",
        ).pack(anchor="w")

        body = scrolledtext.ScrolledText(dialog, wrap=tk.NONE)
        self._style_code_surface(body, font_spec=self.mono_small_font)
        body.pack(expand=True, fill='both', padx=20, pady=(0, 12))

        if not buckets:
            body.insert(tk.END, "(editor is empty)\n")
        else:
            total_blocks = total_blocks or 1
            body.insert(tk.END, f"{'Source':<50} {'Blocks':>10} {'Lines':>10} {'Share':>8}\n")
            body.insert(tk.END, "-" * 80 + "\n")
            for b in buckets:
                share = 100.0 * b["blocking_entries"] / total_blocks
                name = b["name"][:49]
                body.insert(tk.END, f"{name:<50} {b['blocking_entries']:>10,} {b['total_lines']:>10,} {share:>7.1f}%\n")
        body.configure(state="disabled")

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=20, pady=(0, 20))
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
        # sources - those signal returning users whose config predated
        # v2.14 where this flag was introduced.
        if self.custom_sources or self._last_saved_whitelist_text.strip():
            self._has_completed_first_run = True
            self.save_config()
            return
        self._safe_after(400, self.show_first_run_wizard)

    def show_first_run_wizard(self):
        dialog = tk.Toplevel(self.root)
        self._configure_modal_window(
            dialog,
            title=f"Welcome to {APP_NAME}",
            size="700x620",
            min_size=(660, 560),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            f"Welcome to {APP_NAME}",
            "Pick the categories you want blocked and the app will import a small, curated starter set for each one.",
            accent=PALETTE["blue"],
        )
        ttk.Label(
            intro,
            text="You can keep the safe defaults, skip for now, or fine-tune sources later from the sidebar. Nothing is written to disk until you save.",
            style="SectionBody.TLabel",
            wraplength=560,
            justify="left",
        ).pack(anchor="w")

        body = ttk.Frame(dialog)
        body.pack(expand=True, fill='both', padx=20)

        vars_by_category: dict[str, tk.BooleanVar] = {}
        selected_summary = ttk.Label(dialog, text="", style="StatusMeta.TLabel")
        selected_summary.pack(anchor="w", padx=20, pady=(8, 0))

        def update_summary():
            selected_categories = [
                label for label, var in vars_by_category.items()
                if var.get()
            ]
            source_count = sum(
                len(sources)
                for label, _, sources in self.FIRST_RUN_BUNDLES
                if vars_by_category[label].get()
            )
            if not selected_categories:
                selected_summary.config(text="No starter bundles selected yet.")
            else:
                selected_summary.config(
                    text=(
                        f"{len(selected_categories)} categor"
                        f"{'y' if len(selected_categories) == 1 else 'ies'} selected, "
                        f"{source_count} curated source{'s' if source_count != 1 else ''} ready to import."
                    )
                )

        for label, default_on, sources in self.FIRST_RUN_BUNDLES:
            var = tk.BooleanVar(value=default_on)
            vars_by_category[label] = var
            bundle_card = tk.Frame(
                body,
                bg=PALETTE["panel"],
                highlightthickness=1,
                highlightbackground=PALETTE["border"],
                highlightcolor=PALETTE["focus"],
                bd=0,
            )
            bundle_card.pack(fill="x", pady=(0, 8))
            inner = ttk.Frame(bundle_card, style="Section.TFrame", padding=(16, 12, 16, 12))
            inner.pack(fill="both", expand=True)

            top = ttk.Frame(inner, style="Section.TFrame")
            top.pack(fill="x")
            cb = ttk.Checkbutton(top, text=label, variable=var, command=update_summary)
            cb.pack(side="left")
            default_text = "Recommended" if default_on else "Optional"
            tk.Label(
                top,
                text=default_text,
                bg=PALETTE["green"] if default_on else PALETTE["surface1"],
                fg="#0b1020" if default_on else PALETTE["text"],
                padx=8,
                pady=3,
                font=("Segoe UI Semibold", 8),
                bd=0,
            ).pack(side="right")

            preview_names = ", ".join(name for name, _url in sources[:2])
            if len(sources) > 2:
                preview_names += f", +{len(sources) - 2} more"
            ttk.Label(
                inner,
                text=f"{len(sources)} starter source{'s' if len(sources) != 1 else ''}: {preview_names}",
                style="SectionBody.TLabel",
                wraplength=580,
                justify="left",
            ).pack(anchor="w", pady=(6, 0))

        update_summary()

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
        ttk.Button(btn_row, text="Import selected bundles", command=do_apply, style="Action.TButton").pack(side="right")
        dialog.grab_set()

    # ----------------------------- Panic Restore -----------------------------
    def panic_restore_stock(self):
        """Replace the editor with the stock Microsoft default hosts.

        Unlike ``revert_to_backup`` this does not depend on any user-created
        snapshot - handy when every backup is also broken or when the user
        just wants the original Windows baseline back.
        """
        if self._block_during_import("Panic Restore"):
            return
        if not self._confirm_dialog(
            "Load Microsoft default hosts?",
            "This replaces the current editor contents with the stock Microsoft template.",
            tone="warning",
            confirm_text="Load default template",
            cancel_text="Keep current editor",
            details="Nothing is written to disk yet. Use File > Save Raw afterward if you want to commit the template to the real hosts file.",
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
            self.update_status(f"{label}: nothing to remove - editor is already clean.")
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
        self._configure_modal_window(
            dialog,
            title="Remove Import Section",
            size="760x620",
            min_size=(680, 520),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            "Remove imported sections",
            "Each row is an imported source block detected in the editor. Removing a section deletes every line between its Start and End markers, including the markers themselves.",
            accent=PALETTE["red"],
        )
        ttk.Label(
            intro,
            text=f"{len(sections):,} import section{'s' if len(sections) != 1 else ''} found in the current editor.",
            style="SectionBody.TLabel",
            wraplength=680,
            justify="left",
        ).pack(anchor="w")

        list_frame = ttk.Frame(dialog, padding=(20, 0, 20, 0))
        list_frame.pack(expand=True, fill='both')

        canvas = tk.Canvas(list_frame, bg=PALETTE["base"], highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        content = ttk.Frame(canvas)
        content.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure("section-frame", width=e.width))
        canvas.create_window((0, 0), window=content, anchor="nw", tags=("section-frame",))
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        selected = {idx: tk.BooleanVar(value=False) for idx, _ in enumerate(sections)}
        for idx, section in enumerate(sections):
            shell = tk.Frame(
                content,
                bg=PALETTE["panel_alt"],
                highlightthickness=1,
                highlightbackground=PALETTE["border"],
                highlightcolor=PALETTE["focus"],
                bd=0,
            )
            shell.pack(fill="x", pady=(0, 6))
            inner = ttk.Frame(shell, style="Inset.TFrame", padding=(12, 10, 12, 10))
            inner.pack(fill="both", expand=True)

            top = ttk.Frame(inner, style="Inset.TFrame")
            top.pack(fill="x")
            ttk.Checkbutton(
                top,
                text=f"{section['name']} [{section['mode']}]",
                variable=selected[idx],
            ).pack(side="left")
            ttk.Label(
                top,
                text=f"{section['end'] - section['start'] + 1:,} lines",
                style="SectionBody.TLabel",
            ).pack(side="right")
            ttk.Label(
                inner,
                text=f"Lines {section['start'] + 1:,} to {section['end'] + 1:,}",
                style="SectionBody.TLabel",
            ).pack(anchor="w", pady=(6, 0))

        def do_remove():
            targets = [sections[i] for i, var in selected.items() if var.get()]
            if not targets:
                self.update_status("No import sections selected.", is_error=True)
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
        btn_row.pack(fill="x", padx=20, pady=(12, 20))
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

        self.update_status(f"Resolving {domain}...")

        def worker():
            try:
                infos = socket.getaddrinfo(domain, None)
                addrs = sorted({info[4][0] for info in infos})
                error: Exception | None = None
            except socket.gaierror as e:
                addrs = []
                error = e
            except OSError as e:
                addrs = []
                error = e

            def show_result():
                self.update_status(f"Resolved {domain}." if addrs else f"Resolve failed for {domain}.",
                                   is_error=bool(error))
                if error is not None:
                    self._show_notice_dialog(
                        f"Resolve domain: {domain}",
                        "DNS resolution failed for this domain.",
                        tone="warning",
                        details=str(error),
                    )
                    return
                self._show_text_report_dialog(
                    f"Resolve domain: {domain}",
                    "Live DNS resolution from the current machine (bypasses the hosts file).",
                    "\n".join(addrs) if addrs else "(no addresses)",
                    tone="info",
                )

            self._safe_after(0, show_result)

        threading.Thread(target=worker, daemon=True).start()

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
            self._safe_after(
                0,
                lambda o=output: self._show_text_report_dialog(
                    f"Ping {domain}",
                    "Live network reachability output from the current machine.",
                    o,
                    tone="info",
                    height=520,
                ),
            )

        threading.Thread(target=worker, daemon=True).start()
        self.update_status(f"Pinging {domain}...")

    # ----------------------------- Editor Context Menu -----------------------
    def _build_editor_context_menu(self):
        menu = tk.Menu(
            self.text_area, tearoff=0,
            bg=PALETTE["mantle"], fg=PALETTE["text"],
            activebackground=PALETTE["blue"], activeforeground="#0b1020",
        )
        menu.add_command(label="Pin this domain (star)", command=self._ctx_pin_domain)
        menu.add_command(label="Unpin this domain", command=self._ctx_unpin_domain)
        menu.add_command(label="Whitelist this domain", command=self._ctx_whitelist_domain)
        menu.add_command(label="Copy domain", command=self._ctx_copy_domain)
        menu.add_separator()
        menu.add_command(label="Toggle comment on selection", command=self.toggle_selection_comment)
        menu.add_command(label="Remove this line", command=self._ctx_remove_line)
        menu.add_separator()
        menu.add_command(label="Resolve domain (real DNS)", command=self._ctx_resolve_domain)
        menu.add_command(label="Ping domain", command=self._ctx_ping_domain)
        menu.add_separator()
        menu.add_command(label="Check this domain...", command=self._ctx_check_domain)
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

    def _ctx_pin_domain(self):
        _, _, domain = self._ctx_line_info()
        if not domain:
            self.update_status("No domain detected at cursor.", is_error=True)
            return
        bare = domain.lstrip('.')
        if bare in self.pinned_domains:
            self.update_status(f"'{bare}' is already pinned.")
            return
        self.pinned_domains.add(bare)
        self.save_config()
        self._trigger_ui_update()
        self.update_status(
            f"Pinned '{bare}' — it will be preserved across Cleaned Save and whitelist filters."
        )

    def _ctx_unpin_domain(self):
        _, _, domain = self._ctx_line_info()
        if not domain:
            self.update_status("No domain detected at cursor.", is_error=True)
            return
        bare = domain.lstrip('.')
        if bare not in self.pinned_domains:
            self.update_status(f"'{bare}' is not pinned.")
            return
        self.pinned_domains.discard(bare)
        self.save_config()
        self._trigger_ui_update()
        self.update_status(f"Unpinned '{bare}'.")

    def show_pinned_domains(self):
        """Modal showing every pinned domain with an Unpin action per row."""
        dialog = tk.Toplevel(self.root)
        self._configure_modal_window(
            dialog,
            title="Pinned domains",
            size="520x480",
            min_size=(460, 360),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            "Pinned domains",
            "Pinned domains are preserved across Cleaned Save even when they are covered by your whitelist. "
            "Right-click an entry in the editor to pin or unpin it.",
            accent=PALETTE["yellow"],
        )
        ttk.Label(
            intro,
            text=f"{len(self.pinned_domains):,} domain(s) currently pinned.",
            style="SectionBody.TLabel",
        ).pack(anchor="w")

        list_container = ttk.Frame(dialog, padding=(20, 0, 20, 10))
        list_container.pack(expand=True, fill="both")

        listbox = tk.Listbox(list_container, selectmode=tk.EXTENDED)
        self._style_listbox_surface(listbox, font_spec=self.mono_small_font)
        scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)
        listbox.pack(side="left", expand=True, fill="both")
        scrollbar.pack(side="right", fill="y")

        def refresh_listbox():
            listbox.delete(0, tk.END)
            for pinned in sorted(self.pinned_domains):
                listbox.insert(tk.END, pinned)

        refresh_listbox()

        def do_unpin_selected():
            indices = listbox.curselection()
            if not indices:
                self.update_status("Select one or more domains to unpin.", is_error=True)
                return
            targets = {listbox.get(i) for i in indices}
            if not targets:
                return
            self.pinned_domains.difference_update(targets)
            self.save_config()
            self._trigger_ui_update()
            refresh_listbox()
            self.update_status(f"Unpinned {len(targets)} domain(s).")

        def do_clear_all():
            if not self.pinned_domains:
                return
            if not self._confirm_dialog(
                "Unpin every domain?",
                f"This will remove all {len(self.pinned_domains):,} pinned domains. Cleaned Save "
                "will no longer preserve them against whitelist matches.",
                tone="warning",
                confirm_text="Unpin all",
                cancel_text="Keep pinned",
            ):
                return
            count = len(self.pinned_domains)
            self.pinned_domains.clear()
            self.save_config()
            self._trigger_ui_update()
            refresh_listbox()
            self.update_status(f"Unpinned all {count} domain(s).")

        btn_row = ttk.Frame(dialog, padding=(20, 0, 20, 20))
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        ttk.Button(btn_row, text="Unpin Selected", command=do_unpin_selected, style="Danger.TButton").pack(
            side="right", padx=(0, 8)
        )
        ttk.Button(btn_row, text="Unpin All", command=do_clear_all, style="Danger.TButton").pack(
            side="right", padx=(0, 8)
        )
        dialog.grab_set()

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
        self.show_check_domain(initial_domain=domain)

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
        self._configure_modal_window(
            dialog,
            title=f"Preview Source: {name}",
            size="820x620",
            min_size=(720, 540),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            f"Preview source: {name}",
            "Fetch a small snippet so you can inspect the feed before importing it into the editor.",
            accent=PALETTE["blue"],
        )
        ttk.Label(
            intro,
            text=f"{url}\nShowing the first ~{SOURCE_PREVIEW_MAX_LINES} lines only. This preview never edits the editor on its own.",
            wraplength=720,
            justify="left",
            style="SectionBody.TLabel",
        ).pack(anchor='w')

        status_label = ttk.Label(dialog, text="Fetching preview...", style="StatusMeta.TLabel")
        status_label.pack(anchor="w", padx=20, pady=(8, 0))

        body = scrolledtext.ScrolledText(dialog, wrap=tk.NONE)
        self._style_code_surface(body, font_spec=self.mono_small_font)
        body.pack(expand=True, fill='both', padx=20, pady=(12, 12))
        body.insert(tk.END, "Fetching...\n")
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
                        "This URL returned HTML rather than a hosts list - the feed may be behind a captive page or has moved."
                    ))
                    self._safe_after(0, lambda: status_label.config(text="Preview failed: received HTML instead of a hosts list.", foreground=PALETTE["red"]))
                    return
                snippet = '\n'.join(lines[:SOURCE_PREVIEW_MAX_LINES])
                truncated = len(lines) > SOURCE_PREVIEW_MAX_LINES
                if truncated:
                    snippet += f"\n\n... ({len(lines) - SOURCE_PREVIEW_MAX_LINES} more lines not shown)"
                self._safe_after(0, lambda: write_body(snippet or "(empty)"))
                self._safe_after(0, lambda: status_label.config(text="Preview fetched successfully.", foreground=PALETTE["green"]))
            except Exception as e:
                self._safe_after(0, lambda err=e: write_body(f"Could not fetch preview:\n{err}"))
                self._safe_after(0, lambda err=e: status_label.config(text=f"Preview failed: {type(err).__name__}", foreground=PALETTE["red"]))

        threading.Thread(target=worker, daemon=True).start()

        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=20, pady=(0, 20))
        ttk.Button(btn_row, text="Import This Source", command=lambda: (dialog.destroy(), self.start_single_import(name, url)), style="Action.TButton").pack(side="right")
        ttk.Button(btn_row, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right", padx=(0, 8))

    def load_file(self, is_initial_load=False):
        if not is_initial_load and self._block_during_import("Refresh"):
            return
        try:
            if os.path.exists(self.HOSTS_FILE_PATH):
                if not is_initial_load and self._has_unsaved_changes():
                    if not self._confirm_dialog(
                        "Reload from disk?",
                        "Reloading from disk will discard the current unsaved editor changes.",
                        tone="warning",
                        confirm_text="Reload from disk",
                        cancel_text="Keep current editor",
                    ):
                        return

                lines = read_text_file_lines(self.HOSTS_FILE_PATH)

                file_hash = self._hash_lines(lines)
                self._last_applied_raw_hash, self._last_applied_cleaned_hash = resolve_saved_state_hashes(
                    file_hash,
                    self._last_applied_raw_hash,
                    self._last_applied_cleaned_hash,
                )
                self.set_text(lines)

                if self.is_hosts_disabled():
                    self.update_status(
                        "Warning: Hosts are currently disabled. The active file is the temporary minimal template; re-enable before saving editor changes.",
                        is_error=False,
                    )
                else:
                    self.update_status(f"Loaded hosts file: '{self.HOSTS_FILE_PATH}'")
            else:
                if is_initial_load:
                    self._last_applied_raw_hash = None
                    self._last_applied_cleaned_hash = None
                    self._update_save_button_state()
                self.update_status("Hosts file not found.", is_error=True)
        except Exception as e:
            self.update_status(f"Error loading file: {e}", is_error=True)
            self._show_notice_dialog(
                "Could not load the hosts file",
                "The app could not read the current hosts file from disk.",
                tone="error",
                details=str(e),
            )

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

        final_lines, stats = _get_canonical_cleaned_output_and_stats(original_lines, whitelist_set, self.pinned_domains)
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
            self._show_notice_dialog(
                "Administrator privileges required",
                f"{source_description} cannot write the real hosts file without Administrator rights.",
                tone="error",
                details="Relaunch the app as Administrator, or enable Dry-run mode if you only want to preview the result.",
            )
            self.update_status(f"{source_description} failed: Permission denied.", is_error=True)
            return False

        if self.is_hosts_disabled():
            self._show_notice_dialog(
                "Hosts file is currently disabled",
                f"{source_description} is blocked while the hosts file is in disabled mode.",
                tone="warning",
                details=(
                    "The active hosts file is only the temporary minimal Microsoft template right now.\n\n"
                    "Saving into that temporary file would be overwritten the next time you re-enable your preserved hosts configuration. "
                    "Re-enable the hosts file first, then save your editor changes."
                ),
                height=420,
            )
            self.update_status(
                f"{source_description} blocked: re-enable the hosts file before saving changes.",
                is_error=True,
            )
            return False

        if not content_to_save.strip():
            if not self._confirm_dialog(
                "Save an empty hosts file?",
                "The editor is empty. Saving now will replace the current hosts file with an empty file.",
                tone="warning",
                confirm_text="Save empty file",
                cancel_text="Keep current file",
            ):
                return False

        try:
            self._rotate_backups()
        except Exception as e:
            if not self._confirm_dialog(
                "Backup could not be created",
                "A safety backup could not be created before saving.",
                tone="warning",
                confirm_text="Save anyway",
                cancel_text="Cancel save",
                details=str(e),
            ):
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
            self._show_notice_dialog(
                "Permission denied while saving",
                f"{source_description} could not write the hosts file.",
                tone="error",
                details=f"{e}{hint}",
                height=420,
            )
            return False
        except Exception as e:
            self.update_status(f"{source_description} error: {e}", is_error=True)
            self._show_notice_dialog(
                f"{source_description} failed",
                "The save operation ended with an unexpected error.",
                tone="error",
                details=str(e),
            )
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
            self._show_notice_dialog(
                "Could not read the current hosts file",
                "The restore preview could not load the active hosts file.",
                tone="error",
                details=str(e),
            )
            return

        try:
            backup_lines = read_text_file_lines(backup_path)
        except Exception as e:
            self.update_status(f"Error reading backup: {e}", is_error=True)
            self._show_notice_dialog(
                "Could not read the backup file",
                "The restore preview could not load the backup copy.",
                tone="error",
                details=str(e),
            )
            return

        def do_restore(approved_lines):
            try:
                if self._has_unsaved_changes():
                    if not self._confirm_dialog(
                        "Replace unsaved editor content?",
                        "Restoring from backup will replace your current unsaved editor content.",
                        tone="warning",
                        confirm_text="Restore from backup",
                        cancel_text="Keep current editor",
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
                self._show_notice_dialog(
                    "Restore from backup failed",
                    "The backup preview was approved, but the restore operation did not complete.",
                    tone="error",
                    details=str(e),
                )

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
        dialog = BulkSelectionDialog(self, self.BLOCKLIST_SOURCES, self.custom_sources)
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

        while True:
            try:
                self.import_queue.get_nowait()
            except queue.Empty:
                break
             
        self.is_importing = True
        self.stop_import_flag.clear()
        self._set_import_controls_enabled(False)
        self.stop_btn.configure(state="normal")
        self._set_status_hint("Batch imports run sequentially. Stop waits for the current download step.")
        
        # UI Prep
        self.progress_status_label.config(text=f"0 / {len(sources)} queued")
        self.progress_status_label.pack(side=tk.RIGHT, padx=(0, 8))
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
        self.progress_status_label.pack_forget()
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
        self.progress_status_label.config(text="Stopping after current step")
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
                    self.progress_status_label.config(text=f"{i + 1} / {total}  {name}")
                    self.update_status(f"Importing source {i+1} of {total}: {name}...")

                elif msg_type == "source_fetched":
                    name, url, raw_lines = msg[1], msg[2], msg[3]
                    self._cache_source_corpus(name, url, raw_lines)
                    self.source_last_fetched[url] = datetime.datetime.now().isoformat(timespec='seconds')
                    self._source_metadata_dirty = True

                elif msg_type == "log":
                    text, is_err = msg[1], msg[2]
                    # Only show log if it's an error, otherwise it flickers too fast
                    if is_err: self.update_status(text, is_error=True)
                
                elif msg_type == "cancelled":
                    self._finish_import_ui()
                    self._persist_source_metadata_if_needed()
                    self.update_status("Warning: Batch import cancelled.")
                    return # Stop checking
                 
                elif msg_type == "done":
                    new_lines, total, success_count, failure_messages = msg[1], msg[2], msg[3], msg[4]
                    self._finish_import_ui()
                    self._persist_source_metadata_if_needed()
                     
                    if not new_lines:
                        if failure_messages:
                            self.update_status(f"Import finished with {len(failure_messages)} failed source(s) and no usable entries.", is_error=True)
                            self._show_notice_dialog(
                                "Import failed",
                                "No usable entries were imported from the selected sources.",
                                tone="error",
                                details=self._summarize_failure_messages(failure_messages),
                                height=460,
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
                            self._show_notice_dialog(
                                "Import completed with warnings",
                                "Some selected sources could not be imported, but usable entries were still added to the editor.",
                                tone="warning",
                                details=self._summarize_failure_messages(failure_messages),
                                height=460,
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
            self._show_notice_dialog(
                "Could not import pfSense log",
                "An unexpected error occurred while processing the selected pfSense DNSBL log file.",
                tone="error",
                details=str(e),
            )
            
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
            self._show_notice_dialog(
                "Could not import NextDNS log",
                "An unexpected error occurred while processing the selected NextDNS query log file.",
                tone="error",
                details=str(e),
            )
            
    def import_pihole_ftl(self):
        filepath = self._choose_file(
            title="Select pihole-FTL.db",
            filetypes=(("SQLite DB", "*.db"), ("All files", "*.*")),
        )
        if not filepath:
            return

        filename = os.path.basename(filepath)
        self.update_status(f"Reading {filename}...")

        def worker():
            try:
                domains = parse_pihole_ftl_blocked_domains(filepath)
                error: Exception | None = None
            except (OSError, RuntimeError, ValueError) as e:
                domains = []
                error = e

            def apply_result():
                if error is not None:
                    self.update_status(f"Pi-hole FTL import failed: {error}", is_error=True)
                    self._show_notice_dialog(
                        "Could not import Pi-hole FTL DB",
                        "The selected file could not be read as a Pi-hole FTL database.",
                        tone="error",
                        details=str(error),
                    )
                    return
                if not domains:
                    self.update_status(f"No blocked domains found in '{filename}'.", is_error=True)
                    return
                self.fetch_and_append_hosts(f"Pi-hole FTL: {filename}", lines_to_add=domains)

            self._safe_after(0, apply_result)

        threading.Thread(target=worker, daemon=True).start()

    def import_adguard_home_querylog(self):
        filepath = self._choose_file(
            title="Select AdGuard Home querylog",
            filetypes=(("JSON / NDJSON", "*.json"), ("Log files", "*.log"), ("All files", "*.*")),
        )
        if not filepath:
            return

        filename = os.path.basename(filepath)
        try:
            text = read_text_file_content(filepath)
        except OSError as e:
            self.update_status(f"AGH import read error: {e}", is_error=True)
            self._show_notice_dialog(
                "Could not read AdGuard Home log",
                "The selected file could not be read.",
                tone="error",
                details=str(e),
            )
            return

        try:
            domains = parse_adguard_home_querylog(text)
        except Exception as e:
            self.update_status(f"AGH import parse error: {e}", is_error=True)
            self._show_notice_dialog(
                "Could not parse AdGuard Home log",
                "The selected file did not contain valid AdGuard Home log entries.",
                tone="error",
                details=str(e),
            )
            return

        if not domains:
            self.update_status(f"No blocked domains found in '{filename}'.", is_error=True)
            return
        self.fetch_and_append_hosts(f"AdGuard Home: {filename}", lines_to_add=domains)

    def show_find_replace_dialog(self, _event=None):
        if self._block_during_import("Find / Replace"):
            return
        dialog = tk.Toplevel(self.root)
        self._configure_modal_window(
            dialog,
            title="Find and Replace",
            size="560x340",
            min_size=(500, 300),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            "Batch find and replace",
            "Applies across every line in the editor. The result is previewed before it's committed.",
            accent=PALETTE["blue"],
        )
        ttk.Label(
            intro,
            text="Regex mode uses Python syntax — use `\\1`, `\\g<name>` for backreferences (not `$1`).",
            style="SectionBody.TLabel",
            wraplength=500,
            justify="left",
        ).pack(anchor="w")

        form = ttk.Frame(dialog, padding=(20, 0, 20, 10))
        form.pack(fill="x")

        ttk.Label(form, text="Find:").grid(row=0, column=0, sticky="w", pady=4)
        find_var = tk.StringVar()
        ttk.Entry(form, textvariable=find_var).grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=4)

        ttk.Label(form, text="Replace with:").grid(row=1, column=0, sticky="w", pady=4)
        replace_var = tk.StringVar()
        ttk.Entry(form, textvariable=replace_var).grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=4)
        form.grid_columnconfigure(1, weight=1)

        use_regex_var = tk.BooleanVar(value=False)
        case_var = tk.BooleanVar(value=False)
        opts = ttk.Frame(form)
        opts.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Checkbutton(opts, text="Use regex", variable=use_regex_var).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(opts, text="Case sensitive", variable=case_var).pack(side="left")

        btn_row = ttk.Frame(dialog, padding=(20, 0, 20, 20))
        btn_row.pack(fill="x", side="bottom")

        def do_preview():
            pattern = find_var.get()
            if not pattern:
                self.update_status("Enter a find pattern.", is_error=True)
                return
            original = self.get_lines()
            try:
                new_lines, count = apply_find_replace(
                    original,
                    pattern,
                    replace_var.get(),
                    use_regex=use_regex_var.get(),
                    case_sensitive=case_var.get(),
                )
            except ValueError as e:
                self._show_notice_dialog(
                    "Invalid regex",
                    "The find pattern is not a valid Python regular expression.",
                    tone="error",
                    details=str(e),
                )
                return
            if count == 0:
                self.update_status("No matches found.")
                return

            def apply_to_editor(approved_lines):
                self.set_text(approved_lines)
                self.update_status(f"Replaced {count:,} occurrence(s).")
                dialog.destroy()

            PreviewWindow(
                self,
                original,
                new_lines,
                title=f"Preview: Find/Replace ({count:,} changes)",
                on_apply_callback=apply_to_editor,
                apply_label=f"Replace {count:,}",
            )

        ttk.Button(btn_row, text="Cancel", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        ttk.Button(btn_row, text="Preview...", command=do_preview, style="Action.TButton").pack(
            side="right", padx=(0, 8)
        )
        dialog.grab_set()

    def show_backup_diff_viewer(self):
        if self._block_during_import("Backup Diff"):
            return
        snapshots = self.list_backup_snapshots()
        rolling = self.HOSTS_FILE_PATH + ".bak"
        all_paths = []
        if os.path.exists(rolling):
            all_paths.append(rolling)
        all_paths.extend(snapshots)
        if len(all_paths) < 2:
            self._show_notice_dialog(
                "Not enough backups",
                "At least two backup snapshots are required to compare. Make a Cleaned Save, then try again.",
                tone="info",
            )
            return

        dialog = tk.Toplevel(self.root)
        self._configure_modal_window(
            dialog,
            title="Compare backup snapshots",
            size="620x380",
            min_size=(540, 320),
        )

        intro, _ = self._create_sidebar_card(
            dialog,
            "Backup snapshots",
            "Pick any two snapshots to see a preview of their differences. "
            "This is a read-only comparison — applying from the preview overwrites the editor, not disk.",
            accent=PALETTE["blue"],
        )
        ttk.Label(
            intro,
            text=f"{len(all_paths)} snapshot(s) available.",
            style="SectionBody.TLabel",
        ).pack(anchor="w")

        def label_for(path):
            try:
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path))
                ts = mtime.strftime("%Y-%m-%d %H:%M:%S")
            except OSError:
                ts = "?"
            return f"{os.path.basename(path)}   ({ts})"

        labels = [label_for(p) for p in all_paths]

        form = ttk.Frame(dialog, padding=(20, 0, 20, 10))
        form.pack(fill="x")
        ttk.Label(form, text="Older:").grid(row=0, column=0, sticky="w", pady=4)
        older_var = tk.StringVar(value=labels[-1])
        ttk.OptionMenu(form, older_var, older_var.get(), *labels).grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=4)
        ttk.Label(form, text="Newer:").grid(row=1, column=0, sticky="w", pady=4)
        newer_var = tk.StringVar(value=labels[0])
        ttk.OptionMenu(form, newer_var, newer_var.get(), *labels).grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=4)
        form.grid_columnconfigure(1, weight=1)

        def do_compare():
            try:
                older_path = all_paths[labels.index(older_var.get())]
                newer_path = all_paths[labels.index(newer_var.get())]
            except ValueError:
                return
            if older_path == newer_path:
                self.update_status("Pick two different snapshots to compare.", is_error=True)
                return
            try:
                older_lines = read_text_file_lines(older_path)
                newer_lines = read_text_file_lines(newer_path)
            except OSError as e:
                self._show_notice_dialog(
                    "Could not read snapshot",
                    "One of the selected backup files could not be read.",
                    tone="error",
                    details=str(e),
                )
                return
            dialog.destroy()
            # Read-only comparison: supply a no-op apply callback so the
            # Apply button doesn't silently overwrite the editor with one
            # of the snapshots.
            PreviewWindow(
                self,
                older_lines,
                newer_lines,
                title=f"Diff: {os.path.basename(older_path)} -> {os.path.basename(newer_path)}",
                on_apply_callback=lambda _approved: self.update_status("Backup comparison closed."),
                apply_label="Close",
                cancel_label="Close",
            )

        btn_row = ttk.Frame(dialog, padding=(20, 0, 20, 20))
        btn_row.pack(fill="x", side="bottom")
        ttk.Button(btn_row, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        ttk.Button(btn_row, text="Compare...", command=do_compare, style="Action.TButton").pack(
            side="right", padx=(0, 8)
        )
        dialog.grab_set()

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
                self.custom_sources_empty_label.pack(fill="x", pady=(0, 6), before=self.btn_add_custom)
        self._update_custom_source_summary()

    def _rebuild_custom_source_buttons(self):
        self._clear_custom_source_widgets()
        for source in self.custom_sources:
            self._create_custom_source_button(source['name'], source['url'])
        self._update_custom_source_empty_state()
        self.btn_add_custom.pack_forget()
        self.btn_add_custom.pack(fill=tk.X, pady=2, side=tk.BOTTOM)

    def _create_custom_source_button(self, name, url):
        tooltip = f"Use '{name}' as a saved custom feed."
        frame = ttk.Frame(self.custom_sources_frame, style="Inset.TFrame", padding=(0, 8, 0, 8))
        frame.pack(fill=tk.X, pady=0, before=self.btn_add_custom)
        self._custom_source_widgets[name] = frame

        inner = ttk.Frame(frame, style="Inset.TFrame")
        inner.pack(fill="both", expand=True)
        top = ttk.Frame(inner, style="Inset.TFrame")
        top.pack(fill="x")

        copy = ttk.Frame(top, style="Inset.TFrame")
        copy.pack(side="left", fill="x", expand=True)

        last_stamp = self.source_last_fetched.get(url, "") if hasattr(self, "source_last_fetched") else ""
        stamp_hint = format_relative_time(last_stamp)
        source_host = urllib.parse.urlparse(url).netloc or url
        freshness = f"Fetched {stamp_hint}" if stamp_hint else "Not fetched yet"
        tooltip_full = f"{tooltip}\n\nLast fetched: {stamp_hint}" if stamp_hint else tooltip

        ttk.Label(copy, text=name, style="InsetTitle.TLabel").pack(anchor="w")
        ttk.Label(copy, text=f"{source_host}  |  {freshness}", style="InsetBody.TLabel", wraplength=260, justify="left").pack(anchor="w", pady=(3, 0))

        action_row = ttk.Frame(top, style="Inset.TFrame")
        action_row.pack(side="right", padx=(12, 0))
        import_btn = self._btn(
            action_row,
            text="Import",
            command=lambda u=url, n=name: self.start_single_import(n, u),
            tooltip=tooltip_full,
            style="Action.TButton"
        )
        self._register_import_widget(import_btn)
        import_btn.pack(side="left")
        preview_btn = self._btn(
            action_row,
            text="Peek",
            command=lambda u=url, n=name: self.preview_blocklist_source(n, u),
            tooltip=f"Preview the first entries of {name} without importing.",
            style="TButton"
        )
        self._register_import_widget(preview_btn)
        preview_btn.pack(side="left", padx=(6, 0))
        remove_btn = ttk.Button(
            action_row,
            text="Remove",
            command=lambda n=name, f=frame: self.remove_custom_source(n, f),
            style="Remove.TButton"
        )
        self._register_import_widget(remove_btn)
        ToolTip(remove_btn, f"Remove the '{name}' source from configuration.")
        remove_btn.pack(side="left", padx=(6, 0))
        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=(8, 0))


    def show_add_source_dialog(self):
        draft_name = ""
        draft_url = ""

        while True:
            dialog = AddSourceDialog(self, initial_name=draft_name, initial_url=draft_url)
            if not dialog.result:
                return

            name, url = dialog.result
            draft_name, draft_url = name, url
            normalized_url = normalize_custom_source_url(url)
            if any(s['name'].lower() == name.lower() for s in self.custom_sources):
                self._show_notice_dialog(
                    "Saved source name already exists",
                    "A saved source with that display name already exists. Choose a different label so both sources stay distinguishable.",
                    tone="warning",
                )
                self.update_status("Error: Source name already exists.", is_error=True)
                continue
            if any(normalize_custom_source_url(s['url']) == normalized_url for s in self.custom_sources):
                self._show_notice_dialog(
                    "Saved source URL already exists",
                    "That feed URL is already configured in Saved Sources.",
                    tone="warning",
                )
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
        if not self._confirm_dialog(
            "Remove saved source?",
            f"Remove the saved source '{name}' from persistent configuration?",
            tone="warning",
            confirm_text="Remove source",
            cancel_text="Keep source",
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

        return self._confirm_dialog(
            "Replace whitelist contents?",
            f"You have unsaved whitelist edits. Replacing them with content from {source_name} will discard those edits.",
            tone="warning",
            confirm_text="Replace whitelist",
            cancel_text="Keep current edits",
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
            self._show_notice_dialog(
                "Could not load whitelist file",
                "The selected whitelist file could not be read.",
                tone="error",
                details=str(e),
            )

    def import_whitelist_from_web(self):
        if getattr(self, "_whitelist_web_fetch_active", False):
            self.update_status("A whitelist import is already running.", is_error=True)
            return
        url = "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Whitelist.txt"
        if not self._confirm_whitelist_replacement("the HOSTShield web feed"):
            self.update_status("Whitelist import cancelled. Existing entries kept.")
            return
        self.update_status("Importing whitelist from HOSTShield...")

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
        self._show_notice_dialog(
            "Could not fetch whitelist feed",
            "The HOSTShield whitelist feed could not be downloaded.",
            tone="error",
            details=str(error),
        )
            
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

        final_lines, stats = _get_canonical_cleaned_output_and_stats(original, whitelist_set, self.pinned_domains)
        
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
        if not self._confirm_dialog(
            "Launch emergency DNS recovery?",
            "This launches a last-resort recovery script that force-stops the DNS Client service and overwrites the hosts file with a minimal safe copy.",
            tone="warning",
            confirm_text="Launch recovery script",
            cancel_text="Cancel",
            details="Use this only if Windows is already locked up because the hosts file is too large or corrupted.",
            width=620,
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
            # Launch failed - remove the orphaned temp script so it doesn't
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
            self._show_notice_dialog(
                "Could not launch emergency recovery",
                "The emergency recovery script could not be started.",
                tone="error",
                details=str(e),
            )


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
                # Widget torn down during tagging - stop gracefully.
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
            # Text widget torn down (e.g. shutdown during a search cycle) -
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
            proceed = self._confirm_dialog(
                "Too many matches for individual review",
                f"Your search matched {len(matching_indices):,} lines. Building an individual checkbox for each would freeze the UI.",
                tone="warning",
                confirm_text="Review all in one preview",
                cancel_text="Cancel",
                details=(
                    f"Remove all {len(matching_indices):,} matching lines in one step instead. "
                    "A preview will still be shown before the editor changes."
                ),
            )
            if not proceed:
                return
            selected_indices = set(matching_indices)
        else:
            dialog = MatchRemovalDialog(
                self,
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
    try:
        shutil.copy2(hosts_path, f"{hosts_path}.bak")
        shutil.copy2(hosts_path, dest)
    except OSError as e:
        _cli_print(f"Backup failed: {e}")
        return 1
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
    backup_result = _cli_backup(hosts_path)
    if backup_result not in (0, 2):
        return backup_result
    minimal = (
        "# Copyright (c) 1993-2009 Microsoft Corp.\n#\n"
        "127.0.0.1       localhost\n"
        "::1             localhost\n"
    )
    try:
        disable_hosts_file_transactionally(hosts_path, disabled, minimal)
    except OSError as e:
        _cli_print(f"Disable failed: {e}")
        return 1
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
    backup_result = _cli_backup(hosts_path)
    if backup_result not in (0, 2):
        return backup_result
    try:
        enable_hosts_file_transactionally(hosts_path, disabled)
    except OSError as e:
        _cli_print(f"Enable failed: {e}")
        return 1
    _cli_print("hosts file re-enabled.")
    return 0


def _cli_apply(hosts_path: str, source_file: str) -> int:
    if not _cli_is_admin():
        _cli_print("Administrator privileges required.")
        return 1
    if not os.path.isfile(source_file):
        _cli_print(f"source file not found: {source_file}")
        return 2
    if os.path.exists(hosts_path + ".disabled"):
        _cli_print(
            "hosts file is currently disabled; re-enable it before applying a new file or the preserved configuration may overwrite your changes later."
        )
        return 1
    backup_result = _cli_backup(hosts_path)
    if backup_result not in (0, 2):
        return backup_result
    try:
        content = read_text_file_content(source_file)
        write_text_file_atomic(hosts_path, content)
    except OSError as e:
        _cli_print(f"Apply failed: {e}")
        return 1
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
    if os.path.exists(hosts_path + ".disabled"):
        _cli_print(
            "hosts file is currently disabled; re-enable it before running --update so refreshed sources are not written into the temporary minimal file."
        )
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

    backup_result = _cli_backup(hosts_path)
    if backup_result not in (0, 2):
        return backup_result
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
        try:
            existing_lines = read_text_file_lines(hosts_path)
        except OSError as e:
            _cli_print(f"Could not read current hosts file: {e}")
            return 1
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
    pinned = set(sanitized.get("pinned_domains", []))
    cleaned, stats = _get_canonical_cleaned_output_and_stats(merged, whitelist_set, pinned)
    try:
        write_text_file_atomic(hosts_path, '\n'.join(cleaned))
    except OSError as e:
        _cli_print(f"Could not write updated hosts file: {e}")
        return 1

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


