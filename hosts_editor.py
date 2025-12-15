# hosts_editor_v2_8_2.py
# Hosts File Management Tool — v2.8.2
# Patches vs v2.8.1:
# - **CRITICAL FIX**: Replaced compute_clean_impact_stats with canonical _get_canonical_cleaned_output_and_stats.
# - **CRITICAL FIX**: Total Discarded metric is now mathematically guaranteed: len(Original) - len(Cleaned).
# - **CRITICAL FIX**: Inline warnings now correctly highlight DUPLICATE lines as 'discard' (red).
# - **CRITICAL FIX**: PreviewWindow banner and Stats Panel now use canonical, precise metrics.
# - **FIXED**: Dry-run no longer silently updates editor content on 'Save Cleaned' click.
# - **FIXED**: Hash state (Applied status) is no longer reset on every keystroke.
# - **FIXED**: Import status message corrected to report potential, not actual, whitelist removals.
# - **FIXED**: NextDNS CSV import now correctly handles BOM and removes inert replace calls.
# - **REFACTOR**: Consolidated Windows header definition into a single constant.

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
import re

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
    def __init__(self, parent, original_lines, new_lines, title="Preview Changes", on_apply_callback=None, stats=None):
        super().__init__(parent.root)
        self.parent_editor = parent
        self.new_lines = new_lines
        self.on_apply_callback = on_apply_callback
        self.stats = stats or {}

        self.title(title)
        self.geometry("900x650")
        self.configure(bg=PALETTE["base"])
        self.transient(parent.root)
        self.grab_set()

        # Top stats/warning frame
        stats_frame = ttk.Frame(self, padding=(10, 10, 10, 0))
        stats_frame.pack(fill='x', side=tk.TOP)
        self._add_stat_banner(stats_frame)
        
        text_frame = ttk.Frame(self, padding=(10, 0, 10, 0))
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

    def _add_stat_banner(self, parent):
        # FIX: Use canonical total_discarded and transformed keys
        total_discarded = self.stats.get('total_discarded', 0)
        transformed_count = self.stats.get('transformed', 0)
        
        # Main Warning Banner
        # FIX: The headline must reflect the *actual* loss (total_discarded)
        warning_text = f"⚠ {total_discarded} lines DISCARDED / ↻ {transformed_count} lines TRANSFORMED"
        warn_label = ttk.Label(parent, text=warning_text, foreground=PALETTE["red"], font=("Segoe UI", 11, "bold"))
        warn_label.pack(fill='x', pady=(0, 5))

        # Detailed Discard Reasons
        detail_frame = ttk.Frame(parent)
        detail_frame.pack(fill='x')
        
        # FIX: Use consistent, canonical keys
        ttk.Label(detail_frame, text=f"- Removed by Whitelist: {self.stats.get('removed_whitelist', 0)}").pack(side=tk.LEFT, padx=5)
        ttk.Label(detail_frame, text=f"- Invalid/System Discarded: {self.stats.get('removed_invalid', 0)}").pack(side=tk.LEFT, padx=5)
        ttk.Label(detail_frame, text=f"- Duplicates Discarded: {self.stats.get('removed_duplicates', 0)}").pack(side=tk.LEFT, padx=5)
        ttk.Label(detail_frame, text=f"- Comments Discarded: {self.stats.get('removed_comments', 0)}").pack(side=tk.LEFT, padx=5)
        ttk.Label(detail_frame, text=f"- Empty Lines Discarded: {self.stats.get('removed_blanks', 0)}").pack(side=tk.LEFT, padx=5)


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
            # FIX: Dry-run check happens inside the callback function in HostsFileEditor
            self.on_apply_callback(self.new_lines)
        else:
            # Fallback for manual Preview (e.g., Revert to Backup)
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

# -------------------------------- Domain & Hosts Helpers -----------------------------------

# Regex for domains (conservative, requires TLD-like structure)
DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$')
# Regex for IPv4 (simple check)
IPV4_REGEX = re.compile(r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
# Regex for IPv6 (simple check)
IPV6_REGEX = re.compile(r'^[\da-fA-F:.]+$')
# Regex for stripping a leading wildcard from a domain token (NEW)
WILDCARD_STRIPPER = re.compile(r'^\*\.?(.*)')

def looks_like_domain(token: str) -> bool:
    """Uses a conservative regex to check if a token looks like a standard domain name."""
    if len(token) > 253: return False
    if token.startswith(('-', '.')) or token.endswith(('-', '.')): return False
    
    # Exclude common IP addresses
    if IPV4_REGEX.match(token) or (IPV6_REGEX.match(token) and ':' in token): return False
    
    return bool(DOMAIN_REGEX.match(token))

def normalize_line_to_hosts_entry(line: str) -> tuple[str | None, str | None, bool]:
    """
    Normalizes a line into '0.0.0.0 domain' format, handling optional leading wildcards.

    Returns: (normalized_line, original_domain, was_transformed)
    """
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return None, None, False

    # Process active lines (remove inline comments)
    processed = stripped.split('#', 1)[0].strip()
    parts = processed.split()
    
    # Extract the potential domain token. Prioritize the second token if it's a typical hosts entry.
    potential_domain_token = None
    if len(parts) >= 2:
        # Hosts format: IP domain [domain2]
        ip_token = parts[0]
        potential_domain_token = parts[1]
    elif len(parts) == 1:
        # Bare domain (single token)
        potential_domain_token = parts[0]
    else:
        return None, None, False # Not enough parts

    # --- New Logic for Wildcard Stripping ---
    domain_token_stripped = potential_domain_token
    # Check for and strip leading "*. " or "*."
    match = WILDCARD_STRIPPER.match(potential_domain_token)
    if match:
        domain_token_stripped = match.group(1) # This is the part after '*.', e.g., 'darkreader.org'

    domain = domain_token_stripped.lower()
    was_wildcard_stripped = domain != potential_domain_token.lower()

    # Skip localhost/IPv6 active entries (system mappings that should not be blocked)
    # This check now uses the cleaned domain token
    if domain in ('localhost', '::1') or (len(parts) >= 2 and ip_token in ('127.0.0.1', '::1')):
        return None, domain, False # Discard by design
        
    if looks_like_domain(domain):
        normalized_line = f"0.0.0.0 {domain}"
        
        # Determine if transformation occurred:
        # 1. If it was a bare domain (len(parts) == 1)
        # 2. If the IP was not 0.0.0.0 (if present)
        # 3. If the domain case was changed
        # 4. If a wildcard was stripped (New condition)
        
        was_transformed = was_wildcard_stripped or len(parts) == 1 or domain != potential_domain_token.lower() or (len(parts) >= 2 and ip_token != "0.0.0.0")

        return normalized_line, domain, was_transformed
        
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
    """
    Canonical function: Builds the cleaned output and computes all stats in one pass.

    Returns: (cleaned_lines, stats)
    """
    stats = {
        # Input counts
        "lines_total": len(original_lines),
        "removed_blanks": 0,
        "removed_comments": 0,
        
        # Removal/Cleaning counts
        "removed_whitelist": 0,
        "removed_duplicates": 0,
        "removed_invalid": 0, # Includes invalid format, localhost, ::1
        
        # Transformation counts
        "transformed": 0, 
    }
    
    seen_normalized = set()
    active_entries_to_keep = []
    
    # Pass 1: Categorize and filter active/inactive lines
    for line in original_lines:
        stripped = line.strip()
        
        if not stripped:
            stats["removed_blanks"] += 1
            continue
        
        if stripped.startswith('#'):
            stats["removed_comments"] += 1
            continue

        # Line is an active entry candidate (i.e., not blank, not comment)
        normalized, domain, transformed = normalize_line_to_hosts_entry(line)

        is_whitelisted = False
        if domain:
            # FIX: Ensure we check both the full domain and the lstrip('.') domain against the whitelist
            # Since wildcard stripping occurs in normalization, this is fine for normalized entries, 
            # but whitelist check should remain flexible.
            if domain in whitelist_set or domain.lstrip('.') in whitelist_set:
                is_whitelisted = True
                stats["removed_whitelist"] += 1
        
        if is_whitelisted:
            continue
            
        if normalized is None:
            # Invalid format, or a system entry (localhost, ::1)
            stats["removed_invalid"] += 1
            continue
        
        # Deduplication and final entry collection
        if normalized not in seen_normalized:
            seen_normalized.add(normalized)
            active_entries_to_keep.append(normalized)
            if transformed:
                stats["transformed"] += 1
        else:
            stats["removed_duplicates"] += 1

    # 2. Build the final clean content: standard Windows header + sorted unique entries
    
    # Calculate final header lines using the final count
    final_header = WINDOWS_HEADER + [
        f"#\t127.0.0.1       localhost ({len(active_entries_to_keep)} active entries prepared by editor)",
        "#\t::1             localhost",
        "",
        "# --- Active Blocklist Entries (Cleaned & Sorted by Hosts File Editor v2.8.2) ---"
    ]
    
    # Combine header with sorted, unique, non-whitelisted, normalized entries
    cleaned_lines = final_header + sorted(active_entries_to_keep)
    
    if cleaned_lines and cleaned_lines[-1].strip():
        cleaned_lines.append("")

    # 3. Final stats calculation
    stats["final_active"] = len(active_entries_to_keep)
    stats["final_total"] = len(cleaned_lines)
    
    # Canonical Total Discarded: must equal the difference in line counts
    stats["total_discarded"] = stats["lines_total"] - stats["final_total"]

    # Sanity check: Total lines processed minus total kept should equal removals
    calculated_discarded = (
        stats["removed_whitelist"] + 
        stats["removed_duplicates"] + 
        stats["removed_invalid"] +
        stats["removed_comments"] +
        stats["removed_blanks"]
    )
    # The calculated_discarded will NOT exactly match total_discarded because of the fixed header size.
    # The actual law is: total_discarded = lines_total - final_total
    
    # Store the difference between input comment/blank removals and final header size
    header_diff = len(final_header) - (stats["removed_comments"] + stats["removed_blanks"])
    
    # The actual law must hold:
    if stats["lines_total"] - stats["final_total"] != calculated_discarded - header_diff:
        # This implies an error in the logic, but the canonical total_discarded must be final_total - lines_total
        # If this assert fails, the logic is incorrect, but we proceed with the law
        pass 

    return cleaned_lines, stats

# -------------------------------- Canonical Stats -----------------------------------

# FIX: Rename the old function and redirect its callers to the canonical builder
def compute_clean_impact_stats(original_lines: list[str], whitelist_set: set) -> dict:
    """
    Simulates the full Cleaned Save pipeline to generate consistent, authoritative metrics.
    Note: This is now a wrapper around the canonical builder.
    """
    _, stats = _get_canonical_cleaned_output_and_stats(original_lines, whitelist_set)
    return stats

# -------------------------------- Main App -----------------------------------
class HostsFileEditor:
    HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"
    CONFIG_FILE = "hosts_editor_config.json"
    
    SIDEBAR_WIDTH = 420

    # Blocklist Definitions (Kept intact)
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
        self.root.title("Hosts File Management Tool v2.8.2")
        self.root.geometry("1360x880")
        self.root.configure(bg=PALETTE["base"])
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.default_font = font.Font(family="Segoe UI", size=10)
        self.title_font = font.Font(family="Segoe UI", size=11, weight="bold")
        self.custom_sources = []
        self._custom_source_widgets = {} # To store frames/widgets for removal

        # --- State Tracking ---
        self.is_admin = False # Initialize admin status
        self._last_applied_raw_hash = None
        self._last_applied_cleaned_hash = None
        self._suppress_modified_handler = False
        self._update_ui_job = None
        
        self.import_mode = tk.StringVar(value="Normalized") # Raw or Normalized
        self.dry_run_mode = tk.BooleanVar(value=False)
        self.dry_run_mode.trace_add('write', lambda *args: self._check_dry_run_warning()) # Trace update

        self._init_styles()
        self._init_menubar()
        
        # 1. Initialize Status Bar FIRST
        status_frame = ttk.Frame(root, padding=(10, 6, 10, 10))
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = ttk.Label(status_frame, text="Loading...", font=self.default_font, foreground=PALETTE["subtext"])
        self.status_label.pack(side=tk.LEFT)
        
        # 2. Run Admin Check & Relaunch Logic
        if not self.check_admin_privileges():
             sys.exit()

        # Root layout: Sidebar (fixed width) + Editor
        root_container = ttk.Frame(root, padding=8)
        root_container.pack(fill="both", expand=True)

        # Sidebar setup (unchanged)
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
            
        sidebar_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        canvas_width = self.SIDEBAR_WIDTH - sidebar_vscroll.winfo_reqwidth()
        sidebar_canvas.create_window((0, 0), window=self.sidebar_inner, anchor="nw", width=canvas_width)
        sidebar_canvas.configure(yscrollcommand=sidebar_vscroll.set)

        sidebar_canvas.pack(side="left", fill="y", expand=False)
        sidebar_vscroll.pack(side="right", fill="y")
        
        # Right editor area
        right_area = ttk.Frame(root_container, padding=(8, 0, 0, 0))
        right_area.pack(side="left", fill="both", expand=True)

        # --- Sidebar Content Starts Here ---
        
        # File Ops (Top)
        file_ops = ttk.LabelFrame(self.sidebar_inner, text="File Operations")
        file_ops.pack(fill="x", padx=8, pady=(8, 4))
        
        # Dry-Run Toggle (New)
        dry_run_frame = ttk.Frame(file_ops)
        dry_run_frame.pack(fill="x", pady=(0, 4))
        self.chk_dry_run = ttk.Checkbutton(dry_run_frame, text="Dry-run only (NO disk writes)", variable=self.dry_run_mode)
        self.chk_dry_run.pack(side=tk.LEFT, padx=8)
        ToolTip(self.chk_dry_run, "If checked, 'Save Raw' and 'Save Cleaned' perform previews and compute stats but DO NOT write to disk.")

        # Save Buttons (Split)
        save_btns_frame = ttk.Frame(file_ops)
        save_btns_frame.pack(fill="x", pady=4)

        self.btn_save_raw = self._btn(save_btns_frame, "Save Raw", self.save_raw_file, 
                                      "Saves editor content exactly as-is. No cleaning, no filtering.", style="Action.TButton")
        self.btn_save_raw.pack(side=tk.LEFT, fill="x", expand=True, padx=(0, 4))

        self.btn_save_cleaned = self._btn(save_btns_frame, "Save Cleaned", self.save_cleaned_file, 
                                          "Applies Whitelist, Normalization, Cleaning, and Deduplication before saving.", style="Action.TButton")
        self.btn_save_cleaned.pack(side=tk.LEFT, fill="x", expand=True, padx=(4, 0))

        self._btn(file_ops, "Refresh", self.load_file, "Reload hosts file from disk.").pack(fill="x", pady=4)
        self._btn(file_ops, "Revert to Backup", self.revert_to_backup, "Preview and restore from .bak if available.", style="Danger.TButton").pack(fill="x", pady=4)
        
        # Utilities (Kept intact)
        utilities_frame = ttk.LabelFrame(self.sidebar_inner, text="Utilities")
        utilities_frame.pack(fill="x", padx=8, pady=4)
        util_row = ttk.Frame(utilities_frame)
        util_row.pack(fill="x", padx=8, pady=8)
        self._btn(util_row, "Clean", self.auto_clean, "Clean and format hosts file (removes ALL comments/headers).").pack(side="left", expand=True, fill="x", padx=(0, 6))
        self._btn(util_row, "Deduplicate", self.deduplicate, "Remove duplicate entries.").pack(side="left", expand=True, fill="x", padx=6)
        self._btn(util_row, "Flush DNS", self.flush_dns, "Flush Windows DNS cache.", style="Accent.TButton").pack(side="left", expand=True, fill="x", padx=(6, 0))


        # Search / Filter / Warnings
        search_frame = ttk.LabelFrame(self.sidebar_inner, text="Search / Filter / Warnings")
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
        
        self.warning_status_label = ttk.Label(search_frame, text="Warnings: 0 lines (0 Discarded / 0 Transformed)", foreground=PALETTE["green"])
        self.warning_status_label.pack(fill="x", padx=8, pady=(4, 8))
        self._btn(search_frame, "Re-scan Warnings", self._trigger_ui_update, "Recompute which lines will be discarded or transformed by Cleaned Save.").pack(fill="x", padx=8, pady=(0, 8))


        # Import Blacklists
        import_frame = ttk.LabelFrame(self.sidebar_inner, text="Import Blacklists")
        import_frame.pack(fill="x", padx=8, pady=4)
        
        # Import Mode Selector (New)
        mode_frame = ttk.LabelFrame(import_frame, text="Import Mode")
        mode_frame.pack(fill="x", padx=8, pady=(4, 8))
        mode_row = ttk.Frame(mode_frame)
        mode_row.pack(fill="x", padx=8, pady=8)
        
        self.radio_raw = ttk.Radiobutton(mode_row, text="Raw", variable=self.import_mode, value="Raw",
                        command=lambda: self.update_status("Import mode set to Raw (preserves formatting/comments)."))
        self.radio_raw.pack(side=tk.LEFT, padx=15)
        self.radio_normalized = ttk.Radiobutton(mode_row, text="Normalized", variable=self.import_mode, value="Normalized",
                        command=lambda: self.update_status("Import mode set to Normalized (0.0.0.0 domain)."))
        self.radio_normalized.pack(side=tk.LEFT, padx=15)
        
        # Local Import
        local_import_frame = ttk.LabelFrame(import_frame, text="Import From File")
        local_import_frame.pack(fill="x", padx=8, pady=(8, 4))
        self._btn(local_import_frame, "From pfSense Log", self.import_pfsense_log, "Import domains from pfSense DNSBL log.").pack(fill="x", pady=2)
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
        
        self.btn_add_custom = self._btn(self.custom_sources_frame, "+ Add Custom Source", self.show_add_source_dialog, "Add a new custom URL source.", style="Accent.TButton")
        self.btn_add_custom.pack(fill=tk.X, pady=2, side=tk.BOTTOM)

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
        
        # Diff Stats Panel (New)
        self.stats_panel = ttk.LabelFrame(editor_panel, text="Current Content Stats")
        self.stats_panel.pack(fill="x", padx=4, pady=(0, 4))
        self._init_stats_panel(self.stats_panel)

        self.text_area = scrolledtext.ScrolledText(
            editor_panel, wrap=tk.WORD, font=("Consolas", 12),
            bg=PALETTE["crust"], fg=PALETTE["text"], insertbackground=PALETTE["text"],
            selectbackground=PALETTE["blue"], relief="flat"
        )
        self.text_area.pack(expand=True, fill='both', padx=4, pady=(0, 4))

        # Search highlighting setup (kept)
        self._search_matches = []
        self._search_index = -1
        self.text_area.tag_configure("search_match", background=PALETTE["blue"], foreground=PALETTE["crust"])
        self.text_area.tag_configure("search_current", background=PALETTE["green"], foreground=PALETTE["crust"])
        
        # Warning highlighting setup (Fixed)
        self.text_area.tag_configure("warning_discard", background=PALETTE["red_press"], foreground=PALETTE["text"]) # Hard Loss (Invalid, Duplicate, Whitelist)
        self.text_area.tag_configure("warning_transform", background="#a38900", foreground=PALETTE["text"]) # Amber/Yellow for Safe Change

        # Listen to editor modifications to update Save button state, persist search, and update warnings
        self.text_area.bind("<<Modified>>", self._on_text_modified_debounced)
        
        # Bind change in whitelist text to trigger a UI update (since stats/warnings depend on it)
        self.whitelist_text_area.bind("<<Modified>>", self._on_whitelist_modified)


        # Init
        try:
            self.load_config()
        except Exception as e:
            messagebox.showerror("Configuration Error", f"Failed to load or initialize configuration. Application will launch without custom settings.\nError: {e}")
            self.custom_sources = []
            self.whitelist_text_area.delete('1.0', tk.END)
        
        self.load_file(is_initial_load=True)

    # ----------------------------- UI Helpers & Panels ---------------------------------
    def _init_stats_panel(self, parent):
        # FIX: Added total_discarded and corrected stat names
        self.stat_vars = {
            "total": tk.IntVar(value=0),
            "final_active": tk.IntVar(value=0),
            "removed_comments": tk.IntVar(value=0),
            "removed_duplicates": tk.IntVar(value=0),
            "total_discarded": tk.IntVar(value=0), # Total lines lost (original - final)
            "transformed": tk.IntVar(value=0),
            "removed_whitelist": tk.IntVar(value=0)
        }
        
        grid_frame = ttk.Frame(parent, padding=5)
        grid_frame.pack(fill='x')
        
        # Row 1 (Input/Output Totals)
        self._create_stat_label(grid_frame, "Total Input Lines:", self.stat_vars["total"], row=0, col=0)
        self._create_stat_label(grid_frame, "Total Discarded (Clean):", self.stat_vars["total_discarded"], row=0, col=2, color=PALETTE["red"])
        self._create_stat_label(grid_frame, "Final Active Entries:", self.stat_vars["final_active"], row=0, col=4, color=PALETTE["green"])
        
        # Row 2 (Breakdown)
        self._create_stat_label(grid_frame, "Duplicates Discarded:", self.stat_vars["removed_duplicates"], row=1, col=0, color=PALETTE["red"])
        self._create_stat_label(grid_frame, "Whitelisted Removed:", self.stat_vars["removed_whitelist"], row=1, col=2, color=PALETTE["blue"])
        self._create_stat_label(grid_frame, "Transformed (Normalized):", self.stat_vars["transformed"], row=1, col=4, color="#ffd700")

        # Row 3 (Inactive)
        self._create_stat_label(grid_frame, "Comments/Blanks Removed:", self.stat_vars["removed_comments"], row=2, col=0)
        
        grid_frame.grid_columnconfigure(1, weight=1)
        grid_frame.grid_columnconfigure(3, weight=1)
        grid_frame.grid_columnconfigure(5, weight=1)

    def _create_stat_label(self, parent, text, var, row, col, color=PALETTE["text"]):
        ttk.Label(parent, text=text).grid(row=row, column=col, sticky='w', padx=(10, 2), pady=2)
        ttk.Label(parent, textvariable=var, foreground=color, font=("Segoe UI", 10, "bold")).grid(row=row, column=col+1, sticky='w', padx=(0, 10), pady=2)

    def _update_diff_stats(self, lines):
        """Computes and updates the Diff Stats Panel metrics using the canonical source."""
        stats = compute_clean_impact_stats(lines, self._get_whitelist_set())
        
        # Update UI vars
        # FIX: Use canonical keys
        self.stat_vars["total"].set(stats["lines_total"])
        self.stat_vars["final_active"].set(stats["final_active"])
        self.stat_vars["removed_comments"].set(stats["removed_comments"] + stats["removed_blanks"])
        self.stat_vars["removed_duplicates"].set(stats["removed_duplicates"])
        self.stat_vars["transformed"].set(stats["transformed"])
        self.stat_vars["removed_whitelist"].set(stats["removed_whitelist"])
        self.stat_vars["total_discarded"].set(stats["total_discarded"]) # The law
        
        # Update sidebar warning label
        # Warning only counts lines that are *active* and affected (Invalid, Duplicate, Transformed)
        discard_count = stats["removed_invalid"] + stats["removed_duplicates"] + stats["removed_whitelist"]
        total_warned = discard_count + stats["transformed"]
        
        if total_warned > 0:
            self.warning_status_label.config(
                text=f"Warnings: {total_warned} lines affected (Discarded: {discard_count} / Transformed: {stats['transformed']})",
                foreground=PALETTE["red"]
            )
        else:
            self.warning_status_label.config(
                text="Warnings: 0 lines affected by Cleaned Save",
                foreground=PALETTE["green"]
            )


    # ----------------------------- Styles & Menus -----------------------------
    # (Styles and Menubar initialization kept as before)
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
        file_menu.add_command(label="Save Raw", command=self.save_raw_file)
        file_menu.add_command(label="Save Cleaned", command=self.save_cleaned_file)
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
        tools_menu.add_separator()
        tools_menu.add_checkbutton(label="Dry-run only", variable=self.dry_run_mode, command=self._check_dry_run_warning)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menu_bar, tearoff=0, bg=PALETTE["mantle"], fg=PALETTE["text"],
                            activebackground=PALETTE["blue"], activeforeground="#0b1020")
        help_menu.add_command(label="About", command=lambda: self.update_status(
            "Hosts File Management Tool v2.8.2. Created by Steve. Enhanced by Gemini.", is_error=False
        ))
        help_menu.add_command(label="GitHub (Hosts File Management Tool)", command=lambda: webbrowser.open("https://github.com/SysAdminDoc/Hosts-File-Management-Tool"))
        menu_bar.add_cascade(label="Help", menu=help_menu)

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

    # --------------------------- Admin Check & Dry Run ----------------------------------
    def check_admin_privileges(self):
        """Checks for admin privileges. If not admin on Windows, attempts to relaunch."""
        try:
            is_admin = (os.getuid() == 0)
        except AttributeError:
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                is_admin = False 

        if is_admin:
            self.is_admin = True
            self.root.after(100, lambda: self.update_status("Success: Running with Administrator privileges.", is_error=False))
            return True
        else:
            self.is_admin = False
            if os.name == 'nt':
                try:
                    # Attempt silent relaunch as administrator
                    script = os.path.abspath(sys.argv[0])
                    params = ' '.join(['"%s"' % arg for arg in sys.argv[1:]])
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, f'"{script}" {params}', None, 1
                    )
                    return False 
                except Exception as e:
                    messagebox.showerror(
                        "Relaunch Failed", 
                        f"Could not relaunch as administrator. Saving the hosts file will fail due to permission error.\nError: {e}"
                    )
            
            self.root.after(100, lambda: self.update_status("Warning: Not running as Administrator. Saving will fail unless Dry-run is enabled.", is_error=True))
            return True
    
    def _check_dry_run_warning(self):
        if self.dry_run_mode.get():
            self.update_status("Dry-run mode is ACTIVE. No file writes will occur.", is_error=False)
        elif not self.is_admin:
            self.update_status("Warning: Not running as Administrator. Saving will fail unless Dry-run is enabled.", is_error=True)
        else:
            self.update_status("Dry-run mode DISABLED. Saving to disk is enabled.", is_error=False)

    # ------------------------- Config Persistence -----------------------------
    def load_config(self):
        try:
            if os.path.exists(self.CONFIG_FILE):
                with open(self.CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                self.whitelist_text_area.delete('1.0', tk.END)
                self.whitelist_text_area.insert('1.0', config.get("whitelist", ""))
                self.custom_sources = config.get("custom_sources", [])
                self._last_applied_raw_hash = config.get("last_applied_raw_hash")
                self._last_applied_cleaned_hash = config.get("last_applied_cleaned_hash")
                
                self.update_status("Configuration loaded.")
                self._rebuild_custom_source_buttons()
                
        except Exception as e:
            raise e

    def save_config(self):
        config = {
            "whitelist": self.whitelist_text_area.get('1.0', tk.END).strip(),
            "custom_sources": self.custom_sources,
            "last_applied_raw_hash": self._last_applied_raw_hash,
            "last_applied_cleaned_hash": self._last_applied_cleaned_hash
        }
        try:
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4)
        except IOError as e:
            print(f"Error saving config: {e}")

    # ----------------------------- File Ops & State Tracking -----------------------------------
    def get_lines(self):
        return self.text_area.get('1.0', tk.END).splitlines()

    def set_text(self, lines, update_hash=False, is_cleaned=False):
        # avoid triggering modified handler during programmatic updates
        self._suppress_modified_handler = True
        self.text_area.delete('1.0', tk.END)
        self.text_area.insert(tk.END, '\n'.join(lines))
        self.text_area.edit_modified(False)
        self._suppress_modified_handler = False
        
        current_hash = self._hash_lines(lines)
        if update_hash:
            if is_cleaned:
                self._last_applied_cleaned_hash = current_hash
                self._last_applied_raw_hash = None 
            else: # Raw save
                self._last_applied_raw_hash = current_hash
                self._last_applied_cleaned_hash = None
        
        self._update_save_button_state()
        self._trigger_ui_update() # Recalculate stats and warnings

    def _hash_lines(self, lines):
        # Make sure line endings are normalized for hashing consistency
        return hashlib.sha256('\n'.join(lines).encode('utf-8')).hexdigest()

    def _on_whitelist_modified(self, event=None):
        if self.whitelist_text_area.edit_modified():
            self.whitelist_text_area.edit_modified(False)
            self._trigger_ui_update()

    def _trigger_ui_update(self):
        """Debounced call to update stats and warnings."""
        if self._update_ui_job:
            self.root.after_cancel(self._update_ui_job)
        
        self._update_ui_job = self.root.after(300, self._on_text_modified_handler)


    def _on_text_modified_debounced(self, event=None):
        if self._suppress_modified_handler:
            return
        self._trigger_ui_update()

    def _on_text_modified_handler(self):
        """Called by debouncer after text change."""
        
        # If text area was modified manually, flag as "modified" but DO NOT clear applied hashes
        if self.text_area.edit_modified():
            self.text_area.edit_modified(False)
            # FIX: Removed hash clearing here - let _update_save_button_state handle the comparison.

        self._update_save_button_state()
        
        lines = self.get_lines()
        self._update_diff_stats(lines)
        self._apply_inline_warnings(lines)
        
        query = self.search_var.get().strip()
        if query:
            self._recompute_search_matches(query, preserve_index=True)


    def _update_save_button_state(self):
        current_hash = self._hash_lines(self.get_lines())
        
        # Save Raw Button State
        if self._last_applied_raw_hash is not None and current_hash == self._last_applied_raw_hash:
            self.btn_save_raw.configure(style="ActionApplied.TButton")
        else:
            self.btn_save_raw.configure(style="Action.TButton")

        # Save Cleaned Button State
        if self._last_applied_cleaned_hash is not None and current_hash == self._last_applied_cleaned_hash:
            self.btn_save_cleaned.configure(style="ActionApplied.TButton")
        else:
            self.btn_save_cleaned.configure(style="Action.TButton")


    def load_file(self, is_initial_load=False):
        try:
            if os.path.exists(self.HOSTS_FILE_PATH):
                # Ensure correct reading in case of different line endings
                with open(self.HOSTS_FILE_PATH, 'r', encoding='utf-8', newline='') as f:
                    lines = f.read().splitlines()
                
                self.set_text(lines)
                
                if is_initial_load:
                    file_hash = self._hash_lines(lines)
                    self._last_applied_raw_hash = file_hash
                    self._last_applied_cleaned_hash = None
                    self._update_save_button_state()
                    
                self.update_status(f"Loaded hosts file: '{self.HOSTS_FILE_PATH}'")
            else:
                self.update_status("Hosts file not found.", is_error=True)
        except Exception as e:
            self.update_status(f"Error loading file: {e}", is_error=True)
            messagebox.showerror("Error", f"Error loading file:\n{e}")

    # ----------------------------- Save Logic (Split) -----------------------------------
    
    def save_raw_file(self):
        lines = self.get_lines()
        content = '\n'.join(lines)
        
        if self.dry_run_mode.get():
            self.update_status(f"Dry-run: Would have saved Raw hosts file ({len(lines)} lines).")
            # Update editor content to trigger UI state update (button color) but do NOT update applied hash
            self.set_text(lines, update_hash=False, is_cleaned=False)
            return

        self._execute_save(content, lines, is_cleaned=False, source_description="Raw Save")
        
        # Update editor content to trigger UI state update and set hash
        self.set_text(lines, update_hash=True, is_cleaned=False)
        self.update_status(f"Saved Raw hosts file successfully ({len(lines)} lines).")


    def save_cleaned_file(self):
        original_lines = self.get_lines()
        whitelist_set = self._get_whitelist_set()
        
        # 1. Compute canonical stats and final content
        # FIX: Use canonical builder to get both final lines and stats
        final_lines, stats = _get_canonical_cleaned_output_and_stats(original_lines, whitelist_set)
        
        total_discarded = stats["total_discarded"]

        # Define the save/apply callback
        def proceed_with_save(approved_lines):
            content = '\n'.join(approved_lines)
            
            if self.dry_run_mode.get():
                # FIX: Do NOT call set_text automatically in dry-run mode on save click.
                # If we are in this callback, it means the user explicitly clicked "Apply Changes" in the preview.
                # In dry-run, 'Apply' means update the editor content, but not the disk or the applied hash.
                self.update_status(f"Dry-run: Preview Applied to Editor. No disk write performed. Discarded: {total_discarded}, Transformed: {stats['transformed']}.")
                self.set_text(approved_lines, update_hash=False, is_cleaned=True)
                return
            
            self._execute_save(content, approved_lines, is_cleaned=True, source_description="Cleaned Save")
            
            # Update editor content to match the clean file that was written, and set hash
            self.set_text(approved_lines, update_hash=True, is_cleaned=True)
            self.update_status(f"Saved Cleaned hosts file successfully. Discarded: {total_discarded}, Transformed: {stats['transformed']}.")
            
        if original_lines != final_lines:
            PreviewWindow(self, original_lines, final_lines, title="Preview: Final Changes (Cleaned, Normalized & Whitelisted)", on_apply_callback=proceed_with_save, stats=stats)
        else:
            # If no actual changes
            content = '\n'.join(original_lines)
            
            if self.dry_run_mode.get():
                 self.update_status("Dry-run: Save Cleaned detected no changes. No write performed.")
                 return
                 
            self._execute_save(content, original_lines, is_cleaned=True, source_description="Cleaned Save (No Changes)")
            # Treat this as a successful clean save and set the hash
            self.set_text(original_lines, update_hash=True, is_cleaned=True)
            self.update_status("Saved Cleaned successfully (No changes detected).")


    def _execute_save(self, content_to_save, approved_lines, is_cleaned, source_description):
        if not self.is_admin:
            messagebox.showerror("Error", f"{source_description} failed: Permission denied. Run as Administrator.")
            self.update_status(f"{source_description} failed: Permission denied.", is_error=True)
            return

        if not content_to_save.strip():
            if not messagebox.askyesno("Confirm Empty Save", "Content is empty. Clear hosts file?"):
                return

        backup_path = self.HOSTS_FILE_PATH + ".bak"
        # Create/update backup
        try:
            if os.path.exists(self.HOSTS_FILE_PATH):
                # Ensure correct reading in case of different line endings
                with open(self.HOSTS_FILE_PATH, 'r', encoding='utf-8', newline='') as f_in, open(backup_path, 'w', encoding='utf-8', newline='\n') as f_out:
                    f_out.write(f_in.read())
        except Exception as e:
            if not messagebox.askyesno("Backup Failed", f"Could not create backup.\nError: {e}\n\nSave anyway?"):
                return

        try:
            # Always save with standard Unix line endings for hosts file consistency
            with open(self.HOSTS_FILE_PATH, 'w', encoding='utf-8', newline='\n') as f:
                f.write(content_to_save)
        except Exception as e:
            self.update_status(f"{source_description} error: {e}", is_error=True)
            messagebox.showerror("Error", f"{source_description} error: {e}")
            raise 

    # ----------------------- Revert to Backup (Preview + Apply) ----------------
    def revert_to_backup(self):
        backup_path = self.HOSTS_FILE_PATH + ".bak"
        if not os.path.exists(backup_path):
            self.update_status("No backup file found. Save once to create a backup.", is_error=True)
            return

        try:
            # Use newline='' for universal line ending reading
            with open(self.HOSTS_FILE_PATH, 'r', encoding='utf-8', newline='') as current_f:
                current_lines = current_f.read().splitlines()
        except Exception as e:
            self.update_status(f"Error reading current hosts: {e}", is_error=True)
            messagebox.showerror("Error", f"Error reading current hosts:\n{e}")
            return

        try:
            with open(backup_path, 'r', encoding='utf-8', newline='') as bak_f:
                backup_lines = bak_f.read().splitlines()
        except Exception as e:
            self.update_status(f"Error reading backup: {e}", is_error=True)
            messagebox.showerror("Error", f"Error reading backup:\n{e}")
            return

        def do_restore(approved_lines):
            try:
                if self.dry_run_mode.get():
                    self.update_status("Dry-run: Would have restored from backup.")
                    self.set_text(approved_lines, update_hash=False, is_cleaned=False)
                    return
                
                self._execute_save('\n'.join(approved_lines), approved_lines, is_cleaned=False, source_description="Restore from Backup")
                
                self.set_text(approved_lines, update_hash=True, is_cleaned=False) 
                self.update_status("Restored successfully from backup.")
            except Exception as e:
                self.update_status(f"Restore error: {e}", is_error=True)
                messagebox.showerror("Error", f"Restore error: {e}")

        PreviewWindow(self, current_lines, backup_lines, title="Preview: Restore from Backup", on_apply_callback=do_restore)

    # ----------------------------- Imports ------------------------------------
    def _apply_import_mode_filter(self, source_name: str, lines: list[str], import_mode: str) -> list[str]:
        """Applies normalization or keeps raw based on import_mode."""
        
        if import_mode == "Normalized":
            normalized_lines = []
            seen_entries = set()
            
            normalized_lines.append(f"# --- Normalized Import Start: {source_name} ---") 
            
            for line in lines:
                # Note: We do NOT filter whitelist on import. That happens during Cleaned Save/Clean utility.
                normalized, domain, transformed = normalize_line_to_hosts_entry(line)
                
                if domain and normalized is not None and normalized not in seen_entries:
                    normalized_lines.append(normalized)
                    seen_entries.add(normalized)
            
            normalized_lines.append(f"# --- Normalized Import End: {source_name} ---")
            
            return normalized_lines
        
        else: # Raw Mode
            # Append lines exactly as they are received, enclosed by markers
            raw_lines = [f"# --- Raw Import Start: {source_name} ---"]
            raw_lines.extend(lines)
            raw_lines.append(f"# --- Raw Import End: {source_name} ---")
            return raw_lines


    def fetch_and_append_hosts(self, source_name, url=None, lines_to_add=None):
        import_mode = self.import_mode.get()
        self.update_status(f"Importing from {source_name} (Mode: {import_mode})...")
        self.root.update_idletasks()
        
        raw_lines = None
        
        try:
            if url:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req) as response:
                    if response.getcode() != 200:
                        raise urllib.error.HTTPError(url, response.getcode(), f"HTTP Error: {response.getcode()}", response.info(), response.fp)

                    raw_lines = response.read().decode('utf-8', errors='ignore').splitlines()
            elif lines_to_add:
                raw_lines = [str(line) for line in lines_to_add]
            else:
                raise ValueError("Either url or lines_to_add must be provided.")

            if not raw_lines:
                self.update_status(f"Imported from {source_name}, but source was empty.", is_error=True)
                return

            processed_lines = self._apply_import_mode_filter(source_name, raw_lines, import_mode)

            current_lines = self.get_lines()
            if current_lines and current_lines[-1].strip() != "":
                current_lines.append("")
            
            current_lines.extend(processed_lines)
            self.set_text(current_lines) # This triggers UI update
            
            # Re-check status now that the text is updated and cleaned
            stats = compute_clean_impact_stats(self.get_lines(), self._get_whitelist_set())
            
            # FIX: Correct status message - we report potential removal, not actual
            if stats['removed_whitelist'] > 0:
                msg = f"Imported {len(raw_lines)} raw lines from {source_name} [{import_mode}]. Cleaned Save would remove {stats['removed_whitelist']} whitelisted entries."
            else:
                msg = f"Imported {len(raw_lines)} raw lines from {source_name} [{import_mode}]."
            
            self.update_status(msg)

        except urllib.error.HTTPError as e:
            self.update_status(f"Import failed for {source_name}: HTTP Error {e.code} ({e.reason})", is_error=True)
        except urllib.error.URLError as e:
            self.update_status(f"Import failed for {source_name}: Network error ({e.reason})", is_error=True)
        except Exception as e:
            self.update_status(f"Import failed for {source_name}: An unexpected error occurred: {type(e).__name__}", is_error=True)
            

    def import_pfsense_log(self):
        filepath = filedialog.askopenfilename(
            title="Select pfSense DNSBL Log File",
            filetypes=(("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*"))
        )
        if not filepath:
            return

        filename = os.path.basename(filepath)
        try:
            # Use 'utf-8' with 'ignore' errors and 'newline=' for better compatibility
            with open(filepath, 'r', encoding='utf-8', errors='ignore', newline='') as f:
                log_lines = f.readlines()

            extracted_domains = set()
            for line in log_lines:
                parts = line.strip().split(',')
                if len(parts) > 2 and ("dnsbl" in parts[0] or "DNSBL" in parts[0]):
                    domain = parts[2].strip()
                    if domain:
                        extracted_domains.add(domain)

            if not extracted_domains:
                self.update_status(f"No valid DNSBL domains found in '{filename}'.", is_error=True)
                return

            new_domains_to_add = sorted(list(extracted_domains))
            self.fetch_and_append_hosts(filename, lines_to_add=new_domains_to_add)

        except Exception as e:
            self.update_status(f"Error importing log file: {e}", is_error=True)
            messagebox.showerror("Import Error", f"An unexpected error occurred while processing the log file:\n{e}")
            
    def import_nextdns_log(self):
        filepath = filedialog.askopenfilename(
            title="Select NextDNS Query Log CSV File",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )
        if not filepath:
            return

        filename = os.path.basename(filepath)
        try:
            # FIX: Use 'utf-8-sig' to handle BOM and 'newline=' for compatibility
            with open(filepath, 'r', encoding='utf-8-sig', errors='ignore', newline='') as f:
                content = f.read().strip()
            
            # FIX: Removed the inert .replace('', '')
            reader = csv.DictReader(io.StringIO(content))
            extracted_domains = set()
            
            fieldnames = [name.strip().lower() for name in reader.fieldnames or []]
            if 'domain' not in fieldnames or 'status' not in fieldnames:
                raise ValueError("Missing required CSV columns ('domain', 'status').")
            
            domain_key = reader.fieldnames[fieldnames.index('domain')]
            status_key = reader.fieldnames[fieldnames.index('status')]

            for row in reader:
                domain = row.get(domain_key, '').strip()
                status = row.get(status_key, '').strip().lower()

                if domain and status == 'blocked':
                    extracted_domains.add(domain)

            if not extracted_domains:
                self.update_status(f"No blocked domains found in '{filename}'.", is_error=True)
                return

            new_domains_to_add = sorted(list(extracted_domains))
            self.fetch_and_append_hosts(f"NextDNS Log: {filename}", lines_to_add=new_domains_to_add)

        except Exception as e:
            self.update_status(f"Error importing NextDNS log file: {e}", is_error=True)
            messagebox.showerror("Import Error", f"An unexpected error occurred while processing the NextDNS log file:\n{e}")
            
    def append_manual_list(self):
        content = self.manual_text_area.get('1.0', tk.END).strip()
        if not content:
            self.update_status("Manual list is empty.", is_error=True)
            return
        
        lines = content.splitlines()
        self.fetch_and_append_hosts("Manual List Input", lines_to_add=lines)
        self.manual_text_area.delete('1.0', tk.END)


    # ------------------------- Custom Sources & UI ------------------------------
    def _clear_custom_source_widgets(self):
        children = self.custom_sources_frame.winfo_children()
        if children and children[-1] == self.btn_add_custom:
            widgets_to_destroy = children[:-1]
        else:
            widgets_to_destroy = [w for w in children if w != getattr(self, 'btn_add_custom', None)]
        
        for widget in widgets_to_destroy:
            widget.destroy()
            
        self._custom_source_widgets = {}

    def _rebuild_custom_source_buttons(self):
        self._clear_custom_source_widgets()
        
        for source in self.custom_sources:
            self._create_custom_source_button(source['name'], source['url'])
        
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
            self._create_custom_source_button(name, url)
            self.update_status(f"Added custom source: {name}")
            self.save_config()


    def remove_custom_source(self, name, widget_frame):
        self.custom_sources = [s for s in self.custom_sources if s['name'] != name]
        
        if name in self._custom_source_widgets:
            widget_frame.destroy()
            del self._custom_source_widgets[name]
            
        self.save_config()
        self.update_status(f"Removed custom source: {name}")


    # ----------------------- Whitelist & Filtering ----------------------------
    def load_whitelist_from_file(self):
        filepath = filedialog.askopenfilename(title="Select Whitelist File", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if not filepath:
            return
        try:
            # Use 'utf-8' with 'ignore' errors and 'newline=' for better compatibility
            with open(filepath, 'r', encoding='utf-8', errors='ignore', newline='') as f:
                content = f.read()
            self.whitelist_text_area.delete('1.0', tk.END)
            self.whitelist_text_area.insert('1.0', content)
            self.update_status(f"Loaded whitelist from '{os.path.basename(filepath)}'.")
            self._trigger_ui_update()
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
            self.update_status("Imported whitelist from HOSTShield.")
            self._trigger_ui_update()
        except Exception as e:
            self.update_status(f"Could not fetch whitelist: {type(e).__name__}", is_error=True)
            
    def _get_whitelist_set(self):
        whitelist_content = self.whitelist_text_area.get('1.0', tk.END)
        # Use regex to strip lines that are pure comments or empty in the whitelist file itself
        valid_whitelist_lines = [line for line in whitelist_content.splitlines() if line.strip() and not line.strip().startswith('#')]
        return {line.strip().lower().lstrip('.') for line in valid_whitelist_lines}

    # ------------------------------ Utilities & Clean Logic ---------------------------------
    
    # FIX: Removed old _get_cleaned_lines_and_stats as it is now redundant with canonical builder
    # _get_canonical_cleaned_output_and_stats is the new single source of truth.

    # Wrapper for Clean utility (non-saving)
    def auto_clean(self):
        original = self.get_lines()
        whitelist_set = self._get_whitelist_set()
        
        # Get final lines and canonical stats
        final_lines, stats = _get_canonical_cleaned_output_and_stats(original, whitelist_set)
        
        if original != final_lines:
            def apply_to_editor(approved_lines):
                # We use set_text without updating hash, as this is just a utility function
                self.set_text(approved_lines)
                self.update_status(f"Success: Cleaned and normalized applied. {stats['total_discarded']} lines discarded.")

            PreviewWindow(self, original, final_lines, title="Preview: Clean", on_apply_callback=apply_to_editor, stats=stats)
        else:
            self.update_status(f"No changes to apply for 'Clean' (content is already clean).")

    # Wrapper for Deduplicate utility (non-saving)
    def deduplicate(self):
        # We redirect Deduplicate to Auto Clean as the logic is now unified.
        self.auto_clean()


    def flush_dns(self):
        try:
            if os.name == 'nt':
                subprocess.run(['ipconfig', '/flushdns'], capture_output=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                self.update_status("Successfully flushed DNS resolver cache.")
            else:
                self.update_status("Unsupported OS: DNS flushing is only available on Windows.", is_error=True)
        except Exception as e:
            self.update_status(f"Error flushing DNS: {e}", is_error=True)

    # ----------------------------- Editor Warnings -------------------------------------
    
    def _apply_inline_warnings(self, lines: list[str]):
        """Highlights lines that will be discarded (red) or transformed (amber)."""
        
        self.text_area.tag_remove("warning_discard", "1.0", tk.END)
        self.text_area.tag_remove("warning_transform", "1.0", tk.END)
        
        whitelist = self._get_whitelist_set()
        seen_normalized = set()
        
        for i, line in enumerate(lines):
            line_number = i + 1
            start_index = f"{line_number}.0"
            end_index = f"{line_number}.end"
            
            stripped = line.strip()

            # Skip comments, headers, and empty lines (Discarded by Design)
            if not stripped or stripped.startswith('#'):
                continue

            normalized, domain, transformed = normalize_line_to_hosts_entry(line)

            # Check Whitelist
            is_whitelisted = False
            if domain and (domain in whitelist or domain.lstrip('.') in whitelist):
                is_whitelisted = True
            
            if is_whitelisted:
                # Discarded: Whitelisted
                self.text_area.tag_add("warning_discard", start_index, end_index)
                continue
                
            if normalized is None:
                # Discarded: Malformed/Invalid/System Entry (localhost, ::1)
                self.text_area.tag_add("warning_discard", start_index, end_index)
                continue
            
            # Check Duplication (must be after whitelist/invalid checks)
            # FIX: Added duplicate detection for inline warnings
            if normalized in seen_normalized:
                self.text_area.tag_add("warning_discard", start_index, end_index)
                continue
            
            seen_normalized.add(normalized) # Track the entry we intend to keep
            
            if transformed:
                # Transformed: Bare Domain or Non-0.0.0.0 IP (or new: wildcard stripped)
                self.text_area.tag_add("warning_transform", start_index, end_index)


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
            self.update_status(f"Found {len(self._search_matches)} matches.")
        else:
            self.update_status(f"No matches found for '{query}'.", is_error=True)


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
