# FINAL SCRIPT WITH AI/DEVELOPER NOTES
# This script creates a comprehensive GUI tool for managing the Windows hosts file.
# Developed with Tkinter for cross-platform compatibility, though some features are Windows-specific.
# Key design principles:
# - Safety First: Includes admin checks, backup on save, and confirmations for destructive actions.
# - User-Friendliness: Provides a clear UI, previews for changes, and interactive elements.
# - Powerful Cleaning: The 'Clean' function is designed to be an intelligent, all-in-one processor for various malformed and complex blocklist formats.

import tkinter as tk
from tkinter import scrolledtext, messagebox, font, filedialog
import os
import ctypes
import difflib
import subprocess

class PreviewWindow(tk.Toplevel):
    """
    A Toplevel window to display a diff preview of changes.
    This class generates a read-only, color-coded view of what lines will be
    added or removed, allowing the user to visually confirm changes before applying them.
    """
    def __init__(self, parent, original_lines, new_lines, title="Preview Changes"):
        super().__init__(parent.root)
        self.parent_editor = parent
        self.new_lines = new_lines

        self.title(title)
        self.geometry("750x550")
        self.configure(bg="#2E2E2E")
        self.transient(parent.root)
        self.grab_set()

        # UI Setup: A simple text widget and buttons in a dark theme.
        text_frame = tk.Frame(self, bg="#2E2E2E")
        text_frame.pack(expand=True, fill='both', padx=10, pady=5)
        
        self.preview_text = scrolledtext.ScrolledText(
            text_frame,
            wrap=tk.WORD,
            font=("Consolas", 11),
            bg="#1E1E1E",
            fg="#D4D4D4",
            selectbackground="#264F78"
        )
        self.preview_text.pack(expand=True, fill='both')

        button_frame = tk.Frame(self, bg="#2E2E2E", pady=10)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)

        legend_frame = tk.Frame(button_frame, bg="#2E2E2E")
        legend_frame.pack(side=tk.LEFT, padx=10)
        tk.Label(legend_frame, text="■ Added", fg="#89D68D", bg="#2E2E2E", font=parent.default_font).pack(side=tk.LEFT)
        tk.Label(legend_frame, text="■ Removed", fg="#FF7B72", bg="#2E2E2E", font=parent.default_font).pack(side=tk.LEFT, padx=5)

        self.btn_apply = self.parent_editor.create_button(button_frame, "Apply Changes", self.apply_changes, bg_color="#4CAF50")
        self.btn_apply.pack(side=tk.RIGHT, padx=10)

        self.btn_cancel = self.parent_editor.create_button(button_frame, "Cancel", self.destroy)
        self.btn_cancel.pack(side=tk.RIGHT, padx=5)

        # Tkinter text tags are used for color highlighting.
        self.preview_text.tag_config('added', foreground="#89D68D")
        self.preview_text.tag_config('removed', foreground="#FF7B72")

        self.display_diff(original_lines, new_lines)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def display_diff(self, original, new):
        """
        Calculates and displays the diff using Python's built-in difflib library.
        It iterates through the diff results and inserts lines into the text widget
        with the appropriate color tag ('added' or 'removed').
        """
        diff = difflib.ndiff(original, new)
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete('1.0', tk.END)
        for line in diff:
            line_content = line[2:] + '\n' 
            if line.startswith('+ '):
                self.preview_text.insert(tk.END, line_content, 'added')
            elif line.startswith('- '):
                self.preview_text.insert(tk.END, line_content, 'removed')
            elif not line.startswith('? '): # Ignore difflib's informational lines
                self.preview_text.insert(tk.END, line_content)
        self.preview_text.config(state=tk.DISABLED) # Make text read-only

    def apply_changes(self):
        """
        Callback for the 'Apply' button. It calls the parent's set_text method
        to update the main editor with the new content and then closes itself.
        """
        self.parent_editor.set_text(self.new_lines)
        self.parent_editor.update_status(f"Changes from '{self.title()}' applied.")
        self.destroy()

class KeywordRemovalWindow(tk.Toplevel):
    """
    An interactive window for selective removal of entries.
    Instead of a static preview, this window displays a list of matching lines
    with checkboxes, giving the user fine-grained control over what is deleted.
    """
    def __init__(self, parent, keyword, matching_lines):
        super().__init__(parent.root)
        self.parent_editor = parent
        self.matching_lines = matching_lines
        self.check_vars = []

        self.title(f"Select Entries to Remove for '{keyword}'")
        self.geometry("750x550")
        self.configure(bg="#2E2E2E")
        self.transient(parent.root)
        self.grab_set()

        # A scrollable frame is used to handle potentially long lists of matches.
        main_frame = tk.Frame(self, bg="#2E2E2E")
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        canvas = tk.Canvas(main_frame, bg="#1E1E1E", highlightthickness=0)
        scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#1E1E1E")
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Populate the scrollable frame with a Checkbutton for each matching line.
        for line in self.matching_lines:
            var = tk.BooleanVar(value=True) # Default to checked (for removal)
            self.check_vars.append(var)
            cb = tk.Checkbutton(
                scrollable_frame, text=line, variable=var, font=("Consolas", 11),
                bg="#1E1E1E", fg="#D4D4D4", selectcolor="#3C3C3C",
                activebackground="#1E1E1E", activeforeground="#FFFFFF",
                anchor='w', justify='left'
            )
            cb.pack(fill='x', padx=10, pady=2)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        button_frame = tk.Frame(self, bg="#2E2E2E", pady=10)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.btn_confirm = self.parent_editor.create_button(button_frame, "Confirm Removal", self.confirm_removal, bg_color="#D9534F")
        self.btn_confirm.pack(side=tk.RIGHT, padx=10)
        self.btn_cancel = self.parent_editor.create_button(button_frame, "Cancel", self.destroy)
        self.btn_cancel.pack(side=tk.RIGHT, padx=5)
        
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def confirm_removal(self):
        """
        Builds a set of lines to be removed based on the checked items.
        It then reconstructs the full hosts list, excluding the selected lines,
        and updates the main editor.
        """
        lines_to_remove = set()
        for i, var in enumerate(self.check_vars):
            if var.get(): # Only add if the checkbox is checked
                lines_to_remove.add(self.matching_lines[i])

        if not lines_to_remove:
            self.parent_editor.update_status("No entries were selected for removal.")
            self.destroy()
            return

        original_lines = self.parent_editor.get_lines()
        new_lines = [line for line in original_lines if line not in lines_to_remove]
        
        self.parent_editor.set_text(new_lines)
        self.parent_editor.update_status(f"{len(lines_to_remove)} entries removed.")
        self.destroy()

class HostsFileEditor:
    """
    Main application class. This orchestrates the UI, file I/O, and all processing logic.
    """
    HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"

    def __init__(self, root):
        self.root = root
        self.root.title("Hosts File Management Tool")
        self.root.geometry("950x700")
        self.root.configure(bg="#2E2E2E")

        # --- Font and UI setup ---
        # The UI is built with Frames for modularity and easier layout management.
        self.default_font = font.Font(family="Segoe UI", size=10)
        self.title_font = font.Font(family="Segoe UI", size=11, weight="bold")

        control_frame = tk.Frame(root, bg="#3C3C3C", padx=10, pady=10)
        control_frame.pack(side=tk.TOP, fill=tk.X)
        editor_frame = tk.Frame(root, bg="#2E2E2E", padx=10, pady=5)
        editor_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        status_frame = tk.Frame(root, bg="#3C3C3C", padx=10, pady=5)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        # --- Button and Widget Creation ---
        # Buttons are grouped into logical sections using LabelFrames.
        self.btn_save = self.create_button(control_frame, "Save Changes", self.save_file, bg_color="#4CAF50", text_color="#FFFFFF")
        self.btn_save.pack(side=tk.LEFT, padx=(0, 5))
        self.btn_refresh = self.create_button(control_frame, "Refresh", self.load_file)
        self.btn_refresh.pack(side=tk.LEFT, padx=5)
        self.btn_import = self.create_button(control_frame, "Import pfSense Log", self.import_pfsense_log, bg_color="#0275D8")
        self.btn_import.pack(side=tk.LEFT, padx=5)
        
        transform_frame = tk.LabelFrame(control_frame, text="Cleaning & Utilities", bg="#3C3C3C", fg="#FFFFFF", font=self.title_font, padx=10, pady=5)
        transform_frame.pack(side=tk.RIGHT, padx=(10, 0))

        self.btn_clean = self.create_button(transform_frame, "Clean", self.auto_clean)
        self.btn_clean.pack(side=tk.LEFT, padx=5)
        self.btn_dedupe = self.create_button(transform_frame, "Deduplicate", self.deduplicate)
        self.btn_dedupe.pack(side=tk.LEFT, padx=5)
        self.btn_flush_dns = self.create_button(transform_frame, "Flush DNS", self.flush_dns, bg_color="#F0AD4E")
        self.btn_flush_dns.pack(side=tk.LEFT, padx=5)

        search_frame = tk.LabelFrame(control_frame, text="Search & Remove", bg="#3C3C3C", fg="#FFFFFF", font=self.title_font, padx=10, pady=5)
        search_frame.pack(side=tk.RIGHT, padx=(10, 10))

        tk.Label(search_frame, text="Keyword:", bg="#3C3C3C", fg="#FFFFFF", font=self.default_font).pack(side=tk.LEFT, padx=(0, 5))
        self.search_entry = tk.Entry(search_frame, bg="#1E1E1E", fg="#D4D4D4", font=self.default_font, relief=tk.FLAT, insertbackground="#FFFFFF", width=20)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.btn_remove_keyword = self.create_button(search_frame, "Remove", self.remove_by_keyword, bg_color="#D9534F")
        self.btn_remove_keyword.pack(side=tk.LEFT, padx=5)

        # Main text area for displaying and editing the hosts file content.
        self.text_area = scrolledtext.ScrolledText(editor_frame, wrap=tk.WORD, font=("Consolas", 11), bg="#1E1E1E", fg="#D4D4D4", insertbackground="#FFFFFF", selectbackground="#264F78")
        self.text_area.pack(expand=True, fill='both')
        self.text_area.bind("<<Modified>>", self.on_text_modified)
        self.is_modified = False

        # Status bar at the bottom for user feedback.
        self.status_label = tk.Label(status_frame, text="Loading...", font=self.default_font, bg="#3C3C3C", fg="#FFFFFF", anchor='w')
        self.status_label.pack(side=tk.LEFT)

        # --- Initial Checks ---
        self.check_admin_privileges()
        self.load_file(is_initial_load=True) # Load the hosts file on startup.
        
    def create_button(self, parent, text, command, bg_color="#555555", text_color="#FFFFFF"):
        """A helper function to create styled buttons, ensuring a consistent look."""
        return tk.Button(parent, text=text, command=command, font=self.default_font, bg=bg_color, fg=text_color, relief=tk.FLAT, padx=10, pady=5, activebackground="#666666", activeforeground="#FFFFFF", bd=0)

    def on_text_modified(self, event=None):
        """
        A callback to track if the text area has been modified. This is used
        to warn the user about unsaved changes before refreshing.
        """
        if not self.is_modified:
            self.is_modified = True
        self.text_area.edit_modified(False)

    def check_admin_privileges(self):
        """
        Safety Check: Verifies if the script is running with administrator rights.
        This is crucial as writing to the hosts file requires elevation.
        """
        try:
            is_admin = (os.getuid() == 0) # Linux/macOS
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0 # Windows
        if not is_admin:
            self.update_status("Warning: Not running as Administrator. You will not be able to save changes.", is_error=True)
            messagebox.showwarning("Admin Rights Required", "This tool needs to be run as an Administrator to save changes to the hosts file.")

    def update_status(self, message, is_error=False):
        """Helper to update the status bar text and color."""
        self.status_label.config(text=message, fg="#FF6B6B" if is_error else "#FFFFFF")

    def get_lines(self):
        """
        Safely gets content from the text area and splits it into a list of lines.
        Using .splitlines() is more robust than splitting on '\n'.
        """
        return self.text_area.get('1.0', tk.END).splitlines()

    def set_text(self, lines):
        """Clears and sets the text area content from a list of lines."""
        self.text_area.delete('1.0', tk.END)
        self.text_area.insert(tk.END, '\n'.join(lines))
        self.is_modified = False # Reset modified flag after setting text

    def load_file(self, is_initial_load=False):
        """
        Loads the hosts file from disk into the text area.
        Includes a safety check for unsaved changes before proceeding.
        """
        if self.is_modified and not is_initial_load:
            if not messagebox.askyesno("Confirm Refresh", "You have unsaved changes that will be lost.\n\nAre you sure you want to reload the hosts file?"):
                return
        try:
            if os.path.exists(self.HOSTS_FILE_PATH):
                with open(self.HOSTS_FILE_PATH, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.set_text(content.splitlines()) # Use set_text to manage modified flag
                self.update_status(f"Successfully loaded '{self.HOSTS_FILE_PATH}'")
            else:
                 self.update_status(f"Hosts file not found at '{self.HOSTS_FILE_PATH}'.", is_error=True)
        except Exception as e:
            self.update_status(f"Error loading hosts file: {e}", is_error=True)
            messagebox.showerror("Error", f"An unexpected error occurred while loading:\n{e}")

    def save_file(self):
        """
        Saves the content of the text area back to the hosts file.
        Includes critical safety checks:
        1. Warns if the user is about to save an empty file.
        2. Automatically creates a backup (hosts.txt) before writing.
        """
        content_to_save = self.text_area.get('1.0', tk.END)
        
        if not content_to_save.strip():
            if not messagebox.askyesno("Confirm Empty Save", "The editor is empty or contains only whitespace.\n\nAre you sure you want to completely clear your hosts file?"):
                self.update_status("Save cancelled by user.", is_error=True)
                return

        if messagebox.askokcancel("Confirm Save", "This will overwrite your hosts file.\nAre you sure you want to continue?"):
            backup_path = os.path.join(os.path.dirname(self.HOSTS_FILE_PATH), 'hosts.txt')
            try:
                # Create backup before attempting to save.
                if os.path.exists(self.HOSTS_FILE_PATH):
                    with open(self.HOSTS_FILE_PATH, 'r', encoding='utf-8') as original_file:
                        original_content = original_file.read()
                    with open(backup_path, 'w', encoding='utf-8') as backup_file:
                        backup_file.write(original_content)
                else:
                    backup_path = "N/A (original file did not exist)"
            except Exception as e:
                if not messagebox.askyesno("Backup Failed", f"Could not create backup file at '{backup_path}'.\nError: {e}\n\nDo you want to continue saving WITHOUT a backup?"):
                    self.update_status("Save cancelled by user due to backup failure.", is_error=True)
                    return

            # Proceed to save the actual file.
            try:
                with open(self.HOSTS_FILE_PATH, 'w', encoding='utf-8') as f:
                    f.write(content_to_save)
                self.update_status(f"Successfully saved to '{self.HOSTS_FILE_PATH}'. Backup is at '{backup_path}'")
                self.is_modified = False
                messagebox.showinfo("Success", "Hosts file saved successfully!")
            except PermissionError:
                self.update_status("Save failed: Permission denied. Run as Administrator.", is_error=True)
                messagebox.showerror("Error", "Permission denied. Please run this tool as an Administrator to save changes.")
            except Exception as e:
                self.update_status(f"An error occurred during save: {e}", is_error=True)

    def import_pfsense_log(self):
        """
        Allows the user to import a pfSense DNSBL log file. It parses the log,
        extracts unique domains, and appends them to the current editor content
        for further processing with the 'Clean' tool.
        """
        filepath = filedialog.askopenfilename(
            title="Select pfSense DNSBL Log File",
            filetypes=(("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*"))
        )
        if not filepath:
            self.update_status("Log import cancelled.")
            return

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                log_lines = f.readlines()
            
            extracted_domains = set()
            for line in log_lines:
                parts = line.strip().split(',')
                # The domain is expected in the 3rd column (index 2) of a DNSBL-Full log entry.
                if len(parts) > 2 and "DNSBL-Full" in parts[0]:
                    domain = parts[2].strip()
                    if domain:
                        extracted_domains.add(domain)

            if not extracted_domains:
                self.update_status(f"No valid DNSBL domains found in '{os.path.basename(filepath)}'.")
                return

            current_lines = self.get_lines()
            new_domains_to_add = sorted(list(extracted_domains))

            if current_lines and current_lines[-1].strip() != "":
                 current_lines.append("")
            current_lines.append(f"# --- Imported from {os.path.basename(filepath)} ---")
            current_lines.extend(new_domains_to_add)
            
            self.set_text(current_lines)
            self.update_status(f"Successfully imported {len(new_domains_to_add)} unique domains. Click 'Clean' to process.")

        except Exception as e:
            self.update_status(f"Error importing log file: {e}", is_error=True)
            messagebox.showerror("Import Error", f"An unexpected error occurred while processing the log file:\n{e}")

    def flush_dns(self):
        """
        Executes the 'ipconfig /flushdns' command on Windows to clear the DNS cache.
        This is useful after making changes to the hosts file to ensure they take effect immediately.
        """
        try:
            if os.name == 'nt': # Windows-specific command
                subprocess.run(
                    ['ipconfig', '/flushdns'],
                    capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
                )
                self.update_status("Successfully flushed the DNS resolver cache.")
                messagebox.showinfo("DNS Flushed", "Successfully flushed the DNS resolver cache.")
            else:
                messagebox.showwarning("Unsupported OS", "This feature is only available on Windows.")
        except Exception as e:
            self.update_status(f"An unexpected error occurred while flushing DNS: {e}", is_error=True)

    def process_and_preview(self, processing_function, title):
        """
        A wrapper function that takes a processing function (like clean or dedupe),
        runs it, and then opens the PreviewWindow with the results.
        This avoids code duplication.
        """
        original_lines = self.get_lines()
        processed_lines = processing_function(original_lines)
        if original_lines != processed_lines:
            PreviewWindow(self, original_lines, processed_lines, title=title)
        else:
            self.update_status("No changes found to apply.")

    def remove_by_keyword(self):
        """
        Gets the keyword from the search box, finds all matching lines,
        and then launches the interactive KeywordRemovalWindow.
        """
        keyword = self.search_entry.get().strip()
        if not keyword:
            messagebox.showwarning("Empty Keyword", "Please enter a keyword to search for.")
            return
        
        current_lines = self.get_lines()
        matching_lines = [line for line in current_lines if keyword.lower() in line.lower()]

        if not matching_lines:
            messagebox.showinfo("No Matches", f"No entries were found containing '{keyword}'.")
            return
        
        KeywordRemovalWindow(self, keyword, matching_lines)

    def deduplicate(self):
        """
        A simple deduplication function. It iterates through lines, adding them
        to a new list if they haven't been 'seen' before. It ignores comments and is case-insensitive.
        """
        def processor(lines):
            seen = set()
            unique_lines = []
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    if stripped.lower() not in seen:
                        seen.add(stripped.lower())
                        unique_lines.append(line)
                else: # Preserve comments and empty lines
                    unique_lines.append(line)
            return unique_lines
        self.process_and_preview(processor, "Preview: Deduplicate")

    def auto_clean(self):
        """
        This is the core intelligent cleaning function. It processes a list of lines
        and applies a series of robust rules to standardize them.
        """
        def processor(lines):
            seen = set()
            final_lines = []
            for line in lines:
                # 1. Remove inline comments (e.g., "domain.com # remove this").
                processed_line = line.split('#', 1)[0].strip()
                
                # 2. Skip if the line is now empty (was a comment or whitespace).
                if not processed_line:
                    continue
                
                # 3. Isolate the hostname. By splitting and taking the last part,
                #    we automatically discard any malformed IPs or prefixes.
                parts = processed_line.split()
                hostname = parts[-1]

                # 4. Handle wildcard formats (e.g., "*.domain.com"). The hosts file
                #    doesn't support wildcards, so we strip the prefix.
                if hostname.startswith('*.'):
                    hostname = hostname[2:]

                # 5. Rebuild the line in the standard "0.0.0.0 hostname" format.
                clean_line = f"0.0.0.0 {hostname}"

                # 6. Add the cleaned line to our results if it's not a duplicate.
                if clean_line.lower() not in seen:
                    seen.add(clean_line.lower())
                    final_lines.append(clean_line)
            
            # 7. Sort the final list alphabetically for consistency.
            return sorted(final_lines)
        self.process_and_preview(processor, "Preview: Clean")


if __name__ == "__main__":
    # Standard Tkinter app startup.
    root = tk.Tk()
    app = HostsFileEditor(root)
    root.mainloop()

