# Hosts File Management Tool

A user-friendly desktop GUI application for cleaning, managing, and editing the Windows hosts file.  
This tool is designed to simplify the process of maintaining large blocklists, importing domains from firewall logs, and ensuring your hosts file is clean and efficient.

<img width="1738" height="1086" alt="image" src="https://github.com/user-attachments/assets/238d474a-2e23-420d-b795-fd078a568b80" />

---

## Features

### Graphical User Interface
Easily view and edit your entire hosts file in a simple text editor.

### Intelligent Cleaning
A powerful **Clean** function that automatically:
- Removes all comments and empty lines.
- Standardizes all entries to the `0.0.0.0 domain.com` format.
- Fixes malformed entries (e.g., `127.0.0.1`, typos, missing IPs).
- Strips wildcard prefixes (`*.`) from domains.
- Removes all duplicate entries (case-insensitive).
- Sorts the final list alphabetically.

### pfSense Log Importer
Directly import `dnsbl.log` files from a pfSense firewall to quickly add blocked domains to your hosts file.

### Interactive Keyword Removal
Search for entries containing a specific keyword (e.g., `"tiktok"`) and choose exactly which ones to remove from an interactive list.

### DNS Flushing
A one-click button to flush the Windows DNS cache (`ipconfig /flushdns`), making your changes take effect immediately.

### Safety First
- Automatically creates a backup (`hosts.txt`) in the same directory before every save.
- Warns if not run as an administrator.
- Asks for confirmation before saving an empty file or overwriting unsaved changes.

---

## Prerequisites

- **Python 3.x**: You must have Python installed on your system.  
  You can download it from [python.org](https://www.python.org/).

---

## How to Run

Because this tool modifies a system file, it must be run **with administrator privileges**.

1. **Save the Script:**  
   Save the `hosts_editor.py` file to a location on your computer (e.g., your Desktop).

2. **Open as Administrator:**  
   - Click the Start Menu, type `cmd` or `powershell`.  
   - Right-click the application and select **“Run as administrator”**.

3. **Navigate to Directory:**  
   In the administrator command window, use the `cd` command to navigate to the folder where you saved the script.

   Example if you saved it to your desktop:

4. **Execute the Script:**  
Run the tool by typing the following command and pressing Enter:


---

## How to Use the Tool

### Main Controls
- **Save Changes:** Overwrites the system hosts file with the content in the editor. Creates a backup first.  
- **Refresh:** Reloads the hosts file from disk. It will warn you if you have unsaved changes.  
- **Import pfSense Log:** Opens a file dialog to select a `.log` file. It extracts unique domains from the log and appends them to the editor for cleaning.

### Cleaning & Utilities
- **Clean:** The main all-in-one function. It applies all cleaning and formatting rules to the entire file. A preview window will show you all proposed changes.  
- **Deduplicate:** A simpler function that only removes duplicate entries without changing formatting or removing comments.  
- **Flush DNS:** Immediately clears your system's DNS cache.

### Search & Remove
1. **Enter Keyword:** Type a keyword (e.g., `facebook`, `google`) into the text box.  
2. **Click "Remove":** A new window will appear, listing only the entries that contain your keyword.  
3. **Select Entries:** By default, all found entries are checked for removal. Uncheck any you wish to keep.  
4. **Confirm Removal:** Click the **"Confirm Removal"** button to delete only the checked entries from the main editor.

---

## Notes

This tool is designed for Windows environments and should be run with administrator rights to modify the system hosts file safely. Always back up your hosts file before making changes if using it outside this application.

---
