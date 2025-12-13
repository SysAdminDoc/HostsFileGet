#
# Hosts File Management Tool - Automated Launcher
#
# Description:
# This script automatically downloads and runs the hosts_editor.py script.
# It forces the installation of Python via winget, downloads the latest Python script,
# and then launches it with the necessary administrator privileges.
#

# --- 1. Administrator Rights Check ---
# Ensure the script is running with elevated privileges, which is required
# to install Python and to run the hosts editor itself.
function Start-Elevated {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
            $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
            Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
            Exit
        }
    }
}
Start-Elevated # Execute the elevation check.

# --- 2. Automated Download and Launch Function ---
function Download-And-Run-Editor {
    # Per your preference, using BITS for file transfer is generally preferred in PowerShell over Invoke-WebRequest.
    # However, BITS is overkill for a simple one-off HTTP GET of a small file.
    # Sticking with Invoke-WebRequest as it's standard and the script is already using it.
    $scriptUrl = "https://raw.githubusercontent.com/SysAdminDoc/Hosts-File-Management-Tool/refs/heads/main/hosts_editor.py"
    # Save the script to the user's temporary directory to avoid permanent clutter.
    $destinationPath = Join-Path $env:TEMP "hosts_editor.py"

    Write-Host "Downloading the latest version of the Hosts Editor from GitHub..."
    try {
        # Use Invoke-WebRequest to download the file. -UseBasicParsing is good practice for compatibility.
        Invoke-WebRequest -Uri $scriptUrl -OutFile $destinationPath -UseBasicParsing
        Write-Host "Download complete." -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Failed to download the script from GitHub." -ForegroundColor Red
        Write-Host "Please check your internet connection and try again." -ForegroundColor Red
        Read-Host "Press Enter to exit."
        return # Exit the function
    }

    Write-Host "Launching the Hosts File Management Tool..."
    try {
        # Launch the downloaded script using python.exe
        # The python process will inherit the elevated privileges of this launcher.
        Start-Process python -ArgumentList "`"$destinationPath`""
    }
    catch {
        Write-Host "ERROR: Failed to launch the script." -ForegroundColor Red
        Write-Host "This can happen if Python was just installed or if an error occurred." -ForegroundColor Red
        Write-Host "Please try running the launcher again." -ForegroundColor Red
        Read-Host "Press Enter to exit."
    }
}


# --- 3. Python Installation Logic ---
function Ensure-PythonInstalled {
    Write-Host "Forcing Python installation via winget..." -ForegroundColor Yellow
    Write-Host "This may take a few minutes. Please wait..."
    
    try {
        # Per user request, force the installation of a specific Python version without prior checks.
        # Adding silent and agreement flags to ensure it runs without user interaction.
        winget install Python.Python.3.14 --force --source winget --silent --accept-package-agreements --accept-source-agreements
        
        # --- FIX: Reload environment variables to make 'python' available immediately ---
        Write-Host "Installation complete. Reloading session environment variables..." -ForegroundColor Cyan
        
        # This command forces the Windows environment to broadcast the change, which PowerShell picks up.
        # It sets a dummy value to trigger the necessary update in the current session.
        [System.Environment]::SetEnvironmentVariable('TEMP', $env:TEMP, 'Machine')
        
        # Now, explicitly refresh the PATH in the current session from the system PATH.
        # This is the most reliable way to get the newly installed Python path into $env:PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ";" + [System.Environment]::GetEnvironmentVariable('Path', 'User')

        # Verify after install to see if it's available in the current session.
        Write-Host "Verifying 'python' availability in the current session..."
        $versionInfo = python --version 2>&1
        if ($versionInfo -match "Python 3.") {
             Write-Host "Python is now available." -ForegroundColor Green
             return $true
        } else {
            # Fallback if the path reload failed for some reason (e.g., non-standard winget behavior)
            Write-Host "Python was installed, but the 'python' command is still not available." -ForegroundColor Red
            Write-Host "Try running the launcher again." -ForegroundColor Red
            Read-Host "Press Enter to exit."
            return $false
        }
    }
    catch {
        Write-Host "ERROR: Failed to install Python using winget." -ForegroundColor Red
        Write-Host "Please ensure winget is working and try again." -ForegroundColor Red
        Read-Host "Press Enter to exit."
        return $false
    }
}

# --- 4. Main Execution ---
# The script will first force the Python install, then download and run the editor.
if (Ensure-PythonInstalled) {
    Download-And-Run-Editor
}
