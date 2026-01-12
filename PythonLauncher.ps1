#
# Hosts File Management Tool - Automated Launcher
#
# Description:
# This script automatically downloads and runs the hosts_editor.py script.
# It ensures winget is installed, forces the installation of Python via winget,
# downloads the latest Python script, and then launches it with admin privileges.
#

#Requires -RunAsAdministrator

# ==========================================================
# 1. SETUP WPF SPLASH ENVIRONMENT
# ==========================================================
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Hosts Editor Launcher"
        Height="180" Width="450"
        WindowStyle="None"
        ResizeMode="NoResize"
        WindowStartupLocation="CenterScreen"
        Background="#FF020617"
        Topmost="True">
    <Border BorderBrush="#FF22c55e"
            BorderThickness="1"
            CornerRadius="6"
            Padding="10">
        <Grid>
            <StackPanel VerticalAlignment="Center">
                <TextBlock Text="HOSTS EDITOR LAUNCHER"
                           Foreground="#FF22c55e"
                           FontSize="18"
                           FontWeight="Bold"
                           HorizontalAlignment="Center"
                           Margin="0,0,0,15"/>
                
                <ProgressBar IsIndeterminate="True"
                             Height="4"
                             Foreground="#FF22c55e"
                             Background="#FF1e293b"
                             BorderThickness="0"
                             Margin="20,0"/>

                <TextBlock Name="StatusText"
                           Text="Initializing..."
                           Foreground="#FF94a3b8"
                           FontSize="12"
                           HorizontalAlignment="Center"
                           Margin="0,15,0,0"/>
            </StackPanel>
        </Grid>
    </Border>
</Window>
"@

# Build the GUI
try {
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
    $window = [System.Windows.Markup.XamlReader]::Load($reader)
    $statusBlock = $window.FindName("StatusText")
} catch {
    Write-Host "Failed to load GUI resources." -ForegroundColor Red
    exit
}

# Helper to update UI and keep it responsive
function Log-Status {
    param([string]$Message)
    
    Write-Host "[HostsLauncher] $Message" -ForegroundColor Gray

    if ($window) {
        $statusBlock.Text = $Message
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
    }
}

# Force TLS 1.2 for all downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Helper function to download files with multiple methods
function Download-File {
    param(
        [string]$Uri,
        [string]$OutFile
    )
    
    try {
        $ProgressPreference = 'SilentlyContinue'
        
        # Method 1: Try Invoke-WebRequest with proper headers
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
            if (Test-Path $OutFile) { return $true }
        } catch { }
        
        # Method 2: Try WebClient (handles redirects better)
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            $webClient.DownloadFile($Uri, $OutFile)
            if (Test-Path $OutFile) { return $true }
        } catch { }
        
        # Method 3: Try BITS transfer
        try {
            Start-BitsTransfer -Source $Uri -Destination $OutFile -ErrorAction Stop
            if (Test-Path $OutFile) { return $true }
        } catch { }
        
        return $false
    } catch {
        return $false
    }
}

# ==========================================================
# 2. WINGET INSTALLATION LOGIC
# ==========================================================
function Install-Winget {
    Log-Status "Installing WinGet via PSGallery script..."
    
    try {
        # Install NuGet provider (required for PSGallery)
        Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Out-Null
        
        Log-Status "Downloading winget-install script..."
        Install-Script -Name winget-install -Force -ErrorAction Stop
        
        Log-Status "Running winget-install..."
        winget-install
        
        Log-Status "WinGet installed successfully!"
        Start-Sleep -Seconds 2
        return $true
        
    } catch {
        Log-Status "ERROR: $($_.Exception.Message)"
        return $false
    }
}

# ==========================================================
# 3. PYTHON INSTALLATION LOGIC
# ==========================================================
function Ensure-PythonInstalled {
    Log-Status "Installing Python via winget..."
    
    try {
        $wingetResult = winget install Python.Python.3.14 --force --source winget --silent --accept-package-agreements --accept-source-agreements 2>&1
        
        Log-Status "Reloading environment variables..."
        
        # Refresh PATH in the current session
        $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ";" + [System.Environment]::GetEnvironmentVariable('Path', 'User')

        Log-Status "Verifying Python installation..."
        Start-Sleep -Milliseconds 500
        
        $versionInfo = python --version 2>&1
        if ($versionInfo -match "Python 3.") {
            Log-Status "Python is ready!"
            return $true
        } else {
            Log-Status "Python installed but not in PATH"
            return $false
        }
    }
    catch {
        Log-Status "ERROR: Failed to install Python"
        return $false
    }
}

# ==========================================================
# 4. DOWNLOAD AND RUN EDITOR
# ==========================================================
function Download-And-Run-Editor {
    $scriptUrl = "https://raw.githubusercontent.com/SysAdminDoc/Hosts-File-Management-Tool/refs/heads/main/hosts_editor.py"
    $destinationPath = Join-Path $env:TEMP "hosts_editor.py"

    Log-Status "Downloading Hosts Editor..."
    
    try {
        if (Download-File -Uri $scriptUrl -OutFile $destinationPath) {
            Log-Status "Download complete!"
        } else {
            throw "Download failed"
        }
    }
    catch {
        Log-Status "ERROR: Failed to download script"
        Start-Sleep -Seconds 3
        return $false
    }

    Log-Status "Launching Hosts Editor..."
    Start-Sleep -Milliseconds 500
    
    try {
        Start-Process python -ArgumentList "`"$destinationPath`""
        return $true
    }
    catch {
        Log-Status "ERROR: Failed to launch script"
        Start-Sleep -Seconds 3
        return $false
    }
}

# ==========================================================
# 5. MAIN EXECUTION
# ==========================================================
$window.Show()
Log-Status "Initializing..."
Start-Sleep -Milliseconds 500

try {
    # Step 1: Check if winget is installed
    Log-Status "Checking for winget..."
    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    
    if (-not $wingetCmd) {
        Log-Status "Winget not found. Installing..."
        Start-Sleep -Milliseconds 300
        
        if (-not (Install-Winget)) {
            Log-Status "Failed to install winget!"
            Start-Sleep -Seconds 5
            $window.Close()
            exit 1
        }
    } else {
        Log-Status "Winget is available"
        Start-Sleep -Milliseconds 300
    }
    
    # Step 2: Install Python
    if (-not (Ensure-PythonInstalled)) {
        Log-Status "Python installation failed!"
        Start-Sleep -Seconds 5
        $window.Close()
        exit 1
    }
    
    # Step 3: Download and run the editor
    if (Download-And-Run-Editor) {
        Log-Status "Success! Closing launcher..."
        Start-Sleep -Seconds 2
    }
    
} catch {
    Log-Status "Critical Error: $($_.Exception.Message)"
    Write-Host "`nFull error details:" -ForegroundColor Red
    Write-Host $_.Exception | Format-List -Force
    Start-Sleep -Seconds 10
}

$window.Close()
