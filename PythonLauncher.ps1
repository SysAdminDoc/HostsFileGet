#
# Hosts File Management Tool - Automated Launcher
#
# Description:
# This script downloads and runs the latest hosts editor with a small launcher UI.
# It ensures winget is available, reuses an existing Python 3 runtime when possible,
# refreshes the cached editor when a download succeeds, and can fall back to the
# last valid cached copy if the network is unavailable.
#

#Requires -RunAsAdministrator

$AppName = "Hosts File Get"
$AppSlug = "HostsFileGet"
$EditorUrl = "https://raw.githubusercontent.com/SysAdminDoc/Hosts-File-Management-Tool/refs/heads/main/hosts_editor.py"
$EditorCacheBase = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:TEMP }
$EditorCacheRoot = Join-Path $EditorCacheBase $AppSlug
$EditorPath = Join-Path $EditorCacheRoot "hosts_editor.py"

# ==========================================================
# 1. SETUP WPF SPLASH ENVIRONMENT
# ==========================================================
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Hosts File Get Launcher"
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
                <TextBlock Text="HOSTS FILE GET LAUNCHER"
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

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-PythonLaunchInfo {
    $launchers = @(
        @{ Command = "py"; Arguments = @("-3") },
        @{ Command = "python"; Arguments = @() }
    )

    foreach ($launcher in $launchers) {
        $command = Get-Command $launcher.Command -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $command) {
            continue
        }

        try {
            $versionInfo = & $command.Source @($launcher.Arguments + @("--version")) 2>&1
            if ($LASTEXITCODE -eq 0 -and $versionInfo -match "^Python 3\.") {
                return [PSCustomObject]@{
                    FilePath  = $command.Source
                    Arguments = $launcher.Arguments
                    Version   = $versionInfo
                }
            }
        } catch {
            continue
        }
    }

    return $null
}

function Get-WingetInstallScriptPath {
    $command = Get-Command winget-install -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) {
        return $command.Source
    }

    $candidatePaths = @(
        (Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Scripts\winget-install.ps1"),
        (Join-Path $env:USERPROFILE "Documents\PowerShell\Scripts\winget-install.ps1")
    )

    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -LiteralPath $candidatePath) {
            return $candidatePath
        }
    }

    return $null
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
        finally {
            if ($webClient) {
                $webClient.Dispose()
            }
        }
        
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
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue

        # Install NuGet provider (required for PSGallery)
        Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Out-Null
        
        Log-Status "Downloading winget-install script..."
        Install-Script -Name winget-install -Force -Scope CurrentUser -ErrorAction Stop
        
        Log-Status "Running winget-install..."
        $wingetInstallScriptPath = Get-WingetInstallScriptPath
        if ($wingetInstallScriptPath) {
            & $wingetInstallScriptPath
        } else {
            throw "winget-install script was installed but could not be located in PATH."
        }
        
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
    $pythonInfo = Get-PythonLaunchInfo
    if ($pythonInfo) {
        Log-Status "Using existing Python runtime."
        return $pythonInfo
    }

    Log-Status "Installing Python via winget..."
    
    try {
        $wingetResult = winget install --id Python.Python.3.14 --exact --source winget --silent --accept-package-agreements --accept-source-agreements 2>&1
        
        Log-Status "Reloading environment variables..."
        
        # Refresh PATH in the current session
        $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ";" + [System.Environment]::GetEnvironmentVariable('Path', 'User')

        Log-Status "Verifying Python installation..."
        Start-Sleep -Milliseconds 500
        
        $pythonInfo = Get-PythonLaunchInfo
        if ($pythonInfo) {
            Log-Status "Python is ready!"
            return $pythonInfo
        }

        Log-Status "Python installed but could not be located in PATH."
        Write-Host $wingetResult
        return $null
    }
    catch {
        Log-Status "ERROR: Failed to install Python"
        return $null
    }
}

function Test-ValidEditorFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.Length -lt 1000) {
            return $false
        }

        $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ($content -match "<html" -or $content -match "<!DOCTYPE html") {
            return $false
        }

        return $content -match 'APP_NAME\s*=\s*"Hosts File Get"' -and $content -match "class HostsFileEditor"
    } catch {
        return $false
    }
}

# ==========================================================
# 4. DOWNLOAD AND RUN EDITOR
# ==========================================================
function Download-And-Run-Editor {
    param([Parameter(Mandatory = $true)]$PythonInfo)

    Log-Status "Downloading Hosts Editor..."
    
    try {
        Ensure-Directory -Path $EditorCacheRoot
        $temporaryDownloadPath = Join-Path $EditorCacheRoot "hosts_editor.download.py"
        $editorPathToLaunch = $EditorPath

        if (Test-Path -LiteralPath $temporaryDownloadPath) {
            Remove-Item -LiteralPath $temporaryDownloadPath -Force -ErrorAction SilentlyContinue
        }

        if (Download-File -Uri $EditorUrl -OutFile $temporaryDownloadPath) {
            if (-not (Test-ValidEditorFile -Path $temporaryDownloadPath)) {
                throw "Downloaded editor file appears truncated."
            }

            Move-Item -LiteralPath $temporaryDownloadPath -Destination $EditorPath -Force
            Log-Status "Download complete!"
        } elseif (Test-ValidEditorFile -Path $EditorPath) {
            Log-Status "Download failed. Using cached editor copy."
        } else {
            throw "Download failed and no valid cached editor is available."
        }
    }
    catch {
        Log-Status "ERROR: Failed to prepare editor"
        Start-Sleep -Seconds 3
        return $false
    }
    finally {
        if ($temporaryDownloadPath -and (Test-Path -LiteralPath $temporaryDownloadPath)) {
            Remove-Item -LiteralPath $temporaryDownloadPath -Force -ErrorAction SilentlyContinue
        }
    }

    Log-Status "Launching Hosts Editor..."
    Start-Sleep -Milliseconds 500
    
    try {
        $launchArguments = @($PythonInfo.Arguments + @("`"$editorPathToLaunch`""))
        Start-Process -FilePath $PythonInfo.FilePath -ArgumentList $launchArguments
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

        $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ";" + [System.Environment]::GetEnvironmentVariable('Path', 'User')
        $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $wingetCmd) {
            Log-Status "WinGet install completed, but the command is still unavailable in this session."
            Start-Sleep -Seconds 5
            $window.Close()
            exit 1
        }
    } else {
        Log-Status "Winget is available"
        Start-Sleep -Milliseconds 300
    }
    
    # Step 2: Ensure Python is available
    $pythonInfo = Ensure-PythonInstalled
    if (-not $pythonInfo) {
        Log-Status "Python installation failed!"
        Start-Sleep -Seconds 5
        $window.Close()
        exit 1
    }
    
    # Step 3: Download and run the editor
    if (Download-And-Run-Editor -PythonInfo $pythonInfo) {
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
