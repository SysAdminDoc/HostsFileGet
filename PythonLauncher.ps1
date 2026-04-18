#
# Hosts File Get - Automated Launcher
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
$EditorUrl = "https://raw.githubusercontent.com/SysAdminDoc/HostsFileGet/refs/heads/main/hosts_editor.py"
$EditorCacheBase = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:TEMP }
$EditorCacheRoot = Join-Path $EditorCacheBase $AppSlug
$EditorPath = Join-Path $EditorCacheRoot "hosts_editor.py"
$LogPath = Join-Path $EditorCacheRoot "launcher.log"

# Persist a transcript so unattended launches (scheduled tasks, helpdesk
# remote sessions) leave a forensic trail. Failures here are non-fatal.
try {
    if (-not (Test-Path -LiteralPath $EditorCacheRoot)) {
        New-Item -ItemType Directory -Path $EditorCacheRoot -Force | Out-Null
    }
    Start-Transcript -Path $LogPath -Append -Force -ErrorAction Stop | Out-Null
} catch {
    # Non-fatal: continue without transcript.
}

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
function Write-LauncherStatus {
    param([string]$Message)

    Write-Host "[$AppName Launcher] $Message" -ForegroundColor Gray

    if ($window) {
        $statusBlock.Text = $Message
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
    }
}

function Initialize-CacheDirectory {
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

# Allow TLS 1.2 and (where available) TLS 1.3 for all downloads. Older
# Windows PowerShell 5.1 / Server 2016 lack the Tls13 enum value — the
# fallback assignment keeps TLS 1.2 in that case.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# Helper function to download files with multiple methods
function Invoke-FileDownload {
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
    Write-LauncherStatus "Installing WinGet via PSGallery script..."
    
    try {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue

        # Install NuGet provider (required for PSGallery)
        Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Out-Null
        
        Write-LauncherStatus "Downloading winget-install script..."
        Install-Script -Name winget-install -Force -Scope CurrentUser -ErrorAction Stop
        
        Write-LauncherStatus "Running winget-install..."
        $wingetInstallScriptPath = Get-WingetInstallScriptPath
        if ($wingetInstallScriptPath) {
            & $wingetInstallScriptPath
        } else {
            throw "winget-install script was installed but could not be located in PATH."
        }
        
        Write-LauncherStatus "WinGet installed successfully!"
        Start-Sleep -Seconds 2
        return $true
        
    } catch {
        Write-LauncherStatus "ERROR: $($_.Exception.Message)"
        return $false
    }
}

# ==========================================================
# 3. PYTHON INSTALLATION LOGIC
# ==========================================================
function Install-PythonWithWinget {
    $candidateIds = @(
        "Python.Python.3.14",
        "Python.Python.3.13",
        "Python.Python.3.12",
        "Python.Python.3"
    )

    foreach ($packageId in $candidateIds) {
        Write-LauncherStatus "Trying $packageId via winget..."
        try {
            $wingetResult = winget install --id $packageId --exact --source winget --silent --accept-package-agreements --accept-source-agreements 2>&1
            if ($LASTEXITCODE -eq 0) {
                return [PSCustomObject]@{
                    Success = $true
                    PackageId = $packageId
                    Output = $wingetResult
                }
            }

            Write-Host "winget install failed for $packageId"
            Write-Host $wingetResult
        } catch {
            Write-Host "winget install raised for $packageId"
            Write-Host $_.Exception.Message
        }
    }

    return [PSCustomObject]@{
        Success = $false
        PackageId = $null
        Output = $null
    }
}

function Initialize-PythonRuntime {
    $pythonInfo = Get-PythonLaunchInfo
    if ($pythonInfo) {
        Write-LauncherStatus "Using existing Python runtime."
        return $pythonInfo
    }

    Write-LauncherStatus "Installing Python via winget..."
    
    try {
        $installResult = Install-PythonWithWinget
        if (-not $installResult.Success) {
            Write-LauncherStatus "ERROR: Failed to install Python"
            return $null
        }
        
        Write-LauncherStatus "Reloading environment variables..."
        
        # Refresh PATH in the current session
        $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ";" + [System.Environment]::GetEnvironmentVariable('Path', 'User')

        Write-LauncherStatus "Verifying Python installation..."
        Start-Sleep -Milliseconds 500
        
        $pythonInfo = Get-PythonLaunchInfo
        if ($pythonInfo) {
            Write-LauncherStatus "Python is ready!"
            return $pythonInfo
        }

        Write-LauncherStatus "Python installed but could not be located in PATH."
        Write-Host "Last successful package id: $($installResult.PackageId)"
        if ($installResult.Output) {
            Write-Host $installResult.Output
        }
        return $null
    }
    catch {
        Write-LauncherStatus "ERROR: Failed to install Python"
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
        # Upper bound: the current editor is well under 1 MB. A 20 MB file in
        # this slot is either a MITM-substituted payload or a download that
        # picked up a generic landing page we didn't catch. Refuse it.
        if ($item.Length -gt 20MB) {
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

function Test-EditorSyntax {
    param(
        [Parameter(Mandatory = $true)]$PythonInfo,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    try {
        $compileOutput = & $PythonInfo.FilePath @($PythonInfo.Arguments + @("-m", "py_compile", $Path)) 2>&1
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
        Write-Host "Python syntax validation failed for $Path"
        Write-Host $compileOutput
        return $false
    } catch {
        Write-Host "Python syntax validation raised for $Path"
        Write-Host $_.Exception.Message
        return $false
    }
}

# ==========================================================
# 4. DOWNLOAD AND RUN EDITOR
# ==========================================================
function Invoke-EditorBootstrap {
    param([Parameter(Mandatory = $true)]$PythonInfo)

    Write-LauncherStatus "Downloading Hosts Editor..."
    
    try {
        Initialize-CacheDirectory -Path $EditorCacheRoot
        $temporaryDownloadPath = Join-Path $EditorCacheRoot "hosts_editor.download.py"
        $editorPathToLaunch = $EditorPath

        if (Test-Path -LiteralPath $temporaryDownloadPath) {
            Remove-Item -LiteralPath $temporaryDownloadPath -Force -ErrorAction SilentlyContinue
        }

        if (Invoke-FileDownload -Uri $EditorUrl -OutFile $temporaryDownloadPath) {
            if (-not (Test-ValidEditorFile -Path $temporaryDownloadPath)) {
                throw "Downloaded editor file appears truncated."
            }
            if (-not (Test-EditorSyntax -PythonInfo $PythonInfo -Path $temporaryDownloadPath)) {
                throw "Downloaded editor file failed Python syntax validation."
            }

            Move-Item -LiteralPath $temporaryDownloadPath -Destination $EditorPath -Force
            Write-LauncherStatus "Download complete!"
        } elseif ((Test-ValidEditorFile -Path $EditorPath) -and (Test-EditorSyntax -PythonInfo $PythonInfo -Path $EditorPath)) {
            Write-LauncherStatus "Download failed. Using cached editor copy."
        } else {
            throw "Download failed and no valid cached editor is available."
        }
    }
    catch {
        Write-LauncherStatus "ERROR: Failed to prepare editor"
        Start-Sleep -Seconds 3
        return $false
    }
    finally {
        if ($temporaryDownloadPath -and (Test-Path -LiteralPath $temporaryDownloadPath)) {
            Remove-Item -LiteralPath $temporaryDownloadPath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-LauncherStatus "Launching Hosts Editor..."
    Start-Sleep -Milliseconds 500

    try {
        # Start-Process handles quoting internally when given an array of
        # arguments. Wrapping the path in embedded double-quotes previously
        # produced arguments like `""C:\...path..."""` if the cache path
        # contained spaces, which fails on some PowerShell hosts.
        $launchArguments = @()
        $launchArguments += $PythonInfo.Arguments
        $launchArguments += $editorPathToLaunch
        Start-Process -FilePath $PythonInfo.FilePath -ArgumentList $launchArguments
        return $true
    }
    catch {
        Write-LauncherStatus "ERROR: Failed to launch script"
        Start-Sleep -Seconds 3
        return $false
    }
}

# ==========================================================
# 5. MAIN EXECUTION
# ==========================================================
$window.Show()
Write-LauncherStatus "Initializing..."
Start-Sleep -Milliseconds 500

try {
    # Step 1: Check if winget is installed
    Write-LauncherStatus "Checking for winget..."
    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    
    if (-not $wingetCmd) {
        Write-LauncherStatus "Winget not found. Installing..."
        Start-Sleep -Milliseconds 300
        
        if (-not (Install-Winget)) {
            Write-LauncherStatus "Failed to install winget!"
            Start-Sleep -Seconds 5
            $window.Close()
            exit 1
        }

        $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ";" + [System.Environment]::GetEnvironmentVariable('Path', 'User')
        $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $wingetCmd) {
            Write-LauncherStatus "WinGet install completed, but the command is still unavailable in this session."
            Start-Sleep -Seconds 5
            $window.Close()
            exit 1
        }
    } else {
        Write-LauncherStatus "Winget is available"
        Start-Sleep -Milliseconds 300
    }
    
    # Step 2: Ensure Python is available
    $pythonInfo = Initialize-PythonRuntime
    if (-not $pythonInfo) {
        Write-LauncherStatus "Python installation failed!"
        Start-Sleep -Seconds 5
        $window.Close()
        exit 1
    }
    
    # Step 3: Download and run the editor
    if (Invoke-EditorBootstrap -PythonInfo $pythonInfo) {
        Write-LauncherStatus "Success! Closing launcher..."
        Start-Sleep -Seconds 2
    }
    
} catch {
    Write-LauncherStatus "Critical Error: $($_.Exception.Message)"
    Write-Host "`nFull error details:" -ForegroundColor Red
    Write-Host $_.Exception | Format-List -Force
    Start-Sleep -Seconds 10
}

$window.Close()

try {
    Stop-Transcript | Out-Null
} catch {
    # No transcript was running; nothing to flush.
}
