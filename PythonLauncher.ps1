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

# Helper function to download files
function Download-File {
    param(
        [string]$Uri,
        [string]$OutFile
    )
    
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# ==========================================================
# 2. WINGET INSTALLATION LOGIC
# ==========================================================
function Install-Winget {
    $arch = if ([System.Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
    Log-Status "System: Windows $arch"
    Start-Sleep -Milliseconds 300
    
    # Create working directory
    $workDir = "$env:TEMP\WingetInstall"
    if (-not (Test-Path $workDir)) {
        New-Item -Path $workDir -ItemType Directory -Force | Out-Null
    }
    
    # Clean existing broken installations
    Log-Status "Checking for conflicting packages..."
    try {
        $existingWinget = Get-AppxPackage -Name "Microsoft.DesktopAppInstaller" -AllUsers -ErrorAction SilentlyContinue
        if ($existingWinget) {
            Log-Status "Removing existing Winget installation..."
            Remove-AppxPackage -Package $existingWinget.PackageFullName -AllUsers -ErrorAction SilentlyContinue
        }
    } catch { }
    
    # Download required packages
    Log-Status "Downloading installation packages..."
    
    $packages = @{
        VCLibs_x64 = @{
            Url = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
            Path = "$workDir\VCLibs_x64.appx"
            Name = "VCLibs x64"
        }
        VCLibs_x86 = @{
            Url = "https://aka.ms/Microsoft.VCLibs.x86.14.00.Desktop.appx"
            Path = "$workDir\VCLibs_x86.appx"
            Name = "VCLibs x86"
        }
        UIXaml = @{
            Url = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx"
            Path = "$workDir\UIXaml.appx"
            Name = "UI.Xaml 2.8"
        }
        Winget = @{
            Url = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
            Path = "$workDir\Winget.msixbundle"
            Name = "Winget"
        }
    }
    
    $downloadSuccess = $true
    foreach ($pkg in $packages.GetEnumerator()) {
        if (-not (Test-Path $pkg.Value.Path)) {
            Log-Status "Downloading $($pkg.Value.Name)..."
            
            if (-not (Download-File -Uri $pkg.Value.Url -OutFile $pkg.Value.Path)) {
                Log-Status "Failed to download $($pkg.Value.Name)"
                $downloadSuccess = $false
            }
            Start-Sleep -Milliseconds 200
        }
    }
    
    if (-not $downloadSuccess) {
        throw "Failed to download required packages"
    }
    
    # Install dependencies
    Log-Status "Installing dependencies..."
    
    foreach ($vclib in @("VCLibs_x64", "VCLibs_x86")) {
        if (Test-Path $packages[$vclib].Path) {
            Log-Status "Installing $($packages[$vclib].Name)..."
            try {
                Add-AppxPackage -Path $packages[$vclib].Path -ErrorAction Stop
            } catch {
                try {
                    Add-AppxPackage -Path $packages[$vclib].Path -ForceApplicationShutdown -ForceUpdateFromAnyVersion -ErrorAction Stop
                } catch { }
            }
            Start-Sleep -Milliseconds 300
        }
    }
    
    # Install UI.Xaml
    if (Test-Path $packages.UIXaml.Path) {
        Log-Status "Installing UI.Xaml..."
        try {
            Add-AppxPackage -Path $packages.UIXaml.Path -ErrorAction Stop
        } catch { }
        Start-Sleep -Milliseconds 300
    }
    
    # Verify VCLibs
    $vcLibsInstalled = Get-AppxPackage -Name "Microsoft.VCLibs.140.00*" -AllUsers
    
    if (-not $vcLibsInstalled) {
        Log-Status "Trying DISM installation method..."
        foreach ($vclib in @("VCLibs_x64", "VCLibs_x86")) {
            $pkgPath = $packages[$vclib].Path
            if (Test-Path $pkgPath) {
                try {
                    dism /Online /Add-ProvisionedAppxPackage /PackagePath:"$pkgPath" /SkipLicense 2>&1 | Out-Null
                } catch { }
            }
        }
        Start-Sleep -Seconds 2
    }
    
    # Install Winget
    if (Test-Path $packages.Winget.Path) {
        Log-Status "Installing Winget..."
        Start-Sleep -Milliseconds 500
        
        $dependencies = @()
        if (Test-Path $packages.VCLibs_x64.Path) { $dependencies += $packages.VCLibs_x64.Path }
        if (Test-Path $packages.VCLibs_x86.Path) { $dependencies += $packages.VCLibs_x86.Path }
        if (Test-Path $packages.UIXaml.Path) { $dependencies += $packages.UIXaml.Path }
        
        try {
            if ($dependencies.Count -gt 0) {
                Add-AppxPackage -Path $packages.Winget.Path -DependencyPath $dependencies -ForceApplicationShutdown -ErrorAction Stop
            } else {
                Add-AppxPackage -Path $packages.Winget.Path -ForceApplicationShutdown -ErrorAction Stop
            }
            
            Log-Status "Winget installed successfully!"
            Start-Sleep -Seconds 2
            
        } catch {
            Log-Status "ERROR: Failed to install Winget"
            throw "Winget installation failed: $($_.Exception.Message)"
        }
    }
    
    # Cleanup
    Log-Status "Cleaning up temp files..."
    Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
    
    return $true
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
