# Windows Performance Optimization Script
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Low-Spec PC Optimization Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-NOT $isAdmin) {
    Write-Host "ERROR: Please run this script as Administrator!" -ForegroundColor Red
    Write-Host "Right-click the script and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit
}

Write-Host "Select your system's RAM amount:" -ForegroundColor Yellow
Write-Host "1. 4GB RAM" -ForegroundColor White
Write-Host "2. 8GB RAM" -ForegroundColor White  
Write-Host "3. 12GB RAM" -ForegroundColor White
Write-Host "4. 16GB RAM" -ForegroundColor White
Write-Host ""
$ramChoice = Read-Host "Enter your choice (1-4)"

switch ($ramChoice) {
    "1" { $initialSize = 6144; $maximumSize = 8192; $ramAmount = "4GB" }
    "2" { $initialSize = 12288; $maximumSize = 16384; $ramAmount = "8GB" }
    "3" { $initialSize = 18432; $maximumSize = 24576; $ramAmount = "12GB" }
    "4" { $initialSize = 24576; $maximumSize = 32768; $ramAmount = "16GB" }
    default { $initialSize = 6144; $maximumSize = 8192; $ramAmount = "4GB" }
}

Write-Host ""
Write-Host "[1/13] Setting Virtual Memory for $ramAmount system..." -ForegroundColor Green
$computersys = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
$computersys.AutomaticManagedPagefile = $false
$computersys.Put() | Out-Null
$pagefileset = Get-WmiObject -Query "SELECT * FROM Win32_PageFileSetting WHERE Name='C:\\pagefile.sys'"
if ($pagefileset) {
    $pagefileset.InitialSize = $initialSize
    $pagefileset.MaximumSize = $maximumSize
    $pagefileset.Put() | Out-Null
} else {
    Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{name="C:\pagefile.sys"; InitialSize=$initialSize; MaximumSize=$maximumSize} | Out-Null
}
Write-Host "   Done!" -ForegroundColor Gray

Write-Host "[2/13] Removing RemotePC Host..." -ForegroundColor Green
$remotePCFound = $false
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($path in $uninstallPaths) {
    $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { 
        $_.DisplayName -like "*RemotePC*" -and $_.DisplayName -notlike "*RemoteDesktop*"
    }
    
    if ($apps) {
        foreach ($app in $apps) {
            $remotePCFound = $true
            Write-Host "   Found: $($app.DisplayName)" -ForegroundColor Yellow
            
            if ($app.UninstallString) {
                try {
                    if ($app.UninstallString -match "msiexec") {
                        $productCode = $app.UninstallString -replace ".*({[A-F0-9-]+}).*", '$1'
                        Write-Host "   Uninstalling..." -ForegroundColor Yellow
                        Start-Process "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -Wait -NoNewWindow
                        Write-Host "   RemotePC Host removed!" -ForegroundColor Green
                    } else {
                        $uninstallCmd = $app.UninstallString -replace '"', ''
                        Write-Host "   Uninstalling..." -ForegroundColor Yellow
                        Start-Process $uninstallCmd -ArgumentList "/S" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                        Write-Host "   RemotePC Host removed!" -ForegroundColor Green
                    }
                } catch {
                    Write-Host "   Error removing: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
}

if (-not $remotePCFound) {
    Write-Host "   Not installed - skipping" -ForegroundColor Gray
}

Write-Host "[3/13] Installing AnyDesk..." -ForegroundColor Green
$anydeskPassword = "womdigital.cs"
$anydeskExe = ""
$anydeskPaths = @("$env:ProgramFiles(x86)\AnyDesk\AnyDesk.exe", "$env:ProgramFiles\AnyDesk\AnyDesk.exe")
foreach ($path in $anydeskPaths) {
    if (Test-Path $path) {
        $anydeskExe = $path
        Write-Host "   Already installed" -ForegroundColor Gray
        break
    }
}
if (-not $anydeskExe) {
    try {
        $anydeskUrl = "https://download.anydesk.com/AnyDesk.exe"
        $anydeskPath = "$env:TEMP\AnyDesk.exe"
        Write-Host "   Downloading AnyDesk (~5MB)..." -ForegroundColor Yellow
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $anydeskUrl -OutFile $anydeskPath
        $ProgressPreference = 'Continue'
        if (Test-Path $anydeskPath) {
            $fileSize = (Get-Item $anydeskPath).Length / 1MB
            Write-Host "   Downloaded! ($([math]::Round($fileSize, 1)) MB)" -ForegroundColor Gray
            Write-Host "   Installing AnyDesk..." -ForegroundColor Yellow
            Start-Process -FilePath $anydeskPath -ArgumentList "--install `"$env:ProgramFiles(x86)\AnyDesk`" --start-with-win --silent" -Wait -NoNewWindow
            Start-Sleep -Seconds 3
            $anydeskExe = "$env:ProgramFiles(x86)\AnyDesk\AnyDesk.exe"
            Remove-Item $anydeskPath -Force -ErrorAction SilentlyContinue
            Write-Host "   AnyDesk installed successfully!" -ForegroundColor Green
        }
    } catch {
        Write-Host "   Installation failed" -ForegroundColor Yellow
    }
}
if ($anydeskExe -and (Test-Path $anydeskExe)) {
    Write-Host "   Configuring AnyDesk..." -ForegroundColor Yellow
    
    # Set password
    try {
        $anydeskPassword | & "$anydeskExe" --set-password
        Write-Host "   Password set: $anydeskPassword" -ForegroundColor Cyan
    } catch {}
    
    # Get AnyDesk ID
    Write-Host "   Retrieving AnyDesk ID..." -ForegroundColor Gray
    $anydeskID = ""
    try {
        $anydeskID = & "$anydeskExe" --get-id 2>$null | Out-String
        $anydeskID = $anydeskID.Trim()
    } catch {}
    
    # Try config files if command didn't work
    if (!$anydeskID -or $anydeskID -eq "") {
        Start-Sleep -Seconds 2
        $configPaths = @(
            "$env:APPDATA\AnyDesk\service.conf",
            "$env:ProgramData\AnyDesk\system.conf"
        )
        foreach ($configPath in $configPaths) {
            if (Test-Path $configPath) {
                $idContent = Get-Content $configPath | Select-String "ad.anynet.id"
                if ($idContent) {
                    $anydeskID = ($idContent -replace '.*=', '').Trim()
                    break
                }
            }
        }
    }
    
    if ($anydeskID -and $anydeskID -ne "") {
        Write-Host "   AnyDesk ID: $anydeskID" -ForegroundColor Cyan
        $global:anydeskID = $anydeskID
        $global:anydeskPassword = $anydeskPassword
    } else {
        $anydeskID = "Open AnyDesk to see ID"
        $global:anydeskID = $anydeskID
        $global:anydeskPassword = $anydeskPassword
        Write-Host "   Could not capture AnyDesk ID automatically" -ForegroundColor Yellow
    }
}

Write-Host "[4/13] Installing Sumatra PDF..." -ForegroundColor Green
Write-Host "   SKIPPED - Install manually if needed from www.sumatrapdfreader.org" -ForegroundColor Yellow

<#
$sumatraFound = $false
$sumatraPaths = @("$env:ProgramFiles\SumatraPDF\SumatraPDF.exe", "$env:ProgramFiles(x86)\SumatraPDF\SumatraPDF.exe")
foreach ($path in $sumatraPaths) {
    if (Test-Path $path) {
        $sumatraFound = $true
        Write-Host "   Already installed" -ForegroundColor Gray
        break
    }
}
if (-not $sumatraFound) {
    # Add Windows Defender exclusion for TEMP folder temporarily
    Write-Host "   Adding temporary antivirus exclusion..." -ForegroundColor Gray
    Add-MpPreference -ExclusionPath "$env:TEMP" -ErrorAction SilentlyContinue
    
    $sumatraUrl = "https://www.sumatrapdfreader.org/dl/rel/3.5.2/SumatraPDF-3.5.2-64-install.exe"
    $sumatraPath = "$env:TEMP\SumatraPDF-setup-$(Get-Random).exe"
    $sumatraInstalled = $false
    
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        Write-Host "   Download attempt $attempt..." -ForegroundColor Yellow
        
        try {
            # Remove any previous file
            if (Test-Path $sumatraPath) {
                Remove-Item $sumatraPath -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
            }
            
            # Download with longer timeout
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "Mozilla/5.0")
            $webClient.DownloadFile($sumatraUrl, $sumatraPath)
            
            # Verify file exists and has content
            if (Test-Path $sumatraPath) {
                $fileSize = (Get-Item $sumatraPath).Length / 1MB
                Write-Host "   Downloaded: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Gray
                
                if ($fileSize -gt 3 -and $fileSize -lt 15) {
                    Write-Host "   Installing Sumatra PDF..." -ForegroundColor Yellow
                    
                    # Run installer with error capture
                    $process = Start-Process -FilePath $sumatraPath -ArgumentList "-s -d `"$env:ProgramFiles\SumatraPDF`"" -Wait -PassThru -NoNewWindow
                    
                    # Wait for install to complete
                    Start-Sleep -Seconds 4
                    
                    # Check if installed
                    $sumatraExe = "$env:ProgramFiles\SumatraPDF\SumatraPDF.exe"
                    if (Test-Path $sumatraExe) {
                        & "$sumatraExe" -register-for-pdf -silent 2>$null
                        Write-Host "   Sumatra PDF installed successfully!" -ForegroundColor Green
                        $sumatraInstalled = $true
                        break
                    } elseif ($process.ExitCode -ne 0) {
                        Write-Host "   Installer error code: $($process.ExitCode)" -ForegroundColor Yellow
                    } else {
                        Write-Host "   Installation completed but exe not found" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "   Invalid file size - download may be corrupted" -ForegroundColor Yellow
                }
            } else {
                Write-Host "   Download failed - file not found" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Cleanup
        if (Test-Path $sumatraPath) {
            Remove-Item $sumatraPath -Force -ErrorAction SilentlyContinue
        }
        
        if ($attempt -lt 2 -and -not $sumatraInstalled) {
            Write-Host "   Waiting 3 seconds before retry..." -ForegroundColor Gray
            Start-Sleep -Seconds 3
        }
    }
    
    # Remove temporary exclusion
    Remove-MpPreference -ExclusionPath "$env:TEMP" -ErrorAction SilentlyContinue
    
    if (-not $sumatraInstalled) {
        Write-Host "   Skipping Sumatra PDF - install manually if needed" -ForegroundColor Red
        Write-Host "   Download from: www.sumatrapdfreader.org" -ForegroundColor Yellow
    }
}
#>

Write-Host "[5/13] Installing FreeOffice..." -ForegroundColor Green
Write-Host "   SKIPPED - Install manually if needed from www.softmaker.com" -ForegroundColor Yellow

<#
Write-Host ""
Write-Host "   FreeOffice is a 150MB download and may be slow." -ForegroundColor Yellow
Write-Host "   Do you want to install it now?" -ForegroundColor Yellow
Write-Host ""
Write-Host "   Type Y and press Enter to install" -ForegroundColor White
Write-Host "   Type N and press Enter to skip" -ForegroundColor White
Write-Host ""
$Host.UI.RawUI.FlushInputBuffer()
$installOffice = $Host.UI.ReadLine()

if ($installOffice -eq 'Y' -or $installOffice -eq 'y') {
    $officeFound = $false
    $officePaths = @("$env:ProgramFiles\SoftMaker Office", "$env:ProgramFiles(x86)\SoftMaker Office")
    foreach ($path in $officePaths) {
        if (Test-Path $path) {
            $officeFound = $true
            Write-Host "   Already installed" -ForegroundColor Gray
            break
        }
    }
    if (-not $officeFound) {
        try {
            $officeUrl = "https://www.softmaker.net/down/freeoffice2024.msi"
            $officePath = "$env:TEMP\FreeOffice.msi"
            Write-Host "   Downloading FreeOffice (150MB, this may take 2-5 minutes)..." -ForegroundColor Yellow
            Write-Host "   If download is too slow, press Ctrl+C to skip and continue" -ForegroundColor Gray
            
            # Setup WebClient with progress events
            $webClient = New-Object System.Net.WebClient
            
            # Progress bar event
            Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -SourceIdentifier WebClient.DownloadProgressChanged -Action {
                $percent = $EventArgs.ProgressPercentage
                $receivedMB = [math]::Round($EventArgs.BytesReceived / 1MB, 1)
                $totalMB = [math]::Round($EventArgs.TotalBytesToReceive / 1MB, 1)
                Write-Progress -Activity "Downloading FreeOffice" -Status "$receivedMB MB / $totalMB MB" -PercentComplete $percent
            } | Out-Null
            
            # Completion event
            Register-ObjectEvent -InputObject $webClient -EventName DownloadFileCompleted -SourceIdentifier WebClient.DownloadFileCompleted -Action {
                Write-Progress -Activity "Downloading FreeOffice" -Completed
            } | Out-Null
            
            # Start download
            $webClient.DownloadFileAsync([System.Uri]::new($officeUrl), $officePath)
            
            # Wait for download to complete
            while ($webClient.IsBusy) {
                Start-Sleep -Milliseconds 100
            }
            
            # Cleanup events
            Unregister-Event -SourceIdentifier WebClient.DownloadProgressChanged -ErrorAction SilentlyContinue
            Unregister-Event -SourceIdentifier WebClient.DownloadFileCompleted -ErrorAction SilentlyContinue
            Remove-Job -Name WebClient.* -ErrorAction SilentlyContinue
            
            if (Test-Path $officePath) {
                $fileSize = (Get-Item $officePath).Length / 1MB
                Write-Host "   Download complete! ($([math]::Round($fileSize, 1)) MB)" -ForegroundColor Gray
                Write-Host "   Installing FreeOffice (this will take 1-2 minutes)..." -ForegroundColor Yellow
                Start-Process "msiexec.exe" -ArgumentList "/i `"$officePath`" /qn /norestart" -Wait -NoNewWindow
                Start-Sleep -Seconds 3
                
                Write-Host "   Setting FreeOffice as default for office files..." -ForegroundColor Yellow
                
                # TextMaker (Word alternative)
                $textMakerPath = "${env:ProgramFiles}\SoftMaker Office\TextMaker.exe"
                if (!(Test-Path $textMakerPath)) {
                    $textMakerPath = "${env:ProgramFiles(x86)}\SoftMaker Office\TextMaker.exe"
                }
                
                # PlanMaker (Excel alternative)
                $planMakerPath = "${env:ProgramFiles}\SoftMaker Office\PlanMaker.exe"
                if (!(Test-Path $planMakerPath)) {
                    $planMakerPath = "${env:ProgramFiles(x86)}\SoftMaker Office\PlanMaker.exe"
                }
                
                # Set file associations for documents
                $docExtensions = @(".doc", ".docx", ".rtf", ".odt", ".txt")
                foreach ($ext in $docExtensions) {
                    if (Test-Path $textMakerPath) {
                        cmd /c "assoc $ext=FreeOffice.TextMaker" 2>$null
                        cmd /c "ftype FreeOffice.TextMaker=`"$textMakerPath`" `"%1`"" 2>$null
                    }
                }
                
                # Set file associations for spreadsheets
                $spreadsheetExtensions = @(".xls", ".xlsx", ".csv", ".ods")
                foreach ($ext in $spreadsheetExtensions) {
                    if (Test-Path $planMakerPath) {
                        cmd /c "assoc $ext=FreeOffice.PlanMaker" 2>$null
                        cmd /c "ftype FreeOffice.PlanMaker=`"$planMakerPath`" `"%1`"" 2>$null
                    }
                }
                
                Write-Host "   FreeOffice installed successfully!" -ForegroundColor Green
                Remove-Item $officePath -Force -ErrorAction SilentlyContinue
            } else {
                Write-Host "   Error: Download failed" -ForegroundColor Red
            }
        } catch {
            Write-Host "   Error installing FreeOffice: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "   Continuing with other steps..." -ForegroundColor Gray
            Unregister-Event -SourceIdentifier WebClient.* -ErrorAction SilentlyContinue
            Remove-Job -Name WebClient.* -ErrorAction SilentlyContinue
        }
    }
} else {
    Write-Host "   Skipped FreeOffice installation" -ForegroundColor Gray
}
#>

Write-Host "[6/13] Disabling visual effects..." -ForegroundColor Green
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -Type DWord
Write-Host "   Done!" -ForegroundColor Gray

Write-Host "[7/13] Disabling Windows Search..." -ForegroundColor Green
Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "   Done!" -ForegroundColor Gray

Write-Host "[8/13] Disabling transparency..." -ForegroundColor Green
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Type DWord
Write-Host "   Done!" -ForegroundColor Gray

Write-Host "[9/13] Enabling Storage Sense..." -ForegroundColor Green
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Value 1 -Type DWord
Write-Host "   Done!" -ForegroundColor Gray

Write-Host "[10/13] Configuring startup programs..." -ForegroundColor Green
$keepNames = @("RemoteDesktop", "AnyDesk", "RemoteDesktopUIU")
$keepPaths = @("RemoteDesktop Host", "AnyDesk")
$regPaths = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")
$removed = 0

foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        $items = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        if ($items) {
            $props = $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
            foreach ($prop in $props) {
                $name = $prop.Name
                $value = $prop.Value
                $keep = $false
                
                foreach ($keepName in $keepNames) {
                    if ($name -like "*$keepName*") {
                        $keep = $true
                        Write-Host "   KEEP: $name" -ForegroundColor Green
                        break
                    }
                }
                
                if (-not $keep) {
                    foreach ($keepPath in $keepPaths) {
                        if ($value -like "*$keepPath*") {
                            $keep = $true
                            Write-Host "   KEEP: $name" -ForegroundColor Green
                            break
                        }
                    }
                }
                
                if (-not $keep) {
                    Remove-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue
                    Write-Host "   REMOVE: $name" -ForegroundColor Red
                    $removed++
                }
            }
        }
    }
}

$folders = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
foreach ($folder in $folders) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -Filter "*.lnk" | ForEach-Object {
            $name = $_.Name
            $keep = $false
            foreach ($keepName in $keepNames) {
                if ($name -like "*$keepName*") {
                    $keep = $true
                    break
                }
            }
            if (-not $keep) {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                $removed++
            }
        }
    }
}
Write-Host "   Removed $removed items" -ForegroundColor Gray

Write-Host "[11/13] Disabling services..." -ForegroundColor Green
$services = @("SysMain", "DiagTrack", "dmwappushservice")
foreach ($svc in $services) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
}
Write-Host "   Done!" -ForegroundColor Gray

Write-Host "[12/13] Optimizing taskbar..." -ForegroundColor Green
Write-Host "   Hiding search box, task view, and widgets..." -ForegroundColor Gray
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Type DWord

# Disable Widgets (Windows 11)
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Type DWord

Write-Host "   Unpinning all taskbar apps..." -ForegroundColor Gray
$pinnedAppsPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
if (Test-Path $pinnedAppsPath) {
    Get-ChildItem -Path $pinnedAppsPath -Filter "*.lnk" | ForEach-Object {
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    }
}

$taskbarPinPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
if (Test-Path $taskbarPinPath) {
    Remove-ItemProperty -Path $taskbarPinPath -Name "Favorites" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $taskbarPinPath -Name "FavoritesResolve" -ErrorAction SilentlyContinue
}

Start-Sleep -Seconds 2

Write-Host "   Pinning essential apps..." -ForegroundColor Gray

# Create VBScript for pinning
$vbsScript = @"
Set objShell = CreateObject("Shell.Application")
Set objFolder = objShell.Namespace(WScript.Arguments.Item(0))
Set objFolderItem = objFolder.ParseName(WScript.Arguments.Item(1))
Set colVerbs = objFolderItem.Verbs
For Each objVerb in colVerbs
    If Replace(objVerb.name, "&", "") = "Pin to taskbar" Then
        objVerb.DoIt
    End If
Next
"@
$vbsPath = "$env:TEMP\pin-taskbar.vbs"
$vbsScript | Out-File -FilePath $vbsPath -Encoding ASCII

function Pin-ToTaskbar {
    param([string]$exePath)
    if (Test-Path $exePath) {
        $folder = Split-Path $exePath
        $file = Split-Path $exePath -Leaf
        Start-Process "wscript.exe" -ArgumentList "`"$vbsPath`" `"$folder`" `"$file`"" -Wait -WindowStyle Hidden
        return $true
    }
    return $false
}

# Pin Chrome
$chromePaths = @(
    "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
)
foreach ($path in $chromePaths) {
    if (Test-Path $path) {
        Pin-ToTaskbar $path | Out-Null
        Write-Host "      + Chrome pinned" -ForegroundColor Green
        break
    }
}

# Pin File Explorer
Pin-ToTaskbar "$env:windir\explorer.exe" | Out-Null
Write-Host "      + File Explorer pinned" -ForegroundColor Green

# Pin Calculator
$calcPath = "$env:windir\System32\calc.exe"
if (Test-Path $calcPath) {
    Pin-ToTaskbar $calcPath | Out-Null
    Write-Host "      + Calculator pinned" -ForegroundColor Green
}

# Pin AnyDesk
$anydeskPaths = @(
    "${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe",
    "${env:ProgramFiles}\AnyDesk\AnyDesk.exe",
    "$env:LOCALAPPDATA\AnyDesk\AnyDesk.exe"
)
foreach ($path in $anydeskPaths) {
    if (Test-Path $path) {
        Pin-ToTaskbar $path | Out-Null
        Write-Host "      + AnyDesk pinned" -ForegroundColor Green
        break
    }
}

Remove-Item $vbsPath -Force -ErrorAction SilentlyContinue

Write-Host "   Restarting Explorer..." -ForegroundColor Gray
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Write-Host "   Done!" -ForegroundColor Gray

Write-Host "[13/13] Importing Chrome bookmarks..." -ForegroundColor Green
$bookmarksUrl = "https://raw.githubusercontent.com/willfreitasm/chrome-bookmarks/refs/heads/main/bookmarks.html"
$chromeBookmarksPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"
$tempHtmlPath = "$env:TEMP\chrome-bookmarks-import.html"

if (Test-Path "$env:LOCALAPPDATA\Google\Chrome") {
    Write-Host "   Closing Chrome..." -ForegroundColor Yellow
    Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    
    Write-Host "   Downloading bookmarks..." -ForegroundColor Yellow
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $bookmarksUrl -OutFile $tempHtmlPath
        $ProgressPreference = 'Continue'
        
        if (Test-Path $tempHtmlPath) {
            Write-Host "   Clearing existing bookmarks..." -ForegroundColor Yellow
            if (Test-Path $chromeBookmarksPath) {
                $bookmarksJson = Get-Content $chromeBookmarksPath -Raw | ConvertFrom-Json
                $bookmarksJson.roots.bookmark_bar.children = @()
                $bookmarksJson.roots.other.children = @()
                if ($bookmarksJson.roots.synced) {
                    $bookmarksJson.roots.synced.children = @()
                }
                $bookmarksJson | ConvertTo-Json -Depth 100 | Set-Content $chromeBookmarksPath -Encoding UTF8
            }
            
            Write-Host "   Importing bookmarks..." -ForegroundColor Yellow
            $htmlContent = Get-Content $tempHtmlPath -Raw
            $bookmarkMatches = [regex]::Matches($htmlContent, '<A HREF="([^"]+)"[^>]*>([^<]+)</A>')
            
            if ($bookmarkMatches.Count -gt 0) {
                $bookmarksJson = Get-Content $chromeBookmarksPath -Raw | ConvertFrom-Json
                $newBookmarks = @()
                $bookmarkId = [int]$bookmarksJson.roots.bookmark_bar.id + 1
                
                foreach ($match in $bookmarkMatches) {
                    $url = $match.Groups[1].Value
                    $name = $match.Groups[2].Value
                    $newBookmark = @{
                        date_added = [string]([DateTimeOffset]::Now.ToUnixTimeSeconds()) + "000000"
                        date_last_used = "0"
                        guid = [guid]::NewGuid().ToString()
                        id = [string]$bookmarkId
                        name = $name
                        type = "url"
                        url = $url
                    }
                    $newBookmarks += $newBookmark
                    $bookmarkId++
                }
                
                $bookmarksJson.roots.bookmark_bar.children = $newBookmarks
                $bookmarksJson | ConvertTo-Json -Depth 100 | Set-Content $chromeBookmarksPath -Encoding UTF8
                Write-Host "   Imported $($bookmarkMatches.Count) bookmarks!" -ForegroundColor Green
            }
            
            Write-Host "   Enabling bookmarks bar..." -ForegroundColor Yellow
            $chromePrefsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
            if (Test-Path $chromePrefsPath) {
                $prefs = Get-Content $chromePrefsPath -Raw | ConvertFrom-Json
                if (-not $prefs.bookmark_bar) {
                    $prefs | Add-Member -NotePropertyName "bookmark_bar" -NotePropertyValue @{} -Force
                }
                $prefs.bookmark_bar | Add-Member -NotePropertyName "show_on_all_tabs" -NotePropertyValue $true -Force
                $prefs | ConvertTo-Json -Depth 100 -Compress | Set-Content $chromePrefsPath -Encoding UTF8
                Write-Host "   Bookmarks bar enabled!" -ForegroundColor Green
            }
            
            Remove-Item $tempHtmlPath -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "   Chrome not found - skipping" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Optimization Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "WHAT CHANGED:" -ForegroundColor Yellow
Write-Host "[+] Virtual memory optimized for $ramAmount" -ForegroundColor White
Write-Host "[+] RemotePC Host removed (if installed)" -ForegroundColor White
Write-Host "[+] AnyDesk installed and configured" -ForegroundColor White
Write-Host "[+] Sumatra PDF - SKIPPED (code available, commented out)" -ForegroundColor Gray
Write-Host "[+] SoftMaker FreeOffice - SKIPPED (code available, commented out)" -ForegroundColor Gray
Write-Host "[+] Visual effects disabled" -ForegroundColor White
Write-Host "[+] Windows Search disabled" -ForegroundColor White
Write-Host "[+] Transparency disabled" -ForegroundColor White
Write-Host "[+] Storage Sense enabled" -ForegroundColor White
Write-Host "[+] Startup: Only RemoteDesktop Host & AnyDesk enabled" -ForegroundColor White
Write-Host "[+] Unnecessary services disabled" -ForegroundColor White
Write-Host "[+] Taskbar optimized (widgets disabled) and cleaned" -ForegroundColor White
Write-Host "[+] Chrome bookmarks imported from GitHub" -ForegroundColor White
Write-Host "[+] Chrome bookmarks bar enabled" -ForegroundColor White
Write-Host ""
if ($global:anydeskID) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "ANYDESK REMOTE ACCESS INFO" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "AnyDesk ID: $($global:anydeskID)" -ForegroundColor Green
    Write-Host "Password:   $($global:anydeskPassword)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Use these credentials to connect remotely" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}
Write-Host "PROTECTED STARTUP APPS:" -ForegroundColor Yellow
Write-Host "  - RemoteDesktop Host (C:\Program Files (x86)\RemoteDesktop Host)" -ForegroundColor Green
Write-Host "  - AnyDesk (C:\Program Files(x86)\AnyDesk)" -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT NEXT STEPS:" -ForegroundColor Yellow
Write-Host "1. RESTART your computer for all changes to take effect" -ForegroundColor White
Write-Host "2. After restart, verify Task Manager > Startup tab" -ForegroundColor White
Write-Host "3. Open Chrome to see your imported bookmarks" -ForegroundColor White
Write-Host "4. Check taskbar - should only show Chrome, File Explorer, Calculator, AnyDesk" -ForegroundColor White
Write-Host "5. Widgets should be disabled from taskbar (Windows 11)" -ForegroundColor White
Write-Host ""
Write-Host "NOTE: To re-enable Sumatra PDF or FreeOffice installations," -ForegroundColor Cyan
Write-Host "uncomment the code blocks in steps 4 and 5 (remove <# and #>)" -ForegroundColor Cyan
Write-Host ""
pause
