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
$uninstallPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
foreach ($path in $uninstallPaths) {
    $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*RemotePC*" }
    if ($apps) {
        foreach ($app in $apps) {
            if ($app.UninstallString -match "msiexec") {
                $productCode = $app.UninstallString -replace ".*({[A-F0-9-]+}).*", '$1'
                Start-Process "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                Write-Host "   Removed!" -ForegroundColor Green
            }
        }
    }
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
    try {
        $anydeskPassword | & "$anydeskExe" --set-password
        Write-Host "   Password set: $anydeskPassword" -ForegroundColor Cyan
    } catch {}
}

Write-Host "[4/13] Installing Sumatra PDF..." -ForegroundColor Green
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
    $sumatraUrl = "https://www.sumatrapdfreader.org/dl/rel/3.5.2/SumatraPDF-3.5.2-64-install.exe"
    $sumatraPath = "$env:TEMP\SumatraPDF-setup.exe"
    $sumatraInstalled = $false
    
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        Write-Host "   Download attempt $attempt..." -ForegroundColor Yellow
        
        try {
            # Remove any previous failed download
            if (Test-Path $sumatraPath) {
                Remove-Item $sumatraPath -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
            }
            
            # Download with timeout
            $ProgressPreference = 'SilentlyContinue'
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($sumatraUrl, $sumatraPath)
            $ProgressPreference = 'Continue'
            
            # Verify download succeeded and file size is reasonable
            if (Test-Path $sumatraPath) {
                $fileSize = (Get-Item $sumatraPath).Length / 1MB
                Write-Host "   Downloaded: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Gray
                
                # Sumatra installer should be around 5-10MB
                if ($fileSize -gt 3 -and $fileSize -lt 15) {
                    Write-Host "   Installing..." -ForegroundColor Yellow
                    
                    # Run installer
                    $process = Start-Process -FilePath $sumatraPath -ArgumentList "-s -d `"$env:ProgramFiles\SumatraPDF`"" -Wait -PassThru -NoNewWindow
                    Start-Sleep -Seconds 3
                    
                    # Verify installation
                    $sumatraExe = "$env:ProgramFiles\SumatraPDF\SumatraPDF.exe"
                    if (Test-Path $sumatraExe) {
                        & "$sumatraExe" -register-for-pdf -silent 2>$null
                        Write-Host "   Installed successfully!" -ForegroundColor Green
                        $sumatraInstalled = $true
                        break
                    } else {
                        Write-Host "   Installation failed - retrying..." -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "   File size wrong ($([math]::Round($fileSize, 2)) MB) - corrupted download" -ForegroundColor Yellow
                    Write-Host "   Retrying..." -ForegroundColor Yellow
                }
            } else {
                Write-Host "   Download failed - retrying..." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Cleanup failed attempt
        if (Test-Path $sumatraPath) {
            Remove-Item $sumatraPath -Force -ErrorAction SilentlyContinue
        }
        
        if ($attempt -lt 2) {
            Start-Sleep -Seconds 3
        }
    }
    
    if (-not $sumatraInstalled) {
        Write-Host "   Could not install - skipping Sumatra PDF" -ForegroundColor Red
        Write-Host "   You can install manually later from sumatrapdfreader.org" -ForegroundColor Yellow
    }
    
    # Final cleanup
    if (Test-Path $sumatraPath) {
        Remove-Item $sumatraPath -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "[5/13] Installing FreeOffice..." -ForegroundColor Green
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
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Type DWord
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
Write-Host "RESTART your computer now!" -ForegroundColor Yellow
Write-Host ""
Write-Host "After restart:" -ForegroundColor White
Write-Host "- Open Task Manager > Startup to verify" -ForegroundColor White
Write-Host "- Open Chrome to see your bookmarks" -ForegroundColor White
Write-Host ""
pause
