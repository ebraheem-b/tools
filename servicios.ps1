$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║           ADMINISTRATOR PRIVILEGES REQUIRED       ║" -ForegroundColor Red
    Write-Host "║     Please run this script as Administrator!      ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Red
    exit
}

Clear-Host
Write-Host "made with love by lily <3" -ForegroundColor Cyan
Write-Host ""

# 1. SYSTEM UPTIME & BOOT
try {
    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptime = (Get-Date) - $bootTime
    Write-Host "SYSTEM BOOT TIME" -ForegroundColor Cyan
    Write-Host ("  Last Boot: {0}" -f $bootTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
    Write-Host ("  Uptime: {0} days, {1:D2}:{2:D2}:{3:D2}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) -ForegroundColor White
} catch {
    Write-Host "Unable to retrieve boot time information" -ForegroundColor Red
}

# 2. CONNECTED DRIVES
$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -ne 5 }
if ($drives) {
    Write-Host "`nCONNECTED DRIVES" -ForegroundColor Cyan
    foreach ($drive in $drives) {
        Write-Host ("  {0}: {1}" -f $drive.DeviceID, $drive.FileSystem) -ForegroundColor Green
    }
}

# 3. KERNEL BOOT INTEGRITY (TESTSIGNING / BYOVD)
Write-Host "`nKERNEL INTEGRITY" -ForegroundColor Cyan
try {
    $bcd = bcdedit /enum "{current}" 2>$null
    $testSigning = ($bcd | Select-String "testsigning\s+Yes") -ne $null
    $noIntegrity = ($bcd | Select-String "nointegritychecks\s+Yes") -ne $null
    
    if ($testSigning) {
        Write-Host "  TestSigning: " -NoNewline -ForegroundColor White
        Write-Host "Enabled (UNSAFE / DRIVER BYPASS)" -ForegroundColor Red
    } else {
        Write-Host "  TestSigning: " -NoNewline -ForegroundColor White
        Write-Host "Disabled" -ForegroundColor Green
    }

    if ($noIntegrity) {
        Write-Host "  Integrity Checks: " -NoNewline -ForegroundColor White
        Write-Host "Disabled (SUSPICIOUS)" -ForegroundColor Red
    } else {
        Write-Host "  Integrity Checks: " -NoNewline -ForegroundColor White
        Write-Host "Enforced" -ForegroundColor Green
    }
} catch {
    Write-Host "  BCD Integrity: Error reading configuration" -ForegroundColor Yellow
}

# 4. SERVICE STATUS
Write-Host "`nSERVICE STATUS" -ForegroundColor Cyan
$services = @(
    @{Name = "SysMain"; DisplayName = "SysMain"},
    @{Name = "PcaSvc"; DisplayName = "Program Compatibility Assistant Service"},
    @{Name = "DPS"; DisplayName = "Diagnostic Policy Service"},
    @{Name = "EventLog"; DisplayName = "Windows Event Log"},
    @{Name = "Schedule"; DisplayName = "Task Scheduler"},
    @{Name = "Bam"; DisplayName = "Background Activity Moderator"},
    @{Name = "Dusmsvc"; DisplayName = "Data Usage"},
    @{Name = "Appinfo"; DisplayName = "Application Information"},
    @{Name = "CDPSvc"; DisplayName = "Connected Devices Platform Service"},
    @{Name = "DcomLaunch"; DisplayName = "DCOM Server Process Launcher"},
    @{Name = "PlugPlay"; DisplayName = "Plug and Play"},
    @{Name = "wsearch"; DisplayName = "Windows Search"},
    @{Name = "Dnscache"; DisplayName = "DNS Client Cache"}
)

foreach ($svc in $services) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        $displayName = $service.DisplayName
        if ($displayName.Length -gt 40) { $displayName = $displayName.Substring(0, 37) + "..." }
        
        if ($service.Status -eq "Running") {
            Write-Host ("  {0,-12} {1,-40}" -f $svc.Name, $displayName) -ForegroundColor Green -NoNewline
            if ($svc.Name -eq "Bam") {
                Write-Host " | Enabled" -ForegroundColor Yellow
            } else {
                try {
                    $process = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" | Select-Object ProcessId
                    if ($process.ProcessId -gt 0) {
                        $proc = Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue
                        if ($proc) {
                            Write-Host (" | {0}" -f $proc.StartTime.ToString("HH:mm:ss")) -ForegroundColor Yellow
                        } else { Write-Host " | N/A" -ForegroundColor Yellow }
                    } else { Write-Host " | N/A" -ForegroundColor Yellow }
                } catch { Write-Host " | N/A" -ForegroundColor Yellow }
            }
        } else {
            Write-Host ("  {0,-12} {1,-40} {2}" -f $svc.Name, $displayName, $service.Status) -ForegroundColor Red
        }
    } else {
        Write-Host ("  {0,-12} {1,-40} {2}" -f $svc.Name, "Not Found", "Stopped") -ForegroundColor Yellow
    }
}

# 5. REGISTRY POLICIES
Write-Host "`nREGISTRY" -ForegroundColor Cyan
$settings = @(
    @{ Name = "CMD"; Path = "HKCU:\Software\Policies\Microsoft\Windows\System"; Key = "DisableCMD"; Warning = "Disabled"; Safe = "Available" },
    @{ Name = "PowerShell Logging"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Key = "EnableScriptBlockLogging"; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Activities Cache"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Key = "EnableActivityFeed"; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Prefetch Enabled"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Key = "EnablePrefetcher"; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "UAC Status"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Key = "EnableLUA"; Warning = "Disabled"; Safe = "Enabled" }
)

foreach ($s in $settings) {
    $status = Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue
    Write-Host "  " -NoNewline
    if ($status -and $status.$($s.Key) -eq 0) {
        Write-Host "$($s.Name): " -NoNewline -ForegroundColor White
        Write-Host "$($s.Warning)" -ForegroundColor Red
    } else {
        Write-Host "$($s.Name): " -NoNewline -ForegroundColor White
        Write-Host "$($s.Safe)" -ForegroundColor Green
    }
}

# 6. EVENT LOG TRIAGE
function Check-EventLog {
    param ($logName, $eventID, $message)
    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$eventID]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        Write-Host "  $message at: " -NoNewline -ForegroundColor White
        Write-Host $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Yellow
    } else {
        Write-Host "  $message - No records found" -ForegroundColor Green
    }
}

function Check-RecentEventLog {
    param ($logName, $eventIDs, $message)
    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$($eventIDs -join ' or EventID=')]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        Write-Host "  $message (ID: $($event.Id)) at: " -NoNewline -ForegroundColor White
        Write-Host $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Yellow
    } else {
        Write-Host "  $message - No records found" -ForegroundColor Green
    }
}

Write-Host "`nEVENT LOGS" -ForegroundColor Cyan
Check-EventLog "Application" 3079 "USN Journal cleared"
Check-RecentEventLog "System" @(104, 1102) "Event Logs cleared"
Check-EventLog "System" 1074 "Last PC Shutdown"
Check-EventLog "System" 41 "Kernel-Power Abrupt Shutdown"
Check-EventLog "System" 1001 "BSOD / BugCheck Occurred"
Check-EventLog "Security" 4616 "System time changed (Timestomping)"
Check-EventLog "System" 6005 "Event Log Service started"
Check-EventLog "Microsoft-Windows-Windows Defender/Operational" 1116 "Defender Malware Triggered"
Check-EventLog "Microsoft-Windows-Windows Defender/Operational" 5001 "Defender Real-Time Protection Disabled"
Check-EventLog "Microsoft-Windows-Windows Defender/Operational" 5007 "Defender Exclusion Added"

# 7. DNS CACHE SCAN (CHEAT DOMAINS & AUTH APIS)
Write-Host "`nDNS CACHE" -ForegroundColor Cyan
$cheatPattern = 'keyauth|redengine|eauth|skript|eulen|asgard|monstermenu|tzproject|hxcheats|shey\.tech|cobraloader'
try {
    $dnsMatches = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match $cheatPattern }
    if ($dnsMatches) {
        Write-Host "  SUSPICIOUS DNS ENTRIES FOUND:" -ForegroundColor Red
        foreach ($d in $dnsMatches) {
            Write-Host ("    -> {0} : {1}" -f $d.Entry, $d.Data) -ForegroundColor Yellow
        }
    } else {
        Write-Host "  DNS Cache: Clean (No cheat domains found)" -ForegroundColor Green
    }
} catch {
    Write-Host "  DNS Cache: Unable to retrieve entries" -ForegroundColor Yellow
}

# 8. PREFETCH & ALTERNATE DATA STREAMS (ADS)
$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    Write-Host "`nPREFETCH INTEGRITY & ADS" -ForegroundColor Cyan
    $files = Get-ChildItem -Path $prefetchPath -Filter *.pf -Force -ErrorAction SilentlyContinue
    if (-not $files) {
        Write-Host "  No prefetch found? Check the folder" -ForegroundColor Yellow
    } else {
        $suspiciousFiles = @{}
        $adsCount = 0
        $totalFiles = $files.Count

        foreach ($file in $files) {
            try {
                $isHidden = $file.Attributes -band [System.IO.FileAttributes]::Hidden
                $isReadOnly = $file.Attributes -band [System.IO.FileAttributes]::ReadOnly
                
                if ($isHidden -and $isReadOnly) {
                    $suspiciousFiles[$file.Name] = "Hidden and Read-only"
                } elseif ($isHidden) {
                    $suspiciousFiles[$file.Name] = "Hidden file"
                }

                # ADS Check
                $streams = Get-Item -Path $file.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' }
                if ($streams) {
                    $adsCount++
                    $suspiciousFiles[$file.Name] = "Alternate Data Stream ($($streams.Stream))"
                }
            } catch {
                $suspiciousFiles[$file.Name] = "Read Error"
            }
        }

        if ($suspiciousFiles.Count -gt 0) {
            Write-Host "  SUSPICIOUS FILES FOUND: $($suspiciousFiles.Count)/$totalFiles" -ForegroundColor Yellow
            foreach ($entry in $suspiciousFiles.GetEnumerator() | Sort-Object Key) {
                Write-Host ("    {0} : {1}" -f $entry.Key, $entry.Value) -ForegroundColor White
            }
        } else {
            Write-Host "  Prefetch integrity: Clean ($totalFiles files checked, 0 ADS detected)" -ForegroundColor Green
        }
    }
}

# 9. RECYCLE BIN & CONSOLE HISTORY
try {
    $recycleBinPath = "$env:SystemDrive" + '\$Recycle.Bin'
    Write-Host "`nRECYCLE BIN" -ForegroundColor Cyan
    if (Test-Path $recycleBinPath) {
        $recycleBinFolder = Get-Item -LiteralPath $recycleBinPath -Force
        $userFolders = Get-ChildItem -LiteralPath $recycleBinPath -Directory -Force -ErrorAction SilentlyContinue
        if ($userFolders) {
            $allDeletedItems = @()
            $latestModTime = $recycleBinFolder.LastWriteTime
            foreach ($userFolder in $userFolders) {
                if ($userFolder.LastWriteTime -gt $latestModTime) { $latestModTime = $userFolder.LastWriteTime }
                $userItems = Get-ChildItem -LiteralPath $userFolder.FullName -File -Force -ErrorAction SilentlyContinue
                if ($userItems) {
                    $allDeletedItems += $userItems
                    $latestFile = $userItems | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($latestFile -and $latestFile.LastWriteTime -gt $latestModTime) { $latestModTime = $latestFile.LastWriteTime }
                }
            }
            Write-Host "  Last Modified: " -NoNewline -ForegroundColor White
            Write-Host $latestModTime.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Yellow
            if ($allDeletedItems.Count -gt 0) {
                Write-Host "  Total Items: " -NoNewline -ForegroundColor White
                Write-Host $allDeletedItems.Count -ForegroundColor Yellow
            } else {
                Write-Host "  Status: Folders present but empty" -ForegroundColor Green
            }
        }
    }

    $consoleHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
    Write-Host "`nCONSOLE HOST HISTORY" -ForegroundColor Cyan
    if (Test-Path $consoleHistoryPath) {
        $historyFile = Get-Item -Path $consoleHistoryPath -Force
        Write-Host "  Last Modified: " -NoNewline -ForegroundColor White
        Write-Host $historyFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Yellow
        Write-Host "  File Size: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($historyFile.Length/1024, 2)) KB" -ForegroundColor Yellow
    } else {
        Write-Host "  File not found: History cleared or disabled" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Error accessing history info" -ForegroundColor Red
}

Write-Host "`nCheck Complete, hit up @praiselily if u run into any issues." -ForegroundColor Cyan