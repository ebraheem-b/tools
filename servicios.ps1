# ============================================================
#  SYSTEM INTEGRITY & FORENSIC CHECKER v2.0
#  Run as Administrator for full results
# ============================================================

$isAdmin = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║         ADMINISTRATOR PRIVILEGES REQUIRED        ║" -ForegroundColor Red
    Write-Host "║     Please run this script as Administrator!     ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Red
    exit
}

# -- Helpers --
function Write-Section ($title) {
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
}

function Write-StatusLine ($label, $value, $color) {
    Write-Host "  $label" -NoNewline -ForegroundColor White
    Write-Host "$value" -ForegroundColor $color
}

# Global counters for summary
$script:warnings = 0
$script:criticals = 0

function Add-Warning  { $script:warnings++  }
function Add-Critical { $script:criticals++ }

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     SYSTEM INTEGRITY & FORENSIC CHECKER v2.0    ║" -ForegroundColor Cyan
Write-Host "║              $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')               ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan

# ============================================================
#  1. SYSTEM BOOT TIME
# ============================================================
Write-Section "SYSTEM BOOT TIME"

try {
    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptime = (Get-Date) - $bootTime
    $bootStr = $bootTime.ToString("yyyy-MM-dd HH:mm:ss")
    $uptimeStr = "{0} days, {1:D2}:{2:D2}:{3:D2}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds
    Write-StatusLine "Last Boot:  " $bootStr "Yellow"
    Write-StatusLine "Uptime:     " $uptimeStr "White"
} catch {
    Write-Host "  Unable to retrieve boot time information" -ForegroundColor Red
}

# ============================================================
#  2. CONNECTED DRIVES
# ============================================================
$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -ne 5 }
if ($drives) {
    Write-Section "CONNECTED DRIVES"
    foreach ($drive in $drives) {
        $sizeGB = if ($drive.Size) { [math]::Round($drive.Size / 1GB, 1) } else { "N/A" }
        $freeGB = if ($drive.FreeSpace) { [math]::Round($drive.FreeSpace / 1GB, 1) } else { "N/A" }
        $fs = if ($drive.FileSystem) { $drive.FileSystem } else { "Unknown" }
        Write-Host ("  {0} {1,-6}  Size: {2} GB  Free: {3} GB" -f $drive.DeviceID, $fs, $sizeGB, $freeGB) -ForegroundColor Green
    }
}

# ============================================================
#  3. KERNEL INTEGRITY (BCD)
# ============================================================
Write-Section "KERNEL INTEGRITY"

try {
    $bcd = bcdedit /enum "{current}" 2>$null
    if ($bcd -match "testsigning\s+Yes") {
        Write-StatusLine "TestSigning:       " "ENABLED (UNSAFE)" "Red"
        Add-Critical
    } else {
        Write-StatusLine "TestSigning:       " "Disabled" "Green"
    }
    if ($bcd -match "nointegritychecks\s+Yes") {
        Write-StatusLine "Integrity Checks:  " "DISABLED" "Red"
        Add-Critical
    } else {
        Write-StatusLine "Integrity Checks:  " "Enforced" "Green"
    }
} catch {
    Write-Host "  Could not query BCD" -ForegroundColor Yellow
}

# Secure Boot
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($secureBoot) {
        Write-StatusLine "Secure Boot:       " "Enabled" "Green"
    } else {
        Write-StatusLine "Secure Boot:       " "DISABLED" "Red"
        Add-Critical
    }
} catch {
    Write-StatusLine "Secure Boot:       " "Not Supported / Legacy BIOS" "Yellow"
    Add-Warning
}

# ============================================================
#  4. DMA / VIRTUALIZATION SECURITY
# ============================================================
Write-Section "DMA / VIRTUALIZATION SECURITY"

try {
    $kernelDma = $false
    try {
        $ci = Get-ComputerInfo -Property CsKernelDmaProtection -ErrorAction SilentlyContinue
        if ($ci) { $kernelDma = [bool]$ci.CsKernelDmaProtection }
    } catch {}

    $vbsReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue
    $vbs = if ($vbsReg -and $null -ne $vbsReg.EnableVirtualizationBasedSecurity) { [bool]$vbsReg.EnableVirtualizationBasedSecurity } else { $false }

    $hvciReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue
    $hvci = if ($hvciReg -and $null -ne $hvciReg.Enabled) { [bool]$hvciReg.Enabled } else { $false }

    # Kernel DMA Protection
    if ($kernelDma) {
        Write-StatusLine "Kernel DMA Protection:  " "Enabled" "Green"
    } else {
        Write-StatusLine "Kernel DMA Protection:  " "Disabled / Not Supported" "Yellow"
        Add-Warning
    }

    # VBS
    if ($vbs) {
        Write-StatusLine "VBS (Virtualization):   " "Enabled" "Green"
    } else {
        Write-StatusLine "VBS (Virtualization):   " "Disabled" "Yellow"
        Add-Warning
    }

    # HVCI
    if ($hvci) {
        Write-StatusLine "HVCI (Code Integrity):  " "Enabled" "Green"
    } else {
        Write-StatusLine "HVCI (Code Integrity):  " "Disabled" "Yellow"
        Add-Warning
    }

    # Extra: Check DeviceGuard running status via WMI if available
    try {
        $dgStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue
        if ($dgStatus) {
            $vbsRunning = $dgStatus.VirtualizationBasedSecurityStatus
            $statusText = switch ($vbsRunning) {
                0 { "Not Running" }
                1 { "Enabled but not running" }
                2 { "Running" }
                default { "Unknown ($vbsRunning)" }
            }
            $statusColor = if ($vbsRunning -eq 2) { "Green" } else { "Yellow" }
            Write-StatusLine "VBS Runtime Status:     " $statusText $statusColor
        }
    } catch {}
} catch {
    Write-Host "  Error checking DMA/VBS status: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================
#  5. SERVICE STATUS
# ============================================================
Write-Section "SERVICE STATUS"

$services = @(
    @{Name = "SysMain";    DisplayName = "SysMain (Superfetch)"},
    @{Name = "PcaSvc";     DisplayName = "Program Compatibility Assistant"},
    @{Name = "DPS";        DisplayName = "Diagnostic Policy Service"},
    @{Name = "EventLog";   DisplayName = "Windows Event Log"},
    @{Name = "Schedule";   DisplayName = "Task Scheduler"},
    @{Name = "Bam";        DisplayName = "Background Activity Moderator"},
    @{Name = "Dusmsvc";    DisplayName = "Data Usage"},
    @{Name = "Appinfo";    DisplayName = "Application Information (UAC)"},
    @{Name = "CDPSvc";     DisplayName = "Connected Devices Platform"},
    @{Name = "DcomLaunch"; DisplayName = "DCOM Server Process Launcher"},
    @{Name = "PlugPlay";   DisplayName = "Plug and Play"},
    @{Name = "wsearch";    DisplayName = "Windows Search"},
    @{Name = "Dnscache";   DisplayName = "DNS Client Cache"},
    @{Name = "WinDefend";  DisplayName = "Windows Defender Antivirus"},
    @{Name = "WdNisSvc";   DisplayName = "Defender Network Inspection"},
    @{Name = "mpssvc";     DisplayName = "Windows Firewall"}
)

foreach ($svc in $services) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        $dispName = $svc.DisplayName
        if ($dispName.Length -gt 40) { $dispName = $dispName.Substring(0, 37) + "..." }

        if ($service.Status -eq "Running") {
            Write-Host ("  {0,-12} {1,-42}" -f $svc.Name, $dispName) -ForegroundColor Green -NoNewline

            if ($svc.Name -eq "Bam") {
                Write-Host " Running" -ForegroundColor Green
            } else {
                try {
                    $cimSvc = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
                    if ($cimSvc -and $cimSvc.ProcessId -gt 0) {
                        $proc = Get-Process -Id $cimSvc.ProcessId -ErrorAction SilentlyContinue
                        if ($proc -and $proc.StartTime) {
                            $startStr = $proc.StartTime.ToString("HH:mm:ss")
                            Write-Host " Started $startStr" -ForegroundColor Yellow
                        } else {
                            Write-Host " Running" -ForegroundColor Green
                        }
                    } else {
                        Write-Host " Running" -ForegroundColor Green
                    }
                } catch {
                    Write-Host " Running" -ForegroundColor Green
                }
            }
        } else {
            Write-Host ("  {0,-12} {1,-42} {2}" -f $svc.Name, $dispName, $service.Status) -ForegroundColor Red
            # Critical services that should be running
            if ($svc.Name -in @("EventLog", "WinDefend", "mpssvc", "DcomLaunch")) {
                Add-Critical
            } else {
                Add-Warning
            }
        }
    } else {
        Write-Host ("  {0,-12} {1,-42} Not Found" -f $svc.Name, $svc.DisplayName) -ForegroundColor DarkYellow
        Add-Warning
    }
}

# ============================================================
#  6. REGISTRY CHECKS
# ============================================================
Write-Section "REGISTRY CONFIGURATION"

$settings = @(
    @{ Name = "CMD Access";          Path = "HKCU:\Software\Policies\Microsoft\Windows\System";                                          Key = "DisableCMD";                  InvertLogic = $true;  Warning = "BLOCKED";  Safe = "Available" },
    @{ Name = "PowerShell Logging";  Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";                   Key = "EnableScriptBlockLogging";     InvertLogic = $false; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Activities Cache";    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";                                          Key = "EnableActivityFeed";           InvertLogic = $false; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Prefetch";            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Key = "EnablePrefetcher";           InvertLogic = $false; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "UAC Status";          Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";                           Key = "EnableLUA";                   InvertLogic = $false; Warning = "DISABLED"; Safe = "Enabled" },
    @{ Name = "Last Access Update";  Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem";                                         Key = "NtfsDisableLastAccessUpdate";  InvertLogic = $true;  Warning = "Disabled"; Safe = "Enabled" }
)

foreach ($s in $settings) {
    $regVal = Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue
    Write-Host "  " -NoNewline

    $isBad = $false
    if ($s.InvertLogic) {
        # InvertLogic = true: value of 1 or higher means BAD (e.g., DisableCMD=1 => blocked)
        if ($regVal -and $regVal.$($s.Key) -ge 1) { $isBad = $true }
    } else {
        # Normal: value of 0 or missing means BAD
        if ($regVal -and $regVal.$($s.Key) -eq 0) { $isBad = $true }
    }

    if ($isBad) {
        Write-Host "$($s.Name): " -NoNewline -ForegroundColor White
        Write-Host "$($s.Warning)" -ForegroundColor Red
        Add-Warning
    } else {
        Write-Host "$($s.Name): " -NoNewline -ForegroundColor White
        Write-Host "$($s.Safe)" -ForegroundColor Green
    }
}

# ============================================================
#  7. USN JOURNAL STATUS
# ============================================================
Write-Section "USN JOURNAL STATUS"

$ntfsDrives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.FileSystem -eq "NTFS" }
if ($ntfsDrives) {
    foreach ($d in $ntfsDrives) {
        $driveLetter = $d.DeviceID
        try {
            $usnOutput = & fsutil usn queryjournal "${driveLetter}\" 2>&1
            if ($LASTEXITCODE -eq 0 -and $usnOutput -notmatch "Error|error") {
                # Parse the USN ID and next USN for more detail
                $journalId = ($usnOutput | Select-String -Pattern "USN\s+Journal\s+ID|Id.*de.*diario" | Select-Object -First 1) -replace '.*:\s*', ''
                $nextUsn   = ($usnOutput | Select-String -Pattern "Next\s+USN|Siguiente\s+USN"       | Select-Object -First 1) -replace '.*:\s*', ''
                Write-Host ("  {0} : " -f $driveLetter) -NoNewline -ForegroundColor White
                Write-Host "Enabled" -NoNewline -ForegroundColor Green
                if ($journalId) {
                    Write-Host "  (Journal: $($journalId.Trim()), Next: $($nextUsn.Trim()))" -ForegroundColor DarkGray
                } else {
                    Write-Host "" # newline
                }
            } else {
                Write-Host ("  {0} : " -f $driveLetter) -NoNewline -ForegroundColor White
                Write-Host "NOT FOUND / DELETED (CLEANED)" -ForegroundColor Red
                Add-Critical
            }
        } catch {
            Write-Host ("  {0} : " -f $driveLetter) -NoNewline -ForegroundColor White
            Write-Host "NOT FOUND / DELETED (CLEANED)" -ForegroundColor Red
            Add-Critical
        }
    }
} else {
    Write-Host "  No NTFS volumes found" -ForegroundColor Yellow
}

# ============================================================
#  8. EVENT LOGS ANALYSIS
# ============================================================
Write-Section "EVENT LOGS ANALYSIS"

function Check-EventLog {
    param (
        [string]$logName,
        [int]$eventID,
        [string]$message,
        [int]$maxEvents = 1,
        [string]$severityIfFound = "Warning"  # "Warning" or "Critical"
    )
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = $eventID } -MaxEvents $maxEvents -ErrorAction SilentlyContinue
        if ($events) {
            $ev = $events[0]
            $timeStr = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm")
            Write-Host "  $message at: " -NoNewline -ForegroundColor White
            Write-Host $timeStr -ForegroundColor Yellow
            if ($maxEvents -gt 1 -and $events.Count -gt 1) {
                Write-Host "    ($($events.Count) occurrences found, showing latest)" -ForegroundColor DarkGray
            }
            if ($severityIfFound -eq "Critical") { Add-Critical } else { Add-Warning }
            return $true
        } else {
            Write-Host "  $message - No records found" -ForegroundColor Green
            return $false
        }
    } catch {
        Write-Host "  $message - No records found" -ForegroundColor Green
        return $false
    }
}

function Check-MultiEventLog {
    param (
        [string[]]$logNames,
        [int[]]$eventIDs,
        [string]$message,
        [string]$severityIfFound = "Warning"
    )
    $allEvents = @()
    foreach ($log in $logNames) {
        foreach ($eid in $eventIDs) {
            try {
                $ev = Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $eid } -MaxEvents 5 -ErrorAction SilentlyContinue
                if ($ev) { $allEvents += $ev }
            } catch {}
        }
    }

    if ($allEvents.Count -gt 0) {
        $latest = $allEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $timeStr = $latest.TimeCreated.ToString("yyyy-MM-dd HH:mm")
        Write-Host "  $message (ID: $($latest.Id), Log: $($latest.LogName)) at: " -NoNewline -ForegroundColor White
        Write-Host $timeStr -ForegroundColor Yellow
        if ($allEvents.Count -gt 1) {
            Write-Host "    ($($allEvents.Count) total events found across logs)" -ForegroundColor DarkGray
        }
        if ($severityIfFound -eq "Critical") { Add-Critical } else { Add-Warning }
        return $true
    } else {
        Write-Host "  $message - No records found" -ForegroundColor Green
        return $false
    }
}

# --- USN Journal cleared ---
# EventID 2: NTFS - USN journal was deleted. Can also show in System log.
# We search broadly for any USN deletion indicator.
Check-MultiEventLog -logNames @("System", "Application") -eventIDs @(2, 3079) -message "USN Journal cleared" -severityIfFound "Critical"

# --- Event Logs cleared ---
# EventID 104: System log - "The <logname> log file was cleared"
# EventID 1102: Security log - "The audit log was cleared"
Check-MultiEventLog -logNames @("System", "Security") -eventIDs @(104, 1102) -message "Event Logs cleared" -severityIfFound "Critical"

# --- Standard event checks ---
Check-EventLog "System"   1074  "Last PC Shutdown"            -maxEvents 3
Check-EventLog "System"   41    "Kernel-Power Abrupt Shutdown" -maxEvents 3 -severityIfFound "Warning"
Check-EventLog "System"   1001  "BSOD / BugCheck Occurred"    -maxEvents 3 -severityIfFound "Warning"
Check-EventLog "Security" 4616  "System time changed"         -maxEvents 3 -severityIfFound "Critical"
Check-EventLog "System"   6005  "Event Log Service started"   -maxEvents 3
Check-EventLog "System"   6006  "Event Log Service stopped"   -maxEvents 3

# --- Windows Defender events ---
Check-EventLog "Microsoft-Windows-Windows Defender/Operational" 1116 "Defender Malware Triggered"          -severityIfFound "Critical"
Check-EventLog "Microsoft-Windows-Windows Defender/Operational" 5001 "Defender Real-Time Protection OFF"   -severityIfFound "Critical"
Check-EventLog "Microsoft-Windows-Windows Defender/Operational" 5007 "Defender Exclusion Added"            -severityIfFound "Warning"
Check-EventLog "Microsoft-Windows-Windows Defender/Operational" 1117 "Defender Action Taken on Malware"    -severityIfFound "Warning"

# --- Device changes ---
Write-Host ""
Write-Host "  -- Device Changes --" -ForegroundColor DarkCyan
$deviceFound = $false

try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-Kernel-PnP/Configuration"; Id = 400 } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($ev) {
        Write-Host "  Device configuration changed at: " -NoNewline -ForegroundColor White
        Write-Host $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm") -ForegroundColor Yellow
        $deviceFound = $true
        Add-Warning
    }
} catch {}

if (-not $deviceFound) {
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName = "System"; Id = 225 } -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($ev) {
            Write-Host "  Device removed at: " -NoNewline -ForegroundColor White
            Write-Host $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm") -ForegroundColor Yellow
            $deviceFound = $true
            Add-Warning
        }
    } catch {}
}

if (-not $deviceFound) {
    Write-Host "  Device changes - No records found" -ForegroundColor Green
}

# ============================================================
#  9. DNS CACHE ANALYSIS
# ============================================================
Write-Section "DNS CACHE ANALYSIS"

try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    if ($dnsCache) {
        $totalDns = $dnsCache.Count
        Write-StatusLine "DNS Cache Entries: " "$totalDns total" "White"

        $suspiciousPatterns = "keyauth|redengine|eauth|skript|eulen|asgard|monstermenu|tzproject|hxcheats|shey\.tech|cobraloader|unknowncheats|mpgh\.net|elitepvpers|aimjunkies|battlelog|cheatengine|chod-cheats|interwebz|artificial-aiming|phantomoverlay|ring-1|hyperion|aimware|gamesense|nixware|fatality\.win|spirthack|onetap|neverlose|exitlag.*crack|loader\.(cc|gg|to)"
        $cheatMatch = $dnsCache | Where-Object { $_.Entry -match $suspiciousPatterns }

        if ($cheatMatch) {
            Write-Host "  SUSPICIOUS DNS RECORDS FOUND:" -ForegroundColor Red
            foreach ($m in $cheatMatch) {
                $data = if ($m.Data) { $m.Data } else { "N/A" }
                Write-Host ("    {0} -> {1}" -f $m.Entry, $data) -ForegroundColor Yellow
            }
            Add-Critical
        } else {
            Write-Host "  DNS Cache - Clean (no suspicious domains)" -ForegroundColor Green
        }
    } else {
        Write-Host "  DNS Cache is empty" -ForegroundColor Yellow
        Add-Warning
    }
} catch {
    Write-Host "  Could not read DNS cache" -ForegroundColor Yellow
}

# ============================================================
# 10. PREFETCH INTEGRITY
# ============================================================
$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    Write-Section "PREFETCH INTEGRITY"

    $files = Get-ChildItem -Path $prefetchPath -Filter *.pf -Force -ErrorAction SilentlyContinue
    if (-not $files) {
        Write-Host "  No .pf files found - Prefetch may be disabled or cleaned" -ForegroundColor Yellow
        Add-Warning
    } else {
        $hashTable = @{}
        $suspiciousFiles = @{}
        $totalFiles = $files.Count

        $hiddenFiles = @()
        $readOnlyFiles = @()
        $hiddenAndReadOnlyFiles = @()
        $adsFiles = @()
        $errorFiles = @()

        foreach ($file in $files) {
            try {
                $isHidden   = $file.Attributes -band [System.IO.FileAttributes]::Hidden
                $isReadOnly = $file.Attributes -band [System.IO.FileAttributes]::ReadOnly

                if ($isHidden -and $isReadOnly) {
                    $hiddenAndReadOnlyFiles += $file
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                        $suspiciousFiles[$file.Name] = "Hidden + Read-only"
                    }
                } elseif ($isHidden) {
                    $hiddenFiles += $file
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                        $suspiciousFiles[$file.Name] = "Hidden file"
                    }
                } elseif ($isReadOnly) {
                    $readOnlyFiles += $file
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                        $suspiciousFiles[$file.Name] = "Read-only file"
                    }
                }

                $streams = Get-Item -Path $file.FullName -Stream * -ErrorAction SilentlyContinue |
                           Where-Object { $_.Stream -ne ':$DATA' }
                if ($streams) {
                    $adsFiles += $file
                    $streamNames = ($streams | ForEach-Object { $_.Stream }) -join ", "
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                        $suspiciousFiles[$file.Name] = "Alternate Data Stream ($streamNames)"
                    }
                }

                $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($hash) {
                    if ($hashTable.ContainsKey($hash.Hash)) {
                        $hashTable[$hash.Hash].Add($file.Name)
                    } else {
                        $hashTable[$hash.Hash] = [System.Collections.Generic.List[string]]::new()
                        $hashTable[$hash.Hash].Add($file.Name)
                    }
                }
            } catch {
                $errorFiles += $file
                if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                    $suspiciousFiles[$file.Name] = "Error: $($_.Exception.Message)"
                }
            }
        }

        Write-StatusLine "Total Prefetch Files: " "$totalFiles" "White"

        if ($hiddenAndReadOnlyFiles.Count -gt 0) {
            Write-Host "  Hidden + Read-only: $($hiddenAndReadOnlyFiles.Count) found" -ForegroundColor Yellow
            foreach ($file in $hiddenAndReadOnlyFiles) {
                Write-Host ("    - {0}" -f $file.Name) -ForegroundColor White
            }
        }

        if ($hiddenFiles.Count -gt 0) {
            Write-Host "  Hidden Files: $($hiddenFiles.Count) found" -ForegroundColor Yellow
            foreach ($file in $hiddenFiles) {
                Write-Host ("    - {0}" -f $file.Name) -ForegroundColor White
            }
        } else {
            Write-Host "  Hidden Files: None" -ForegroundColor Green
        }

        if ($readOnlyFiles.Count -gt 0) {
            Write-Host "  Read-Only Files: $($readOnlyFiles.Count)" -ForegroundColor Yellow
            foreach ($file in $readOnlyFiles) {
                Write-Host ("    - {0}" -f $file.Name) -ForegroundColor White
            }
        } else {
            Write-Host "  Read-Only Files: None" -ForegroundColor Green
        }

        if ($adsFiles.Count -gt 0) {
            Write-Host "  ADS Files: $($adsFiles.Count) found" -ForegroundColor Red
            foreach ($file in $adsFiles) {
                Write-Host ("    - {0}" -f $file.Name) -ForegroundColor White
            }
            Add-Critical
        } else {
            Write-Host "  ADS Files: None" -ForegroundColor Green
        }

        $repeatedHashes = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
        if ($repeatedHashes) {
            $repeatCount = @($repeatedHashes).Count
            Write-Host "  Duplicate Sets: $repeatCount found" -ForegroundColor Yellow
            foreach ($entry in $repeatedHashes) {
                foreach ($file in $entry.Value) {
                    if (-not $suspiciousFiles.ContainsKey($file)) {
                        $suspiciousFiles[$file] = "Duplicate file"
                    }
                }
                Write-Host ("    Duplicates: {0}" -f ($entry.Value -join ", ")) -ForegroundColor White
            }
            Add-Warning
        } else {
            Write-Host "  Duplicates: None" -ForegroundColor Green
        }

        if ($suspiciousFiles.Count -gt 0) {
            Write-Host ""
            Write-Host "  SUSPICIOUS FILES: $($suspiciousFiles.Count)/$totalFiles" -ForegroundColor Yellow
            foreach ($entry in $suspiciousFiles.GetEnumerator() | Sort-Object Key) {
                Write-Host ("    {0} : {1}" -f $entry.Key, $entry.Value) -ForegroundColor White
            }
        } else {
            Write-Host "  Prefetch integrity: CLEAN ($totalFiles files checked)" -ForegroundColor Green
        }
    }
} else {
    Write-Host ""
    Write-Host "  Prefetch folder not found at: $prefetchPath" -ForegroundColor Red
    Add-Warning
}

# ============================================================
# 11. RECYCLE BIN
# ============================================================
Write-Section "RECYCLE BIN"

try {
    $recycleBinPath = "$env:SystemDrive" + '\$Recycle.Bin'

    if (Test-Path $recycleBinPath) {
        $recycleBinFolder = Get-Item -LiteralPath $recycleBinPath -Force
        $userFolders = Get-ChildItem -LiteralPath $recycleBinPath -Directory -Force -ErrorAction SilentlyContinue

        if ($userFolders) {
            $allDeletedItems = @()
            $latestModTime = $recycleBinFolder.LastWriteTime

            foreach ($userFolder in $userFolders) {
                if ($userFolder.LastWriteTime -gt $latestModTime) {
                    $latestModTime = $userFolder.LastWriteTime
                }
                $userItems = Get-ChildItem -LiteralPath $userFolder.FullName -File -Force -ErrorAction SilentlyContinue
                if ($userItems) {
                    $allDeletedItems += $userItems
                    $latestFile = $userItems | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($latestFile -and $latestFile.LastWriteTime -gt $latestModTime) {
                        $latestModTime = $latestFile.LastWriteTime
                    }
                }
            }

            $modStr = $latestModTime.ToString("yyyy-MM-dd HH:mm:ss")
            Write-StatusLine "Last Modified:  " $modStr "Yellow"

            if ($allDeletedItems.Count -gt 0) {
                Write-StatusLine "Total Items:    " "$($allDeletedItems.Count)" "Yellow"
                $latestItem = $allDeletedItems | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                Write-StatusLine "Latest Item:    " $latestItem.Name "Gray"
            } else {
                Write-StatusLine "Status:         " "Folders present but empty" "Green"
            }
        } else {
            Write-StatusLine "Status:         " "Empty" "Green"
            $modStr = $recycleBinFolder.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            Write-StatusLine "Last Modified:  " $modStr "Green"
        }

        # Check if recycle bin was recently emptied
        $clearEvent = Get-WinEvent -FilterHashtable @{ LogName = "System"; Id = 10006 } -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($clearEvent) {
            $clearStr = $clearEvent.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Write-StatusLine "Last Cleared:   " $clearStr "Red"
            Add-Warning
        }
    } else {
        Write-Host "  Recycle Bin not found at: $recycleBinPath" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Error reading Recycle Bin: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================
# 12. CONSOLE HOST HISTORY
# ============================================================
Write-Section "CONSOLE HOST HISTORY"

$consoleHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

if (Test-Path $consoleHistoryPath) {
    $historyFile = Get-Item -Path $consoleHistoryPath -Force
    $modStr = $historyFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
    Write-StatusLine "Last Modified:  " $modStr "Yellow"

    $attributes = $historyFile.Attributes
    if ($attributes -ne "Archive") {
        Write-StatusLine "Attributes:     " "$attributes" "Yellow"
    } else {
        Write-StatusLine "Attributes:     " "Normal" "Green"
    }

    $fileSizeKB = [math]::Round($historyFile.Length / 1024, 2)
    Write-StatusLine "File Size:      " "$fileSizeKB KB" "Yellow"

    # Show last 5 commands for quick review
    $lastCommands = Get-Content $consoleHistoryPath -Tail 5 -ErrorAction SilentlyContinue
    if ($lastCommands) {
        Write-Host "  Last commands:" -ForegroundColor DarkCyan
        foreach ($cmd in $lastCommands) {
            if ($cmd.Trim()) {
                Write-Host "    > $cmd" -ForegroundColor DarkGray
            }
        }
    }
} else {
    Write-Host "  File not found: history may be disabled or never used" -ForegroundColor Yellow
}

# ============================================================
# 13. NETWORK ADAPTERS
# ============================================================
Write-Section "NETWORK ADAPTERS"

try {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    if ($adapters) {
        foreach ($adapter in $adapters) {
            $mac = $adapter.MacAddress
            $name = $adapter.Name
            $desc = $adapter.InterfaceDescription
            if ($desc.Length -gt 45) { $desc = $desc.Substring(0, 42) + "..." }
            Write-Host ("  {0,-20} {1}" -f $name, $desc) -ForegroundColor Green -NoNewline
            Write-Host "  MAC: $mac" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  No active network adapters found" -ForegroundColor Yellow
    }

    # Check for MAC spoofing indicators
    $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
    foreach ($adapter in $allAdapters) {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
        $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
        foreach ($key in $subKeys) {
            $netAddr = Get-ItemProperty -Path $key.PSPath -Name "NetworkAddress" -ErrorAction SilentlyContinue
            if ($netAddr -and $netAddr.NetworkAddress) {
                Write-Host "  MAC Override found in registry: $($netAddr.NetworkAddress)" -ForegroundColor Red
                Add-Critical
                break
            }
        }
        break  # Only check once
    }
} catch {
    Write-Host "  Could not enumerate network adapters" -ForegroundColor Yellow
}

# ============================================================
# 14. RECENT INSTALLED PROGRAMS (Last 7 days)
# ============================================================
Write-Section "RECENTLY INSTALLED PROGRAMS (Last 7 days)"

try {
    $cutoff = (Get-Date).AddDays(-7)
    $recentApps = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                                   "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                  Where-Object { $_.InstallDate -and $_.DisplayName } |
                  ForEach-Object {
                      $dateStr = $_.InstallDate
                      try {
                          $installDate = [datetime]::ParseExact($dateStr, "yyyyMMdd", $null)
                          if ($installDate -ge $cutoff) {
                              [PSCustomObject]@{
                                  Name = $_.DisplayName
                                  Date = $installDate.ToString("yyyy-MM-dd")
                                  Publisher = if ($_.Publisher) { $_.Publisher } else { "Unknown" }
                              }
                          }
                      } catch {}
                  } |
                  Sort-Object Date -Descending

    if ($recentApps) {
        foreach ($app in $recentApps) {
            $appName = $app.Name
            if ($appName.Length -gt 40) { $appName = $appName.Substring(0, 37) + "..." }
            Write-Host ("  {0}  {1,-42} {2}" -f $app.Date, $appName, $app.Publisher) -ForegroundColor Yellow
        }
    } else {
        Write-Host "  No installations in the last 7 days" -ForegroundColor Green
    }
} catch {
    Write-Host "  Could not query installed programs" -ForegroundColor Yellow
}

# ============================================================
# 15. SCHEDULED TASKS CHECK (Suspicious)
# ============================================================
Write-Section "SUSPICIOUS SCHEDULED TASKS"

try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
             Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notmatch "\\Microsoft\\" } |
             Select-Object TaskName, TaskPath, State -First 15

    if ($tasks) {
        foreach ($task in $tasks) {
            $taskName = $task.TaskName
            if ($taskName.Length -gt 45) { $taskName = $taskName.Substring(0, 42) + "..." }
            Write-Host ("  {0,-47} {1}" -f $taskName, $task.State) -ForegroundColor Yellow
        }
        Write-Host "  (Showing non-Microsoft active tasks)" -ForegroundColor DarkGray
    } else {
        Write-Host "  No suspicious scheduled tasks found" -ForegroundColor Green
    }
} catch {
    Write-Host "  Could not query scheduled tasks" -ForegroundColor Yellow
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor DarkGray

if ($script:criticals -gt 0) {
    Write-Host "  RESULT: " -NoNewline -ForegroundColor White
    Write-Host "$($script:criticals) CRITICAL" -NoNewline -ForegroundColor Red
    Write-Host " / " -NoNewline -ForegroundColor White
    Write-Host "$($script:warnings) WARNINGS" -ForegroundColor Yellow
} elseif ($script:warnings -gt 0) {
    Write-Host "  RESULT: " -NoNewline -ForegroundColor White
    Write-Host "0 Critical" -NoNewline -ForegroundColor Green
    Write-Host " / " -NoNewline -ForegroundColor White
    Write-Host "$($script:warnings) WARNINGS" -ForegroundColor Yellow
} else {
    Write-Host "  RESULT: " -NoNewline -ForegroundColor White
    Write-Host "ALL CLEAN - No issues detected" -ForegroundColor Green
}

Write-Host "══════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""
