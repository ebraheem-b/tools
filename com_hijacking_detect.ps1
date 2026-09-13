$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[!] Administrator privileges required. Please run PowerShell as Admin." -ForegroundColor Red
    exit
}

Clear-Host
Write-Host "made with love by lily<3" -ForegroundColor Cyan
Write-Host "`nCOM HIJACKING & BINARY SIGNATURE AUDITOR" -ForegroundColor Cyan

$registryPaths = @(
    "Registry::HKEY_CURRENT_USER\Software\Classes\CLSID",
    "Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID"
)

$suspiciousItems = [System.Collections.Generic.List[PSObject]]::new()
$validComExts = @(".dll", ".ocx", ".ax", ".cpl")

Write-Host "`n[*] Inspecting InprocServer32 entries..." -ForegroundColor Gray

foreach ($regPath in $registryPaths) {
    if (-not (Test-Path $regPath)) { continue }

    Get-ChildItem -Path $regPath -Recurse -Depth 2 -ErrorAction SilentlyContinue | 
        Where-Object { $_.PSChildName -eq "InprocServer32" } | ForEach-Object {
            
            $key = $_
            $defaultVal = (Get-ItemProperty -LiteralPath $key.PSPath -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
            if ([string]::IsNullOrWhiteSpace($defaultVal)) { return }

            $expandedPath = [System.Environment]::ExpandEnvironmentVariables($defaultVal).Trim('"')
            $clsid = $key.PSParentPath.Split('\')[-1]
            $ext = [System.IO.Path]::GetExtension($expandedPath).ToLower()
            $isHkcu = $key.PSPath -match "HKEY_CURRENT_USER"

            # 1. Archivos inexistentes referenciados (vulnerables a Phantom DLL Hijacking)
            if (-not (Test-Path -LiteralPath $expandedPath)) {
                if ($isHkcu -or $expandedPath -match 'AppData|Temp|Downloads') {
                    $suspiciousItems.Add([PSCustomObject]@{
                        CLSID   = $clsid
                        Path    = $expandedPath
                        Status  = "MissingFile"
                        Reason  = "Referenced binary not found (Phantom Hijack)"
                        Signer  = "N/A"
                        Level   = "Medium"
                    })
                }
                return
            }

            # 2. Análisis de firma digital
            $sig = Get-AuthenticodeSignature -LiteralPath $expandedPath -ErrorAction SilentlyContinue
            $sigStatus = if ($sig) { $sig.Status.ToString() } else { "NotSigned" }
            $signer = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "None" }

            $reasons = @()
            $threatLevel = "Low"

            # Extensión anormal (.nls, .dat, .bin, etc.)
            if ($ext -notin $validComExts) {
                $reasons += "Disguised extension ($ext)"
                $threatLevel = "High"
            }

            # Rutas de usuario / directorios escribibles
            if ($expandedPath -match 'AppData|Temp|Users\\Public|Downloads|Globalization\\Sorting') {
                $reasons += "User-writable directory"
                $threatLevel = "High"
            }

            # Sobrescritura en HKCU (no requiere permisos de admin)
            if ($isHkcu) {
                $reasons += "HKCU User Override"
                if ($threatLevel -ne "High") { $threatLevel = "Medium" }
            }

            # Firma rota o manipulada
            if ($sigStatus -ne "Valid" -and $sigStatus -ne "NotSigned") {
                $reasons += "Tampered/Corrupt Signature ($sigStatus)"
                $threatLevel = "Critical"
            }

            # Binario sin firma en System32 o con firma no-Microsoft en directorios del sistema
            if ($sigStatus -eq "NotSigned") {
                $reasons += "Unsigned Binary"
                $threatLevel = "High"
            } elseif ($expandedPath -match "System32" -and $signer -notmatch "Microsoft") {
                $reasons += "Third-party signed in System32"
                if ($threatLevel -ne "High" -and $threatLevel -ne "Critical") { $threatLevel = "Medium" }
            }

            if ($reasons.Count -gt 0) {
                $suspiciousItems.Add([PSCustomObject]@{
                    CLSID   = $clsid
                    Path    = $expandedPath
                    Status  = $sigStatus
                    Reason  = ($reasons -join " | ")
                    Signer  = $signer
                    Level   = $threatLevel
                })
            }
    }
}

# Mostrar resultados clasificados
if ($suspiciousItems.Count -eq 0) {
    Write-Host "`n[+] No suspicious COM registrations or untrusted binaries found." -ForegroundColor Green
} else {
    Write-Host ("`n[!] SUSPICIOUS / UNTRUSTED COM MODULES FOUND ({0})" -f $suspiciousItems.Count) -ForegroundColor Red
    Write-Host "----------------------------------------------------------------------"

    foreach ($item in $suspiciousItems) {
        $color = switch ($item.Level) {
            "Critical" { "Red" }
            "High"     { "Yellow" }
            "Medium"   { "Cyan" }
            Default    { "White" }
        }

        Write-Host ("`n[{0}] CLSID: {1}" -f $item.Level.ToUpper(), $item.CLSID) -ForegroundColor $color
        Write-Host ("      Path:   {0}" -f $item.Path) -ForegroundColor White
        Write-Host ("      Reason: {0}" -f $item.Reason) -ForegroundColor Gray
        Write-Host ("      Status: {0} | Signer: {1}" -f $item.Status, $item.Signer) -ForegroundColor DarkGray
    }
}

Write-Host "`nAudit complete." -ForegroundColor Cyan
