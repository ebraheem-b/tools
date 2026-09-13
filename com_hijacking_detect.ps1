$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║           ADMINISTRATOR PRIVILEGES REQUIRED       ║" -ForegroundColor Red
    Write-Host "║     Please run this script as Administrator!      ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Red
    exit
}

Clear-Host
Write-Host "by ebrahem" -ForegroundColor Cyan
Write-Host "`nCOM HIJACKING & BINARY SIGNATURE AUDITOR" -ForegroundColor Cyan

$registryPaths = @(
    "Registry::HKEY_CURRENT_USER\Software\Classes\CLSID",
    "Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID"
)

$suspiciousItems = [System.Collections.Generic.List[PSObject]]::new()
$validComExts = @(".dll", ".ocx", ".ax", ".cpl")

Write-Host "`n[*] Inspecting InprocServer32 entries..." -ForegroundColor Gray

# Función auxiliar para comprobar la cabecera ejecutable PE (MZ)
function Test-IsPEHeader {
    param([string]$FilePath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
            return $true # Encabezado 'MZ' detectado
        }
    } catch {}
    return $false
}

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

            # 1. Archivo inexistente referenciado
            if (-not (Test-Path -LiteralPath $expandedPath)) {
                if ($isHkcu -or $expandedPath -match 'AppData|Temp|Downloads|Globalization') {
                    $suspiciousItems.Add([PSCustomObject]@{
                        CLSID   = $clsid
                        Path    = $expandedPath
                        Status  = "MissingFile"
                        Reason  = "Referenced payload not found (Phantom Hijack / Cleaner residual)"
                        Signer  = "N/A"
                        Level   = "Medium"
                    })
                }
                return
            }

            # 2. Análisis de cabecera en crudo (Caza de camuflaje .nls / .dat / .bin)
            $isPeBinary = Test-IsPEHeader -FilePath $expandedPath

            # 3. Análisis de firma digital
            $sig = Get-AuthenticodeSignature -LiteralPath $expandedPath -ErrorAction SilentlyContinue
            $sigStatus = if ($sig) { $sig.Status.ToString() } else { "NotSigned" }
            $signer = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "None" }

            $reasons = @()
            $threatLevel = "Low"

            # DELATOR DEFINITIVO: Extensión no ejecutable pero con cabecera MZ real
            if ($ext -notin $validComExts -and $isPeBinary) {
                $reasons += "DISGUISED EXECUTABLE (PE/MZ Header in .$ext)"
                $threatLevel = "Critical"
            } elseif ($ext -notin $validComExts) {
                $reasons += "Disguised extension ($ext)"
                $threatLevel = "High"
            }

            # Rutas sospechosas o de usuario
            if ($expandedPath -match 'AppData|Temp|Users\\Public|Downloads|Globalization\\Sorting') {
                $reasons += "User-writable or abnormal directory"
                if ($threatLevel -ne "Critical") { $threatLevel = "High" }
            }

            # Clave registrada en HKCU
            if ($isHkcu) {
                $reasons += "HKCU User Override"
                if ($threatLevel -eq "Low") { $threatLevel = "Medium" }
            }

            # Firma alterada o rota
            if ($sigStatus -ne "Valid" -and $sigStatus -ne "NotSigned") {
                $reasons += "Tampered/Corrupt Signature ($sigStatus)"
                $threatLevel = "Critical"
            }

            # Binario no firmado
            if ($sigStatus -eq "NotSigned") {
                $reasons += "Unsigned Binary"
                if ($threatLevel -eq "Low") { $threatLevel = "High" }
            } elseif ($expandedPath -match "System32" -and $signer -notmatch "Microsoft") {
                $reasons += "Third-party signed in System32"
                if ($threatLevel -eq "Low") { $threatLevel = "Medium" }
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
