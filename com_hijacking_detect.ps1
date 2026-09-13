Write-Host "`n[*] AUDITANDO CLAVES COM (InprocServer32)..." -ForegroundColor Cyan

$results = [System.Collections.Generic.List[PSObject]]::new()
$registryPaths = @(
    "Registry::HKEY_CURRENT_USER\Software\Classes\CLSID",
    "Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID"
)

foreach ($regPath in $registryPaths) {
    if (-not (Test-Path $regPath)) { continue }
    
    Get-ChildItem -Path $regPath -Recurse -Depth 2 -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq "InprocServer32" } | ForEach-Object {
        $key = $_
        $defaultVal = (Get-ItemProperty -LiteralPath $key.PSPath -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
        
        if ([string]::IsNullOrWhiteSpace($defaultVal)) { return }
        
        # Expandir variables de entorno si las tiene (ej. %SystemRoot%)
        $expandedPath = [System.Environment]::ExpandEnvironmentVariables($defaultVal).Trim('"')
        
        $isSuspicious = $false
        $reason = ""

        # 1. Chequeo de extensiones sospechosas (no dll)
        $ext = [System.IO.Path]::GetExtension($expandedPath).ToLower()
        if ($ext -notin @(".dll", ".ocx") -and $ext -ne "") {
            $isSuspicious = $true
            $reason = "Extension anomala ($ext)"
        }

        # 2. Rutas tipicas de persistencia / carpetas escribibles por usuario
        if ($expandedPath -match 'AppData|Temp|Users\\Public|Downloads|Globalization\\Sorting') {
            $isSuspicious = $true
            $reason = if ($reason) { "$reason + Ruta no estandar" } else { "Ruta en carpeta de usuario" }
        }

        # 3. Claves COM registradas bajo HKCU (potencial User Hijack)
        if ($key.PSPath -match "HKEY_CURRENT_USER") {
            $isSuspicious = $true
            $reason = if ($reason) { "$reason + Definido en HKCU" } else { "Clave COM en HKCU (Override)" }
        }

        if ($isSuspicious) {
            $fileExists = Test-Path -LiteralPath $expandedPath
            $signer = "Desconocido"
            if ($fileExists) {
                $sig = Get-AuthenticodeSignature -LiteralPath $expandedPath -ErrorAction SilentlyContinue
                $signer = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "NotSigned" }
            }

            $results.Add([PSCustomObject]@{
                CLSID   = $key.PSParentPath.Split('\')[-1]
                Payload = $expandedPath
                Reason  = $reason
                Exists  = $fileExists
                Signer  = $signer
            })
        }
    }
}

if ($results.Count -gt 0) {
    Write-Host "`n[!] ALERTA: CLAVES COM SOSPECHOSAS DETECTADAS ($($results.Count))" -ForegroundColor Red
    foreach ($item in $results) {
        Write-Host ("`n[+] CLSID:   {0}" -f $item.CLSID) -ForegroundColor Yellow
        Write-Host ("    Payload: {0}" -f $item.Payload) -ForegroundColor White
        Write-Host ("    Motivo:  {0}" -f $item.Reason) -ForegroundColor Magenta
        Write-Host ("    Existe:  {0} | Firma: {1}" -f $item.Exists, $item.Signer) -ForegroundColor Gray
    }
} else {
    Write-Host "`n[+] No se encontraron secuestros COM evidentes." -ForegroundColor Green
}