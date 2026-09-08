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
Write-Host "SYSTEM32 BINARIES & SIGNATURE AUDIT" -ForegroundColor Cyan
Write-Host ""

$targetDir = "$env:SystemRoot\System32"
$extensions = @("*.dll", "*.exe", "*.sys", "*.bin")

Write-Host "[*] Scanning target: $targetDir" -ForegroundColor White
Write-Host "[*] Indexing root binaries (excluding deep subfolders for speed)..." -ForegroundColor Gray

$files = Get-ChildItem -Path $targetDir -Include $extensions -File -ErrorAction SilentlyContinue
Write-Host ("[*] Found {0} binaries. Checking signatures..." -f $files.Count) -ForegroundColor Gray
Write-Host "----------------------------------------------------------"

$unsigned = [System.Collections.Generic.List[PSObject]]::new()
$invalid = [System.Collections.Generic.List[PSObject]]::new()
$nonMicrosoft = [System.Collections.Generic.List[PSObject]]::new()

$count = 0
foreach ($file in $files) {
    $count++
    if ($count % 250 -eq 0) {
        Write-Progress -Activity "Auditing System32 Binaries" -Status ("Checking {0}/{1}" -f $count, $files.Count) -PercentComplete (($count / $files.Count) * 100)
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
        $status = $sig.Status
        $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "None" }

        if ($status -eq "NotSigned") {
            $unsigned.Add([PSCustomObject]@{ File = $file.Name; Path = $file.FullName; Size = [math]::Round($file.Length/1KB, 2) })
        }
        elseif ($status -ne "Valid") {
            $invalid.Add([PSCustomObject]@{ File = $file.Name; Status = $status.ToString(); Signer = $signer })
        }
        elseif ($signer -notmatch "Microsoft") {
            $nonMicrosoft.Add([PSCustomObject]@{ File = $file.Name; Signer = $signer; Size = [math]::Round($file.Length/1KB, 2) })
        }
    } catch {}
}
Write-Progress -Activity "Auditing System32 Binaries" -Completed

# REPORT: INVALID / TAMPERED
if ($invalid.Count -gt 0) {
    Write-Host "`nCRITICAL: TAMPERED OR INVALID SIGNATURES ($($invalid.Count))" -ForegroundColor Red
    foreach ($item in $invalid) {
        Write-Host ("  [!] {0} | Status: {1}" -f $item.File, $item.Status) -ForegroundColor Red
    }
} else {
    Write-Host "`nTampered Signatures: None" -ForegroundColor Green
}

# REPORT: UNSIGNED BINARIES
if ($unsigned.Count -gt 0) {
    Write-Host "`nWARNING: UNSIGNED BINARIES IN SYSTEM32 ($($unsigned.Count))" -ForegroundColor Yellow
    foreach ($item in $unsigned) {
        Write-Host ("  [-] {0,-32} {1,8} KB" -f $item.File, $item.Size) -ForegroundColor White
    }
} else {
    Write-Host "`nUnsigned Binaries: None" -ForegroundColor Green
}

# REPORT: NON-MICROSOFT SIGNATURES (PROXY DLLS / INJECTORS)
if ($nonMicrosoft.Count -gt 0) {
    Write-Host "`nNOTICE: THIRD-PARTY SIGNED BINARIES ($($nonMicrosoft.Count))" -ForegroundColor Cyan
    foreach ($item in $nonMicrosoft) {
        $shortSigner = $item.Signer
        if ($shortSigner.Length -gt 45) { $shortSigner = $shortSigner.Substring(0, 42) + "..." }
        Write-Host ("  [~] {0,-32} | {1}" -f $item.File, $shortSigner) -ForegroundColor Yellow
    }
} else {
    Write-Host "`nThird-Party Binaries: None" -ForegroundColor Green
}

Write-Host "`nCheck Complete, hit up @praiselily if u run into any issues." -ForegroundColor Cyan