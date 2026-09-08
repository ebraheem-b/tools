$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║           ADMINISTRATOR PRIVILEGES REQUIRED       ║" -ForegroundColor Red
    Write-Host "║     Please run this script as Administrator!      ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Red
    exit
}

Clear-Host
Write-Host "`nBINARIES & SIGNATURE AUDIT" -ForegroundColor Cyan

Add-Type -AssemblyName System.Windows.Forms
$folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
$folderBrowser.Description = "Select the folder to audit (e.g. C:\Windows\System32, FiveM AppData, etc.)"
$folderBrowser.ShowNewFolderButton = $false

$dialogResult = $folderBrowser.ShowDialog()

if ($dialogResult -ne 'OK' -or [string]::IsNullOrWhiteSpace($folderBrowser.SelectedPath)) {
    Write-Host "`n[!] No folder selected. Operation cancelled." -ForegroundColor Yellow
    exit
}

$targetDir = $folderBrowser.SelectedPath
$extensions = @("*.dll", "*.exe", "*.sys", "*.bin")

Write-Host "`n[*] Scanning target: $targetDir" -ForegroundColor White
Write-Host "[*] Indexing binaries..." -ForegroundColor Gray

$files = Get-ChildItem -Path $targetDir -Include $extensions -File -Recurse -ErrorAction SilentlyContinue
if (-not $files) {
    Write-Host "`n[!] No executable files found in the selected directory." -ForegroundColor Yellow
    exit
}

Write-Host ("[*] Found {0} binaries. Checking signatures..." -f $files.Count) -ForegroundColor Gray
Write-Host "----------------------------------------------------------"

$unsigned = [System.Collections.Generic.List[PSObject]]::new()
$invalid = [System.Collections.Generic.List[PSObject]]::new()
$suspicious = [System.Collections.Generic.List[PSObject]]::new()

$count = 0
foreach ($file in $files) {
    $count++
    if ($count % 50 -eq 0) {
        Write-Progress -Activity "Auditing Binaries" -Status ("Checking {0}/{1}" -f $count, $files.Count) -PercentComplete (($count / $files.Count) * 100)
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
        $status = $sig.Status
        $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "None" }

        if ($status -eq "NotSigned") {
            $unsigned.Add([PSCustomObject]@{ File = $file.Name; Path = $file.FullName; Size = [math]::Round($file.Length/1KB, 2) })
        }
        elseif ($status -ne "Valid") {
            $invalid.Add([PSCustomObject]@{ File = $file.Name; Path = $file.FullName; Status = $status.ToString(); Signer = $signer })
        }
        elseif ($targetDir -match "System32" -and $signer -notmatch "Microsoft") {
            $suspicious.Add([PSCustomObject]@{ File = $file.Name; Path = $file.FullName; Signer = $signer; Size = [math]::Round($file.Length/1KB, 2) })
        }
    } catch {}
}
Write-Progress -Activity "Auditing Binaries" -Completed

if ($invalid.Count -gt 0) {
    Write-Host "`nCRITICAL: TAMPERED OR INVALID SIGNATURES ($($invalid.Count))" -ForegroundColor Red
    foreach ($item in $invalid) {
        Write-Host ("  [!] {0}" -f $item.File) -ForegroundColor Red
        Write-Host ("      Status: {0}" -f $item.Status) -ForegroundColor DarkRed
    }
} else {
    Write-Host "`nTampered Signatures: None" -ForegroundColor Green
}

if ($unsigned.Count -gt 0) {
    Write-Host "`nWARNING: UNSIGNED BINARIES ($($unsigned.Count))" -ForegroundColor Yellow
    foreach ($item in $unsigned) {
        Write-Host ("  [-] {0,-32} {1,8} KB" -f $item.File, $item.Size) -ForegroundColor White
    }
} else {
    Write-Host "`nUnsigned Binaries: None" -ForegroundColor Green
}

if ($suspicious.Count -gt 0) {
    Write-Host "`nNOTICE: THIRD-PARTY SIGNED BINARIES IN SYSTEM32 ($($suspicious.Count))" -ForegroundColor Cyan
    foreach ($item in $suspicious) {
        $shortSigner = $item.Signer
        if ($shortSigner.Length -gt 60) { $shortSigner = $shortSigner.Substring(0, 57) + "..." }
        Write-Host ("  [~] {0}" -f $item.File) -ForegroundColor Yellow
        Write-Host ("      Signer: {0}" -f $shortSigner) -ForegroundColor DarkGray
    }
} elseif ($targetDir -match "System32") {
    Write-Host "`nThird-Party Binaries in System32: None" -ForegroundColor Green
}

Write-Host "`nCheck Complete." -ForegroundColor Cyan
