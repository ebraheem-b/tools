[CmdletBinding()]
param (
    [int64]$MaxFileSizeBytes = 104857600,
    [switch]$IncludeSystemPaths
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$BinarySignatures = @(
    @{ Name = 'PE/EXE/DLL';       Offset = 0; Magic = [byte[]]@(0x4D, 0x5A) }
    @{ Name = 'ELF';              Offset = 0; Magic = [byte[]]@(0x7F, 0x45, 0x4C, 0x46) }
    @{ Name = 'Mach-O (32)';      Offset = 0; Magic = [byte[]]@(0xFE, 0xED, 0xFA, 0xCE) }
    @{ Name = 'Mach-O (64)';      Offset = 0; Magic = [byte[]]@(0xFE, 0xED, 0xFA, 0xCF) }
    @{ Name = 'Mach-O Universal'; Offset = 0; Magic = [byte[]]@(0xCA, 0xFE, 0xBA, 0xBE) }
    @{ Name = 'OLE2/Compound';    Offset = 0; Magic = [byte[]]@(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1) }
    @{ Name = 'DEX (Android)';    Offset = 0; Magic = [byte[]]@(0x64, 0x65, 0x78, 0x0A) }
    @{ Name = 'WASM';             Offset = 0; Magic = [byte[]]@(0x00, 0x61, 0x73, 0x6D) }
    @{ Name = 'CAB Archive';      Offset = 0; Magic = [byte[]]@(0x4D, 0x53, 0x43, 0x46) }
    @{ Name = 'RAR SFX';          Offset = 0; Magic = [byte[]]@(0x52, 0x61, 0x72, 0x21) }
)

$KnownBinaryExtensions = @{}
@(
    '.exe', '.dll', '.sys', '.drv', '.efi', '.scr', '.cpl', '.ocx', '.mui', '.node',
    '.msi', '.msp', '.mst',
    '.class', '.jar', '.war', '.ear',
    '.so', '.dylib', '.a', '.o', '.ko',
    '.elf', '.bin', '.com', '.pif',
    '.dex', '.apk', '.aab',
    '.wasm',
    '.cab', '.cat',
    '.pyc', '.pyo',
    '.beam',
    '.pdf',
    '.tlb', '.ax', '.acm', '.tsp', '.winmd', '.rll', '.ime',
    '.rs', '.iec', '.ds', '.fon', '.nls', '.mun', '.mof',
    '.cnv', '.cpx', '.rpl', '.dat'
) | ForEach-Object { $KnownBinaryExtensions[$_.ToLower()] = $true }

$SkipExtensions = @{}
@(
    '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm',
    '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma',
    '.iso', '.img', '.vmdk', '.vhd', '.vhdx', '.qcow2',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.zst', '.lz4',
    '.bak', '.tmp', '.log', '.etl',
    '.bmp', '.jpg', '.jpeg', '.png', '.gif', '.tiff', '.ico', '.svg', '.webp',
    '.psd', '.ai',
    '.ttf', '.otf', '.woff', '.woff2',
    '.sqlite', '.db', '.mdb', '.accdb', '.ldf', '.mdf', '.ndf',
    '.sample', '.lock', '.map', '.min', '.pack', '.idx', '.flow'
) | ForEach-Object { $SkipExtensions[$_.ToLower()] = $true }

$OLE2DocumentExtensions = @{}
@(
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.msg', '.vsd', '.vsdx', '.pub', '.mpp'
) | ForEach-Object { $OLE2DocumentExtensions[$_.ToLower()] = $true }

$SuspiciousIfBinary = @{}
@(
    '.txt', '.cfg', '.ini', '.xml', '.json', '.yaml', '.yml', '.csv', '.md', '.rst',
    '.html', '.htm', '.css', '.js', '.ts', '.jsx', '.tsx',
    '.py', '.rb', '.pl', '.php', '.lua', '.sh', '.bash', '.ps1', '.psm1', '.bat', '.cmd', '.vbs',
    '.rtf',
    '.data', '.config', '.settings', '.manifest',
    '.temp', '.cache',
    '.old', '.orig',
    ''
) | ForEach-Object { $SuspiciousIfBinary[$_.ToLower()] = $true }

function Test-BinarySignature {
    param ([string]$FilePath)
    try {
        $stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $reader = New-Object System.IO.BinaryReader($stream)
        try {
            if ($stream.Length -lt 4) { return $null }
            $headerSize = [math]::Min(16, $stream.Length)
            $header = $reader.ReadBytes($headerSize)

            foreach ($sig in $script:BinarySignatures) {
                $offset = $sig.Offset
                $magic  = $sig.Magic
                if (($offset + $magic.Length) -gt $header.Length) { continue }

                $match = $true
                for ($i = 0; $i -lt $magic.Length; $i++) {
                    if ($header[$offset + $i] -ne $magic[$i]) {
                        $match = $false
                        break
                    }
                }

                if ($match) {
                    if ($sig.Name -eq 'PE/EXE/DLL') {
                        if (Confirm-PESignature -Stream $stream -Reader $reader) { return 'PE/EXE/DLL' }
                        continue
                    }
                    return $sig.Name
                }
            }
            return $null
        }
        finally {
            $reader.Close(); $reader.Dispose()
            $stream.Close(); $stream.Dispose()
        }
    }
    catch { return $null }
}

function Confirm-PESignature {
    param ([System.IO.Stream]$Stream, [System.IO.BinaryReader]$Reader)
    try {
        if ($Stream.Length -lt 256) { return $false }
        $Stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peOffset = $Reader.ReadInt32()
        if ($peOffset -le 0 -or $peOffset -gt ($Stream.Length - 4)) { return $false }
        $Stream.Seek($peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peSig = $Reader.ReadBytes(4)
        return ($peSig.Length -eq 4 -and $peSig[0] -eq 0x50 -and $peSig[1] -eq 0x45 -and $peSig[2] -eq 0x00 -and $peSig[3] -eq 0x00)
    }
    catch { return $false }
}

function Get-RiskLevel {
    param ([string]$DetectedType, [string]$Extension)
    $ext = if ([string]::IsNullOrWhiteSpace($Extension)) { '' } else { $Extension.ToLower() }

    if ($DetectedType -eq 'PE/EXE/DLL' -and $script:SuspiciousIfBinary.ContainsKey($ext)) { return 'CRITICO' }
    if (@('PE/EXE/DLL','ELF','Mach-O (32)','Mach-O (64)','Mach-O Universal','DEX (Android)','WASM') -contains $DetectedType) { return 'ALTO' }
    if (@('OLE2/Compound','Java Class','CAB Archive','RAR SFX') -contains $DetectedType) { return 'MEDIO' }
    return 'BAJO'
}

function Get-FilesRecursive {
    param ([string]$RootPath, [string[]]$ExcludePaths = @())

    $SkipDirNames = @{}
    @('node_modules','.git','.hg','.svn','__pycache__','.venv','venv','.tox',
      'bower_components','.nuget','packages','.cargo','.rustup','.gradle',
      '.m2','target','dist','build','obj','Debug','Release',
      '$Recycle.Bin','System Volume Information','Recovery'
    ) | ForEach-Object { $SkipDirNames[$_] = $true }

    $stack = New-Object System.Collections.Stack
    $stack.Push($RootPath)

    while ($stack.Count -gt 0) {
        $currentDir = $stack.Pop()
        try {
            $files = [System.IO.Directory]::GetFiles($currentDir)
            foreach ($f in $files) { $f }
        } catch {}

        try {
            $dirs = [System.IO.Directory]::GetDirectories($currentDir)
            foreach ($d in $dirs) {
                try {
                    $attr = [System.IO.File]::GetAttributes($d)
                    if ($attr -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                } catch { continue }

                $dirName = [System.IO.Path]::GetFileName($d)
                if ($SkipDirNames.ContainsKey($dirName)) { continue }

                $excluded = $false
                foreach ($ep in $ExcludePaths) {
                    if ($d.Equals($ep, [System.StringComparison]::OrdinalIgnoreCase) -or
                        $d.StartsWith("$ep\", [System.StringComparison]::OrdinalIgnoreCase)) {
                        $excluded = $true
                        break
                    }
                }
                if ($excluded) { continue }
                $stack.Push($d)
            }
        } catch {}
    }
}

$TargetDrives = [System.IO.DriveInfo]::GetDrives() |
    Where-Object { $_.DriveType -eq [System.IO.DriveType]::Fixed -and $_.IsReady } |
    Select-Object -ExpandProperty RootDirectory

$winDir = $env:SystemRoot
$progFiles = $env:ProgramFiles
$progFilesX86 = ${env:ProgramFiles(x86)}
$SystemExcludePaths = @(
    "$winDir\WinSxS",
    "$winDir\System32",
    "$winDir\SysWOW64",
    "$winDir\assembly",
    "$winDir\Microsoft.NET",
    "$winDir\servicing",
    "$winDir\Installer",
    "$winDir\WinStore",
    "$winDir\SystemApps",
    "$winDir\Fonts",
    "$winDir\Boot",
    "$winDir\Globalization",
    "$winDir\IME",
    "$winDir\InputMethod",
    "$winDir\Cursors",
    "$winDir\inf",
    "$winDir\PolicyDefinitions",
    "$winDir\diagnostics",
    "$winDir\rescache",
    "$winDir\Logs",
    "$winDir\Temp",
    "$winDir\Prefetch",
    "$winDir\SoftwareDistribution",
    "$progFiles\Windows Defender",
    "$progFiles\Windows Mail",
    "$progFiles\Windows Media Player",
    "$progFiles\Reference Assemblies",
    "$progFiles\Windows NT",
    "$progFiles\Common Files",
    "$progFiles\WindowsApps"
)
if ($progFilesX86) {
    $SystemExcludePaths += @(
        "$progFilesX86\Windows Defender",
        "$progFilesX86\Windows Mail",
        "$progFilesX86\Windows Media Player",
        "$progFilesX86\Reference Assemblies",
        "$progFilesX86\Windows NT",
        "$progFilesX86\Common Files"
    )
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [*] AUDITORIA GLOBAL DE BINARIOS DISFRAZADOS" -ForegroundColor Cyan
Write-Host "     Detecta: PE, ELF, Mach-O, WASM, DEX, OLE2, CAB" -ForegroundColor DarkCyan
Write-Host "     Unidades: $($TargetDrives.Name -join ', ')" -ForegroundColor Gray
Write-Host "     Tamano max: $([math]::Round($MaxFileSizeBytes / 1MB)) MB" -ForegroundColor Gray
if ($IncludeSystemPaths) {
    Write-Host "     Rutas del sistema: INCLUIDAS" -ForegroundColor Yellow
} else {
    Write-Host "     Rutas del sistema: EXCLUIDAS (-IncludeSystemPaths para incluir)" -ForegroundColor Gray
}
Write-Host "=================================================================" -ForegroundColor Cyan

Write-Host "`n[FASE 1] Indexando archivos candidatos..." -ForegroundColor Yellow
$swPhase1 = [System.Diagnostics.Stopwatch]::StartNew()

$CandidateFiles = New-Object System.Collections.Generic.List[string]
$TotalDiscovered = 0
$excludeList = if ($IncludeSystemPaths) { @() } else { $SystemExcludePaths }

foreach ($drive in $TargetDrives) {
    Write-Host " -> Indexando unidad $($drive.Name)..." -ForegroundColor Gray
    try {
        $files = Get-FilesRecursive -RootPath $drive.FullName -ExcludePaths $excludeList
        foreach ($file in $files) {
            $TotalDiscovered++
            $ext = [System.IO.Path]::GetExtension($file).ToLower()
            if (-not $KnownBinaryExtensions.ContainsKey($ext) -and
                -not $SkipExtensions.ContainsKey($ext) -and
                -not $OLE2DocumentExtensions.ContainsKey($ext)) {
                $CandidateFiles.Add($file)
            }
        }
    }
    catch {
        Write-Warning "Error recorriendo $($drive.Name): $($_.Exception.Message)"
    }
}

$swPhase1.Stop()
Write-Host "[OK] Fase 1: $($swPhase1.Elapsed.TotalSeconds.ToString('F2'))s" -ForegroundColor Green
Write-Host "     Total archivos: $($TotalDiscovered.ToString('N0'))"
Write-Host "     Candidatos: $($CandidateFiles.Count.ToString('N0'))" -ForegroundColor Cyan

Write-Host "`n[FASE 2] Analizando cabeceras binarias..." -ForegroundColor Yellow
$swPhase2 = [System.Diagnostics.Stopwatch]::StartNew()

$Detections = New-Object System.Collections.Generic.List[PSCustomObject]
$processed = 0
$totalCandidates = $CandidateFiles.Count

foreach ($file in $CandidateFiles) {
    $processed++
    if ($processed % 5000 -eq 0 -or $processed -eq $totalCandidates) {
        $percent = [math]::Round(($processed / [math]::Max($totalCandidates, 1)) * 100, 1)
        Write-Progress -Activity "Inspeccionando cabeceras" -Status "$processed / $totalCandidates ($percent%)" -PercentComplete $percent
    }

    try {
        $fInfo = New-Object System.IO.FileInfo($file)
        if ($fInfo.Length -le $MaxFileSizeBytes -and $fInfo.Length -ge 4) {
            $detectedType = Test-BinarySignature -FilePath $file
            if ($detectedType) {
                $ext = [System.IO.Path]::GetExtension($file)
                $risk = Get-RiskLevel -DetectedType $detectedType -Extension $ext

                $riskColor = switch ($risk) {
                    'CRITICO' { 'Magenta' }
                    'ALTO'    { 'Red' }
                    'MEDIO'   { 'Yellow' }
                    default   { 'DarkYellow' }
                }
                Write-Host " [!] $risk - $detectedType disfrazado: $file" -ForegroundColor $riskColor

                $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                $Detections.Add([PSCustomObject]@{
                    Riesgo       = $risk
                    TipoBinario  = $detectedType
                    Extension    = if ([string]::IsNullOrWhiteSpace($ext)) { '[SIN EXTENSION]' } else { $ext }
                    SizeKB       = [math]::Round($fInfo.Length / 1KB, 2)
                    Created      = $fInfo.CreationTime.ToString('yyyy-MM-dd HH:mm')
                    LastModified = $fInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                    SHA256       = $hash
                    Path         = $file
                })
            }
        }
    } catch {}
}

$swPhase2.Stop()
Write-Progress -Activity "Inspeccionando cabeceras" -Completed

$detCount = $Detections.Count
$resultColor = if ($detCount -gt 0) { 'Red' } else { 'Green' }

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [*] AUDITORIA COMPLETADA" -ForegroundColor Cyan
Write-Host "     Fase 1: $($swPhase1.Elapsed.TotalSeconds.ToString('F2'))s | Fase 2: $($swPhase2.Elapsed.TotalSeconds.ToString('F2'))s | Total: $(($swPhase1.Elapsed + $swPhase2.Elapsed).TotalSeconds.ToString('F2'))s"
Write-Host "     Binarios disfrazados: $detCount" -ForegroundColor $resultColor
Write-Host "=================================================================" -ForegroundColor Cyan

if ($detCount -gt 0) {
    Write-Host "`n[POR TIPO]" -ForegroundColor Yellow
    $Detections | Group-Object TipoBinario | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Gray
    }

    Write-Host "`n[POR RIESGO]" -ForegroundColor Yellow
    $riskOrder = @{ 'CRITICO' = 0; 'ALTO' = 1; 'MEDIO' = 2; 'BAJO' = 3 }
    $Detections | Group-Object Riesgo | Sort-Object { $riskOrder[$_.Name] } | ForEach-Object {
        $color = switch ($_.Name) { 'CRITICO' { 'Magenta' } 'ALTO' { 'Red' } 'MEDIO' { 'Yellow' } default { 'DarkYellow' } }
        Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor $color
    }

    Write-Host ""
    $Detections | Sort-Object { $ro = @{ 'CRITICO'=0;'ALTO'=1;'MEDIO'=2;'BAJO'=3 }; $ro[$_.Riesgo] } |
        Format-Table -Property Riesgo, TipoBinario, Extension, SizeKB, LastModified, Path -AutoSize

    $csvName = Join-Path $PWD "Disguised_Binaries_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Detections | Export-Csv -Path $csvName -NoTypeInformation -Encoding UTF8
    Write-Host "[i] Exportado a: $csvName" -ForegroundColor Green
} else {
    Write-Host "`n[OK] No se detectaron binarios encubiertos." -ForegroundColor Green
}