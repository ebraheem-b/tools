# EFI Checker
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Iniciando analisis forense EFI avanzado..." -ForegroundColor Cyan

function Get-FileEntropy {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -eq 0) { return 0 }
        $freq = @{}
        foreach ($b in $bytes) {
            if ($freq.ContainsKey($b)) { $freq[$b]++ } else { $freq[$b] = 1 }
        }
        $entropy = 0.0
        $len = $bytes.Length
        foreach ($count in $freq.Values) {
            $p = $count / $len
            if ($p -gt 0) { $entropy -= $p * [Math]::Log($p, 2) }
        }
        return [Math]::Round($entropy, 3)
    } catch { return -1 }
}

function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        "CRITICO"    { return [System.Drawing.Color]::FromArgb(255, 220, 220) }
        "ALTO"       { return [System.Drawing.Color]::FromArgb(255, 240, 200) }
        "MEDIO"      { return [System.Drawing.Color]::FromArgb(255, 255, 210) }
        "INFO"       { return [System.Drawing.Color]::FromArgb(220, 240, 255) }
        "OK"         { return [System.Drawing.Color]::FromArgb(220, 255, 220) }
        default      { return [System.Drawing.Color]::White }
    }
}

$BootkitPatterns = @(
    "blacklotus", "especter", "lojax", "mosaic", "cosmicstrand",
    "moonbounce", "trickbot", "finspy", "vector-edk", "hacking ?team",
    "rovnix", "gapz", "thunderstrike", "dreamboot", "rkloader",
    "boothole", "baton ?drop", "eset", "kaspersky.*efi.*hack"
)
$BootkitRegex = "(" + ($BootkitPatterns -join "|") + ")"

$KnownLegitEfi = @(
    "bootmgfw.efi", "bootmgr.efi", "memtest.efi", "bootx64.efi",
    "bootia32.efi", "bootaa64.efi", "grubx64.efi", "shimx64.efi",
    "mmx64.efi", "fbia32.efi", "fbx64.efi", "wudfrd.efi",
    "securebootrecovery.efi", "bootmgr.efi.mui", "memtest.efi.mui",
    "winia32.efi", "winload.efi", "winresume.efi", "winload.efi.mui",
    "kdnet_uart16550.efi", "kdstub.efi", "kdnet.efi"
)

$espLetter = "S"
$espRoot = "${espLetter}:\"
$espMounted = Test-Path "${espLetter}:\EFI"

if (-not $espMounted) {
    Write-Host "[*] Montando particion EFI en ${espLetter}: ..." -ForegroundColor Yellow
    mountvol "${espLetter}:" /s
    Start-Sleep -Seconds 2
}

if (-not (Test-Path $espRoot)) {
    Write-Host "[ERROR] No se pudo acceder a la particion EFI." -ForegroundColor Red
    Write-Host "        Asegurate de ejecutar como Administrador." -ForegroundColor Red
    Read-Host "Pulsa Enter para salir"
    exit
}

Write-Host "[OK] Particion EFI accesible: ${espLetter}:" -ForegroundColor Green

Write-Host "[*] Escaneando archivos de la ESP..." -ForegroundColor Cyan

$allFiles = Get-ChildItem $espRoot -Recurse -Force -File
$allDirs = Get-ChildItem $espRoot -Recurse -Force -Directory
$efiFiles = $allFiles | Where-Object { $_.Extension -ieq ".efi" }

Write-Host "[*] Analizando firmas, hashes y entropia de $($efiFiles.Count) archivos .EFI..." -ForegroundColor Cyan

$efiAnalysis = foreach ($file in $efiFiles) {
    $sig = Get-AuthenticodeSignature $file.FullName
    $publisher = "SIN CERTIFICADO"
    $serialNumber = ""
    $thumbprint = ""
    $certExpiry = ""
    $certValid = $false

    if ($sig.SignerCertificate) {
        $publisher = $sig.SignerCertificate.Subject
        $serialNumber = $sig.SignerCertificate.SerialNumber
        $thumbprint = $sig.SignerCertificate.Thumbprint
        $certExpiry = $sig.SignerCertificate.NotAfter.ToString("yyyy-MM-dd")
        $certValid = ($sig.SignerCertificate.NotAfter -gt (Get-Date))
    }

    $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash
    $entropy = Get-FileEntropy $file.FullName

    $relPath = $file.FullName.Substring($espRoot.Length)

    $inNormalPath = ($relPath -like "EFI\Microsoft\*") -or ($relPath -like "EFI\Boot\*")
    $isKnownName = $KnownLegitEfi -contains $file.Name.ToLower()
    $isSuspiciousName = $file.Name -imatch $BootkitRegex

    $tsAnomaly = ($file.LastWriteTime -lt (Get-Date "2018-01-01")) -or ($file.LastWriteTime -gt (Get-Date).AddDays(1))
    $creationAnomaly = ($file.CreationTime -lt (Get-Date "2018-01-01")) -or ($file.CreationTime -gt (Get-Date).AddDays(1))

    $severity = "OK"
    $alerts = @()

    if ($sig.Status -ne "Valid") {
        $severity = "CRITICO"
        $alerts += "Firma invalida: $($sig.Status)"
    }
    if ($sig.Status -eq "Valid" -and -not ($publisher -match "Microsoft")) {
        if ($severity -eq "OK") { $severity = "MEDIO" }
        $alerts += "Firmante no-Microsoft: $publisher"
    }
    if (-not $certValid -and $sig.SignerCertificate) {
        if ($severity -ne "CRITICO") { $severity = "ALTO" }
        $alerts += "Certificado expirado: $certExpiry"
    }
    if (-not $inNormalPath) {
        if ($severity -eq "OK") { $severity = "ALTO" }
        $alerts += "Fuera de ruta habitual (EFI\Microsoft o EFI\Boot)"
    }
    if (-not $isKnownName) {
        if ($severity -eq "OK") { $severity = "MEDIO" }
        $alerts += "Nombre no reconocido como EFI legitimo estandar"
    }
    if ($isSuspiciousName) {
        $severity = "CRITICO"
        $alerts += "Nombre coincide con patron de bootkit conocido"
    }
    if ($entropy -gt 7.5) {
        if ($severity -eq "OK") { $severity = "ALTO" }
        $alerts += "Entropia alta ($entropy) - posible empaquetado/cifrado"
    }
    if ($tsAnomaly -or $creationAnomaly) {
        if ($severity -eq "OK") { $severity = "MEDIO" }
        $alerts += "Anomalia de timestamp (fecha sospechosa)"
    }

    if ($alerts.Count -eq 0) { $alerts += "Sin anomalias detectadas" }

    [PSCustomObject]@{
        Archivo       = $file.Name
        RutaCompleta  = $file.FullName
        RutaRelativa  = $relPath
        Tamano        = $file.Length
        Modificado    = $file.LastWriteTime
        Creado        = $file.CreationTime
        Firma         = $sig.Status.ToString()
        Firmante      = $publisher
        SerialCert    = $serialNumber
        Thumbprint    = $thumbprint
        CertExpira    = $certExpiry
        CertVigente   = $certValid
        SHA256        = $hash
        Entropia      = $entropy
        RutaNormal    = $inNormalPath
        NombreConocido= $isKnownName
        Severidad     = $severity
        Alertas       = ($alerts -join " | ")
    }
}
Write-Host "[*] Buscando archivos ocultos y Alternate Data Streams..." -ForegroundColor Cyan

$hiddenFiles = $allFiles | Where-Object {
    $_.Attributes -band [System.IO.FileAttributes]::Hidden
}

# ADS detection
$adsResults = @()
foreach ($f in $allFiles) {
    try {
        $streams = Get-Item $f.FullName -Stream * -ErrorAction SilentlyContinue |
            Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne '' }
        if ($streams) {
            foreach ($s in $streams) {
                $adsResults += [PSCustomObject]@{
                    Archivo = $f.FullName
                    Stream  = $s.Stream
                    Tamano  = $s.Length
                }
            }
        }
    } catch {}
}

# --- Archivos no-EFI sospechosos ---
$suspiciousNonEfi = $allFiles | Where-Object {
    $_.Extension -imatch "\.(dll|sys|exe|bat|cmd|ps1|vbs|js|bin|dat|cfg|inf)$" -or
    $_.Name -imatch "boot|loader|shim|grub|start|launch|hack|inject|patch|hook"
}

# --- Secure Boot ---
Write-Host "[*] Verificando estado de Secure Boot..." -ForegroundColor Cyan

$secureBootStatus = "Desconocido"
$secureBootColor = "MEDIO"
try {
    $sb = Confirm-SecureBootUEFI
    if ($sb) {
        $secureBootStatus = "ACTIVADO"
        $secureBootColor = "OK"
    } else {
        $secureBootStatus = "DESACTIVADO"
        $secureBootColor = "CRITICO"
    }
} catch {
    $secureBootStatus = "No soportado / No disponible"
    $secureBootColor = "MEDIO"
}

# --- Modo Firmware ---
$firmwareType = "Desconocido"
try {
    $firmwareType = (Get-ComputerInfo).BiosFirmwareType
} catch {}

# --- TPM ---
Write-Host "[*] Consultando estado del TPM..." -ForegroundColor Cyan
$tpmInfo = $null
try {
    $tpmInfo = Get-Tpm -ErrorAction SilentlyContinue
} catch {}

# --- BCD ---
Write-Host "[*] Leyendo configuracion BCD..." -ForegroundColor Cyan
$bcdOutput = bcdedit /enum all 2>&1 | Out-String
$bcdFirmware = bcdedit /enum firmware 2>&1 | Out-String

# --- Secure Boot Policy DB/DBX ---
Write-Host "[*] Consultando bases de datos Secure Boot (DB/DBX)..." -ForegroundColor Cyan
$dbInfo = ""
try {
    $dbVars = Get-SecureBootPolicy -ErrorAction SilentlyContinue
    if ($dbVars) { $dbInfo = $dbVars | Out-String }
} catch {}

# Si no hay cmdlet, intentar via registro
if ([string]::IsNullOrEmpty($dbInfo)) {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        if (Test-Path $regPath) {
            $dbInfo = "Secure Boot Registry Keys:`r`n"
            $dbInfo += (Get-ItemProperty $regPath | Out-String)
            $availUpdates = Get-ItemProperty "$regPath\AvailableUpdates" -ErrorAction SilentlyContinue
            if ($availUpdates) {
                $dbInfo += "`r`nAvailable Updates:`r`n" + ($availUpdates | Out-String)
            }
        }
    } catch {}
}

# --- Volumenes FAT32 ---
$fat32Volumes = Get-Volume | Where-Object { $_.FileSystem -eq "FAT32" } |
    Select-Object DriveLetter, FileSystemLabel, FileSystem,
        @{N='TamanoMB';E={[math]::Round($_.Size/1MB,1)}},
        @{N='LibreMB';E={[math]::Round($_.SizeRemaining/1MB,1)}}

# --- EFI en otros volumenes ---
Write-Host "[*] Buscando .EFI en otros volumenes..." -ForegroundColor Cyan
$otherEfi = @()
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -ne $espLetter }
foreach ($drive in $drives) {
    $root = "$($drive.Name):\"
    $found = Get-ChildItem $root -Recurse -Force -File -Filter "*.efi" -ErrorAction SilentlyContinue
    if ($found) {
        foreach ($f in $found) {
            $otherEfi += [PSCustomObject]@{
                Volumen   = $drive.Name
                Archivo   = $f.FullName
                Tamano    = $f.Length
                Modificado= $f.LastWriteTime
            }
        }
    }
}

# --- Kernel-Boot Events ---
Write-Host "[*] Consultando eventos Kernel-Boot y TPM..." -ForegroundColor Cyan

$bootEvents = @()
$bootEventIds = @(32, 33, 125)
try {
    $evts = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Kernel-Boot/Operational"
        Id = $bootEventIds
    } -MaxEvents 50 -ErrorAction SilentlyContinue

    foreach ($e in $evts) {
        $bootEvents += [PSCustomObject]@{
            Fecha   = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventID = $e.Id
            Tipo    = switch ($e.Id) {
                32  { "Boot Integrity Policy" }
                33  { "Hypervisor Load Status" }
                125 { "Secure Boot Validation" }
            }
            Mensaje = ($e.Message -replace "`r`n"," " -replace "\s+"," ").Trim()
        }
    }
} catch {}

# TPM events from System log
$tpmEvents = @()
try {
    $tEvts = Get-WinEvent -FilterHashtable @{
        LogName = "System"
        ProviderName = "Microsoft-Windows-TPM-WMI"
    } -MaxEvents 30 -ErrorAction SilentlyContinue

    foreach ($e in $tEvts) {
        $tpmEvents += [PSCustomObject]@{
            Fecha   = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventID = $e.Id
            Nivel   = $e.LevelDisplayName
            Mensaje = ($e.Message -replace "`r`n"," " -replace "\s+"," ").Trim()
        }
    }
} catch {}

# Measured Boot / Integrity events
$measuredBootEvents = @()
try {
    $mbEvts = Get-WinEvent -FilterHashtable @{
        LogName = "System"
        ProviderName = @("Microsoft-Windows-Kernel-Boot", "Microsoft-Windows-Measured-Boot")
    } -MaxEvents 30 -ErrorAction SilentlyContinue

    foreach ($e in $mbEvts) {
        $measuredBootEvents += [PSCustomObject]@{
            Fecha    = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventID  = $e.Id
            Origen   = $e.ProviderName
            Nivel    = $e.LevelDisplayName
            Mensaje  = ($e.Message -replace "`r`n"," " -replace "\s+"," ").Trim()
        }
    }
} catch {}


Write-Host "[+] Recoleccion completada. Construyendo interfaz..." -ForegroundColor Green

# ============================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "EFI Forensic Check - Analisis Avanzado"
$form.Size = New-Object System.Drawing.Size(1280, 800)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.ForeColor = [System.Drawing.Color]::White
try { $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon((Get-Process -id $PID).Path) } catch {}

$fontNormal = New-Object System.Drawing.Font("Segoe UI", 9)
$fontBold = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$fontTitle = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$fontMono = New-Object System.Drawing.Font("Consolas", 9.5)

$darkBg = [System.Drawing.Color]::FromArgb(30, 30, 30)
$panelBg = [System.Drawing.Color]::FromArgb(45, 45, 45)
$accentBlue = [System.Drawing.Color]::FromArgb(0, 120, 215)
$textWhite = [System.Drawing.Color]::White
$textGray = [System.Drawing.Color]::FromArgb(180, 180, 180)

$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Dock = "Top"
$headerPanel.Height = 100
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 40)
$form.Controls.Add($headerPanel)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "UEFI / EFI FORENSIC CHECK"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = $accentBlue
$lblTitle.Location = New-Object System.Drawing.Point(20, 10)
$lblTitle.AutoSize = $true
$headerPanel.Controls.Add($lblTitle)

$critCount = ($efiAnalysis | Where-Object Severidad -eq "CRITICO").Count
$altoCount = ($efiAnalysis | Where-Object Severidad -eq "ALTO").Count
$medioCount = ($efiAnalysis | Where-Object Severidad -eq "MEDIO").Count
$okCount = ($efiAnalysis | Where-Object Severidad -eq "OK").Count

$summaryText = "Archivos ESP: $($allFiles.Count)  |  "
$summaryText += "EFI totales: $($efiFiles.Count)  |  "
$summaryText += "Secure Boot: $secureBootStatus  |  "
$summaryText += "Firmware: $firmwareType  |  "
$summaryText += "Ocultos: $($hiddenFiles.Count)  |  "
$summaryText += "ADS: $($adsResults.Count)"

$lblSummary = New-Object System.Windows.Forms.Label
$lblSummary.Text = $summaryText
$lblSummary.Font = $fontNormal
$lblSummary.ForeColor = $textGray
$lblSummary.Location = New-Object System.Drawing.Point(20, 45)
$lblSummary.AutoSize = $true
$headerPanel.Controls.Add($lblSummary)

$sevX = 20
$sevY = 70
foreach ($sevItem in @(
    @{Label="CRITICO: $critCount"; Color=[System.Drawing.Color]::FromArgb(220,50,50)},
    @{Label="ALTO: $altoCount"; Color=[System.Drawing.Color]::FromArgb(255,165,0)},
    @{Label="MEDIO: $medioCount"; Color=[System.Drawing.Color]::FromArgb(255,220,50)},
    @{Label="OK: $okCount"; Color=[System.Drawing.Color]::FromArgb(50,200,50)}
)) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = [char]0x25CF  # circulo
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 12)
    $lbl.ForeColor = $sevItem.Color
    $lbl.Location = New-Object System.Drawing.Point($sevX, $sevY)
    $lbl.AutoSize = $true
    $headerPanel.Controls.Add($lbl)
    $sevX += 18

    $lbl2 = New-Object System.Windows.Forms.Label
    $lbl2.Text = $sevItem.Label
    $lbl2.Font = $fontBold
    $lbl2.ForeColor = $sevItem.Color
    $lbl2.Location = New-Object System.Drawing.Point($sevX, ($sevY + 2))
    $lbl2.AutoSize = $true
    $headerPanel.Controls.Add($lbl2)
    $sevX += 110
}

$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = "Fill"
$tabControl.Font = $fontBold
$tabControl.Padding = New-Object System.Drawing.Point(12, 6)
$form.Controls.Add($tabControl)
$form.Controls.SetChildIndex($tabControl, 0)


function New-StyledGrid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = "Fill"
    $g.AutoSizeColumnsMode = "Fill"
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.ReadOnly = $true
    $g.SelectionMode = "FullRowSelect"
    $g.BackgroundColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
    $g.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
    $g.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $g.DefaultCellStyle.SelectionBackColor = $accentBlue
    $g.DefaultCellStyle.Font = $fontNormal
    $g.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $g.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $g.ColumnHeadersDefaultCellStyle.Font = $fontBold
    $g.EnableHeadersVisualStyles = $false
    $g.RowHeadersVisible = $false
    $g.GridColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $g.BorderStyle = "None"
    $g.CellBorderStyle = "SingleHorizontal"
    return $g
}

function Show-RowDetail {
    param(
        [System.Windows.Forms.DataGridView]$Grid,
        [int]$RowIndex,
        [string]$Title = "Detalle"
    )
    if ($RowIndex -lt 0) { return }
    $row = $Grid.Rows[$RowIndex]

    $detForm = New-Object System.Windows.Forms.Form
    $detForm.Text = $Title
    $detForm.Size = New-Object System.Drawing.Size(850, 550)
    $detForm.StartPosition = "CenterParent"
    $detForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Multiline = $true
    $txt.ReadOnly = $true
    $txt.ScrollBars = "Both"
    $txt.Dock = "Fill"
    $txt.Font = $fontMono
    $txt.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
    $txt.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 150)
    $txt.WordWrap = $true

    $lines = "==================== DETALLE COMPLETO ====================`r`n`r`n"
    foreach ($col in $Grid.Columns) {
        $colName = $col.Name
        $val = $row.Cells[$colName].Value
        if ($null -eq $val) { $val = "" }
        $valStr = $val.ToString()
        $padded = $colName.PadRight(18)
        if ($valStr.Length -gt 120) {
            $lines += "${padded}: `r`n$valStr`r`n`r`n"
        } else {
            $lines += "${padded}: $valStr`r`n"
        }
    }
    $lines += "`r`n========================================================"

    $txt.Text = $lines
    $txt.SelectionStart = 0
    $txt.SelectionLength = 0
    $detForm.Controls.Add($txt)

    $btnCopy = New-Object System.Windows.Forms.Button
    $btnCopy.Text = "Copiar al Portapapeles"
    $btnCopy.Dock = "Bottom"
    $btnCopy.Height = 35
    $btnCopy.BackColor = [System.Drawing.Color]::FromArgb(0, 100, 180)
    $btnCopy.ForeColor = [System.Drawing.Color]::White
    $btnCopy.FlatStyle = "Flat"
    $btnCopy.Font = $fontBold
    $btnCopy.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnCopy.Add_Click({
        [System.Windows.Forms.Clipboard]::SetText($txt.Text)
        $btnCopy.Text = "Copiado!"
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 1500
        $timer.Add_Tick({ $btnCopy.Text = "Copiar al Portapapeles"; $timer.Stop() })
        $timer.Start()
    })
    $detForm.Controls.Add($btnCopy)

    [void]$detForm.ShowDialog()
}


$tab1 = New-Object System.Windows.Forms.TabPage
$tab1.Text = "Analisis EFI"
$tab1.BackColor = $darkBg
$tabControl.TabPages.Add($tab1)

$filterPanel1 = New-Object System.Windows.Forms.Panel
$filterPanel1.Dock = "Top"
$filterPanel1.Height = 45
$filterPanel1.BackColor = $panelBg
$tab1.Controls.Add($filterPanel1)

$lblSevFilter = New-Object System.Windows.Forms.Label
$lblSevFilter.Text = "Filtrar por severidad:"
$lblSevFilter.Font = $fontBold
$lblSevFilter.ForeColor = $textWhite
$lblSevFilter.Location = New-Object System.Drawing.Point(15, 12)
$lblSevFilter.AutoSize = $true
$filterPanel1.Controls.Add($lblSevFilter)

$comboSev = New-Object System.Windows.Forms.ComboBox
$comboSev.Location = New-Object System.Drawing.Point(170, 9)
$comboSev.Width = 140
$comboSev.DropDownStyle = "DropDownList"
$comboSev.Font = $fontNormal
$comboSev.Items.AddRange(@("Todos", "CRITICO", "ALTO", "MEDIO", "OK"))
$comboSev.SelectedIndex = 0
$filterPanel1.Controls.Add($comboSev)

$lblSearchEfi = New-Object System.Windows.Forms.Label
$lblSearchEfi.Text = "Buscar:"
$lblSearchEfi.Font = $fontBold
$lblSearchEfi.ForeColor = $textWhite
$lblSearchEfi.Location = New-Object System.Drawing.Point(340, 12)
$lblSearchEfi.AutoSize = $true
$filterPanel1.Controls.Add($lblSearchEfi)

$txtSearchEfi = New-Object System.Windows.Forms.TextBox
$txtSearchEfi.Location = New-Object System.Drawing.Point(400, 9)
$txtSearchEfi.Width = 250
$txtSearchEfi.Font = $fontNormal
$filterPanel1.Controls.Add($txtSearchEfi)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = "Exportar CSV"
$btnExport.Location = New-Object System.Drawing.Point(680, 7)
$btnExport.Size = New-Object System.Drawing.Size(120, 30)
$btnExport.BackColor = [System.Drawing.Color]::FromArgb(0, 100, 180)
$btnExport.ForeColor = $textWhite
$btnExport.FlatStyle = "Flat"
$btnExport.Font = $fontBold
$btnExport.Cursor = [System.Windows.Forms.Cursors]::Hand
$filterPanel1.Controls.Add($btnExport)

$grid1 = New-StyledGrid
$tab1.Controls.Add($grid1)
$tab1.Controls.SetChildIndex($grid1, 0)

$dt1 = New-Object System.Data.DataTable
$dt1.Columns.Add("Severidad", [string]) | Out-Null
$dt1.Columns.Add("Archivo", [string]) | Out-Null
$dt1.Columns.Add("Ruta", [string]) | Out-Null
$dt1.Columns.Add("Tamano", [int64]) | Out-Null
$dt1.Columns.Add("Modificado", [datetime]) | Out-Null
$dt1.Columns.Add("Firma", [string]) | Out-Null
$dt1.Columns.Add("Firmante", [string]) | Out-Null
$dt1.Columns.Add("Entropia", [double]) | Out-Null
$dt1.Columns.Add("SHA256", [string]) | Out-Null
$dt1.Columns.Add("Alertas", [string]) | Out-Null

foreach ($efi in $efiAnalysis) {
    $r = $dt1.NewRow()
    $r["Severidad"] = $efi.Severidad
    $r["Archivo"] = $efi.Archivo
    $r["Ruta"] = $efi.RutaRelativa
    $r["Tamano"] = $efi.Tamano
    $r["Modificado"] = $efi.Modificado
    $r["Firma"] = $efi.Firma
    $r["Firmante"] = $efi.Firmante
    $r["Entropia"] = $efi.Entropia
    $r["SHA256"] = $efi.SHA256
    $r["Alertas"] = $efi.Alertas
    $dt1.Rows.Add($r)
}

$dv1 = New-Object System.Data.DataView($dt1)
$grid1.DataSource = $dv1

$grid1.Add_CellFormatting({
    param($sender, $e)
    if ($e.RowIndex -ge 0 -and $sender.Columns[$e.ColumnIndex].Name -eq "Severidad") {
        $val = $sender.Rows[$e.RowIndex].Cells["Severidad"].Value
        $color = Get-SeverityColor $val
        $e.CellStyle.BackColor = $color
        $e.CellStyle.ForeColor = [System.Drawing.Color]::Black
    }
})

$grid1.Add_CellDoubleClick({
    param($sender, $e)
    if ($e.RowIndex -ge 0) {
        $row = $sender.Rows[$e.RowIndex]
        $archivo = $row.Cells["Archivo"].Value
        $match = $efiAnalysis | Where-Object { $_.Archivo -eq $archivo } | Select-Object -First 1
        if ($match) {
            $detForm = New-Object System.Windows.Forms.Form
            $detForm.Text = "Detalle EFI: $archivo"
            $detForm.Size = New-Object System.Drawing.Size(800, 550)
            $detForm.StartPosition = "CenterParent"
            $detForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

            $txt = New-Object System.Windows.Forms.TextBox
            $txt.Multiline = $true
            $txt.ReadOnly = $true
            $txt.ScrollBars = "Both"
            $txt.Dock = "Fill"
            $txt.Font = $fontMono
            $txt.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
            $txt.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 150)
            $txt.WordWrap = $false

            $detail = @"
================== DETALLE FORENSE ==================

Archivo       : $($match.Archivo)
Ruta Completa : $($match.RutaCompleta)
Ruta Relativa : $($match.RutaRelativa)
Tamano        : $($match.Tamano) bytes
Fecha Creacion: $($match.Creado)
Fecha Modif.  : $($match.Modificado)

--- FIRMA DIGITAL ---
Estado        : $($match.Firma)
Firmante      : $($match.Firmante)
Serial Cert.  : $($match.SerialCert)
Thumbprint    : $($match.Thumbprint)
Cert. Expira  : $($match.CertExpira)
Cert. Vigente : $($match.CertVigente)

--- INTEGRIDAD ---
SHA256        : $($match.SHA256)
Entropia      : $($match.Entropia) / 8.0
Ruta Normal   : $($match.RutaNormal)
Nombre Conocido: $($match.NombreConocido)

--- VEREDICTO ---
Severidad     : $($match.Severidad)
Alertas       : $($match.Alertas)

======================================================
"@
            $txt.Text = $detail
            $txt.SelectionStart = 0
            $txt.SelectionLength = 0
            $detForm.Controls.Add($txt)
            [void]$detForm.ShowDialog()
        }
    }
})

$applyEfiFilter = {
    $parts = @()
    if ($comboSev.SelectedItem -ne "Todos") {
        $parts += "Severidad = '$($comboSev.SelectedItem)'"
    }
    if (![string]::IsNullOrWhiteSpace($txtSearchEfi.Text)) {
        $s = $txtSearchEfi.Text -replace "'","''"
        $parts += "(Archivo LIKE '%$s%' OR Ruta LIKE '%$s%' OR Firmante LIKE '%$s%' OR Alertas LIKE '%$s%' OR SHA256 LIKE '%$s%')"
    }
    if ($parts.Count -gt 0) {
        $dv1.RowFilter = $parts -join " AND "
    } else {
        $dv1.RowFilter = ""
    }
}

$comboSev.Add_SelectedIndexChanged($applyEfiFilter)
$txtSearchEfi.Add_KeyDown({ if ($_.KeyCode -eq 'Enter') { & $applyEfiFilter } })

$btnExport.Add_Click({
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "CSV (*.csv)|*.csv"
    $sfd.FileName = "efi_forensic_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -eq "OK") {
        $efiAnalysis | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Exportado a:`n$($sfd.FileName)", "Exportacion", "OK", "Information")
    }
})


$tab2 = New-Object System.Windows.Forms.TabPage
$tab2.Text = "Alertas / Hallazgos"
$tab2.BackColor = $darkBg
$tabControl.TabPages.Add($tab2)

$txtAlerts = New-Object System.Windows.Forms.TextBox
$txtAlerts.Multiline = $true
$txtAlerts.ReadOnly = $true
$txtAlerts.ScrollBars = "Both"
$txtAlerts.Dock = "Fill"
$txtAlerts.Font = $fontMono
$txtAlerts.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$txtAlerts.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 100)
$txtAlerts.WordWrap = $false

$alertText = "==================== INFORME DE HALLAZGOS ====================`r`n"
$alertText += "Fecha del analisis: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n"
$alertText += "Equipo: $env:COMPUTERNAME`r`n"
$alertText += "===============================================================`r`n`r`n"

$alertText += "[SECURE BOOT] Estado: $secureBootStatus`r`n"
if ($secureBootStatus -ne "ACTIVADO") {
    $alertText += "  >> ALERTA: Secure Boot no esta activo. Bootkits pueden cargarse sin restriccion.`r`n"
}
$alertText += "`r`n"

if ($tpmInfo) {
    $alertText += "[TPM] Presente: $($tpmInfo.TpmPresent) | Listo: $($tpmInfo.TpmReady) | Habilitado: $($tpmInfo.TpmEnabled)`r`n"
    if (-not $tpmInfo.TpmReady) {
        $alertText += "  >> ALERTA: TPM no esta listo. La cadena de medicion de arranque puede estar comprometida.`r`n"
    }
} else {
    $alertText += "[TPM] No se pudo consultar el estado del TPM.`r`n"
}
$alertText += "`r`n"

$alertText += "--- ARCHIVOS EFI CON ALERTAS ---`r`n`r`n"
$critEfis = $efiAnalysis | Where-Object { $_.Severidad -ne "OK" } | Sort-Object {
    switch ($_.Severidad) { "CRITICO" {0} "ALTO" {1} "MEDIO" {2} default {3} }
}

if ($critEfis.Count -eq 0) {
    $alertText += "  [OK] No se encontraron archivos EFI con anomalias.`r`n"
} else {
    foreach ($ce in $critEfis) {
        $alertText += "  [$($ce.Severidad)] $($ce.RutaRelativa)`r`n"
        $alertText += "         Firma: $($ce.Firma) | Entropia: $($ce.Entropia) | SHA256: $($ce.SHA256.Substring(0,16))...`r`n"
        $alertText += "         -> $($ce.Alertas)`r`n`r`n"
    }
}

$alertText += "--- ARCHIVOS OCULTOS EN ESP ---`r`n`r`n"
if ($hiddenFiles.Count -eq 0) {
    $alertText += "  [OK] No hay archivos ocultos.`r`n"
} else {
    foreach ($hf in $hiddenFiles) {
        $alertText += "  [ALTO] $($hf.FullName) (Tamano: $($hf.Length), Mod: $($hf.LastWriteTime))`r`n"
    }
}
$alertText += "`r`n"

$alertText += "--- ALTERNATE DATA STREAMS ---`r`n`r`n"
if ($adsResults.Count -eq 0) {
    $alertText += "  [OK] No se encontraron ADS sospechosos.`r`n"
} else {
    foreach ($ads in $adsResults) {
        $alertText += "  [CRITICO] $($ads.Archivo) -> Stream: $($ads.Stream) (Tamano: $($ads.Tamano))`r`n"
    }
}
$alertText += "`r`n"

$alertText += "--- ARCHIVOS SOSPECHOSOS NO-EFI EN ESP ---`r`n`r`n"
$nonEfiList = $suspiciousNonEfi | Where-Object { $_.Extension -ine ".efi" }
if ($nonEfiList.Count -eq 0) {
    $alertText += "  [OK] No se encontraron archivos sospechosos no-EFI.`r`n"
} else {
    foreach ($nef in $nonEfiList) {
        $alertText += "  [MEDIO] $($nef.FullName) ($($nef.Length) bytes, Mod: $($nef.LastWriteTime))`r`n"
    }
}
$alertText += "`r`n"

$alertText += "--- .EFI EN OTROS VOLUMENES ---`r`n`r`n"
if ($otherEfi.Count -eq 0) {
    $alertText += "  [OK] No se encontraron .EFI fuera de la ESP.`r`n"
} else {
    foreach ($oe in $otherEfi) {
        $alertText += "  [MEDIO] [$($oe.Volumen):] $($oe.Archivo) ($($oe.Tamano) bytes)`r`n"
    }
}
$alertText += "`r`n"

$alertText += "--- VOLUMENES FAT32 ---`r`n`r`n"
foreach ($v in $fat32Volumes) {
    $alertText += "  $($v.DriveLetter): $($v.FileSystemLabel) - $($v.TamanoMB) MB (Libre: $($v.LibreMB) MB)`r`n"
}

$alertText += "`r`n===============================================================`r`n"
$alertText += "FIN DEL INFORME - Este script es SOLO de lectura.`r`n"
$alertText += "No elimina, reemplaza ni modifica ningun archivo.`r`n"
$alertText += "===============================================================`r`n"

$txtAlerts.Text = $alertText
$tab2.Controls.Add($txtAlerts)


$tab3 = New-Object System.Windows.Forms.TabPage
$tab3.Text = "Inventario ESP"
$tab3.BackColor = $darkBg
$tabControl.TabPages.Add($tab3)

$grid3 = New-StyledGrid
$tab3.Controls.Add($grid3)

$dt3 = New-Object System.Data.DataTable
$dt3.Columns.Add("Archivo", [string]) | Out-Null
$dt3.Columns.Add("Ruta", [string]) | Out-Null
$dt3.Columns.Add("Extension", [string]) | Out-Null
$dt3.Columns.Add("Tamano", [int64]) | Out-Null
$dt3.Columns.Add("Modificado", [datetime]) | Out-Null
$dt3.Columns.Add("Atributos", [string]) | Out-Null

foreach ($f in $allFiles) {
    $r3 = $dt3.NewRow()
    $r3["Archivo"] = $f.Name
    $r3["Ruta"] = $f.FullName
    $r3["Extension"] = $f.Extension
    $r3["Tamano"] = $f.Length
    $r3["Modificado"] = $f.LastWriteTime
    $r3["Atributos"] = $f.Attributes.ToString()
    $dt3.Rows.Add($r3)
}

$dv3 = New-Object System.Data.DataView($dt3)
$dv3.Sort = "Ruta ASC"
$grid3.DataSource = $dv3

$grid3.Add_CellDoubleClick({
    param($sender, $e)
    Show-RowDetail -Grid $sender -RowIndex $e.RowIndex -Title "Detalle Archivo ESP"
})


$tab4 = New-Object System.Windows.Forms.TabPage
$tab4.Text = "Carpetas ESP"
$tab4.BackColor = $darkBg
$tabControl.TabPages.Add($tab4)

$grid4 = New-StyledGrid
$tab4.Controls.Add($grid4)

$dt4 = New-Object System.Data.DataTable
$dt4.Columns.Add("Carpeta", [string]) | Out-Null
$dt4.Columns.Add("Modificado", [datetime]) | Out-Null

foreach ($d in $allDirs) {
    $r4 = $dt4.NewRow()
    $r4["Carpeta"] = $d.FullName
    $r4["Modificado"] = $d.LastWriteTime
    $dt4.Rows.Add($r4)
}

$dv4 = New-Object System.Data.DataView($dt4)
$grid4.DataSource = $dv4

$grid4.Add_CellDoubleClick({
    param($sender, $e)
    Show-RowDetail -Grid $sender -RowIndex $e.RowIndex -Title "Detalle Carpeta ESP"
})


$tab5 = New-Object System.Windows.Forms.TabPage
$tab5.Text = "BCD / Boot Config"
$tab5.BackColor = $darkBg
$tabControl.TabPages.Add($tab5)

$splitBCD = New-Object System.Windows.Forms.SplitContainer
$splitBCD.Dock = "Fill"
$splitBCD.Orientation = "Vertical"
$splitBCD.SplitterDistance = 600
$splitBCD.BackColor = $darkBg
$tab5.Controls.Add($splitBCD)

$txtBCD = New-Object System.Windows.Forms.TextBox
$txtBCD.Multiline = $true
$txtBCD.ReadOnly = $true
$txtBCD.ScrollBars = "Both"
$txtBCD.Dock = "Fill"
$txtBCD.Font = $fontMono
$txtBCD.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$txtBCD.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 255)
$txtBCD.WordWrap = $false
$txtBCD.Text = "===== BCDEDIT /ENUM ALL =====`r`n`r`n$bcdOutput`r`n`r`n===== BCDEDIT /ENUM FIRMWARE =====`r`n`r`n$bcdFirmware"
$splitBCD.Panel1.Controls.Add($txtBCD)

$txtSecureBoot = New-Object System.Windows.Forms.TextBox
$txtSecureBoot.Multiline = $true
$txtSecureBoot.ReadOnly = $true
$txtSecureBoot.ScrollBars = "Both"
$txtSecureBoot.Dock = "Fill"
$txtSecureBoot.Font = $fontMono
$txtSecureBoot.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$txtSecureBoot.ForeColor = [System.Drawing.Color]::FromArgb(200, 255, 200)
$txtSecureBoot.WordWrap = $false

$sbText = "===== SECURE BOOT =====`r`n`r`n"
$sbText += "Estado: $secureBootStatus`r`n"
$sbText += "Firmware: $firmwareType`r`n`r`n"
if ($tpmInfo) {
    $sbText += "===== TPM =====`r`n`r`n"
    $sbText += "Presente : $($tpmInfo.TpmPresent)`r`n"
    $sbText += "Listo    : $($tpmInfo.TpmReady)`r`n"
    $sbText += "Habilitado: $($tpmInfo.TpmEnabled)`r`n"
    $sbText += "Version  : $($tpmInfo.ManufacturerVersion)`r`n`r`n"
}
$sbText += "===== SECURE BOOT DB/DBX =====`r`n`r`n"
if ([string]::IsNullOrEmpty($dbInfo)) {
    $sbText += "No se pudo obtener informacion de DB/DBX.`r`n"
} else {
    $sbText += $dbInfo
}
$txtSecureBoot.Text = $sbText
$splitBCD.Panel2.Controls.Add($txtSecureBoot)


$tab6 = New-Object System.Windows.Forms.TabPage
$tab6.Text = "Eventos Boot/TPM"
$tab6.BackColor = $darkBg
$tabControl.TabPages.Add($tab6)

$splitEvents = New-Object System.Windows.Forms.SplitContainer
$splitEvents.Dock = "Fill"
$splitEvents.Orientation = "Horizontal"
$splitEvents.SplitterDistance = 250
$splitEvents.BackColor = $darkBg
$tab6.Controls.Add($splitEvents)

$lblBootEvt = New-Object System.Windows.Forms.Label
$lblBootEvt.Text = "Eventos Kernel-Boot (IDs 32, 33, 125) - Integridad de Arranque y Secure Boot"
$lblBootEvt.Dock = "Top"
$lblBootEvt.Height = 25
$lblBootEvt.Font = $fontBold
$lblBootEvt.ForeColor = $accentBlue
$lblBootEvt.BackColor = $panelBg
$lblBootEvt.Padding = New-Object System.Windows.Forms.Padding(10, 4, 0, 0)
$splitEvents.Panel1.Controls.Add($lblBootEvt)

$grid6a = New-StyledGrid
$splitEvents.Panel1.Controls.Add($grid6a)
$splitEvents.Panel1.Controls.SetChildIndex($grid6a, 0)

$dt6a = New-Object System.Data.DataTable
$dt6a.Columns.Add("Fecha", [string]) | Out-Null
$dt6a.Columns.Add("EventID", [int32]) | Out-Null
$dt6a.Columns.Add("Tipo", [string]) | Out-Null
$dt6a.Columns.Add("Mensaje", [string]) | Out-Null

foreach ($be in $bootEvents) {
    $r6a = $dt6a.NewRow()
    $r6a["Fecha"] = $be.Fecha
    $r6a["EventID"] = $be.EventID
    $r6a["Tipo"] = $be.Tipo
    $r6a["Mensaje"] = $be.Mensaje
    $dt6a.Rows.Add($r6a)
}
$grid6a.DataSource = $dt6a

$grid6a.Add_CellDoubleClick({
    param($sender, $e)
    Show-RowDetail -Grid $sender -RowIndex $e.RowIndex -Title "Detalle Evento Kernel-Boot"
})

$lblTpmEvt = New-Object System.Windows.Forms.Label
$lblTpmEvt.Text = "Eventos TPM y Measured Boot - Cadena de Confianza"
$lblTpmEvt.Dock = "Top"
$lblTpmEvt.Height = 25
$lblTpmEvt.Font = $fontBold
$lblTpmEvt.ForeColor = $accentBlue
$lblTpmEvt.BackColor = $panelBg
$lblTpmEvt.Padding = New-Object System.Windows.Forms.Padding(10, 4, 0, 0)
$splitEvents.Panel2.Controls.Add($lblTpmEvt)

$grid6b = New-StyledGrid
$splitEvents.Panel2.Controls.Add($grid6b)
$splitEvents.Panel2.Controls.SetChildIndex($grid6b, 0)

$dt6b = New-Object System.Data.DataTable
$dt6b.Columns.Add("Fecha", [string]) | Out-Null
$dt6b.Columns.Add("EventID", [int32]) | Out-Null
$dt6b.Columns.Add("Origen", [string]) | Out-Null
$dt6b.Columns.Add("Nivel", [string]) | Out-Null
$dt6b.Columns.Add("Mensaje", [string]) | Out-Null

$allTpmMb = @()
$allTpmMb += $tpmEvents | ForEach-Object {
    [PSCustomObject]@{ Fecha=$_.Fecha; EventID=$_.EventID; Origen="TPM-WMI"; Nivel=$_.Nivel; Mensaje=$_.Mensaje }
}
$allTpmMb += $measuredBootEvents | ForEach-Object {
    [PSCustomObject]@{ Fecha=$_.Fecha; EventID=$_.EventID; Origen=$_.Origen; Nivel=$_.Nivel; Mensaje=$_.Mensaje }
}

foreach ($tm in $allTpmMb) {
    $r6b = $dt6b.NewRow()
    $r6b["Fecha"] = $tm.Fecha
    $r6b["EventID"] = $tm.EventID
    $r6b["Origen"] = $tm.Origen
    $r6b["Nivel"] = $tm.Nivel
    $r6b["Mensaje"] = $tm.Mensaje
    $dt6b.Rows.Add($r6b)
}
$grid6b.DataSource = $dt6b

$grid6b.Add_CellDoubleClick({
    param($sender, $e)
    Show-RowDetail -Grid $sender -RowIndex $e.RowIndex -Title "Detalle Evento TPM / Measured Boot"
})


$tab7 = New-Object System.Windows.Forms.TabPage
$tab7.Text = "EFI Otros Vol."
$tab7.BackColor = $darkBg
$tabControl.TabPages.Add($tab7)

$grid7 = New-StyledGrid
$tab7.Controls.Add($grid7)

$dt7 = New-Object System.Data.DataTable
$dt7.Columns.Add("Volumen", [string]) | Out-Null
$dt7.Columns.Add("Archivo", [string]) | Out-Null
$dt7.Columns.Add("Tamano", [int64]) | Out-Null
$dt7.Columns.Add("Modificado", [datetime]) | Out-Null

foreach ($oe in $otherEfi) {
    $r7 = $dt7.NewRow()
    $r7["Volumen"] = $oe.Volumen
    $r7["Archivo"] = $oe.Archivo
    $r7["Tamano"] = $oe.Tamano
    $r7["Modificado"] = $oe.Modificado
    $dt7.Rows.Add($r7)
}
$grid7.DataSource = $dt7

$grid7.Add_CellDoubleClick({
    param($sender, $e)
    Show-RowDetail -Grid $sender -RowIndex $e.RowIndex -Title "Detalle EFI en Otro Volumen"
})


$form.Add_Load({
    if ($grid1.Columns.Count -gt 0) {
        $grid1.Columns["Severidad"].FillWeight = 8
        $grid1.Columns["Archivo"].FillWeight = 12
        $grid1.Columns["Ruta"].FillWeight = 15
        $grid1.Columns["Tamano"].FillWeight = 7
        $grid1.Columns["Modificado"].FillWeight = 12
        $grid1.Columns["Modificado"].DefaultCellStyle.Format = "yyyy-MM-dd HH:mm"
        $grid1.Columns["Firma"].FillWeight = 8
        $grid1.Columns["Firmante"].FillWeight = 13
        $grid1.Columns["Entropia"].FillWeight = 7
        $grid1.Columns["SHA256"].FillWeight = 10
        $grid1.Columns["Alertas"].FillWeight = 20
    }
})

[void]$form.ShowDialog()

Write-Host "`n[*] Analisis finalizado." -ForegroundColor Cyan
