#Event Viewer
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "[*] Iniciando auditoria forense de eventos (PC Check)..." -ForegroundColor Cyan

$EventMap = @{
    "Application:1000" = "Crash de App (Inyecciones / DLLs rotas)"
    "Application:1001" = "Reporte de error enviado (Crash WER)"
    "Application:1002" = "Bloqueo / Congelamiento de App"
    "Application:3079" = "Limpieza de log de Aplicacion"
    "System:41"        = "Apagado abrupto / Kernel-Power (Tiron de cable / Reinicio)"
    "System:6008"      = "Apagado inesperado previo"
    "System:1001"      = "BugCheck / BSOD por driver kernel"
    "System:4101"      = "Driver de video crasheado (Hooks DirectX / Overlays)"
    "System:4201"      = "Cambio/Reconexion de interfaz de red"
    "System:104"       = "Limpieza de log del Sistema"
    "System:7031"      = "Servicio crasheado + accion de recuperacion (Kill forzado)"
    "System:7034"      = "Servicio terminado inesperadamente (Crash / taskkill)"
    "System:7035"      = "Solicitud de control enviada a servicio (start/stop request)"
    "System:7036"      = "Servicio cambio de estado: Iniciado o Detenido (Bypass / sc stop)"
    "System:7040"      = "Tipo de inicio de servicio cambiado (Disabled = Bypass persistente)"
    "System:7045"      = "Nuevo servicio instalado en el sistema (Persistencia / Driver)"
    "Security:1100"    = "Servicio EventLog detenido"
    "Security:1102"    = "Registro de auditoria borrado (Cleaner / Antiforense)"
    "Security:4616"    = "Cambio de hora del sistema (Timestomping)"
    "Windows PowerShell:400" = "Motor PowerShell iniciado"
    "Windows PowerShell:800" = "Pipeline Execution Details"
    "Microsoft-Windows-PowerShell/Operational:4104" = "Script Block ejecutado (IEX / Obfuscated)"
    "Microsoft-Windows-TaskScheduler/Operational:106" = "Nueva tarea creada (Persistencia / Loader)"
    "Microsoft-Windows-TaskScheduler/Operational:140" = "Tarea modificada"
    "Microsoft-Windows-TaskScheduler/Operational:141" = "Tarea eliminada (Cleaner / Borrado de rastro)"
    "Microsoft-Windows-Windows Defender/Operational:1116" = "Amenaza o malware detectado en disco"
    "Microsoft-Windows-Windows Defender/Operational:1117" = "Accion Defender: Archivo borrado o bloqueado"
    "Microsoft-Windows-Windows Defender/Operational:5001" = "Proteccion en tiempo real desactivada"
    "Microsoft-Windows-Windows Defender/Operational:5007" = "Exclusion o configuracion alterada en Defender"
    "Microsoft-Windows-Kernel-PnP/Device Configuration:400" = "Dispositivo/VHD configurado"
    "Microsoft-Windows-Kernel-PnP/Device Configuration:410" = "Dispositivo/VHD nuevo iniciado"
    "Microsoft-Windows-Kernel-PnP/Device Configuration:411" = "Fallo de inicializacion de dispositivo/driver"
    "Microsoft-Windows-Kernel-PnP/Operational:400" = "Dispositivo configurado (PnP Oper)"
    "Microsoft-Windows-Kernel-PnP/Operational:410" = "Dispositivo nuevo iniciado (PnP Oper)"
    "Microsoft-Windows-Kernel-PnP/Operational:411" = "Dispositivo no arrancado (PnP Oper)"
    "Microsoft-Windows-Ntfs/Operational:501"       = "Limpieza de diario USN Journal (Cleaner)"
}

$queries = @(
    @{ LogName = "Application"; Ids = @(1000, 1001, 1002, 3079) },
    @{ LogName = "System"; Ids = @(41, 6008, 1001, 4101, 4201, 104, 7031, 7034, 7035, 7036, 7040, 7045) },
    @{ LogName = "Security"; Ids = @(1100, 1102, 4616) },
    @{ LogName = "Windows PowerShell"; Ids = @(400, 800) },
    @{ LogName = "Microsoft-Windows-PowerShell/Operational"; Ids = @(4104) },
    @{ LogName = "Microsoft-Windows-TaskScheduler/Operational"; Ids = @(106, 140, 141) },
    @{ LogName = "Microsoft-Windows-Windows Defender/Operational"; Ids = @(1116, 1117, 5001, 5007) },
    @{ LogName = "Microsoft-Windows-Kernel-PnP/Device Configuration"; Ids = @(400, 410, 411) },
    @{ LogName = "Microsoft-Windows-Kernel-PnP/Operational"; Ids = @(400, 410, 411) },
    @{ LogName = "Microsoft-Windows-Ntfs/Operational"; Ids = @(501) }
)

$results = [System.Collections.Generic.List[PSObject]]::new()

foreach ($target in $queries) {
    Write-Host "   -> Escaneando canal: $($target.LogName)..." -ForegroundColor DarkGray
    
    # Comprobar si el log existe y tiene eventos antes de leerlo
    $logCheck = Get-WinEvent -ListLog $target.LogName -ErrorAction SilentlyContinue
    if (-not $logCheck -or$logCheck.RecordCount -eq 0) { continue }

    foreach ($singleId in $target.Ids) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $target.LogName; Id =$singleId } -MaxEvents 150 -ErrorAction SilentlyContinue
            if ($events) {
                foreach ($evt in $events) {$key = "$($evt.LogName):$($evt.Id)"
                    $desc = if ($EventMap.ContainsKey($key)) { $EventMap[$key] } else { "Evento auditado" }

                    $shortLog = switch -Wildcard ($evt.LogName) {
                        "*TaskScheduler*" { "TaskScheduler" }
                        "*Defender*"      { "Defender" }
                        "*Kernel-PnP*"    { "Kernel-PnP" }
                        "*Ntfs*"          { "NTFS" }
                        "*PowerShell*"    { "PowerShell" }
                        Default           { $evt.LogName }
                    }

                    $rawMsg =$evt.Message
                    if (-not $rawMsg) {$rawMsg = "Sin detalle adicional registrado." }
                    $cleanMsg = ($rawMsg -replace "`r`n", " " -replace "\s+", " ").Trim()

                    $results.Add([PSCustomObject]@{
                        "Fecha y Hora"         = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        "Registro"             = $shortLog
                        "ID"                   = $evt.Id
                        "Descripcion / Riesgo" = $desc
                        "Detalle Tecnico"      = $cleanMsg
                    })
                }
            }
        } catch { }
    }
}

Write-Host "[+] Escaneo completado. Total eventos encontrados: $($results.Count)" -ForegroundColor Green

if ($results.Count -gt 0) {
    Write-Host "[*] Construyendo interfaz avanzada..." -ForegroundColor Cyan
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "PC Check - Visor Forense Avanzado ($($results.Count) eventos)"
    $form.Size = New-Object System.Drawing.Size(1100, 650)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::WhiteSmoke
    try { $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon((Get-Process -id $PID).Path) } catch {}

    $topPanel = New-Object System.Windows.Forms.Panel
    $topPanel.Dock = "Top"
    $topPanel.Height = 90
    $topPanel.BackColor = [System.Drawing.Color]::White
    $form.Controls.Add($topPanel)

    # FILA 1 (Y=15)
    $lblFilter = New-Object System.Windows.Forms.Label
    $lblFilter.Text = "Registro:"
    $lblFilter.Location = New-Object System.Drawing.Point(15, 17)
    $lblFilter.AutoSize = $true
    $lblFilter.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $topPanel.Controls.Add($lblFilter)

    $comboLog = New-Object System.Windows.Forms.ComboBox
    $comboLog.Location = New-Object System.Drawing.Point(80, 14)
    $comboLog.Width = 160
    $comboLog.DropDownStyle = "DropDownList"
    $comboLog.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $topPanel.Controls.Add($comboLog)

    $lblSearch = New-Object System.Windows.Forms.Label
    $lblSearch.Text = "Buscar en mensaje:"
    $lblSearch.Location = New-Object System.Drawing.Point(260, 17)
    $lblSearch.AutoSize = $true
    $lblSearch.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $topPanel.Controls.Add($lblSearch)

    $txtSearch = New-Object System.Windows.Forms.TextBox
    $txtSearch.Location = New-Object System.Drawing.Point(390, 14)
    $txtSearch.Width = 230
    $txtSearch.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $topPanel.Controls.Add($txtSearch)

    $lblId = New-Object System.Windows.Forms.Label
    $lblId.Text = "Cod/ID:"
    $lblId.Location = New-Object System.Drawing.Point(640, 17)
    $lblId.AutoSize = $true
    $lblId.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $topPanel.Controls.Add($lblId)

    $txtId = New-Object System.Windows.Forms.TextBox
    $txtId.Location = New-Object System.Drawing.Point(695, 14)
    $txtId.Width = 80
    $txtId.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $topPanel.Controls.Add($txtId)

    # FILA 2 (Y=50)
    $lblDateFrom = New-Object System.Windows.Forms.Label
    $lblDateFrom.Text = "Desde:"
    $lblDateFrom.Location = New-Object System.Drawing.Point(15, 53)
    $lblDateFrom.AutoSize = $true
    $lblDateFrom.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $topPanel.Controls.Add($lblDateFrom)

    $dtFrom = New-Object System.Windows.Forms.DateTimePicker
    $dtFrom.Location = New-Object System.Drawing.Point(80, 50)
    $dtFrom.Width = 160
    $dtFrom.Format = "Custom"
    $dtFrom.CustomFormat = "yyyy-MM-dd HH:mm"
    $topPanel.Controls.Add($dtFrom)

    $lblDateTo = New-Object System.Windows.Forms.Label
    $lblDateTo.Text = "Hasta:"
    $lblDateTo.Location = New-Object System.Drawing.Point(260, 53)
    $lblDateTo.AutoSize = $true
    $lblDateTo.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $topPanel.Controls.Add($lblDateTo)

    $dtTo = New-Object System.Windows.Forms.DateTimePicker
    $dtTo.Location = New-Object System.Drawing.Point(390, 50)
    $dtTo.Width = 160
    $dtTo.Format = "Custom"
    $dtTo.CustomFormat = "yyyy-MM-dd HH:mm"
    $topPanel.Controls.Add($dtTo)

    $lblExcludeId = New-Object System.Windows.Forms.Label
    $lblExcludeId.Text = "Excluir:"
    $lblExcludeId.Location = New-Object System.Drawing.Point(640, 53)
    $lblExcludeId.AutoSize = $true
    $lblExcludeId.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $topPanel.Controls.Add($lblExcludeId)

    $txtExcludeId = New-Object System.Windows.Forms.TextBox
    $txtExcludeId.Location = New-Object System.Drawing.Point(695, 50)
    $txtExcludeId.Width = 80
    $txtExcludeId.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $topPanel.Controls.Add($txtExcludeId)

    $btnFilter = New-Object System.Windows.Forms.Button
    $btnFilter.Text = "Aplicar Filtros"
    $btnFilter.Location = New-Object System.Drawing.Point(820, 14)
    $btnFilter.Width = 120
    $btnFilter.Height = 60
    $btnFilter.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $btnFilter.ForeColor = [System.Drawing.Color]::White
    $btnFilter.FlatStyle = "Flat"
    $btnFilter.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnFilter.Cursor = [System.Windows.Forms.Cursors]::Hand
    $topPanel.Controls.Add($btnFilter)
    
    $btnReset = New-Object System.Windows.Forms.Button
    $btnReset.Text = "Limpiar"
    $btnReset.Location = New-Object System.Drawing.Point(950, 14)
    $btnReset.Width = 90
    $btnReset.Height = 60
    $btnReset.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
    $btnReset.ForeColor = [System.Drawing.Color]::White
    $btnReset.FlatStyle = "Flat"
    $btnReset.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnReset.Cursor = [System.Windows.Forms.Cursors]::Hand
    $topPanel.Controls.Add($btnReset)

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = "Fill"
    $grid.AutoSizeColumnsMode = "Fill"
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.ReadOnly = $true
    $grid.SelectionMode = "FullRowSelect"
    $grid.BackgroundColor = [System.Drawing.Color]::White
    $grid.RowHeadersVisible = $false
    $grid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(240, 248, 255)
    $grid.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $form.Controls.Add($grid)
    $form.Controls.SetChildIndex($grid, 0)

    $dataTable = New-Object System.Data.DataTable
    $dataTable.Columns.Add("Fecha y Hora", [System.DateTime]) | Out-Null
    $dataTable.Columns.Add("Registro", [System.String]) | Out-Null
    $dataTable.Columns.Add("ID", [System.Int32]) | Out-Null
    $dataTable.Columns.Add("Riesgo", [System.String]) | Out-Null
    $dataTable.Columns.Add("Detalle Tecnico", [System.String]) | Out-Null

    $logsUnicos = @("Todos")
    $minDate = [DateTime]::MaxValue
    $maxDate = [DateTime]::MinValue

    foreach ($res in $results) {
        $row = $dataTable.NewRow()
        $parsedDate = [datetime]::ParseExact($res."Fecha y Hora", "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        $row["Fecha y Hora"] = $parsedDate
        $row["Registro"] = $res."Registro"
        $row["ID"] = [int]$res."ID"
        $row["Riesgo"] = $res."Descripcion / Riesgo"
        $row["Detalle Tecnico"] = $res."Detalle Tecnico"
        $dataTable.Rows.Add($row)

        if ($parsedDate -lt $minDate) { $minDate = $parsedDate }
        if ($parsedDate -gt $maxDate) { $maxDate = $parsedDate }
        if ($logsUnicos -notcontains $res."Registro") {
            $logsUnicos += $res."Registro"
        }
    }

    if ($minDate -eq [DateTime]::MaxValue) { $minDate = (Get-Date).AddDays(-30) }
    if ($maxDate -eq [DateTime]::MinValue) { $maxDate = Get-Date }
    
    $dtFrom.Value = $minDate.Date
    $dtTo.Value = $maxDate.Date.AddDays(1).AddSeconds(-1)

    $comboLog.Items.AddRange($logsUnicos)
    $comboLog.SelectedIndex = 0

    $dataView = New-Object System.Data.DataView($dataTable)
    $dataView.Sort = "Fecha y Hora DESC"
    $grid.DataSource = $dataView

    $form.Add_Load({
        $grid.Columns["Fecha y Hora"].FillWeight = 15
        $grid.Columns["Fecha y Hora"].DefaultCellStyle.Format = "yyyy-MM-dd HH:mm:ss"
        $grid.Columns["Registro"].FillWeight = 15
        $grid.Columns["ID"].FillWeight = 8
        $grid.Columns["Riesgo"].FillWeight = 25
        $grid.Columns["Detalle Tecnico"].FillWeight = 37
    })

    $grid.Add_CellDoubleClick({
        if ($_.RowIndex -ge 0) {
            $row = $grid.Rows[$_.RowIndex]
            $valFecha = $row.Cells["Fecha y Hora"].Value.ToString("yyyy-MM-dd HH:mm:ss")
            $valReg = $row.Cells["Registro"].Value
            $valId = $row.Cells["ID"].Value
            $valRiesgo = $row.Cells["Riesgo"].Value
            $valDet = $row.Cells["Detalle Tecnico"].Value

            $detForm = New-Object System.Windows.Forms.Form
            $detForm.Text = "Detalle del Evento - ID: $valId"
            $detForm.Size = New-Object System.Drawing.Size(700, 450)
            $detForm.StartPosition = "CenterParent"
            $detForm.BackColor = [System.Drawing.Color]::White

            $txtDet = New-Object System.Windows.Forms.TextBox
            $txtDet.Multiline = $true
            $txtDet.ReadOnly = $true
            $txtDet.ScrollBars = "Vertical"
            $txtDet.Dock = "Fill"
            $txtDet.Font = New-Object System.Drawing.Font("Consolas", 10)
            $txtDet.Text = "Fecha       : $valFecha`r`nRegistro    : $valReg`r`nID Evento   : $valId`r`nRiesgo      : $valRiesgo`r`n`r`n---------------- DETALLE TECNICO ----------------`r`n`r`n$valDet"
            $txtDet.SelectionStart = 0
            $txtDet.SelectionLength = 0
            
            $detForm.Controls.Add($txtDet)
            [void]$detForm.ShowDialog()
        }
    })

    $applyFilters = {
        $filterParts = @()
        if ($comboLog.SelectedItem -ne "Todos") {
            $logName = $comboLog.SelectedItem -replace "'","''"
            $filterParts += "Registro = '$logName'"
        }
        if (![string]::IsNullOrWhiteSpace($txtSearch.Text)) {
            $searchText = $txtSearch.Text -replace "'","''"
            $filterParts += "(Registro LIKE '%$searchText%' OR Riesgo LIKE '%$searchText%' OR [Detalle Tecnico] LIKE '%$searchText%')"
        }
        if (![string]::IsNullOrWhiteSpace($txtId.Text)) {
            $ids = $txtId.Text -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
            if ($ids.Count -gt 0) {
                $idFilter = $ids | ForEach-Object { "ID = $_" }
                $filterParts += "(" + ($idFilter -join " OR ") + ")"
            }
        }
        
        if (![string]::IsNullOrWhiteSpace($txtExcludeId.Text)) {
            $exIds = $txtExcludeId.Text -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
            if ($exIds.Count -gt 0) {
                $exIdFilter = $exIds | ForEach-Object { "ID <> $_" }
                $filterParts += "(" + ($exIdFilter -join " AND ") + ")"
            }
        }
        
        $dFrom = $dtFrom.Value.ToString("MM/dd/yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        $dTo = $dtTo.Value.ToString("MM/dd/yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        $filterParts += "[Fecha y Hora] >= #$dFrom# AND [Fecha y Hora] <= #$dTo#"
        
        if ($filterParts.Count -gt 0) {
            $dataView.RowFilter = $filterParts -join " AND "
        } else {
            $dataView.RowFilter = $null
        }
    }

    $btnFilter.Add_Click($applyFilters)
    $txtSearch.Add_KeyDown({
        if ($_.KeyCode -eq 'Enter') {
            & $applyFilters
        }
    })
    $txtId.Add_KeyDown({
        if ($_.KeyCode -eq 'Enter') { & $applyFilters }
    })
    $txtExcludeId.Add_KeyDown({
        if ($_.KeyCode -eq 'Enter') { & $applyFilters }
    })
    
    $btnReset.Add_Click({
        $comboLog.SelectedIndex = 0
        $txtSearch.Text = ""
        $txtId.Text = ""
        $txtExcludeId.Text = ""
        $dtFrom.Value = $maxDate.Date
        $dtTo.Value = $maxDate.Date.AddDays(1).AddSeconds(-1)
        $dataView.RowFilter = $null
    })

    [void]$form.ShowDialog()
} else {
    Write-Host "[-] No se encontraron eventos de la lista." -ForegroundColor Yellow
}



