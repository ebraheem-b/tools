# Requiere elevación de privilegios para leer el log de Seguridad
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# Interfaz XAML con tema oscuro y controles de filtrado
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PC Check - Visor Forense de Eventos" Height="700" Width="1100"
        Background="#18181b" WindowStartupLocation="CenterScreen">
    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Cabecera -->
        <TextBlock Text="AUDITORÍA DE EVENTOS FORENSES (PC CHECK)" 
                   Foreground="#38bdf8" FontSize="18" FontWeight="Bold" Margin="0,0,0,12"/>

        <!-- Barra de Filtros y Acciones -->
        <Border Grid.Row="1" Background="#27272a" CornerRadius="6" Padding="12" Margin="0,0,0,12">
            <WrapPanel Orientation="Horizontal" VerticalAlignment="Center">
                <Button Name="BtnScan" Content="Escanear Eventos" Background="#0284c7" Foreground="White" 
                        FontWeight="Bold" Padding="15,6" BorderThickness="0" Cursor="Hand" Margin="0,0,15,0"/>
                
                <TextBlock Text="Buscar:" Foreground="#e4e4e7" VerticalAlignment="Center" Margin="0,0,6,0"/>
                <TextBox Name="TxtFilter" Width="180" Height="26" VerticalContentAlignment="Center" 
                         Background="#18181b" Foreground="White" BorderBrush="#3f3f46" Margin="0,0,15,0"/>

                <TextBlock Text="Categoría:" Foreground="#e4e4e7" VerticalAlignment="Center" Margin="0,0,6,0"/>
                <ComboBox Name="CmbLog" Width="140" Height="26" Margin="0,0,15,0"/>

                <TextBlock Text="Desde:" Foreground="#e4e4e7" VerticalAlignment="Center" Margin="0,0,6,0"/>
                <DatePicker Name="DpDate" Width="115" Height="26" Margin="0,0,8,0"/>
                
                <TextBox Name="TxtHour" Width="45" Height="26" Text="00:00" ToolTip="Formato HH:mm" 
                         VerticalContentAlignment="Center" Background="#18181b" Foreground="White" BorderBrush="#3f3f46" Margin="0,0,15,0"/>

                <Button Name="BtnFilter" Content="Aplicar Filtros" Background="#3f3f46" Foreground="White" 
                        Padding="10,4" BorderThickness="0" Cursor="Hand"/>
            </WrapPanel>
        </Border>

        <!-- Tabla de Datos -->
        <DataGrid Name="DataGridEvents" Grid.Row="2" AutoGenerateColumns="False" IsReadOnly="True"
                  Background="#18181b" Foreground="#f4f4f5" RowBackground="#18181b" AlternatingRowBackground="#202024"
                  GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#27272a" HeadersVisibility="Column"
                  BorderBrush="#27272a" SelectionMode="Single" CanUserResizeRows="False">
            <DataGrid.ColumnHeaderStyle>
                <Style TargetType="DataGridColumnHeader">
                    <Setter Property="Background" Value="#27272a"/>
                    <Setter Property="Foreground" Value="#38bdf8"/>
                    <Setter Property="FontWeight" Value="SemiBold"/>
                    <Setter Property="Padding" Value="8,6"/>
                    <Setter Property="BorderBrush" Value="#3f3f46"/>
                    <Setter Property="BorderThickness" Value="0,0,1,1"/>
                </Style>
            </DataGrid.ColumnHeaderStyle>
            <DataGrid.Columns>
                <DataGridTextColumn Header="Fecha y Hora" Binding="{Binding TimeCreated}" Width="150"/>
                <DataGridTextColumn Header="Registro" Binding="{Binding LogName}" Width="120"/>
                <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="60"/>
                <DataGridTextColumn Header="Descripción / Riesgo" Binding="{Binding RuleDescription}" Width="260"/>
                <DataGridTextColumn Header="Detalle Técnico" Binding="{Binding Message}" Width="*"/>
            </DataGrid.Columns>
        </DataGrid>

        <!-- Barra de Estado inferior -->
        <StatusBar Grid.Row="3" Background="#18181b" Margin="0,8,0,0">
            <TextBlock Name="TxtStatus" Text="Listo para escanear." Foreground="#a1a1aa" FontSize="12"/>
        </StatusBar>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Controles de la interfaz
$btnScan        =$window.FindName("BtnScan")
$btnFilter      =$window.FindName("BtnFilter")
$dataGrid       =$window.FindName("DataGridEvents")
$txtFilter      =$window.FindName("TxtFilter")
$cmbLog         =$window.FindName("CmbLog")
$dpDate         =$window.FindName("DpDate")
$txtHour        =$window.FindName("TxtHour")
$txtStatus      =$window.FindName("TxtStatus")

# Inicialización de Combobox
$cmbLog.Items.Add("Todas") | Out-Null
@("Application", "System", "Security", "PowerShell", "TaskScheduler", "Defender", "Kernel-PnP", "NTFS") | ForEach-Object {
    $cmbLog.Items.Add($_) | Out-Null
}
$cmbLog.SelectedIndex = 0$dpDate.SelectedDate = (Get-Date).AddDays(-1)

# Mapa de descripciones según tus IDs de evento
$Script:EventDescriptions = @{
    "Application:1000" = "Crash de App (Inyecciones / DLLs rotas)"
    "Application:1001" = "Reporte de error enviado (Crash WER)"
    "Application:1002" = "Bloqueo / Congelamiento de App"
    "Application:3079" = "Limpieza de log de Aplicación"
    "System:41"        = "Apagado abrupto / Tirón de cable (Kernel-Power)"
    "System:6008"      = "Apagado inesperado previo"
    "System:1001"      = "BugCheck / BSOD por driver kernel"
    "System:4101"      = "Driver de vídeo crasheado (Hooks DirectX / Overlays)"
    "System:4201"      = "Cambio/Reconexión de interfaz de red"
    "System:104"       = "Limpieza de log del Sistema"
    "Security:1100"    = "Servicio EventLog detenido"
    "Security:1102"    = "Registro de auditoría borrado (Cleaner)"
    "Security:4616"    = "Cambio de hora del sistema (Timestomping)"
    "Windows PowerShell:400" = "Motor de PowerShell iniciado"
    "Windows PowerShell:800" = "Cambio de estado en Pipeline de PowerShell"
    "Microsoft-Windows-TaskScheduler/Operational:106" = "Nueva tarea creada (Persistencia / Loader)"
    "Microsoft-Windows-TaskScheduler/Operational:140" = "Tarea modificada"
    "Microsoft-Windows-TaskScheduler/Operational:141" = "Tarea eliminada (Cleaner / Borrado de rastro)"
    "Microsoft-Windows-Windows Defender/Operational:1116" = "Amenaza/Malware detectado en disco"
    "Microsoft-Windows-Windows Defender/Operational:1117" = "Acción Defender: Archivo borrado/bloqueado"
    "Microsoft-Windows-Windows Defender/Operational:5001" = "Protección en tiempo real desactivada"
    "Microsoft-Windows-Windows Defender/Operational:5007" = "Configuración/Exclusión añadida en Defender"
    "Microsoft-Windows-Kernel-PnP/Device Configuration:400" = "Dispositivo/VHD configurado"
    "Microsoft-Windows-Kernel-PnP/Device Configuration:410" = "Dispositivo/VHD nuevo iniciado"
    "Microsoft-Windows-Kernel-PnP/Device Configuration:411" = "Fallo de inicialización de dispositivo/driver"
    "Microsoft-Windows-Ntfs/Operational:501"               = "Limpieza de diario USN Journal (Cleaner)"
}

$Script:AllEvents = [System.Collections.Generic.List[PSObject]]::new()

# Función de recolección de eventos
$btnScan.Add_Click({$btnScan.IsEnabled = $false$txtStatus.Text = "Escaneando registros del sistema... espera unos segundos."
    $Script:AllEvents.Clear()

    # Rutas e identificadores a consultar
    $queries = @(
        @{ Log = "Application"; Ids = "1000,1001,1002,3079" },
        @{ Log = "System"; Ids = "41,6008,1001,4101,4201,104" },
        @{ Log = "Security"; Ids = "1100,1102,4616" },
        @{ Log = "Windows PowerShell"; Ids = "400,800" },
        @{ Log = "Microsoft-Windows-TaskScheduler/Operational"; Ids = "106,140,141" },
        @{ Log = "Microsoft-Windows-Windows Defender/Operational"; Ids = "1116,1117,5001,5007" },
        @{ Log = "Microsoft-Windows-Kernel-PnP/Device Configuration"; Ids = "400,410,411" },
        @{ Log = "Microsoft-Windows-Ntfs/Operational"; Ids = "501" }
    )

    foreach ($q in $queries) {$xmlFilter = @"
<QueryList>
  <Query Id="0" Path="$($q.Log)">
    <Select Path="$($q.Log)">*[System[(EventID=$($q.Ids.Replace(',', ' or EventID=')))]]</Select>
  </Query>
</QueryList>
"@
        try {
            $events = Get-WinEvent -FilterXml$xmlFilter -ErrorAction SilentlyContinue
            if ($events) {
                foreach ($evt in $events) {$key = "$($evt.LogName):$($evt.Id)"
                    $desc = if ($Script:EventDescriptions.ContainsKey($key)) { $Script:EventDescriptions[$key] } else { "Evento auditado" }
                    
                    # Simplificación del nombre del log para visualización
                    $shortLog = switch -Wildcard ($evt.LogName) {
                        "*TaskScheduler*" { "TaskScheduler" }
                        "*Defender*"      { "Defender" }
                        "*Kernel-PnP*"    { "Kernel-PnP" }
                        "*Ntfs*"          { "NTFS" }
                        "*PowerShell*"    { "PowerShell" }
                        Default           { $evt.LogName }
                    }

                    $cleanMessage = ($evt.Message -replace "`r`n", " " -replace "\s+", " ").Trim()

                    $Script:AllEvents.Add([PSCustomObject]@{
                        TimeCreated     = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        DateTimeObj     = $evt.TimeCreated
                        LogName         = $shortLog
                        Id              = $evt.Id
                        RuleDescription = $desc
                        Message         = $cleanMessage
                    })
                }
            }
        } catch { }
    }

    # Ordenar por fecha descendente
    $sorted = $Script:AllEvents \vert{} Sort-Object DateTimeObj -Descending$dataGrid.ItemsSource = [System.Collections.ObjectModel.ObservableCollection[PSObject]]::new($sorted)$txtStatus.Text = "Escaneo completado. Total de eventos detectados: $($Script:AllEvents.Count)"
    $btnScan.IsEnabled =$true
})

# Función de filtrado dinámico
$applyFilter = {
    if ($Script:AllEvents.Count -eq 0) { return }

    $filtered =$Script:AllEvents

    # Filtro por texto general
    $searchText =$txtFilter.Text.Trim()
    if (-not [string]::IsNullOrEmpty($searchText)) {
        $filtered =$filtered | Where-Object { 
            $_.Message -match [regex]::Escape($searchText) -or 
            $_.RuleDescription -match [regex]::Escape($searchText) -or 
            $_.Id.ToString() -eq$searchText 
        }
    }

    # Filtro por Log
    $selectedLog =$cmbLog.SelectedItem.ToString()
    if ($selectedLog -ne "Todas") {
        $filtered =$filtered | Where-Object { $_.LogName -eq$selectedLog }
    }

    # Filtro por Fecha y Hora
    if ($dpDate.SelectedDate) {
        $dateStr =$dpDate.SelectedDate.Value.ToString("yyyy-MM-dd")
        $timeStr = if ($txtHour.Text -match "^\d{2}:\d{2}$") { $txtHour.Text } else { "00:00" }
        $minDate = [datetime]::ParseExact("$dateStr$timeStr", "yyyy-MM-dd HH:mm", $null)

        $filtered =$filtered | Where-Object { $_.DateTimeObj -ge$minDate }
    }

    $sortedFiltered = $filtered \vert{} Sort-Object DateTimeObj -Descending$dataGrid.ItemsSource = [System.Collections.ObjectModel.ObservableCollection[PSObject]]::new($sortedFiltered)$txtStatus.Text = "Mostrando $($sortedFiltered.Count) de $($Script:AllEvents.Count) eventos tras aplicar filtros."
}

$btnFilter.Add_Click($applyFilter)$txtFilter.Add_KeyDown({ if ($_.Key -eq 'Enter') { &$applyFilter } })

# Abrir ventana
$window.ShowDialog() | Out-Null
