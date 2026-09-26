if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs;
    exit;
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase;

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PC Check - Visor Forense de Eventos" Height="720" Width="1120"
        Background="#18181b" WindowStartupLocation="CenterScreen">
    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Text="AUDITORIA DE EVENTOS FORENSES (PC CHECK)" 
                   Foreground="#38bdf8" FontSize="18" FontWeight="Bold" Margin="0,0,0,12"/>

        <Border Grid.Row="1" Background="#27272a" CornerRadius="6" Padding="12" Margin="0,0,0,12">
            <WrapPanel Orientation="Horizontal" VerticalAlignment="Center">
                <Button Name="BtnScan" Content="Escanear Eventos" Background="#0284c7" Foreground="White" 
                        FontWeight="Bold" Padding="15,6" BorderThickness="0" Cursor="Hand" Margin="0,0,15,0"/>
                
                <TextBlock Text="Buscar:" Foreground="#e4e4e7" VerticalAlignment="Center" Margin="0,0,6,0"/>
                <TextBox Name="TxtFilter" Width="170" Height="26" VerticalContentAlignment="Center" 
                         Background="#18181b" Foreground="White" BorderBrush="#3f3f46" Margin="0,0,15,0"/>

                <TextBlock Text="Categoria:" Foreground="#e4e4e7" VerticalAlignment="Center" Margin="0,0,6,0"/>
                <ComboBox Name="CmbLog" Width="130" Height="26" Margin="0,0,15,0"/>

                <TextBlock Text="Desde:" Foreground="#e4e4e7" VerticalAlignment="Center" Margin="0,0,6,0"/>
                <DatePicker Name="DpDate" Width="115" Height="26" Margin="0,0,8,0"/>
                
                <TextBox Name="TxtHour" Width="45" Height="26" Text="00:00" ToolTip="Formato HH:mm" 
                         VerticalContentAlignment="Center" Background="#18181b" Foreground="White" BorderBrush="#3f3f46" Margin="0,0,15,0"/>

                <Button Name="BtnFilter" Content="Aplicar Filtros" Background="#3f3f46" Foreground="White" 
                        Padding="10,4" BorderThickness="0" Cursor="Hand" Margin="0,0,8,0"/>
                <Button Name="BtnReset" Content="Limpiar" Background="#27272a" Foreground="#a1a1aa" 
                        Padding="8,4" BorderBrush="#3f3f46" BorderThickness="1" Cursor="Hand"/>
            </WrapPanel>
        </Border>

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
                <DataGridTextColumn Header="Descripcion / Riesgo" Binding="{Binding RuleDescription}" Width="280"/>
                <DataGridTextColumn Header="Detalle Tecnico" Binding="{Binding Message}" Width="*"/>
            </DataGrid.Columns>
        </DataGrid>

        <StatusBar Grid.Row="3" Background="#18181b" Margin="0,8,0,0">
            <TextBlock Name="TxtStatus" Text="Listo para escanear." Foreground="#a1a1aa" FontSize="12"/>
        </StatusBar>
    </Grid>
</Window>
"@;

$reader = (New-Object System.Xml.XmlNodeReader $xaml);
$window = [Windows.Markup.XamlReader]::Load($reader);

$btnScan   =$window.FindName("BtnScan");
$btnFilter =$window.FindName("BtnFilter");
$btnReset  =$window.FindName("BtnReset");
$dataGrid  =$window.FindName("DataGridEvents");
$txtFilter =$window.FindName("TxtFilter");
$cmbLog    =$window.FindName("CmbLog");
$dpDate    =$window.FindName("DpDate");
$txtHour   =$window.FindName("TxtHour");
$txtStatus =$window.FindName("TxtStatus");

[void]$cmbLog.Items.Add("Todas");
@("Application", "System", "Security", "PowerShell", "TaskScheduler", "Defender", "Kernel-PnP", "NTFS") | ForEach-Object {
    [void]$cmbLog.Items.Add($_);
};
$cmbLog.SelectedIndex = 0;

# Diccionario completo de mapeo
$Script:EventMap = @{
    "Application:1000" = "Crash de App (Inyecciones / DLLs rotas)";
    "Application:1001" = "Reporte de error enviado / Crash report (WER)";
    "Application:1002" = "Bloqueo / Congelamiento de App";
    "Application:3079" = "Limpieza de log (Application)";
    "System:41"        = "Apagado abrupto / Kernel-Power (Tiron de cable / Reinicio)";
    "System:6008"      = "Apagado inesperado previo";
    "System:1001"      = "BugCheck / BSOD por driver kernel";
    "System:4101"      = "Driver de video crasheado (Hooks DirectX / Overlays)";
    "System:4201"      = "Cambio / Reconexion de interfaz de red (Corte intencionado)";
    "System:104"       = "Limpieza de log (System)";
    "Security:1100"    = "Servicio EventLog detenido";
    "Security:1102"    = "Registro de auditoria borrado (Cleaner / Antiforense)";
    "Security:4616"    = "Cambio de hora del sistema (Timestomping)";
    "Windows PowerShell:400" = "Motor PowerShell iniciado";
    "Windows PowerShell:800" = "Pipeline Execution Details";
    "Microsoft-Windows-PowerShell/Operational:4104" = "Script Block ejecutado (IEX / Obfuscated)";
    "Microsoft-Windows-TaskScheduler/Operational:106" = "Nueva tarea creada (Persistencia / Loaders)";
    "Microsoft-Windows-TaskScheduler/Operational:140" = "Tarea modificada";
    "Microsoft-Windows-TaskScheduler/Operational:141" = "Tarea eliminada (Cleaner / Borrado de rastro)";
    "Microsoft-Windows-Windows Defender/Operational:1116" = "Amenaza o malware detectado en disco";
    "Microsoft-Windows-Windows Defender/Operational:1117" = "Accion Defender: Archivo borrado o bloqueado";
    "Microsoft-Windows-Windows Defender/Operational:5001" = "Proteccion en tiempo real desactivada";
    "Microsoft-Windows-Windows Defender/Operational:5007" = "Exclusion o configuracion alterada en Defender";
    "Microsoft-Windows-Kernel-PnP/Device Configuration:400" = "Dispositivo/VHD configurado";
    "Microsoft-Windows-Kernel-PnP/Device Configuration:410" = "Dispositivo/VHD nuevo iniciado";
    "Microsoft-Windows-Kernel-PnP/Device Configuration:411" = "Fallo de inicializacion de dispositivo/driver";
    "Microsoft-Windows-Kernel-PnP/Operational:400" = "Dispositivo configurado (PnP Oper)";
    "Microsoft-Windows-Kernel-PnP/Operational:410" = "Dispositivo nuevo iniciado (PnP Oper)";
    "Microsoft-Windows-Kernel-PnP/Operational:411" = "Dispositivo no arrancado (PnP Oper)";
    "Microsoft-Windows-Ntfs/Operational:501"       = "Limpieza de diario USN Journal (Cleaner)";
};

$Script:AllEvents = [System.Collections.Generic.List[PSObject]]::new();

$btnScan.Add_Click({
    $btnScan.IsEnabled =$false;
    $txtStatus.Text = "Escaneando registros del sistema... esto puede tomar unos segundos.";
    $Script:AllEvents.Clear();

    $logTargets = @(
        @{ LogName = "Application"; Ids = @(1000, 1001, 1002, 3079) },
        @{ LogName = "System"; Ids = @(41, 6008, 1001, 4101, 4201, 104) },
        @{ LogName = "Security"; Ids = @(1100, 1102, 4616) },
        @{ LogName = "Windows PowerShell"; Ids = @(400, 800) },
        @{ LogName = "Microsoft-Windows-PowerShell/Operational"; Ids = @(4104) },
        @{ LogName = "Microsoft-Windows-TaskScheduler/Operational"; Ids = @(106, 140, 141) },
        @{ LogName = "Microsoft-Windows-Windows Defender/Operational"; Ids = @(1116, 1117, 5001, 5007) },
        @{ LogName = "Microsoft-Windows-Kernel-PnP/Device Configuration"; Ids = @(400, 410, 411) },
        @{ LogName = "Microsoft-Windows-Kernel-PnP/Operational"; Ids = @(400, 410, 411) },
        @{ LogName = "Microsoft-Windows-Ntfs/Operational"; Ids = @(501) }
    );

    foreach ($target in$logTargets) {
        try {
            $filter = @{
                LogName = $target.LogName;
                Id      = $target.Ids;
            };
            
            # Consultamos los eventos individuales con límite de 500 por tipo para máxima rapidez
            $foundEvents = Get-WinEvent -FilterHashtable$filter -MaxEvents 500 -ErrorAction SilentlyContinue;
            
            if ($foundEvents) {
                foreach ($evt in $foundEvents) {$key = "$($evt.LogName):$($evt.Id)";
                    $desc = if ($Script:EventMap.ContainsKey($key)) { $Script:EventMap[$key] } else { "Evento auditado" };

                    $shortLog = switch -Wildcard ($evt.LogName) {
                        "*TaskScheduler*" { "TaskScheduler" }
                        "*Defender*"      { "Defender" }
                        "*Kernel-PnP*"    { "Kernel-PnP" }
                        "*Ntfs*"          { "NTFS" }
                        "*PowerShell*"    { "PowerShell" }
                        Default           { $evt.LogName }
                    };

                    $rawMsg =$evt.Message;
                    if (-not $rawMsg) {$rawMsg = "Evento ID $($evt.Id) registrado en $($evt.LogName)";
                    }
                    $cleanMsg = ($rawMsg -replace "`r`n", " " -replace "\s+", " ");
                    if ($cleanMsg) { $cleanMsg =$cleanMsg.Trim() };

                    $Script:AllEvents.Add([PSCustomObject]@{
                        TimeCreated     = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss");
                        DateTimeObj     = $evt.TimeCreated;
                        LogName         = $shortLog;
                        Id              = $evt.Id;
                        RuleDescription = $desc;
                        Message         = $cleanMsg;
                    });
                }
            }
        } catch { }
    }

    $sorted = @($Script:AllEvents | Sort-Object DateTimeObj -Descending);
    $dataGrid.ItemsSource =$sorted;
    $txtStatus.Text = "Escaneo completado. Total de eventos detectados: $($Script:AllEvents.Count)";
    $btnScan.IsEnabled =$true;
});

$applyFilter = {
    if ($Script:AllEvents.Count -eq 0) { return };

    $filtered =$Script:AllEvents;

    $searchText =$txtFilter.Text.Trim();
    if (-not [string]::IsNullOrEmpty($searchText)) {
        $filtered =$filtered | Where-Object { 
            $_.Message -match [regex]::Escape($searchText) -or 
            $_.RuleDescription -match [regex]::Escape($searchText) -or 
            $_.Id.ToString() -eq$searchText 
        };
    }

    $selectedLog =$cmbLog.SelectedItem.ToString();
    if ($selectedLog -ne "Todas") {
        $filtered =$filtered | Where-Object { $_.LogName -eq$selectedLog };
    }

    if ($dpDate.SelectedDate) {
        $dateStr =$dpDate.SelectedDate.Value.ToString("yyyy-MM-dd");
        $timeStr = if ($txtHour.Text -match "^\d{2}:\d{2}$") { $txtHour.Text } else { "00:00" };
        $minDate = [datetime]::ParseExact("$dateStr$timeStr", "yyyy-MM-dd HH:mm", $null);

        $filtered =$filtered | Where-Object { $_.DateTimeObj -ge$minDate };
    }

    $sortedFiltered = @($filtered | Sort-Object DateTimeObj -Descending);
    $dataGrid.ItemsSource =$sortedFiltered;
    $txtStatus.Text = "Mostrando $($sortedFiltered.Count) de $($Script:AllEvents.Count) eventos tras aplicar filtros.";
};

$btnReset.Add_Click({$txtFilter.Text = "";
    $cmbLog.SelectedIndex = 0;
    $dpDate.SelectedDate =$null;
    $txtHour.Text = "00:00";
    $sorted = @($Script:AllEvents | Sort-Object DateTimeObj -Descending);
    $dataGrid.ItemsSource =$sorted;
    $txtStatus.Text = "Filtros restablecidos. Mostrando $($Script:AllEvents.Count) eventos.";
});

$btnFilter.Add_Click($applyFilter);$txtFilter.Add_KeyDown({ if ($_.Key -eq 'Enter') { &$applyFilter } });

[void]$window.ShowDialog();
