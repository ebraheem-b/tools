Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

Write-Host "[*] Conectando con la base de datos de LOLDrivers..." -ForegroundColor Cyan
try {
    $lolData = Invoke-RestMethod -Uri "https://www.loldrivers.io/api/drivers.json" -UseBasicParsing -TimeoutSec 15
    $vulnerableHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $lolData) {
        if ($d.KnownVulnerableSamples) {
            foreach ($sample in $d.KnownVulnerableSamples) {
                if ($sample.SHA256) { [void]$vulnerableHashes.Add($sample.SHA256) }
            }
        }
    }
    Write-Host "[+] Base de datos cargada: $($vulnerableHashes.Count) hashes vulnerables." -ForegroundColor Green
} catch {
    Write-Warning "[-] No se pudo conectar a LOLDrivers. Se verificaran firmas y certificados."
    $vulnerableHashes = $null
}

Write-Host "[*] Escaneando controladores en System32\drivers..." -ForegroundColor Cyan

$driverFiles = Get-ChildItem -Path "C:\Windows\System32\drivers" -Filter *.sys -ErrorAction SilentlyContinue

$results = [System.Collections.ArrayList]::new()
foreach ($file in $driverFiles) {
    $sig = Get-AuthenticodeSignature $file.FullName
    $cert = $sig.SignerCertificate
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
    
    $isExpired = $false
    $expireDate = $null
    if ($cert) {
        $expireDate = $cert.NotAfter.ToString("dd/MM/yyyy HH:mm:ss")
        if ($cert.NotAfter -lt (Get-Date)) {
            $isExpired = $true
        }
    }

    $isVulnerable = $false
    if ($vulnerableHashes -and $vulnerableHashes.Contains($hash)) {
        $isVulnerable = $true
    }

    $obj = [PSCustomObject]@{
        Driver          = $file.Name
        FirmaValida     = ($sig.Status -eq 'Valid')
        CertCaducado    = $isExpired
        FechaCaduca     = $expireDate
        VulnerableBYOVD = $isVulnerable
        Firmante        = if ($cert) { $cert.Subject.Split(',')[0].Replace('CN=', '').Trim() } else { "Sin firma" }
        Ruta            = $file.FullName
    }
    [void]$results.Add($obj)
}

# Crear interfaz gráfica WPF con auto-copiado al clic izquierdo
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Auditoría de Drivers - Clic izquierdo en una fila para copiar la ruta" Height="700" Width="1250" WindowStartupLocation="CenterScreen">
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <DockPanel Grid.Row="0" Margin="0,0,0,10">
            <TextBlock Text="Buscar:" VerticalAlignment="Center" Margin="0,0,10,0" FontWeight="Bold"/>
            <TextBox Name="txtSearch" Height="26" VerticalContentAlignment="Center" Padding="4,0,0,0"/>
        </DockPanel>

        <DataGrid Grid.Row="1" Name="gridDrivers" AutoGenerateColumns="True" IsReadOnly="True" 
                  SelectionMode="Single" HeadersVisibility="Column" GridLinesVisibility="All" AlternatingRowBackground="#F0F0F0"
                  CanUserSortColumns="True"/>

        <Border Grid.Row="2" Background="#E8E8E8" Padding="6" Margin="0,8,0,0" CornerRadius="4">
            <TextBlock Name="lblStatus" Text="Haz clic izquierdo sobre cualquier driver para copiar su ruta directa al portapapeles." 
                       FontWeight="SemiBold" Foreground="#333333"/>
        </Border>
    </Grid>
</Window>
"@

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [System.Windows.Markup.XamlReader]::Load($reader)

$gridDrivers = $window.FindName("gridDrivers")
$txtSearch = $window.FindName("txtSearch")
$lblStatus = $window.FindName("lblStatus")

$gridDrivers.ItemsSource = $results

# Evento: Clic izquierdo selecciona y copia la ruta
$gridDrivers.add_SelectionChanged({
    $selected = $gridDrivers.SelectedItem
    if ($selected -and $selected.Ruta) {
        [System.Windows.Clipboard]::SetText($selected.Ruta)
        $lblStatus.Text = "[COPIADO AL PORTAPAPELES] " + $selected.Ruta
        $lblStatus.Foreground = [System.Windows.Media.Brushes]::DarkGreen
    }
})

# Filtro en tiempo real al escribir en la barra de búsqueda
$txtSearch.add_TextChanged({
    $filter = $txtSearch.Text.Trim().ToLower()
    if ([string]::IsNullOrEmpty($filter)) {
        $gridDrivers.ItemsSource = $results
    } else {
        $filtered = $results | Where-Object {
            $_.Driver.ToLower().Contains($filter) -or
            $_.Firmante.ToLower().Contains($filter) -or
            $_.Ruta.ToLower().Contains($filter) -or
            $_.VulnerableBYOVD.ToString().ToLower().Contains($filter)
        }
        $gridDrivers.ItemsSource = @($filtered)
    }
})

$window.ShowDialog() | Out-Null