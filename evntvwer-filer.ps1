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
    @{ LogName = "Application"; Id = @(1000, 1001, 1002, 3079) },
    @{ LogName = "System"; Id = @(41, 6008, 1001, 4101, 4201, 104) },
    @{ LogName = "Security"; Id = @(1100, 1102, 4616) },
    @{ LogName = "Windows PowerShell"; Id = @(400, 800) },
    @{ LogName = "Microsoft-Windows-PowerShell/Operational"; Id = @(4104) },
    @{ LogName = "Microsoft-Windows-TaskScheduler/Operational"; Id = @(106, 140, 141) },
    @{ LogName = "Microsoft-Windows-Windows Defender/Operational"; Id = @(1116, 1117, 5001, 5007) },
    @{ LogName = "Microsoft-Windows-Kernel-PnP/Device Configuration"; Id = @(400, 410, 411) },
    @{ LogName = "Microsoft-Windows-Kernel-PnP/Operational"; Id = @(400, 410, 411) },
    @{ LogName = "Microsoft-Windows-Ntfs/Operational"; Id = @(501) }
)

$results = [System.Collections.Generic.List[PSObject]]::new()

foreach ($target in$queries) {
    Write-Host "   -> Escaneando canal: $($target.LogName)..." -ForegroundColor DarkGray
    try {
        $events = Get-WinEvent -FilterHashtable$target -MaxEvents 300 -ErrorAction SilentlyContinue
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
                if (-not $rawMsg) {$rawMsg = "Evento registrado sin descripcion adicional" }
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

Write-Host "[+] Escaneo completado. Total eventos encontrados: $($results.Count)" -ForegroundColor Green

if ($results.Count -gt 0) {$results | Out-GridView -Title "PC Check - Visor Forense de Eventos ($($results.Count) encontrados)"
} else {
    Write-Host "[-] No se encontraron eventos de la lista en este equipo." -ForegroundColor Yellow
}
