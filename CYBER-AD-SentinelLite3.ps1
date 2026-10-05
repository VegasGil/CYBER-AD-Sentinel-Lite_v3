#Requires -RunAsAdministrator
<#
=================================================================
 CYBER-AD Sentinel-Lite v3
 Auditoria local de seguridad para equipos SIN EDR
 Sustituto manual de consultas KQL (Sentinel / Defender)
=================================================================
 Modulos (solo lectura):
   0. Telemetria disponible (Sysmon / Audit 4688)
   1. Credential Dumping / Manipulacion de procesos vitales
   2. Persistencia / AppX sospechoso / PowerShell malicioso
   2b. Persistencia avanzada (Run, Tasks, Services, WMI)
   3. Software desactualizado y CVE (NIST NVD)
   4. Extensiones de navegador corruptas o de alto riesgo
   6. Postura de Windows Defender

 Modulo que SI modifica el sistema (opt-in explicito):
   5. Parcheo: punto de restauracion + winget upgrade + diff

 Uso interactivo (menu):
   .\CYBER-AD-SentinelLite3.ps1

 Uso CLI (no muestra menu, ejecuta y sale):
   .\CYBER-AD-SentinelLite3.ps1 -Modulos Todos
   .\CYBER-AD-SentinelLite3.ps1 -Modulos Extensiones,Defender
   .\CYBER-AD-SentinelLite3.ps1 -Modulos Todos,Parcheo -AutoConfirmar
   .\CYBER-AD-SentinelLite3.ps1 -Modulos Todos -ExportarHtml
=================================================================
#>

param(
    [ValidateSet('Telemetria','Credenciales','Persistencia','PersistenciaAvanzada',
                 'Software','Extensiones','Defender','Parcheo','Todos')]
    [string[]]$Modulos = @('Todos'),

    [switch]$AutoConfirmar,
    [switch]$ExportarHtml,
    [string]$NvdApiKey = $null,
    [int]$NvdDelaySeconds = 6,
    [int]$DiasVentana = 30
)

# =================================================================
# 1. VARIABLES GLOBALES
# =================================================================
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue' 

$Global:ResultadosGlobales = [System.Collections.Generic.List[PSObject]]::new()
$Global:ReporteSoftwareCVE = [System.Collections.Generic.List[PSObject]]::new()
$Global:ReporteExtensiones = [System.Collections.Generic.List[PSObject]]::new()
$Global:NvdCache           = @{}
$Global:NvdCachePath       = Join-Path $env:TEMP "CYBERAD_NvdCache.json"
$Global:Timestamp          = Get-Date -Format 'yyyyMMdd_HHmmss'
$Global:RutaBase           = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

$Global:OptExportarHtml  = [bool]$ExportarHtml
$Global:OptAutoConfirmar = [bool]$AutoConfirmar
$Global:OptNvdApiKey     = $NvdApiKey
$Global:OptDiasVentana   = $DiasVentana
$Global:OptNvdDelay      = $NvdDelaySeconds

# Mapa de CPE manual para productos con nombre ambiguo en NVD.
# Sin esto, productos como "Microsoft Edge" se mapean al Edge Legacy (obsoleto)
# y devuelven CVEs de 2016 en lugar de los del Edge Chromium actual.
$Global:CpeMap = @{
    # Microsoft Edge (Chromium, actual) - NO confundir con "microsoft:edge" (Legacy)
    'Microsoft.Edge'                = @{ Vendor='microsoft'; Product='edge_chromium' }
    'Microsoft.EdgeWebView2Runtime' = @{ Vendor='microsoft'; Product='edge_chromium' }
    'Microsoft.EdgeUpdate'          = @{ Vendor='microsoft'; Product='edge_chromium' }

    # Outlook nuevo (UWP) - NO confundir con "microsoft:outlook" (clasico Win32)
    # Outlook nuevo (UWP) - NO confundir con "microsoft:outlook" (clasico Win32)
    'Microsoft.OutlookForWindows'   = @{ Vendor='microsoft'; Product='outlook_for_windows' }
    'Microsoft.Outlook'             = @{ Vendor='microsoft'; Product='outlook_for_windows' }

    # OneDrive
    'Microsoft.OneDrive'            = @{ Vendor='microsoft'; Product='onedrive' }

    # Office y derivados
    'Microsoft.Office'              = @{ Vendor='microsoft'; Product='office' }
    'Microsoft.Office.OneNote'      = @{ Vendor='microsoft'; Product='onenote' }
    'Microsoft.Teams'               = @{ Vendor='microsoft'; Product='teams' }

    # Python Launcher (producto especifico, no Python base)
    'Python.Launcher'               = @{ Vendor='python';    Product='launcher' }
    'Python.Python.3.10'            = @{ Vendor='python';    Product='python' }
    'Python.Python.3.11'            = @{ Vendor='python';    Product='python' }
    'Python.Python.3.12'            = @{ Vendor='python';    Product='python' }
    'Python.Python.3.13'            = @{ Vendor='python';    Product='python' }

    # Navegadores
    'Google.Chrome'                 = @{ Vendor='google';    Product='chrome' }
    'Mozilla.Firefox'               = @{ Vendor='mozilla';   Product='firefox' }
    'Brave.Brave'                   = @{ Vendor='brave';     Product='brave' }

    # Utilidades comunes
    '7zip.7zip'                     = @{ Vendor='7-zip';     Product='7-zip' }
    'Notepad++.Notepad++'           = @{ Vendor='notepad-plus-plus'; Product='notepad_plus_plus' }
    'WinRAR.WinRAR'                 = @{ Vendor='rarlab';    Product='winrar' }
    'VideoLAN.VLC'                  = @{ Vendor='videolan';  Product='vlc_media_player' }

    # Adobe
    'Adobe.Acrobat.Reader.64-bit'   = @{ Vendor='adobe';     Product='acrobat_reader_dc' }
    'Adobe.Acrobat.Reader.32-bit'   = @{ Vendor='adobe';     Product='acrobat_reader_dc' }
    'Adobe.Acrobat.Reader'          = @{ Vendor='adobe';     Product='acrobat_reader_dc' }

    # Oracle
    'Oracle.VirtualBox'             = @{ Vendor='oracle';    Product='vm_virtualbox' }

    # Editores / herramientas dev
    'Microsoft.VisualStudioCode'    = @{ Vendor='microsoft'; Product='visual_studio_code' }
    'Git.Git'                       = @{ Vendor='git-scm';   Product='git' }
    'OpenJS.NodeJS'                 = @{ Vendor='nodejs';    Product='node.js' }
    'OpenJS.NodeJS.LTS'             = @{ Vendor='nodejs';    Product='node.js' }
}
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try { chcp 65001 > $null } catch { }

# =================================================================
# 2. UTILIDADES
# =================================================================
function Write-Banner ($Texto) {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "  $Texto" -ForegroundColor Cyan
    Write-Host "=================================================================`n" -ForegroundColor Cyan
}

function Show-BannerInicio {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor DarkGreen
    Write-Host "   ____ _   _ ____  _____ ____      _    ____               " -ForegroundColor Green
    Write-Host "  / ___| | | | __ )| ____|  _ \    / \  |  _ \              " -ForegroundColor Green
    Write-Host " | |   | | | |  _ \|  _| | |_) |  / _ \ | | | |             " -ForegroundColor Green
    Write-Host " | |___| |_| | |_) | |___|  _ <  / ___ \| |_| |             " -ForegroundColor Green
    Write-Host "  \____|\__, |____/|_____|_| \_\/_/   \_\____/              " -ForegroundColor Green
    Write-Host "        |___/                                               " -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor DarkGreen
    Write-Host " [+] CYBER-AD Sentinel-Lite v3 - Auditoria de Seguridad" -ForegroundColor Cyan
    Write-Host " [+] Estado: Sistema listo para iniciar modulos..." -ForegroundColor Yellow
    Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host ""
}

function Set-ConsolaAncha {
    try {
        $ui = $Host.UI.RawUI
        $anchoDeseado = 160
        if ($ui.BufferSize.Width -lt $anchoDeseado) {
            $buffer = $ui.BufferSize; $buffer.Width = $anchoDeseado; $ui.BufferSize = $buffer
        }
        if ($ui.WindowSize.Width -lt $anchoDeseado -and $ui.MaxWindowSize.Width -ge $anchoDeseado) {
            $window = $ui.WindowSize; $window.Width = $anchoDeseado; $ui.WindowSize = $window
        }
    } catch { }
}

function Limitar-Texto ($Texto, $Max) {
    if (-not $Texto) { return "" }
    $Texto = [string]$Texto
    if ($Texto.Length -le $Max) { return $Texto }
    return $Texto.Substring(0, [Math]::Max(0, $Max - 3)) + "..."
}

function Get-ColorSeveridad ($Sev) {
    switch -Regex ($Sev) {
        'CRITICAL'        { return 'Red' }
        'HIGH|ALTA'       { return 'Yellow' }
        'MEDIA|REVISAR'   { return 'DarkYellow' }
        'RESUELTO|LIMPIO' { return 'Green' }
        'ERROR'           { return 'Red' }
        default           { return 'Gray' }
    }
}

function Get-RangoSeveridad ($Sev) {
    switch -Regex ($Sev) {
        'CRITICAL'      { return 0 }
        'HIGH|ALTA'     { return 1 }
        'ERROR'         { return 2 }
        'MEDIA|REVISAR' { return 3 }
        'PENDIENTE'     { return 4 }
        'INFO'          { return 5 }
        default         { return 6 }
    }
}

function Add-Resultado ($Modulo, $Severidad, $Hallazgo, $Detalle) {
    $Global:ResultadosGlobales.Add([PSCustomObject]@{
        Modulo    = $Modulo
        Severidad = $Severidad
        Hallazgo  = $Hallazgo
        Detalle   = $Detalle
    })
}

function Reset-Resultados {
    $Global:ResultadosGlobales = [System.Collections.Generic.List[PSObject]]::new()
    $Global:ReporteSoftwareCVE = [System.Collections.Generic.List[PSObject]]::new()
    $Global:ReporteExtensiones = [System.Collections.Generic.List[PSObject]]::new()
}

# =================================================================
# 3. CLIENTE NVD
# =================================================================
function Load-NvdCache {
    if (Test-Path $Global:NvdCachePath) {
        try {
            $raw = Get-Content $Global:NvdCachePath -Raw -ErrorAction Stop
            $Global:NvdCache = $raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        } catch { $Global:NvdCache = @{} }
    }
}

function Save-NvdCache {
    try {
        $Global:NvdCache | ConvertTo-Json -Depth 5 | Set-Content $Global:NvdCachePath -Encoding UTF8
    } catch { }
}

function Get-CVEByCpe {
    param(
        [string]$Vendor,
        [string]$Product,
        [string]$Version,
        [int]$MaxCves = 3
    )

    # Clave de cache
    $cacheKey = "$Vendor|$Product|$Version"
    if ($Global:NvdCache.ContainsKey($cacheKey)) {
        return $Global:NvdCache[$cacheKey]
    }

    # CPE 2.3 sin wildcard en version (match exacto)
        # Validar formato de version: no rangos (<, >, ~), no vacios, no con espacios
    if (-not $Version -or $Version -match '[<>=~]' -or $Version -match '\s') {
        $valor = 'Version no valida para consulta CPE (rango o formato desconocido)'
        $Global:NvdCache[$cacheKey] = $valor
        Save-NvdCache
        return $valor
    }

    # CPE 2.3 sin wildcard en version (match exacto)
    $cpe = "cpe:2.3:a:$Vendor`:$Product`:$Version"

    $headers = @{}
    if ($Global:OptNvdApiKey) { $headers['apiKey'] = $Global:OptNvdApiKey }

    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$([uri]::EscapeDataString($cpe))"

    Write-Host "    NVD cpeName: $cpe" -ForegroundColor DarkGray

     $valor = $null
    $intentos = 0
    $maxIntentos = 2
    $agotoIntentos = $false

    while ($intentos -lt $maxIntentos) {
        $intentos++
        try {
            $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -TimeoutSec 25 -ErrorAction Stop

            if ($resp.vulnerabilities -and $resp.vulnerabilities.Count -gt 0) {
                $cvesFiltrados = @()
                foreach ($v in $resp.vulnerabilities) {
                    $id = $v.cve.id
                    $score = 0.0
                    try {
                        $metrics = $v.cve.metrics
                        if ($metrics.cvssMetricV31) { $score = [double]$metrics.cvssMetricV31[0].cvssData.baseScore }
                        elseif ($metrics.cvssMetricV30) { $score = [double]$metrics.cvssMetricV30[0].cvssData.baseScore }
                        elseif ($metrics.cvssMetricV2)  { $score = [double]$metrics.cvssMetricV2[0].cvssData.baseScore }
                    } catch { }

                    if ($score -ge 4.0) {
                        $cvesFiltrados += "$id (CVSS $score)"
                    }
                }
                if ($cvesFiltrados.Count -gt 0) {
                    $valor = ($cvesFiltrados | Select-Object -First $MaxCves) -join ", "
                } else {
                    $valor = "Solo CVEs de bajo impacto (< 4.0 CVSS)"
                }
            } else {
                $valor = "Sin CVE aplicable a esta version"
            }
            $agotoIntentos = $false
            break
        } catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            if ($status -eq 403 -or $status -eq 429) {
                if ($intentos -lt $maxIntentos) {
                    $retryAfter = 6 * $intentos
                    Write-Host "    [!] Rate limit NVD. Esperando $retryAfter s..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds $retryAfter
                } else {
                    $agotoIntentos = $true
                }
            } else {
                $valor = "Consulta NVD fallida"
                $agotoIntentos = $false
                break
            }
        }
    }

    if ($agotoIntentos -or -not $valor) {
        $valor = "Consulta NVD fallida (rate limit agotado)"
    }

    $Global:NvdCache[$cacheKey] = $valor
    Save-NvdCache

    $delay = if ($Global:OptNvdApiKey) { 1.2 } else { $Global:OptNvdDelay }
    Start-Sleep -Seconds $delay

    return $valor
}

# =================================================================
# 4. MODULO 0 - TELEMETRIA
# =================================================================
function Test-TelemetriaDisponible {
    Write-Banner "MODULO 0: VERIFICANDO TELEMETRIA DISPONIBLE"

    $SysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    $TieneSysmon = $null -ne $SysmonLog

    $AuditPol = auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" 2>$null
    if (-not $AuditPol) { $AuditPol = auditpol /get /subcategory:"Process Creation" 2>$null }
    # Convertir a string concatenado para que -match devuelva boolean (no array)
    $AuditPolTexto = if ($AuditPol -is [array]) { $AuditPol -join "`n" } else { [string]$AuditPol }
    $AuditActivo = [bool]($AuditPolTexto -match "Correcto|Success")

    $RegCmdLine = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    $CmdLineHabilitado = $RegCmdLine.ProcessCreationIncludeCmdLine_Enabled -eq 1

    Write-Host "[+] Sysmon instalado:              $(if($TieneSysmon){'SI'}else{'NO'})" -ForegroundColor $(if($TieneSysmon){'Green'}else{'Red'})
    Write-Host "[+] Audit 'Creacion de proceso':    $(if($AuditActivo){'ACTIVO'}else{'INACTIVO'})" -ForegroundColor $(if($AuditActivo){'Green'}else{'Red'})
    Write-Host "[+] Linea de comandos en 4688:      $(if($CmdLineHabilitado){'HABILITADO'}else{'DESHABILITADO'})" -ForegroundColor $(if($CmdLineHabilitado){'Green'}else{'Red'})

    $Cobertura = if ($TieneSysmon) { "COMPLETA (Sysmon)" }
                 elseif ($AuditActivo -and $CmdLineHabilitado) { "PARCIAL (4688 con cmdline)" }
                 elseif ($AuditActivo) { "MINIMA (4688 sin cmdline)" }
                 else { "NULA" }

    if ($Cobertura -eq "NULA") {
        Write-Host "`n[!] ADVERTENCIA: No hay telemetria de creacion de procesos." -ForegroundColor Red
        Write-Host "    Los resultados de los modulos 1 y 2 NO seran confiables." -ForegroundColor Red
    } else {
        Write-Host "`n[+] Cobertura de telemetria: $Cobertura" -ForegroundColor Green
    }

    Add-Resultado '0. Telemetria' `
        $(if ($Cobertura -eq 'NULA') { 'CRITICAL' } elseif ($Cobertura -like 'MINIMA*') { 'MEDIA' } else { 'INFO' }) `
        "Cobertura: $Cobertura" `
        "Sysmon=$TieneSysmon | Audit4688=$AuditActivo | CmdLine=$CmdLineHabilitado"

    Enable-TelemetriaFaltante -TieneSysmon $TieneSysmon -AuditActivo $AuditActivo -CmdLineHabilitado $CmdLineHabilitado
}

function Enable-TelemetriaFaltante {
    param($TieneSysmon, $AuditActivo, $CmdLineHabilitado)

    if (-not $AuditActivo -or -not $CmdLineHabilitado) {
        Write-Host "`n[?] La auditoria nativa de Windows (4688) esta incompleta." -ForegroundColor Yellow

        $activar = $false
        if ($Global:OptAutoConfirmar) {
            $activar = $true
            Write-Host "    (-AutoConfirmar activo: se habilita automaticamente)" -ForegroundColor Gray
        } else {
            $resp = Read-Host "    Deseas habilitarla ahora (S/N)"
            $activar = $resp -match '^[Ss]'
        }

        if ($activar) {
            try {
                auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
                if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit")) {
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
                }
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
                    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force | Out-Null
                Write-Host "    -> Auditoria 4688 + linea de comandos habilitadas.`n" -ForegroundColor Green
                Add-Resultado '0. Telemetria' 'RESUELTO' 'Auditoria 4688 habilitada por el script' '-'
            } catch {
                Write-Host "    -> [!] No se pudo habilitar: $($_.Exception.Message)`n" -ForegroundColor Red
            }
        } else {
            Write-Host "    -> Omitido.`n" -ForegroundColor DarkYellow
        }
    }

    if (-not $TieneSysmon) {
        Write-Host "`n[?] Sysmon no esta instalado en este equipo." -ForegroundColor Yellow

        $instalar = $false
        if ($Global:OptAutoConfirmar) {
            $instalar = $true
            Write-Host "    (-AutoConfirmar activo: se instala automaticamente)" -ForegroundColor Gray
        } else {
            $resp = Read-Host "    Deseas descargar e instalar Sysmon ahora (S/N)"
            $instalar = $resp -match '^[Ss]'
        }

        if ($instalar) {
            Install-SysmonSeguro
        } else {
            Write-Host "    -> Omitido.`n" -ForegroundColor DarkYellow
        }
    }
}

function Install-SysmonSeguro {
    try {
        $TempDir = Join-Path $env:TEMP "CYBER-AD_Sysmon"
        New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
        $SysmonExe = Join-Path $TempDir "Sysmon64.exe"
        $ConfigPath = Join-Path $TempDir "sysmonconfig.xml"
        

        Write-Host "    Descargando Sysmon..." -ForegroundColor Gray
        Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile $SysmonExe -ErrorAction Stop

          # Sysinternals no publica un fichero .sha256.txt oficial en live.sysinternals.com.
        # Se calcula el hash del binario descargado y se muestra en el log para auditoria,
        # pero no se verifica contra una fuente externa que no existe.
        $hashReal = (Get-FileHash -Path $SysmonExe -Algorithm SHA256).Hash.ToLower()
        Write-Host "    -> SHA256 del binario descargado: $hashReal" -ForegroundColor Gray
        Write-Host "    -> (Sysinternals no publica hash oficial verificable en esa URL; se instala confiando en HTTPS)" -ForegroundColor DarkGray

        $ConfigOk = $false
        try {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $ConfigPath -ErrorAction Stop
            $ConfigOk = $true
        } catch { }

        if ($ConfigOk) {
            & $SysmonExe -accepteula -i $ConfigPath | Out-Null
        } else {
            & $SysmonExe -accepteula -i | Out-Null
        }

        Start-Sleep -Seconds 2
        $Verificar = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
        if ($Verificar) {
            Write-Host "    -> Sysmon instalado y funcionando.`n" -ForegroundColor Green
            Add-Resultado '0. Telemetria' 'RESUELTO' 'Sysmon instalado (hash calculado para auditoria)' '-'
        } else {
            Write-Host "    -> [!] No se pudo verificar el servicio.`n" -ForegroundColor DarkYellow
        }
    } catch {
        Write-Host "    -> [!] No se pudo instalar Sysmon: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# =================================================================
# 5. MODULO 1 - CREDENTIAL DUMPING
# =================================================================
function Test-CredentialDumping {
    Write-Banner "MODULO 1: CREDENTIAL DUMPING Y PROCESOS VITALES"

    $UsuarioActual = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
    if (-not $UsuarioActual) { $UsuarioActual = "Desconocido / Sin sesion activa" }
    Write-Host "[+] Usuario en sesion: $UsuarioActual" -ForegroundColor Gray

    $FechaLimite = (Get-Date).AddDays(-$Global:OptDiasVentana)
    $EventosProcesos = [System.Collections.Generic.List[PSObject]]::new()

    # Sysmon Event 1: ProcessCreate
    $SysmonExiste = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    if ($SysmonExiste) {
        Write-Host "[+] Escaneando Sysmon Event 1 (ProcessCreate)..." -ForegroundColor Gray
        $Events = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$FechaLimite } -ErrorAction SilentlyContinue
        foreach ($evt in $Events) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = $item.'#text' }
            $EventosProcesos.Add([PSCustomObject]@{
                Timestamp                 = $evt.TimeCreated
                FileName                  = [System.IO.Path]::GetFileName($data['Image'])
                ProcessCommandLine        = $data['CommandLine']
                InitiatingProcessFileName = [System.IO.Path]::GetFileName($data['ParentImage'])
                InitiatingAccount         = $data['User']
                Fuente                    = 'Sysmon-E1'
            })
        }

        Write-Host "[+] Escaneando Sysmon Event 10 (ProcessAccess a LSASS)..." -ForegroundColor Gray
        $Events10 = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=10; StartTime=$FechaLimite } -ErrorAction SilentlyContinue
        foreach ($evt in $Events10) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = $item.'#text' }
            $target = $data['TargetImage']
            if ($target -match '(?i)lsass\.exe|lsaiso\.exe') {
                $source = [System.IO.Path]::GetFileName($data['SourceImage'])
                if ($source -in @('MsMpEng.exe','svchost.exe','csrss.exe','wininit.exe','services.exe')) { continue }
                $EventosProcesos.Add([PSCustomObject]@{
                    Timestamp                 = $evt.TimeCreated
                    FileName                  = $source
                    ProcessCommandLine        = "GrantedAccess=$($data['GrantedAccess']) TargetImage=$target"
                    InitiatingProcessFileName = '(ProcessAccess)'
                    InitiatingAccount         = $data['SourceUser']
                    Fuente                    = 'Sysmon-E10'
                })
            }
        }
    }

    # Security Event 4688
    Write-Host "[+] Escaneando Security 4688..." -ForegroundColor Gray
    $EventsSec = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=$FechaLimite } -ErrorAction SilentlyContinue
    foreach ($evt in $EventsSec) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = $item.'#text' }
        $EventosProcesos.Add([PSCustomObject]@{
            Timestamp                 = $evt.TimeCreated
            FileName                  = [System.IO.Path]::GetFileName($data['NewProcessName'])
            ProcessCommandLine        = $data['CommandLine']
            InitiatingProcessFileName = [System.IO.Path]::GetFileName($data['ParentProcessName'])
            InitiatingAccount         = $data['SubjectUserName']
            Fuente                    = 'Security-4688'
        })
    }

    $Resultados = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($proc in $EventosProcesos) {
        $FileName = if ($proc.FileName) { $proc.FileName.ToLower() } else { "" }
        $CmdLine  = if ($proc.ProcessCommandLine) { $proc.ProcessCommandLine.ToLower() } else { "" }
        $Diag = "Normal"

        if (($FileName -eq "procdump.exe" -or $FileName -eq "procdump64.exe") -and ($CmdLine -like "*lsass*" -or $CmdLine -like "*lsaiso*")) {
            $Diag = "CRITICAL: Uso de ProcDump contra LSASS"
        }
        elseif ($FileName -eq "rundll32.exe" -and $CmdLine -like "*comsvcs.dll*" -and $CmdLine -like "*minidump*") {
            $Diag = "CRITICAL: rundll32 abusando comsvcs para volcar memoria"
        }
        elseif ($FileName -eq "taskmgr.exe" -and ($CmdLine -like "*lsass*" -or $CmdLine -like "*lsaiso*")) {
            $Diag = "HIGH: Administrador de Tareas interactuando con LSASS"
        }
        elseif (@("cdb.exe","ntsd.exe","windbg.exe","livekd.exe","livekd64.exe","kd.exe") -contains $FileName -and ($CmdLine -like "*lsass*" -or $CmdLine -like "*lsaiso*")) {
            $Diag = "CRITICAL: Uso de depuradores contra procesos de credenciales"
        }
        elseif (($CmdLine -like "*msmpeng.exe*" -or $CmdLine -like "*sppsvc.exe*" -or $CmdLine -like "*smss.exe*" -or $CmdLine -like "*csrss.exe*" -or $CmdLine -like "*wininit.exe*" -or $CmdLine -like "*services.exe*") -and ($CmdLine -like "*stop*" -or $CmdLine -like "*disable*" -or $CmdLine -like "*kill*" -or $CmdLine -like "*suspend*")) {
            $Diag = "CRITICAL: Intento de detener servicios PPL/Antivirus"
        }
        elseif ($FileName -eq "ntdsutil.exe" -and ($CmdLine -like "*ac i ntds*" -or $CmdLine -like "*ifm*")) {
            $Diag = "CRITICAL: Extraccion de NTDS.dit"
        }
        elseif (@("mimikatz.exe","nanodump.exe","safetykatz.exe","rubeus.exe") -contains $FileName) {
            $Diag = "CRITICAL: Herramienta de robo de credenciales detectada"
        }
        elseif ($proc.Fuente -eq 'Sysmon-E10' -and $CmdLine -match 'GrantedAccess=0x(1010|1410|143a|1fffff)') {
            $Diag = "CRITICAL: Acceso sospechoso a LSASS (Sysmon E10)"
        }

        if ($Diag -ne "Normal") {
            $Resultados.Add([PSCustomObject]@{
                Hora         = $proc.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
                Fuente       = $proc.Fuente
                Diagnostico  = $Diag
                Proceso      = $proc.FileName
                LineaComando = $proc.ProcessCommandLine
                ProcesoPadre = $proc.InitiatingProcessFileName
                Usuario      = $proc.InitiatingAccount
            })
        }
    }

    if ($Resultados.Count -gt 0) {
        $Resultados | Format-Table -AutoSize
        foreach ($r in $Resultados) {
            Add-Resultado '1. Credential Dumping' ($r.Diagnostico -split ':')[0] $r.Diagnostico "$($r.Proceso) | $($r.Hora) | $($r.Fuente)"
        }
    } else {
        Write-Host "[-] Sin hallazgos de credential dumping." -ForegroundColor Green
        Add-Resultado '1. Credential Dumping' 'LIMPIO' 'Sin hallazgos' '-'
    }
}
# =================================================================
# 5b. MODULO 1b - RELACIONES PADRE-HIJO ANOMALAS
# =================================================================
function Test-ProcesosPadreHijo {
    Write-Banner "MODULO 1b: RELACIONES PADRE-HIJO ANOMALAS"

    $CombinacionesSospechosas = @(
        @{ Padre='winword.exe';   Hijo='powershell.exe'; Sev='CRITICAL'; Razon='Macro Office ejecutando PowerShell' }
        @{ Padre='winword.exe';   Hijo='cmd.exe';        Sev='CRITICAL'; Razon='Macro Office ejecutando cmd' }
        @{ Padre='winword.exe';   Hijo='wscript.exe';    Sev='CRITICAL'; Razon='Macro Office ejecutando WScript' }
        @{ Padre='excel.exe';     Hijo='powershell.exe'; Sev='CRITICAL'; Razon='Macro Excel ejecutando PowerShell' }
        @{ Padre='outlook.exe';   Hijo='cmd.exe';        Sev='ALTA';     Razon='Outlook ejecutando cmd (phishing)' }
        @{ Padre='outlook.exe';   Hijo='powershell.exe'; Sev='ALTA';     Razon='Outlook ejecutando PowerShell' }
        @{ Padre='services.exe';  Hijo='powershell.exe'; Sev='ALTA';     Razon='Servicio ejecutando PowerShell' }
        @{ Padre='services.exe';  Hijo='cmd.exe';        Sev='ALTA';     Razon='Servicio ejecutando cmd' }
        @{ Padre='w3wp.exe';      Hijo='cmd.exe';        Sev='CRITICAL'; Razon='IIS ejecutando cmd (webshell)' }
        @{ Padre='w3wp.exe';      Hijo='powershell.exe'; Sev='CRITICAL'; Razon='IIS ejecutando PowerShell' }
        @{ Padre='httpd.exe';     Hijo='cmd.exe';        Sev='CRITICAL'; Razon='Apache ejecutando cmd' }
        @{ Padre='nginx.exe';     Hijo='powershell.exe'; Sev='CRITICAL'; Razon='Nginx ejecutando PowerShell' }
        @{ Padre='wmiprvse.exe';  Hijo='cmd.exe';        Sev='ALTA';     Razon='WMI ejecutando cmd' }
        @{ Padre='mshta.exe';     Hijo='powershell.exe'; Sev='ALTA';     Razon='MSHTA ejecutando PowerShell' }
        @{ Padre='regsvr32.exe';  Hijo='cmd.exe';        Sev='ALTA';     Razon='Regsvr32 ejecutando cmd' }
    )

    $FechaLimite = (Get-Date).AddDays(-$Global:OptDiasVentana)
    $SysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    if (-not $SysmonLog) {
        Write-Host "[!] Sysmon no disponible. Modulo omitido." -ForegroundColor Yellow
        Add-Resultado '1b. Padre-Hijo' 'MEDIA' 'Sysmon no disponible' '-'
        return
    }

    Write-Host "[+] Analizando relaciones padre-hijo en Sysmon E1 ($($Global:OptDiasVentana) dias)..." -ForegroundColor Yellow
    $Events = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$FechaLimite } -ErrorAction SilentlyContinue

    $Hallazgos = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($evt in $Events) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = $item.'#text' }

        $padre = if ($data['ParentImage']) { [System.IO.Path]::GetFileName($data['ParentImage']).ToLower() } else { '' }
        $hijo  = if ($data['Image']) { [System.IO.Path]::GetFileName($data['Image']).ToLower() } else { '' }

        foreach ($combo in $CombinacionesSospechosas) {
            if ($padre -eq $combo.Padre -and $hijo -eq $combo.Hijo) {
                $Hallazgos.Add([PSCustomObject]@{
                    Timestamp = $evt.TimeCreated
                    Padre = $padre
                    Hijo = $hijo
                    Razon = $combo.Razon
                    Severidad = $combo.Sev
                    Comando = $data['CommandLine']
                    Usuario = $data['User']
                })
                break
            }
        }
    }

    if ($Hallazgos.Count -gt 0) {
        $Hallazgos | Format-Table Timestamp, Padre, Hijo, Severidad -AutoSize
        foreach ($h in $Hallazgos) {
            Add-Resultado '1b. Padre-Hijo' $h.Severidad `
                "Relacion padre-hijo: $($h.Padre) -> $($h.Hijo)" `
                "$($h.Razon) | $($h.Timestamp) | Cmd: $(Limitar-Texto $h.Comando 60)"
        }
    } else {
        Write-Host "[-] Sin relaciones padre-hijo anomalas detectadas." -ForegroundColor Green
        Add-Resultado '1b. Padre-Hijo' 'LIMPIO' 'Sin hallazgos' '-'
    }
}
# =================================================================
# 5c. MODULO 1c - CONEXIONES DE RED Y CONSULTAS DNS
# =================================================================
function Test-RedDns {
    Write-Banner "MODULO 1c: CONEXIONES DE RED Y CONSULTAS DNS"

    $FechaLimite = (Get-Date).AddDays(-$Global:OptDiasVentana)
    $SysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    if (-not $SysmonLog) {
        Write-Host "[!] Sysmon no disponible. Modulo omitido." -ForegroundColor Yellow
        Add-Resultado '1c. Red/DNS' 'MEDIA' 'Sysmon no disponible' '-'
        return
    }

      # Whitelist de procesos conocidos como legitimos para evitar falsos positivos
    # (aunque corran desde AppData, son aplicaciones oficiales)
        $ProcesosLegitimos = @(
        # Aplicaciones de usuario comunes
        'OneDrive.exe','Teams.exe','ms-teams.exe','msedge.exe','chrome.exe','firefox.exe',
        'Code.exe','Discord.exe','Slack.exe','Zoom.exe','Spotify.exe','Steam.exe',
        'MicrosoftEdgeUpdate.exe','GoogleUpdate.exe','MicrosoftEdgeCP.exe',
        # Software de audio de fabricantes
        'nahimicNotifSys.exe','NahimicSvc32.exe','NahimicSvc64.exe',
        'RtkAudUService64.exe','RtkAudioService64.exe',
        # Utilidades gaming
        'RazerSynapseService.exe','LGHUB.exe','Corsair.Service.exe',
        # Utilidades de fabricante
        'LenovoVantageService.exe','Lenovo.Modern.ImController.exe',
        'Dell.Command.Update.exe','Dell.Digital.Delivery.exe',
        # Otros comunes
        'Everything.exe','Greenshot.exe','ShareX.exe'
    )

    Write-Host "[1/2] Analizando conexiones de red (Sysmon E3)..." -ForegroundColor Yellow
    $NetEvents = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=3; StartTime=$FechaLimite } -ErrorAction SilentlyContinue

    $ProcesosSospechosos = @()
    $ConexionesPorProceso = @{}

    foreach ($evt in $NetEvents) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = $item.'#text' }

        $img = [System.IO.Path]::GetFileName($data['Image'])
        $destIp = $data['DestinationIp']
        $destPort = $data['DestinationPort']

        if ($destIp -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|::1|fe80:)') { continue }

        $key = $img
        if (-not $ConexionesPorProceso.ContainsKey($key)) {
            $ConexionesPorProceso[$key] = [PSCustomObject]@{
                Proceso = $img
                IPs = [System.Collections.Generic.HashSet[string]]::new()
                Puertos = [System.Collections.Generic.HashSet[string]]::new()
                Count = 0
                ImagenRuta = $data['Image']
            }
        }
        $ConexionesPorProceso[$key].IPs.Add($destIp) | Out-Null
        $ConexionesPorProceso[$key].Puertos.Add($destPort) | Out-Null
        $ConexionesPorProceso[$key].Count++
    }

    foreach ($proc in $ConexionesPorProceso.Values) {
        $sospechoso = $false
        $motivos = @()

        if ($ProcesosLegitimos -contains $proc.Proceso) { continue }

        if ($proc.ImagenRuta -match '(?i)(\\temp\\|\\appdata\\|\\users\\public\\|\\downloads\\)') {
            $sospechoso = $true; $motivos += 'Proceso en ruta sospechosa'
        }
        if ($proc.IPs.Count -gt 10) {
            $sospechoso = $true; $motivos += "Muchas IPs destino ($($proc.IPs.Count))"
        }
        if ($proc.Puertos.Count -gt 5) {
            $sospechoso = $true; $motivos += "Muchos puertos ($($proc.Puertos.Count))"
        }

        if ($sospechoso) {
            $ProcesosSospechosos += [PSCustomObject]@{
                Proceso = $proc.Proceso
                Conexiones = $proc.Count
                IPsUnicas = $proc.IPs.Count
                PuertosUnicos = $proc.Puertos.Count
                Motivo = ($motivos -join ' | ')
                Ruta = $proc.ImagenRuta
            }
        }
    }

    if ($ProcesosSospechosos.Count -gt 0) {
        $ProcesosSospechosos | Format-Table Proceso, Conexiones, IPsUnicas, PuertosUnicos, Motivo -AutoSize
        foreach ($p in $ProcesosSospechosos) {
            Add-Resultado '1c. Red/DNS' 'ALTA' "Conexion sospechosa: $($p.Proceso)" "$($p.Motivo) | $($p.Ruta)"
        }
    } else {
        Write-Host "[-] Sin conexiones de red anomalas." -ForegroundColor Green
    }

    Write-Host "[2/2] Analizando consultas DNS (Sysmon E22)..." -ForegroundColor Yellow
    $DnsEvents = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=22; StartTime=$FechaLimite } -ErrorAction SilentlyContinue

    $DominiosPorProceso = @{}

    foreach ($evt in $DnsEvents) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = $item.'#text' }

        $img = [System.IO.Path]::GetFileName($data['Image'])
        $query = $data['QueryName']

        if (-not $DominiosPorProceso.ContainsKey($img)) {
            $DominiosPorProceso[$img] = [System.Collections.Generic.List[string]]::new()
        }
        $DominiosPorProceso[$img].Add($query)
    }

     # Dominios legitimos de altisimo volumen que nunca se marcan como tunneling
    $DominiosConfianza = @(
        'google.com','gstatic.com','googleapis.com','googleusercontent.com',
        'googlevideo.com','googleadservices.com','googlesyndication.com',
        'doubleclick.net','gvt1.com','gvt2.com','ytimg.com','youtube.com',
        'microsoft.com','windows.com','windowsupdate.com','live.com','msn.com',
        'office.com','office365.com','sharepoint.com','onedrive.com',
        'microsoftonline.com','bing.com','azure.com','azurewebsites.net',
        'cloudflare.com','cloudflare-dns.com','akamai.net','akamaiedge.net',
        'akamaitechnologies.com','fastly.net','amazonaws.com','cloudfront.net',
        'apple.com','icloud.com','mzstatic.com','cdn-apple.com',
        'facebook.com','fbcdn.net','instagram.com','whatsapp.net',
        'twitter.com','twimg.com','x.com',
        'adobe.com','adobelogin.com','adobedtm.com',
        'mozilla.org','mozilla.net','firefox.com',
        'nvidia.com','geforce.com','lenovo.com','lenovocs.com','lenovoservices.com',
        'teamviewer.com','anydesk.com','dropbox.com','dropboxusercontent.com',
        'github.com','githubusercontent.com','githubassets.com'
    )

    $DnsSospechoso = @()
    foreach ($proc in $DominiosPorProceso.Keys) {
        $queries = $DominiosPorProceso[$proc]
        $total = $queries.Count

        $dominiosRaiz = $queries | ForEach-Object {
            $partes = $_ -split '\.'
            if ($partes.Count -ge 2) { ($partes[-2..-1] -join '.') } else { $_ }
        } | Select-Object -Unique

        foreach ($dr in $dominiosRaiz) {
            # Whitelist: nunca marcar dominios masivos conocidos
            if ($DominiosConfianza -contains $dr) { continue }

            $subdominios = $queries | Where-Object { $_ -like "*.$dr" } | Select-Object -Unique
            if ($subdominios.Count -gt 50) {   # umbral subido de 20 a 50
                $DnsSospechoso += [PSCustomObject]@{
                    Proceso = $proc
                    DominioRaiz = $dr
                    SubdominiosUnicos = $subdominios.Count
                    TotalQueries = $total
                    Motivo = 'Posible DNS Tunneling'
                }
            }
        }
    }

    if ($DnsSospechoso.Count -gt 0) {
        $DnsSospechoso | Format-Table Proceso, DominioRaiz, SubdominiosUnicos, Motivo -AutoSize
        foreach ($d in $DnsSospechoso) {
            Add-Resultado '1c. Red/DNS' 'ALTA' "DNS sospechoso: $($d.DominioRaiz)" "$($d.Proceso) | $($d.SubdominiosUnicos) subdominios unicos"
        }
    } else {
        Write-Host "[-] Sin consultas DNS anomalas." -ForegroundColor Green
    }

    if ($ProcesosSospechosos.Count -eq 0 -and $DnsSospechoso.Count -eq 0) {
        Add-Resultado '1c. Red/DNS' 'LIMPIO' 'Sin hallazgos' '-'
    }
}

# =================================================================
# 6. MODULO 2 - PERSISTENCIA BASICA
# =================================================================
function Test-Persistencia {
    Write-Banner "MODULO 2: PERSISTENCIA, APPX SOSPECHOSO Y ARCHIVOS TEMP"

    Write-Host "[1/4] Eventos PowerShell 4104 ($($Global:OptDiasVentana) dias)..." -ForegroundColor Yellow
    $StartDate = (Get-Date).AddDays(-$Global:OptDiasVentana)
    $Eventos = Get-WinEvent -FilterHashtable @{ ProviderName='Microsoft-Windows-PowerShell'; Id=4104; StartTime=$StartDate } -ErrorAction SilentlyContinue |
        Where-Object {
            $sb = $_.Message
            $sb -like "*dism.exe*" -and $sb -like "*Add-ProvisionedAppxPackage*" -and
            ($sb -like "*AppxProvision*" -or $sb -like "*.appxbundle*" -or $sb -like "*MSICenter*")
        }

    Write-Host "[2/4] Paquetes DISM aprovisionados..." -ForegroundColor Yellow
    $Provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*MSICenter*" -or $_.PackageName -like "*AppxProvision*" }

    Write-Host "[3/4] Paquetes AppX de usuario..." -ForegroundColor Yellow
    $Installed = Get-AppxPackage -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*MSICenter*" -or $_.PackageFullName -like "*AppxProvision*" }

    Write-Host "[4/4] Ejecutables recientes en Temp (24h)..." -ForegroundColor Yellow
    $FechaInicio = (Get-Date).AddHours(-24)
    $Rutas = @($env:TEMP, "$env:LOCALAPPDATA\Temp", "C:\Windows\Temp")
    $Ext = @("*.exe","*.bat","*.ps1","*.vbs","*.scr")
    $ArchivosSospechosos = Get-ChildItem -Path $Rutas -Include $Ext -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -ge $FechaInicio -and $_.FullName -notlike "*\Downloads\*" }

    $Checks = @(
        @{ Nombre='Eventos PowerShell sospechosos'; Detectado=$Eventos;              Diag='Scripts sospechosos ejecutados en memoria' }
        @{ Nombre='Paquetes DISM aprovisionados';    Detectado=$Provisioned;         Diag='Malware aprovisionado en el sistema' }
        @{ Nombre='AppX de usuario sospechoso';      Detectado=$Installed;           Diag='AppX sospechoso instalado' }
        @{ Nombre='Ejecutables recientes en Temp';   Detectado=$ArchivosSospechosos; Diag='Binarios recientes sin origen claro' }
    )

    $Tabla = foreach ($c in $Checks) {
        [PSCustomObject]@{
            'Prueba'      = $c.Nombre
            'Resultado'   = if ($c.Detectado) { '[!] Detectado' } else { '[-] Limpio' }
            'Diagnostico' = if ($c.Detectado) { $c.Diag } else { 'Sin hallazgos' }
        }
        Add-Resultado '2. Persistencia' `
            $(if ($c.Detectado) { 'ALTA' } else { 'LIMPIO' }) `
            $(if ($c.Detectado) { $c.Diag } else { 'Sin hallazgos' }) `
            $c.Nombre
    }
    $Tabla | Format-Table -AutoSize
}

# =================================================================
# 7. MODULO 2b - PERSISTENCIA AVANZADA
# =================================================================
function Test-PersistenciaAvanzada {
    Write-Banner "MODULO 2b: PERSISTENCIA AVANZADA (RUN, TASKS, SERVICES, WMI)"

    $Hallazgos = [System.Collections.Generic.List[PSObject]]::new()

    Write-Host "[1/4] Run / RunOnce keys..." -ForegroundColor Yellow
    $RunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    )
      Write-Host "[1/4] Run / RunOnce keys..." -ForegroundColor Yellow
    $RunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    )

    # Whitelist de entradas Run/RunOnce conocidas como legitimas
       $RunKeysLegitimas = @(
        'OneDrive','MicrosoftEdgeAutoLaunch','Teams','com.squirrel.Teams.Teams',
        'Discord','Steam','EpicGamesLauncher','Spotify','Slack','Zoom','Everything',
        'SecurityHealth','WindowsDefender','GrooveMonitor','Adobe Reader Speed Launcher',
        'LenovoVantageToolbar','Lenovo Vantage','LenovoUtility',
        'RazerSynapse','LGHUB','Nahimic','NahimicSvc',
        'NvBackend','NvMediaCenter'
    )

    foreach ($key in $RunKeys) {
        if (Test-Path $key) {
            $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match '^PS') { continue }
                if ($RunKeysLegitimas -contains $p.Name) { continue }   # ← AÑADIDO
                $valor = [string]$p.Value
                $sospechoso = $valor -match '(?i)(temp|appdata|users\\public|programdata|\\downloads\\)' -or
                              ($valor -match '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32)' -and
                               $valor -match '(?i)(-enc|-encoded|frombase64|downloadstring|invoke-|http)')
                if ($sospechoso) {
                    $Hallazgos.Add([PSCustomObject]@{
                        Tipo='RunKey'; Ubicacion=$key; Nombre=$p.Name; Valor=Limitar-Texto $valor 80; Severidad='ALTA'
                    })
                }
            }
        }
    }

    Write-Host "[2/4] Scheduled Tasks sospechosas..." -ForegroundColor Yellow
    $Tareas = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.State -ne 'Disabled' -and $_.Actions -and
        ($_.Actions | Where-Object {
            $_.Execute -match '(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)' -and
            $_.Arguments -match '(?i)(temp|appdata|public|http|https|base64|-enc|downloadstring|invoke-|frombase64)'
        })
    }
    foreach ($t in $Tareas) {
        foreach ($a in $t.Actions) {
            $Hallazgos.Add([PSCustomObject]@{
                Tipo='ScheduledTask'
                Ubicacion="$($t.TaskPath)$($t.TaskName)"
                Nombre=$a.Execute
                Valor=Limitar-Texto "$($a.Arguments)" 80
                Severidad='ALTA'
            })
        }
    }

    Write-Host "[3/4] Servicios con binario en rutas sospechosas..." -ForegroundColor Yellow
    $Servicios = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.PathName -and ($_.PathName -match '(?i)(\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\)') -and
        $_.StartMode -ne 'Disabled'
    }
        foreach ($s in $Servicios) {
        # Excluir servicios legitimos conocidos
        if ($s.PathName -like "*\Windows Defender\*") { continue }
        if ($s.PathName -like "*\Microsoft\Windows Defender\*") { continue }
        if ($s.PathName -like "*\Google\Chrome Remote Desktop\*") { continue }
        if ($s.PathName -like "*\Program Files\Google\*") { continue }
        if ($s.PathName -like "*\NVIDIA Corporation\*") { continue }
        if ($s.PathName -like "*\DriverStore\FileRepository\nv*\*") { continue }
        if ($s.PathName -like "*\Program Files\NVIDIA*\*") { continue }
        if ($s.Name -in @(
            'MDCoreSvc','WdNisSvc','WinDefend','WdNisDrv','Sense','SecurityHealthService',
            'chromoting','NvContainerLocalSystem','NVDisplay.ContainerLocalSystem'
        )) { continue }

        $Hallazgos.Add([PSCustomObject]@{
            Tipo='Servicio'; Ubicacion=$s.Name; Nombre=$s.PathName
            Valor=$s.StartMode; Severidad='MEDIA'
        })
    }

    Write-Host "[4/4] WMI Event Subscriptions..." -ForegroundColor Yellow

    # Whitelist de filtros/consumidores WMI conocidos como legitimos (sistema)
    $WmiLegitimos = @(
        'SCM Event Log Filter','SCM Event Log Consumer',
        'BVTFilter','BVTConsumer',
        'MSFT_WmiProvider_*'
    )

    $Filtros = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    foreach ($f in $Filtros) {
        $esLegitimo = $false
        foreach ($patron in $WmiLegitimos) {
            if ($f.Name -like $patron) { $esLegitimo = $true; break }
        }
        if ($esLegitimo) { continue }   # ← AÑADIDO

        $Hallazgos.Add([PSCustomObject]@{
            Tipo='WMI_Filter'; Ubicacion='root\subscription'; Nombre=$f.Name
            Valor=Limitar-Texto $f.Query 80; Severidad='ALTA'
        })
    }

    $Consumidores = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
    foreach ($c in $Consumidores) {
        $esLegitimo = $false
        foreach ($patron in $WmiLegitimos) {
            if ($c.Name -like $patron) { $esLegitimo = $true; break }
        }
        if ($esLegitimo) { continue }   # ← AÑADIDO

        $Hallazgos.Add([PSCustomObject]@{
            Tipo='WMI_Consumer'; Ubicacion='root\subscription'; Nombre=$c.Name
            Valor=Limitar-Texto $c.CommandLineTemplate 80; Severidad='ALTA'
        })
    }
    $Consumidores = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
    foreach ($c in $Consumidores) {
        $Hallazgos.Add([PSCustomObject]@{
            Tipo='WMI_Consumer'; Ubicacion='root\subscription'; Nombre=$c.Name
            Valor=Limitar-Texto $c.CommandLineTemplate 80; Severidad='ALTA'
        })
    }

    if ($Hallazgos.Count -gt 0) {
        $Hallazgos | Format-Table Tipo, Ubicacion, Nombre, Severidad -AutoSize
        foreach ($h in $Hallazgos) {
            Add-Resultado '2b. Persistencia Avanzada' $h.Severidad "$($h.Tipo): $($h.Nombre)" $h.Ubicacion
        }
    } else {
        Write-Host "[-] Sin hallazgos de persistencia avanzada." -ForegroundColor Green
        Add-Resultado '2b. Persistencia Avanzada' 'LIMPIO' 'Sin hallazgos' '-'
    }
}
# =================================================================
# 7b. MODULO 2c - DRIVERS VULNERABLES (LOLDrivers / BYOVD)
# =================================================================
function Test-LolDrivers {
    Write-Banner "MODULO 2c: DRIVERS VULNERABLES (LOLDrivers / BYOVD)"

    $LolUrl = "https://www.loldrivers.io/api/drivers.csv"
    $LolCachePath = Join-Path $env:TEMP "CYBERAD_LolDrivers.csv"
    $LolCacheMaxAge = 24

    $necesitaDescarga = $true
    if (Test-Path $LolCachePath) {
        $edad = (Get-Date) - (Get-Item $LolCachePath).LastWriteTime
        if ($edad.TotalHours -lt $LolCacheMaxAge) { $necesitaDescarga = $false }
    }

    if ($necesitaDescarga) {
        Write-Host "[+] Descargando catalogo LOLDrivers..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri $LolUrl -OutFile $LolCachePath -ErrorAction Stop
        } catch {
            Write-Host "  [!] No se pudo descargar LOLDrivers: $($_.Exception.Message)" -ForegroundColor Red
            Add-Resultado '2c. Drivers LOLDrivers' 'ERROR' 'No se pudo descargar catalogo' '-'
            return
        }
    }

             Write-Host "  [+] Parseando catalogo CSV..." -ForegroundColor DarkGray
    try {
        $LolData = Import-Csv -Path $LolCachePath -Encoding UTF8
        if (-not $LolData -or $LolData.Count -eq 0) {
            throw "El catalogo esta vacio o mal formado"
        }
    } catch {
        Write-Host "  [!] Error parseando el catalogo: $($_.Exception.Message)" -ForegroundColor Red
        Remove-Item $LolCachePath -Force -ErrorAction SilentlyContinue
        Add-Resultado '2c. Drivers LOLDrivers' 'ERROR' "Catalogo LOLDrivers corrupto: $($_.Exception.Message)" '-'
        return
    }

    $PorHash = @{}
    $PorNombre = @{}
    foreach ($row in $LolData) {
        if ($row.SHA256) { $PorHash[$row.SHA256.ToLower()] = $row }
        if ($row.FileName) { $PorNombre[$row.FileName.ToLower()] = $row }
    }

    Write-Host "[+] Catalogo cargado: $($PorHash.Count) hashes, $($PorNombre.Count) nombres" -ForegroundColor Gray
    Write-Host "[+] Escaneando drivers del sistema..." -ForegroundColor Yellow

    $RutasDrivers = @(
        "C:\Windows\System32\drivers",
        "C:\Windows\SysWOW64\drivers"
    )

    $Hallazgos = [System.Collections.Generic.List[PSObject]]::new()
    $Escaneados = 0

    foreach ($ruta in $RutasDrivers) {
        if (-not (Test-Path $ruta)) { continue }
        $archivos = Get-ChildItem -Path $ruta -Filter "*.sys" -Recurse -ErrorAction SilentlyContinue
        foreach ($f in $archivos) {
            $Escaneados++
            $nombre = $f.Name.ToLower()

            if ($PorNombre.ContainsKey($nombre)) {
                $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
                $info = $PorNombre[$nombre]
                $tipo = if ($PorHash.ContainsKey($hash)) { 'HASH+Nombre' } else { 'Nombre' }
                $Hallazgos.Add([PSCustomObject]@{
                    Driver = $f.FullName; Nombre = $f.Name; SHA256 = $hash
                    Categoria = $info.Category; Tipo = $tipo
                    Descripcion = $info.Description
                })
                continue
            }

            $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($hash -and $PorHash.ContainsKey($hash.ToLower())) {
                $info = $PorHash[$hash.ToLower()]
                $Hallazgos.Add([PSCustomObject]@{
                    Driver = $f.FullName; Nombre = $f.Name; SHA256 = $hash.ToLower()
                    Categoria = $info.Category; Tipo = 'Hash'
                    Descripcion = $info.Description
                })
            }
        }
    }

    Write-Host "[+] Escaneados: $Escaneados archivos .sys`n" -ForegroundColor Gray

    if ($Hallazgos.Count -gt 0) {
        $Hallazgos | Format-Table Nombre, Categoria, Tipo -AutoSize
        foreach ($h in $Hallazgos) {
            $sev = if ($h.Categoria -match 'malicious') { 'CRITICAL' } else { 'ALTA' }
            Add-Resultado '2c. Drivers LOLDrivers' $sev `
                "Driver $($h.Categoria): $($h.Nombre)" "$($h.Driver) | SHA256: $($h.SHA256)"
        }
    } else {
        Write-Host "[-] Sin drivers vulnerables/maliciosos detectados." -ForegroundColor Green
        Add-Resultado '2c. Drivers LOLDrivers' 'LIMPIO' 'Sin hallazgos' "$Escaneados drivers escaneados"
    }
}

# =================================================================
# CONSTRUIR CPE DESDE WINGET
# =================================================================
function Get-CpeFromWinget {
    param([string]$WingetId)

    # 0. Consultar mapa manual PRIMERO (maxima fiabilidad)
    if ($Global:CpeMap -and $Global:CpeMap.ContainsKey($WingetId)) {
        $entry = $Global:CpeMap[$WingetId]
        Write-Host "      [OK] CPE desde mapa: $($entry.Vendor) : $($entry.Product)" -ForegroundColor DarkGreen
        return $entry
    }

    # 1. Fallback: parsear el Id "Vendor.Product"
    #    Ej: "Microsoft.Edge" -> vendor="microsoft", product="edge"
    if ($WingetId -match '^([^.]+)\.(.+)$') {
        $vendorId  = $Matches[1].ToLower() -replace '[^a-z0-9]',''
        $productId = ($Matches[2] -split '\.')[0].ToLower() -replace '[^a-z0-9]',''
        if ($vendorId -and $productId -and $vendorId -ne 'winget') {
            Write-Host "      [OK] CPE desde Id: $vendorId : $productId" -ForegroundColor DarkGreen
            return @{ Vendor = $vendorId; Product = $productId }
        }
    }

    # 2. Fallback final: winget show con soporte ES/EN
    $info = winget show --id $WingetId --exact --accept-source-agreements 2>$null | Out-String
    if (-not $info) { return $null }

    $editor = $null
    foreach ($linea in ($info -split "`r?`n")) {
        if ($linea -match '^\s*(?:Publisher|Editor):\s*(.+?)\s*$') {
            $editor = $Matches[1].Trim()
            break
        }
    }

    if (-not $editor) { return $null }

    $vendor = $editor.ToLower()
    $vendor = $vendor -replace '\s+(corporation|incorporated|inc\.?|llc|ltd\.?|s\.a\.?|gmbh|foundation|project|team|s\.l\.?|s\.a\.s\.?)\s*$',''
    $vendor = $vendor -replace '[^a-z0-9]',''

    $product = $WingetId.ToLower()
    if ($product.Contains('.')) { $product = ($product -split '\.')[-1] }
    $product = $product -replace '[^a-z0-9]',''

    if (-not $vendor -or -not $product) { return $null }

    Write-Host "      [OK] CPE desde winget show: $vendor : $product" -ForegroundColor DarkGreen
    return @{ Vendor = $vendor; Product = $product }
}

# =================================================================
# 8. SOFTWARE / CVE
# =================================================================
function Get-SoftwarePendienteWinget {
    param([switch]$ConsultarCVE)

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        return [System.Collections.Generic.List[PSObject]]::new()
    }

    Write-Host "    Consultando winget list --upgrade-available..." -ForegroundColor DarkGray
    $raw = winget list --upgrade-available --accept-source-agreements 2>$null | Out-String
    $lineas = $raw -split "`r?`n"

    # Localiza el header de la tabla
    $headerIdx = -1
    for ($i = 0; $i -lt $lineas.Count; $i++) {
        if ($lineas[$i] -match '^\s*Name\s+Id\s+Version\s+Available') { $headerIdx = $i; break }
        if ($lineas[$i] -match '^\s*Nombre\s+Id\s+Versi')          { $headerIdx = $i; break }
    }
    if ($headerIdx -lt 0) { return [System.Collections.Generic.List[PSObject]]::new() }

    $header = $lineas[$headerIdx]
    $idCol   = $header.IndexOf("Id")
    $verCol  = $header.IndexOf("Version")
    if ($verCol -lt 0) { $verCol = $header.IndexOf("Versi") }
    $dispCol = $header.IndexOf("Available")
    if ($dispCol -lt 0) { $dispCol = $header.IndexOf("Disponible") }

    $Pendientes = [System.Collections.Generic.List[PSObject]]::new()

    for ($i = $headerIdx + 1; $i -lt $lineas.Count; $i++) {
        $line = $lineas[$i]
        if (-not $line.Trim()) { continue }
        if ($line -match '^-+$') { continue }
        if ($line -match '^\s*\d+\s+(upgrade|actualizaci)') { continue }

        # Extrae nombre, id, version, available usando posiciones de columna
        $nombre = $null; $id = $null; $version = $null; $available = $null
        try {
            $nombre = $line.Substring(0, $idCol).Trim()

            $idEnd = if ($verCol -gt $idCol) { $verCol } else { $line.Length }
            if ($line.Length -ge $idEnd) {
                $id = $line.Substring($idCol, $idEnd - $idCol).Trim()
            }

            if ($line.Length -gt $verCol) {
                $verEnd = if ($dispCol -gt $verCol) { $dispCol } else { $line.Length }
                $version = $line.Substring($verCol, [Math]::Min($verEnd - $verCol, $line.Length - $verCol)).Trim()
            }

            if ($line.Length -gt $dispCol) {
                $available = $line.Substring($dispCol).Trim()
                $available = ($available -split '\s{2,}')[0]
            }
        } catch { continue }

        if (-not $nombre -or -not $id) { continue }

        # Resolver CPE
        $cpe = Get-CpeFromWinget -WingetId $id

        $Pendientes.Add([PSCustomObject]@{
            Software  = $nombre
            Id        = $id
            Version   = $version
            Available = $available
            Vendor    = if ($cpe) { $cpe.Vendor } else { $null }
            Product   = if ($cpe) { $cpe.Product } else { $null }
            CVE       = 'N/A'
        })
    }

    # Consultar CVEs por CPE
    if ($ConsultarCVE -and $Pendientes.Count -gt 0) {
        foreach ($p in $Pendientes) {
            if ($p.Vendor -and $p.Product -and $p.Version) {
                $p.CVE = Get-CVEByCpe -Vendor $p.Vendor -Product $p.Product -Version $p.Version
            } else {
                $p.CVE = 'Sin CPE (no se pudo resolver vendor/product)'
            }
        }
    }

    return $Pendientes
}
# =================================================================
# 9. MODULO 3 - SOFTWARE DESACTUALIZADO / CVE
# =================================================================
function Test-SoftwareDesactualizado {
    Write-Banner "MODULO 3: SOFTWARE, VULNERABILIDADES Y CVE (NIST NVD)"

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "[!] Winget no esta instalado." -ForegroundColor Red
        Add-Resultado '3. Software/CVE' 'ERROR' 'Winget no disponible' '-'
        return
    }

    Write-Host "[+] Consultando repositorio de actualizaciones (winget)..." -ForegroundColor Yellow
    $Pendientes = Get-SoftwarePendienteWinget -ConsultarCVE

    if ($Pendientes.Count -eq 0) {
        Write-Host "[-] Todo el software esta actualizado.`n" -ForegroundColor Green
        Add-Resultado '3. Software/CVE' 'LIMPIO' 'Todo actualizado' '-'
        return
    }

    Write-Host "[!] $($Pendientes.Count) aplicaciones con parches pendientes.`n" -ForegroundColor Red

    # Tabla principal
    $Pendientes |
        Select-Object Software, Version, Available, Vendor, Product, CVE |
        Format-Table -AutoSize

    foreach ($d in $Pendientes) {
        $Global:ReporteSoftwareCVE.Add([PSCustomObject]@{
            Software  = $d.Software
            Version   = $d.Version
            Available = $d.Available
            Vendor    = $d.Vendor
            Product   = $d.Product
            CVE       = $d.CVE
            Fecha     = (Get-Date -Format 'yyyy-MM-dd HH:mm')
        })
        Add-Resultado '3. Software/CVE' 'ALTA' "Parche pendiente ($($d.CVE))" "$($d.Software) v$($d.Version) -> $($d.Available)"
    }
}
# =================================================================
# 9. MODULO 4 - EXTENSIONES DE NAVEGADOR
# =================================================================
function Test-ExtensionesNavegador {
    Write-Banner "MODULO 4: EXTENSIONES DE NAVEGADOR SOSPECHOSAS O CORRUPTAS"

    $PesoPermisos = @{
        'nativeMessaging'    = 2
        'debugger'           = 2
        'proxy'              = 2
        'management'         = 1
        'webRequestBlocking' = 1
        'webRequest'         = 1
        'privacy'            = 1
        'declarativeNetRequestWithHostAccess' = 2
    }
    $PatronesHostWildcard = @('<all_urls>','http://*/*','https://*/*')
    $UmbralAlta  = 3
    $UmbralMedia = 1

    $Navegadores = @(
        @{ Nombre='Chrome'; Ruta="$env:LOCALAPPDATA\Google\Chrome\User Data" }
        @{ Nombre='Edge';   Ruta="$env:LOCALAPPDATA\Microsoft\Edge\User Data" }
        @{ Nombre='Brave';  Ruta="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
    )

    $Hallazgos = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($nav in $Navegadores) {
        if (-not (Test-Path $nav.Ruta)) { continue }
        Write-Host "[+] Escaneando extensiones de $($nav.Nombre)..." -ForegroundColor Yellow

        $Perfiles = Get-ChildItem -Path $nav.Ruta -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^(Default|Profile \d+)$' }
        foreach ($perfil in $Perfiles) {
            $ExtDir = Join-Path $perfil.FullName "Extensions"
            if (-not (Test-Path $ExtDir)) { continue }

            $Extensiones = Get-ChildItem -Path $ExtDir -Directory -ErrorAction SilentlyContinue
            foreach ($ext in $Extensiones) {
                $VersionDir = Get-ChildItem -Path $ext.FullName -Directory -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending | Select-Object -First 1
                if (-not $VersionDir) {
                    $Hallazgos.Add([PSCustomObject]@{
                        Navegador=$nav.Nombre; Perfil=$perfil.Name; ExtensionId=$ext.Name
                        Nombre='(desconocido)'; Problema='CORRUPTA: carpeta vacia'; Severidad='MEDIA'
                    }); continue
                }
                $ManifestPath = Join-Path $VersionDir.FullName "manifest.json"
                if (-not (Test-Path $ManifestPath)) {
                    $Hallazgos.Add([PSCustomObject]@{
                        Navegador=$nav.Nombre; Perfil=$perfil.Name; ExtensionId=$ext.Name
                        Nombre='(desconocido)'; Problema='CORRUPTA: falta manifest.json'; Severidad='MEDIA'
                    }); continue
                }
                try {
                    $Manifest = Get-Content $ManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    $Hallazgos.Add([PSCustomObject]@{
                        Navegador=$nav.Nombre; Perfil=$perfil.Name; ExtensionId=$ext.Name
                        Nombre='(desconocido)'; Problema='CORRUPTA: manifest invalido'; Severidad='ALTA'
                    }); continue
                }

                $NombreExt = $Manifest.name
                if ($NombreExt -match '^__MSG_') { $NombreExt = "$NombreExt (id: $($ext.Name))" }

                $Permisos = @()
                if ($Manifest.permissions)          { $Permisos += $Manifest.permissions }
                if ($Manifest.host_permissions)     { $Permisos += $Manifest.host_permissions }
                if ($Manifest.optional_permissions) { $Permisos += $Manifest.optional_permissions }

                $Score = 0
                $Etiquetas = [System.Collections.Generic.List[string]]::new()
                foreach ($k in $PesoPermisos.Keys) {
                    if ($Permisos -like "*$k*") { $Score += $PesoPermisos[$k]; $Etiquetas.Add($k) }
                }
                $tieneHostWildcard = $PatronesHostWildcard | Where-Object { $p=$_; $Permisos -like "*$p*" }
                if ($tieneHostWildcard) { $Score += 1; $Etiquetas.Add('host_wildcard') }

                if ($Score -ge $UmbralAlta) {
                    $Hallazgos.Add([PSCustomObject]@{
                        Navegador=$nav.Nombre; Perfil=$perfil.Name; ExtensionId=$ext.Name; Nombre=$NombreExt
                        Problema="Riesgo ALTO (score=$Score): $($Etiquetas -join '+')"; Severidad='ALTA'
                    })
                } elseif ($Score -ge $UmbralMedia) {
                    $Hallazgos.Add([PSCustomObject]@{
                        Navegador=$nav.Nombre; Perfil=$perfil.Name; ExtensionId=$ext.Name; Nombre=$NombreExt
                        Problema="Permiso aislado (score=$Score): $($Etiquetas -join '+')"; Severidad='MEDIA'
                    })
                }
            }
        }

        $RutasPolicy = @(
            "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
            "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist"
        )
        foreach ($rp in $RutasPolicy) {
            if (Test-Path $rp) {
                $Forzadas = Get-Item $rp -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
                foreach ($f in $Forzadas) {
                    $valor = (Get-ItemProperty -Path $rp -Name $f).$f
                    $Hallazgos.Add([PSCustomObject]@{
                        Navegador=($rp -split '\\')[3]; Perfil='(politica)'; ExtensionId=$f
                        Nombre='(forzada via GPO)'; Problema="Forcelist: $valor"; Severidad='REVISAR'
                    })
                }
            }
        }
    }

    if ($Hallazgos.Count -gt 0) {
        $Agrupados = $Hallazgos | Group-Object Navegador, ExtensionId, Problema | ForEach-Object {
            $primero = $_.Group[0]
            $perfiles = ($_.Group.Perfil | Select-Object -Unique) -join '/'
            [PSCustomObject]@{
                Navegador = $primero.Navegador
                Extension = Limitar-Texto $primero.Nombre 40
                Id        = $primero.ExtensionId
                Perfiles  = Limitar-Texto $perfiles 20
                Problema  = Limitar-Texto $primero.Problema 55
                Severidad = $primero.Severidad
            }
        } | Sort-Object { Get-RangoSeveridad $_.Severidad }

        $Agrupados | Format-Table Navegador, Extension, Id, Perfiles, Problema, Severidad -AutoSize

        foreach ($h in $Hallazgos) {
            Add-Resultado '4. Extensiones Navegador' $h.Severidad $h.Problema "$($h.Navegador) | $($h.Nombre) | $($h.ExtensionId)"
            $Global:ReporteExtensiones.Add([PSCustomObject]@{
                Navegador=$h.Navegador; Perfil=$h.Perfil; ExtensionId=$h.ExtensionId
                Nombre=$h.Nombre; Problema=$h.Problema; Severidad=$h.Severidad
                FechaAuditoria=(Get-Date -Format 'yyyy-MM-dd HH:mm')
            })
        }
    } else {
        Write-Host "[-] Sin extensiones corruptas ni de alto riesgo." -ForegroundColor Green
        Add-Resultado '4. Extensiones Navegador' 'LIMPIO' 'Sin hallazgos' '-'
    }
}

# =================================================================
# 10. MODULO 6 - DEFENDER
# =================================================================
function Test-DefenderPostura {
    Write-Banner "MODULO 6: POSTURA DE WINDOWS DEFENDER"

    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Host "[!] Windows Defender no disponible en este equipo." -ForegroundColor Red
        Add-Resultado '6. Defender' 'ERROR' 'Defender no disponible' '-'
        return
    }

    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    $status = Get-MpComputerStatus -ErrorAction SilentlyContinue

    if (-not $status) {
        Write-Host "[!] No se pudo obtener el estado de Defender." -ForegroundColor Red
        Add-Resultado '6. Defender' 'ERROR' 'Sin estado de Defender' '-'
        return
    }

    $asrCount = 0
    if ($mp.AttackSurfaceReductionRules_Actions) {
        $asrCount = ($mp.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 'Enabled' }).Count
    }

    $Checks = @(
        @{ Nombre='Antivirus tiempo real';          Valor=$status.RealTimeProtectionEnabled; Ok=$status.RealTimeProtectionEnabled }
        @{ Nombre='Proteccion contra manipulacion'; Valor=$status.IsTamperProtected;         Ok=$status.IsTamperProtected }
        @{ Nombre='Antivirus actualizado';          Valor="Firma edad: $($status.AntivirusSignatureAge) dias"; Ok=($status.AntivirusSignatureAge -le 3) }
        @{ Nombre='Nube (MAPS)';                    Valor=$mp.MAPSReporting;                 Ok=($mp.MAPSReporting -eq 2) }
        @{ Nombre='ASR rules activas';              Valor=$asrCount;                         Ok=($asrCount -gt 0) }
        @{ Nombre='PUA Protection';                 Valor=$mp.PUAProtection;                 Ok=($mp.PUAProtection -ge 1) }
        @{ Nombre='Behavior Monitoring';            Valor=$status.BehaviorMonitorEnabled;    Ok=$status.BehaviorMonitorEnabled }
    )

    foreach ($c in $Checks) {
        $color = if ($c.Ok) { 'Green' } else { 'Red' }
        Write-Host ("  {0,-38} {1}" -f $c.Nombre, $c.Valor) -ForegroundColor $color
        if (-not $c.Ok) {
            Add-Resultado '6. Defender' 'ALTA' "Defender: $($c.Nombre) no configurado" "Valor: $($c.Valor)"
        }
    }

    $exclusionSospechosa = $false
    if ($mp.ExclusionPath -and $mp.ExclusionPath.Count -gt 0) {
        Write-Host "`n[+] Exclusiones de ruta configuradas: $($mp.ExclusionPath.Count)" -ForegroundColor Yellow
        foreach ($ex in $mp.ExclusionPath) {
            $sosp = $ex -match '(?i)(\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\)'
            $color = if ($sosp) { 'Red' } else { 'Gray' }
            Write-Host "    - $ex" -ForegroundColor $color
            if ($sosp) {
                $exclusionSospechosa = $true
                Add-Resultado '6. Defender' 'CRITICAL' 'Exclusion sospechosa en Defender' $ex
            }
        }
    }

    if ($mp.ExclusionProcess -and $mp.ExclusionProcess.Count -gt 0) {
        Write-Host "`n[+] Exclusiones de proceso: $($mp.ExclusionProcess.Count)" -ForegroundColor Yellow
        foreach ($ex in $mp.ExclusionProcess) {
            Write-Host "    - $ex" -ForegroundColor Gray
            Add-Resultado '6. Defender' 'MEDIA' 'Exclusion de proceso en Defender' $ex
        }
    }

    if (($Checks | Where-Object { -not $_.Ok }).Count -eq 0 -and -not $exclusionSospechosa) {
        Add-Resultado '6. Defender' 'LIMPIO' 'Postura correcta' '-'
    }
}

# =================================================================
# 11. MODULO 5 - PARCHEO (con modos: Criticos / Todo)
# =================================================================
function New-PuntoRestauracionCYBERAD ($Descripcion) {
    Write-Host "[+] Creando punto de restauracion..." -ForegroundColor Yellow
    try {
        Checkpoint-Computer -Description $Descripcion -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Host " -> Punto de restauracion creado.`n" -ForegroundColor Green
        return $true
    } catch {
        Write-Host " -> [!] No se pudo crear (proteccion deshabilitada o limite 24h)." -ForegroundColor DarkYellow
        if (-not $Global:OptAutoConfirmar) {
            $seguir = Read-Host "Continuar sin punto de restauracion fresco (S/N)"
            return ($seguir -match '^[Ss]')
        }
        return $true
    }
}

function Test-TieneCveReal {
    param([string]$Cve)
    if (-not $Cve) { return $false }
    if ($Cve -eq 'N/A') { return $false }
    if ($Cve -like 'Sin CVE aplicable*') { return $false }
    if ($Cve -like 'Sin CPE*') { return $false }
    if ($Cve -like 'Sin CVE publico directo*') { return $false }
    if ($Cve -like 'Consulta NVD fallida*') { return $false }
    if ($Cve -like 'Solo CVEs de bajo impacto*') { return $false }
    if ($Cve -notmatch 'CVE-\d{4}-\d+') { return $false }
    return $true
}

function Invoke-Parcheo {
    param(
        [ValidateSet('Criticos','Todo')]
        [string]$Modo = 'Criticos'
    )

    $titulo = switch ($Modo) {
        'Criticos' { "MODULO 5: PARCHEO - SOLO CRITICOS (con CVE real)" }
        'Todo'     { "MODULO 5: PARCHEO - TODO EL SOFTWARE ACTUALIZABLE" }
    }
    Write-Banner $titulo
    Write-Host "[!] Este modulo APLICA CAMBIOS al sistema.`n" -ForegroundColor Red

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "[!] Winget no esta instalado." -ForegroundColor Red
        return
    }

    # Punto de restauracion
    $restoreOk = New-PuntoRestauracionCYBERAD "Antes_De_Winget_Upgrade_CYBERAD"
    if (-not $restoreOk) {
        Write-Host "Cancelado por el usuario (no se creó punto de restauración).`n" -ForegroundColor DarkYellow
        return
    }

    Write-Host "[+] Auditando software antes de parchear..." -ForegroundColor Yellow
    $ReporteAntes = Get-SoftwarePendienteWinget -ConsultarCVE

    if ($ReporteAntes.Count -eq 0) {
        Write-Host " -> No hay actualizaciones pendientes.`n" -ForegroundColor Green
        Add-Resultado '5. Parcheo' 'LIMPIO' 'Nada pendiente' '-'
        return
    }

    # Filtrar segun el modo
    if ($Modo -eq 'Criticos') {
        $ParaParchear = @($ReporteAntes | Where-Object { Test-TieneCveReal $_.CVE })
    } else {
        $ParaParchear = @($ReporteAntes)
    }

    if ($ParaParchear.Count -eq 0) {
        Write-Host "[-] No hay aplicaciones con CVE real para parchear en modo Criticos.`n" -ForegroundColor Green
        Write-Host "    Apps con actualizacion disponible (pero sin CVE catalogado):" -ForegroundColor DarkGray
        foreach ($r in $ReporteAntes) {
            Write-Host "      - $($r.Software) v$($r.Version) -> $($r.Available)" -ForegroundColor DarkGray
        }
        Write-Host ""
        Add-Resultado '5. Parcheo' 'LIMPIO' 'Sin apps con CVE real' "-"
        return
    }

    Write-Host "[+] Aplicaciones que se van a parchear ($($ParaParchear.Count)):`n" -ForegroundColor Cyan
    $ParaParchear | Format-Table Software, Version, Available, CVE -AutoSize

    # Si en modo Criticos hay otras apps pendientes, se avisa
    if ($Modo -eq 'Criticos') {
        $NoCriticas = @($ReporteAntes | Where-Object { -not (Test-TieneCveReal $_.CVE) })
        if ($NoCriticas.Count -gt 0) {
            Write-Host "[i] $($NoCriticas.Count) app(s) quedaran sin parchear (no tienen CVE real):" -ForegroundColor DarkGray
            foreach ($r in $NoCriticas) {
                Write-Host "      - $($r.Software) v$($r.Version) -> $($r.Available)" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
    }

    # Confirmacion
    if (-not $Global:OptAutoConfirmar) {
        Write-Host "[!] Se actualizara el software listado arriba." -ForegroundColor Yellow
        $confirmar = Read-Host "Proceder (S/N)"
        if ($confirmar -notmatch '^[Ss]') {
            Write-Host "Cancelado por el usuario.`n" -ForegroundColor DarkYellow
            foreach ($r in $ParaParchear) {
                Add-Resultado '5. Parcheo' 'PENDIENTE' "No parcheado (cancelado): $($r.CVE)" "$($r.Software) v$($r.Version)"
            }
            return
        }
    }

    Write-Host "`n[+] Aplicando actualizaciones..." -ForegroundColor Yellow
    $RutaLog = Join-Path $Global:RutaBase "CYBER-AD_Log_Winget_$($Global:Timestamp).txt"

    foreach ($pkg in $ParaParchear.Software) {
        Write-Host "    -> Actualizando: $pkg" -ForegroundColor Cyan
        winget upgrade --name "$pkg" --include-unknown --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 |
            Tee-Object -FilePath $RutaLog -Append | Out-Null
    }

    Write-Host "`n[+] Re-evaluando tras el parcheo..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    $ReporteDespues = Get-SoftwarePendienteWinget -ConsultarCVE

    $nombresParcheados = $ParaParchear.Software
    $parcheadoOk = $nombresParcheados | Where-Object { $_ -notin $ReporteDespues.Software }
    $siguenPendientes = $nombresParcheados | Where-Object { $_ -in $ReporteDespues.Software }

    Write-Host "`n[+] Parcheado OK: $($parcheadoOk.Count) | Sigue pendiente: $($siguenPendientes.Count)" -ForegroundColor Cyan

    foreach ($p in $parcheadoOk) {
        Add-Resultado '5. Parcheo' 'RESUELTO' 'Parcheado con exito' $p
    }
    foreach ($p in $siguenPendientes) {
        $info = $ParaParchear | Where-Object { $_.Software -eq $p } | Select-Object -First 1
        Add-Resultado '5. Parcheo' 'ALTA' "Sigue pendiente ($($info.CVE))" "$($info.Software) v$($info.Version)"
    }
}

# =================================================================
# 12. RESUMEN EJECUTIVO
# =================================================================
function Show-ResumenEjecutivo {
    Write-Banner "RESUMEN EJECUTIVO CONSOLIDADO - CYBER-AD Sentinel-Lite v3"

    if ($Global:ResultadosGlobales.Count -eq 0) {
        Write-Host "  (Sin resultados registrados)" -ForegroundColor Gray
        return
    }

    $AnchoModulo=24; $AnchoSev=10; $AnchoHallazgo=55; $AnchoDetalle=45

    $Agrupados = $Global:ResultadosGlobales | Group-Object Modulo, Severidad, Hallazgo | ForEach-Object {
        $p = $_.Group[0]
        [PSCustomObject]@{
            Modulo=$p.Modulo; Severidad=$p.Severidad; Hallazgo=$p.Hallazgo
            Detalle = if ($_.Count -gt 1) { "$($p.Detalle) (+$($_.Count - 1) mas)" } else { $p.Detalle }
            Rango=Get-RangoSeveridad $p.Severidad
        }
    } | Sort-Object Rango, Modulo

    $linea = ("Modulo".PadRight($AnchoModulo)) + ("Severidad".PadRight($AnchoSev)) + ("Hallazgo".PadRight($AnchoHallazgo)) + "Detalle"
    Write-Host $linea -ForegroundColor Cyan
    Write-Host ("-" * ($AnchoModulo + $AnchoSev + $AnchoHallazgo + 20)) -ForegroundColor Cyan

    foreach ($r in $Agrupados) {
        $color = Get-ColorSeveridad $r.Severidad
        $fila = (Limitar-Texto $r.Modulo $($AnchoModulo - 1)).PadRight($AnchoModulo) +
                (Limitar-Texto $r.Severidad $($AnchoSev - 1)).PadRight($AnchoSev) +
                (Limitar-Texto $r.Hallazgo $($AnchoHallazgo - 1)).PadRight($AnchoHallazgo) +
                (Limitar-Texto $r.Detalle $AnchoDetalle)
        Write-Host $fila -ForegroundColor $color
    }

    $Criticos = ($Global:ResultadosGlobales | Where-Object { $_.Severidad -match 'CRITICAL' }).Count
    $Altos    = ($Global:ResultadosGlobales | Where-Object { $_.Severidad -match 'HIGH|ALTA' }).Count
    $Medios   = ($Global:ResultadosGlobales | Where-Object { $_.Severidad -match 'MEDIA|REVISAR' }).Count

    Write-Host "`n$('-' * 65)" -ForegroundColor Cyan
    Write-Host "  CRITICAL: $Criticos    ALTA: $Altos    MEDIA/REVISAR: $Medios" -ForegroundColor Cyan
    Write-Host "$('-' * 65)`n" -ForegroundColor Cyan

    if ($Criticos -gt 0) {
        Write-Host "[!] $Criticos hallazgo(s) CRITICO(S). Revisar de inmediato." -ForegroundColor Red
    } elseif ($Altos -gt 0) {
        Write-Host "[!] $Altos hallazgo(s) de severidad ALTA. Revisar pronto." -ForegroundColor Yellow
    } else {
        Write-Host "[+] Sin hallazgos criticos ni altos." -ForegroundColor Green
    }
}

# =================================================================
# 13. EXPORTACION
# =================================================================
function Export-HtmlReporte ($Path) {
    $filas = $Global:ResultadosGlobales | Group-Object Modulo, Severidad, Hallazgo | ForEach-Object {
        $p = $_.Group[0]
        $sev = $p.Severidad
        $color = switch -Regex ($sev) {
            'CRITICAL'        { '#c0392b' }
            'HIGH|ALTA'       { '#e67e22' }
            'MEDIA|REVISAR'   { '#f39c12' }
            'RESUELTO|LIMPIO' { '#27ae60' }
            'ERROR'           { '#c0392b' }
            default           { '#7f8c8d' }
        }
        $detalle = if ($_.Count -gt 1) { "$($p.Detalle) (+$($_.Count-1) mas)" } else { $p.Detalle }
        "<tr><td>$($p.Modulo)</td><td style='color:$color;font-weight:bold'>$sev</td><td>$($p.Hallazgo)</td><td>$detalle</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'>
<title>CYBER-AD Sentinel-Lite v3 - Reporte</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#1e1e1e;color:#e0e0e0;padding:24px}
h1{color:#00b894}
table{border-collapse:collapse;width:100%;margin-top:20px}
th,td{border:1px solid #444;padding:8px;text-align:left;vertical-align:top}
th{background:#2c3e50;color:#ecf0f1}
tr:nth-child(even){background:#252525}
.footer{margin-top:24px;color:#7f8c8d;font-size:12px}
</style></head><body>
<h1>CYBER-AD Sentinel-Lite v3 - Reporte de Auditoria</h1>
<p>Generado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &mdash; Equipo: $env:COMPUTERNAME &mdash; Usuario: $env:USERNAME</p>
<table>
<thead><tr><th>Modulo</th><th>Severidad</th><th>Hallazgo</th><th>Detalle</th></tr></thead>
<tbody>
$($filas -join "`n")
</tbody></table>
<p class='footer'>CYBER-AD Sentinel-Lite v3 &mdash; Auditoria local de seguridad</p>
</body></html>
"@
    $html | Set-Content -Path $Path -Encoding UTF8
}

function Export-ReportesCYBERAD {
    $RutasGeneradas = [System.Collections.Generic.List[string]]::new()

    if ($Global:ResultadosGlobales.Count -gt 0) {
        $Ruta = Join-Path $Global:RutaBase "CYBER-AD_Resumen_$($Global:Timestamp).csv"
        $Global:ResultadosGlobales | Export-Csv -Path $Ruta -NoTypeInformation -Encoding UTF8
        $RutasGeneradas.Add($Ruta)
    }
    if ($Global:ReporteSoftwareCVE.Count -gt 0) {
        $Ruta = Join-Path $Global:RutaBase "CYBER-AD_Software_CVE_$($Global:Timestamp).csv"
        $Global:ReporteSoftwareCVE | Export-Csv -Path $Ruta -NoTypeInformation -Encoding UTF8
        $RutasGeneradas.Add($Ruta)
    }
    if ($Global:ReporteExtensiones.Count -gt 0) {
        $Ruta = Join-Path $Global:RutaBase "CYBER-AD_Extensiones_$($Global:Timestamp).csv"
        $Global:ReporteExtensiones | Export-Csv -Path $Ruta -NoTypeInformation -Encoding UTF8
        $RutasGeneradas.Add($Ruta)
    }

    if ($Global:OptExportarHtml -and $Global:ResultadosGlobales.Count -gt 0) {
        $RutaHtml = Join-Path $Global:RutaBase "CYBER-AD_Reporte_$($Global:Timestamp).html"
        Export-HtmlReporte -Path $RutaHtml
        $RutasGeneradas.Add($RutaHtml)
    }

    if ($RutasGeneradas.Count -gt 0) {
        Write-Host "`n[+] Reportes generados:" -ForegroundColor Cyan
        $RutasGeneradas | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
        Write-Host ""
    }
}

# =================================================================
# 14. MENU INTERACTIVO
# =================================================================
function Pause {
    Write-Host ""
    Read-Host "  Pulsa [Enter] para continuar" | Out-Null
}

function Post-Ejecucion {
    if ($Global:ResultadosGlobales.Count -gt 0) {
        Show-ResumenEjecutivo
        Export-ReportesCYBERAD
    } else {
        Write-Host "`n[+] Modulo finalizado sin resultados que exportar." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor DarkGreen
    Write-Host "  [Enter] Volver al menu     [S] Salir" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor DarkGreen
    $r = Read-Host "  Opcion"
    if ($r -and $r.Trim().ToUpper() -eq 'S') {
        Write-Host "`n[+] Saliendo...`n" -ForegroundColor Green
        exit
    }
}

function Show-OpcionesActuales {
    Write-Host ""
    Write-Host "  --- OPCIONES ACTUALES ---" -ForegroundColor Cyan
    Write-Host "   Reporte HTML:      $($Global:OptExportarHtml)" -ForegroundColor Gray
    Write-Host "   AutoConfirmar:     $($Global:OptAutoConfirmar)" -ForegroundColor Gray
    Write-Host "   NVD API key:       $(if($Global:OptNvdApiKey){'configurada'}else{'vacia'})" -ForegroundColor Gray
    Write-Host "   Dias ventana:      $($Global:OptDiasVentana)" -ForegroundColor Gray
    Write-Host ""
}

function Show-Ayuda {
    Write-Host ""
    Write-Host "  --- AYUDA ---" -ForegroundColor Cyan
    Write-Host "   Los modulos 0-6 son de SOLO LECTURA." -ForegroundColor Gray
    Write-Host "   El modulo [P] (Parcheo) MODIFICA el sistema:" -ForegroundColor Yellow
    Write-Host "     - Crea un punto de restauracion" -ForegroundColor Gray
    Write-Host "     - Ejecuta winget upgrade" -ForegroundColor Gray
    Write-Host "     - Compara antes/despues" -ForegroundColor Gray
    Write-Host ""
    Write-Host "   AutoConfirmar: evita preguntas interactivas (usar con cuidado)." -ForegroundColor Gray
    Write-Host "   NVD API key:   acelera las consultas de CVE (50 req/30s vs 5)." -ForegroundColor Gray
    Write-Host "   Dias ventana:  cuantos dias atras buscar en los logs (default 30)." -ForegroundColor Gray
    Write-Host ""
    Write-Host "   Modo de parcheo:" -ForegroundColor Gray
    Write-Host "     [P1] o submenu [1]: Solo apps con CVE real (recomendado)" -ForegroundColor Gray
    Write-Host "     [P2] o submenu [2]: Todas las apps actualizables" -ForegroundColor Gray
    Write-Host ""
}

function Show-MenuOpciones {
    while ($true) {
        Clear-Host
        Write-Host "================================================================" -ForegroundColor DarkGreen
        Write-Host "  OPCIONES DE CONFIGURACION" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor DarkGreen
        Write-Host ""
        Write-Host "   [1] Reporte HTML al finalizar:     $(if($Global:OptExportarHtml){'ACTIVADO'}else{'desactivado'})" -ForegroundColor $(if($Global:OptExportarHtml){'Green'}else{'Gray'})
        Write-Host "   [2] AutoConfirmar (sin preguntas): $(if($Global:OptAutoConfirmar){'ACTIVADO'}else{'desactivado'})" -ForegroundColor $(if($Global:OptAutoConfirmar){'Green'}else{'Gray'})
        Write-Host "   [3] NVD API key:                   $(if($Global:OptNvdApiKey){'configurada'}else{'(vacia - rate limit 5/30s)'})" -ForegroundColor $(if($Global:OptNvdApiKey){'Green'}else{'Yellow'})
        Write-Host "   [4] Dias de ventana de eventos:    $($Global:OptDiasVentana)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   [L] Limpiar cache NVD" -ForegroundColor Magenta
        Write-Host "   [V] Volver al menu principal" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor DarkGreen

        $op = Read-Host "  Elige una opcion"
        $op = if ($op) { $op.Trim().ToUpper() } else { "" }

        switch ($op) {
            '1' {
                $Global:OptExportarHtml = -not $Global:OptExportarHtml
                Write-Host " -> Reporte HTML: $(if($Global:OptExportarHtml){'ACTIVADO'}else{'desactivado'})" -ForegroundColor Green
                Start-Sleep -Seconds 1
            }
            '2' {
                $Global:OptAutoConfirmar = -not $Global:OptAutoConfirmar
                Write-Host " -> AutoConfirmar: $(if($Global:OptAutoConfirmar){'ACTIVADO'}else{'desactivado'})" -ForegroundColor Green
                Start-Sleep -Seconds 1
            }
            '3' {
                Write-Host ""
                $key = Read-Host "  Introduce tu NVD API key (Enter para dejar vacia)"
                $Global:OptNvdApiKey = if ($key) { $key.Trim() } else { $null }
                Write-Host " -> API key: $(if($Global:OptNvdApiKey){'configurada'}else{'vacia'})" -ForegroundColor Green
                Start-Sleep -Seconds 1
            }
            '4' {
                Write-Host ""
                $n = Read-Host "  Dias de ventana (actual: $($Global:OptDiasVentana))"
                if ($n -match '^\d+$' -and [int]$n -gt 0) {
                    $Global:OptDiasVentana = [int]$n
                    Write-Host " -> Dias: $($Global:OptDiasVentana)" -ForegroundColor Green
                } else {
                    Write-Host " -> Valor invalido, no se cambio." -ForegroundColor Red
                }
                Start-Sleep -Seconds 1
            }
            'L' {
                if (Test-Path $Global:NvdCachePath) {
                    Remove-Item $Global:NvdCachePath -Force -ErrorAction SilentlyContinue
                    $Global:NvdCache = @{}
                    Write-Host " -> Cache NVD eliminada." -ForegroundColor Green
                } else {
                    Write-Host " -> No habia cache NVD." -ForegroundColor Gray
                }
                Start-Sleep -Seconds 1
            }
            'V' { return }
            ''  { }
            default { }
        }
    }
}
function Show-SubMenuParcheo {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor DarkRed
    Write-Host "  PARCHEO CON WINGET - Elige el modo" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor DarkRed
    Write-Host ""
    Write-Host "  [1]  Parchear SOLO CRITICOS" -ForegroundColor Red
    Write-Host "       Solo apps con CVE real detectado en el modulo 3" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2]  Parchear TODO" -ForegroundColor Red
    Write-Host "       Todas las apps que winget reporte como actualizables" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [0]  Cancelar" -ForegroundColor Gray
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor DarkRed

    $op = Read-Host "  Elige una opcion"
    $op = if ($op) { $op.Trim().ToUpper() } else { "" }

    switch ($op) {
        '1' { Reset-Resultados; Invoke-Parcheo -Modo 'Criticos'; Post-Ejecucion }
        '2' { Reset-Resultados; Invoke-Parcheo -Modo 'Todo';     Post-Ejecucion }
        '0' { }
        default { }
    }
}

function Show-MenuPrincipal {
    while ($true) {
        Clear-Host
        Write-Host "================================================================" -ForegroundColor DarkGreen
        Write-Host "   ____ _   _ ____  _____ ____      _    ____               " -ForegroundColor Green
        Write-Host "  / ___| | | | __ )| ____|  _ \    / \  |  _ \              " -ForegroundColor Green
        Write-Host " | |   | | | |  _ \|  _| | |_) |  / _ \ | | | |             " -ForegroundColor Green
        Write-Host " | |___| |_| | |_) | |___|  _ <  / ___ \| |_| |             " -ForegroundColor Green
        Write-Host "  \____|\__, |____/|_____|_| \_\/_/   \_\____/              " -ForegroundColor Green
        Write-Host "        |___/                                               " -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor DarkGreen
        Write-Host " [+] CYBER-AD Sentinel-Lite v3 - MENU PRINCIPAL" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor DarkGreen
        Write-Host ""

        Write-Host "  MODULOS INDIVIDUALES (solo lectura):" -ForegroundColor Yellow
        Write-Host "   [0]  Telemetria disponible (Sysmon / Audit 4688)" -ForegroundColor Gray
        Write-Host "   [1]  Credential Dumping / Procesos vitales" -ForegroundColor Gray
        Write-Host "   [2]  Persistencia (PowerShell 4104 / AppX / Temp)" -ForegroundColor Gray
        Write-Host "   [3]  Persistencia avanzada (Run / Tasks / Services / WMI)" -ForegroundColor Gray
        Write-Host "   [4]  Software desactualizado y CVE (NIST NVD)" -ForegroundColor Gray
        Write-Host "   [5]  Extensiones de navegador" -ForegroundColor Gray
        Write-Host "   [6]  Postura de Windows Defender" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  MODULOS AVANZADOS:" -ForegroundColor Yellow
        Write-Host "   [7]  Relaciones padre-hijo anomalas (Sysmon E1)" -ForegroundColor Gray
        Write-Host "   [8]  Conexiones de red / DNS sospechosos (Sysmon E3/E22)" -ForegroundColor Gray
        Write-Host "   [9]  Drivers vulnerables (LOLDrivers / BYOVD)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  GRUPOS PREDEFINIDOS:" -ForegroundColor Yellow
        Write-Host "   [A]  Auditoria COMPLETA (todos los modulos 0-9) - solo lectura" -ForegroundColor Cyan
        Write-Host "   [B]  Auditoria RAPIDA (0,1,6)" -ForegroundColor Cyan
        Write-Host "   [C]  Solo Extensiones + Defender (5,6)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  ACCIONES QUE MODIFICAN EL SISTEMA:" -ForegroundColor Red
        Write-Host "   [P1] Parchear SOLO CRITICOS (apps con CVE real)" -ForegroundColor Red
        Write-Host "   [P2] Parchear TODO (todas las apps actualizables)" -ForegroundColor Red
        Write-Host ""
        Write-Host "  OPCIONES:" -ForegroundColor Yellow
        Write-Host "   [O]  Configurar opciones (HTML, AutoConfirmar, API key, Dias)" -ForegroundColor Magenta
        Write-Host "   [V]  Ver opciones actuales" -ForegroundColor Magenta
        Write-Host "   [H]  Ayuda" -ForegroundColor Magenta
        Write-Host "   [S]  Salir" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor DarkGreen

        $opcion = Read-Host "  Elige una opcion"
        $opcion = if ($opcion) { $opcion.Trim().ToUpper() } else { "" }

        switch ($opcion) {
            '0' { Reset-Resultados; Test-TelemetriaDisponible;         Post-Ejecucion }
            '1' { Reset-Resultados; Test-CredentialDumping;             Post-Ejecucion }
            '2' { Reset-Resultados; Test-Persistencia;                  Post-Ejecucion }
            '3' { Reset-Resultados; Test-PersistenciaAvanzada;          Post-Ejecucion }
            '4' { Reset-Resultados; Test-SoftwareDesactualizado;        Post-Ejecucion }
            '5' { Reset-Resultados; Test-ExtensionesNavegador;          Post-Ejecucion }
            '6' { Reset-Resultados; Test-DefenderPostura;               Post-Ejecucion }
            '7' { Reset-Resultados; Test-ProcesosPadreHijo;             Post-Ejecucion }
            '8' { Reset-Resultados; Test-RedDns;                        Post-Ejecucion }
            '9' { Reset-Resultados; Test-LolDrivers;                    Post-Ejecucion }

            'A' {
                  Reset-Resultados
                  Test-TelemetriaDisponible
                  Test-CredentialDumping
                  Test-ProcesosPadreHijo       # nuevo
                  Test-RedDns                  # nuevo
                  Test-Persistencia
                  Test-PersistenciaAvanzada
                  Test-LolDrivers              # nuevo
                  Test-SoftwareDesactualizado
                  Test-ExtensionesNavegador
                  Test-DefenderPostura
                  Post-Ejecucion
            }
            'B' {
                Reset-Resultados
                Test-TelemetriaDisponible
                Test-CredentialDumping
                Test-DefenderPostura
                Post-Ejecucion
            }
            'C' {
                Reset-Resultados
                Test-ExtensionesNavegador
                Test-DefenderPostura
                Post-Ejecucion
            }

            'P'  { Show-SubMenuParcheo }
            'P1' { Reset-Resultados; Invoke-Parcheo -Modo 'Criticos'; Post-Ejecucion }
            'P2' { Reset-Resultados; Invoke-Parcheo -Modo 'Todo';     Post-Ejecucion }

            'O' { Show-MenuOpciones }
            'V' { Show-OpcionesActuales; Pause }
            'H' { Show-Ayuda; Pause }
            'S' { return }
            'Q' { return }
            ''  { }
            default {
                Write-Host "`n[!] Opcion no valida: '$opcion'" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

# =================================================================
# 15. BLOQUE DE ARRANQUE (unico, al final)
# =================================================================
Show-BannerInicio

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] ERROR: Este script requiere ejecutarse como ADMINISTRADOR." -ForegroundColor Red
    return
}

Set-ConsolaAncha
Load-NvdCache

# Detectar modo CLI: solo si el usuario paso -Modulos explicitamente con algo distinto de 'Todos'
$invocadoDesdeCli = $PSBoundParameters.ContainsKey('Modulos')

if ($invocadoDesdeCli) {
    $EjecutarTodos = $Modulos -contains 'Todos'
    if ($EjecutarTodos -or $Modulos -contains 'Telemetria')            { Test-TelemetriaDisponible }
    if ($EjecutarTodos -or $Modulos -contains 'Credenciales')          { Test-CredentialDumping }
    if ($EjecutarTodos)                                                { Test-ProcesosPadreHijo }
    if ($EjecutarTodos)                                                { Test-RedDns }
    if ($EjecutarTodos -or $Modulos -contains 'Persistencia')          { Test-Persistencia }
    if ($EjecutarTodos -or $Modulos -contains 'PersistenciaAvanzada')  { Test-PersistenciaAvanzada }
    if ($EjecutarTodos)                                                { Test-LolDrivers }
    if ($EjecutarTodos -or $Modulos -contains 'Software')              { Test-SoftwareDesactualizado }
    if ($EjecutarTodos -or $Modulos -contains 'Extensiones')           { Test-ExtensionesNavegador }
    if ($EjecutarTodos -or $Modulos -contains 'Defender')              { Test-DefenderPostura }
    if ($Modulos -contains 'Parcheo')                                  { Invoke-Parcheo -Modo 'Todo' }
    Show-ResumenEjecutivo
    Export-ReportesCYBERAD
    return
}

# Modo interactivo (menu) por defecto
Show-MenuPrincipal