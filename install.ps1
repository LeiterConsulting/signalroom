# SignalRoom universal installer and lifecycle manager for Windows.
# Requires PowerShell 7+ and Python 3.11+.

param(
    [Parameter(Position = 0)]
    [string]$Command = "",
    [switch]$Help,
    [switch]$Start,
    [switch]$Stop,
    [switch]$Restart,
    [switch]$Status,
    [switch]$Uninstall,
    [switch]$ForceYes,
    [switch]$PublicOnly,
    [switch]$PurgeData,
    [switch]$OpenBrowser,
    [switch]$SetupModels,
    [switch]$InstallOllama,
    [switch]$PullModels,
    [int]$Port = 8003,
    [string]$BindAddress = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$Version = "0.1.0"
$AppName = "SignalRoom Splunk Security Agent"
$InstallDir = $PSScriptRoot
$VenvDir = Join-Path $InstallDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$ManifestFile = Join-Path $InstallDir ".install_manifest.json"
$PidFile = Join-Path $InstallDir ".signalroom.pid"
$RuntimeFile = Join-Path $InstallDir ".signalroom.runtime.json"
$LogFile = Join-Path $InstallDir "signalroom.log"
$ErrorLogFile = Join-Path $InstallDir "signalroom.err.log"
$PyPiUrl = "https://pypi.org/simple"

function Write-Info([string]$Message) { Write-Host $Message -ForegroundColor Cyan }
function Write-Success([string]$Message) { Write-Host $Message -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host $Message -ForegroundColor Yellow }
function Write-Failure([string]$Message) { Write-Host $Message -ForegroundColor Red }

function Show-Help {
    Write-Success "$AppName v$Version"
    Write-Host ""
    Write-Info "USAGE"
    Write-Host "    .\install.ps1 [OPTIONS]"
    Write-Host "    .\install.ps1 [start|stop|restart|status|uninstall]"
    Write-Host ""
    Write-Info "OPTIONS"
    Write-Host "    (no arguments)    Install or update dependencies and start"
    Write-Host "    -Start             Install if needed, then start"
    Write-Host "    -Stop              Stop the managed service"
    Write-Host "    -Restart           Restart the managed service"
    Write-Host "    -Status            Show process, URL, health, and log locations"
    Write-Host "    -Uninstall         Remove the virtual environment and runtime files"
    Write-Host "    -ForceYes          Skip the uninstall confirmation"
    Write-Host "    -PurgeData         With -Uninstall, also remove local secrets and artifacts"
    Write-Host "    -PublicOnly        Install only from public PyPI"
    Write-Host "    -Port 8003         Preferred port; the app safely falls forward if busy"
    Write-Host "    -BindAddress ...   Bind address (default 127.0.0.1)"
    Write-Host "    -OpenBrowser       Open the workspace after a successful start"
    Write-Host "    -SetupModels       Check Ollama and Hugging Face model readiness"
    Write-Host "    -InstallOllama     Explicitly install Ollama from ollama.com"
    Write-Host "    -PullModels        Download the configured Ollama model profiles"
    Write-Host "    -Help              Show this help"
    Write-Host ""
    Write-Info "EXAMPLES"
    Write-Host "    .\install.ps1"
    Write-Host "    .\install.ps1 -Start -PublicOnly"
    Write-Host "    .\install.ps1 -SetupModels -InstallOllama -PullModels"
    Write-Host "    .\install.ps1 -Restart"
    Write-Host "    .\install.ps1 -Status"
    Write-Host "    .\install.ps1 -Uninstall -ForceYes"
    Write-Host ""
    Write-Info "DEFAULT WORKSPACE"
    Write-Host "    http://localhost:8003"
}

function Get-BootstrapPython {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Failure "PowerShell 7+ is required. Install it with: winget install Microsoft.PowerShell"
        exit 1
    }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        Write-Failure "Python 3.11+ was not found. Install it with: winget install Python.Python.3.13"
        exit 1
    }
    & $python.Source -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
    if ($LASTEXITCODE -ne 0) {
        Write-Failure "SignalRoom requires Python 3.11 or newer."
        exit 1
    }
    return $python.Source
}

function Invoke-PipWithFallback {
    param([string]$Description, [string[]]$PipArguments)
    $common = @("--disable-pip-version-check", "--retries", "2", "--timeout", "20")
    if ($PublicOnly) {
        Write-Info "Using public PyPI only."
        & $VenvPython -m pip @PipArguments @common --index-url $PyPiUrl --no-cache-dir
        if ($LASTEXITCODE -eq 0) { return }
        Write-Failure "$Description failed while using public PyPI."
        exit 1
    }
    & $VenvPython -m pip @PipArguments @common
    if ($LASTEXITCODE -eq 0) { return }
    Write-Warn "$Description failed with the configured package index. Retrying with public PyPI..."
    & $VenvPython -m pip @PipArguments @common --index-url $PyPiUrl --no-cache-dir
    if ($LASTEXITCODE -eq 0) { return }
    Write-Failure "$Description failed. Check network access or retry with -PublicOnly."
    exit 1
}

function Get-ProjectHash {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $InstallDir "pyproject.toml")).Hash.ToLowerInvariant()
}

function Test-Installation {
    if (-not (Test-Path -LiteralPath $ManifestFile) -or -not (Test-Path -LiteralPath $VenvPython)) {
        return $false
    }
    try {
        $manifest = Get-Content -Raw -LiteralPath $ManifestFile | ConvertFrom-Json
        return ($manifest.version -eq $Version -and $manifest.project_hash -eq (Get-ProjectHash))
    } catch {
        return $false
    }
}

function Install-Dependencies {
    $bootstrapPython = Get-BootstrapPython
    $pythonVersion = (& $bootstrapPython --version 2>&1) -replace "Python ", ""
    Write-Success "Python $pythonVersion found"
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        Write-Info "Creating isolated virtual environment..."
        & $bootstrapPython -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) { Write-Failure "Virtual environment creation failed."; exit 1 }
    }
    & $VenvPython -m pip --version *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "The existing virtual environment is incomplete; rebuilding it..."
        Remove-SafeTree $VenvDir
        & $bootstrapPython -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) { Write-Failure "Virtual environment repair failed."; exit 1 }
    }
    Write-Info "Installing SignalRoom and dependencies..."
    Invoke-PipWithFallback "SignalRoom installation" @("install", "-e", $InstallDir, "-q")
    $pipVersion = (& $VenvPython -m pip --version) -replace "pip ", "" -replace " from.*", ""
    $manifest = @{
        version = $Version
        project_hash = Get-ProjectHash
        installed_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        os = "Windows"
        python = @{ version = $pythonVersion; executable = $VenvPython }
        pip = @{ version = $pipVersion }
        virtual_env = $VenvDir
        preferred_port = $Port
    }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ManifestFile -Encoding UTF8
    Write-Success "SignalRoom installation is up to date."
}

function Get-ManagedPid {
    $runtime = Get-RuntimeState
    if ($runtime -and ([string]$runtime.pid -match "^\d+$")) {
        $runtimePid = [int]$runtime.pid
        if ((Get-Process -Id $runtimePid -ErrorAction SilentlyContinue) -and (Test-OwnedProcess $runtimePid)) {
            return $runtimePid
        }
    }
    if (-not (Test-Path -LiteralPath $PidFile)) { return $null }
    $value = (Get-Content -Raw -LiteralPath $PidFile).Trim()
    if ($value -notmatch "^\d+$") { return $null }
    return [int]$value
}

function Test-OwnedProcess([int]$ProcessId) {
    try {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
        if (-not $process) { return $false }
        $commandLine = [string]$process.CommandLine
        return $commandLine.Contains("splunk_security_agent.main") -and $commandLine.Contains(".signalroom.runtime.json")
    } catch {
        return $false
    }
}

function Get-RuntimeState {
    if (-not (Test-Path -LiteralPath $RuntimeFile)) { return $null }
    try { return Get-Content -Raw -LiteralPath $RuntimeFile | ConvertFrom-Json } catch { return $null }
}

function Test-Health([string]$Url) {
    try {
        $response = Invoke-RestMethod -Method Get -Uri "$Url/api/health" -TimeoutSec 2
        return [bool]$response.ok
    } catch {
        return $false
    }
}

function Start-SignalRoom {
    if (-not (Test-Installation)) { Install-Dependencies }
    $existingPid = Get-ManagedPid
    if ($existingPid -and (Get-Process -Id $existingPid -ErrorAction SilentlyContinue)) {
        if (Test-OwnedProcess $existingPid) {
            $runtime = Get-RuntimeState
            $url = if ($runtime) { $runtime.url } else { "http://localhost:$Port" }
            Write-Warn "SignalRoom is already running (PID $existingPid)."
            Write-Info "Workspace: $url"
            return
        }
        Write-Warn "Ignoring a stale PID file that points to an unrelated process."
    }
    Remove-Item -LiteralPath $PidFile, $RuntimeFile -Force -ErrorAction SilentlyContinue
    New-Item -ItemType File -Path $LogFile, $ErrorLogFile -Force | Out-Null
    Write-Info "Starting SignalRoom..."
    $arguments = @(
        "-m", "splunk_security_agent.main",
        "--host", $BindAddress,
        "--port", [string]$Port,
        "--runtime-file", "`"$RuntimeFile`""
    )
    try {
        $process = Start-Process -FilePath $VenvPython -ArgumentList $arguments `
            -WorkingDirectory $InstallDir -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $LogFile -RedirectStandardError $ErrorLogFile
    } catch {
        Write-Failure "Unable to start SignalRoom: $($_.Exception.Message)"
        exit 1
    }
    [string]$process.Id | Set-Content -LiteralPath $PidFile -Encoding ASCII
    $runtime = $null
    $healthy = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        Start-Sleep -Milliseconds 250
        if (-not (Get-Process -Id $process.Id -ErrorAction SilentlyContinue)) { break }
        $runtime = Get-RuntimeState
        if ($runtime -and (Test-Health ([string]$runtime.url))) { $healthy = $true; break }
    }
    if (-not $healthy) {
        Write-Failure "SignalRoom did not become healthy."
        Write-Info "Error log: $ErrorLogFile"
        if (Test-OwnedProcess $process.Id) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $PidFile, $RuntimeFile -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $ErrorLogFile) { Get-Content -Tail 20 -LiteralPath $ErrorLogFile }
        exit 1
    }
    $actualPid = [int]$runtime.pid
    [string]$actualPid | Set-Content -LiteralPath $PidFile -Encoding ASCII
    Write-Success "SignalRoom started successfully (PID $actualPid)."
    Write-Info "Workspace: $($runtime.url)"
    Write-Info "Logs: Get-Content `"$LogFile`" -Wait"
    Write-Info "Errors: Get-Content `"$ErrorLogFile`" -Wait"
    if ($OpenBrowser) { Start-Process ([string]$runtime.url) }
}

function Stop-SignalRoom {
    $managedPid = Get-ManagedPid
    if (-not $managedPid) {
        Write-Warn "SignalRoom is not running."
        Remove-Item -LiteralPath $RuntimeFile -Force -ErrorAction SilentlyContinue
        return
    }
    if (-not (Get-Process -Id $managedPid -ErrorAction SilentlyContinue)) {
        Write-Warn "SignalRoom is not running (stale PID file removed)."
        Remove-Item -LiteralPath $PidFile, $RuntimeFile -Force -ErrorAction SilentlyContinue
        return
    }
    if (-not (Test-OwnedProcess $managedPid)) {
        Write-Failure "PID $managedPid is not owned by this SignalRoom installation; it will not be stopped."
        Remove-Item -LiteralPath $PidFile, $RuntimeFile -Force -ErrorAction SilentlyContinue
        return
    }
    Write-Info "Stopping SignalRoom (PID $managedPid)..."
    Stop-Process -Id $managedPid -Force
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        if (-not (Get-Process -Id $managedPid -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 250
    }
    Remove-Item -LiteralPath $PidFile, $RuntimeFile -Force -ErrorAction SilentlyContinue
    Write-Success "SignalRoom stopped."
}

function Show-Status {
    $managedPid = Get-ManagedPid
    if (-not $managedPid -or -not (Get-Process -Id $managedPid -ErrorAction SilentlyContinue)) {
        Write-Warn "SignalRoom is not running."
        Remove-Item -LiteralPath $PidFile, $RuntimeFile -Force -ErrorAction SilentlyContinue
        return
    }
    if (-not (Test-OwnedProcess $managedPid)) {
        Write-Warn "SignalRoom PID file is stale or points to an unrelated process."
        return
    }
    $runtime = Get-RuntimeState
    $url = if ($runtime) { [string]$runtime.url } else { "http://localhost:$Port" }
    Write-Success "SignalRoom is running (PID $managedPid)."
    Write-Info "Workspace: $url"
    Write-Host "Health: $(if (Test-Health $url) { 'healthy' } else { 'starting or unavailable' })"
    Write-Host "Logs: $LogFile"
    Write-Host "Errors: $ErrorLogFile"
}

function Remove-SafeTree([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $root = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\') + '\'
    $target = [IO.Path]::GetFullPath($Path)
    if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the SignalRoom workspace: $target"
    }
    Remove-Item -LiteralPath $target -Recurse -Force
}

function Clear-Data {
    $dataDir = Join-Path $InstallDir "data"
    foreach ($name in @("config.json", "secrets.enc", ".vault.key", "evidence.db")) {
        Remove-Item -LiteralPath (Join-Path $dataDir $name) -Force -ErrorAction SilentlyContinue
    }
    foreach ($folder in @("artifacts", "uploads")) {
        $folderPath = Join-Path $dataDir $folder
        if (Test-Path -LiteralPath $folderPath) {
            Get-ChildItem -LiteralPath $folderPath -Force | Where-Object Name -ne ".gitkeep" | Remove-Item -Recurse -Force
        }
    }
}

function Uninstall-Service {
    if (-not $ForceYes) {
        $scope = if ($PurgeData) { "the environment and all local data" } else { "the environment (local data is preserved)" }
        Write-Warn "This will remove $scope."
        if ((Read-Host "Continue? (yes/no)") -ne "yes") { Write-Info "Uninstall cancelled."; return }
    }
    Stop-SignalRoom
    if (Test-Path -LiteralPath $VenvDir) { Write-Info "Removing virtual environment..."; Remove-SafeTree $VenvDir }
    Remove-Item -LiteralPath $ManifestFile, $PidFile, $RuntimeFile, $LogFile, $ErrorLogFile -Force -ErrorAction SilentlyContinue
    if ($PurgeData) { Clear-Data; Write-Warn "Local SignalRoom data was removed." }
    Write-Success "Uninstall complete. Source code remains in $InstallDir"
}

function Invoke-ModelSetup {
    if ($InstallOllama -and -not (Get-Command ollama -ErrorAction SilentlyContinue)) {
        Write-Info "Installing Ollama from the official ollama.com installer..."
        $installer = Invoke-RestMethod -Uri "https://ollama.com/install.ps1"
        & ([ScriptBlock]::Create($installer))
        if ($LASTEXITCODE -ne 0) { Write-Failure "Ollama installation failed."; exit 1 }
    }
    Write-Info "Checking model readiness..."
    & $VenvPython -m splunk_security_agent.model_setup status
    if ($LASTEXITCODE -ne 0) { Write-Failure "Model readiness check failed."; exit 1 }
    if ($PullModels) {
        Write-Warn "Downloading configured Ollama models. This can use several gigabytes of disk and bandwidth."
        & $VenvPython -m splunk_security_agent.model_setup pull
        if ($LASTEXITCODE -ne 0) { Write-Failure "One or more model downloads failed."; exit 1 }
    }
}

$selected = $Command.ToLowerInvariant()
if ($Help) { $selected = "help" }
elseif ($Start) { $selected = "start" }
elseif ($Stop) { $selected = "stop" }
elseif ($Restart) { $selected = "restart" }
elseif ($Status) { $selected = "status" }
elseif ($Uninstall) { $selected = "uninstall" }

switch ($selected) {
    "help" { Show-Help }
    "-h" { Show-Help }
    "--help" { Show-Help }
    "start" { Start-SignalRoom; if ($SetupModels -or $InstallOllama -or $PullModels) { Invoke-ModelSetup } }
    "stop" { Stop-SignalRoom }
    "restart" { Stop-SignalRoom; Start-Sleep -Seconds 1; Start-SignalRoom }
    "status" { Show-Status }
    "uninstall" { Uninstall-Service }
    "" {
        Write-Info "=================================================="
        Write-Success " $AppName"
        Write-Success " Version $Version"
        Write-Info "=================================================="
        if (Test-Installation) { Write-Success "Installation is up to date." }
        Start-SignalRoom
        if ($SetupModels -or $InstallOllama -or $PullModels) { Invoke-ModelSetup }
    }
    default { Write-Failure "Unknown command: $Command"; Show-Help; exit 1 }
}
