$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$pythonExe = Join-Path $projectRoot "venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    Write-Host "[ERREUR] Environnement virtuel introuvable: $pythonExe" -ForegroundColor Red
    Write-Host "Lance d'abord: python setup_hackathon.py" -ForegroundColor Yellow
    exit 1
}

Write-Host "[1/3] Arret des anciennes instances main.py..." -ForegroundColor Cyan
$oldProcs = Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -match "^python(\.exe)?$" -and
        $_.CommandLine -match "main\.py"
    }

foreach ($proc in $oldProcs) {
    try {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
        Write-Host ("  - Stop PID {0}" -f $proc.ProcessId)
    } catch {
        Write-Host ("  - PID {0} deja arrete" -f $proc.ProcessId) -ForegroundColor DarkYellow
    }
}

Start-Sleep -Seconds 1

Write-Host "[2/3] Demarrage d'InfraSentinel-CI..." -ForegroundColor Cyan
$stdoutPath = Join-Path $projectRoot "app_stdout.log"
$stderrPath = Join-Path $projectRoot "app_stderr.log"

if (Test-Path $stdoutPath) { Remove-Item $stdoutPath -Force -ErrorAction SilentlyContinue }
if (Test-Path $stderrPath) { Remove-Item $stderrPath -Force -ErrorAction SilentlyContinue }

$proc = Start-Process -FilePath $pythonExe `
    -ArgumentList "-u", "main.py" `
    -WorkingDirectory $projectRoot `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath `
    -PassThru

Start-Sleep -Seconds 4

Write-Host "[3/3] Verification du port 9090..." -ForegroundColor Cyan
$isListening = $false
for ($i = 0; $i -lt 25; $i++) {
    if ($proc.HasExited) {
        break
    }
    $listenLine = netstat -ano | Select-String ":9090" | Select-String "LISTENING"
    if ($listenLine) {
        $isListening = $true
        break
    }
    Start-Sleep -Seconds 1
}

if ($isListening) {
    Write-Host "OK: Dashboard en ligne sur http://127.0.0.1:9090" -ForegroundColor Green
    Write-Host ("PID actif: {0}" -f $proc.Id) -ForegroundColor Green
    exit 0
}

Write-Host "ECHEC: le port 9090 n'est pas en ecoute." -ForegroundColor Red
Write-Host "Consulte app_stderr.log pour le detail." -ForegroundColor Yellow
if (Test-Path $stderrPath) {
    Get-Content $stderrPath -Tail 40
}
exit 1
