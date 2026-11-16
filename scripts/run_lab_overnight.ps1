# Runs the lab suite (3 repeats, shield off then on) once the laptop is on mains power.
#
#   powershell -File scripts/run_lab_overnight.ps1            # waits for power, then runs
#   Start-Process powershell -ArgumentList '-File','scripts/run_lab_overnight.ps1' -WindowStyle Minimized
#
# Waiting matters: on battery the run is slower and the laptop may sleep. The suite itself asks
# Windows to stay awake while it runs. Output goes to data/logs/ (git-ignored).
#   powershell -File scripts/run_lab_overnight.ps1 -Suite ablation   # the layer ablation (P7.3)
#   powershell -File scripts/run_lab_overnight.ps1 -Suite latency    # latency profiling (P7.4)
param([int]$Repeats = 3, [ValidateSet("lab", "ablation", "latency")][string]$Suite = "lab")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$logs = Join-Path $root "data\logs"
New-Item -ItemType Directory -Force $logs | Out-Null
$log = Join-Path $logs ("{0}_overnight_{1:yyyyMMdd_HHmm}.log" -f $Suite, (Get-Date))

function Write-Log([string]$text) {
    $line = "{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $text
    Add-Content -Path $log -Value $line -Encoding utf8
}

function Test-Mains {
    $battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    # BatteryStatus 1 means discharging; anything else (charging, full, no battery) is mains.
    return ($null -eq $battery) -or ($battery.BatteryStatus -ne 1)
}

Write-Log "waiting for mains power (repeats: $Repeats)"
while (-not (Test-Mains)) { Start-Sleep -Seconds 30 }
Write-Log "on mains power"

$ollama = if ($env:OLLAMA_URL) { $env:OLLAMA_URL } else { "http://localhost:11434" }
try {
    Invoke-RestMethod "$ollama/api/version" -TimeoutSec 5 | Out-Null
} catch {
    Write-Log "Ollama is not reachable at $ollama; stopping without running"
    exit 1
}

Write-Log "starting: eval.run_benchmark --suite $Suite --repeats $Repeats"
# cmd's redirect appends the bytes as they come (the suite prints UTF-8). PowerShell 5.1's `*>>` would
# write UTF-16 into a UTF-8 log, and its `2>&1` would turn stderr lines into errors under "Stop".
& cmd /c "uv run --group eval python -m eval.run_benchmark --suite $Suite --repeats $Repeats >> `"$log`" 2>&1"
$code = $LASTEXITCODE
Write-Log "finished with exit code $code"
exit $code
