# Starts the whole demo with one command: attack site, attacker sink, API + MCP gateway, dashboard.
#
#   powershell -File scripts/demo.ps1          # start, print URLs, Ctrl+C stops everything
#   powershell -File scripts/demo.ps1 -Check   # start, check every URL answers, stop (exit 0/1)
#
# The mock MCP servers (files, mail, http, web) aren't long-running: every lab run starts its own.
# Everything binds to 127.0.0.1. Services already running on their port are reused and left alone.
# Logs: data/logs/demo_<stamp>/ (git-ignored).
param([switch]$Check)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$logs = Join-Path $root ("data\logs\demo_{0:yyyyMMdd_HHmmss}" -f (Get-Date))
New-Item -ItemType Directory -Force $logs | Out-Null

$services = @(
    @{ Name = 'Attack site'; Port = 8081; Url = 'http://127.0.0.1:8081/b01_article.html'
       File = 'uv'; Args = @('run', 'python', '-m', 'lab.attack_site.serve') },
    @{ Name = 'Attacker sink'; Port = 9999; Url = 'http://127.0.0.1:9999/captured'
       File = 'uv'; Args = @('run', 'python', '-m', 'lab.attacker_sink.server') },
    @{ Name = 'API + MCP gateway'; Port = 8000; Url = 'http://127.0.0.1:8000/health'
       File = 'uv'; Args = @('run', 'python', '-m', 'promptshield.api.server') },
    @{ Name = 'Dashboard'; Port = 5173; Url = 'http://127.0.0.1:5173/'
       File = 'pnpm'; Args = @('--dir', 'dashboard', 'dev') }
)

function Test-Url([string]$url) {
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3
        return $response.StatusCode -eq 200
    } catch { return $false }
}

function Test-PortBusy([int]$port) {
    $client = New-Object Net.Sockets.TcpClient
    try { $client.Connect('127.0.0.1', $port); return $true } catch { return $false } finally { $client.Close() }
}

function Resolve-Launch([string]$name, [string[]]$arguments) {
    # Applications only: on Windows pnpm is often a .ps1 shim first and a .cmd second, and a .cmd
    # has to go through cmd.exe to start with redirected output.
    $app = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $app) { throw "Can't find an executable for $name" }
    if ($app.Source -match '\.(cmd|bat)$') {
        return @{ File = $env:ComSpec; Args = @('/c', $app.Source) + $arguments }
    }
    return @{ File = $app.Source; Args = $arguments }
}

function Stop-Started($started) {
    foreach ($process in $started) {
        if (-not $process.HasExited) {
            # /T takes the children too: uv starts python, pnpm starts node.
            & taskkill /PID $process.Id /T /F 2>&1 | Out-Null
        }
    }
}

# Preflight
foreach ($tool in 'uv', 'pnpm') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Host "Missing $tool. Run: powershell -File scripts/check.ps1" -ForegroundColor Red
        exit 1
    }
}
if (-not (Test-Path (Join-Path $root '.venv')) -or -not (Test-Path (Join-Path $root 'dashboard\node_modules'))) {
    Write-Host 'Dependencies are not installed. Run: make setup (or powershell -File scripts/setup.ps1)' -ForegroundColor Red
    exit 1
}
$ollama = if ($env:OLLAMA_URL) { $env:OLLAMA_URL } else { 'http://localhost:11434' }
$ollamaUp = Test-Url "$ollama/api/version"
if (-not $ollamaUp) {
    Write-Host "Ollama isn't reachable at $ollama. The dashboard works, but lab runs need it." -ForegroundColor Yellow
}

$started = New-Object System.Collections.ArrayList
$exitCode = 0
try {
    foreach ($service in $services) {
        if (Test-Url $service.Url) {
            Write-Host ("{0,-18} already running, reusing it" -f $service.Name)
            $service.Reused = $true
            continue
        }
        if (Test-PortBusy $service.Port) {
            throw ("Port {0} is taken by something that isn't the {1}. Stop it, then try again." -f $service.Port, $service.Name)
        }
        $slug = ($service.Name -replace '[^A-Za-z]+', '_').ToLower()
        $launch = Resolve-Launch $service.File $service.Args
        $process = Start-Process -FilePath $launch.File -ArgumentList $launch.Args -WorkingDirectory $root `
            -RedirectStandardOutput (Join-Path $logs "$slug.log") -RedirectStandardError (Join-Path $logs "$slug.err.log") `
            -WindowStyle Hidden -PassThru
        [void]$started.Add($process)
        Write-Host ("{0,-18} starting (pid {1})" -f $service.Name, $process.Id)
    }
    # The API loads the classifier at startup, so it gets the longest wait.
    $deadline = (Get-Date).AddSeconds(180)
    foreach ($service in $services) {
        while (-not (Test-Url $service.Url)) {
            if ((Get-Date) -gt $deadline) { throw "$($service.Name) didn't answer at $($service.Url). Logs: $logs" }
            Start-Sleep -Milliseconds 500
        }
        Write-Host ("{0,-18} ready   {1}" -f $service.Name, $service.Url) -ForegroundColor Green
    }

    Write-Host ''
    Write-Host 'PromptShield demo is running (localhost only):' -ForegroundColor Cyan
    Write-Host '  Dashboard        http://127.0.0.1:5173/'
    Write-Host '  Red-Team Lab     http://127.0.0.1:5173/lab   (pick A02, then "Run comparison")'
    Write-Host '  API docs         http://127.0.0.1:8000/docs'
    Write-Host '  MCP gateway      http://127.0.0.1:8000/mcp/'
    Write-Host '  Attack page A02  http://127.0.0.1:8081/a02_article.html   (white-on-white instruction)'
    Write-Host '  Attacker sink    http://127.0.0.1:9999/captured'
    Write-Host "  Logs             $logs"
    if (-not $ollamaUp) { Write-Host '  Note: start Ollama before running lab scenarios.' -ForegroundColor Yellow }

    if ($Check) {
        # The browser reaches the API through the dashboard's proxy, so check that link too.
        $extra = @('http://127.0.0.1:5173/v1/stats?window=1h', 'http://127.0.0.1:8000/docs', 'http://127.0.0.1:8081/a02_article.html')
        foreach ($url in $extra) {
            if (-not (Test-Url $url)) { throw "No answer from $url. Logs: $logs" }
        }
        Write-Host 'Check passed: every service answered, and the dashboard reaches the API.' -ForegroundColor Green
    } else {
        Write-Host 'Press Ctrl+C to stop everything this script started.'
        while ($true) {
            foreach ($process in $started) {
                if ($process.HasExited) { throw "A service stopped (pid $($process.Id)). Logs: $logs" }
            }
            Start-Sleep -Seconds 2
        }
    }
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    $exitCode = 1
} finally {
    if ($started.Count -gt 0) {
        Write-Host 'Stopping the services this script started...'
        Stop-Started $started
    }
}
exit $exitCode
