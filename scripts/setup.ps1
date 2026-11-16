# Project-level setup only: installs Python and dashboard dependencies.
# Never installs system software and never pulls models.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

& (Join-Path $PSScriptRoot 'check.ps1')
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Setup stopped: fix the missing items above first.' -ForegroundColor Red
    exit 1
}

if (Test-Path -LiteralPath (Join-Path $root 'pyproject.toml')) {
    Write-Host 'Installing Python dependencies...'
    Push-Location $root
    try { & uv sync; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } } finally { Pop-Location }
} else {
    Write-Host 'Skipping uv sync: no pyproject.toml yet.'
}

$dashboard = Join-Path $root 'dashboard'
if (Test-Path -LiteralPath (Join-Path $dashboard 'package.json')) {
    Write-Host 'Installing dashboard dependencies...'
    Push-Location $dashboard
    try { & pnpm install; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } } finally { Pop-Location }
} else {
    Write-Host 'Skipping pnpm install: no dashboard yet.'
}

Write-Host 'Setup complete.' -ForegroundColor Green
