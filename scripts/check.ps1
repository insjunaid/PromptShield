# Read-only prerequisite check. Installs nothing and never prints secrets.
# Exit code: 0 when every required item passes, 1 otherwise.
# Overrides: PROMPTSHIELD_ENV_FILE, OLLAMA_URL, PROMPTSHIELD_AGENT_MODEL, PROMPTSHIELD_JUDGE_MODEL.

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$script:failed = 0

function Write-Result([string]$status, [string]$name, [string]$detail) {
    $color = switch ($status) { 'OK' { 'Green' } 'MISSING' { 'Red' } default { 'Yellow' } }
    Write-Host ('[{0,-7}] {1,-20} {2}' -f $status, $name, $detail) -ForegroundColor $color
}

function Add-Failure([string]$name, [string]$detail) {
    $script:failed++
    Write-Result 'MISSING' $name $detail
}

function Get-EnvValue([string]$key, [string]$default) {
    $fromProcess = [Environment]::GetEnvironmentVariable($key)
    if ($fromProcess) { return $fromProcess }
    if (Test-Path -LiteralPath $script:envFile) {
        foreach ($line in Get-Content -LiteralPath $script:envFile) {
            if ($line.StartsWith("$key=")) {
                return $line.Substring($key.Length + 1).Trim().Trim('"', "'")
            }
        }
    }
    return $default
}

function Test-Tool([string]$name, [string]$versionArg, [string]$installHint) {
    $command = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $command) {
        Add-Failure $name "install with: $installHint"
        return
    }
    $version = (& $name $versionArg 2>$null | Select-Object -First 1)
    Write-Result 'OK' $name "$version"
}

# Asks for the file without following redirects, so the token only goes to huggingface.co.
function Get-HfStatus([string]$repo, [string]$token) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $request = [System.Net.HttpWebRequest]::Create("https://huggingface.co/$repo/resolve/main/config.json")
    $request.Method = 'HEAD'
    $request.AllowAutoRedirect = $false
    $request.Timeout = 15000
    $request.Headers.Add('Authorization', "Bearer $token")
    try {
        $response = $request.GetResponse()
        $code = [int]$response.StatusCode
        $response.Close()
        return $code
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}

$script:envFile = $env:PROMPTSHIELD_ENV_FILE
if (-not $script:envFile) { $script:envFile = Join-Path $root '.env' }

Write-Host 'PromptShield prerequisite check (read-only)'
Write-Host ''
Write-Host 'Tools'
Test-Tool 'git' '--version' 'winget install --id Git.Git -e'
Test-Tool 'uv' '--version' 'winget install --id astral-sh.uv -e'
Test-Tool 'node' '--version' 'winget install --id OpenJS.NodeJS.LTS -e'
Test-Tool 'pnpm' '--version' 'npm install -g pnpm'
Test-Tool 'make' '--version' 'winget install --id ezwinports.make -e'

if (Get-Command uv -ErrorAction SilentlyContinue) {
    $python = (& uv python find 3.12 2>$null | Select-Object -First 1)
    if ($python) { Write-Result 'OK' 'python 3.12' "$python" }
    else { Add-Failure 'python 3.12' 'install with: uv python install 3.12' }
}

if (Get-Command docker -ErrorAction SilentlyContinue) { Write-Result 'OK' 'docker (optional)' 'found' }
else { Write-Result 'INFO' 'docker (optional)' 'not found; only needed for the stretch compose file' }

Write-Host ''
Write-Host 'Ollama (HTTP API)'
$ollamaUrl = Get-EnvValue 'OLLAMA_URL' 'http://localhost:11434'
$agentModel = Get-EnvValue 'PROMPTSHIELD_AGENT_MODEL' 'qwen3:4b-instruct'
$judgeModel = Get-EnvValue 'PROMPTSHIELD_JUDGE_MODEL' 'qwen3:4b-instruct'
try {
    $version = Invoke-RestMethod -Uri "$ollamaUrl/api/version" -TimeoutSec 5
    Write-Result 'OK' 'ollama server' "$ollamaUrl, version $($version.version)"
    $names = (Invoke-RestMethod -Uri "$ollamaUrl/api/tags" -TimeoutSec 5).models.name
    foreach ($model in (@($agentModel, $judgeModel) | Select-Object -Unique)) {
        if ($names -contains $model) { Write-Result 'OK' 'model' $model }
        else { Add-Failure 'model' "$model not pulled; POST $ollamaUrl/api/pull or 'ollama pull $model'" }
    }
} catch {
    Add-Failure 'ollama server' "not reachable at $ollamaUrl; start the Ollama app"
}

Write-Host ''
Write-Host 'Hugging Face'
$token = Get-EnvValue 'HF_TOKEN' ''
if (-not $token) {
    Write-Result 'WARN' 'HF_TOKEN' 'not set; export the ungated fallback instead: export_classifiers.py --model fallback'
} else {
    Write-Result 'OK' 'HF_TOKEN' 'set (value not shown)'
    foreach ($repo in @('meta-llama/Llama-Prompt-Guard-2-22M', 'meta-llama/Llama-Prompt-Guard-2-86M')) {
        $code = Get-HfStatus $repo $token
        if ($code -ge 200 -and $code -lt 400) { Write-Result 'OK' 'gated access' "$repo (HTTP $code)" }
        elseif ($code -eq 0) { Write-Result 'WARN' 'gated access' "$repo could not be checked (network)" }
        else { Write-Result 'WARN' 'gated access' "$repo denied (HTTP $code); accept the license or check the token" }
    }
}

Write-Host ''
Write-Host 'Machine'
$os = Get-CimInstance Win32_OperatingSystem
$freeGb = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
$totalGb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
if ($freeGb -lt 3) { Write-Result 'WARN' 'memory' "$freeGb GB free of $totalGb GB; close other apps before long runs" }
else { Write-Result 'OK' 'memory' "$freeGb GB free of $totalGb GB" }

Write-Host ''
if ($script:failed -eq 0) {
    Write-Host 'All required checks passed.' -ForegroundColor Green
    exit 0
}
Write-Host "$($script:failed) required item(s) missing. Install them, open a new terminal, and run this again." -ForegroundColor Red
exit 1
