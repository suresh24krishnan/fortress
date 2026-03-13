# ------------------------------------------------------------
# FortressV2 Platform Startup Script (Enterprise Safe)
# Handles:
# - Spaces in paths
# - Policy configuration
# - SQLite ledger configuration
# - Stable uvicorn reload (no .venv watching)
# ------------------------------------------------------------

Write-Host "Starting FortressV2..." -ForegroundColor Cyan

# Resolve project root (parent of tools/)
$ROOT = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$VENV_ACTIVATE = Join-Path $ROOT ".venv\Scripts\Activate.ps1"
$POLICY_PATH   = Join-Path $ROOT "policy\policy.yaml"
$LEDGER_PATH   = Join-Path $ROOT "data\ledger.db"

# Validate environment
if (!(Test-Path $VENV_ACTIVATE)) {
    Write-Host "Virtual environment not found at .venv" -ForegroundColor Red
    exit 1
}

if (!(Test-Path $POLICY_PATH)) {
    Write-Host "policy.yaml not found at $POLICY_PATH" -ForegroundColor Red
    exit 1
}

# Ensure data directory exists
$dataDir = Join-Path $ROOT "data"
if (!(Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir | Out-Null
}

Write-Host "Root   : $ROOT" -ForegroundColor Green
Write-Host "Policy : $POLICY_PATH" -ForegroundColor Green
Write-Host "Ledger : $LEDGER_PATH" -ForegroundColor Green

# Escape for child PowerShell sessions
$ROOT_ESC   = $ROOT.Replace("'", "''")
$POLICY_ESC = $POLICY_PATH.Replace("'", "''")
$LEDGER_ESC = $LEDGER_PATH.Replace("'", "''")
$ACT_ESC    = $VENV_ACTIVATE.Replace("'", "''")

# ------------------------------------------------------------
# API Command
# ------------------------------------------------------------
Write-Host "Starting API..." -ForegroundColor Yellow

$apiCommand = @"
Set-Location -Path '$ROOT_ESC'
`$env:FORTRESS_POLICY = '$POLICY_ESC'
`$env:FORTRESS_LEDGER = 'on'
`$env:FORTRESS_LEDGER_PATH = '$LEDGER_ESC'
& '$ACT_ESC'
uvicorn api.main:app --reload --reload-dir api --reload-dir policy --port 8000
"@

Start-Process powershell -ArgumentList "-NoExit", "-Command", $apiCommand

Start-Sleep -Seconds 2

# ------------------------------------------------------------
# UI Command
# ------------------------------------------------------------
Write-Host "Starting UI..." -ForegroundColor Yellow

$uiCommand = @"
Set-Location -Path '$ROOT_ESC'
& '$ACT_ESC'
streamlit run ui/app.py
"@

Start-Process powershell -ArgumentList "-NoExit", "-Command", $uiCommand

Write-Host ""
Write-Host "FortressV2 launched" -ForegroundColor Cyan
Write-Host "API: http://localhost:8000"
Write-Host "UI : http://localhost:8501"
Write-Host ""