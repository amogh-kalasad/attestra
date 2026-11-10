# Local (venv) install: deps + auto Fernet key in .env + Mongo schema init.
# Run from the repository root:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install_local.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "==> Creating/using .venv"
if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    python -m venv .venv
}
$Py = ".\.venv\Scripts\python.exe"

Write-Host "==> Installing package (dev extras)"
& $Py -m pip install --upgrade pip
& $Py -m pip install -e ".[dev]"

Write-Host "==> Ensuring ATTESTRA_CREDENTIAL_FERNET_KEY in .env"
& $Py .\scripts\ensure_env_secrets.py

Write-Host "==> Mongo schema init (requires reachable ATTESTRA_MONGODB_URI)"
& $Py -m attestra.cli init

Write-Host "Done. Activate with: .\.venv\Scripts\Activate.ps1"
Write-Host "Then: python -m attestra.cli serve   and   python -m attestra.cli worker"
