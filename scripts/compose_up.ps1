# Docker Compose install/up: ensure Fernet key in host .env, then build and start.
# Run from the repository root:
#   powershell -ExecutionPolicy Bypass -File .\scripts\compose_up.ps1
# Extra args are passed to `docker compose up` (default: -d --build).

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Py = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }

Write-Host "==> Ensuring local-testing .env (Fernet, session, pepper, auth-web, VAPT, paths)"
& $Py .\scripts\ensure_env_secrets.py --local-testing

$composeArgs = $args
if (-not $composeArgs -or $composeArgs.Count -eq 0) {
    $composeArgs = @("-d", "--build")
}

Write-Host "==> docker compose up $($composeArgs -join ' ')"
docker compose up @composeArgs
Write-Host "Done. UI: http://127.0.0.1:8000  Health: http://127.0.0.1:8000/api/health"
