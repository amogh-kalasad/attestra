# Attestra - Local Setup Guide (Windows)

Project location: `E:\attestra` (moved from Downloads because C: and D: are nearly full).

## 1. Requirements
- Python 3.11 or newer
- Free disk space on E: (keep venv, caches and temp on E:)

## 2. One-time setup
Open PowerShell:

```powershell
cd E:\attestra
$env:TEMP="E:\tmp"; $env:TMP="E:\tmp"; New-Item -ItemType Directory -Force E:\tmp | Out-Null
$env:PIP_CACHE_DIR="E:\attestra\.cache\pip"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

The database is stored at `E:\attestra\data\attestra.db`. See README.md for the `demo` command to load sample data.

## 3. Start the app

```powershell
cd E:\attestra
.\.venv\Scripts\attestra.exe serve --host 127.0.0.1 --port 8000
```

Then open:
- Dashboard: http://127.0.0.1:8000/
- API docs: http://127.0.0.1:8000/docs

## 4. Stop the app
Press `Ctrl+C` in the window running it, or:

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```

## 5. Run tests

```powershell
cd E:\attestra
.\.venv\Scripts\python.exe -m pytest -q
```

## 6. Troubleshooting
- "Port 8000 in use": stop the old process (step 4) or use `--port 8001`.
- Disk full errors during install: make sure TEMP/TMP and PIP_CACHE_DIR point to E: (step 2).
- Logs (when started in background): `E:\attestra\data\serve.out.log`, `serve.err.log`.
- `/metrics` returns 401: set `ATTESTRA_METRICS_TOKEN` for Prometheus scrapers (recommended). Do not leave metrics open on a public host; `ATTESTRA_METRICS_ALLOW_ANON=true` is only for trusted private networks.
