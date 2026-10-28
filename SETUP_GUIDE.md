# Attestra - Local Setup Guide (Windows)

All commands are run from the repo folder (the folder that holds `pyproject.toml`).

## 1. Requirements
- Python 3.11 or newer
- Git
- Docker Desktop, for the in-app scanners that run in containers (ZAP, testssl, Nuclei and others)
- Enough free disk space for the venv, scanner images and caches

## 2. One-time setup
Open PowerShell in the repo folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"          # or: pip install -r requirements.txt
python -m attestra.cli init      # create the database
```

If your system drive is low on space, point the temp and pip cache folders to another drive first, for example `$env:TEMP="D:\tmp"; $env:TMP="D:\tmp"; $env:PIP_CACHE_DIR="D:\pip-cache"`.

The database is stored at `data\attestra.db` inside the repo folder. Set `ATTESTRA_DATA_DIR` to keep it somewhere else.

Optional environment template: copy `.env.example` and set values in the shell (or a process manager). `SUBSCRIPTION_SERVICE`, `SIGNED_AUTHORIZATION`, and `OWNERSHIP_VERIFICATION` must each be `ON` or `OFF` (default `ON` when unset). Invalid values stop `init` / `serve` / `worker` at startup. Restart the API and any workers after changing them. New organizations receive `ATTESTRA_INITIAL_TEST_RUN_CREDITS` (default 3). On Postgres, migrate to head including `0023_subscription_credits`.

Optional: load sample data with `python -m attestra.cli demo`.

## 3. Create your first user

```powershell
python -m attestra.cli user add <username> --role admin --password <password>
```

Passwords must be at least 12 characters long and use at least 4 different characters. To change a password later, run `python -m attestra.cli user set-password <username>`.

Run these commands from the same folder as the app, or with the same `ATTESTRA_DATA_DIR`. Otherwise they change a different database.

## 4. Set the scanner images (only for in-app scans)
Each scanner image must be pinned by digest. Set one variable per tool you use before starting the app, for example:

```powershell
$env:ATTESTRA_IMAGE_ZAP = "ghcr.io/zaproxy/zaproxy@sha256:<digest>"
$env:ATTESTRA_IMAGE_TESTSSL = "docker.io/drwetter/testssl.sh@sha256:<digest>"
$env:ATTESTRA_HSTS_PRELOAD_LOOKUP = "1"     # optional: check the HSTS preload list
```

The built-in values are placeholders, so a scanner without a real image won't run.

You can also queue a scan from the CLI (same permission gate as the UI):

```powershell
python -m attestra.cli --user <username> scan <engagement_id> <asset_id> --tool zap --profile baseline
```

`--profile` is `baseline`, `active`, or `intrusive`.

## 5. Start the app
Window 1 (the web app):

```powershell
.\.venv\Scripts\Activate.ps1
python -m attestra.cli serve --host 127.0.0.1 --port 8000
```

Window 2 (the worker that runs queued scans):

```powershell
.\.venv\Scripts\Activate.ps1
python -m attestra.cli worker
```

Then open (after sign-in):
- Home: http://127.0.0.1:8000/
- Metrics dashboard: http://127.0.0.1:8000/dashboard
- Sites (grades): http://127.0.0.1:8000/sites
- Client / auditor portal: http://127.0.0.1:8000/portal
- API docs: http://127.0.0.1:8000/docs

Keep both windows open while you use the app. Scans stay "Queued" if the worker is not running.

## 6. Optional: authenticated website testing

Off by default. Full notes: [docs/AUTH_WEB_TESTING.md](docs/AUTH_WEB_TESTING.md).

```powershell
$env:ATTESTRA_AUTH_WEB_ENABLED = "1"
# Production / shared installs: set a Fernet key (do not commit it)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:ATTESTRA_CREDENTIAL_FERNET_KEY = "<paste-key-here>"
# Local/dev only when you have no Fernet key yet:
# $env:ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL = "1"
```

Restart the app and worker after changing these. `cryptography` is already in `requirements.txt`.

## 7. Optional: PostgreSQL

SQLite under `data\attestra.db` is fine for local use. For Postgres:

```powershell
pip install -e ".[postgres]"
$env:ATTESTRA_DATABASE_URL = "postgresql+psycopg://user:pass@127.0.0.1:5432/attestra"
python -m attestra.cli init
# Or apply migrations explicitly:
.\.venv\Scripts\alembic.exe upgrade head
```

Migration `0022_auth_web` creates the authenticated-website tables (`auth_credential_profiles`, route/element inventory, checklist). Bring Postgres to head before enabling auth-web there.

## 8. Stop the app
Press `Ctrl+C` in each window, or:

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```

## 9. Run tests

```powershell
python -m pytest -q
ruff check .
```

## 10. Troubleshooting
- "Port 8000 in use": another copy of Attestra may still be running. Stop it (step 8) or use `--port 8001`. Run only one copy on a port at a time.
- "invalid choice: 'set-password'" (or another missing command): the `attestra.exe` in the venv is out of date. Use `python -m attestra.cli ...`, or run `pip install -e .` again.
- "Invalid password" at sign-in after changing it: the password was saved to a different database. Run the command from the app's folder, or set `ATTESTRA_DATA_DIR` to the app's data folder.
- Scans stay Queued: start the worker (step 5) and make sure Docker is running.
- A scanner says its image is not set: set `ATTESTRA_IMAGE_<TOOL>` (step 4) and restart the app and worker.
- Disk full during install: move TEMP, TMP and PIP_CACHE_DIR to a drive with space (step 2).
- `/metrics` returns 401: set `ATTESTRA_METRICS_TOKEN` for Prometheus scrapers. Don't leave metrics open on a public host. `ATTESTRA_METRICS_ALLOW_ANON=true` is only for trusted private networks.
- Auth-web refuses or credential store errors: confirm `ATTESTRA_AUTH_WEB_ENABLED` and either `ATTESTRA_CREDENTIAL_FERNET_KEY` or (dev only) `ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL=1`. On Postgres, confirm Alembic is at head including `0022_auth_web`.
