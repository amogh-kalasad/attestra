# Release steps

Releases are cut by the project owner. Tagging and pushing are manual.

1. **Branch clean:** `main` is up to date and GitHub Actions is green.
2. **Version:** `version` in `pyproject.toml` and `__version__` in `attestra/__init__.py` match (now `1.0.0`).
   `GET /api/health` reports the same version.
3. **Changelog:** move the `[x.y.z] - unreleased` heading in `CHANGELOG.md` to the release date.
4. **Checks locally:**
   - `.\.venv\Scripts\python.exe -m ruff check .`
   - `.\.venv\Scripts\python.exe -m pytest -q` (set `ATTESTRA_TEST_POSTGRES_URL` to include the Postgres tests)
   - `alembic upgrade head` on a fresh Postgres 16 ends at `0027_finding_observations_rls` (see `docs/MASTER_IMPL_PHASE10_MIGRATIONS.md`).
5. **Load test:** run `deploy/loadtest/attestra.js` against staging and update `docs/LOAD_TEST.md`.
6. **Security:** no open critical/high from the external pentest (Step 8.1); dependency licences reviewed (`docs/LICENSES.md`).
7. **Build:** build the container image and `helm lint deploy/helm/...`; record image digests.
8. **Commit:** `Release x.y.z` via GitHub Desktop and push.
9. **Tag:** create tag `vx.y.z` on GitHub (Releases > Draft a new release), paste the changelog section, publish.
10. **After:** bump to the next dev version if wanted, and add a new `unreleased` section to the changelog.

## Rollback
- Redeploy the previous image/Helm release (`helm rollback`).
- Migrations are forward-only in production: restore from the backup taken before the upgrade (`attestra restore`).
