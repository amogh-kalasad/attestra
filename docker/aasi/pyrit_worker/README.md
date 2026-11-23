# attestra_pyrit_worker

Thin CLI used by `PyRITAdapter` inside an isolated container.

- Reads `pyrit-run.json` written by Attestra.
- Runs an allowlisted scenario against the authorized HTTP target.
- Writes `pyrit-results.json` for `attestra.importers.pyrit`.

Full multi-turn PyRIT engines stay in the **microsoft/PyRIT** dependency installed
in the image. This module does not expose unrestricted shell or free-form argv.
