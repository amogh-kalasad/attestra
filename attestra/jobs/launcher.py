"""Start and stop the scan worker from the web page (Start Worker / Stop Worker buttons).

``attestra serve`` only queues scans; ``attestra worker`` runs them. For local use the
engagement page can start the worker as a detached background process so nobody needs a
second terminal. Safety rules:

* Only when ``APP_ENV`` is local / test / development, or ``ATTESTRA_ALLOW_UI_WORKER_START``
  is true. Staging and production keep running the worker as a managed service.
* Never with the Temporal orchestrator (its worker does not use the instance lock).
* Never while a worker is alive: the worker instance lock (``DATA_DIR/.lock-worker``),
  fresh job heartbeats, or a start from this page in the last few seconds all count.
  Even if two clicks race, the second worker cannot take the instance lock and exits.
* Stop is graceful: it writes ``DATA_DIR/.worker-stop``; the worker sees it within a
  couple of seconds, stops running scanners, puts those scans back in the queue and exits.

The worker's output goes to ``DATA_DIR/worker.log``. The worker loads ``.env`` itself.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from attestra import config
from attestra.jobs.instance_lock import LOCK_REFRESH_STALE_S, pid_alive, read_lock

UI_START_ENVS = frozenset({"local", "test", "development"})
ALLOW_FLAG = "ATTESTRA_ALLOW_UI_WORKER_START"
START_GRACE_S = 30.0
_TRUE = frozenset({"1", "true", "yes", "on"})
_start_lock = threading.Lock()

# Windows process creation flags (constants exist only on Windows builds of subprocess).
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000


class WorkerControlError(Exception):
    """A start/stop request was refused; the message is shown on the page."""


def lock_path() -> Path:
    return config.DATA_DIR / ".lock-worker"


def stop_path() -> Path:
    return config.DATA_DIR / ".worker-stop"


def marker_path() -> Path:
    return config.DATA_DIR / ".worker-ui.json"


def log_path() -> Path:
    return config.DATA_DIR / "worker.log"


def ui_control_allowed() -> tuple[bool, str]:
    """(allowed, reason when not) for the Start Worker / Stop Worker buttons."""
    flag = os.environ.get(ALLOW_FLAG, "").strip().lower() in _TRUE
    try:
        env = config.parse_app_env()
    except ValueError:
        env = None
    if env not in UI_START_ENVS and not flag:
        return False, (
            f"Starting the worker from the web page is off for APP_ENV={env or 'unset'}. "
            f"Run `attestra worker` on the server, or set {ALLOW_FLAG}=true."
        )
    try:
        from attestra.orchestration import orchestrator

        if orchestrator() == "temporal":
            return False, "The Temporal orchestrator is on; start its worker with `attestra worker`."
    except ValueError as exc:
        return False, str(exc)
    return True, ""


@dataclass
class WorkerStatus:
    running: bool = False
    pid: int | None = None
    via: str = ""  # "lock" | "heartbeat"
    starting: bool = False
    stale_lock: bool = False
    last_start_exited: bool = False
    stop_requested: bool = False
    log: str = ""


def _read_marker() -> dict:
    try:
        return json.loads(marker_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _fresh_heartbeats(s) -> int:
    from sqlalchemy import func, select

    from attestra.models import Job, utcnow

    cutoff = utcnow() - timedelta(seconds=config.JOB_STALE_HEARTBEAT_S)
    q = select(func.count()).select_from(Job).where(Job.status == "running", Job.heartbeat_at >= cutoff)
    return int(s.scalar(q) or 0)


def worker_status(s=None) -> WorkerStatus:
    """Is a scan worker alive? Lock file first, then fresh job heartbeats (needs ``s``)."""
    st = WorkerStatus(log=str(log_path()))
    st.stop_requested = stop_path().exists()
    pid, age = read_lock(lock_path())
    if pid is not None and pid_alive(pid):
        # The lock holder is alive, so a new worker could not take the lock anyway.
        # A lock that is not being refreshed is a worker from before this update, or
        # (rarely) a reused PID: still "running", with a hint on the page.
        st.running, st.pid, st.via = True, pid, "lock"
        st.stale_lock = age is not None and age > LOCK_REFRESH_STALE_S
        return st
    if s is not None:
        try:
            if _fresh_heartbeats(s):
                st.running, st.via = True, "heartbeat"
                return st
        except Exception:  # noqa: BLE001 - status must never break the page
            pass
    marker = _read_marker()
    mpid = marker.get("pid")
    if mpid:
        alive = pid_alive(mpid)
        recent = time.time() - float(marker.get("started_at") or 0) < START_GRACE_S
        if alive and recent:
            st.starting, st.pid = True, int(mpid)
        elif not alive:
            st.last_start_exited = True
    return st


def worker_command() -> list[str]:
    """Same interpreter / venv as ``attestra serve``; the CLI loads .env on import."""
    return [sys.executable, "-c", "import sys; from attestra.cli import main; main(sys.argv[1:])", "worker"]


def _popen_kwargs(log_fh) -> dict:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("ATTESTRA_DATA_DIR", str(config.DATA_DIR))
    kw: dict = {
        "cwd": os.getcwd(),
        "env": env,
        "stdin": subprocess.DEVNULL,
        "stdout": log_fh,
        "stderr": subprocess.STDOUT,
        "close_fds": True,
    }
    if os.name == "nt":
        # Own (hidden) console and process group: Ctrl+C or closing the serve window
        # does not stop it, and docker.exe children do not pop up console windows.
        kw["creationflags"] = CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    else:
        kw["start_new_session"] = True
    return kw


def start_worker(*, actor: str = "ui", s=None) -> int:
    """Spawn ``attestra worker`` in the background. Returns its PID.

    Raises WorkerControlError when not allowed or a worker is already running/starting.
    """
    allowed, why = ui_control_allowed()
    if not allowed:
        raise WorkerControlError(why)
    with _start_lock:
        st = worker_status(s)
        if st.running:
            who = f" (PID {st.pid})" if st.pid else ""
            raise WorkerControlError(f"A worker is already running{who}. Queued scans are picked up automatically.")
        if st.starting:
            raise WorkerControlError(f"The worker is already starting (PID {st.pid}). Refresh in a few seconds.")
        config.ensure_dirs()
        try:
            stop_path().unlink(missing_ok=True)
        except OSError:
            pass
        log = log_path()
        log.parent.mkdir(parents=True, exist_ok=True)
        cmd = worker_command()
        with open(log, "ab") as fh:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S %z")
            fh.write(f"\n===== {stamp} worker started from the web page by {actor} =====\n".encode())
            fh.flush()
            proc = subprocess.Popen(cmd, **_popen_kwargs(fh))
        try:
            marker_path().write_text(
                json.dumps({"pid": proc.pid, "started_at": time.time(), "by": actor, "log": str(log)}),
                encoding="utf-8",
            )
        except OSError:
            pass
        return proc.pid


def stop_worker(*, actor: str = "ui", s=None) -> WorkerStatus:
    """Ask the running worker to stop gracefully (scans in progress go back to the queue)."""
    allowed, why = ui_control_allowed()
    if not allowed:
        raise WorkerControlError(why)
    st = worker_status(s)
    if not st.running and not st.starting:
        raise WorkerControlError("No worker is running.")
    config.ensure_dirs()
    stop_path().write_text(f"{actor} {time.time()}\n", encoding="utf-8")
    return st