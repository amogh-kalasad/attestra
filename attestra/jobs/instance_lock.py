"""Cross-process lock so two workers do not claim the same job."""

from __future__ import annotations

import os
import time
from pathlib import Path

from attestra import config

# A running worker refreshes its lock file every ~30 s (see WorkerPool._heartbeat).
# The web page treats an older lock as "looks stale"; acquire() still only frees a
# lock whose process is gone, so a stale-looking lock never starts a second worker.
LOCK_REFRESH_STALE_S = 600

_STILL_ACTIVE = 259
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_ERROR_ACCESS_DENIED = 5


def pid_alive(pid: int) -> bool:
    """True when a process with ``pid`` exists.

    On Windows ``os.kill(pid, 0)`` is NOT a liveness check: signal 0 is CTRL_C_EVENT,
    so it either sends Ctrl+C to that console process group or fails. Use the Win32
    API there instead.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return ctypes.get_last_error() == _ERROR_ACCESS_DENIED
        try:
            code = wintypes.DWORD()
            if not k32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == _STILL_ACTIVE
        finally:
            k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def read_lock(path: Path) -> tuple[int | None, float | None]:
    """(pid, age in seconds) of a lock file, or (None, None) when there is none."""
    try:
        raw = path.read_text().strip()
        age = max(0.0, time.time() - path.stat().st_mtime)
    except OSError:
        return None, None
    try:
        return int(raw), age
    except ValueError:
        return None, age


class InstanceLock:
    def __init__(self, name: str = "worker"):
        config.ensure_dirs()
        self.path = config.DATA_DIR / f".lock-{name}"
        self._fh = None

    def acquire(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                self._fh = fd
                return True
            except FileExistsError:
                # Stale lock if holder is dead (an empty file younger than 5 s is a
                # lock that is still being written, so leave it alone).
                pid, age = read_lock(self.path)
                if pid is None and age is not None and age < 5:
                    pass
                elif pid is None or not pid_alive(pid):
                    try:
                        self.path.unlink(missing_ok=True)
                    except OSError:
                        pass
                time.sleep(0.1)
        return False

    def touch(self) -> None:
        """Refresh the lock file's mtime so the web page can tell the worker is alive."""
        try:
            os.utime(self.path, None)
        except OSError:
            pass

    def release(self) -> None:
        if self._fh is not None:
            try:
                os.close(self._fh)
            except OSError:
                pass
            self._fh = None
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass