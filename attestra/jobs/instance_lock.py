"""Cross-process lock so two workers do not claim the same job."""

from __future__ import annotations

import os
import time

from attestra import config


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
                # Stale lock if holder is dead
                try:
                    pid = int(self.path.read_text().strip())
                    os.kill(pid, 0)
                except (ValueError, OSError, ProcessLookupError):
                    try:
                        self.path.unlink(missing_ok=True)
                    except OSError:
                        pass
                time.sleep(0.1)
        return False

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
