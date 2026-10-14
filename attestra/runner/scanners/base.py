"""Process runner and scanner adapter base."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from attestra import config
from attestra.runner.authorization import assert_safe_cli_arg
from attestra.runner.dns_pin import PinnedTarget


@dataclass
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    cancelled: bool = False


@dataclass
class ScannerResult:
    tool: str
    tool_version: str = ""
    image_digest: str = ""
    raw_path: Path | None = None
    raw_sha256: str = ""
    quarantine: bool = False
    quarantine_reason: str = ""
    import_tool: str = ""  # tool name for services.import_results (e.g. sarif for semgrep)
    extra: dict = field(default_factory=dict)


def which(name: str) -> str | None:
    return shutil.which(name)


def docker_available() -> bool:
    return which("docker") is not None


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Best-effort kill of the process and its children (Windows + POSIX)."""
    if proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                check=False,
            )
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_process(
    argv: list[str],
    *,
    timeout: float | None = None,
    cancel: threading.Event | None = None,
    cwd: str | Path | None = None,
    env: dict | None = None,
) -> ProcessResult:
    """Run argv without a shell; kill the process tree on timeout or cancel."""
    for a in argv:
        assert_safe_cli_arg(a)
    timeout = timeout if timeout is not None else config.SCANNER_TIMEOUT_S
    kwargs: dict = {
        "args": argv,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "cwd": str(cwd) if cwd else None,
        "env": env,
    }
    if sys.platform != "win32":
        kwargs["start_new_session"] = True
    else:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    proc = subprocess.Popen(**kwargs)
    deadline = time.monotonic() + timeout
    cancelled = timed_out = False
    while proc.poll() is None:
        if cancel is not None and cancel.is_set():
            cancelled = True
            _kill_process_tree(proc)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            _kill_process_tree(proc)
            break
        time.sleep(0.5)
    try:
        stdout, stderr = proc.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        _kill_process_tree(proc)
        stdout, stderr = proc.communicate(timeout=2)
    return ProcessResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout or b"",
        stderr=stderr or b"",
        timed_out=timed_out,
        cancelled=cancelled,
    )


class ScannerAdapter(ABC):
    name: str
    import_tool: str  # zap|nuclei|trivy|sarif

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def version(self) -> str: ...

    @abstractmethod
    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]: ...

    def resolve_output(self, out_file: Path) -> Path:
        """Where the tool actually wrote its report (some tools add their own suffix)."""
        return out_file

    def scan(
        self,
        pin: PinnedTarget | str,
        *,
        out_dir: Path,
        cancel: threading.Event | None = None,
        profile: str = "baseline",
    ) -> ScannerResult:
        config.ensure_dirs()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{self.name}-out.json"
        argv = self.build_argv(pin, out_file=out_file, profile=profile)
        result = run_process(argv, cancel=cancel)
        if result.cancelled or result.timed_out:
            return ScannerResult(
                tool=self.name,
                tool_version=self.version(),
                quarantine=False,
                extra={"cancelled": result.cancelled, "timed_out": result.timed_out, "stderr": result.stderr[-2000:]},
            )
        out_file = self.resolve_output(out_file)
        raw = out_file.read_bytes() if out_file.exists() else result.stdout
        if not out_file.exists():
            out_file.write_bytes(raw)
        return ScannerResult(
            tool=self.name,
            tool_version=self.version(),
            raw_path=out_file,
            import_tool=self.import_tool,
            extra={"returncode": result.returncode, "stderr": result.stderr[-2000:]},
        )


def require_digest_image(image: str) -> str:
    return config.require_image_digest(image)
