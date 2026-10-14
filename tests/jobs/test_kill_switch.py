"""Tests for the kill switch (cancel Event) — process terminates within deadline."""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

from attestra.runner.scanners.base import run_process


def _sleep_script(tmp_path: Path) -> Path:
    """Write a sleeper without shell metacharacters (assert_safe_cli_arg forbids ';')."""
    path = tmp_path / "sleeper.py"
    path.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    return path


def test_cancel_event_terminates_process(tmp_path):
    """run_process with a long-sleeping process and a set cancel Event finishes < 5 s."""
    script = _sleep_script(tmp_path)
    cancel = threading.Event()
    result_box: list = []

    def _run():
        result_box.append(
            run_process([sys.executable, str(script)], cancel=cancel, timeout=120)
        )

    t = threading.Thread(target=_run, daemon=True)
    started = time.monotonic()
    t.start()
    time.sleep(0.3)
    cancel.set()
    t.join(timeout=5)
    elapsed = time.monotonic() - started
    assert not t.is_alive(), "process should have been killed"
    assert elapsed < 5, f"took too long: {elapsed:.2f}s"
    assert result_box and result_box[0].cancelled is True


def test_cancel_result_has_cancelled_flag(tmp_path):
    script = _sleep_script(tmp_path)
    cancel = threading.Event()
    cancel.set()
    result = run_process([sys.executable, str(script)], cancel=cancel, timeout=120)
    assert result.cancelled is True
