"""Associate Elite screenshots with engagement / execution / test case ids."""

from __future__ import annotations

from dataclasses import dataclass

from attestra.automated_vapt.capture.browser_capture import stable_screenshot_name

# @lat: [[architecture#Elite automated security testing#Evidence visuals]]


@dataclass
class ScreenshotRecord:
    engagement_id: int
    execution_id: int
    test_case_id: str
    finding_id: int | None
    filename: str
    png_bytes: bytes
    label: str = "viewport"


class ScreenshotManager:
    """In-memory registry of screenshots for one Elite execution."""

    def __init__(self) -> None:
        self._items: list[ScreenshotRecord] = []

    def add(
        self,
        *,
        engagement_id: int,
        execution_id: int,
        test_case_id: str,
        png_bytes: bytes,
        finding_id: int | None = None,
        label: str = "viewport",
    ) -> ScreenshotRecord:
        name = stable_screenshot_name(
            engagement_id=engagement_id,
            execution_id=execution_id,
            test_case_id=test_case_id,
            label=label,
        )
        rec = ScreenshotRecord(
            engagement_id=engagement_id,
            execution_id=execution_id,
            test_case_id=test_case_id,
            finding_id=finding_id,
            filename=name,
            png_bytes=png_bytes,
            label=label,
        )
        self._items.append(rec)
        return rec

    def list(self) -> list[ScreenshotRecord]:
        return list(self._items)
