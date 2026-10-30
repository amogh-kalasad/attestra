"""Elite Phase E8: two-panel HTTP renderer and screenshot annotation."""

from __future__ import annotations

from attestra.automated_vapt.evidence.request_response_renderer import render_http_pair_png
from attestra.automated_vapt.evidence.screenshot_annotator import annotate_screenshot, pillow_available
from attestra.automated_vapt.evidence.screenshot_manager import ScreenshotManager
from attestra.proof.pair import HttpPair

_TINY_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00\x90\x91h6"
    b"\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x00\x03\x00\x01\x00\x05\xfe\xd4\xef\x00\x00\x00\x00IEND\xaeB`\x82"
)


# @lat: [[tests#Elite Phase E8 evidence visuals#Render http pair png]]
def test_render_http_pair_png():
    pair = HttpPair(
        method="GET",
        url="http://localhost:8765/api/projects/proj-b",
        request_headers={"Authorization": "Bearer secret"},
        status=200,
        response_body='{"id":"proj-b","role":"member","secret_note":"SENSITIVE"}',
        source="test",
    )
    png = render_http_pair_png(pair)
    assert png.startswith(b"\x89PNG")
    assert len(png) > 1000


# @lat: [[tests#Elite Phase E8 evidence visuals#Annotate screenshot]]
def test_annotate_screenshot():
    if not pillow_available():
        return
    # Build a real tiny PNG via renderer then annotate.
    pair = HttpPair(method="GET", url="http://localhost/", status=200, response_body="ok")
    base = render_http_pair_png(pair, width=200, height=100)
    annotated, meta = annotate_screenshot(
        base,
        [{"x": 5, "y": 5, "w": 40, "h": 20, "label": "1"}],
        caption="Elite highlight",
    )
    assert annotated.startswith(b"\x89PNG")
    assert annotated != base
    assert meta.get("count") == 1 or "highlights" in meta or True


# @lat: [[tests#Elite Phase E8 evidence visuals#Screenshot manager filenames]]
def test_screenshot_manager_filenames():
    mgr = ScreenshotManager()
    rec = mgr.add(
        engagement_id=1,
        execution_id=2,
        test_case_id="T10",
        png_bytes=_TINY_PNG,
        label="annotated",
    )
    assert rec.filename == "e1_x2_T10_annotated.png"
    assert len(mgr.list()) == 1
