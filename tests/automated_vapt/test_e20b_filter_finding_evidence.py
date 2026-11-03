"""E20b: technical report embeds only failed automated evidence."""
from __future__ import annotations

from types import SimpleNamespace

from attestra.reports.render import _filter_automated_vapt_evidence, _is_automated_vapt_evidence


def _ev(**kw):
    defaults = dict(
        id=1,
        kind="http_pair",
        note="",
        filename="http_pair.json",
        source_tool="",
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def test_is_automated_recognizes_legacy_elite_markers():
    assert _is_automated_vapt_evidence(
        _ev(note="proof: GET https://x/api/a'\nelite automated capture")
    )
    assert _is_automated_vapt_evidence(
        _ev(kind="screenshot", filename="elite_http_pair_17_two_panel.png", note="Two-panel")
    )
    assert _is_automated_vapt_evidence(_ev(source_tool="automated_vapt"))
    assert not _is_automated_vapt_evidence(_ev(note="manual screenshot", filename="shot.png"))


def test_filter_keeps_only_location_matching_pairs():
    loc = "https://demo.harmonypm.ai/api/projects/get-invite-stake-holders/'"
    items = [
        _ev(id=1, note="proof: GET https://demo.harmonypm.ai/api/other\nelite automated capture"),
        _ev(
            id=17,
            note="proof: GET https://demo.harmonypm.ai/api/projects/get-invite-stake-holders/'\nelite automated capture",
        ),
        _ev(
            id=18,
            kind="screenshot",
            filename="elite_http_pair_17_two_panel.png",
            note="Two-panel HTTP visual",
        ),
        _ev(
            id=2,
            note="proof: GET https://demo.harmonypm.ai/api/projects/get-invite-stake-holders/1\nelite automated capture",
        ),
        _ev(id=99, kind="screenshot", filename="manual.png", note="analyst", source_tool=""),
    ]
    # pad to >4 auto so filter activates
    for i in range(10, 16):
        items.append(
            _ev(id=i, note=f"proof: GET https://demo.harmonypm.ai/api/pad/{i}\nelite automated capture")
        )
    finding = SimpleNamespace(location=loc)
    kept = _filter_automated_vapt_evidence(finding, items)
    ids = {e.id for e in kept}
    assert 17 in ids
    assert 18 in ids
    assert 99 in ids  # non-automated kept
    assert 1 not in ids
    assert 2 not in ids
