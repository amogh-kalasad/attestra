"""Checklist catalog v2 and mapping integrity (FND-05).

Pure data + validator. ``data/checklist_catalog.yaml`` holds stable WSTG v4.2 /
ASVS 4.0.3 refs, their automation level, aliases (``WSTG-INPV-19`` carries the
legacy ``WSTG-BUSL-09`` SSRF alias) and every mapping from automated test ids and
scanner rules to refs. ``auth_web/checklists.py`` and ``auth_web/checklist_auto.py``
(INT) derive their module-level tables from :func:`load_catalog` so nothing is
maintained twice, and :func:`validate_catalog` makes CI fail on orphan refs,
unmapped automated tests, automated->manual mappings without an exception, and
duplicate ids. No checklist row is ever deleted.
"""

# @lat: [[run-validity-and-policy#Checklist catalog]]

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

CATALOG_PATH = Path(__file__).resolve().parent / "data" / "checklist_catalog.yaml"
AUTOMATION_LEVELS = ("automated", "partial", "manual", "n/a")
LEGACY_SSRF_REF = "WSTG-BUSL-09"
SSRF_REF = "WSTG-INPV-19"


@dataclass(frozen=True)
class CatalogItem:
    ref: str
    title: str
    standard: str
    domain: str
    automation: str
    applicability: str = ""
    aliases: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class Catalog:
    version: str
    items: tuple[CatalogItem, ...]
    automated: dict[str, tuple[str, ...]]
    zap: dict[str, dict[str, tuple[str, ...]]]
    nuclei: tuple[tuple[str, str, str | None], ...]
    webcheck: dict[str, tuple[str, ...]]
    testssl: str
    exception_test_ids: dict[str, str] = field(default_factory=dict)
    exception_manual_targets: dict[str, str] = field(default_factory=dict)

    def item(self, ref: str) -> CatalogItem | None:
        for it in self.items:
            if it.ref == ref:
                return it
        return None

    @property
    def refs(self) -> tuple[str, ...]:
        return tuple(it.ref for it in self.items)

    def resolve(self, ref_or_alias: str) -> str | None:
        """Canonical ref for a ref or alias (``WSTG-BUSL-09-legacy-ssrf`` -> ``WSTG-INPV-19``)."""
        for it in self.items:
            if ref_or_alias == it.ref or ref_or_alias in it.aliases:
                return it.ref
        return None


def _parse(raw: dict[str, Any]) -> Catalog:
    items = tuple(
        CatalogItem(
            ref=str(d["ref"]),
            title=str(d.get("title") or ""),
            standard=str(d.get("standard") or ""),
            domain=str(d.get("domain") or ""),
            automation=str(d.get("automation") or "manual"),
            applicability=str(d.get("applicability") or ""),
            aliases=tuple(str(a) for a in (d.get("aliases") or ())),
            note=str(d.get("note") or ""),
        )
        for d in (raw.get("items") or [])
    )
    m = raw.get("mappings") or {}
    exc = raw.get("exceptions") or {}
    return Catalog(
        version=str(raw.get("catalog_version") or ""),
        items=items,
        automated={str(k): tuple(str(r) for r in (v or ())) for k, v in (m.get("automated") or {}).items()},
        zap={
            str(ref): {str(k): tuple(str(x) for x in (v or ())) for k, v in (spec or {}).items()}
            for ref, spec in (m.get("zap") or {}).items()
        },
        nuclei=tuple(
            (str(n["ref"]), str(n["pattern"]), (str(n["exclude"]) if n.get("exclude") else None))
            for n in (m.get("nuclei") or [])
        ),
        webcheck={str(k): tuple(str(x) for x in (v or ())) for k, v in (m.get("webcheck") or {}).items()},
        testssl=str(m.get("testssl") or ""),
        exception_test_ids={str(k): str(v) for k, v in ((exc.get("test_ids") or {}).items())},
        exception_manual_targets={str(k): str(v) for k, v in ((exc.get("manual_targets") or {}).items())},
    )


def load_catalog(path: Path | str | None = None) -> Catalog:
    """Load and parse a catalog file (cached for the default path)."""
    if path is None:
        return _default_catalog()
    return _parse(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})


@lru_cache(maxsize=1)
def _default_catalog() -> Catalog:
    return _parse(yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8")) or {})


def catalog_version() -> str:
    return load_catalog().version


# ------------------------------------------------------------------ derived views (INT consumes these)


def default_items(cat: Catalog | None = None) -> tuple[tuple[str, str, str], ...]:
    """``(ref, title, mapping_version)`` rows like ``checklists.DEFAULT_CHECKLIST``."""
    c = cat or load_catalog()
    return tuple((it.ref, it.title, it.standard) for it in c.items)


def automated_map(cat: Catalog | None = None) -> dict[str, tuple[str, ...]]:
    return dict((cat or load_catalog()).automated)


def zap_map(cat: Catalog | None = None) -> dict[str, dict[str, tuple[str, ...]]]:
    return {k: dict(v) for k, v in (cat or load_catalog()).zap.items()}


def nuclei_map(cat: Catalog | None = None) -> tuple[tuple[str, re.Pattern[str], re.Pattern[str] | None], ...]:
    c = cat or load_catalog()
    return tuple((ref, re.compile(p), re.compile(x) if x else None) for ref, p, x in c.nuclei)


def webcheck_map(cat: Catalog | None = None) -> dict[str, tuple[str, ...]]:
    return dict((cat or load_catalog()).webcheck)


def testssl_ref(cat: Catalog | None = None) -> str:
    return (cat or load_catalog()).testssl


def manual_only(cat: Catalog | None = None) -> tuple[str, ...]:
    """Refs whose automation level is ``manual`` (never set by automation)."""
    return tuple(it.ref for it in (cat or load_catalog()).items if it.automation == "manual")


def legacy_mirror_targets(ref: str, cat: Catalog | None = None) -> tuple[str, ...]:
    """Refs a verdict on ``ref`` must also be mirrored to (legacy BUSL-09 SSRF -> INPV-19)."""
    if ref == LEGACY_SSRF_REF:
        return (SSRF_REF,)
    return ()


# ------------------------------------------------------------------ validation


@dataclass(frozen=True)
class Problem:
    kind: str  # duplicate_ref | duplicate_alias | bad_automation | orphan_ref | manual_target | unmapped_test | ssrf_legacy | bad_regex | missing_version
    subject: str
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.kind}: {self.subject}" + (f" ({self.detail})" if self.detail else "")


def validate_catalog(cat: Catalog | None = None, *, registry_ids: list[str] | tuple[str, ...] | None = None) -> list[Problem]:
    """Integrity problems; an empty list means the catalog is consistent.

    ``registry_ids`` defaults to every id in ``automated_vapt.core.test_registry``.
    """
    c = cat or load_catalog()
    out: list[Problem] = []
    if not c.version:
        out.append(Problem("missing_version", "catalog_version"))
    seen: set[str] = set()
    aliases: set[str] = set()
    for it in c.items:
        if it.ref in seen:
            out.append(Problem("duplicate_ref", it.ref))
        seen.add(it.ref)
        if it.automation not in AUTOMATION_LEVELS:
            out.append(Problem("bad_automation", it.ref, it.automation))
        for a in it.aliases:
            if a in aliases or a in seen:
                out.append(Problem("duplicate_alias", a, it.ref))
            aliases.add(a)
    refs = set(c.refs)

    def _check_ref(ref: str, where: str, *, automated_source: bool) -> None:
        if ref not in refs:
            out.append(Problem("orphan_ref", ref, where))
            return
        it = c.item(ref)
        if automated_source and it is not None and it.automation == "manual" and ref not in c.exception_manual_targets:
            out.append(Problem("manual_target", ref, where))

    for tid, rs in sorted(c.automated.items()):
        if not rs:
            out.append(Problem("unmapped_test", tid, "empty mapping"))
        for r in rs:
            _check_ref(r, f"automated:{tid}", automated_source=True)
        if tid == "SSRF" and LEGACY_SSRF_REF in rs:
            out.append(Problem("ssrf_legacy", tid, "SSRF must map to WSTG-INPV-19, never WSTG-BUSL-09"))
    for ref in sorted(c.zap):
        _check_ref(ref, "zap", automated_source=True)
        if ref == LEGACY_SSRF_REF and "40046" in c.zap[ref].get("rules", ()):
            out.append(Problem("ssrf_legacy", "zap:40046"))
    for ref, pat, exc in c.nuclei:
        _check_ref(ref, "nuclei", automated_source=True)
        for rx in (pat, exc):
            if rx:
                try:
                    re.compile(rx)
                except re.error as e:
                    out.append(Problem("bad_regex", ref, str(e)))
        if ref == LEGACY_SSRF_REF and "ssrf" in pat:
            out.append(Problem("ssrf_legacy", "nuclei:ssrf"))
    for ref in sorted(c.webcheck):
        _check_ref(ref, "webcheck", automated_source=True)
    if c.testssl:
        _check_ref(c.testssl, "testssl", automated_source=True)
    for ref in sorted(c.exception_manual_targets):
        if ref not in refs:
            out.append(Problem("orphan_ref", ref, "exceptions.manual_targets"))

    if registry_ids is None:
        try:
            from attestra.automated_vapt.core.test_registry import list_test_cases

            registry_ids = [tc.id for tc in list_test_cases()]
        except Exception:  # pragma: no cover
            registry_ids = []
    for tid in sorted(set(registry_ids or ())):
        if tid not in c.automated and tid not in c.exception_test_ids:
            out.append(Problem("unmapped_test", tid, "registered test id has no checklist mapping or exception"))
    return out


def audit_unmapped(test_ids: list[str] | tuple[str, ...], cat: Catalog | None = None) -> list[dict[str, str]]:
    """Value-free ``checklist_audit`` rows for ids that would otherwise be dropped silently."""
    c = cat or load_catalog()
    rows: list[dict[str, str]] = []
    for tid in test_ids:
        if tid in c.automated:
            for ref in c.automated[tid]:
                if ref not in c.refs:
                    rows.append({"test_id": tid, "ref": ref, "kind": "orphan"})
        elif tid not in c.exception_test_ids:
            rows.append({"test_id": tid, "ref": "", "kind": "unmapped"})
    return rows
