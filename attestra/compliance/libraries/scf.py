"""Import the Secure Controls Framework (SCF) CSV export as a framework pack.

SCF ships crosswalk columns to other frameworks (for example "PCI DSS v4.0.1",
"ISO 27001 v2022", "AICPA TSC 2017"). We use them to tie each SCF control to the
hub objectives that already carry those framework refs, so no hand mapping is
needed. An optional objective map YAML ``{objective: [SCF #, ...]}`` adds to it.
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path

from attestra.compliance.libraries.common import (
    ImportedLibrary,
    check_framework_key,
    clean,
    hub_objectives,
    load_objective_map,
)

ID_COLUMNS = ("SCF #", "SCF#", "SCF Control #", "Control ID", "ID")
TITLE_COLUMNS = ("SCF Control", "Control", "Control Name", "Title")
# hub framework key -> header fragments that identify its SCF crosswalk column
CROSSWALK_HINTS = {
    "pci_dss_4": ("pci dss v4", "pci dss 4"),
    "iso_27001_2022": ("iso 27001 v2022", "iso 27001:2022", "iso 27001 2022", "iso/iec 27001 2022"),
    "soc2": ("aicpa tsc", "soc 2", "soc2"),
    "nist_csf_2": ("nist csf v2", "nist csf 2"),
}
_SPLIT = re.compile(r"[\n;,]+")


def _pick(headers: list[str], options: tuple[str, ...]) -> str | None:
    norm = {h.strip().lower(): h for h in headers}
    for opt in options:
        if opt.lower() in norm:
            return norm[opt.lower()]
    return None


def _crosswalk_columns(headers: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for fw, hints in CROSSWALK_HINTS.items():
        for h in headers:
            if any(hint in h.strip().lower() for hint in hints):
                out[fw] = h
                break
    return out


def _candidates(fw: str, ref: str) -> list[str]:
    """Spellings a crosswalk cell may use for a hub ref (lower-cased)."""
    ref = " ".join(ref.split())
    if fw != "iso_27001_2022":
        return [ref.lower()]
    m = re.match(r"^(?:annex\s*)?a\s*\.?\s*(\d+(?:\.\d+)+)$", ref, re.I)
    if m:
        return [f"a.{m.group(1)}"]
    m = re.match(r"^(?:clause\s*)?(\d+(?:\.\d+)*)$", ref, re.I)
    if m:  # bare "8.24" or "6.1.2": could be Annex A or a clause
        return [f"a.{m.group(1)}", f"clause {m.group(1)}"]
    return [ref.lower()]


def _hub_index(objectives: dict) -> dict[tuple[str, str], set[str]]:
    idx: dict[tuple[str, str], set[str]] = {}
    for key, obj in objectives.items():
        for fw, refs in (obj.get("controls") or {}).items():
            for ref in refs:
                idx.setdefault((fw, " ".join(str(ref).split()).lower()), set()).add(key)
    return idx


def import_scf_csv(
    data: bytes | str,
    framework: str = "scf",
    name: str | None = None,
    objective_map: dict[str, list[str]] | Path | None = None,
) -> ImportedLibrary:
    check_framework_key(framework)
    text = data.decode("utf-8-sig") if isinstance(data, bytes) else data.lstrip("\ufeff")
    reader = csv.DictReader(io.StringIO(text))
    headers = list(reader.fieldnames or [])
    id_col = _pick(headers, ID_COLUMNS)
    title_col = _pick(headers, TITLE_COLUMNS)
    if not id_col or not title_col:
        raise ValueError("SCF CSV needs an 'SCF #' and an 'SCF Control' column")
    cross = _crosswalk_columns(headers)
    objectives = hub_objectives()
    idx = _hub_index(objectives)
    omap = objective_map if isinstance(objective_map, dict) else load_objective_map(objective_map)
    for obj in omap:
        if obj not in objectives:
            raise ValueError(f"objective map: unknown objective {obj!r}")
    by_control: dict[str, set[str]] = {}
    for obj, ids in omap.items():
        for cid in ids:
            by_control.setdefault(cid.strip().upper(), set()).add(obj)

    lib = ImportedLibrary(framework=framework, name=name or "Secure Controls Framework", source="SCF CSV")
    for row in reader:
        ref = (row.get(id_col) or "").strip()
        if not ref:
            continue
        lib.titles[ref] = clean(row.get(title_col) or ref)
        objs = set(by_control.get(ref.upper(), set()))
        for fw, col in cross.items():
            for part in _SPLIT.split(row.get(col) or ""):
                if part.strip():
                    for cand in _candidates(fw, part):
                        objs |= idx.get((fw, cand), set())
        if objs:
            for obj in sorted(objs):
                lib.add(obj, ref)
        else:
            lib.unmapped.append(ref)
    if not lib.titles:
        raise ValueError("SCF CSV has no control rows")
    return lib
