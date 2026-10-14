"""Import a NIST OSCAL catalog (JSON) as a framework pack.

OSCAL catalogs carry no link to Attestra's hub objectives, so mappings come from:
1. an objective map YAML ``{objective: [control id, ...]}`` passed by the caller, and/or
2. a control prop ``{"name": "attestra-objective", "value": "<objective>"}``.
Controls without a mapping are still listed as titles but are reported as unmapped.
"""

from __future__ import annotations

import json
from pathlib import Path

from attestra.compliance.libraries.common import (
    ImportedLibrary,
    check_framework_key,
    clean,
    hub_objectives,
    load_objective_map,
)

OBJECTIVE_PROP = "attestra-objective"


def _label(control: dict) -> str:
    for prop in control.get("props") or []:
        if prop.get("name") == "label" and prop.get("value"):
            return str(prop["value"])
    return str(control.get("id") or "")


def _walk(node: dict):
    for control in node.get("controls") or []:
        yield control
        yield from _walk(control)
    for group in node.get("groups") or []:
        yield from _walk(group)


def import_oscal_catalog(
    data: bytes | str | dict,
    framework: str,
    name: str | None = None,
    objective_map: dict[str, list[str]] | Path | None = None,
    use_labels: bool = True,
) -> ImportedLibrary:
    check_framework_key(framework)
    doc = data if isinstance(data, dict) else json.loads(data)
    catalog = doc.get("catalog") if isinstance(doc, dict) else None
    if not isinstance(catalog, dict):
        raise ValueError("not an OSCAL catalog: missing top-level 'catalog'")
    meta = catalog.get("metadata") or {}
    lib = ImportedLibrary(
        framework=framework,
        name=name or str(meta.get("title") or framework),
        source=f"OSCAL catalog {clean(meta.get('title') or '', 80)} v{meta.get('version', '?')}".strip(),
    )
    omap = objective_map if isinstance(objective_map, dict) else load_objective_map(objective_map)
    by_control: dict[str, set[str]] = {}
    for obj, ids in omap.items():
        for cid in ids:
            by_control.setdefault(cid.lower(), set()).add(obj)
    objectives = hub_objectives()
    for obj in omap:
        if obj not in objectives:
            raise ValueError(f"objective map: unknown objective {obj!r}")

    for control in _walk(catalog):
        cid = str(control.get("id") or "")
        if not cid:
            continue
        ref = _label(control) if use_labels else cid
        lib.titles[ref] = clean(control.get("title") or ref)
        objs = set(by_control.get(cid.lower(), set())) | set(by_control.get(ref.lower(), set()))
        for prop in control.get("props") or []:
            if prop.get("name") == OBJECTIVE_PROP and prop.get("value") in objectives:
                objs.add(prop["value"])
        if objs:
            for obj in sorted(objs):
                lib.add(obj, ref)
        else:
            lib.unmapped.append(ref)
    if not lib.titles:
        raise ValueError("OSCAL catalog has no controls")
    return lib
