"""OSV correlation (G-05): match SBOM components to OSV advisories with a stated confidence.

Confidence is never certainty:

* ``high``   — the component version is listed verbatim in the advisory ``versions``.
* ``medium`` — the version falls inside an ``affected.ranges`` interval (generic
  dotted-number comparison; ecosystem-specific ordering may differ).
* ``low``    — the package matches but the version is missing or not comparable.

Parsers take bytes/dicts only; no network access happens here.
"""
# @lat: [[intel-and-reporting#NVD and OSV]]

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import unquote

PURL_ECOSYSTEMS = {
    "npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "cargo": "crates.io",
    "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist", "hex": "Hex", "pub": "Pub",
    "deb": "Debian", "apk": "Alpine",
}
CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class Component:
    ecosystem: str
    name: str
    version: str = ""
    purl: str = ""
    ref: str = ""


@dataclass
class OsvMatch:
    component: str
    version: str
    vuln_id: str
    aliases: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    confidence: str = "low"
    reason: str = ""
    summary: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def parse_purl(purl: str) -> Component | None:
    """Parse ``pkg:type/namespace/name@version`` (qualifiers/subpath ignored)."""
    p = (purl or "").strip()
    if not p.startswith("pkg:"):
        return None
    body = p[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return None
    ptype, rest = body.split("/", 1)
    version = ""
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
    parts = [unquote(x) for x in rest.split("/") if x]
    if not parts:
        return None
    eco = PURL_ECOSYSTEMS.get(ptype.lower(), ptype)
    if eco == "Maven" and len(parts) >= 2:
        name = f"{parts[-2]}:{parts[-1]}"
    elif eco == "Go":
        name = "/".join(parts)
    else:
        name = "/".join(parts)
    return Component(ecosystem=eco, name=name, version=unquote(version), purl=p)


def _norm_name(eco: str, name: str) -> str:
    n = (name or "").strip()
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", n).lower()
    if eco in ("npm", "crates.io", "RubyGems", "Packagist", "NuGet"):
        return n.lower()
    return n


def _vkey(v: str):
    """Generic version key: numeric dotted parts, pre-release sorts before release."""
    v = (v or "").strip().lstrip("vV").split("+", 1)[0]
    if not v or not re.match(r"^\d", v):
        return None
    m = re.match(r"^([\d.]+)(.*)$", v)
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).strip(".").split(".") if x != "")
    tail = m.group(2).lstrip("-.")
    # Release (no tail) > any pre-release tail.
    padded = nums + (0,) * max(0, 6 - len(nums))
    return (padded, 0 if tail else 1, tail)


def _in_range(version: str, events: list[dict]) -> bool | None:
    """True/False when comparable; None when any bound or the version is not comparable."""
    vk = _vkey(version)
    if vk is None:
        return None
    affected = False
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        if "introduced" in ev:
            intro = str(ev["introduced"])
            if intro == "0":
                affected = True
                continue
            ik = _vkey(intro)
            if ik is None:
                return None
            if vk >= ik:
                affected = True
        elif "fixed" in ev:
            fk = _vkey(str(ev["fixed"]))
            if fk is None:
                return None
            if vk >= fk:
                affected = False
        elif "last_affected" in ev:
            lk = _vkey(str(ev["last_affected"]))
            if lk is None:
                return None
            if vk > lk:
                affected = False
    return affected


def load_vulns(raw: bytes | str | dict | list) -> list[dict]:
    """Accept one OSV record, a list, ``{"vulns": [...]}`` or a querybatch ``results`` doc."""
    doc = json.loads(raw) if isinstance(raw, (bytes, str)) else raw
    if isinstance(doc, dict) and "results" in doc:
        out: list[dict] = []
        for r in doc.get("results") or []:
            out.extend((r or {}).get("vulns") or [])
        return [v for v in out if isinstance(v, dict) and v.get("id")]
    if isinstance(doc, dict) and "vulns" in doc:
        doc = doc["vulns"]
    if isinstance(doc, dict):
        doc = [doc]
    if not isinstance(doc, list):
        raise ValueError("OSV payload must be an object or a list of objects")
    return [v for v in doc if isinstance(v, dict) and v.get("id")]


def _match_one(comp: Component, vuln: dict) -> OsvMatch | None:
    best: tuple[str, str] | None = None
    for aff in vuln.get("affected") or []:
        pkg = (aff or {}).get("package") or {}
        eco = str(pkg.get("ecosystem") or "").split(":", 1)[0]
        if eco != comp.ecosystem or _norm_name(eco, pkg.get("name", "")) != _norm_name(comp.ecosystem, comp.name):
            continue
        if aff.get("package", {}).get("purl") and comp.purl and comp.purl.split("@", 1)[0] != str(pkg["purl"]).split("@", 1)[0]:
            continue
        cand: tuple[str, str] | None
        if not comp.version:
            cand = ("low", "package matched; component version unknown")
        elif comp.version in [str(v) for v in aff.get("versions") or []]:
            cand = ("high", "version listed in advisory 'versions'")
        else:
            verdicts = [_in_range(comp.version, r.get("events")) for r in aff.get("ranges") or [] if isinstance(r, dict)]
            if any(v is True for v in verdicts):
                cand = ("medium", "version inside an affected range (generic version ordering)")
            elif verdicts and all(v is False for v in verdicts):
                cand = None
            elif aff.get("versions") and not verdicts:
                cand = None  # explicit list present and version not in it
            else:
                cand = ("low", "package matched; version not comparable with advisory ranges")
        if cand and (best is None or CONFIDENCE_ORDER[cand[0]] > CONFIDENCE_ORDER[best[0]]):
            best = cand
    if best is None:
        return None
    aliases = [str(a) for a in vuln.get("aliases") or []]
    cves = sorted({a.upper() for a in aliases + [vuln["id"]] if str(a).upper().startswith("CVE-")})
    return OsvMatch(
        component=f"{comp.ecosystem}:{comp.name}", version=comp.version, vuln_id=str(vuln["id"]),
        aliases=aliases, cves=cves, confidence=best[0], reason=best[1],
        summary=str(vuln.get("summary") or "")[:300],
    )


def correlate(components: list[Component | dict | str], vulns: list[dict]) -> list[OsvMatch]:
    """Return matches sorted by (component, vuln id). Withdrawn advisories are ignored."""
    comps: list[Component] = []
    for c in components:
        if isinstance(c, Component):
            comps.append(c)
        elif isinstance(c, str):
            pc = parse_purl(c)
            if pc:
                comps.append(pc)
        elif isinstance(c, dict):
            pc = parse_purl(c.get("purl", "")) if c.get("purl") else None
            if pc is None and c.get("ecosystem") and c.get("name"):
                pc = Component(ecosystem=c["ecosystem"], name=c["name"], version=str(c.get("version") or ""))
            if pc:
                comps.append(pc)
    out: list[OsvMatch] = []
    for comp in comps:
        for v in vulns:
            if v.get("withdrawn"):
                continue
            m = _match_one(comp, v)
            if m:
                out.append(m)
    return sorted(out, key=lambda m: (m.component, m.version, m.vuln_id))


def components_from_cyclonedx(raw: bytes) -> list[Component]:
    """Components (with purl) from a CycloneDX JSON SBOM, including nested components."""
    doc = json.loads(raw)
    out: list[Component] = []

    def walk(items):
        for c in items or []:
            if not isinstance(c, dict):
                continue
            pc = parse_purl(c.get("purl", "")) if c.get("purl") else None
            if pc:
                out.append(Component(pc.ecosystem, pc.name, pc.version or str(c.get("version") or ""), pc.purl,
                                     str(c.get("bom-ref") or "")))
            walk(c.get("components"))

    walk(doc.get("components"))
    return out
