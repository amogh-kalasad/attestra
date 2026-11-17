"""Pure-Python CVSS v4.0 base/threat/environmental score calculator.

A port of the FIRST reference calculator (github.com/FIRSTdotorg/cvss-v4-calculator,
``cvss_score.js`` + ``cvss_lookup.js`` + ``max_composed.js`` + ``max_severity.js``),
Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors, BSD-2-Clause.

The score is reproducible from ``(vector, CALCULATOR_VERSION)``: the MacroVector
lookup table is embedded below and no network or third-party package is used.
Malformed vectors raise :class:`Cvss4Error`; callers on import paths should catch it.
"""
# @lat: [[intel-and-reporting#CVSS 4.0 calculator]]

from __future__ import annotations

import math
from dataclasses import dataclass

CALCULATOR_VERSION = "cvss4-first-ref-2023.1"

# Valid values per metric (FIRST metrics.js order). Base metrics are mandatory.
METRICS: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
    "E": ("X", "A", "P", "U"),
    "CR": ("X", "H", "M", "L"),
    "IR": ("X", "H", "M", "L"),
    "AR": ("X", "H", "M", "L"),
    "MAV": ("X", "N", "A", "L", "P"),
    "MAC": ("X", "L", "H"),
    "MAT": ("X", "N", "P"),
    "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", "H", "L", "N"),
    "MVI": ("X", "H", "L", "N"),
    "MVA": ("X", "H", "L", "N"),
    "MSC": ("X", "H", "L", "N"),
    "MSI": ("X", "S", "H", "L", "N"),
    "MSA": ("X", "S", "H", "L", "N"),
    "S": ("X", "N", "P"),
    "AU": ("X", "N", "Y"),
    "R": ("X", "A", "U", "I"),
    "V": ("X", "D", "C"),
    "RE": ("X", "L", "M", "H"),
    "U": ("X", "Clear", "Green", "Amber", "Red"),
}
BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")

# MacroVector -> score (FIRST cvss_lookup.js, 270 entries).
LOOKUP: dict[str, float] = {
    "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
    "000100": 10.0, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9.0, "000210": 8.9, "000211": 8.0, "000220": 8.1, "000221": 6.8,
    "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9.0, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
    "001200": 8.8, "001201": 8.0, "001210": 7.8, "001211": 7.0, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5.0,
    "002201": 6.9, "002211": 5.5, "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9.0,
    "010111": 8.3, "010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5, "011001": 9.3, "011010": 9.2,
    "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8.0,
    "011111": 7.2, "011120": 7.0, "011121": 5.9, "011200": 8.4, "011201": 7.0, "011210": 7.1,
    "011211": 5.2, "011220": 5.0, "011221": 3.0, "012001": 8.6, "012011": 7.5, "012021": 5.2,
    "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
    "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
    "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5.0,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
    "102001": 8.3, "102011": 7.0, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5, "110001": 9.0, "110010": 8.8,
    "110011": 7.6, "110020": 7.6, "110021": 7.0, "110100": 9.0, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8,
    "110211": 5.9, "110220": 5.2, "110221": 3.0, "111000": 8.9, "111001": 7.8, "111010": 7.6,
    "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4, "111101": 5.9, "111110": 5.7,
    "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3.0,
    "112101": 5.8, "112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
    "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7.0, "200201": 5.4, "200210": 5.2, "200211": 4.0, "200220": 4.0, "200221": 2.2,
    "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
    "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2.0, "202101": 4.7, "202111": 2.1, "202121": 1.1,
    "202201": 2.4, "202211": 0.9, "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
    "210011": 5.3, "210020": 6.0, "210021": 5.0, "210100": 7.3, "210101": 5.5, "210110": 5.9,
    "210111": 4.0, "210120": 4.1, "210121": 2.0, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2.0, "210221": 1.1, "211000": 7.5, "211001": 5.5, "211010": 5.8,
    "211011": 4.5, "211020": 4.0, "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
    "211111": 1.8, "211120": 2.0, "211121": 0.9, "211200": 4.6, "211201": 1.8, "211210": 1.7,
    "211211": 0.7, "211220": 0.8, "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1.0, "212211": 0.3, "212221": 0.1,
}

MAX_COMPOSED: dict[str, dict] = {
    "eq1": {0: ["AV:N/PR:N/UI:N/"], 1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
            2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]},
    "eq2": {0: ["AC:L/AT:N/"], 1: ["AC:H/AT:N/", "AC:L/AT:P/"]},
    "eq3": {
        0: {"0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]},
        1: {"0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            "1": ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                  "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                  "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]},
        2: {"1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
    },
    "eq4": {0: ["SC:H/SI:S/SA:S/"], 1: ["SC:H/SI:H/SA:H/"], 2: ["SC:L/SI:L/SA:L/"]},
    "eq5": {0: ["E:A/"], 1: ["E:P/"], 2: ["E:U/"]},
}

MAX_SEVERITY: dict[str, dict] = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

_LEVELS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}


class Cvss4Error(ValueError):
    """Raised for a malformed or incomplete CVSS v4.0 vector."""


@dataclass(frozen=True)
class Cvss4Result:
    vector: str
    score: float
    severity: str
    macro_vector: str
    calculator_version: str = CALCULATOR_VERSION

    def as_dict(self) -> dict:
        return {
            "vector": self.vector,
            "score": self.score,
            "severity": self.severity,
            "macro_vector": self.macro_vector,
            "calculator_version": self.calculator_version,
        }


def parse_vector(vector: str) -> dict[str, str]:
    """Parse ``CVSS:4.0/AV:N/...`` into a metric dict; strict on keys, values and duplicates."""
    v = (vector or "").strip()
    if not v.startswith("CVSS:4.0/"):
        raise Cvss4Error("CVSS 4.0 vector must start with 'CVSS:4.0/'")
    parts = v[len("CVSS:4.0/"):].split("/")
    selected: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise Cvss4Error(f"malformed metric {part!r}")
        key, val = part.split(":", 1)
        if key not in METRICS:
            raise Cvss4Error(f"unknown metric {key!r}")
        if key in selected:
            raise Cvss4Error(f"duplicate metric {key!r}")
        if val not in METRICS[key]:
            raise Cvss4Error(f"invalid value {val!r} for metric {key}")
        selected[key] = val
    missing = [k for k in BASE_METRICS if k not in selected]
    if missing:
        raise Cvss4Error(f"missing mandatory base metric(s): {', '.join(missing)}")
    for key in METRICS:
        selected.setdefault(key, "X")
    return selected


def _m(sel: dict[str, str], metric: str) -> str:
    val = sel.get(metric, "X")
    if metric == "E" and val == "X":
        return "A"
    if metric in ("CR", "IR", "AR") and val == "X":
        return "H"
    mod = sel.get("M" + metric)
    if mod is not None and mod != "X":
        return mod
    return val


def macro_vector(sel: dict[str, str]) -> str:
    m = lambda k: _m(sel, k)  # noqa: E731
    if m("AV") == "N" and m("PR") == "N" and m("UI") == "N":
        eq1 = 0
    elif (m("AV") == "N" or m("PR") == "N" or m("UI") == "N") and m("AV") != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if (m("AC") == "L" and m("AT") == "N") else 1
    if m("VC") == "H" and m("VI") == "H":
        eq3 = 0
    elif m("VC") == "H" or m("VI") == "H" or m("VA") == "H":
        eq3 = 1
    else:
        eq3 = 2
    if m("MSI") == "S" or m("MSA") == "S":
        eq4 = 0
    elif m("SC") == "H" or m("SI") == "H" or m("SA") == "H":
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[m("E")]
    if (m("CR") == "H" and m("VC") == "H") or (m("IR") == "H" and m("VI") == "H") or (
        m("AR") == "H" and m("VA") == "H"
    ):
        eq6 = 0
    else:
        eq6 = 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _extract(metric: str, max_vector: str) -> str:
    for part in max_vector.strip("/").split("/"):
        k, _, v = part.partition(":")
        if k == metric:
            return v
    raise KeyError(metric)


def _round1(x: float) -> float:
    # JS Math.round semantics (half away from zero for positives), with float-noise guard.
    return math.floor(x * 10 + 0.5 + 1e-9) / 10


def severity_rating(score: float) -> str:
    """FIRST qualitative rating for a CVSS v4.0 score (lowercase, Attestra style)."""
    if score == 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _score_selected(sel: dict[str, str], mv: str) -> float:
    if all(_m(sel, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    value = LOOKUP[mv]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in mv)

    def lk(*eqs: int) -> float | None:
        return LOOKUP.get("".join(str(e) for e in eqs))

    s_eq1 = lk(eq1 + 1, eq2, eq3, eq4, eq5, eq6)
    s_eq2 = lk(eq1, eq2 + 1, eq3, eq4, eq5, eq6)
    if eq3 == 1 and eq6 == 1:
        s_eq36 = lk(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 0 and eq6 == 1:
        s_eq36 = lk(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 1 and eq6 == 0:
        s_eq36 = lk(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
    elif eq3 == 0 and eq6 == 0:
        left = lk(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
        right = lk(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
        # JS: left > right ? left : right  (undefined compares false)
        if left is not None and right is not None and left > right:
            s_eq36 = left
        else:
            s_eq36 = right
    else:
        s_eq36 = lk(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)
    s_eq4 = lk(eq1, eq2, eq3, eq4 + 1, eq5, eq6)
    s_eq5 = lk(eq1, eq2, eq3, eq4, eq5 + 1, eq6)

    eq1_maxes = MAX_COMPOSED["eq1"][eq1]
    eq2_maxes = MAX_COMPOSED["eq2"][eq2]
    eq36_maxes = MAX_COMPOSED["eq3"][eq3][str(eq6)]
    eq4_maxes = MAX_COMPOSED["eq4"][eq4]
    eq5_maxes = MAX_COMPOSED["eq5"][eq5]
    max_vectors = [
        a + b + c + d + e
        for a in eq1_maxes for b in eq2_maxes for c in eq36_maxes for d in eq4_maxes for e in eq5_maxes
    ]
    order = ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR")
    dist: dict[str, float] = {}
    for mvx in max_vectors:
        dist = {k: _LEVELS[k][_m(sel, k)] - _LEVELS[k][_extract(k, mvx)] for k in order}
        if any(d < 0 for d in dist.values()):
            continue
        break

    cur_eq1 = dist["AV"] + dist["PR"] + dist["UI"]
    cur_eq2 = dist["AC"] + dist["AT"]
    cur_eq36 = dist["VC"] + dist["VI"] + dist["VA"] + dist["CR"] + dist["IR"] + dist["AR"]
    cur_eq4 = dist["SC"] + dist["SI"] + dist["SA"]

    step = 0.1
    max_eq1 = MAX_SEVERITY["eq1"][eq1] * step
    max_eq2 = MAX_SEVERITY["eq2"][eq2] * step
    max_eq36 = MAX_SEVERITY["eq3eq6"][eq3][eq6] * step
    max_eq4 = MAX_SEVERITY["eq4"][eq4] * step

    n_lower = 0
    total = 0.0
    for nxt, cur, mx in ((s_eq1, cur_eq1, max_eq1), (s_eq2, cur_eq2, max_eq2),
                         (s_eq36, cur_eq36, max_eq36), (s_eq4, cur_eq4, max_eq4)):
        if nxt is not None:
            n_lower += 1
            total += (value - nxt) * (cur / mx)
    if s_eq5 is not None:
        n_lower += 1  # eq5 proportion is always 0
    mean = total / n_lower if n_lower else 0.0
    value -= mean
    value = min(max(value, 0.0), 10.0)
    return _round1(value)


def score(vector: str) -> Cvss4Result:
    """Score a CVSS v4.0 vector (base, threat and environmental metrics all honoured)."""
    sel = parse_vector(vector)
    mv = macro_vector(sel)
    sc = _score_selected(sel, mv)
    return Cvss4Result(vector=vector.strip(), score=sc, severity=severity_rating(sc), macro_vector=mv)


def try_score(vector: str | None) -> Cvss4Result | None:
    """Return a result, or ``None`` when the vector is empty, not 4.0, or malformed."""
    try:
        return score(vector or "")
    except Cvss4Error:
        return None
