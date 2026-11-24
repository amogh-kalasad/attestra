"""Supported version pins for the AASI V5.1 shared scanner runtime.

Python scanners (garak, safelabs-eval, pyrit) install into the single shared
venv. Promptfoo is Node/npm under the same root — never pip. Node is 20.x.
"""

from __future__ import annotations

# Exact pins for PyPI packages installed into the shared venv.
PYTHON_PACKAGE_PINS: dict[str, str] = {
    "garak": "0.17.1",
    "safelabs-eval": "0.12.0",
    "pyrit": "1.2.1",
}

# Semver-ish ranges: ~0.118.x means 0.118.*; 20.x means major 20.
PROMPTFOO_PIN = "~0.118.x"
NODE_PIN = "20.x"

SUPPORTED: dict[str, str] = {
    **PYTHON_PACKAGE_PINS,
    "promptfoo": PROMPTFOO_PIN,
    "node": NODE_PIN,
}

# Scanner display names used by health_report (safelabs package is safelabs-eval).
SCANNER_NAMES: tuple[str, ...] = ("garak", "safelabs", "pyrit", "promptfoo")

SCANNER_TO_PACKAGE: dict[str, str] = {
    "garak": "garak",
    "safelabs": "safelabs-eval",
    "pyrit": "pyrit",
    "promptfoo": "promptfoo",
}


def version_matches(installed: str | None, expected: str) -> bool:
    """Return True when ``installed`` satisfies the pin in ``expected``.

    Exact pins compare equality after stripping a leading ``v``. Range pins:
    ``~0.118.x`` / ``0.118.x`` match major.minor; ``20.x`` matches major only.
    """
    if not installed:
        return False
    got = installed.strip().lstrip("vV")
    exp = expected.strip()
    if exp.startswith("~"):
        exp = exp[1:]
    if exp.endswith(".x"):
        prefix = exp[:-2]  # "0.118" or "20"
        parts_exp = prefix.split(".")
        parts_got = got.split(".")
        if len(parts_exp) == 1:
            return parts_got[0] == parts_exp[0]
        if len(parts_exp) >= 2 and len(parts_got) >= 2:
            return parts_got[0] == parts_exp[0] and parts_got[1] == parts_exp[1]
        return False
    return got == exp.lstrip("vV")
