"""Unit tests for AASI V5.1 shared-env openai 3.x + Garak --no-deps policy helpers."""
# @lat: [[tests#AASI V5.1 openai shared-env policy]]

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "aasi" / "install_shared_env.py"


def _load_install_module():
    spec = importlib.util.spec_from_file_location("attestra_install_shared_env", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def install_mod():
    return _load_install_module()


def test_pins_prefer_openai_3_and_exclude_garak_from_joint(install_mod):
    assert install_mod.OPENAI_PIN == "openai>=3,<4"
    assert install_mod.GARAK_PIN == "garak==0.17.1"
    assert install_mod.GARAK_PIN not in install_mod.AI_SCANNER_JOINT_PINS
    assert install_mod.PYRIT_PIN in install_mod.AI_SCANNER_JOINT_PINS
    assert install_mod.ANTHROPIC_PIN in install_mod.AI_SCANNER_JOINT_PINS
    assert install_mod.LITELLM_PIN in install_mod.AI_SCANNER_JOINT_PINS
    assert install_mod.GARAK_PIN in install_mod.AI_SCANNER_PINS


def test_filter_garak_requirements_drops_openai_and_extras(install_mod):
    reqs = [
        "openai<3.0,>=2.0",
        "anthropic<1.0.0,>=0.40.0",
        "litellm>=1.84.0",
        'soundfile>=0.13.1; extra == "audio"',
        'python-magic-bin>=0.4.14; sys_platform == "win32"',
        "torch>=2.13.0",
    ]
    got = install_mod.filter_garak_requirements(reqs)
    assert all("openai" not in r.lower().split(";", 1)[0] for r in got)
    assert "anthropic<1.0.0,>=0.40.0" in got
    assert "litellm>=1.84.0" in got
    assert "torch>=2.13.0" in got
    assert any("python-magic-bin" in r for r in got)
    assert not any("soundfile" in r for r in got)


def test_pip_check_accepts_only_known_garak_openai_mismatch(install_mod):
    ok = (
        "garak 0.17.1 has requirement openai<3.0,>=2.0, but you have openai 3.9.0.\n"
    )
    assert install_mod._pip_check_only_known_openai_mismatch(ok) is True
    bad = ok + "pyrit 1.2.1 has requirement something-else==1, but you have something-else 2.\n"
    assert install_mod._pip_check_only_known_openai_mismatch(bad) is False
    assert install_mod._pip_check_only_known_openai_mismatch("") is True
