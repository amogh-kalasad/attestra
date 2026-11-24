#!/usr/bin/env python3
"""Install AASI V5.1 shared scanner environment (one Python venv + npm Promptfoo).

Creates ATTESTRA_SHARED_ENV_ROOT layout, a single venv/, installs
``pip install -e ".[ai-scanners]"`` into that venv only, optionally wires
Node under tools/node, runs ``npm install`` for Promptfoo under npm/, and
writes manifests/. Never creates a second venv. Never runs docker pull.

Usage (from repo root):
  python scripts/aasi/install_shared_env.py
  python scripts/aasi/install_shared_env.py --root /opt/attestra/runtime
  python scripts/aasi/install_shared_env.py --skip-node
  python scripts/aasi/install_shared_env.py --promptfoo-only
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCAL_ROOT = REPO_ROOT / ".attestra-runtime"
COMMITTED_PACKAGE_JSON = REPO_ROOT / "runtime" / "npm" / "package.json"

# Pinned for V5.1 (see docs/ai_security/AASI_V51_DEPENDENCIES.md).
NODE_VERSION = "20.20.2"
PROMPTFOO_VERSION = "0.118.17"
# Prefer openai 3.x for PyRIT. Garak is installed with --no-deps (REST/Anthropic/LiteLLM).
OPENAI_PIN = "openai>=3,<4"
ANTHROPIC_PIN = "anthropic>=0.40.0,<1.0.0"
LITELLM_PIN = "litellm>=1.84.0"
GARAK_PIN = "garak==0.17.1"
SAFELABS_PIN = "safelabs-eval==0.12.0"
PYRIT_PIN = "pyrit==1.2.1"
# Joint-resolvable pins (no garak — its openai<3 bound conflicts with PyRIT).
AI_SCANNER_JOINT_PINS = (
    SAFELABS_PIN,
    PYRIT_PIN,
    OPENAI_PIN,
    ANTHROPIC_PIN,
    LITELLM_PIN,
)
AI_SCANNER_PINS = (GARAK_PIN, *AI_SCANNER_JOINT_PINS)
# pip check may report this single known mismatch after the staged install.
_KNOWN_PIP_CHECK_SUBSTRING = "has requirement openai"

LAYOUT_DIRS = ("venv", "tools", "tools/node", "npm", "manifests", "logs", "cache", "tmp")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.expanduser().resolve()
    env = os.environ.get("ATTESTRA_SHARED_ENV_ROOT", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return DEFAULT_LOCAL_ROOT.resolve()


def ensure_layout(root: Path) -> None:
    for rel in LAYOUT_DIRS:
        (root / rel).mkdir(parents=True, exist_ok=True)
    # Reject extra scanner venvs under the shared root.
    for child in root.iterdir():
        name = child.name.lower()
        if child.is_dir() and name.endswith("-venv") and name != "venv":
            raise SystemExit(
                f"Refusing shared root with extra scanner venv: {child}\n"
                "AASI V5.1 allows exactly one Python venv at <root>/venv."
            )


def venv_python(root: Path) -> Path:
    if platform.system() == "Windows":
        return root / "venv" / "Scripts" / "python.exe"
    return root / "venv" / "bin" / "python"


def ensure_venv(root: Path) -> Path:
    py = venv_python(root)
    if py.is_file():
        print(f"OK: existing venv python {py}")
        return py
    print(f"==> Creating single shared venv at {root / 'venv'}")
    subprocess.run([sys.executable, "-m", "venv", str(root / "venv")], check=True)
    if not py.is_file():
        raise SystemExit(f"venv created but python missing: {py}")
    return py


def _requirement_package_name(req: str) -> str:
    """Return the distribution name from a PEP 508 requirement string."""
    base = req.split(";", 1)[0].strip()
    for sep in ("[", "<", ">", "=", "!", "~", " "):
        if sep in base:
            base = base.split(sep, 1)[0]
    return base.strip().lower()


def filter_garak_requirements(requires_dist: list[str] | None) -> list[str]:
    """Keep Garak runtime deps except openai and extras (Attestra uses REST/Anthropic/LiteLLM)."""
    out: list[str] = []
    for raw in requires_dist or []:
        req = (raw or "").strip()
        if not req:
            continue
        if ";" in req:
            marker = req.split(";", 1)[1]
            # Drop optional extras (audio, lint, tests, …).
            if "extra" in marker:
                continue
        if _requirement_package_name(req) == "openai":
            continue
        out.append(req)
    return out


def _garak_support_requirements(py: Path) -> list[str]:
    """Read installed garak METADATA requires and drop openai / extras."""
    script = (
        "import json, importlib.metadata as m;\n"
        "print(json.dumps(m.requires('garak') or []))\n"
    )
    raw = subprocess.check_output([str(py), "-c", script], text=True, cwd=str(REPO_ROOT))
    import json as _json

    return filter_garak_requirements(_json.loads(raw))


def _pip_check_only_known_openai_mismatch(output: str) -> bool:
    """True when pip check fails solely on garak's openai<3 vs installed openai 3.x."""
    lines = [ln.strip() for ln in (output or "").splitlines() if ln.strip()]
    if not lines:
        return True
    for ln in lines:
        lower = ln.lower()
        if "garak" in lower and _KNOWN_PIP_CHECK_SUBSTRING in lower:
            continue
        if "openai" in lower and "garak" in lower:
            continue
        return False
    return True


def _verify_ai_scanner_imports(py: Path) -> int:
    """Confirm openai 3.x + garak/pyrit/safelabs/anthropic/litellm import in the shared venv."""
    script = r"""
import importlib.metadata as m
import sys

def maj(name: str) -> int:
    return int(m.version(name).split(".", 1)[0])

errors = []
try:
    import openai  # noqa: F401
    if maj("openai") < 3:
        errors.append(f"openai major {m.version('openai')} < 3")
except Exception as exc:  # noqa: BLE001
    errors.append(f"openai: {exc}")
for mod, dist in (
    ("garak", "garak"),
    ("pyrit", "pyrit"),
    ("anthropic", "anthropic"),
    ("litellm", "litellm"),
):
    try:
        __import__(mod)
        _ = m.version(dist)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{mod}: {exc}")
# safelabs-eval may expose safelabs or safelabs_eval
safelabs_ok = False
for mod in ("safelabs", "safelabs_eval"):
    try:
        __import__(mod)
        safelabs_ok = True
        break
    except Exception:
        pass
if not safelabs_ok:
    try:
        _ = m.version("safelabs-eval")
        safelabs_ok = True
    except Exception as exc:  # noqa: BLE001
        errors.append(f"safelabs-eval: {exc}")
if errors:
    print("FAIL import verification:")
    for e in errors:
        print(" ", e)
    sys.exit(1)
print(
    "OK imports:",
    "openai", m.version("openai"),
    "garak", m.version("garak"),
    "pyrit", m.version("pyrit"),
    "anthropic", m.version("anthropic"),
)
"""
    print("==> Verifying AI scanner imports (openai 3.x + garak REST stack)")
    proc = subprocess.run([str(py), "-c", script], cwd=str(REPO_ROOT))
    return proc.returncode


def pip_install_ai_scanners(py: Path, *, upgrade_pip: bool) -> int:
    """Staged shared-venv install: openai 3.x + PyRIT; Garak via --no-deps.

    Upstream clash: garak==0.17.1 wants openai>=2,<3; pyrit==1.2.1 wants openai>=3,<4.
    Policy: keep openai 3.x for PyRIT; install Garak without pulling openai<3;
    Attestra Garak runs REST (Anthropic/LiteLLM packages present for generators).
    """
    if upgrade_pip:
        print("==> Upgrading pip in shared venv")
        subprocess.run([str(py), "-m", "pip", "install", "--upgrade", "pip"], check=True)

    print("==> pip install -e . (Attestra core) into shared venv")
    core = subprocess.run(
        [str(py), "-m", "pip", "install", "-e", "."],
        cwd=str(REPO_ROOT),
    )
    if core.returncode != 0:
        print("FAIL: editable Attestra core install")
        return core.returncode or 1

    print("==> pip install PyRIT/SafeLabs + openai 3.x + anthropic + litellm")
    joint = subprocess.run(
        [str(py), "-m", "pip", "install", *AI_SCANNER_JOINT_PINS],
        cwd=str(REPO_ROOT),
    )
    if joint.returncode != 0:
        print("FAIL: joint AI scanner pins (openai 3.x path)")
        return joint.returncode or 1

    print(f"==> pip install {GARAK_PIN} --no-deps (avoid openai<3 pull)")
    garak = subprocess.run(
        [str(py), "-m", "pip", "install", "--no-deps", GARAK_PIN],
        cwd=str(REPO_ROOT),
    )
    if garak.returncode != 0:
        print(f"FAIL: could not install {GARAK_PIN} with --no-deps")
        return garak.returncode or 1

    try:
        support = _garak_support_requirements(py)
    except subprocess.CalledProcessError as exc:
        print(f"FAIL: could not read garak requires from METADATA: {exc}")
        return 1
    if support:
        print(f"==> pip install {len(support)} garak support deps (openai excluded)")
        # Re-assert openai 3.x so a transitive pin cannot silently downgrade.
        support_cmd = [str(py), "-m", "pip", "install", *support, OPENAI_PIN]
        supp = subprocess.run(support_cmd, cwd=str(REPO_ROOT))
        if supp.returncode != 0:
            print("FAIL: garak support dependency install")
            return supp.returncode or 1
    else:
        print("WARN: garak METADATA listed no non-openai runtime deps")

    # Ensure openai stayed on 3.x after support deps.
    print(f"==> Re-pin {OPENAI_PIN}")
    pin_rc = subprocess.run(
        [str(py), "-m", "pip", "install", OPENAI_PIN],
        cwd=str(REPO_ROOT),
    )
    if pin_rc.returncode != 0:
        print("FAIL: could not re-pin openai 3.x")
        return pin_rc.returncode or 1

    verify_rc = _verify_ai_scanner_imports(py)
    if verify_rc != 0:
        return verify_rc

    print("==> pip check (known garak↔openai mismatch is accepted WARN)")
    check = subprocess.run(
        [str(py), "-m", "pip", "check"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    combined = ((check.stdout or "") + (check.stderr or "")).strip()
    if check.returncode == 0:
        print("OK: pip check clean")
        return 0
    if _pip_check_only_known_openai_mismatch(combined):
        print(
            "WARN: pip check reports garak openai<3 vs installed openai 3.x — "
            "accepted for V5.1 (Garak uses REST/Anthropic/LiteLLM; PyRIT needs openai 3.x). "
            "See docs/ai_security/AASI_V51_DEPENDENCIES.md."
        )
        if combined:
            print(combined)
        return 0
    print("FAIL: pip check reported unexpected conflicts:")
    if combined:
        print(combined)
    return check.returncode or 1


def _node_archive_url(version: str) -> tuple[str, str]:
    """Return (url, kind) where kind is 'tar.xz' or 'zip'."""
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Windows":
        arch = "x64" if machine in ("amd64", "x86_64") else "arm64"
        return (
            f"https://nodejs.org/dist/v{version}/node-v{version}-win-{arch}.zip",
            "zip",
        )
    if system == "Darwin":
        arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
        return (
            f"https://nodejs.org/dist/v{version}/node-v{version}-darwin-{arch}.tar.gz",
            "tar.gz",
        )
    # Linux default
    arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
    return (
        f"https://nodejs.org/dist/v{version}/node-v{version}-linux-{arch}.tar.xz",
        "tar.xz",
    )


def node_bin_dir(root: Path) -> Path:
    """Locate node binary directory under tools/node (portable layouts differ)."""
    base = root / "tools" / "node"
    if platform.system() == "Windows":
        # Official win zip extracts to node-vVER-win-ARCH/ with node.exe at top.
        if (base / "node.exe").is_file():
            return base
        for child in base.iterdir() if base.is_dir() else []:
            if (child / "node.exe").is_file():
                return child
        return base
    # Unix: prefer tools/node/bin/node after flatten, else nested extract.
    if (base / "bin" / "node").is_file():
        return base / "bin"
    for child in base.iterdir() if base.is_dir() else []:
        if (child / "bin" / "node").is_file():
            return child / "bin"
    return base / "bin"


def node_exe(root: Path) -> Path:
    bdir = node_bin_dir(root)
    return bdir / ("node.exe" if platform.system() == "Windows" else "node")


def npm_cmd(root: Path) -> list[str]:
    """Return argv prefix to run npm with the shared Node (npm.cmd on Windows)."""
    bdir = node_bin_dir(root)
    if platform.system() == "Windows":
        npm = bdir / "npm.cmd"
        if npm.is_file():
            return [str(npm)]
        # Fallback: node + npm-cli.js
        cli = bdir / "node_modules" / "npm" / "bin" / "npm-cli.js"
        if cli.is_file():
            return [str(node_exe(root)), str(cli)]
        raise SystemExit(f"npm not found under {bdir}")
    npm = bdir / "npm"
    if npm.is_file():
        return [str(npm)]
    raise SystemExit(f"npm not found under {bdir}")


def download_node(root: Path, *, force: bool) -> None:
    nexe = node_exe(root)
    if nexe.is_file() and not force:
        print(f"OK: Node already present at {nexe}")
        return
    url, kind = _node_archive_url(NODE_VERSION)
    dest = root / "tools" / "node"
    print(f"==> Downloading Node {NODE_VERSION} from {url}")
    try:
        with tempfile.TemporaryDirectory(prefix="attestra-node-") as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / f"node-archive.{kind}"
            urllib.request.urlretrieve(url, archive)  # noqa: S310 — pinned official dist URL
            extract_dir = tmp_path / "extract"
            extract_dir.mkdir()
            if kind == "zip":
                with zipfile.ZipFile(archive) as zf:
                    zf.extractall(extract_dir)
            else:
                with tarfile.open(archive) as tf:
                    tf.extractall(extract_dir)
            # Single top-level directory expected.
            tops = [p for p in extract_dir.iterdir() if p.is_dir()]
            if len(tops) != 1:
                raise SystemExit(f"Unexpected Node archive layout under {extract_dir}")
            if dest.exists():
                shutil.rmtree(dest)
            shutil.move(str(tops[0]), str(dest))
    except Exception as exc:  # noqa: BLE001 — surface actionable install failure
        raise SystemExit(
            f"Node auto-download failed ({exc}).\n"
            "On Windows, install Node 20 LTS manually into the shared root:\n"
            f"  1. Download https://nodejs.org/dist/v{NODE_VERSION}/node-v{NODE_VERSION}-win-x64.zip\n"
            f"  2. Extract so that {root / 'tools' / 'node' / 'node.exe'} exists\n"
            "  3. Re-run: python scripts/aasi/install_shared_env.py --skip-python --promptfoo-only\n"
            "Or pass --skip-node and follow docs/ai_security/AASI_V51_INSTALL.md."
        ) from exc
    if not node_exe(root).is_file():
        raise SystemExit(f"Node extract finished but binary missing: {node_exe(root)}")
    print(f"OK: Node installed at {node_exe(root)}")


def install_promptfoo(root: Path) -> int:
    if not COMMITTED_PACKAGE_JSON.is_file():
        raise SystemExit(f"Missing committed pin file: {COMMITTED_PACKAGE_JSON}")
    npm_root = root / "npm"
    npm_root.mkdir(parents=True, exist_ok=True)
    dest_pkg = npm_root / "package.json"
    shutil.copy2(COMMITTED_PACKAGE_JSON, dest_pkg)
    print(f"==> npm install in {npm_root} (promptfoo@{PROMPTFOO_VERSION})")
    env = os.environ.copy()
    # Keep npm cache under shared root; never use a second Python venv.
    env["npm_config_cache"] = str(root / "cache" / "npm")
    (root / "cache" / "npm").mkdir(parents=True, exist_ok=True)
    # Windows npm.cmd / node-gyp resolve `node` from PATH. System Node (e.g. 24)
    # breaks better-sqlite3 prebuilds for the pinned Promptfoo Node 20 engine.
    bdir = str(node_bin_dir(root))
    path_sep = ";" if platform.system() == "Windows" else ":"
    env["PATH"] = bdir + path_sep + env.get("PATH", "")
    env["npm_config_scripts_prepend_node_path"] = "true"
    nexe = node_exe(root)
    if nexe.is_file():
        print(f"OK: using shared Node for npm: {nexe}")
        ver = subprocess.run(
            [str(nexe), "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        if ver.stdout.strip():
            print(f"OK: shared Node reports {ver.stdout.strip()}")
    cmd = npm_cmd(root) + ["install", "--omit=dev", "--no-fund", "--no-audit"]
    proc = subprocess.run(cmd, cwd=str(npm_root), env=env)
    return proc.returncode


def write_manifests(root: Path, py: Path | None, *, node_ok: bool, promptfoo_ok: bool) -> None:
    manifests = root / "manifests"
    manifests.mkdir(parents=True, exist_ok=True)
    python_info: dict = {
        "written_at": _utc_now(),
        "shared_env_root": str(root),
        "python_executable": str(py) if py else None,
        "ai_scanners_extra": "ai-scanners",
        "pins": list(AI_SCANNER_PINS),
        "openai_policy": "prefer_openai_3_for_pyrit",
        "garak_install": "pip install --no-deps (REST/Anthropic/LiteLLM; OpenAI generator unsupported)",
        "note": "Exactly one venv at <root>/venv. Promptfoo is npm-only.",
    }
    if py and py.is_file():
        try:
            ver = subprocess.check_output([str(py), "--version"], text=True).strip()
            python_info["python_version"] = ver
        except subprocess.CalledProcessError:
            python_info["python_version"] = None
        for name in ("garak", "safelabs-eval", "pyrit"):
            try:
                out = subprocess.check_output(
                    [str(py), "-m", "pip", "show", name],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
                version_line = next(
                    (ln.split(":", 1)[1].strip() for ln in out.splitlines() if ln.startswith("Version:")),
                    None,
                )
                python_info.setdefault("installed", {})[name] = version_line
            except (subprocess.CalledProcessError, FileNotFoundError):
                python_info.setdefault("installed", {})[name] = None
    (manifests / "python-runtime.json").write_text(
        json.dumps(python_info, indent=2) + "\n", encoding="utf-8"
    )
    for tool, pin in (
        ("garak", "garak==0.17.1"),
        ("safelabs", "safelabs-eval==0.12.0"),
        ("pyrit", "pyrit==1.2.1"),
    ):
        payload = {
            "tool": tool,
            "pin": pin,
            "written_at": _utc_now(),
            "install_channel": "pip",
            "shared_venv": str(root / "venv"),
        }
        if py and python_info.get("installed"):
            key = pin.split("==", 1)[0]
            payload["installed_version"] = python_info["installed"].get(key)
        (manifests / f"{tool}.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    pf = {
        "tool": "promptfoo",
        "pin": f"promptfoo@{PROMPTFOO_VERSION}",
        "written_at": _utc_now(),
        "install_channel": "npm",
        "package_json": str(root / "npm" / "package.json"),
        "node_home": str(root / "tools" / "node"),
        "node_ok": node_ok,
        "promptfoo_ok": promptfoo_ok,
        "node_version_target": NODE_VERSION,
    }
    if node_ok and node_exe(root).is_file():
        try:
            pf["node_version"] = subprocess.check_output(
                [str(node_exe(root)), "--version"], text=True
            ).strip()
        except subprocess.CalledProcessError:
            pf["node_version"] = None
    (manifests / "promptfoo.json").write_text(json.dumps(pf, indent=2) + "\n", encoding="utf-8")
    print(f"OK: wrote manifests under {manifests}")


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Install AASI V5.1 shared scanner environment")
    p.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Shared env root (default: $ATTESTRA_SHARED_ENV_ROOT or .attestra-runtime)",
    )
    p.add_argument("--skip-python", action="store_true", help="Skip venv create / pip install")
    p.add_argument("--skip-node", action="store_true", help="Skip Node download/extract")
    p.add_argument("--skip-promptfoo", action="store_true", help="Skip npm install for Promptfoo")
    p.add_argument(
        "--promptfoo-only",
        action="store_true",
        help="Only ensure layout + Node (unless --skip-node) + npm Promptfoo + manifests",
    )
    p.add_argument("--force-node", action="store_true", help="Re-download Node even if present")
    p.add_argument("--no-upgrade-pip", action="store_true", help="Do not upgrade pip first")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.promptfoo_only:
        args.skip_python = True
    root = resolve_root(args.root)
    print(f"ATTESTRA_SHARED_ENV_ROOT={root}")
    ensure_layout(root)

    py: Path | None = None
    rc = 0
    if not args.skip_python:
        py = ensure_venv(root)
        # Guard: never create a second venv name.
        if (root / "venv-scanners").exists() or (root / "scanner-venv").exists():
            raise SystemExit("Extra scanner venv directories are forbidden under the shared root.")
        pip_rc = pip_install_ai_scanners(py, upgrade_pip=not args.no_upgrade_pip)
        if pip_rc != 0:
            rc = pip_rc
            print(
                "FAIL: shared-venv AI scanner install. "
                "See docs/ai_security/AASI_V51_DEPENDENCIES.md "
                "(openai 3.x + Garak --no-deps policy)."
            )
    else:
        candidate = venv_python(root)
        py = candidate if candidate.is_file() else None

    node_ok = False
    if not args.skip_node:
        try:
            download_node(root, force=args.force_node)
            node_ok = node_exe(root).is_file()
        except SystemExit as exc:
            print(str(exc))
            node_ok = False
            rc = rc or 1
    else:
        node_ok = node_exe(root).is_file()
        if node_ok:
            print(f"OK: using existing Node at {node_exe(root)}")
        else:
            print(
                "SKIP: Node (--skip-node). Manual Windows steps are in "
                "docs/ai_security/AASI_V51_INSTALL.md"
            )

    promptfoo_ok = False
    if not args.skip_promptfoo:
        if not node_ok:
            print("SKIP: Promptfoo npm install requires Node under tools/node")
            rc = rc or 1
        else:
            pf_rc = install_promptfoo(root)
            promptfoo_ok = pf_rc == 0
            if pf_rc != 0:
                rc = pf_rc
                print("FAIL: npm install for Promptfoo")
            else:
                print(f"OK: Promptfoo@{PROMPTFOO_VERSION} under {root / 'npm'}")

    write_manifests(root, py, node_ok=node_ok, promptfoo_ok=promptfoo_ok)
    print("Done. Never use docker pull for AI scanners. Never create a second venv.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
