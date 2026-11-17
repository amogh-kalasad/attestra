"""Prowler adapter: cloud/Kubernetes posture checks, JSON-OCSF output imported via prowler importer.

F-02 (WP4): before a run the operator sees exactly which read-only permissions Prowler
needs for the chosen provider (:func:`permission_disclosure`). The disclosure is static
text: nothing reads or prints the credentials Prowler will use, and the adapter never
asks for write permissions.
"""
# @lat: [[attack-surface-and-platform#Cloud correlation and Prowler disclosure]]

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, which

PROVIDERS = ("aws", "azure", "gcp", "kubernetes")

# F-02: least-privilege, read-only roles Prowler documents per provider. Shown before a
# run; Attestra never creates, reads or stores these credentials itself.
REQUIRED_PERMISSIONS: dict[str, dict[str, object]] = {
    "aws": {
        "grants": ("arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"),
        "notes": "Read-only managed policies. Prowler's optional extra read policy covers a few newer services.",
        "write_access": False,
    },
    "azure": {
        "grants": ("Reader (subscription scope)", "Microsoft Graph Directory.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All"),
        "notes": "Reader role on each subscription in scope plus read-only Graph API permissions.",
        "write_access": False,
    },
    "gcp": {
        "grants": ("roles/reviewer", "roles/iam.securityReviewer", "roles/serviceusage.serviceUsageConsumer"),
        "notes": "Viewer-style roles on each project in scope.",
        "write_access": False,
    },
    "kubernetes": {
        "grants": ("ClusterRole with get/list/watch on core, rbac and apps resources",),
        "notes": "Read-only ClusterRole bound to the service account Prowler runs as.",
        "write_access": False,
    },
}


def permission_disclosure(provider: str) -> dict[str, object]:
    """F-02: what Prowler will be allowed to see for ``provider`` (value-free, no secrets)."""
    p = str(provider or "").strip().lower()
    if p not in PROVIDERS:
        raise ValueError(f"prowler provider must be one of {PROVIDERS}")
    info = REQUIRED_PERMISSIONS[p]
    return {
        "provider": p,
        "grants": list(info["grants"]),  # type: ignore[arg-type]
        "write_access": bool(info["write_access"]),
        "notes": str(info["notes"]),
        "summary": (
            f"Prowler checks the {p} configuration with read-only access: "
            + "; ".join(info["grants"])  # type: ignore[arg-type]
            + ". It needs no write permission and Attestra does not store the cloud credentials."
        ),
    }


class ProwlerAdapter(ScannerAdapter):
    name = "prowler"
    import_tool = "prowler"

    def available(self) -> bool:
        return which("prowler") is not None

    def version(self) -> str:
        return "prowler"

    def scan(self, pin, *, out_dir, cancel=None, profile="baseline", **opts):  # type: ignore[override]
        """Run as usual and attach the F-02 permission disclosure to ``result.extra``."""
        sr = super().scan(pin, out_dir=out_dir, cancel=cancel, profile=profile, **opts)
        try:
            sr.extra.setdefault("permission_disclosure", permission_disclosure(str(pin)))
        except ValueError:
            pass
        return sr

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if isinstance(target, PinnedTarget):
            raise ValueError("prowler expects a cloud provider name, not a URL pin")
        provider = str(target).strip().lower()
        if provider not in PROVIDERS:
            raise ValueError(f"prowler provider must be one of {PROVIDERS}")
        return [
            "prowler",
            provider,
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            str(out_file.parent),
            "--output-filename",
            out_file.stem,
            "--no-banner",
        ]

    def resolve_output(self, out_file: Path) -> Path:
        # Prowler appends its own extension (e.g. <stem>.ocsf.json).
        if out_file.exists():
            return out_file
        matches = sorted(out_file.parent.glob(f"{out_file.stem}*.json"))
        return matches[0] if matches else out_file
