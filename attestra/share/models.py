"""Share-link table (migration 0019_share_links)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from attestra.db import Base
from attestra.models import utcnow

SHARE_KINDS = ("grade", "scan")


class ShareLink(Base):
    """Read-only public share for one target grade or one scan result.

    Only ``token_hash`` is stored — the raw token is returned once at create time.
    """

    __tablename__ = "share_links"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    kind: Mapped[str] = mapped_column(String(10))  # grade | scan
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"))
    scan_run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[str] = mapped_column(String(200), default="")
    created_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str] = mapped_column(String(200), default="")
    last_viewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_viewed_ip: Mapped[str] = mapped_column(String(64), default="")
    last_view_audit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
