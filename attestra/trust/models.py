"""Trust center tables (migration 0011_trust_center)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from attestra.db import Base
from attestra.models import utcnow

ITEM_KINDS = ("framework", "report", "badge", "document", "finding", "evidence")
ACCESS_LEVELS = ("public", "nda")
REQUEST_STATUSES = ("pending", "approved", "denied")


class TrustCenter(Base):
    __tablename__ = "trust_centers"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), unique=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    title: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[str] = mapped_column(String(200), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TrustItem(Base):
    __tablename__ = "trust_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    kind: Mapped[str] = mapped_column(String(20))
    ref_id: Mapped[int | None] = mapped_column(Integer)
    ref_key: Mapped[str] = mapped_column(String(100), default="")
    title: Mapped[str] = mapped_column(String(300))
    summary: Mapped[str] = mapped_column(Text, default="")
    access: Mapped[str] = mapped_column(String(10), default="public")
    path: Mapped[str] = mapped_column(String(500), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    published: Mapped[bool] = mapped_column(Boolean, default=True)
    published_by: Mapped[str] = mapped_column(String(200), default="")
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TrustAccessRequest(Base):
    __tablename__ = "trust_access_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    item_id: Mapped[int] = mapped_column(ForeignKey("trust_items.id"))
    requester_name: Mapped[str] = mapped_column(String(200))
    requester_email: Mapped[str] = mapped_column(String(200))
    company: Mapped[str] = mapped_column(String(200), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    nda_accepted: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(10), default="pending")
    token_hash: Mapped[str] = mapped_column(String(64), default="")
    decided_by: Mapped[str] = mapped_column(String(200), default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
