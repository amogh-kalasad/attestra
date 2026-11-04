"""BSON helpers: UTC datetimes and document shaping with integer ids."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any


def utcnow() -> datetime:
    return datetime.now(UTC)


def ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def date_to_datetime(value: date | datetime | None) -> datetime | None:
    """Store calendar dates as UTC midnight for BSON Date fields."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return ensure_utc(value)
    return datetime(value.year, value.month, value.day, tzinfo=UTC)


def datetime_to_date(value: datetime | date | None) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return ensure_utc(value).date()
    return value


def with_id(doc: dict[str, Any]) -> dict[str, Any]:
    """Ensure public ``id`` mirrors integer ``_id``."""
    out = dict(doc)
    if "_id" in out and "id" not in out:
        out["id"] = out["_id"]
    return out


def strip_none(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in doc.items() if v is not None}
