"""C11: SOC 2 Type II population and sample export.

A Type II auditor tests a control over a period by picking a sample from the full
population of occurrences. This module builds that population from engagement
records, picks a reproducible seeded sample, and exports both as CSV or JSON.

Sample sizes follow a documented population-size table (SAMPLE_SIZE_TABLE), in line
with common Type II practice. The auditor may override the size. The same
engagement, population, period and seed always yield the same sample.
"""
# @lat: [[compliance]]

from __future__ import annotations

import csv
import hashlib
import io
import random
from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import services
from attestra.models import OPEN_STATUSES, Finding

METHOD = "simple random sampling without replacement (Python random.Random(seed).sample over population sorted by id)"

# (max population size inclusive, sample size). None means sample the whole population.
SAMPLE_SIZE_TABLE: tuple[tuple[int, int | None], ...] = (
    (2, None),  # tiny populations: test every item
    (4, 2),  # quarterly-type frequency
    (12, 2),  # monthly-type frequency
    (52, 5),  # weekly-type frequency
    (250, 25),  # daily-type frequency
    (10**12, 40),  # many times per day
)

POPULATIONS = {
    "findings": "Every reportable finding identified in the engagement (false positives excluded). Supports CC7.1/CC4.1.",
    "remediations": "Every finding that left an open status (fixed, retested, closed or risk-accepted). Supports CC7.4/CC7.5.",
}

FIELDS = ["id", "title", "severity", "status", "cwe", "first_seen", "last_seen", "sla_due", "ticket_ref", "validated_by"]


def sample_size_for(population_size: int) -> int:
    """Documented sample size for a population of this size (see SAMPLE_SIZE_TABLE)."""
    if population_size <= 0:
        return 0
    for limit, size in SAMPLE_SIZE_TABLE:
        if population_size <= limit:
            return population_size if size is None else min(size, population_size)
    return population_size


def default_seed(engagement_id: int, population: str, period_start: date | None, period_end: date | None) -> int:
    raw = f"attestra-soc2:{engagement_id}:{population}:{period_start or ''}:{period_end or ''}"
    return int(hashlib.sha256(raw.encode()).hexdigest()[:12], 16)


def _row(f: Finding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "status": f.status,
        "cwe": f.cwe,
        "first_seen": f.first_seen.date().isoformat() if f.first_seen else "",
        "last_seen": f.last_seen.date().isoformat() if f.last_seen else "",
        "sla_due": f.sla_due.isoformat() if f.sla_due else "",
        "ticket_ref": f.ticket_ref or "",
        "validated_by": f.validated_by or "",
    }


def build_population(
    s: Session, engagement_id: int, population: str = "findings",
    period_start: date | None = None, period_end: date | None = None,
) -> list[dict]:
    if population not in POPULATIONS:
        raise services.ServiceError(f"population must be one of {sorted(POPULATIONS)}")
    if period_start and period_end and period_start > period_end:
        raise services.ServiceError("period_start must be on or before period_end")
    services.get_engagement(s, engagement_id)
    rows = []
    for f in s.scalars(select(Finding).where(Finding.engagement_id == engagement_id).order_by(Finding.id)):
        if f.status == "false_positive":
            continue
        if population == "remediations" and f.status in OPEN_STATUSES:
            continue
        seen = f.first_seen.date() if f.first_seen else None
        if period_start and (seen is None or seen < period_start):
            continue
        if period_end and (seen is None or seen > period_end):
            continue
        rows.append(_row(f))
    return rows


def build_sample(
    s: Session, engagement_id: int, population: str = "findings", *,
    period_start: date | None = None, period_end: date | None = None,
    seed: int | None = None, size: int | None = None,
) -> dict:
    pop = build_population(s, engagement_id, population, period_start, period_end)
    seed = default_seed(engagement_id, population, period_start, period_end) if seed is None else int(seed)
    documented = sample_size_for(len(pop))
    if size is not None and size < 0:
        raise services.ServiceError("size must be zero or more")
    n = documented if size is None else min(size, len(pop))
    picked = sorted(random.Random(seed).sample([r["id"] for r in pop], n))
    chosen = set(picked)
    return {
        "engagement_id": engagement_id,
        "population": population,
        "population_description": POPULATIONS[population],
        "period_start": period_start.isoformat() if period_start else None,
        "period_end": period_end.isoformat() if period_end else None,
        "population_size": len(pop),
        "documented_sample_size": documented,
        "sample_size": n,
        "size_overridden": size is not None,
        "seed": seed,
        "method": METHOD,
        "sample_size_table": [
            {"population_up_to": lim, "sample": sz if sz is not None else "all"} for lim, sz in SAMPLE_SIZE_TABLE
        ],
        "sample_ids": picked,
        "population_rows": [{**r, "sampled": r["id"] in chosen} for r in pop],
    }


def to_csv(result: dict) -> str:
    """Population CSV with a `sampled` column, preceded by '#' lines that document
    the seed, method and sizes so the file stands on its own."""
    buf = io.StringIO()
    for k in ("engagement_id", "population", "period_start", "period_end", "population_size",
              "documented_sample_size", "sample_size", "seed", "method"):
        buf.write(f"# {k}: {result[k] if result[k] is not None else ''}\n")
    w = csv.DictWriter(buf, fieldnames=[*FIELDS, "sampled"], lineterminator="\n")
    w.writeheader()
    for r in result["population_rows"]:
        w.writerow({**r, "cwe": r["cwe"] if r["cwe"] is not None else "", "sampled": "yes" if r["sampled"] else "no"})
    return buf.getvalue()