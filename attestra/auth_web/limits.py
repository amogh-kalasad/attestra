"""Conservative crawl budget defaults for authenticated website security testing."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CrawlLimits:
    """Depth/page/time/concurrency/rate ceilings for a controlled crawl.

    Defaults stay passive and small so baseline authenticated inventory stays
    inside engagement windows without hammering the target.
    """

    max_routes: int = 50
    max_depth: int = 3
    max_duration_s: float = 120.0
    rate_per_host: float = 2.0  # requests per second per host
    concurrency: int = 2
    timeout_s: float = 15.0

    def __post_init__(self) -> None:
        if self.max_routes < 1:
            raise ValueError("max_routes must be >= 1")
        if self.max_depth < 0:
            raise ValueError("max_depth must be >= 0")
        if self.max_duration_s <= 0:
            raise ValueError("max_duration_s must be > 0")
        if self.rate_per_host <= 0:
            raise ValueError("rate_per_host must be > 0")
        if self.concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
