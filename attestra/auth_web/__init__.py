"""Authenticated website crawl, scope, forms, and role-comparison helpers.

Optional engagement workflow for authorized security testing of in-scope web apps.
Crawl and form checks stay non-destructive unless callers set explicit authorize
flags and gate intrusive work through the existing scan gate.
"""

from attestra.auth_web.crawl import (
    CrawlRecord,
    CrawlResult,
    crawl,
    crawl_or_block_without_playwright,
    extract_links,
    is_logout_url,
    normalize_url,
    playwright_available,
)
from attestra.auth_web.forms import (
    ElementInventoryItem,
    FormField,
    FormInventory,
    fill_form_values,
    inventory_elements,
    inventory_forms,
    looks_like_secret,
    may_submit,
    synthetic_value,
)
from attestra.auth_web.limits import CrawlLimits
from attestra.auth_web.roles import (
    IntrusiveProbePlan,
    RoleDiff,
    RoleSnapshot,
    compare_roles,
    is_read_only_comparison,
    plan_object_access_probes,
)
from attestra.auth_web.scope import (
    CrawlScope,
    ScopeError,
    assert_redirect_in_scope,
    assert_url_in_scope,
    is_in_scope,
    is_same_origin,
    origin_of,
    scope_from_seeds,
)
from attestra.auth_web.tamper import (
    TamperRunResult,
    assert_intrusive_allowed,
    plan_and_maybe_execute_probes,
)

__all__ = [
    "CrawlLimits",
    "CrawlRecord",
    "CrawlResult",
    "CrawlScope",
    "ElementInventoryItem",
    "FormField",
    "FormInventory",
    "IntrusiveProbePlan",
    "RoleDiff",
    "RoleSnapshot",
    "ScopeError",
    "TamperRunResult",
    "assert_intrusive_allowed",
    "assert_redirect_in_scope",
    "assert_url_in_scope",
    "compare_roles",
    "crawl",
    "crawl_or_block_without_playwright",
    "extract_links",
    "fill_form_values",
    "inventory_elements",
    "inventory_forms",
    "is_in_scope",
    "is_logout_url",
    "is_read_only_comparison",
    "is_same_origin",
    "looks_like_secret",
    "may_submit",
    "normalize_url",
    "origin_of",
    "plan_and_maybe_execute_probes",
    "plan_object_access_probes",
    "playwright_available",
    "scope_from_seeds",
    "synthetic_value",
]
