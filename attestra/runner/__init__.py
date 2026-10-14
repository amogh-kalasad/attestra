"""Runner plane: authorize targets, pin DNS, dispatch scanners under engagement scope."""

from attestra.runner.authorization import AuthorizationError, AuthorizedScope, authorize_target, scope_for_engagement

__all__ = [
    "AuthorizationError",
    "AuthorizedScope",
    "authorize_target",
    "scope_for_engagement",
]
