"""Identity: users, API keys, roles, optional OIDC."""

from attestra.auth.keys import Principal, authenticate_api_key, create_api_key, generate_api_key, hash_api_key
from attestra.auth.roles import PERMISSIONS, has_permission

__all__ = [
    "PERMISSIONS",
    "Principal",
    "authenticate_api_key",
    "create_api_key",
    "generate_api_key",
    "has_permission",
    "hash_api_key",
]
