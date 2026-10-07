"""Security layer: JWT authentication, role authorisation, rate limiting."""

from .auth import (
    CONTROL_ROLES,
    AuthContext,
    Authenticator,
    AuthError,
    ConnectionRateLimiter,
    JwksError,
    Role,
    TokenBucket,
    TokenClaimsError,
    TokenExpiredError,
    TokenInvalidError,
    TokenMissingError,
    build_rate_limiter,
    extract_ws_token,
)

__all__ = [
    "CONTROL_ROLES",
    "AuthContext",
    "AuthError",
    "Authenticator",
    "ConnectionRateLimiter",
    "JwksError",
    "Role",
    "TokenBucket",
    "TokenClaimsError",
    "TokenExpiredError",
    "TokenInvalidError",
    "TokenMissingError",
    "build_rate_limiter",
    "extract_ws_token",
]
