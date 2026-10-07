"""Security layer of OmniAgent Studio.

Public surface (import from ``omniagent.security``)::

    from omniagent.security import (
        Principal, Role, Permission, TokenService, get_token_service,
        authenticate_websocket, WsAuthError, ConnectionRateLimiter,
    )

Sub-modules
-----------
:mod:`~omniagent.security.roles`
    Role/permission model and the immutable :class:`Principal`.
:mod:`~omniagent.security.tokens`
    JWT issuing/verification (access, refresh, single-use ``ws-ticket``).
:mod:`~omniagent.security.ws_auth`
    WebSocket handshake authentication (subprotocol / header / query), origin
    policy and handshake throttling.
:mod:`~omniagent.security.ratelimit`
    Token buckets, ``mousemove`` coalescing, sliding windows — the anti-DoS
    shield in front of the CDP input path.
:mod:`~omniagent.security.user_store`
    PBKDF2 password hashing and the reference user directory.
"""

from __future__ import annotations

from .ratelimit import (
    ConnectionRateLimiter,
    MouseMoveCoalescer,
    RateLimitDecision,
    RateLimitPolicy,
    SharedLimiterRegistry,
    SlidingWindowCounter,
    ThrottleStats,
    TokenBucket,
    get_graph_input_registry,
)
from .roles import (
    ANONYMOUS_SUBJECT,
    WILDCARD_GRAPH,
    Permission,
    Principal,
    Role,
    build_anonymous_principal,
    coerce_role,
    normalize_graph_ids,
    permissions_for,
    role_level,
)
from .tokens import (
    IssuedToken,
    SecurityConfigError,
    TokenError,
    TokenErrorCode,
    TokenService,
    TokenType,
    client_fingerprint,
    get_token_service,
    reset_token_service,
    token_fingerprint,
)
from .user_store import (
    InMemoryUserStore,
    LoginThrottle,
    PasswordPolicyError,
    UnknownUserError,
    UserConflictError,
    UserRecord,
    UserStore,
    get_login_throttle,
    get_user_store,
    hash_password,
    verify_password,
)
from .ws_auth import (
    CredentialSource,
    WsAuthError,
    WsAuthResult,
    WsCredentials,
    authenticate_message_token,
    authenticate_websocket,
    check_origin,
    client_ip,
    extract_credentials,
    negotiate_subprotocol,
    record_handshake_attempt,
    redact_url,
    required_role_for,
    resolve_principal,
)

__all__ = [
    "ANONYMOUS_SUBJECT",
    "ConnectionRateLimiter",
    "CredentialSource",
    "InMemoryUserStore",
    "IssuedToken",
    "LoginThrottle",
    "MouseMoveCoalescer",
    "PasswordPolicyError",
    "Permission",
    "Principal",
    "RateLimitDecision",
    "RateLimitPolicy",
    "Role",
    "SecurityConfigError",
    "SharedLimiterRegistry",
    "SlidingWindowCounter",
    "ThrottleStats",
    "TokenBucket",
    "TokenError",
    "TokenErrorCode",
    "TokenService",
    "TokenType",
    "UnknownUserError",
    "UserConflictError",
    "UserRecord",
    "UserStore",
    "WILDCARD_GRAPH",
    "WsAuthError",
    "WsAuthResult",
    "WsCredentials",
    "authenticate_message_token",
    "authenticate_websocket",
    "build_anonymous_principal",
    "check_origin",
    "client_fingerprint",
    "client_ip",
    "coerce_role",
    "extract_credentials",
    "get_graph_input_registry",
    "get_login_throttle",
    "get_token_service",
    "get_user_store",
    "hash_password",
    "negotiate_subprotocol",
    "normalize_graph_ids",
    "permissions_for",
    "record_handshake_attempt",
    "redact_url",
    "required_role_for",
    "reset_token_service",
    "resolve_principal",
    "role_level",
    "token_fingerprint",
    "verify_password",
]
