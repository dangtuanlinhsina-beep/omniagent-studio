"""WebSocket handshake authentication & origin policy.

Browsers cannot attach custom headers to a ``WebSocket`` upgrade, so the
credential has to travel in one of three places.  They are tried in this
(most-preferred first) order:

1. ``Sec-WebSocket-Protocol`` — the client offers
   ``["omniagent.v1", "<ticket>"]`` (or the single string
   ``omniagent.v1.jwt.<ticket>``).  The server selects ``omniagent.v1`` on
   ``accept()`` so the token is never echoed back.  **This is the
   recommended transport**: it keeps the credential out of URLs, access logs,
   ``Referer`` headers and browser history.
2. ``Authorization: Bearer <ticket>`` — for non-browser clients (Python
   ``websockets``, mobile, service-to-service).
3. ``?token=<ticket>`` — legacy/dev convenience, gated by
   ``api_ws_token_in_query``.  Discouraged: query strings are logged
   everywhere.

Whatever the transport, the credential should be a **single-use, 60-second,
graph-bound ``ws-ticket``** minted by ``POST /api/auth/ws-ticket`` — not the
user's access token.  See :mod:`omniagent.security.tokens`.

Everything in this module fails *closed*: no credential, bad signature, wrong
type, revoked session, wrong graph, disallowed origin, too many handshakes
from one IP → :class:`WsAuthError`, which the route translates into a close
code (or a pre-``accept()`` HTTP 403).
"""

from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from urllib.parse import urlsplit

from starlette.websockets import WebSocket

from ..sandboxes.browser.config import Settings
from ..sandboxes.browser.models import AppErrorCode, WsCloseCode
from .ratelimit import SlidingWindowCounter
from .roles import Principal, Role, WILDCARD_GRAPH, build_anonymous_principal, coerce_role
from .tokens import (
    TokenError,
    TokenErrorCode,
    TokenService,
    TokenType,
    client_fingerprint,
    token_fingerprint,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CredentialSource",
    "WsAuthError",
    "WsAuthResult",
    "authenticate_message_token",
    "authenticate_websocket",
    "check_origin",
    "client_ip",
    "extract_credentials",
    "get_handshake_limiter",
    "negotiate_subprotocol",
    "record_handshake_attempt",
    "redact_url",
    "required_role_for",
    "reset_handshake_limiter",
    "resolve_principal",
]


class CredentialSource(StrEnum):
    """Where the handshake credential came from (audit + metrics)."""

    SUBPROTOCOL = "subprotocol"
    HEADER = "header"
    QUERY = "query"
    STATIC = "static-token"
    MESSAGE = "message"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class WsCredentials:
    """A raw credential pulled off the handshake, before verification."""

    token: str
    source: CredentialSource
    #: Subprotocol string that must be echoed to ``accept()`` (may be ``None``).
    subprotocol: str | None = None


@dataclass(frozen=True, slots=True)
class WsAuthResult:
    """Successful authentication outcome for one WebSocket connection."""

    principal: Principal
    source: CredentialSource
    subprotocol: str | None
    #: ``True`` when the credential was a single-use ticket (best practice).
    used_ticket: bool
    #: Seconds until the credential expires (``None`` = never).
    expires_in_s: float | None = None


class WsAuthError(Exception):
    """Authentication/authorization failure with wire-level metadata."""

    def __init__(
        self,
        message: str,
        *,
        close_code: int = WsCloseCode.UNAUTHORIZED,
        app_code: int = AppErrorCode.UNAUTHENTICATED,
        pre_accept: bool = True,
        log_level: int = logging.WARNING,
    ) -> None:
        self.message = message
        self.close_code = close_code
        self.app_code = app_code
        #: ``True`` when the socket can be refused before ``accept()`` (the
        #: client then sees a plain HTTP 403 and no resources are allocated).
        self.pre_accept = pre_accept
        self.log_level = log_level
        super().__init__(message)

    @classmethod
    def from_token_error(cls, exc: TokenError) -> WsAuthError:
        """Map a :class:`TokenError` onto close code + app error code."""
        close_code, app_code, pre_accept = _TOKEN_ERROR_MAP.get(
            exc.code,
            (WsCloseCode.UNAUTHORIZED, AppErrorCode.TOKEN_INVALID, True),
        )
        return cls(
            exc.public_message,
            close_code=close_code,
            app_code=app_code,
            pre_accept=pre_accept,
        )


#: TokenErrorCode -> (ws close code, app error code, safe to reject pre-accept)
_TOKEN_ERROR_MAP: Final[dict[TokenErrorCode, tuple[int, int, bool]]] = {
    TokenErrorCode.MISSING: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.UNAUTHENTICATED,
        True,
    ),
    TokenErrorCode.TOO_LARGE: (
        WsCloseCode.PAYLOAD_TOO_LARGE,
        AppErrorCode.MESSAGE_TOO_LARGE,
        True,
    ),
    TokenErrorCode.MALFORMED: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.TOKEN_INVALID,
        True,
    ),
    TokenErrorCode.SIGNATURE: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.TOKEN_INVALID,
        True,
    ),
    TokenErrorCode.ALGORITHM: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.TOKEN_INVALID,
        True,
    ),
    TokenErrorCode.EXPIRED: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.TOKEN_EXPIRED,
        True,
    ),
    TokenErrorCode.IMMATURE: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.TOKEN_INVALID,
        True,
    ),
    TokenErrorCode.AUDIENCE: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.TOKEN_INVALID,
        True,
    ),
    TokenErrorCode.ISSUER: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.TOKEN_INVALID,
        True,
    ),
    TokenErrorCode.SUBJECT: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.TOKEN_INVALID,
        True,
    ),
    TokenErrorCode.TYPE: (
        WsCloseCode.FORBIDDEN,
        AppErrorCode.FORBIDDEN,
        False,
    ),
    TokenErrorCode.REPLAYED: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.TOKEN_REPLAYED,
        False,
    ),
    TokenErrorCode.REVOKED: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.TOKEN_INVALID,
        False,
    ),
    TokenErrorCode.BINDING: (
        WsCloseCode.FORBIDDEN,
        AppErrorCode.FORBIDDEN,
        False,
    ),
    TokenErrorCode.GRAPH: (
        WsCloseCode.FORBIDDEN,
        AppErrorCode.GRAPH_FORBIDDEN,
        False,
    ),
    TokenErrorCode.CLAIM: (
        WsCloseCode.UNAUTHORIZED,
        AppErrorCode.TOKEN_INVALID,
        True,
    ),
    TokenErrorCode.KEY: (
        WsCloseCode.SERVICE_UNAVAILABLE,
        AppErrorCode.INTERNAL,
        False,
    ),
    TokenErrorCode.DISABLED: (
        WsCloseCode.SERVICE_UNAVAILABLE,
        AppErrorCode.INTERNAL,
        False,
    ),
}


# ---------------------------------------------------------------------------
# Request metadata helpers
# ---------------------------------------------------------------------------


def client_ip(websocket: WebSocket, settings: Settings) -> str:
    """Best-effort client IP.

    ``X-Forwarded-For`` is only honoured when ``api_trust_proxy_headers`` is
    on — otherwise an attacker could rotate the header to evade the handshake
    throttle.  Only the *first* hop is used (that is the client; the rest are
    proxies you chose to trust).
    """
    if settings.api_trust_proxy_headers:
        forwarded = websocket.headers.get("x-forwarded-for", "")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return first
        real_ip = websocket.headers.get("x-real-ip", "").strip()
        if real_ip:
            return real_ip
    client = websocket.client
    return client.host if client else "unknown"


def redact_url(url: str) -> str:
    """Strip credentials and ``token``/``ticket`` query args for safe logging."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:  # pragma: no cover - defensive
        return "<unparsable-url>"
    if not parts.query:
        return url
    kept = [
        kv
        for kv in parts.query.split("&")
        if kv.split("=", 1)[0].lower() not in {"token", "ticket", "access_token", "auth"}
    ]
    query = "&".join(kept)
    rebuilt = parts._replace(query=query, netloc=parts.hostname or "")
    return rebuilt.geturl()


def check_origin(websocket: WebSocket, settings: Settings) -> None:
    """Enforce the ``Origin`` allow-list (cross-site WebSocket hijacking).

    An empty allow-list means "not enforced" — the caller logs a startup
    warning about it.  Requests without an ``Origin`` header (curl, Python
    clients, health probes) are always allowed: origin checks exist to stop
    *browsers* from being weaponised, and a non-browser attacker who already
    holds a valid ticket does not need to forge an origin.
    """
    allowed = settings.api_ws_allowed_origins
    if not allowed and not settings.api_ws_allowed_origin_regex:
        return

    origin = (websocket.headers.get("origin") or "").strip()
    if not origin:
        return

    if origin in allowed or "*" in allowed:
        return
    # Compare without trailing slashes / case differences in the scheme+host.
    normalized = origin.rstrip("/").lower()
    for candidate in allowed:
        if candidate.rstrip("/").lower() == normalized:
            return
    pattern = settings.api_ws_allowed_origin_regex
    if pattern:
        try:
            if re.fullmatch(pattern, origin):
                return
        except re.error as exc:
            logger.error("invalid OMNIAGENT_API_WS_ALLOWED_ORIGIN_REGEX: %s", exc)

    logger.warning(
        "rejecting websocket handshake from disallowed origin %r (ip=%s)",
        origin,
        client_ip(websocket, settings),
    )
    raise WsAuthError(
        "origin not allowed",
        close_code=WsCloseCode.FORBIDDEN,
        app_code=AppErrorCode.FORBIDDEN,
        pre_accept=True,
    )


def negotiate_subprotocol(
    websocket: WebSocket, settings: Settings
) -> tuple[str | None, str | None]:
    """Split ``Sec-WebSocket-Protocol`` into ``(token, protocol_to_echo)``.

    Supported client forms::

        # 1. recommended — token never echoed back
        WebSocket(url, ["omniagent.v1", "<ticket>"])        -> echo "omniagent.v1"

        # 2. single-string form (Kubernetes style) — must be echoed verbatim
        WebSocket(url, ["omniagent.v1.jwt.<ticket>"])       -> echo the same string

    Returns ``(None, None)`` when the client offered nothing usable.  Note
    that RFC 6455 requires the server to select one of the offered values or
    none at all; selecting an unknown value makes browsers abort with 1006.
    """
    offered = [p.strip() for p in websocket.headers.get("sec-websocket-protocol", "").split(",")]
    offered = [p for p in offered if p]
    if not offered:
        return None, None

    known = list(settings.api_ws_subprotocols)

    # Form 1: [<known-protocol>, <token>]
    if len(offered) >= 2 and offered[0] in known:
        token = offered[1]
        if _looks_like_token(token):
            return token, offered[0]

    # Form 2: "omniagent.v1.jwt.<token>" (prefix + token in one entry)
    for entry in offered:
        for base in known:
            prefix = f"{base}.jwt."
            if entry.startswith(prefix) and _looks_like_token(entry[len(prefix) :]):
                return entry[len(prefix) :], entry

    # The client offered only known protocol names (token came from elsewhere).
    for entry in offered:
        if entry in known:
            return None, entry
    return None, None


def _looks_like_token(value: str) -> bool:
    """Cheap shape test: JWTs have 3 dot-separated base64url segments."""
    if not value or len(value) < 16 or " " in value:
        return False
    parts = value.split(".")
    return len(parts) >= 2 and all(parts)


def extract_credentials(
    websocket: WebSocket, settings: Settings
) -> tuple[WsCredentials | None, str | None]:
    """Locate the handshake credential.

    Returns ``(credentials, subprotocol_to_echo)``.  ``credentials`` is
    ``None`` when no credential was supplied at all.  The subprotocol is
    returned separately because it must be echoed on ``accept()`` even when
    the credential came from a header.
    """
    token, subprotocol = negotiate_subprotocol(websocket, settings)
    if token:
        return (
            WsCredentials(token=token, source=CredentialSource.SUBPROTOCOL, subprotocol=subprotocol),
            subprotocol,
        )

    header = websocket.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        bearer = header[7:].strip()
        if bearer:
            return (
                WsCredentials(
                    token=bearer, source=CredentialSource.HEADER, subprotocol=subprotocol
                ),
                subprotocol,
            )

    if settings.api_ws_token_in_query:
        query_token = websocket.query_params.get("token") or websocket.query_params.get("ticket")
        if query_token:
            logger.warning(
                "credential supplied via query string (ip=%s); prefer "
                "Sec-WebSocket-Protocol and set OMNIAGENT_API_WS_TOKEN_IN_QUERY=false",
                client_ip(websocket, settings),
            )
            return (
                WsCredentials(
                    token=query_token,
                    source=CredentialSource.QUERY,
                    subprotocol=subprotocol,
                ),
                subprotocol,
            )

    return None, subprotocol


# ---------------------------------------------------------------------------
# Handshake throttling
# ---------------------------------------------------------------------------

_handshake_limiter: SlidingWindowCounter | None = None
_limiter_lock = threading.Lock()


def get_handshake_limiter(settings: Settings | None = None) -> SlidingWindowCounter:
    """Process-wide handshake throttle (per client IP), built from settings."""
    global _handshake_limiter
    with _limiter_lock:
        if _handshake_limiter is None:
            cfg = settings or Settings()
            _handshake_limiter = SlidingWindowCounter(
                limit=cfg.api_ws_handshake_rate_limit,
                window_s=cfg.api_ws_handshake_window_s,
                max_keys=20_000,
            )
        return _handshake_limiter


def reset_handshake_limiter() -> None:
    """Drop the cached limiter (tests / settings reload)."""
    global _handshake_limiter
    with _limiter_lock:
        _handshake_limiter = None


def record_handshake_attempt(
    websocket: WebSocket, settings: Settings
) -> None:
    """Charge one handshake attempt; raise on flood.

    Runs *before* ``accept()`` so an attacker cannot make the server allocate
    a streamer/CDP session per attempt.
    """
    limiter = get_handshake_limiter(settings)
    ip = client_ip(websocket, settings)
    allowed, retry_after, hits = limiter.hit(f"ws:{ip}")
    if not allowed:
        logger.warning(
            "handshake throttled: ip=%s hits=%d limit=%d/%.0fs",
            ip,
            hits,
            settings.api_ws_handshake_rate_limit,
            settings.api_ws_handshake_window_s,
        )
        raise WsAuthError(
            "too many connection attempts; slow down",
            close_code=WsCloseCode.TOO_MANY_REQUESTS,
            app_code=AppErrorCode.CONNECTION_LIMIT,
            pre_accept=True,
            log_level=logging.WARNING,
        )


# ---------------------------------------------------------------------------
# Principal resolution
# ---------------------------------------------------------------------------


def _legacy_static_principal(
    provided: str, settings: Settings
) -> Principal | None:
    """Validate the legacy shared static token (constant-time)."""
    expected = settings.api_ws_auth_token
    if not expected or not provided:
        return None
    if not secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        return None
    role = coerce_role(settings.api_ws_static_token_role)
    logger.warning(
        "authenticated with the legacy static token (role=%s); this credential "
        "has no identity, no expiry and cannot be revoked — migrate to JWT",
        role.value,
    )
    return Principal(
        subject="<static-token>",
        role=role,
        graph_ids=(WILDCARD_GRAPH,),
        token_type="static",
    )


def resolve_principal(
    credentials: WsCredentials | None,
    *,
    settings: Settings,
    graph_id: str,
    token_service: TokenService,
    fingerprint: str | None = None,
) -> WsAuthResult:
    """Verify ``credentials`` and return the connection's :class:`WsAuthResult`.

    Raises:
        WsAuthError: for every failure mode, with close/app codes attached.
    """
    if not settings.auth_enabled:
        principal = build_anonymous_principal(coerce_role(settings.auth_anonymous_role))
        logger.warning(
            "authentication disabled (OMNIAGENT_AUTH_ENABLED=false); "
            "accepting %s as %s for graph_id=%s",
            credentials.source.value if credentials else "anonymous",
            principal.describe(),
            graph_id,
        )
        return WsAuthResult(
            principal=principal,
            source=credentials.source if credentials else CredentialSource.NONE,
            subprotocol=credentials.subprotocol if credentials else None,
            used_ticket=False,
        )

    if credentials is None:
        raise WsAuthError("missing authentication credential")

    token = credentials.token.strip()

    # 1) Legacy shared static token (opt-in).
    if settings.auth_allow_legacy_static_token:
        static_principal = _legacy_static_principal(token, settings)
        if static_principal is not None:
            if not static_principal.can_access_graph(graph_id):
                raise WsAuthError(
                    "you are not authorized for this graph",
                    close_code=WsCloseCode.FORBIDDEN,
                    app_code=AppErrorCode.GRAPH_FORBIDDEN,
                    pre_accept=False,
                )
            return WsAuthResult(
                principal=static_principal,
                source=CredentialSource.STATIC,
                subprotocol=credentials.subprotocol,
                used_ticket=False,
            )

    # 2) JWT — try the single-use ws-ticket first, then a plain access token.
    errors: list[TokenError] = []
    for token_type in (TokenType.WS_TICKET, TokenType.ACCESS):
        try:
            principal = token_service.verify(
                token,
                expected_type=token_type,
                graph_id=graph_id,
                fingerprint=fingerprint,
            )
        except TokenError as exc:
            errors.append(exc)
            # A signature/expiry failure is final: no point trying the other
            # flavour (and it would burn the single-use check on a bad token).
            if exc.code not in (TokenErrorCode.TYPE,):
                raise WsAuthError.from_token_error(exc) from exc
            continue

        effective_exp = principal.effective_expires_at
        expires_in = max(0.0, effective_exp - _now()) if effective_exp else None
        logger.info(
            "websocket auth ok: %s graph_id=%s token=%s type=%s source=%s ttl=%.0fs",
            principal.describe(),
            graph_id,
            token_fingerprint(token),
            token_type.value,
            credentials.source.value,
            expires_in or -1.0,
        )
        return WsAuthResult(
            principal=principal,
            source=credentials.source,
            subprotocol=credentials.subprotocol,
            used_ticket=token_type is TokenType.WS_TICKET,
            expires_in_s=expires_in,
        )

    raise WsAuthError.from_token_error(errors[-1] if errors else TokenError(TokenErrorCode.MISSING))


def authenticate_message_token(
    token: str,
    *,
    settings: Settings,
    graph_id: str,
    token_service: TokenService,
    fingerprint: str | None = None,
    current: Principal,
) -> WsAuthResult:
    """Verify a credential sent *inside* an established connection (``AUTH``).

    The replacement principal must keep access to the same graph; a role
    downgrade is allowed (it just removes capabilities), but changing
    ``sub`` mid-connection is rejected — otherwise a stolen VIEWER socket
    could be hijacked into somebody else's session.
    """
    result = resolve_principal(
        WsCredentials(token=token, source=CredentialSource.MESSAGE),
        settings=settings,
        graph_id=graph_id,
        token_service=token_service,
        fingerprint=fingerprint,
    )
    if result.principal.subject != current.subject and not current.is_service:
        logger.warning(
            "AUTH attempted to switch identity %s -> %s on graph_id=%s; refused",
            current.describe(),
            result.principal.describe(),
            graph_id,
        )
        raise WsAuthError(
            "cannot switch identity on an established connection",
            close_code=WsCloseCode.FORBIDDEN,
            app_code=AppErrorCode.FORBIDDEN,
            pre_accept=False,
        )
    return result


def authenticate_websocket(
    websocket: WebSocket,
    *,
    settings: Settings,
    graph_id: str,
    token_service: TokenService,
) -> WsAuthResult:
    """Full handshake authentication: origin -> throttle -> credential -> JWT.

    ``check_origin`` and ``record_handshake_attempt`` are expected to have run
    before ``accept()``; calling this function repeats nothing expensive, it
    only resolves the principal.
    """
    fingerprint = None
    if settings.jwt_ticket_bind_client:
        fingerprint = client_fingerprint(
            client_ip(websocket, settings), websocket.headers.get("user-agent")
        )
    credentials, _subprotocol = extract_credentials(websocket, settings)
    return resolve_principal(
        credentials,
        settings=settings,
        graph_id=graph_id,
        token_service=token_service,
        fingerprint=fingerprint,
    )


def required_role_for(message_type: str) -> Role | None:
    """Minimum role for an inbound message type (``None`` = anyone)."""
    return _MESSAGE_ROLE_REQUIREMENTS.get(message_type.upper())


_MESSAGE_ROLE_REQUIREMENTS: Final[dict[str, Role]] = {
    "SET_TAKEOVER": Role.OPERATOR,
    "MOUSE_EVENT": Role.OPERATOR,
    "KEYBOARD_EVENT": Role.OPERATOR,
    "PING": Role.VIEWER,
    "AUTH": Role.VIEWER,
}


def _now() -> float:
    return time.time()
