"""JWT issuing & verification for HTTP endpoints and WebSocket handshakes.

Token flavours
--------------
``access``    Short-lived (default 15 min) bearer token proving a login.
              Sent as ``Authorization: Bearer`` to the REST API.  It is never
              handed to the browser's ``WebSocket`` constructor.
``refresh``   Longer-lived (default 12 h) token used only against
              ``POST /api/auth/refresh`` to mint a new access token.
``ws-ticket`` **Single-use**, very short-lived (default 60 s) ticket minted by
              ``POST /api/auth/ws-ticket`` for exactly one ``graph_id`` and
              consumed during the WebSocket handshake.  This is what actually
              travels over ``Sec-WebSocket-Protocol`` (browsers cannot set
              custom headers on a WS upgrade), so a leaked URL/header never
              exposes the real session token and cannot be replayed.

Hardening rules implemented here
--------------------------------
* Explicit algorithm allow-list (``alg: none`` and algorithm-confusion are
  rejected by PyJWT when ``algorithms=[…]`` is passed).
* ``iss`` / ``aud`` / ``exp`` / ``nbf`` / ``iat`` / ``sub`` / ``jti`` are all
  **required** claims.
* Symmetric secrets must be >= 256 bits of entropy; asymmetric setups must
  provide a public key.  Misconfiguration raises at import/startup time
  (:class:`SecurityConfigError`) instead of silently disabling auth.
* Replay protection: ``ws-ticket`` JTIs are consumed atomically; revoked JTIs
  and revoked session ids are tracked in a bounded TTL store.
* Optional sender binding (``fp`` claim) ties a ticket to the client that
  requested it.
* Tokens are never logged — use :func:`token_fingerprint` for correlation.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

import jwt
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
    PyJWTError,
)

from ..sandboxes.browser.config import Settings, get_settings
from .roles import Principal, Role, WILDCARD_GRAPH, coerce_role, normalize_graph_ids

logger = logging.getLogger(__name__)

__all__ = [
    "IssuedToken",
    "SecurityConfigError",
    "TokenError",
    "TokenErrorCode",
    "TokenService",
    "TokenType",
    "client_fingerprint",
    "get_token_service",
    "token_fingerprint",
]

#: Minimum entropy (characters) accepted for an HS256/HS384/HS512 secret.
MIN_HMAC_SECRET_CHARS: Final = 43  # 43 base64url chars ~= 256 bits

#: Algorithms this service will ever accept.  ``none`` is not a thing.
ALLOWED_ALGORITHMS: Final[frozenset[str]] = frozenset(
    {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
)


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"
    WS_TICKET = "ws-ticket"


class TokenErrorCode(StrEnum):
    """Machine-readable failure reasons (mapped to HTTP/WS codes upstream)."""

    MISSING = "missing_token"
    TOO_LARGE = "token_too_large"
    MALFORMED = "malformed_token"
    SIGNATURE = "bad_signature"
    ALGORITHM = "disallowed_algorithm"
    EXPIRED = "token_expired"
    IMMATURE = "token_not_yet_valid"
    AUDIENCE = "bad_audience"
    ISSUER = "bad_issuer"
    SUBJECT = "missing_subject"
    TYPE = "wrong_token_type"
    REPLAYED = "ticket_already_used"
    REVOKED = "token_revoked"
    BINDING = "sender_binding_mismatch"
    GRAPH = "graph_not_authorized"
    CLAIM = "invalid_claim"
    KEY = "signing_key_not_configured"
    DISABLED = "auth_disabled"


class TokenError(Exception):
    """Raised for every authentication failure.

    Carries a stable :class:`TokenErrorCode` plus an HTTP status so both the
    REST layer and the WebSocket layer can translate it consistently.  The
    ``message`` is deliberately generic — it is shown to clients and must not
    disclose why verification failed beyond the coarse category.
    """

    #: Coarse categories that are safe to surface verbatim to a client.
    _PUBLIC: Final[frozenset[TokenErrorCode]] = frozenset(
        {
            TokenErrorCode.MISSING,
            TokenErrorCode.TOO_LARGE,
            TokenErrorCode.EXPIRED,
            TokenErrorCode.REPLAYED,
            TokenErrorCode.REVOKED,
            TokenErrorCode.GRAPH,
            TokenErrorCode.TYPE,
            TokenErrorCode.DISABLED,
        }
    )

    def __init__(
        self,
        code: TokenErrorCode,
        detail: str = "",
        *,
        http_status: int | None = None,
    ) -> None:
        self.code = code
        self.detail = detail
        self.http_status = http_status or _default_http_status(code)
        safe = detail if code in self._PUBLIC else ""
        super().__init__(f"{code.value}{': ' + safe if safe else ''}")

    @property
    def public_message(self) -> str:
        """Client-safe message (never leaks internals)."""
        if self.code in self._PUBLIC and self.detail:
            return self.detail
        return _GENERIC_MESSAGES.get(self.code, "authentication failed")


def _default_http_status(code: TokenErrorCode) -> int:
    if code is TokenErrorCode.MISSING:
        return 401
    if code in (TokenErrorCode.GRAPH, TokenErrorCode.TYPE, TokenErrorCode.DISABLED):
        return 403
    if code is TokenErrorCode.KEY:
        return 503
    return 401


_GENERIC_MESSAGES: Final[dict[TokenErrorCode, str]] = {
    TokenErrorCode.MISSING: "missing authentication token",
    TokenErrorCode.TOO_LARGE: "authentication token is too large",
    TokenErrorCode.MALFORMED: "malformed authentication token",
    TokenErrorCode.SIGNATURE: "invalid authentication token",
    TokenErrorCode.ALGORITHM: "invalid authentication token",
    TokenErrorCode.EXPIRED: "authentication token has expired",
    TokenErrorCode.IMMATURE: "authentication token is not valid yet",
    TokenErrorCode.AUDIENCE: "authentication token is not valid for this service",
    TokenErrorCode.ISSUER: "authentication token was issued by an untrusted issuer",
    TokenErrorCode.SUBJECT: "authentication token has no subject",
    TokenErrorCode.TYPE: "wrong token type for this operation",
    TokenErrorCode.REPLAYED: "this connection ticket has already been used",
    TokenErrorCode.REVOKED: "authentication token has been revoked",
    TokenErrorCode.BINDING: "authentication token is bound to a different client",
    TokenErrorCode.GRAPH: "you are not authorized for this graph",
    TokenErrorCode.CLAIM: "authentication token contains invalid claims",
    TokenErrorCode.KEY: "authentication is not configured on this server",
    TokenErrorCode.DISABLED: "authentication is disabled on this server",
}


class SecurityConfigError(RuntimeError):
    """Fatal misconfiguration of the security layer (fail closed at boot)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def token_fingerprint(token: str) -> str:
    """Short, non-reversible id for a token — safe to write to logs."""
    if not token:
        return "<empty>"
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"{digest[:12]}…"


def client_fingerprint(ip: str | None, user_agent: str | None) -> str:
    """Sender-binding value for a ``ws-ticket``.

    Binds a minted ticket to the client that requested it so a ticket stolen
    from a log/proxy cannot be used from a different machine.  Only enable
    this when the API sees real client IPs (i.e. the proxy sets
    ``X-Forwarded-For`` and uvicorn runs with ``--proxy-headers``), otherwise
    every user behind one NAT egress IP shares a fingerprint anyway.
    """
    material = f"{(ip or '').strip()}|{(user_agent or '').strip()}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# JTI / session store (single-use + revocation)
# ---------------------------------------------------------------------------


class JtiStore:
    """Bounded, TTL-aware set of JWT ids.

    Used for two purposes: (1) single-use enforcement of ``ws-ticket`` JTIs
    and (2) explicit revocation (logout / admin kill-switch) of access tokens
    and whole sessions.  Entries expire on their own, and the store hard-caps
    its size by evicting the entries closest to expiry.
    """

    __slots__ = ("_entries", "_lock", "_max_entries")

    def __init__(self, *, max_entries: int = 16_384) -> None:
        self._entries: dict[str, float] = {}
        self._lock = threading.Lock()
        self._max_entries = max(256, max_entries)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def consume(self, jti: str, ttl_s: float, *, now: float | None = None) -> bool:
        """Atomically record ``jti``; ``True`` only on first use."""
        if not jti:
            return False
        moment = time.time() if now is None else now
        with self._lock:
            self._sweep_locked(moment)
            expiry = self._entries.get(jti)
            if expiry is not None and expiry > moment:
                return False
            self._entries[jti] = moment + max(1.0, ttl_s)
            self._evict_locked()
            return True

    def add(self, jti: str, ttl_s: float, *, now: float | None = None) -> None:
        """Record ``jti`` unconditionally (revocation)."""
        if not jti:
            return
        moment = time.time() if now is None else now
        with self._lock:
            self._entries[jti] = moment + max(1.0, ttl_s)
            self._evict_locked()

    def contains(self, jti: str, *, now: float | None = None) -> bool:
        if not jti:
            return False
        moment = time.time() if now is None else now
        with self._lock:
            expiry = self._entries.get(jti)
            if expiry is None:
                return False
            if expiry <= moment:
                del self._entries[jti]
                return False
            return True

    def remove(self, jti: str) -> None:
        with self._lock:
            self._entries.pop(jti, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    # -- internals ------------------------------------------------------

    def _sweep_locked(self, now: float) -> None:
        stale = [key for key, expiry in self._entries.items() if expiry <= now]
        for key in stale:
            del self._entries[key]

    def _evict_locked(self) -> None:
        overflow = len(self._entries) - self._max_entries
        if overflow <= 0:
            return
        # Evict the entries that would have expired soonest anyway.
        for key, _ in sorted(self._entries.items(), key=lambda kv: kv[1])[:overflow]:
            del self._entries[key]


@dataclass(frozen=True, slots=True)
class IssuedToken:
    """Result of a successful ``issue_*`` call."""

    token: str
    token_type: TokenType
    jti: str
    issued_at: int
    expires_at: int
    subject: str
    role: Role
    graph_id: str | None = None
    session_id: str | None = None

    @property
    def ttl_s(self) -> int:
        return max(0, self.expires_at - self.issued_at)

    def public_dict(self) -> dict[str, Any]:
        """JSON-safe representation for API responses."""
        payload: dict[str, Any] = {
            "token": self.token,
            "token_type": self.token_type.value,
            "expires_in": self.ttl_s,
            "expires_at": self.expires_at,
            "subject": self.subject,
            "role": self.role.value,
        }
        if self.graph_id is not None:
            payload["graph_id"] = self.graph_id
        return payload


# ---------------------------------------------------------------------------
# Token service
# ---------------------------------------------------------------------------


class TokenService:
    """Issues and verifies the three token flavours.

    Thread-safe and side-effect free apart from the JTI stores, so a single
    process-wide instance (see :func:`get_token_service`) is enough.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._used_tickets = JtiStore(max_entries=self._settings.jwt_ticket_cache_size)
        self._revoked = JtiStore(max_entries=self._settings.jwt_revoked_cache_size)
        self._algorithm = self._resolve_algorithm()

    # -- configuration --------------------------------------------------

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def enabled(self) -> bool:
        return self._settings.auth_enabled

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def _resolve_algorithm(self) -> str:
        algorithm = (self._settings.jwt_algorithm or "HS256").upper()
        if algorithm not in ALLOWED_ALGORITHMS:
            raise SecurityConfigError(
                f"OMNIAGENT_JWT_ALGORITHM={algorithm!r} is not allowed; "
                f"supported: {sorted(ALLOWED_ALGORITHMS)}"
            )
        return algorithm

    def validate_configuration(self) -> list[str]:
        """Return a list of human-readable configuration problems.

        Called from the application lifespan so a misconfigured deployment
        fails loudly at boot instead of rejecting every user at 3 a.m.
        """
        problems: list[str] = []
        if not self._settings.auth_enabled:
            problems.append(
                "OMNIAGENT_AUTH_ENABLED=false — every WebSocket/HTTP caller is "
                "treated as an anonymous principal (development only)"
            )
            return problems

        if self._algorithm.startswith("HS"):
            secret = self._settings.jwt_secret or ""
            if not secret:
                problems.append(
                    f"OMNIAGENT_JWT_ALGORITHM={self._algorithm} requires "
                    "OMNIAGENT_JWT_SECRET (>= 43 chars of random data)"
                )
            elif len(secret) < MIN_HMAC_SECRET_CHARS:
                problems.append(
                    f"OMNIAGENT_JWT_SECRET is only {len(secret)} chars; use at "
                    f"least {MIN_HMAC_SECRET_CHARS} (e.g. `openssl rand -base64 48`)"
                )
            elif _looks_like_placeholder(secret):
                problems.append(
                    "OMNIAGENT_JWT_SECRET looks like a placeholder value; "
                    "generate a real secret (`openssl rand -base64 48`)"
                )
        else:
            if not self._settings.jwt_public_key:
                problems.append(
                    f"OMNIAGENT_JWT_ALGORITHM={self._algorithm} requires "
                    "OMNIAGENT_JWT_PUBLIC_KEY (PEM) for verification"
                )
            if not self._settings.jwt_private_key:
                problems.append(
                    f"OMNIAGENT_JWT_ALGORITHM={self._algorithm}: no "
                    "OMNIAGENT_JWT_PRIVATE_KEY — this process can verify but "
                    "not issue tokens (fine for a resource server)"
                )

        if self._settings.auth_access_token_ttl_s > 3600:
            problems.append(
                "OMNIAGENT_AUTH_ACCESS_TOKEN_TTL_S > 3600 — access tokens should "
                "be short-lived; use refresh tokens for long sessions"
            )
        if self._settings.jwt_ws_ticket_ttl_s > 300:
            problems.append(
                "OMNIAGENT_JWT_WS_TICKET_TTL_S > 300 — WS tickets are meant to be "
                "single-use and near-instant"
            )
        return problems

    # -- issuing --------------------------------------------------------

    def issue_access_token(
        self,
        *,
        subject: str,
        role: Role | str,
        graph_ids: tuple[str, ...] | list[str] | str | None = None,
        ttl_s: int | None = None,
        session_id: str | None = None,
        display_name: str | None = None,
        scopes: list[str] | None = None,
        is_service: bool = False,
        extra_claims: dict[str, Any] | None = None,
    ) -> IssuedToken:
        """Mint a short-lived access token for an authenticated user."""
        return self._issue(
            token_type=TokenType.ACCESS,
            subject=subject,
            role=coerce_role(role),
            graph_ids=normalize_graph_ids(graph_ids),
            ttl_s=ttl_s if ttl_s is not None else self._settings.auth_access_token_ttl_s,
            session_id=session_id or secrets.token_urlsafe(16),
            display_name=display_name,
            scopes=scopes,
            is_service=is_service,
            extra_claims=extra_claims,
            fingerprint=None,
            graph_id=None,
        )

    def issue_refresh_token(
        self,
        *,
        subject: str,
        role: Role | str,
        graph_ids: tuple[str, ...] | list[str] | str | None = None,
        ttl_s: int | None = None,
        session_id: str | None = None,
    ) -> IssuedToken:
        """Mint a long-lived refresh token (only valid at ``/auth/refresh``)."""
        return self._issue(
            token_type=TokenType.REFRESH,
            subject=subject,
            role=coerce_role(role),
            graph_ids=normalize_graph_ids(graph_ids),
            ttl_s=ttl_s if ttl_s is not None else self._settings.auth_refresh_token_ttl_s,
            session_id=session_id or secrets.token_urlsafe(16),
            display_name=None,
            scopes=None,
            is_service=False,
            extra_claims=None,
            fingerprint=None,
            graph_id=None,
        )

    def issue_ws_ticket(
        self,
        *,
        principal: Principal,
        graph_id: str,
        ttl_s: int | None = None,
        fingerprint: str | None = None,
    ) -> IssuedToken:
        """Mint a single-use WebSocket handshake ticket bound to ``graph_id``.

        The ticket inherits the principal's role but **narrows** the graph
        scope to exactly the requested graph, so a ticket leaked in a proxy
        log cannot be replayed against another graph (and cannot be replayed
        at all — see :meth:`verify`).
        """
        if not principal.can_access_graph(graph_id):
            raise TokenError(
                TokenErrorCode.GRAPH,
                f"principal {principal.describe()} is not scoped to graph {graph_id!r}",
                http_status=403,
            )
        return self._issue(
            token_type=TokenType.WS_TICKET,
            subject=principal.subject,
            role=principal.role,
            graph_ids=(graph_id,),
            ttl_s=ttl_s if ttl_s is not None else self._settings.jwt_ws_ticket_ttl_s,
            session_id=principal.session_id,
            display_name=principal.display_name,
            scopes=sorted(principal.scopes) or None,
            is_service=principal.is_service,
            extra_claims=None,
            fingerprint=fingerprint,
            graph_id=graph_id,
            # Carry the session expiry so a 60 s ticket does not tear down a
            # healthy WebSocket after one minute (Principal.effective_expires_at).
            session_expires_at=principal.effective_expires_at,
        )

    def _issue(
        self,
        *,
        token_type: TokenType,
        subject: str,
        role: Role,
        graph_ids: tuple[str, ...],
        ttl_s: int,
        session_id: str | None,
        display_name: str | None,
        scopes: list[str] | None,
        is_service: bool,
        extra_claims: dict[str, Any] | None,
        fingerprint: str | None,
        graph_id: str | None,
        session_expires_at: float | None = None,
    ) -> IssuedToken:
        if not subject:
            raise SecurityConfigError("cannot issue a token without a subject")
        key = self._signing_key()
        now = int(time.time())
        expires = now + max(1, int(ttl_s))
        jti = secrets.token_urlsafe(16)

        claims: dict[str, Any] = {
            "iss": self._settings.jwt_issuer,
            "aud": self._settings.jwt_audience,
            "sub": subject,
            "role": role.value,
            "gph": list(graph_ids),
            "typ": token_type.value,
            "jti": jti,
            "iat": now,
            "nbf": now - self._settings.jwt_clock_skew_s,
            "exp": expires,
        }
        if session_id:
            claims["sid"] = session_id
        if display_name:
            claims["name"] = display_name[:120]
        if scopes:
            claims["scp"] = list(scopes)
        if is_service:
            claims["svc"] = True
        if fingerprint:
            claims["fp"] = fingerprint
        if session_expires_at:
            claims["sexp"] = int(session_expires_at)
        if extra_claims:
            # Never let a caller override security-relevant claims.
            reserved = {"iss", "aud", "sub", "exp", "nbf", "iat", "jti", "typ", "role"}
            claims.update({k: v for k, v in extra_claims.items() if k not in reserved})

        token = jwt.encode(claims, key, algorithm=self._algorithm)
        if isinstance(token, bytes):  # PyJWT < 2 returns bytes
            token = token.decode("ascii")
        return IssuedToken(
            token=token,
            token_type=token_type,
            jti=jti,
            issued_at=now,
            expires_at=expires,
            subject=subject,
            role=role,
            graph_id=graph_id,
            session_id=session_id,
        )

    # -- verification ---------------------------------------------------

    def verify(
        self,
        token: str | None,
        *,
        expected_type: TokenType | str | None = None,
        graph_id: str | None = None,
        fingerprint: str | None = None,
        consume_ticket: bool = True,
    ) -> Principal:
        """Verify a token and return the authenticated :class:`Principal`.

        Raises:
            TokenError: with a stable :class:`TokenErrorCode` for any failure.
        """
        if not self._settings.auth_enabled:
            raise TokenError(
                TokenErrorCode.DISABLED,
                "authentication is disabled; tokens are not accepted",
                http_status=503,
            )
        if not token or not token.strip():
            raise TokenError(TokenErrorCode.MISSING)
        token = token.strip()
        if len(token) > self._settings.jwt_max_token_chars:
            raise TokenError(
                TokenErrorCode.TOO_LARGE,
                f"token exceeds {self._settings.jwt_max_token_chars} characters",
            )

        claims = self._decode(token)
        token_type = self._claim_str(claims, "typ") or TokenType.ACCESS.value
        if expected_type is not None:
            expected = str(expected_type)
            if token_type != expected:
                raise TokenError(
                    TokenErrorCode.TYPE,
                    f"expected a {expected} token, got {token_type!r}",
                    http_status=403,
                )

        jti = self._claim_str(claims, "jti")
        sid = self._claim_str(claims, "sid")
        if jti and self._revoked.contains(jti):
            raise TokenError(TokenErrorCode.REVOKED, "token has been revoked")
        if sid and self._revoked.contains(f"sid:{sid}"):
            raise TokenError(TokenErrorCode.REVOKED, "session has been revoked")

        exp = claims.get("exp")
        ttl_remaining = max(1.0, float(exp) - time.time()) if isinstance(exp, (int, float)) else 60.0

        # Single-use enforcement must happen *after* signature/expiry checks
        # but *before* we hand out a principal.
        if token_type == TokenType.WS_TICKET.value:
            if not jti:
                raise TokenError(TokenErrorCode.CLAIM, "ws-ticket without jti")
            if self._settings.jwt_tickets_single_use and consume_ticket:
                if not self._used_tickets.consume(jti, ttl_remaining):
                    raise TokenError(
                        TokenErrorCode.REPLAYED,
                        "this connection ticket has already been used",
                    )

        bound = self._claim_str(claims, "fp")
        if bound:
            if not fingerprint or not hmac.compare_digest(bound, fingerprint):
                raise TokenError(TokenErrorCode.BINDING, http_status=403)

        role = coerce_role(claims.get("role"))
        graph_ids = normalize_graph_ids(claims.get("gph"))
        if not graph_ids and not self._settings.jwt_require_graph_binding:
            # Unbound tokens are only produced when the operator explicitly
            # relaxes graph binding; treat them as wildcard so downstream
            # checks stay total.
            graph_ids = (WILDCARD_GRAPH,)

        subject = self._claim_str(claims, "sub")
        if not subject:
            raise TokenError(TokenErrorCode.SUBJECT)

        principal = Principal(
            subject=subject,
            role=role,
            graph_ids=graph_ids,
            session_id=sid,
            token_id=jti,
            token_type=token_type,
            display_name=self._claim_str(claims, "name"),
            expires_at=float(exp) if isinstance(exp, (int, float)) else None,
            session_expires_at=(
                float(claims["sexp"]) if isinstance(claims.get("sexp"), (int, float)) else None
            ),
            issued_at=float(claims["iat"]) if isinstance(claims.get("iat"), (int, float)) else None,
            is_service=bool(claims.get("svc", False)),
            scopes=frozenset(
                s for s in (claims.get("scp") or []) if isinstance(s, str)
            ),
        )

        if graph_id is not None and self._settings.jwt_require_graph_binding:
            if not principal.can_access_graph(graph_id):
                # Do not leak whether the graph exists — same message for everyone.
                logger.warning(
                    "graph access denied: %s -> graph_id=%s", principal.describe(), graph_id
                )
                raise TokenError(
                    TokenErrorCode.GRAPH,
                    "you are not authorized for this graph",
                    http_status=403,
                )
        return principal

    def _decode(self, token: str) -> dict[str, Any]:
        key = self._verify_key()
        options = {
            "require": ["exp", "iat", "sub", "jti", "iss", "aud"],
            "verify_signature": True,
            "verify_aud": True,
            "verify_iss": True,
            "verify_exp": True,
            "verify_nbf": True,
        }
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[self._algorithm],
                audience=self._settings.jwt_audience,
                issuer=self._settings.jwt_issuer,
                leeway=self._settings.jwt_clock_skew_s,
                options=options,
            )
        except ExpiredSignatureError as exc:
            raise TokenError(TokenErrorCode.EXPIRED) from exc
        except ImmatureSignatureError as exc:
            raise TokenError(TokenErrorCode.IMMATURE) from exc
        except InvalidSignatureError as exc:
            raise TokenError(TokenErrorCode.SIGNATURE) from exc
        except InvalidAudienceError as exc:
            raise TokenError(TokenErrorCode.AUDIENCE) from exc
        except InvalidIssuerError as exc:
            raise TokenError(TokenErrorCode.ISSUER) from exc
        except MissingRequiredClaimError as exc:
            raise TokenError(TokenErrorCode.CLAIM, f"missing claim: {exc.claim}") from exc
        except InvalidTokenError as exc:
            message = str(exc).lower()
            if "algorithm" in message:
                raise TokenError(TokenErrorCode.ALGORITHM) from exc
            raise TokenError(TokenErrorCode.MALFORMED, str(exc)) from exc
        except PyJWTError as exc:  # pragma: no cover - defensive
            raise TokenError(TokenErrorCode.MALFORMED) from exc

        if not isinstance(claims, dict):  # pragma: no cover - defensive
            raise TokenError(TokenErrorCode.MALFORMED, "token payload is not an object")
        return claims

    @staticmethod
    def _claim_str(claims: dict[str, Any], key: str) -> str | None:
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    # -- revocation -----------------------------------------------------

    def revoke_token(self, jti: str | None, ttl_s: float | None = None) -> None:
        """Blacklist a single token id until it would have expired anyway."""
        if not jti:
            return
        self._revoked.add(jti, ttl_s or self._settings.auth_access_token_ttl_s)

    def revoke_session(self, session_id: str | None, ttl_s: float | None = None) -> None:
        """Blacklist every token belonging to one login session."""
        if not session_id:
            return
        self._revoked.add(
            f"sid:{session_id}",
            ttl_s or max(
                self._settings.auth_access_token_ttl_s,
                self._settings.auth_refresh_token_ttl_s,
            ),
        )

    def is_revoked(self, jti: str | None = None, session_id: str | None = None) -> bool:
        if jti and self._revoked.contains(jti):
            return True
        return bool(session_id and self._revoked.contains(f"sid:{session_id}"))

    # -- key material ---------------------------------------------------

    def _signing_key(self) -> Any:
        if self._algorithm.startswith("HS"):
            secret = self._settings.jwt_secret
            if not secret:
                raise SecurityConfigError(
                    "OMNIAGENT_JWT_SECRET is not set; refusing to sign tokens"
                )
            if len(secret) < MIN_HMAC_SECRET_CHARS:
                raise SecurityConfigError(
                    f"OMNIAGENT_JWT_SECRET must be at least {MIN_HMAC_SECRET_CHARS} "
                    "characters (256 bits of entropy)"
                )
            return secret.encode("utf-8")
        private_key = self._settings.jwt_private_key
        if not private_key:
            raise SecurityConfigError(
                f"OMNIAGENT_JWT_PRIVATE_KEY is required to sign {self._algorithm} tokens"
            )
        return private_key

    def _verify_key(self) -> Any:
        if self._algorithm.startswith("HS"):
            return self._signing_key()
        return self._settings.jwt_public_key or self._settings.jwt_private_key or self._signing_key()


def _looks_like_placeholder(secret: str) -> bool:
    """Heuristic guard against ``changeme``-style secrets."""
    lowered = secret.strip().lower()
    obvious = {
        "changeme",
        "change-me",
        "secret",
        "supersecret",
        "dev",
        "development",
        "test",
        "password",
        "omniagent",
        "omniagent-secret",
        "your-256-bit-secret",
        "keyboard-cat",
    }
    if lowered in obvious:
        return True
    if len(set(lowered)) <= 2 and len(lowered) >= 8:  # "aaaaaaaaaaaa"
        return True
    return False


_service: TokenService | None = None
_service_settings: Settings | None = None
_service_lock = threading.Lock()


def get_token_service(settings: Settings | None = None) -> TokenService:
    """Return the process-wide :class:`TokenService` (lazily constructed).

    The instance **must** be stable for a given :class:`Settings` object: it
    owns the single-use-ticket and revocation stores.  Rebuilding it per call
    (an earlier bug) silently disabled replay protection, because every
    connection would have checked a fresh, empty JTI cache.
    """
    global _service, _service_settings
    config = settings or get_settings()
    with _service_lock:
        if _service is None or _service_settings is not config:
            _service = TokenService(config)
            _service_settings = config
        return _service


def reset_token_service() -> None:
    """Drop the cached instance (used by tests after changing settings)."""
    global _service, _service_settings
    with _service_lock:
        _service = None
        _service_settings = None
