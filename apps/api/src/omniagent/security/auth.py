"""Authentication, authorisation and rate-limiting for WebSocket endpoints.

Capabilities
------------
* **JWT verification** for two families of issuers:

  - **HS256 shared secret** — tokens minted by OmniAgent itself and *legacy*
    Supabase projects (verified against the project JWT secret).
  - **RS256 / ES256 via JWKS** — Clerk (``https://<slug>.clerk.accounts.dev``)
    and modern Supabase (asymmetric signing keys). The JWKS endpoint is
    either configured explicitly (``OMNIAGENT_SECURITY_JWKS_URL``) or derived
    from the issuer (``{issuer}/.well-known/jwks.json`` — the layout used by
    both Clerk and Supabase). Keys are cached with a TTL and refreshed
    at most once per ``_MIN_JWKS_REFRESH_INTERVAL`` on an unknown ``kid``.

  The token's own ``alg`` header never gets to choose the verification key:
  HS256 is only accepted when a shared secret is configured and is always
  verified with that secret; asymmetric algs are only accepted against a
  typed JWK. Algorithm-confusion (RS256 -> HS256) and ``alg=none`` are
  therefore rejected by construction.

* **Claim mapping** into :class:`AuthContext` — ``user_id``, ``workspace_id``,
  ``role`` and ``exp`` — tolerant of provider layouts:

  ==================  ==========================================
  field               claim lookup order (dot-paths supported)
  ==================  ==========================================
  user_id             configured, ``user_id``, ``sub``, ``uid``
  workspace_id        configured, ``workspace_id``, ``org_id``
                      (Clerk), ``wsp_id``, ``app_metadata.workspace_id``
  role                configured, ``role``, ``app_role``,
                      ``app_metadata.role``, ``user_metadata.role``
  ==================  ==========================================

  Supabase's transport-level ``role`` values (``anon``/``authenticated``/
  ``service_role``) describe *authentication*, not authorisation, so they are
  skipped during lookup; an app role should live in ``app_metadata.role``.
  A missing/unknown role falls back to ``security_default_role`` (VIEWER —
  deny-by-default). ``exp`` is mandatory.

* **Per-connection rate limiting** — token buckets: ``60`` input packets/s
  (MOUSE_EVENT / KEYBOARD_EVENT) plus a coarser whole-message guard.
  Violations count strikes; after ``security_rate_limit_max_strikes`` the
  connection is closed with code 4429.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

import httpx
import jwt
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm
from starlette.websockets import WebSocket

from ..sandboxes.browser.config import Settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


class Role(StrEnum):
    """Application-level authorisation role carried in the token."""

    VIEWER = "VIEWER"
    OPERATOR = "OPERATOR"
    ADMIN = "ADMIN"


#: Roles allowed to drive the browser (mouse/keyboard/takeover).
CONTROL_ROLES: Final[frozenset[Role]] = frozenset({Role.OPERATOR, Role.ADMIN})

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AuthError(Exception):
    """Base class for authentication failures."""

    reason: str = "auth_failed"


class TokenMissingError(AuthError):
    reason = "token_missing"


class TokenInvalidError(AuthError):
    reason = "token_invalid"


class TokenExpiredError(AuthError):
    reason = "token_expired"


class TokenClaimsError(AuthError):
    reason = "claims_invalid"


class JwksError(AuthError):
    reason = "jwks_unavailable"


# ---------------------------------------------------------------------------
# Auth context
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthContext:
    """Verified identity + authorisation material for one connection."""

    user_id: str
    workspace_id: str | None
    role: Role
    expires_at: datetime | None
    issuer: str | None = None
    subject: str | None = None
    token_id: str | None = None
    claims: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def can_control(self) -> bool:
        """True for OPERATOR/ADMIN — may drive mouse/keyboard/takeover."""
        return self.role in CONTROL_ROLES


# ---------------------------------------------------------------------------
# Claim lookup helpers
# ---------------------------------------------------------------------------

_USER_ID_CLAIMS: Final[tuple[str, ...]] = ("user_id", "sub", "uid")
_WORKSPACE_ID_CLAIMS: Final[tuple[str, ...]] = (
    "workspace_id",
    "org_id",  # Clerk organisations
    "wsp_id",
    "app_metadata.workspace_id",
)
_ROLE_CLAIMS: Final[tuple[str, ...]] = (
    "role",
    "app_role",
    "app_metadata.role",
    "user_metadata.role",
)
#: Provider roles that describe authentication state, not app authorisation.
_NON_APP_ROLE_VALUES: Final[frozenset[str]] = frozenset(
    {"anon", "anonymous", "authenticated", "service_role", "none", "null"}
)


def _dig(claims: dict[str, Any], path: str) -> Any:
    """Resolve a claim path; ``None`` when absent.

    Supports literal keys (including namespaced URLs with dots, e.g.
    ``https://omniagent.io/claims.role``) as well as dotted traversal of
    nested objects (``app_metadata.role``). Resolution is greedy on the
    longest literal key prefix, so a namespaced parent containing dots
    still resolves: ``https://omniagent.io/claims`` + ``.role``.
    """
    if path in claims:
        return claims[path]
    segments = path.split(".")
    for split_at in range(len(segments) - 1, 0, -1):
        prefix = ".".join(segments[:split_at])
        nested = claims.get(prefix)
        if isinstance(nested, dict):
            remainder = ".".join(segments[split_at:])
            return _dig(nested, remainder)
    return None


def _first_claim(claims: dict[str, Any], paths: Sequence[str]) -> Any:
    for path in paths:
        value = _dig(claims, path)
        if value is not None and value != "":
            return value
    return None


def _as_text(value: Any) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _parse_role(value: Any) -> Role | None:
    if not isinstance(value, str):
        return None
    with contextlib.suppress(ValueError):
        return Role(value.strip().upper().replace("-", "_"))
    return None


# ---------------------------------------------------------------------------
# Rate limiting (token buckets)
# ---------------------------------------------------------------------------


class TokenBucket:
    """Classic token bucket; single event-loop use (no locking needed).

    ``now`` can be injected into :meth:`allow` for deterministic tests —
    production callers use the default ``time.monotonic()``.
    """

    __slots__ = ("_last", "_tokens", "capacity", "rate")

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        if rate <= 0:
            raise ValueError(f"rate must be > 0, got {rate}")
        resolved_capacity = float(rate if capacity is None else capacity)
        if resolved_capacity <= 0:
            raise ValueError(f"capacity must be > 0, got {resolved_capacity}")
        self.rate = float(rate)
        self.capacity = resolved_capacity
        self._tokens = resolved_capacity
        self._last = time.monotonic()

    def allow(self, cost: float = 1.0, *, now: float | None = None) -> bool:
        """Consume ``cost`` tokens; False when the bucket is exhausted."""
        current = time.monotonic() if now is None else now
        elapsed = max(0.0, current - self._last)
        self._last = current
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False

    @property
    def retry_after(self) -> float:
        """Seconds until one token is available again."""
        return max(0.0, (1.0 - self._tokens) / self.rate)


class ConnectionRateLimiter:
    """Per-connection limiter: input packets + whole-message flood guard.

    ``register_strike`` should be called for every rejection; once strikes
    reach ``max_strikes`` the caller must terminate the connection
    (WebSocket close code 4429).
    """

    __slots__ = ("input", "max_strikes", "messages", "strikes")

    def __init__(
        self,
        *,
        input_rate: float,
        input_burst: float | None = None,
        message_rate: float,
        message_burst: float | None = None,
        max_strikes: int = 100,
    ) -> None:
        self.input = TokenBucket(input_rate, input_burst)
        self.messages = TokenBucket(message_rate, message_burst)
        self.max_strikes = max(1, int(max_strikes))
        self.strikes = 0

    def allow_message(self) -> bool:
        return self.messages.allow()

    def allow_input(self) -> bool:
        return self.input.allow()

    def register_strike(self) -> bool:
        """Record a violation; True when the strike limit has been reached."""
        self.strikes += 1
        return self.strikes >= self.max_strikes

    def retry_after(self, *, for_input: bool) -> float:
        bucket = self.input if for_input else self.messages
        return round(bucket.retry_after, 3)


# ---------------------------------------------------------------------------
# JWKS cache (async, TTL + single-flight refresh)
# ---------------------------------------------------------------------------

_MIN_JWKS_REFRESH_INTERVAL: Final[float] = 5.0
_ASYMMETRIC_ALGORITHMS: Final[frozenset[str]] = frozenset({"RS256", "ES256", "EdDSA"})

#: JWK members that may reach a verifier (public material + metadata only).
_JWK_PUBLIC_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "kty",  # all types
        "kid",
        "alg",
        "use",
        "key_ops",
        "n",
        "e",  # RSA public
        "crv",
        "x",
        "y",  # EC / OKP public
    }
)


class _JwksCache:
    """Fetches and caches a JWKS document; resolves ``kid`` -> key object."""

    def __init__(self, url: str, *, ttl: float, timeout: float) -> None:
        self._url = url
        self._ttl = max(1.0, ttl)
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._keys: dict[str, tuple[Any, str | None]] = {}
        self._fetched_at: float = 0.0
        self._lock = asyncio.Lock()
        self.fetch_count = 0  # observable in tests (real HTTP fetches)

    async def get_key(self, kid: str, alg: str) -> Any:
        key = self._lookup(kid, alg)
        if key is not None:
            return key
        async with self._lock:
            key = self._lookup(kid, alg)
            if key is not None:
                return key
            now = time.monotonic()
            recently_fetched = (
                self._fetched_at > 0.0
                and (now - self._fetched_at) < _MIN_JWKS_REFRESH_INTERVAL
            )
            if not recently_fetched:
                await self._fetch()
        key = self._lookup(kid, alg)
        if key is None:
            raise TokenInvalidError(f"token signed with unknown key id {kid!r}")
        return key

    def _lookup(self, kid: str, alg: str) -> Any | None:
        entry = self._keys.get(kid)
        if entry is None:
            return None
        key, key_alg = entry
        if key_alg is not None and key_alg != alg:
            return None
        return key

    async def _fetch(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout, follow_redirects=True
            )
        try:
            response = await self._client.get(self._url)
            response.raise_for_status()
            document = response.json()
        except httpx.HTTPError as exc:
            logger.error("JWKS fetch failed (%s): %s", self._url, exc)
            raise JwksError(f"could not fetch JWKS from {self._url}") from exc
        except ValueError as exc:
            logger.error("JWKS document invalid (%s): %s", self._url, exc)
            raise JwksError("JWKS document is not valid JSON") from exc

        keys: dict[str, tuple[Any, str | None]] = {}
        for jwk_dict in document.get("keys", []):
            if not isinstance(jwk_dict, dict):
                continue
            kid = jwk_dict.get("kid")
            if not isinstance(kid, str) or not kid:
                continue
            key = _jwk_to_key(jwk_dict)
            if key is not None:
                keys[kid] = (key, jwk_dict.get("alg"))
        if not keys:
            raise JwksError(f"JWKS at {self._url} contained no usable keys")
        self._keys = keys
        self._fetched_at = time.monotonic()
        self.fetch_count += 1
        logger.info("JWKS refreshed from %s (%d keys)", self._url, len(keys))

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _jwk_to_key(jwk_dict: dict[str, Any]) -> Any | None:
    """Convert one JWK dict into a PUBLIC key object usable by PyJWT.

    Private key material is stripped defensively: a JWKS must only ever
    publish public keys, but a misconfigured IdP should not turn our
    verifier into something that fails obscurely (or worse).
    """
    kty = jwk_dict.get("kty")
    public_projection = {
        key: value
        for key, value in jwk_dict.items()
        if key in _JWK_PUBLIC_FIELDS
    }
    serialised = json.dumps(public_projection)
    try:
        if kty == "RSA":
            return RSAAlgorithm.from_jwk(serialised)
        if kty == "EC":
            return ECAlgorithm.from_jwk(serialised)
        if kty == "OKP":
            return OKPAlgorithm.from_jwk(serialised)
    except (ValueError, KeyError, NotImplementedError) as exc:
        logger.warning("skipping unusable JWK kid=%s: %s", jwk_dict.get("kid"), exc)
    return None


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------


class Authenticator:
    """Verifies bearer tokens into an :class:`AuthContext`.

    Construction is cheap and synchronous; network access happens lazily
    inside :meth:`authenticate` (JWKS). One instance should be shared per
    process (it owns the JWKS cache and httpx client) — see the app lifespan.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._secret = settings.security_jwt_secret
        self._issuer = settings.security_jwt_issuer
        self._audience = settings.security_jwt_audience
        self._leeway = settings.security_jwt_leeway_seconds

        jwks_url = settings.security_jwks_url
        if not jwks_url and self._issuer:
            jwks_url = f"{self._issuer.rstrip('/')}/.well-known/jwks.json"
        self._jwks: _JwksCache | None = (
            _JwksCache(
                jwks_url,
                ttl=settings.security_jwks_cache_ttl_seconds,
                timeout=settings.security_jwks_fetch_timeout_seconds,
            )
            if jwks_url
            else None
        )

        default_role = _parse_role(settings.security_default_role)
        if default_role is None:
            raise ValueError(
                f"security_default_role must be one of {[r.value for r in Role]}, "
                f"got {settings.security_default_role!r}"
            )
        self._default_role = default_role

    # ------------------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        """True when JWT verification is available (secret and/or JWKS)."""
        return bool(self._secret) or self._jwks is not None

    async def authenticate(self, token: str) -> AuthContext:
        """Verify ``token`` and return the authenticated context.

        Raises:
            AuthError (subclass): with a machine-readable ``reason``.
        """
        cleaned = token.strip()
        if cleaned.lower().startswith("bearer "):
            cleaned = cleaned[7:].strip()
        if not cleaned:
            raise TokenMissingError("empty bearer token")
        if not self.is_configured:
            raise AuthError(
                "JWT verification is not configured (set "
                "OMNIAGENT_SECURITY_JWT_SECRET or OMNIAGENT_SECURITY_JWKS_URL / "
                "OMNIAGENT_SECURITY_JWT_ISSUER)"
            )

        try:
            header = jwt.get_unverified_header(cleaned)
        except jwt.InvalidTokenError as exc:
            raise TokenInvalidError(f"malformed token: {exc}") from exc

        alg = header.get("alg")
        claims = await self._verify(cleaned, alg, header.get("kid"))
        return self._build_context(claims)

    async def aclose(self) -> None:
        if self._jwks is not None:
            await self._jwks.aclose()

    # ------------------------------------------------------------------

    async def _verify(self, token: str, alg: Any, kid: Any) -> dict[str, Any]:
        options: dict[str, Any] = {
            "require": ["exp"],
            # Only enforce `aud` when explicitly configured; providers embed
            # their own audience values we should not reject by accident.
            "verify_aud": self._audience is not None,
        }
        decode_kwargs: dict[str, Any] = {
            "issuer": self._issuer,  # None => not enforced
            "leeway": self._leeway,
            "options": options,
        }
        if self._audience is not None:
            decode_kwargs["audience"] = self._audience

        if alg == "HS256":
            if not self._secret:
                raise TokenInvalidError(
                    "token uses HS256 but no shared secret is configured"
                )
            return self._decode(token, self._secret, ["HS256"], decode_kwargs)

        if isinstance(alg, str) and alg in _ASYMMETRIC_ALGORITHMS:
            if self._jwks is None:
                raise TokenInvalidError(
                    f"token uses {alg} but no JWKS endpoint is configured"
                )
            if not isinstance(kid, str) or not kid:
                raise TokenInvalidError(f"{alg} token is missing a 'kid' header")
            key = await self._jwks.get_key(kid, alg)
            return self._decode(token, key, [alg], decode_kwargs)

        raise TokenInvalidError(
            f"unsupported token algorithm {alg!r} "
            f"(allowed: HS256{', RS256/ES256/EdDSA via JWKS' if self._jwks else ''})"
        )

    def _decode(
        self,
        token: str,
        key: Any,
        algorithms: list[str],
        decode_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            claims: dict[str, Any] = jwt.decode(
                token, key, algorithms=algorithms, **decode_kwargs
            )
            return claims
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("token has expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenInvalidError("token issuer does not match") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenInvalidError("token audience does not match") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise TokenClaimsError(f"token is missing required claim: {exc}") from exc
        except jwt.InvalidSignatureError as exc:
            raise TokenInvalidError("token signature is invalid") from exc
        except jwt.InvalidAlgorithmError as exc:
            raise TokenInvalidError(f"token algorithm rejected: {exc}") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenInvalidError(f"token verification failed: {exc}") from exc

    # ------------------------------------------------------------------

    def _build_context(self, claims: dict[str, Any]) -> AuthContext:
        user_id = _as_text(
            _first_claim(claims, self._claim_paths(_USER_ID_CLAIMS, "security_user_id_claim"))
        )
        if user_id is None:
            raise TokenClaimsError(
                "token carries no user identifier (expected one of: user_id, sub, uid)"
            )

        workspace_id = _as_text(
            _first_claim(
                claims,
                self._claim_paths(_WORKSPACE_ID_CLAIMS, "security_workspace_id_claim"),
            )
        )
        if workspace_id is None and self._settings.security_require_workspace_id:
            raise TokenClaimsError(
                "token carries no workspace identifier (expected one of: "
                "workspace_id, org_id, wsp_id, app_metadata.workspace_id)"
            )

        role = self._resolve_role(claims)

        expires_at: datetime | None = None
        exp = claims.get("exp")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            expires_at = datetime.fromtimestamp(exp, tz=UTC)

        return AuthContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            expires_at=expires_at,
            issuer=_as_text(claims.get("iss")),
            subject=_as_text(claims.get("sub")),
            token_id=_as_text(claims.get("jti")),
            claims=claims,
        )

    def _resolve_role(self, claims: dict[str, Any]) -> Role:
        saw_unparseable: Any = None
        for path in self._claim_paths(_ROLE_CLAIMS, "security_role_claim"):
            value = _dig(claims, path)
            if value is None or value == "":
                continue
            if isinstance(value, str) and value.strip().lower() in _NON_APP_ROLE_VALUES:
                # Supabase-style auth role, not an app role — keep looking.
                continue
            role = _parse_role(value)
            if role is not None:
                return role
            saw_unparseable = value
        if saw_unparseable is not None:
            logger.warning(
                "token role claim %r is not a valid app role; "
                "falling back to %s (deny-by-default)",
                saw_unparseable,
                self._default_role.value,
            )
        else:
            logger.info(
                "token has no app role claim; falling back to %s",
                self._default_role.value,
            )
        return self._default_role

    def _claim_paths(self, defaults: Sequence[str], setting_name: str) -> tuple[str, ...]:
        configured = getattr(self._settings, setting_name, None)
        if isinstance(configured, str) and configured.strip():
            return (configured.strip(), *defaults)
        return tuple(defaults)


# ---------------------------------------------------------------------------
# Token extraction from a WebSocket handshake
# ---------------------------------------------------------------------------

_BEARER_PROTOCOL_PREFIX: Final = "bearer."
_TOKEN_QUERY_PARAMS: Final[tuple[str, ...]] = ("token", "access_token")


def extract_ws_token(websocket: WebSocket) -> tuple[str | None, str | None]:
    """Pull the bearer token out of a WebSocket handshake.

    Checked in order:
      1. ``Authorization: Bearer <jwt>`` header (non-browser clients),
      2. ``?token=`` / ``?access_token=`` query parameter,
      3. ``Sec-WebSocket-Protocol`` entry shaped ``bearer.<jwt>`` — the only
         option available to browser ``WebSocket`` clients, which cannot set
         headers. When used, the returned subprotocol string must be echoed
         via ``websocket.accept(subprotocol=...)``.

    Returns ``(token, subprotocol_to_echo)``; either may be ``None``.
    """
    header = websocket.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        token = header[7:].strip()
        if token:
            return token, None

    for param in _TOKEN_QUERY_PARAMS:
        token = websocket.query_params.get(param, "").strip()
        if token:
            return token, None

    offered: list[str] = list(websocket.scope.get("subprotocols") or [])
    if not offered:
        raw = websocket.headers.get("sec-websocket-protocol", "")
        offered = [p.strip() for p in raw.split(",") if p.strip()]
    for protocol in offered:
        if protocol.lower().startswith(_BEARER_PROTOCOL_PREFIX):
            token = protocol[len(_BEARER_PROTOCOL_PREFIX):].strip()
            if token:
                return token, protocol

    return None, None


def build_rate_limiter(settings: Settings) -> ConnectionRateLimiter:
    """Create the per-connection limiter from settings."""
    return ConnectionRateLimiter(
        input_rate=settings.security_rate_limit_input_per_second,
        input_burst=settings.security_rate_limit_input_burst,
        message_rate=settings.security_rate_limit_messages_per_second,
        message_burst=settings.security_rate_limit_message_burst,
        max_strikes=settings.security_rate_limit_max_strikes,
    )
