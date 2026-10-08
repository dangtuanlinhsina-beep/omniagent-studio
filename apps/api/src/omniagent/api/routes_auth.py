"""REST authentication surface (login / register / refresh / WS tickets).

Flow used by the Next.js frontend (see ``docs/SECURITY_HARDENING.md`` §4)::

    ┌────────────┐  1. POST /api/auth/login (email+password)   ┌──────────┐
    │ Browser    │ ───────────────────────────────────────────▶│ FastAPI  │
    │ (Next BFF) │ ◀───────────────────────────────────────────│          │
    └────────────┘  2. access_token (15 min) + refresh (12 h)  └──────────┘
         │           stored in an httpOnly cookie by the BFF
         │  3. POST /api/auth/ws-ticket {graph_id}
         │ ───────────────────────────────────────────────────▶
         │ ◀───────────────────────────────────────────────────
         │  4. single-use ticket (60 s, bound to graph_id)
         │
         │  5. new WebSocket(url, ["omniagent.v1", "<ticket>"])
         ▼
    /ws/graph/{graph_id}

Why a *ticket* and not the access token on the socket?  A browser cannot set
``Authorization`` on a WS upgrade, so the credential has to ride in the URL or
in ``Sec-WebSocket-Protocol``.  Both end up in proxy/access logs.  A
single-use, 60-second, graph-bound ticket makes that leak harmless: it cannot
be replayed, cannot be used on another graph, and never exposes the session
token.

Every endpoint here is rate-limited, audited and returns generic error text
(no user enumeration: "invalid credentials" for both unknown e-mail and wrong
password, with an equalising dummy hash so timing does not leak either).
"""

from __future__ import annotations

import logging
import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..sandboxes.browser.config import Settings, get_settings
from ..security.audit import AuditEvent, audit_event, redact_email
from ..security.roles import (
    Permission,
    Principal,
    Role,
    WILDCARD_GRAPH,
    coerce_role,
    normalize_graph_ids,
    permissions_for,
)
from ..security.tokens import (
    TokenError,
    TokenService,
    TokenType,
    client_fingerprint,
    get_token_service,
)
from ..security.user_store import (
    PasswordPolicyError,
    UserConflictError,
    UserRecord,
    get_login_throttle,
    get_user_store,
    verify_password,
)
from .connection_registry import get_connection_registry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

#: ``auto_error=False`` so a missing header becomes our own 401 (with audit),
#: not FastAPI's opaque default.
_bearer = HTTPBearer(auto_error=False, scheme_name="Bearer")


def token_service_dependency() -> TokenService:
    """FastAPI dependency wrapper around :func:`get_token_service`.

    ``get_token_service`` takes an optional ``Settings`` argument; used
    directly as a dependency, FastAPI would interpret that as a *body*
    parameter and silently re-shape every request body on the route.  A
    zero-argument wrapper keeps the schema clean.
    """
    return get_token_service()


TokenServiceDep = Annotated[TokenService, Depends(token_service_dependency)]

#: Cost of the dummy verification performed for unknown e-mail addresses.
_DUMMY_PASSWORD_HASH = "pbkdf2_sha256$210000$AAAAAAAAAAAAAAAAAAAAAA$" + "A" * 44


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


#: Deliberately permissive e-mail shape.  ``pydantic.EmailStr`` rejects
#: reserved TLDs (``.test``, ``.local``, ``.internal``), which would lock out
#: legitimate corporate directories; the store lower-cases and de-duplicates
#: anyway, and a malformed address simply never matches an account.
Email = Annotated[
    str,
    Field(min_length=3, max_length=254, pattern=r"^[^@\s,;]+@[^@\s,;]+$"),
]


class LoginRequest(BaseModel):
    email: Email
    password: str = Field(min_length=1, max_length=512)


class RegisterRequest(BaseModel):
    email: Email
    password: str = Field(min_length=1, max_length=512)
    display_name: str | None = Field(None, max_length=80)
    #: Ignored unless the caller is an ADMIN using the admin registration path:
    #: self-service registration always gets ``auth_default_registration_role``.
    role: str | None = None
    graph_ids: list[str] | None = None


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=16, max_length=8192)


class WsTicketRequest(BaseModel):
    graph_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]{1,64}$")
    #: Ask for a shorter ticket than the server default (never longer).
    ttl_s: int | None = Field(None, ge=5, le=600)


class UserResponse(BaseModel):
    id: str
    email: str
    role: Role
    graph_ids: list[str]
    display_name: str | None = None
    disabled: bool = False


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int
    role: Role
    subject: str
    permissions: list[str]
    user: UserResponse | None = None


class WsTicketResponse(BaseModel):
    ticket: str
    token_type: str = "ws-ticket"
    expires_in: int
    graph_id: str
    #: Subprotocols the client should offer, in order.
    subprotocols: list[str]
    ws_url_template: str = "/ws/graph/{graph_id}"


class MeResponse(BaseModel):
    subject: str
    role: Role
    permissions: list[str]
    graph_ids: list[str]
    session_id: str | None = None
    expires_at: float | None = None
    token_type: str


class GraphStreamStats(BaseModel):
    graph_id: str
    connections: int
    viewers: int
    operators: int
    takeover_holder: str | None = None
    takeover_expires_at: float | None = None


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def request_ip(request: Request, settings: Settings) -> str:
    """Client IP, honouring proxy headers only when explicitly trusted."""
    if settings.api_trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return first
        real_ip = request.headers.get("x-real-ip", "").strip()
        if real_ip:
            return real_ip
    return request.client.host if request.client else "unknown"


async def current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    settings: Annotated[Settings, Depends(get_settings)],
    token_service: TokenServiceDep,
) -> Principal:
    """Require a valid **access** token (refresh tokens are rejected here)."""
    if not settings.auth_enabled:
        from ..security.roles import build_anonymous_principal

        return build_anonymous_principal(coerce_role(settings.auth_anonymous_role))
    if credentials is None or not credentials.credentials:
        audit_event(
            AuditEvent.WS_AUTH_FAILED,
            ip=request_ip(request, settings),
            path=request.url.path,
            reason="missing_bearer",
            level=logging.WARNING,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        principal = token_service.verify(
            credentials.credentials,
            expected_type=TokenType.ACCESS,
            fingerprint=(
                client_fingerprint(
                    request_ip(request, settings), request.headers.get("user-agent")
                )
                if settings.jwt_ticket_bind_client
                else None
            ),
        )
    except TokenError as exc:
        audit_event(
            AuditEvent.WS_AUTH_FAILED,
            ip=request_ip(request, settings),
            path=request.url.path,
            reason=exc.code.value,
            token=credentials.credentials,
            level=logging.WARNING,
        )
        raise HTTPException(
            status_code=exc.http_status,
            detail=exc.public_message,
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc
    request.state.principal = principal
    return principal


def require_permission(permission: Permission):
    """Dependency factory enforcing one permission on an HTTP route."""

    async def _dependency(
        principal: Annotated[Principal, Depends(current_principal)]
    ) -> Principal:
        if not principal.can(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role {principal.role.value} lacks {permission.value}",
            )
        return principal

    return _dependency


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/config", summary="Public auth configuration for the frontend")
async def auth_config(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, Any]:
    """Everything the SPA needs to talk to the API — no secrets."""
    return {
        "auth_enabled": settings.auth_enabled,
        "registration_enabled": settings.auth_allow_self_registration,
        "access_token_ttl_s": settings.auth_access_token_ttl_s,
        "refresh_token_ttl_s": settings.auth_refresh_token_ttl_s,
        "ws_ticket_ttl_s": settings.jwt_ws_ticket_ttl_s,
        "ws_subprotocols": list(settings.api_ws_subprotocols),
        "ws_url_template": "/ws/graph/{graph_id}",
        "password_min_length": settings.auth_password_min_length,
        "roles": [role.value for role in Role],
    }


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenResponse:
    """Self-service registration (disabled unless explicitly enabled).

    The role is **always** forced to ``auth_default_registration_role`` — a
    client-supplied ``role`` is ignored, otherwise anyone could sign up as an
    OPERATOR and drive browsers.
    """
    if not settings.auth_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="auth is disabled")
    if not settings.auth_allow_self_registration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="self-service registration is disabled on this server",
        )

    ip = request_ip(request, settings)
    allowed, retry_after = get_login_throttle(settings).check(ip, payload.email)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many attempts; try again later",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )

    store = get_user_store(settings)
    role = coerce_role(settings.auth_default_registration_role)
    graphs = normalize_graph_ids(settings.auth_registration_graph_ids.split("|"))
    try:
        user = await store.create(
            email=str(payload.email),
            password=payload.password,
            role=role,
            graph_ids=graphs,
            display_name=payload.display_name,
        )
    except UserConflictError as exc:
        # Generic message: do not confirm that the e-mail exists.
        audit_event(
            AuditEvent.AUTH_REGISTER,
            ip=ip,
            email=redact_email(str(payload.email)),
            outcome="conflict",
            level=logging.WARNING,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="registration failed"
        ) from exc
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    audit_event(
        AuditEvent.AUTH_REGISTER,
        subject=user.id,
        role=user.role.value,
        ip=ip,
        email=redact_email(user.email),
    )
    return _token_response(user, settings, get_token_service(settings), include_refresh=True)


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    token_service: TokenServiceDep,
) -> TokenResponse:
    """Exchange e-mail + password for a short-lived access token."""
    ip = request_ip(request, settings)
    email = str(payload.email)

    allowed, retry_after = get_login_throttle(settings).check(ip, email)
    if not allowed:
        audit_event(
            AuditEvent.AUTH_LOGIN_FAILED,
            ip=ip,
            email=redact_email(email),
            reason="throttled",
            level=logging.WARNING,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many login attempts; try again later",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )

    store = get_user_store(settings)
    user = await store.get_by_email(email)
    stored_hash = user.password_hash if user else _DUMMY_PASSWORD_HASH
    # Always run one PBKDF2 so "unknown user" and "wrong password" take the
    # same amount of time (user-enumeration timing oracle).
    password_ok = verify_password(payload.password, stored_hash)

    if user is None or not password_ok:
        audit_event(
            AuditEvent.AUTH_LOGIN_FAILED,
            ip=ip,
            email=redact_email(email),
            reason="unknown_user" if user is None else "bad_password",
            level=logging.WARNING,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials"
        )
    if user.disabled:
        audit_event(
            AuditEvent.AUTH_LOGIN_FAILED,
            subject=user.id,
            ip=ip,
            email=redact_email(user.email),
            reason="disabled",
            level=logging.WARNING,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="account disabled")

    await store.touch_login(user)
    rehash = getattr(store, "needs_rehash", None)
    if callable(rehash) and rehash(user):
        await store.rehash(user, payload.password)  # type: ignore[attr-defined]

    audit_event(
        AuditEvent.AUTH_LOGIN, subject=user.id, role=user.role.value, ip=ip, outcome="ok"
    )
    response = _token_response(user, settings, token_service, include_refresh=True)
    logger.info(
        "login ok: user=%s role=%s ip=%s", user.id, user.role.value, ip
    )
    return response


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    token_service: TokenServiceDep,
) -> TokenResponse:
    """Rotate a refresh token into a fresh access token."""
    ip = request_ip(request, settings)
    try:
        principal = token_service.verify(
            payload.refresh_token, expected_type=TokenType.REFRESH
        )
    except TokenError as exc:
        audit_event(
            AuditEvent.AUTH_LOGIN_FAILED,
            ip=ip,
            reason=exc.code.value,
            token=payload.refresh_token,
            level=logging.WARNING,
        )
        raise HTTPException(
            status_code=exc.http_status, detail=exc.public_message
        ) from exc

    # Rotate: the presented refresh token is single-use from now on.
    token_service.revoke_token(principal.token_id, _remaining_ttl(principal))
    user = UserRecord(
        id=principal.subject,
        email=principal.display_name or principal.subject,
        password_hash="",
        role=principal.role,
        graph_ids=principal.graph_ids,
        display_name=principal.display_name,
    )
    audit_event(
        AuditEvent.AUTH_LOGIN,
        subject=principal.subject,
        role=principal.role.value,
        ip=ip,
        outcome="refresh",
    )
    return _token_response(
        user, settings, token_service, include_refresh=True, session_id=principal.session_id
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    token_service: TokenServiceDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    """Revoke the whole session (every access/refresh token of that login)."""
    token_service.revoke_session(principal.session_id, _remaining_ttl(principal))
    token_service.revoke_token(principal.token_id, _remaining_ttl(principal))
    audit_event(
        AuditEvent.AUTH_LOGOUT,
        subject=principal.subject,
        role=principal.role.value,
        ip=request_ip(request, settings),
    )


@router.get("/me", response_model=MeResponse)
async def me(
    principal: Annotated[Principal, Depends(current_principal)]
) -> MeResponse:
    """Echo the caller's identity and effective permissions."""
    return MeResponse(
        subject=principal.subject,
        role=principal.role,
        permissions=sorted(p.value for p in principal.permissions),
        graph_ids=list(principal.graph_ids),
        session_id=principal.session_id,
        expires_at=principal.effective_expires_at,
        token_type=principal.token_type,
    )


@router.post("/ws-ticket", response_model=WsTicketResponse)
async def issue_ws_ticket(
    payload: WsTicketRequest,
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    token_service: TokenServiceDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> WsTicketResponse:
    """Mint the single-use WebSocket handshake ticket for one graph.

    This is the **object-level authorization checkpoint** for the stream: the
    ticket is only issued when the caller's own ``gph`` claim covers
    ``graph_id``, and it is narrowed to that single graph.
    """
    if not principal.can(Permission.SCREEN_VIEW):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="your role cannot view browser streams",
        )
    if not principal.can_access_graph(payload.graph_id):
        audit_event(
            AuditEvent.AUTH_TICKET_ISSUED,
            graph_id=payload.graph_id,
            subject=principal.subject,
            ip=request_ip(request, settings),
            outcome="denied",
            level=logging.WARNING,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="you are not authorized for this graph",
        )

    fingerprint = (
        client_fingerprint(request_ip(request, settings), request.headers.get("user-agent"))
        if settings.jwt_ticket_bind_client
        else None
    )
    issued = token_service.issue_ws_ticket(
        principal=principal,
        graph_id=payload.graph_id,
        ttl_s=min(payload.ttl_s, settings.jwt_ws_ticket_ttl_s)
        if payload.ttl_s
        else settings.jwt_ws_ticket_ttl_s,
        fingerprint=fingerprint,
    )
    audit_event(
        AuditEvent.AUTH_TICKET_ISSUED,
        graph_id=payload.graph_id,
        subject=principal.subject,
        role=principal.role.value,
        ip=request_ip(request, settings),
        token=issued.token,
        ttl_s=issued.ttl_s,
        bound=bool(fingerprint),
    )
    return WsTicketResponse(
        ticket=issued.token,
        expires_in=issued.ttl_s,
        graph_id=payload.graph_id,
        subprotocols=list(settings.api_ws_subprotocols),
    )


@router.get(
    "/graphs/{graph_id}/stream-stats",
    response_model=GraphStreamStats,
    dependencies=[Depends(require_permission(Permission.AUDIT_READ))],
)
async def stream_stats(graph_id: str) -> GraphStreamStats:
    """ADMIN: who is watching/driving a graph right now."""
    stats = get_connection_registry().stats(graph_id)
    return GraphStreamStats(
        graph_id=stats.graph_id,
        connections=stats.connections,
        viewers=stats.viewers,
        operators=stats.operators,
        takeover_holder=stats.takeover.subject if stats.takeover else None,
        takeover_expires_at=stats.takeover.expires_at if stats.takeover else None,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _remaining_ttl(principal: Principal) -> float:
    if not principal.expires_at:
        return 900.0
    return max(1.0, principal.expires_at - time.time())


def _token_response(
    user: UserRecord,
    settings: Settings,
    token_service: TokenService,
    *,
    include_refresh: bool,
    session_id: str | None = None,
) -> TokenResponse:
    """Mint access (+refresh) tokens and shape the login response.

    Both tokens share one ``sid`` so ``POST /auth/logout`` revokes the whole
    session in a single move.
    """
    graphs = user.graph_ids or (WILDCARD_GRAPH,)
    access = token_service.issue_access_token(
        subject=user.id,
        role=user.role,
        graph_ids=graphs,
        session_id=session_id,
        display_name=user.display_name or user.email,
    )
    refresh_token = None
    if include_refresh:
        refresh_token = token_service.issue_refresh_token(
            subject=user.id,
            role=user.role,
            graph_ids=graphs,
            session_id=access.session_id,
        ).token

    return TokenResponse(
        access_token=access.token,
        refresh_token=refresh_token,
        expires_in=access.ttl_s,
        role=user.role,
        subject=user.id,
        permissions=sorted(p.value for p in permissions_for(user.role)),
        user=UserResponse(
            id=user.id,
            email=user.email,
            role=user.role,
            graph_ids=list(graphs),
            display_name=user.display_name,
            disabled=user.disabled,
        ),
    )
