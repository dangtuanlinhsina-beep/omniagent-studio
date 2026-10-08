"""Object-level authorization for ``graph_id`` (BOLA/IDOR defence).

The single most dangerous property of the original endpoint was that *any*
authenticated client could stream *any* ``graph_id``: the id was only
regex-validated, never authorized.  Because a graph id maps 1:1 onto a browser
sandbox that may hold a logged-in session (cookies, OTP screens, internal
dashboards), that is a full cross-tenant data leak.

This module puts one gate in front of both the WebSocket route and the REST
routes:

1. **Shape** — ``graph_id`` must match ``api_graph_id_pattern`` (prevents
   path/URL-template injection into the CDP endpoint template).
2. **Claim** — the principal's ``gph`` claim must cover the graph (enforced
   inside :class:`~omniagent.security.tokens.TokenService.verify`).
3. **Ownership** — a pluggable :class:`GraphAuthorizer` may consult the graph
   store (Postgres/K8s annotation/…) to verify tenant membership.  The default
   implementation is claim-only; production deployments should subclass it.
4. **Transport** — the resolved CDP URL is validated (scheme/host/port) and
   the per-sandbox guard token is attached, so the API never talks to an
   unexpected endpoint and never reaches an unauthenticated one.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol
from urllib.parse import urlsplit

from ..sandboxes.browser.config import Settings, get_settings
from ..sandboxes.browser.models import AppErrorCode, WsCloseCode
from ..sandboxes.browser.registry import SandboxRegistry, get_sandbox_registry
from ..security.roles import Permission, Principal, Role

logger = logging.getLogger(__name__)

__all__ = [
    "ClaimBasedGraphAuthorizer",
    "GraphAccessError",
    "GraphAuthorizer",
    "GraphContext",
    "get_graph_authorizer",
    "set_graph_authorizer",
    "validate_cdp_url",
    "validate_graph_id",
]

#: CDP is plain HTTP inside the cluster network; TLS terminates in front of it.
_ALLOWED_CDP_SCHEMES = frozenset({"http", "https", "ws", "wss"})


class GraphAccessError(Exception):
    """Raised when a principal may not use a graph (or it is malformed)."""

    def __init__(
        self,
        message: str,
        *,
        close_code: int = WsCloseCode.FORBIDDEN,
        app_code: int = AppErrorCode.GRAPH_FORBIDDEN,
        http_status: int = 403,
    ) -> None:
        self.message = message
        self.close_code = close_code
        self.app_code = app_code
        self.http_status = http_status
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class GraphContext:
    """Everything the stream route needs about one authorized graph."""

    graph_id: str
    principal: Principal
    cdp_url: str | None
    #: Bearer token for the in-sandbox CDP guard (see infra/sandbox-browser).
    cdp_auth_token: str | None = None
    tenant_id: str | None = None
    owner_subject: str | None = None

    @property
    def cdp_headers(self) -> dict[str, str] | None:
        """Headers Playwright must send on the CDP handshake."""
        if not self.cdp_auth_token:
            return None
        return {"Authorization": f"Bearer {self.cdp_auth_token}"}


def validate_graph_id(graph_id: str, settings: Settings | None = None) -> str:
    """Validate the shape of ``graph_id`` against the configured pattern."""
    cfg = settings or get_settings()
    pattern = _compiled_pattern(cfg.api_graph_id_pattern)
    if not graph_id or not pattern.fullmatch(graph_id):
        raise GraphAccessError(
            "invalid graph identifier",
            close_code=WsCloseCode.BAD_REQUEST,
            app_code=AppErrorCode.INVALID_PAYLOAD,
            http_status=400,
        )
    return graph_id


@lru_cache(maxsize=8)
def _compiled_pattern(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise GraphAccessError(
            "server misconfiguration: invalid graph_id pattern",
            close_code=WsCloseCode.INTERNAL_ERROR,
            app_code=AppErrorCode.INTERNAL,
            http_status=500,
        ) from exc


def validate_cdp_url(url: str, settings: Settings | None = None) -> str:
    """Sanity-check a resolved CDP endpoint (SSRF / misconfiguration guard).

    Rejects non-HTTP(S)/WS(S) schemes, embedded credentials, empty hosts and
    (optionally) loopback/link-local targets, which are the classic signs of a
    broken ``browser_sandbox_cdp_url_template``.
    """
    cfg = settings or get_settings()
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise GraphAccessError(
            "sandbox endpoint is not a valid URL",
            close_code=WsCloseCode.INTERNAL_ERROR,
            app_code=AppErrorCode.INTERNAL,
            http_status=500,
        ) from exc

    if parts.scheme.lower() not in _ALLOWED_CDP_SCHEMES:
        raise GraphAccessError(
            "sandbox endpoint uses a disallowed scheme",
            close_code=WsCloseCode.INTERNAL_ERROR,
            app_code=AppErrorCode.INTERNAL,
            http_status=500,
        )
    if parts.username or parts.password:
        raise GraphAccessError(
            "sandbox endpoint must not embed credentials",
            close_code=WsCloseCode.INTERNAL_ERROR,
            app_code=AppErrorCode.INTERNAL,
            http_status=500,
        )
    host = (parts.hostname or "").strip().lower()
    if not host:
        raise GraphAccessError(
            "sandbox endpoint has no host",
            close_code=WsCloseCode.INTERNAL_ERROR,
            app_code=AppErrorCode.INTERNAL,
            http_status=500,
        )
    if cfg.browser_sandbox_cdp_reject_loopback and host in {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    }:
        raise GraphAccessError(
            "sandbox endpoint resolves to a loopback address",
            close_code=WsCloseCode.INTERNAL_ERROR,
            app_code=AppErrorCode.INTERNAL,
            http_status=500,
        )
    return url


class GraphAuthorizer(Protocol):
    """Strategy interface for graph-level authorization."""

    async def authorize(
        self,
        principal: Principal,
        graph_id: str,
        *,
        permission: Permission | None = None,
    ) -> GraphContext:
        """Return a :class:`GraphContext` or raise :class:`GraphAccessError`."""
        ...


class ClaimBasedGraphAuthorizer:
    """Default authorizer: JWT claims + sandbox registry, no extra I/O.

    Production deployments with a graph store should subclass this and add a
    database check in :meth:`authorize` (call ``super().authorize`` first so
    the cheap checks still run before any query).
    """

    def __init__(
        self,
        settings: Settings | None = None,
        registry: SandboxRegistry | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._registry = registry or get_sandbox_registry()

    async def authorize(
        self,
        principal: Principal,
        graph_id: str,
        *,
        permission: Permission | None = None,
    ) -> GraphContext:
        validate_graph_id(graph_id, self._settings)

        if permission is not None and not principal.can(permission):
            logger.warning(
                "[%s] %s lacks permission %s", graph_id, principal.describe(), permission.value
            )
            raise GraphAccessError(
                "your role does not allow this operation on the graph",
                close_code=WsCloseCode.FORBIDDEN,
                app_code=AppErrorCode.FORBIDDEN,
            )

        if not principal.can_access_graph(graph_id):
            # Identical message for "not yours" and "does not exist".
            logger.warning(
                "[%s] graph access denied for %s", graph_id, principal.describe()
            )
            raise GraphAccessError("you are not authorized for this graph")

        try:
            cdp_url = await self._registry.resolve_cdp_url(graph_id)
        except Exception:  # noqa: BLE001 - never leak registry internals
            logger.exception("[%s] sandbox registry failure", graph_id)
            raise GraphAccessError(
                "failed to resolve browser sandbox",
                close_code=WsCloseCode.INTERNAL_ERROR,
                app_code=AppErrorCode.CDP_DISPATCH_FAILED,
                http_status=502,
            ) from None

        if cdp_url:
            cdp_url = validate_cdp_url(cdp_url, self._settings)

        return GraphContext(
            graph_id=graph_id,
            principal=principal,
            cdp_url=cdp_url,
            cdp_auth_token=self._cdp_token(graph_id),
        )

    def _cdp_token(self, graph_id: str) -> str | None:
        """Per-sandbox guard token (preferred) or the shared static one."""
        template = self._settings.browser_sandbox_cdp_auth_token_template
        if template:
            try:
                return template.format(graph_id=graph_id)
            except (KeyError, IndexError, ValueError) as exc:
                logger.error(
                    "[%s] invalid CDP token template: %s", graph_id, exc
                )
                return None
        return self._settings.browser_sandbox_cdp_auth_token


_authorizer: GraphAuthorizer | None = None


def get_graph_authorizer(settings: Settings | None = None) -> GraphAuthorizer:
    """Return the process-wide graph authorizer."""
    global _authorizer
    if _authorizer is None:
        _authorizer = ClaimBasedGraphAuthorizer(settings)
    return _authorizer


def set_graph_authorizer(authorizer: GraphAuthorizer | None) -> None:
    """Override the authorizer (database-backed impls, tests)."""
    global _authorizer
    _authorizer = authorizer


def minimum_role_for_view() -> Role:
    """Lowest role allowed to open a stream socket at all."""
    return Role.VIEWER
