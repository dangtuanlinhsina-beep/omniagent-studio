"""OmniAgent Studio — API application entrypoint (wiring + security posture).

Run with::

    uvicorn omniagent.main:app --host 0.0.0.0 --port 8000

Production notes
----------------
* Run behind TLS with ``--proxy-headers --forwarded-allow-ips=<proxy cidr>``
  and set ``OMNIAGENT_API_TRUST_PROXY_HEADERS=true`` so the handshake/login
  throttles see real client IPs (otherwise every request looks like it comes
  from the load balancer).
* ``OMNIAGENT_AUTH_ENABLED=true`` (default) + a real ``OMNIAGENT_JWT_SECRET``
  (``openssl rand -base64 48``) are mandatory.  The lifespan below logs a
  *security posture* report at startup and refuses to boot when the JWT
  configuration is unusable.
* ``uvicorn``'s own WS keepalive (``--ws-ping-interval 20 --ws-ping-timeout 20``)
  complements the application-level idle timeout in ``routes_stream``.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .api.routes_auth import router as auth_router
from .api.routes_stream import router as stream_router
from .sandboxes.browser.config import Settings, get_settings
from .security.audit import AuditEvent, audit_event, configure_audit_logging, set_audit_config
from .security.tokens import SecurityConfigError, get_token_service
from .security.user_store import get_user_store

logger = logging.getLogger(__name__)

#: Headers that harden the JSON/WS API and any HTML it might serve.
_SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    # The API never renders HTML; a strict CSP neutralises any reflected
    # content that slips through an error page.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach hardening headers to every HTTP response."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        # Never advertise the framework/version.
        if "server" in response.headers:
            del response.headers["server"]
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    configure_audit_logging()
    settings = get_settings()  # fail fast on invalid configuration
    set_audit_config(
        input_events=settings.audit_input_events,
        ip_addresses=settings.audit_ip_addresses,
    )

    # Warm the user directory (also seeds OMNIAGENT_AUTH_BOOTSTRAP_USERS).
    store = get_user_store(settings)
    users = await store.count()

    problems = get_token_service(settings).validate_configuration()
    warnings = _insecure_defaults(settings)
    for problem in problems:
        audit_event(AuditEvent.CONFIG_INSECURE, reason=problem, level=logging.WARNING)
        logger.warning("security: %s", problem)
    for warning in warnings:
        audit_event(AuditEvent.CONFIG_INSECURE, reason=warning, level=logging.WARNING)
        logger.warning("security: %s", warning)

    if settings.auth_enabled:
        # Hard failure: an unusable JWT setup must not silently become "no auth".
        try:
            get_token_service(settings)._signing_key()  # noqa: SLF001
        except SecurityConfigError as exc:
            logger.critical("refusing to start: %s", exc)
            raise

    logger.info(
        "browser sandbox: static_cdp=%s template=%s local_fallback=%s require_remote=%s cdp_auth=%s",
        settings.browser_sandbox_cdp_url,
        settings.browser_sandbox_cdp_url_template,
        settings.browser_sandbox_launch_local_fallback,
        settings.browser_sandbox_require_remote,
        "token" if (
            settings.browser_sandbox_cdp_auth_token
            or settings.browser_sandbox_cdp_auth_token_template
        ) else "none",
    )
    logger.info(
        "auth: enabled=%s algorithm=%s access_ttl=%ss ws_ticket_ttl=%ss "
        "graph_binding=%s origins=%s users=%d",
        settings.auth_enabled,
        settings.jwt_algorithm,
        settings.auth_access_token_ttl_s,
        settings.jwt_ws_ticket_ttl_s,
        settings.jwt_require_graph_binding,
        settings.api_ws_allowed_origins or "<unrestricted>",
        users,
    )
    app.state.security_posture = {
        "auth_enabled": settings.auth_enabled,
        "problems": problems,
        "warnings": warnings,
        "users": users,
    }
    yield


def _insecure_defaults(settings: Settings) -> list[str]:
    """Warn (not fail) about settings that are fine in dev, risky in prod."""
    warnings: list[str] = []
    if not settings.api_ws_allowed_origins and not settings.api_ws_allowed_origin_regex:
        warnings.append(
            "OMNIAGENT_API_WS_ALLOWED_ORIGINS is empty — any website can open a "
            "WebSocket to this API with a stolen ticket (CSWSH)"
        )
    if settings.api_ws_token_in_query:
        warnings.append(
            "OMNIAGENT_API_WS_TOKEN_IN_QUERY=true — credentials may leak via "
            "proxy/access logs; send them in Sec-WebSocket-Protocol instead"
        )
    if settings.auth_allow_legacy_static_token or (
        settings.api_ws_auth_token and not settings.auth_enabled
    ):
        warnings.append(
            "the legacy shared WS token is enabled — it has no identity, no "
            "expiry and cannot be revoked per user"
        )
    if settings.browser_sandbox_launch_local_fallback and not settings.browser_sandbox_require_remote:
        warnings.append(
            "OMNIAGENT_BROWSER_SANDBOX_LAUNCH_LOCAL_FALLBACK=true — the API can "
            "spawn Chromium in its own container; set "
            "OMNIAGENT_BROWSER_SANDBOX_REQUIRE_REMOTE=true in production"
        )
    if not settings.jwt_require_graph_binding:
        warnings.append(
            "OMNIAGENT_JWT_REQUIRE_GRAPH_BINDING=false — any authenticated user "
            "can attach to any graph (IDOR)"
        )
    if settings.auth_allow_self_registration:
        warnings.append(
            "OMNIAGENT_AUTH_ALLOW_SELF_REGISTRATION=true — open sign-up; make "
            "sure OMNIAGENT_AUTH_DEFAULT_REGISTRATION_ROLE is VIEWER"
        )
    if not (
        settings.browser_sandbox_cdp_auth_token
        or settings.browser_sandbox_cdp_auth_token_template
    ):
        warnings.append(
            "no CDP guard token configured — anyone able to reach the sandbox "
            "port owns that browser session"
        )
    if settings.takeover_single_holder_per_graph is False:
        warnings.append(
            "OMNIAGENT_TAKEOVER_SINGLE_HOLDER_PER_GRAPH=false — several operators "
            "can drive one browser concurrently"
        )
    return warnings


def create_app() -> FastAPI:
    settings = get_settings()
    # The OpenAPI schema is a gift to an attacker: off unless explicitly enabled.
    docs = settings.api_docs_enabled
    app = FastAPI(
        title="OmniAgent Studio API",
        version="0.2.0",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
    )
    if settings.api_security_headers_enabled:
        app.add_middleware(SecurityHeadersMiddleware)
    if settings.api_cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.api_cors_allow_origins,
            allow_credentials=settings.api_cors_allow_credentials,
            # Never "*" with credentials: browsers reject it and it is almost
            # always a misconfiguration.
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
            expose_headers=["Retry-After"],
            max_age=600,
        )

    @app.exception_handler(SecurityConfigError)
    async def _security_config_error(  # pragma: no cover - defensive
        _request: Request, exc: SecurityConfigError
    ) -> JSONResponse:
        logger.critical("security configuration error: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "authentication is not configured on this server"},
        )

    @app.exception_handler(Exception)
    async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        """Never leak stack traces / internals to a client."""
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "internal server error"},
        )

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, object]:
        """Liveness probe — no dependencies, no secrets."""
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> JSONResponse:
        """Readiness probe — fails when the security configuration is broken."""
        posture = getattr(app.state, "security_posture", {})
        problems = posture.get("problems", [])
        blocking = [p for p in problems if "SECRET" in p or "PRIVATE_KEY" in p or "PUBLIC_KEY" in p]
        payload = {
            "status": "degraded" if blocking else "ok",
            "auth_enabled": posture.get("auth_enabled"),
            "blocking_issues": len(blocking),
        }
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE if blocking else status.HTTP_200_OK,
            content=payload,
        )

    app.include_router(auth_router)
    app.include_router(stream_router)
    return app


app = create_app()
