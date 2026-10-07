"""OmniAgent Studio — API application entrypoint (wiring example).

Run with::

    uvicorn omniagent.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .api.routes_stream import router as stream_router
from .api.supervisor import TaskSupervisor
from .sandboxes.browser.config import get_settings
from .security.auth import Authenticator


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = get_settings()  # fail fast on invalid configuration
    logging.getLogger(__name__).info(
        "browser sandbox: static_cdp=%s template=%s local_fallback=%s",
        settings.browser_sandbox_cdp_url,
        settings.browser_sandbox_cdp_url_template,
        settings.browser_sandbox_launch_local_fallback,
    )

    # Process-wide authenticator: owns the JWKS cache + httpx client shared
    # by all WebSocket handshakes.
    authenticator = Authenticator(settings)
    app.state.authenticator = authenticator
    if authenticator.is_configured:
        logging.getLogger(__name__).info(
            "ws auth: JWT mode (hs256_secret=%s, jwks=%s, issuer=%s)",
            bool(settings.security_jwt_secret),
            settings.security_jwks_url or "<derived-from-issuer>"
            if settings.security_jwt_issuer or settings.security_jwks_url
            else None,
            settings.security_jwt_issuer,
        )
    elif settings.api_ws_auth_token:
        logging.getLogger(__name__).warning(
            "ws auth: legacy static token mode (no RBAC — all clients get "
            "full control); set OMNIAGENT_SECURITY_JWT_SECRET for JWT+roles"
        )
    else:
        logging.getLogger(__name__).warning(
            "ws auth: DISABLED — endpoint is wide open (development only!)"
        )

    # Background supervisor owning screencast runners so they survive
    # per-request cancel scopes (see api/supervisor.py for rationale).
    supervisor = TaskSupervisor(name="omniagent-stream-supervisor")
    await supervisor.start()
    app.state.stream_supervisor = supervisor
    try:
        yield
    finally:
        await supervisor.aclose(timeout=settings.browser_cdp_command_timeout + 10.0)
        await authenticator.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="OmniAgent Studio API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(stream_router)
    return app


app = create_app()
