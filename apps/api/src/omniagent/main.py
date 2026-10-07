"""OmniAgent Studio — API application entrypoint (wiring example).

Run with::

    uvicorn omniagent.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from .api.routes_stream import router as stream_router
from .sandboxes.browser.config import get_settings


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
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
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="OmniAgent Studio API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(stream_router)
    return app


app = create_app()
