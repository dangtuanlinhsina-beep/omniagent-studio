"""Resolution of ``graph_id`` -> browser-sandbox CDP endpoint.

The default implementation resolves endpoints from configuration:

1. ``OMNIAGENT_BROWSER_SANDBOX_CDP_URL`` — one static sandbox for everything
   (local development).
2. ``OMNIAGENT_BROWSER_SANDBOX_CDP_URL_TEMPLATE`` — a per-graph DNS template
   such as ``http://{graph_id}-browser:9222`` (docker-compose) or
   ``http://browser-{graph_id}.sandbox.svc.cluster.local:9222`` (Kubernetes
   headless service / StatefulSet DNS).
3. ``None`` — the streamer falls back to launching a local Playwright
   Chromium when ``browser_sandbox_launch_local_fallback`` is enabled.

Production deployments that allocate sandboxes dynamically (one browser pod
per graph run) should subclass :class:`SandboxRegistry` and query the
orchestrator / allocation service here; the rest of the stack only depends on
``resolve_cdp_url``.
"""

from __future__ import annotations

import logging
from functools import lru_cache

from .config import Settings, get_settings

logger = logging.getLogger(__name__)


class SandboxRegistry:
    """Maps a graph id to the CDP endpoint of its browser sandbox."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def resolve_cdp_url(self, graph_id: str) -> str | None:
        """Return the CDP HTTP endpoint for ``graph_id`` or ``None``.

        ``None`` means "no remote sandbox configured" — the caller decides
        whether to launch a local browser instead.
        """
        static = self._settings.browser_sandbox_cdp_url
        if static:
            return static

        template = self._settings.browser_sandbox_cdp_url_template
        if template:
            try:
                return template.format(graph_id=graph_id)
            except (KeyError, IndexError, ValueError) as exc:
                logger.error(
                    "invalid CDP URL template %r for graph_id=%s: %s",
                    template,
                    graph_id,
                    exc,
                )
                return None

        logger.debug(
            "no sandbox endpoint configured for graph_id=%s; "
            "local fallback=%s",
            graph_id,
            self._settings.browser_sandbox_launch_local_fallback,
        )
        return None


@lru_cache(maxsize=1)
def get_sandbox_registry() -> SandboxRegistry:
    """Return the process-wide registry built from cached settings."""
    return SandboxRegistry(get_settings())
