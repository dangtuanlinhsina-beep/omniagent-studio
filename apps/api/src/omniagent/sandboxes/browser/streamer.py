"""CDP screencast streamer for a browser sandbox.

Responsibilities
----------------
* Attach Playwright to the sandbox browser — either over CDP
  (``chromium.connect_over_cdp``) or by launching a local fallback browser.
* Open a raw CDP session with ``page.context.new_cdp_session(page)`` and
  enable ``Page.startScreencast`` (JPEG, quality 70 by default).
* Consume ``Page.screencastFrame`` events, wrap them into ``SCREEN_FRAME``
  envelopes, push them onto a bounded queue (drop-oldest under backpressure)
  and acknowledge every frame with ``Page.screencastFrameAck`` so Chromium
  keeps producing frames at an *adaptive* rate: the browser only emits a new
  frame when the page actually changed AND the previous frame was acked,
  which naturally throttles fast clients and static pages alike.
* Supervise the stream: re-attach to newly opened tabs, recover from
  disconnects/crashes with capped exponential backoff + jitter, and publish
  lifecycle envelopes (``STREAM_READY`` / ``STREAM_RECONNECTING`` /
  ``STREAM_ERROR``) on the same queue.

The consumer (WebSocket route) simply drains :attr:`ScreencastStreamer.events`
until the terminal ``None`` sentinel appears.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
import random
from typing import Any, Final

from playwright.async_api import (
    Browser,
    BrowserContext,
    CDPSession,
    Page,
    Playwright,
    async_playwright,
)

from ._compat import PlaywrightError, TargetClosedError
from .config import Settings, get_settings
from .models import ServerMessageType, server_envelope

logger = logging.getLogger(__name__)

#: Terminal sentinel pushed onto :attr:`ScreencastStreamer.events`.
STREAM_END_SENTINEL: Final[None] = None

_BROWSER_LAUNCH_ARGS: Final[list[str]] = [
    # The fallback browser also runs inside the API container as non-root.
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--mute-audio",
]


class BrowserSandboxUnavailable(RuntimeError):
    """Raised when no sandbox endpoint is reachable/resolvable."""


class _RunResult(enum.Enum):
    """Why a single streaming attempt ended."""

    STOPPED = "stopped"
    DISCONNECTED = "disconnected"
    FAILED = "failed"


class ScreencastStreamer:
    """Streams one browser sandbox to a queue of JSON envelopes.

    Usage::

        streamer = ScreencastStreamer(graph_id=..., cdp_url=..., settings=...)
        runner = asyncio.create_task(streamer.run())
        while (envelope := await streamer.events.get()) is not None:
            await websocket.send_json(envelope)
        streamer.stop()

    ``streamer.active_session`` exposes the live :class:`CDPSession` for
    human-takeover input dispatch while the stream is up.
    """

    def __init__(
        self,
        *,
        graph_id: str,
        settings: Settings | None = None,
        cdp_url: str | None = None,
        cdp_headers: dict[str, str] | None = None,
    ) -> None:
        self._graph_id = graph_id
        self._settings = settings or get_settings()
        self._cdp_url = cdp_url
        #: Extra HTTP headers for the CDP handshake — used to authenticate
        #: against the sandbox's CDP guard (``infra/sandbox-browser``), which
        #: refuses DevTools clients without a bearer token.
        self._cdp_headers = dict(cdp_headers) if cdp_headers else None

        self.events: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(
            maxsize=self._settings.browser_frame_queue_size
        )

        self._seq: int = 0
        self._session: CDPSession | None = None
        self._page: Page | None = None

        self._stop = asyncio.Event()
        self._disconnected = asyncio.Event()
        self._reattach = asyncio.Event()

        self._frame_tasks: set[asyncio.Task[None]] = set()
        self._teardown_tasks: set[asyncio.Task[None]] = set()
        self._last_device_size: tuple[int, int] | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def graph_id(self) -> str:
        return self._graph_id

    @property
    def active_session(self) -> CDPSession | None:
        """The CDP session of the page currently being streamed (if any)."""
        return self._session

    @property
    def active_page(self) -> Page | None:
        return self._page

    @property
    def is_stopped(self) -> bool:
        return self._stop.is_set()

    def stop(self) -> None:
        """Request a graceful, idempotent shutdown of :meth:`run`."""
        self._stop.set()
        # Unblock any in-progress waiters so teardown happens immediately.
        self._disconnected.set()
        self._reattach.set()

    async def run(self) -> None:
        """Supervise the screencast until stopped or permanently failed.

        Never raises (except ``asyncio.CancelledError``); always pushes the
        terminal ``None`` sentinel onto :attr:`events` before returning.
        """
        attempt = 0
        try:
            while not self._stop.is_set():
                try:
                    result = await self._run_once()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception(
                        "[%s] unexpected screencast failure", self._graph_id
                    )
                    result = _RunResult.FAILED

                if self._stop.is_set() or result is _RunResult.STOPPED:
                    break

                attempt += 1
                max_attempts = self._settings.browser_max_reconnect_attempts
                if max_attempts is not None and attempt > max_attempts:
                    logger.error(
                        "[%s] giving up after %d reconnect attempts",
                        self._graph_id,
                        max_attempts,
                    )
                    self._push(
                        server_envelope(
                            ServerMessageType.STREAM_ERROR,
                            graph_id=self._graph_id,
                            fatal=True,
                            message=(
                                "browser sandbox unreachable after "
                                f"{max_attempts} reconnect attempts"
                            ),
                        )
                    )
                    break

                delay = self._backoff_delay(attempt)
                logger.warning(
                    "[%s] stream %s; reconnecting in %.2fs (attempt %d)",
                    self._graph_id,
                    result.value,
                    delay,
                    attempt,
                )
                self._push(
                    server_envelope(
                        ServerMessageType.STREAM_RECONNECTING,
                        graph_id=self._graph_id,
                        attempt=attempt,
                        delay_s=round(delay, 3),
                        reason=result.value,
                    )
                )
                if await self._wait_for_stop(delay):
                    break
        except asyncio.CancelledError:
            logger.info("[%s] streamer cancelled", self._graph_id)
            raise
        finally:
            self._push(STREAM_END_SENTINEL)

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def _run_once(self) -> _RunResult:
        """One full connect -> stream -> teardown cycle."""
        self._disconnected.clear()
        self._reattach.clear()

        playwright_obj: Playwright | None = None
        browser: Browser | None = None
        try:
            playwright_obj = await async_playwright().start()
            browser = await self._connect_browser(playwright_obj)
            browser.on("disconnected", self._on_browser_disconnected)

            context = await self._resolve_context(browser)
            context.on("page", self._on_new_page)

            result = await self._stream_pages(context)
            return result
        except asyncio.CancelledError:
            raise
        except BrowserSandboxUnavailable:
            logger.exception("[%s] sandbox unavailable", self._graph_id)
            return _RunResult.FAILED
        except (TimeoutError, PlaywrightError, OSError):
            logger.exception(
                "[%s] failed to establish screencast", self._graph_id
            )
            return _RunResult.FAILED
        finally:
            await self._teardown_safely(browser, playwright_obj)

    async def _connect_browser(self, playwright_obj: Playwright) -> Browser:
        """Connect over CDP to the sandbox, or launch a local fallback."""
        if self._cdp_url:
            # Never log the token: only whether one is attached.
            logger.info(
                "[%s] connecting to sandbox CDP endpoint %s (auth=%s)",
                self._graph_id,
                self._cdp_url,
                "bearer" if self._cdp_headers else "none",
            )
            connect_kwargs: dict[str, Any] = {
                "timeout": self._settings.browser_connect_timeout_ms,
            }
            if self._cdp_headers:
                connect_kwargs["headers"] = self._cdp_headers
            return await playwright_obj.chromium.connect_over_cdp(
                self._cdp_url, **connect_kwargs
            )

        if self._settings.browser_sandbox_require_remote:
            raise BrowserSandboxUnavailable(
                f"no CDP endpoint resolved for graph_id={self._graph_id!r} and "
                "OMNIAGENT_BROWSER_SANDBOX_REQUIRE_REMOTE=true forbids the "
                "in-process fallback browser"
            )

        if not self._settings.browser_sandbox_launch_local_fallback:
            raise BrowserSandboxUnavailable(
                f"no CDP endpoint resolved for graph_id={self._graph_id!r} "
                "and local fallback launch is disabled"
            )

        logger.warning(
            "[%s] no sandbox endpoint configured; launching local fallback "
            "Chromium (headless=%s)",
            self._graph_id,
            self._settings.browser_sandbox_local_headless,
        )
        return await playwright_obj.chromium.launch(
            headless=self._settings.browser_sandbox_local_headless,
            args=list(_BROWSER_LAUNCH_ARGS),
            timeout=self._settings.browser_connect_timeout_ms,
        )

    async def _resolve_context(self, browser: Browser) -> BrowserContext:
        """Pick the sandbox's default context or create one (local launch)."""
        if browser.contexts:
            return browser.contexts[0]
        return await browser.new_context(
            viewport={
                "width": self._settings.browser_viewport_width,
                "height": self._settings.browser_viewport_height,
            },
        )

    async def _stream_pages(self, context: BrowserContext) -> _RunResult:
        """Attach screencast to the active page; follow tab switches.

        Returns why streaming ended: explicit stop or browser disconnect.
        Page switches (popups, new tabs, closed/crashed pages) are handled
        internally by re-attaching to the newest *live* page. Transient
        attach failures (e.g. racing a tab that is still closing) are
        retried in-place instead of tearing down the whole connection.
        """
        attach_failures = 0
        while not self._stop.is_set() and not self._disconnected.is_set():
            self._reattach.clear()

            try:
                page = await self._pick_page(context)
                page.on("close", self._on_page_closed)
                page.on("crash", self._on_page_crashed)
                self._page = page

                session = await context.new_cdp_session(page)
                self._session = session
                # Register the listener BEFORE starting so no frame is missed.
                session.on("Page.screencastFrame", self._on_screencast_frame)
                await self._send(
                    session, "Page.startScreencast", self._screencast_params()
                )
            except asyncio.CancelledError:
                raise
            except PlaywrightError as exc:
                # Typically "Not attached to an active page" while a tab is
                # mid-close: retry the pick/attach loop a few times before
                # escalating to a full browser reconnect.
                attach_failures += 1
                await self._detach_session()
                if self._disconnected.is_set() or self._stop.is_set():
                    break
                if attach_failures > 5:
                    logger.error(
                        "[%s] giving up attach after %d failures: %s",
                        self._graph_id,
                        attach_failures,
                        exc,
                    )
                    return _RunResult.FAILED
                logger.warning(
                    "[%s] screencast attach failed (attempt %d/5): %s",
                    self._graph_id,
                    attach_failures,
                    exc,
                )
                await asyncio.sleep(0.25)
                continue
            attach_failures = 0

            logger.info(
                "[%s] screencast started on %s", self._graph_id, page.url
            )
            self._push(
                server_envelope(
                    ServerMessageType.STREAM_READY,
                    graph_id=self._graph_id,
                    page_url=page.url,
                    format=self._settings.browser_screencast_format,
                    quality=(
                        self._settings.browser_screencast_quality
                        if self._settings.browser_screencast_format == "jpeg"
                        else None
                    ),
                    max_width=self._settings.browser_screencast_max_width,
                    max_height=self._settings.browser_screencast_max_height,
                )
            )

            await self._wait_for_state_change()

            # Detach from the old page before (possibly) attaching a new one.
            await self._detach_session()

            if self._stop.is_set():
                logger.debug("[%s] stream loop: stopped", self._graph_id)
                return _RunResult.STOPPED
            if self._disconnected.is_set():
                logger.debug("[%s] stream loop: disconnected", self._graph_id)
                return _RunResult.DISCONNECTED
            # Otherwise: _reattach — loop picks up the newest page.
            logger.debug("[%s] stream loop: reattaching", self._graph_id)

        if self._stop.is_set():
            return _RunResult.STOPPED
        return _RunResult.DISCONNECTED

    async def _pick_page(self, context: BrowserContext) -> Page:
        """Return the newest non-closed page, creating one if needed."""
        for page in reversed(context.pages):
            if not page.is_closed():
                return page
        return await context.new_page()

    def _screencast_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {
            "format": self._settings.browser_screencast_format,
            "maxWidth": self._settings.browser_screencast_max_width,
            "maxHeight": self._settings.browser_screencast_max_height,
            "everyNthFrame": self._settings.browser_screencast_every_nth_frame,
            # Chromium >= 116: faster JPEG encoding path; ignored elsewhere.
            "optimizeForSpeed": True,
        }
        if self._settings.browser_screencast_format == "jpeg":
            params["quality"] = self._settings.browser_screencast_quality
        return params

    async def _wait_for_state_change(self) -> None:
        """Block until stop / disconnect / re-attach is requested."""
        waiters = [
            asyncio.create_task(self._stop.wait(), name="streamer-stop"),
            asyncio.create_task(self._disconnected.wait(), name="streamer-disconnected"),
            asyncio.create_task(self._reattach.wait(), name="streamer-reattach"),
        ]
        try:
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in waiters:
                task.cancel()
            await asyncio.gather(*waiters, return_exceptions=True)

    # ------------------------------------------------------------------
    # Screencast frames
    # ------------------------------------------------------------------

    def _on_screencast_frame(self, params: dict[str, Any]) -> None:
        """Sync CDP event callback; hands off to a tracked async task."""
        task = asyncio.create_task(
            self._process_frame(params),
            name=f"screencast-frame-{self._seq + 1}",
        )
        self._frame_tasks.add(task)
        task.add_done_callback(self._frame_tasks.discard)

    async def _process_frame(self, params: dict[str, Any]) -> None:
        session = self._session
        session_id = params.get("sessionId")
        try:
            data_b64 = params.get("data")
            metadata = params.get("metadata") or {}

            if data_b64 and not self._stop.is_set():
                width, height, device_w, device_h, page_scale = (
                    self._compute_frame_size(metadata)
                )
                self._seq += 1
                self._push(
                    server_envelope(
                        ServerMessageType.SCREEN_FRAME,
                        seq=self._seq,
                        format=self._settings.browser_screencast_format,
                        width=width,
                        height=height,
                        data_b64=data_b64,
                        device_width=device_w,
                        device_height=device_h,
                        page_scale_factor=page_scale,
                    )
                )

            # Always ack — even for dropped frames — otherwise Chromium
            # stalls the screencast waiting for the acknowledgement.
            if session is not None and session_id is not None:
                with contextlib.suppress(TargetClosedError, PlaywrightError):
                    await self._send(
                        session,
                        "Page.screencastFrameAck",
                        {"sessionId": session_id},
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "[%s] failed to process screencast frame", self._graph_id
            )

    def _compute_frame_size(
        self, metadata: dict[str, Any]
    ) -> tuple[int, int, int, int, float]:
        """Derive (width, height, device_w, device_h, page_scale_factor).

        CDP scales the emitted image down proportionally so it fits inside
        ``maxWidth``/``maxHeight``; we recompute the same factor to report
        the true pixel dimensions of ``data_b64``.
        """
        device_w = int(metadata.get("deviceWidth") or 0)
        device_h = int(metadata.get("deviceHeight") or 0)
        if device_w <= 0 or device_h <= 0:
            device_w, device_h = self._last_device_size or (
                self._settings.browser_screencast_max_width,
                self._settings.browser_screencast_max_height,
            )
        else:
            self._last_device_size = (device_w, device_h)

        page_scale = float(metadata.get("pageScaleFactor") or 1.0)
        max_w = self._settings.browser_screencast_max_width
        max_h = self._settings.browser_screencast_max_height
        fit_scale = min(max_w / device_w, max_h / device_h, 1.0)

        width = max(1, round(device_w * fit_scale))
        height = max(1, round(device_h * fit_scale))
        return width, height, device_w, device_h, page_scale

    # ------------------------------------------------------------------
    # Playwright / CDP event handlers
    # ------------------------------------------------------------------

    def _on_browser_disconnected(self, _browser: Browser) -> None:
        logger.warning(
            "[%s] browser disconnected from CDP endpoint", self._graph_id
        )
        self._disconnected.set()

    def _on_new_page(self, page: Page) -> None:
        # Only meaningful while a session is live; during (re)attach the
        # selection logic already picks the newest page.
        if self._session is not None and page is not self._page:
            logger.info("[%s] new page opened; re-attaching", self._graph_id)
            self._reattach.set()

    def _on_page_closed(self, page: Page) -> None:
        if page is self._page:
            logger.info("[%s] streamed page closed; re-attaching", self._graph_id)
            # NOTE: _stream_pages checks _stop/_disconnected BEFORE _reattach,
            # so a browser-wide disconnect still wins over this re-attach.
            self._reattach.set()

    def _on_page_crashed(self, page: Page) -> None:
        if page is self._page:
            logger.warning("[%s] streamed page crashed; re-attaching", self._graph_id)
            self._reattach.set()

    # ------------------------------------------------------------------
    # CDP plumbing
    # ------------------------------------------------------------------

    async def _send(
        self, session: CDPSession, method: str, params: dict[str, Any] | None = None
    ) -> Any:
        """``session.send`` with a hard timeout so we never hang forever."""
        return await asyncio.wait_for(
            session.send(method, params or {}),
            timeout=self._settings.browser_cdp_command_timeout,
        )

    async def _detach_session(self) -> None:
        """Best-effort stopScreencast + detach of the current session."""
        # Cancel frame processors that may still be acking the old session.
        tasks = [t for t in self._frame_tasks if not t.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        session = self._session
        self._session = None
        self._page = None
        if session is None:
            return
        with contextlib.suppress(Exception):
            await asyncio.wait_for(
                session.send("Page.stopScreencast"),
                timeout=self._settings.browser_cdp_command_timeout,
            )
        with contextlib.suppress(Exception):
            await asyncio.wait_for(
                session.detach(), timeout=self._settings.browser_cdp_command_timeout
            )

    async def _teardown_safely(
        self, browser: Browser | None, playwright_obj: Playwright | None
    ) -> None:
        """Run :meth:`_teardown` immune to outer-task cancellation.

        If this task is cancelled while teardown is in flight (e.g. the WS
        route is being torn down), the teardown continues as an orphan task
        on the running loop — abandoning it half-way would leak Playwright
        driver subprocesses and CDP connections.
        """
        logger.debug("[%s] teardown: starting", self._graph_id)
        task = asyncio.create_task(
            self._teardown(browser, playwright_obj),
            name=f"streamer-teardown-{self._graph_id}",
        )
        self._teardown_tasks.add(task)
        task.add_done_callback(self._teardown_tasks.discard)
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            logger.info(
                "[%s] cancelled during teardown; teardown continues in background",
                self._graph_id,
            )
            raise

    async def _teardown(
        self, browser: Browser | None, playwright_obj: Playwright | None
    ) -> None:
        await self._detach_session()
        logger.debug("[%s] teardown: session detached", self._graph_id)
        if browser is not None:
            with contextlib.suppress(Exception):
                # For connect_over_cdp this only drops OUR connection; the
                # sandbox browser itself keeps running for the next attempt.
                # Bounded: a wedged connection must never block teardown.
                await asyncio.wait_for(
                    browser.close(),
                    timeout=self._settings.browser_cdp_command_timeout,
                )
        logger.debug("[%s] teardown: browser closed", self._graph_id)
        if playwright_obj is not None:
            await self._stop_playwright(playwright_obj)
        logger.debug("[%s] teardown: complete", self._graph_id)

    async def _stop_playwright(self, playwright_obj: Playwright) -> None:
        """Stop the Playwright driver, surviving cancellation of THIS task.

        ``playwright.stop()`` must run to completion: interrupting it leaks
        the node driver subprocess, and the watcher thread blocked in
        ``waitpid`` for that child can then wedge event-loop shutdown
        forever. If we are cancelled while waiting, we keep waiting for the
        shielded stop to finish.
        """
        stop_task = asyncio.create_task(
            playwright_obj.stop(), name=f"playwright-stop-{self._graph_id}"
        )
        while True:
            try:
                await asyncio.shield(stop_task)
                return
            except asyncio.CancelledError:
                if stop_task.done():
                    return
                logger.debug(
                    "[%s] cancelled while stopping playwright driver; "
                    "waiting for stop to finish",
                    self._graph_id,
                )
                continue
            except Exception:
                logger.warning(
                    "[%s] playwright driver stop failed",
                    self._graph_id,
                    exc_info=True,
                )
                return

    # ------------------------------------------------------------------
    # Queue helpers (drop-oldest backpressure policy)
    # ------------------------------------------------------------------

    def _push(self, envelope: dict[str, Any] | None) -> None:
        """Non-blocking put; drops the oldest item when the queue is full.

        Live video must stay current: a slow consumer should see the *newest*
        frames, never a growing backlog of stale ones.
        """
        while True:
            try:
                self.events.put_nowait(envelope)
                return
            except asyncio.QueueFull:
                with contextlib.suppress(asyncio.QueueEmpty):
                    self.events.get_nowait()

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def _backoff_delay(self, attempt: int) -> float:
        base = self._settings.browser_reconnect_base_delay
        cap = self._settings.browser_reconnect_max_delay
        delay = min(cap, base * (2.0 ** (attempt - 1)))
        # +-25% jitter so fleets of sandboxes don't reconnect in lockstep.
        return delay * (0.875 + random.random() * 0.25)

    async def _wait_for_stop(self, delay: float) -> bool:
        """Wait up to ``delay`` seconds; True if stop was requested."""
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=delay)
            return True
        except TimeoutError:
            return False
