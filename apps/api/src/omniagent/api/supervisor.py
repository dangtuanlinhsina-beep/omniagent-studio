"""A loop-owned supervisor for background tasks that must outlive requests.

Why this exists
---------------
Tasks created inside a request handler are *children* of that handler's
asyncio task (and, under anyio-based servers/test clients, descendants of the
handler's cancel scope). When the scope exits — e.g. a Starlette TestClient
WebSocket session closes — every descendant task is cancelled, including
library-internal tasks such as Playwright's driver connection. Interrupting
Playwright mid-command leaks its node driver subprocess and can wedge event
loop shutdown on the child watcher thread.

The supervisor task is created once from the application lifespan, outside of
any request scope. Coroutines submitted to it become children of the
supervisor instead of the caller, so per-request cancellation can never tear
a half-finished browser teardown apart. Handler code still receives the
``asyncio.Task`` handle and can await/cancel it explicitly.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Coroutine
from typing import Any

logger = logging.getLogger(__name__)


class TaskSupervisor:
    """Spawns and owns background tasks on behalf of request handlers."""

    def __init__(self, *, name: str = "task-supervisor") -> None:
        self._name = name
        self._submissions: asyncio.Queue[
            tuple[Coroutine[Any, Any, None], str, asyncio.Future[asyncio.Task[None]]] | None
        ] = asyncio.Queue()
        self._loop_task: asyncio.Task[None] | None = None
        self._children: set[asyncio.Task[None]] = set()
        self._closed = False

    # ------------------------------------------------------------------
    # Lifecycle (call from the FastAPI lifespan)
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._loop_task is not None:
            return
        self._closed = False
        self._loop_task = asyncio.create_task(self._run(), name=self._name)
        logger.debug("%s started", self._name)

    async def aclose(self, *, timeout: float = 15.0) -> None:
        """Stop accepting work and drain supervised tasks (bounded)."""
        if self._closed:
            return
        self._closed = True
        if self._loop_task is not None:
            self._submissions.put_nowait(None)
            with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(self._loop_task, timeout=5.0)
            self._loop_task.cancel()
        if self._children:
            logger.debug(
                "%s waiting for %d supervised tasks", self._name, len(self._children)
            )
            _done, pending = await asyncio.wait(self._children, timeout=timeout)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        logger.debug("%s closed", self._name)

    @property
    def is_running(self) -> bool:
        return self._loop_task is not None and not self._loop_task.done()

    # ------------------------------------------------------------------
    # Submission (call from request handlers)
    # ------------------------------------------------------------------

    async def submit(
        self, coro: Coroutine[Any, Any, None], *, name: str | None = None
    ) -> asyncio.Task[None]:
        """Schedule ``coro`` as a child of the supervisor; return its Task.

        Falls back to spawning on the current task if the supervisor is not
        running, so callers never deadlock on a misconfigured lifespan.
        """
        if not self.is_running or self._closed:
            logger.warning(
                "%s not running; spawning %r on the caller task instead",
                self._name,
                name or coro,
            )
            return asyncio.create_task(coro, name=name)

        future: asyncio.Future[asyncio.Task[None]] = (
            asyncio.get_running_loop().create_future()
        )
        self._submissions.put_nowait((coro, name or "supervised-task", future))
        return await future

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _run(self) -> None:
        while True:
            item = await self._submissions.get()
            if item is None:
                return
            coro, name, future = item
            task = asyncio.create_task(coro, name=name)  # parent = supervisor
            self._children.add(task)
            task.add_done_callback(self._children.discard)
            task.add_done_callback(self._log_task_result)
            if not future.done():
                future.set_result(task)

    def _log_task_result(self, task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.error(
                "supervised task %s failed: %r", task.get_name(), exc, exc_info=exc
            )
