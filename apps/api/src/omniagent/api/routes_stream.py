"""WebSocket streaming endpoints: live browser screen + human takeover.

Endpoint
--------
``WS /ws/graph/{graph_id}``

Lifecycle:
    1. ``accept()`` the socket, authenticate (optional shared token) and
       validate ``graph_id``.
    2. Resolve the graph's browser sandbox CDP endpoint via
       :class:`~omniagent.sandboxes.browser.registry.SandboxRegistry`.
    3. Start a :class:`~omniagent.sandboxes.browser.streamer.ScreencastStreamer`
       which pushes ``SCREEN_FRAME`` / lifecycle envelopes onto a queue.
    4. Run four cooperating tasks: stream runner, frame pump, a *single*
       outbound writer (WebSocket sends are serialised through one task to
       avoid interleaving) and the inbound receive loop.
    5. When any task finishes (client disconnect, fatal stream error, send
       failure) everything is torn down deterministically and the socket is
       closed with a meaningful code.

Inbound commands are dispatched per :mod:`omniagent.sandboxes.browser.models`;
mouse/keyboard input is gated behind an explicit ``SET_TAKEOVER`` handshake so
a viewer cannot accidentally fight the agent for the pointer.

Integration point: when takeover toggles, a full deployment should also
pause/resume the agent's graph execution (e.g. publish an event to the graph
supervisor). That coupling lives outside the sandbox layer; here we log the
transition and notify the client via ``TAKEOVER_STATE``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Final

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import ValidationError
from starlette.websockets import WebSocketState

from ..sandboxes.browser._compat import PlaywrightError, TargetClosedError
from ..sandboxes.browser.config import Settings, get_settings
from ..sandboxes.browser.human_takeover import (
    dispatch_keyboard_event,
    dispatch_mouse_event,
)
from ..sandboxes.browser.models import (
    AppErrorCode,
    ClientMessageType,
    KeyboardEvent,
    MouseEvent,
    ServerMessageType,
    SetTakeoverMessage,
    WsCloseCode,
    error_envelope,
    parse_client_envelope,
    server_envelope,
)
from ..sandboxes.browser.registry import SandboxRegistry, get_sandbox_registry
from ..sandboxes.browser.streamer import ScreencastStreamer

logger = logging.getLogger(__name__)

router = APIRouter()

_TASK_STREAM_RUNNER: Final = "graph-stream-runner"
_TASK_FRAME_PUMP: Final = "graph-frame-pump"
_TASK_WS_WRITER: Final = "graph-ws-writer"
_TASK_WS_RECEIVER: Final = "graph-ws-receiver"

_OUT_QUEUE_FACTOR: Final = 2


class _AuthError(Exception):
    """WebSocket authentication failed."""


class _ProtocolError(Exception):
    """WebSocket-level protocol violation (close the connection)."""


@dataclass
class _ConnectionState:
    """Per-connection mutable state."""

    graph_id: str
    takeover_active: bool = False
    started_at: float = field(default_factory=time.time)
    frames_sent: int = 0


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.websocket("/ws/graph/{graph_id}")
async def graph_browser_stream(websocket: WebSocket, graph_id: str) -> None:
    """Stream a graph's browser sandbox and relay human-takeover input."""
    settings = get_settings()
    client = _describe_client(websocket)

    await websocket.accept()

    try:
        _authenticate(websocket, settings)
        _validate_graph_id(graph_id, settings)
    except _AuthError as exc:
        logger.warning("[%s] rejecting %s: %s", graph_id, client, exc)
        await _reject(websocket, WsCloseCode.UNAUTHORIZED, AppErrorCode.INVALID_PAYLOAD, str(exc))
        return
    except _ProtocolError as exc:
        logger.warning("[%s] rejecting %s: %s", graph_id, client, exc)
        await _reject(websocket, WsCloseCode.BAD_REQUEST, AppErrorCode.INVALID_PAYLOAD, str(exc))
        return

    registry = get_sandbox_registry()
    try:
        cdp_url = await registry.resolve_cdp_url(graph_id)
    except Exception:  # noqa: BLE001 - registry must never kill the socket handler
        logger.exception("[%s] sandbox registry failure", graph_id)
        await _reject(
            websocket,
            WsCloseCode.INTERNAL_ERROR,
            AppErrorCode.CDP_DISPATCH_FAILED,
            "failed to resolve browser sandbox",
        )
        return

    logger.info(
        "[%s] websocket connected (%s); sandbox=%s",
        graph_id,
        client,
        cdp_url or "<local-fallback>",
    )

    state = _ConnectionState(graph_id=graph_id)
    streamer = ScreencastStreamer(graph_id=graph_id, settings=settings, cdp_url=cdp_url)
    out_queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(
        maxsize=settings.browser_frame_queue_size * _OUT_QUEUE_FACTOR
    )

    tasks = {
        asyncio.create_task(
            streamer.run(), name=_TASK_STREAM_RUNNER
        ),
        asyncio.create_task(
            _pump_stream_events(streamer, out_queue), name=_TASK_FRAME_PUMP
        ),
        asyncio.create_task(
            _writer_loop(websocket, out_queue, state), name=_TASK_WS_WRITER
        ),
        asyncio.create_task(
            _receive_loop(websocket, state, streamer, out_queue, settings),
            name=_TASK_WS_RECEIVER,
        ),
    }

    close_code = WsCloseCode.NORMAL
    close_reason = "connection closed"
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        close_code, close_reason = _classify_completion(graph_id, done)
    finally:
        streamer.stop()
        # Cancel the lightweight IO tasks first so an external cancellation
        # of this handler can never orphan them.
        runner_task = next(t for t in tasks if t.get_name() == _TASK_STREAM_RUNNER)
        for task in tasks:
            if task is not runner_task:
                task.cancel()
        # Give the streamer a grace window to finish its CDP/Playwright
        # teardown cleanly; cancelling it mid-teardown would leak the driver
        # subprocess and socket. shield() so OUR timeout can't kill it.
        grace = settings.browser_cdp_command_timeout + 5.0
        with contextlib.suppress(asyncio.TimeoutError, PlaywrightError, OSError):
            await asyncio.wait_for(asyncio.shield(runner_task), timeout=grace)
        for task in tasks:
            task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for task, result in zip(tasks, results):
            if isinstance(result, BaseException) and not isinstance(
                result, (asyncio.CancelledError, WebSocketDisconnect)
            ):
                logger.error(
                    "[%s] task %s failed: %r", graph_id, task.get_name(), result
                )
        await _close_socket(websocket, close_code, close_reason)
        logger.info(
            "[%s] websocket closed (%s): code=%d reason=%r frames_sent=%d "
            "duration=%.1fs",
            graph_id,
            client,
            close_code,
            close_reason,
            state.frames_sent,
            time.time() - state.started_at,
        )


# ---------------------------------------------------------------------------
# Task loops
# ---------------------------------------------------------------------------


async def _pump_stream_events(
    streamer: ScreencastStreamer, out_queue: asyncio.Queue[dict[str, Any] | None]
) -> None:
    """Move streamer envelopes to the outbound queue; propagate the sentinel."""
    while True:
        envelope = await streamer.events.get()
        if envelope is None:
            await out_queue.put(None)
            return
        await out_queue.put(envelope)


async def _writer_loop(
    websocket: WebSocket,
    out_queue: asyncio.Queue[dict[str, Any] | None],
    state: _ConnectionState,
) -> None:
    """The ONLY task allowed to send on the socket (serialised writer)."""
    while True:
        envelope = await out_queue.get()
        if envelope is None:
            return
        await websocket.send_json(envelope)
        if envelope.get("type") == ServerMessageType.SCREEN_FRAME.value:
            state.frames_sent += 1


async def _receive_loop(
    websocket: WebSocket,
    state: _ConnectionState,
    streamer: ScreencastStreamer,
    out_queue: asyncio.Queue[dict[str, Any] | None],
    settings: Settings,
) -> None:
    """Read client commands and dispatch them.

    Returns on clean client disconnect; raises :class:`_ProtocolError` for
    violations that must terminate the connection.
    """
    graph_id = state.graph_id
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            logger.info(
                "[%s] client disconnected (code=%s)",
                graph_id,
                message.get("code"),
            )
            return

        raw = message.get("text")
        if raw is None:
            payload_bytes = message.get("bytes")
            if payload_bytes is None:
                continue
            try:
                raw = payload_bytes.decode("utf-8")
            except UnicodeDecodeError:
                await out_queue.put(
                    error_envelope(
                        AppErrorCode.INVALID_PAYLOAD,
                        "binary payloads must be UTF-8 encoded JSON",
                    )
                )
                continue

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            await out_queue.put(
                error_envelope(AppErrorCode.INVALID_PAYLOAD, f"invalid JSON: {exc}")
            )
            continue
        if not isinstance(data, dict):
            await out_queue.put(
                error_envelope(
                    AppErrorCode.INVALID_PAYLOAD, "message must be a JSON object"
                )
            )
            continue

        msg_type, payload = parse_client_envelope(data)

        if msg_type == ClientMessageType.PING.value:
            await out_queue.put(
                server_envelope(
                    ServerMessageType.PONG,
                    ts_ms=int(time.time() * 1000),
                    echo=payload.get("ts"),
                )
            )
        elif msg_type == ClientMessageType.SET_TAKEOVER.value:
            await _handle_set_takeover(payload, state, out_queue)
        elif msg_type == ClientMessageType.MOUSE_EVENT.value:
            await _handle_mouse_event(payload, state, streamer, out_queue, settings)
        elif msg_type == ClientMessageType.KEYBOARD_EVENT.value:
            await _handle_keyboard_event(payload, state, streamer, out_queue, settings)
        else:
            await out_queue.put(
                error_envelope(
                    AppErrorCode.UNKNOWN_MESSAGE_TYPE,
                    f"unknown message type: {msg_type or '<missing>'!r}",
                )
            )


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


async def _handle_set_takeover(
    payload: dict[str, Any],
    state: _ConnectionState,
    out_queue: asyncio.Queue[dict[str, Any] | None],
) -> None:
    try:
        message = SetTakeoverMessage.model_validate(payload)
    except ValidationError as exc:
        await out_queue.put(
            error_envelope(AppErrorCode.VALIDATION_FAILED, _format_validation(exc))
        )
        return

    state.takeover_active = message.enabled
    logger.info(
        "[%s] human takeover %s", state.graph_id, "ENABLED" if message.enabled else "disabled"
    )
    # Integration point: notify the graph supervisor to pause/resume agent
    # actions on this sandbox so human and agent never drive concurrently.
    await out_queue.put(
        server_envelope(
            ServerMessageType.TAKEOVER_STATE,
            graph_id=state.graph_id,
            enabled=message.enabled,
        )
    )


async def _handle_mouse_event(
    payload: dict[str, Any],
    state: _ConnectionState,
    streamer: ScreencastStreamer,
    out_queue: asyncio.Queue[dict[str, Any] | None],
    settings: Settings,
) -> None:
    prepared = _prepare_input_dispatch(state, streamer, settings)
    if isinstance(prepared, dict):  # error envelope already queued/returned
        await out_queue.put(prepared)
        return
    session = prepared

    try:
        event = MouseEvent.model_validate(payload)
    except ValidationError as exc:
        await out_queue.put(
            error_envelope(AppErrorCode.VALIDATION_FAILED, _format_validation(exc))
        )
        return

    try:
        await dispatch_mouse_event(
            session, event, timeout=settings.browser_cdp_command_timeout
        )
    except ValueError as exc:
        await out_queue.put(
            error_envelope(AppErrorCode.VALIDATION_FAILED, str(exc))
        )
    except asyncio.TimeoutError:
        logger.warning("[%s] mouse dispatch timed out: %s", state.graph_id, event.action)
        await out_queue.put(
            error_envelope(
                AppErrorCode.CDP_DISPATCH_TIMEOUT, "mouse event dispatch timed out"
            )
        )
    except (TargetClosedError, PlaywrightError) as exc:
        logger.warning(
            "[%s] mouse dispatch failed (%s): %s", state.graph_id, event.action, exc
        )
        await out_queue.put(
            error_envelope(AppErrorCode.CDP_DISPATCH_FAILED, f"input dispatch failed: {exc}")
        )


async def _handle_keyboard_event(
    payload: dict[str, Any],
    state: _ConnectionState,
    streamer: ScreencastStreamer,
    out_queue: asyncio.Queue[dict[str, Any] | None],
    settings: Settings,
) -> None:
    prepared = _prepare_input_dispatch(state, streamer, settings)
    if isinstance(prepared, dict):
        await out_queue.put(prepared)
        return
    session = prepared

    try:
        event = KeyboardEvent.model_validate(payload)
    except ValidationError as exc:
        await out_queue.put(
            error_envelope(AppErrorCode.VALIDATION_FAILED, _format_validation(exc))
        )
        return

    try:
        await dispatch_keyboard_event(
            session, event, timeout=settings.browser_cdp_command_timeout
        )
    except ValueError as exc:
        await out_queue.put(
            error_envelope(AppErrorCode.VALIDATION_FAILED, str(exc))
        )
    except asyncio.TimeoutError:
        logger.warning("[%s] key dispatch timed out: %s", state.graph_id, event.action)
        await out_queue.put(
            error_envelope(
                AppErrorCode.CDP_DISPATCH_TIMEOUT, "keyboard event dispatch timed out"
            )
        )
    except (TargetClosedError, PlaywrightError) as exc:
        logger.warning(
            "[%s] key dispatch failed (%s): %s", state.graph_id, event.action, exc
        )
        await out_queue.put(
            error_envelope(AppErrorCode.CDP_DISPATCH_FAILED, f"input dispatch failed: {exc}")
        )


def _prepare_input_dispatch(
    state: _ConnectionState,
    streamer: ScreencastStreamer,
    settings: Settings,
) -> Any:
    """Gate check for input events.

    Returns the live ``CDPSession`` when input may be dispatched, otherwise
    an ``ERROR`` envelope to send back to the client.
    """
    if settings.browser_input_requires_takeover and not state.takeover_active:
        return error_envelope(
            AppErrorCode.TAKEOVER_NOT_ACTIVE,
            "human takeover is not active; send SET_TAKEOVER {enabled: true} first",
        )
    session = streamer.active_session
    if session is None:
        return error_envelope(
            AppErrorCode.SESSION_NOT_READY,
            "screencast session is not attached yet; wait for STREAM_READY",
        )
    return session


# ---------------------------------------------------------------------------
# Auth / validation / shutdown helpers
# ---------------------------------------------------------------------------


def _authenticate(websocket: WebSocket, settings: Settings) -> None:
    """Validate the optional shared token (query param or Bearer header)."""
    expected = settings.api_ws_auth_token
    if not expected:
        return

    provided = websocket.query_params.get("token", "")
    if not provided:
        header = websocket.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            provided = header[7:].strip()

    if not provided or not secrets.compare_digest(
        provided.encode("utf-8"), expected.encode("utf-8")
    ):
        raise _AuthError("missing or invalid authentication token")


def _validate_graph_id(graph_id: str, settings: Settings) -> None:
    try:
        pattern = re.compile(settings.api_graph_id_pattern)
    except re.error as exc:
        raise _ProtocolError(f"misconfigured graph_id pattern: {exc}") from exc
    if not pattern.fullmatch(graph_id):
        raise _ProtocolError(
            f"graph_id {graph_id!r} does not match {settings.api_graph_id_pattern!r}"
        )


def _describe_client(websocket: WebSocket) -> str:
    client = websocket.client
    return f"{client.host}:{client.port}" if client else "unknown"


def _format_validation(exc: ValidationError) -> str:
    details = "; ".join(
        f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}"
        for err in exc.errors()
    )
    return f"payload validation failed: {details}"


async def _reject(
    websocket: WebSocket,
    close_code: WsCloseCode,
    app_code: AppErrorCode,
    message: str,
) -> None:
    """Send a final ERROR envelope and close a freshly accepted socket."""
    with contextlib.suppress(Exception):
        await websocket.send_json(error_envelope(app_code, message))
    await _close_socket(websocket, close_code, message)


async def _close_socket(
    websocket: WebSocket, code: int, reason: str
) -> None:
    """Close the socket exactly once, tolerating already-closed states."""
    if (
        websocket.client_state is WebSocketState.CONNECTED
        and websocket.application_state is not WebSocketState.DISCONNECTED
    ):
        with contextlib.suppress(Exception):
            await websocket.close(code=code, reason=reason[:120])


def _classify_completion(
    graph_id: str, done: set[asyncio.Task[Any]]
) -> tuple[int, str]:
    """Map the first finished task(s) to a WebSocket close code/reason."""
    for task in done:
        name = task.get_name()
        if task.cancelled():
            continue
        exc = task.exception()

        if exc is not None:
            if isinstance(exc, WebSocketDisconnect):
                return WsCloseCode.NORMAL, "client disconnected"
            if isinstance(exc, _ProtocolError):
                return WsCloseCode.BAD_REQUEST, str(exc)
            if isinstance(exc, _AuthError):
                return WsCloseCode.UNAUTHORIZED, str(exc)
            logger.error("[%s] task %s crashed: %r", graph_id, name, exc)
            return WsCloseCode.INTERNAL_ERROR, f"internal error in {name}"

        # Task completed without exception.
        if name == _TASK_WS_RECEIVER:
            return WsCloseCode.NORMAL, "client disconnected"
        if name == _TASK_STREAM_RUNNER:
            # run() exited after fatal retries / max attempts; the pump and
            # writer wind down on their own after the sentinel.
            return WsCloseCode.STREAM_ENDED, "browser stream terminated"
        if name == _TASK_FRAME_PUMP:
            return WsCloseCode.STREAM_ENDED, "browser stream terminated"
        if name == _TASK_WS_WRITER:
            # Writer only exits on the sentinel (stream ended) or send error.
            return WsCloseCode.STREAM_ENDED, "browser stream terminated"

    return WsCloseCode.NORMAL, "connection closed"
