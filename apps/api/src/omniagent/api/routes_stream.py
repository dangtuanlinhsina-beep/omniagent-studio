"""WebSocket streaming endpoints: live browser screen + human takeover.

Endpoint
--------
``WS /ws/graph/{graph_id}``

Lifecycle:
    1. Extract the bearer token from the handshake (Authorization header,
       ``?token=``/``?access_token=`` query, or a ``bearer.<jwt>``
       ``Sec-WebSocket-Protocol`` entry for browser clients) and verify it
       BEFORE accepting: JWT (HS256 secret or Clerk/Supabase JWKS) when
       configured, otherwise the legacy static shared token. Failures are
       rejected at handshake level (close code 4401 => HTTP 403 for
       browsers) so no unauthenticated frame is ever produced.
    2. Validate ``graph_id`` and resolve the sandbox CDP endpoint via
       :class:`~omniagent.sandboxes.browser.registry.SandboxRegistry`.
       (Binding the graph to ``AuthContext.workspace_id`` is the registry /
       orchestrator's responsibility — the context is threaded through for
       that purpose.)
    3. Start a :class:`~omniagent.sandboxes.browser.streamer.ScreencastStreamer`
       which pushes ``SCREEN_FRAME`` / lifecycle envelopes onto a queue.
    4. Run four cooperating tasks: stream runner (supervisor-owned), frame
       pump, a *single* outbound writer (WebSocket sends are serialised
       through one task to avoid interleaving) and the inbound receive loop.
    5. When any task finishes (client disconnect, fatal stream error, send
       failure, rate-limit strike-out) everything is torn down
       deterministically and the socket is closed with a meaningful code.

Authorisation (role-based takeover)
-----------------------------------
* ``VIEWER``   — frames + PING only. ``MOUSE_EVENT`` / ``KEYBOARD_EVENT`` /
  ``SET_TAKEOVER`` are rejected with error code ``40301`` and
  ``reason="role_forbidden"``.
* ``OPERATOR`` / ``ADMIN`` — may toggle takeover and, while takeover is
  active, drive mouse/keyboard. (Further ADMIN-only operations can hook
  ``AuthContext.role`` where noted.)
* Legacy static-token connections (no JWT configured) carry no role info and
  retain full control rights — set ``OMNIAGENT_SECURITY_JWT_SECRET`` (or
  JWKS) to enforce RBAC.

Anti spam/DoS
-------------
Every inbound message passes a per-connection message bucket; mouse/keyboard
events additionally pass the *input* bucket (default 60 packets/s).
Rejections return error ``42901`` (with ``retry_after``) and count strikes;
after ``OMNIAGENT_SECURITY_RATE_LIMIT_MAX_STRIKES`` the socket is closed
with code ``4429``.

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
from playwright.async_api import CDPSession
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
from ..sandboxes.browser.registry import get_sandbox_registry
from ..sandboxes.browser.streamer import ScreencastStreamer
from ..security.auth import (
    AuthContext,
    Authenticator,
    AuthError,
    ConnectionRateLimiter,
    build_rate_limiter,
    extract_ws_token,
)
from .supervisor import TaskSupervisor

logger = logging.getLogger(__name__)

router = APIRouter()

_TASK_STREAM_RUNNER: Final = "graph-stream-runner"
_TASK_FRAME_PUMP: Final = "graph-frame-pump"
_TASK_WS_WRITER: Final = "graph-ws-writer"
_TASK_WS_RECEIVER: Final = "graph-ws-receiver"

_OUT_QUEUE_FACTOR: Final = 2

_INPUT_MESSAGE_TYPES: Final[frozenset[str]] = frozenset(
    {ClientMessageType.MOUSE_EVENT.value, ClientMessageType.KEYBOARD_EVENT.value}
)


class _AuthError(Exception):
    """WebSocket handshake authentication failed."""


class _ProtocolError(Exception):
    """WebSocket-level protocol violation (close the connection)."""


class _RateLimitError(Exception):
    """Client exceeded the rate-limit strike budget (close 4429)."""


@dataclass
class _ConnectionState:
    """Per-connection mutable state."""

    graph_id: str
    auth: AuthContext | None
    limiter: ConnectionRateLimiter
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

    # --- Handshake: authenticate BEFORE accept (reject with HTTP 403) -----
    token, subprotocol = extract_ws_token(websocket)
    try:
        auth = await _perform_handshake_auth(websocket, token, settings)
        _validate_graph_id(graph_id, settings)
    except _AuthError as exc:
        logger.warning("[%s] handshake rejected for %s: %s", graph_id, client, exc)
        await _reject_handshake(websocket, WsCloseCode.UNAUTHORIZED, str(exc))
        return
    except _ProtocolError as exc:
        logger.warning("[%s] handshake rejected for %s: %s", graph_id, client, exc)
        await _reject_handshake(websocket, WsCloseCode.BAD_REQUEST, str(exc))
        return

    await websocket.accept(subprotocol=subprotocol)

    registry = get_sandbox_registry()
    try:
        cdp_url = await registry.resolve_cdp_url(graph_id)
    except Exception:
        logger.exception("[%s] sandbox registry failure", graph_id)
        await _close_socket(
            websocket, WsCloseCode.INTERNAL_ERROR, "failed to resolve browser sandbox"
        )
        return

    if auth is not None:
        logger.info(
            "[%s] websocket connected (%s): user=%s workspace=%s role=%s; sandbox=%s",
            graph_id,
            client,
            auth.user_id,
            auth.workspace_id or "-",
            auth.role.value,
            cdp_url or "<local-fallback>",
        )
        # Integration point: verify `graph_id` belongs to `auth.workspace_id`
        # once the registry is backed by the workspace-aware orchestrator.
    else:
        logger.info(
            "[%s] websocket connected (%s): legacy/static auth, full control; "
            "sandbox=%s",
            graph_id,
            client,
            cdp_url or "<local-fallback>",
        )

    state = _ConnectionState(
        graph_id=graph_id, auth=auth, limiter=build_rate_limiter(settings)
    )
    streamer = ScreencastStreamer(graph_id=graph_id, settings=settings, cdp_url=cdp_url)
    out_queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(
        maxsize=settings.browser_frame_queue_size * _OUT_QUEUE_FACTOR
    )

    # The stream runner is spawned through the app-level supervisor (owned by
    # the lifespan, outside any request cancel scope) so an abrupt handler
    # cancellation can never interrupt Playwright/CDP teardown mid-flight
    # and leak the driver subprocess. Falls back to a local task when the
    # supervisor is unavailable (e.g. app mounted without its lifespan).
    supervisor: TaskSupervisor | None = getattr(
        websocket.app.state, "stream_supervisor", None
    )
    if supervisor is not None and supervisor.is_running:
        runner = await supervisor.submit(streamer.run(), name=_TASK_STREAM_RUNNER)
    else:
        runner = asyncio.create_task(streamer.run(), name=_TASK_STREAM_RUNNER)

    tasks = {
        runner,
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

    close_code: int = WsCloseCode.NORMAL
    close_reason = "connection closed"
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        close_code, close_reason = _classify_completion(graph_id, done)
    finally:
        logger.debug("[%s] cleanup: stopping streamer", graph_id)
        streamer.stop()
        # Cancel the lightweight IO tasks first so an external cancellation
        # of this handler can never orphan them.
        for task in tasks:
            if task is not runner:
                task.cancel()
        # Give the streamer a grace window to finish its CDP/Playwright
        # teardown cleanly; cancelling it mid-teardown would leak the driver
        # subprocess and socket. shield() so OUR timeout can't kill it.
        grace = settings.browser_cdp_command_timeout + 5.0
        try:
            await asyncio.wait_for(asyncio.shield(runner), timeout=grace)
        except asyncio.CancelledError:
            # This handler itself is being cancelled (e.g. TestClient /
            # server shutdown). The runner is supervisor-owned and already
            # stopping gracefully; let it finish detached. IO tasks are
            # cancelled above, so nothing is orphaned by re-raising.
            logger.debug(
                "[%s] cleanup: handler cancelled; streamer finishes detached",
                graph_id,
            )
            raise
        except (TimeoutError, PlaywrightError, OSError):
            logger.warning(
                "[%s] cleanup: streamer did not stop within grace", graph_id
            )
        runner.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for task, result in zip(tasks, results, strict=True):
            if isinstance(result, BaseException) and not isinstance(
                result, (asyncio.CancelledError, WebSocketDisconnect)
            ):
                logger.error(
                    "[%s] task %s failed: %r", graph_id, task.get_name(), result
                )
        await _close_socket(websocket, close_code, close_reason)
        logger.info(
            "[%s] websocket closed (%s): code=%d reason=%r frames_sent=%d "
            "strikes=%d duration=%.1fs",
            graph_id,
            client,
            close_code,
            close_reason,
            state.frames_sent,
            state.limiter.strikes,
            time.time() - state.started_at,
        )


# ---------------------------------------------------------------------------
# Handshake authentication / validation
# ---------------------------------------------------------------------------


def _get_authenticator(websocket: WebSocket, settings: Settings) -> Authenticator:
    """Prefer the app-wide instance (lifespan-managed JWKS cache/client)."""
    authenticator: Authenticator | None = getattr(
        websocket.app.state, "authenticator", None
    )
    if authenticator is not None:
        return authenticator
    logger.warning(
        "no app-level Authenticator found (lifespan not run?); "
        "building an ephemeral instance for this request"
    )
    return Authenticator(settings)


async def _perform_handshake_auth(
    websocket: WebSocket, token: str | None, settings: Settings
) -> AuthContext | None:
    """Authenticate the handshake.

    Returns the verified :class:`AuthContext`, or ``None`` for legacy
    static-token / open dev modes (no role information => full control).
    Raises :class:`_AuthError` to reject the connection.
    """
    authenticator = _get_authenticator(websocket, settings)

    if authenticator.is_configured:
        if not token:
            raise _AuthError(
                "missing authentication token (Authorization: Bearer, "
                "?token=, or Sec-WebSocket-Protocol 'bearer.<jwt>')"
            )
        try:
            return await authenticator.authenticate(token)
        except AuthError as exc:
            raise _AuthError(f"{type(exc).reason}: {exc}") from exc

    # Legacy mode: static shared token (constant-time compare).
    expected = settings.api_ws_auth_token
    if expected:
        if not token or not secrets.compare_digest(
            token.encode("utf-8"), expected.encode("utf-8")
        ):
            raise _AuthError("missing or invalid authentication token")
        return None

    logger.warning(
        "WebSocket auth is DISABLED (no JWT secret/JWKS and no static token); "
        "anyone reaching this endpoint can view and control sandboxes"
    )
    return None


def _validate_graph_id(graph_id: str, settings: Settings) -> None:
    try:
        pattern = re.compile(settings.api_graph_id_pattern)
    except re.error as exc:
        raise _ProtocolError(f"misconfigured graph_id pattern: {exc}") from exc
    if not pattern.fullmatch(graph_id):
        raise _ProtocolError(
            f"graph_id {graph_id!r} does not match {settings.api_graph_id_pattern!r}"
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

    Returns on clean client disconnect; raises :class:`_RateLimitError`
    when the strike budget is exhausted (close 4429).
    """
    graph_id = state.graph_id
    limiter = state.limiter
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            logger.info(
                "[%s] client disconnected (code=%s)",
                graph_id,
                message.get("code"),
            )
            return

        # Whole-message flood guard — applied before any parsing work.
        if not limiter.allow_message():
            await _register_rate_violation(
                graph_id, limiter, out_queue, for_input=False
            )
            continue

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

        if msg_type in _INPUT_MESSAGE_TYPES and not limiter.allow_input():
            await _register_rate_violation(
                graph_id, limiter, out_queue, for_input=True
            )
            continue

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


async def _register_rate_violation(
    graph_id: str,
    limiter: ConnectionRateLimiter,
    out_queue: asyncio.Queue[dict[str, Any] | None],
    *,
    for_input: bool,
) -> None:
    """Emit a 42901 envelope; raise :class:`_RateLimitError` on strike-out."""
    exceeded = limiter.register_strike()
    kind = "input" if for_input else "message"
    logger.warning(
        "[%s] rate limit exceeded (%s): strike %d/%d",
        graph_id,
        kind,
        limiter.strikes,
        limiter.max_strikes,
    )
    await out_queue.put(
        error_envelope(
            AppErrorCode.RATE_LIMITED,
            f"{kind} rate limit exceeded; slow down",
            reason="rate_limited",
            retry_after=limiter.retry_after(for_input=for_input),
            strikes=limiter.strikes,
        )
    )
    if exceeded:
        raise _RateLimitError(
            f"rate-limit strike budget exhausted ({limiter.strikes} violations)"
        )


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


async def _handle_set_takeover(
    payload: dict[str, Any],
    state: _ConnectionState,
    out_queue: asyncio.Queue[dict[str, Any] | None],
) -> None:
    # Role gate: VIEWER may never (de)activate human takeover.
    if not _may_control(state):
        _log_forbidden(state, "SET_TAKEOVER")
        await out_queue.put(_role_forbidden_envelope(state))
        return

    try:
        message = SetTakeoverMessage.model_validate(payload)
    except ValidationError as exc:
        await out_queue.put(
            error_envelope(AppErrorCode.VALIDATION_FAILED, _format_validation(exc))
        )
        return

    state.takeover_active = message.enabled
    logger.info(
        "[%s] human takeover %s by %s (role=%s)",
        state.graph_id,
        "ENABLED" if message.enabled else "disabled",
        state.auth.user_id if state.auth else "<static-token>",
        state.auth.role.value if state.auth else "-",
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
    if isinstance(prepared, dict):  # error envelope to send back
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
    except TimeoutError:
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
    except TimeoutError:
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


def _may_control(state: _ConnectionState) -> bool:
    """RBAC gate: True when the connection may drive the browser.

    ``auth is None`` covers legacy static-token / open dev mode (no role
    information available => full control, documented behaviour).
    """
    return state.auth is None or state.auth.can_control


def _role_forbidden_envelope(state: _ConnectionState) -> dict[str, Any]:
    role = state.auth.role.value if state.auth else "UNKNOWN"
    return error_envelope(
        AppErrorCode.TAKEOVER_NOT_ACTIVE,
        f"role {role} is not allowed to control this sandbox "
        "(requires OPERATOR or ADMIN)",
        reason="role_forbidden",
        role=role,
    )


def _log_forbidden(state: _ConnectionState, action: str) -> None:
    logger.warning(
        "[%s] forbidden %s from user=%s role=%s",
        state.graph_id,
        action,
        state.auth.user_id if state.auth else "-",
        state.auth.role.value if state.auth else "-",
    )


def _prepare_input_dispatch(
    state: _ConnectionState,
    streamer: ScreencastStreamer,
    settings: Settings,
) -> CDPSession | dict[str, Any]:
    """Gate check for input events.

    Returns the live ``CDPSession`` when input may be dispatched, otherwise
    an ``ERROR`` envelope to send back to the client. Order: RBAC ->
    takeover handshake -> session readiness.
    """
    if not _may_control(state):
        _log_forbidden(state, "input")
        return _role_forbidden_envelope(state)
    if settings.browser_input_requires_takeover and not state.takeover_active:
        return error_envelope(
            AppErrorCode.TAKEOVER_NOT_ACTIVE,
            "human takeover is not active; send SET_TAKEOVER {enabled: true} first",
            reason="takeover_not_active",
        )
    session = streamer.active_session
    if session is None:
        return error_envelope(
            AppErrorCode.SESSION_NOT_READY,
            "screencast session is not attached yet; wait for STREAM_READY",
            reason="session_not_ready",
        )
    return session


# ---------------------------------------------------------------------------
# Shutdown helpers
# ---------------------------------------------------------------------------


def _describe_client(websocket: WebSocket) -> str:
    client = websocket.client
    return f"{client.host}:{client.port}" if client else "unknown"


def _format_validation(exc: ValidationError) -> str:
    details = "; ".join(
        f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}"
        for err in exc.errors()
    )
    return f"payload validation failed: {details}"


async def _reject_handshake(
    websocket: WebSocket, close_code: WsCloseCode, reason: str
) -> None:
    """Refuse the handshake BEFORE accept (client sees HTTP 403)."""
    with contextlib.suppress(Exception):
        await websocket.close(code=close_code, reason=reason[:120])


async def _close_socket(websocket: WebSocket, code: int, reason: str) -> None:
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
            if isinstance(exc, _RateLimitError):
                logger.warning("[%s] closing: %s", graph_id, exc)
                return WsCloseCode.RATE_LIMITED, str(exc)
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
