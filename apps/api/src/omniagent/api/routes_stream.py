"""WebSocket streaming endpoint: live browser screen + human takeover.

Endpoint
--------
``WS /ws/graph/{graph_id}``

Handshake gauntlet (credentials and authorization are verified **before**
``accept()`` so an invalid ticket never receives HTTP 101 and no streamer/CDP
session/queue is allocated for an unauthenticated attempt):

    1. ``Origin`` allow-list  → cross-site WebSocket hijacking.
    2. Per-IP handshake throttle → connection floods.
    3. ``graph_id`` shape (regex) → template/path injection.
    4. Extract credential from ``Sec-WebSocket-Protocol`` / ``Authorization`` /
       optional ``?token=``; reject missing credentials.
    5. Full JWT verification (signature, ``iss``/``aud``/``exp``/``nbf``,
       single-use ticket replay, optional sender binding) → principal.
    6. **Object-level authorization**: the principal's ``gph`` claim must
       cover ``graph_id`` and the graph authorizer must grant ``screen:view``.
    7. ``accept(subprotocol=…)`` — echoing the negotiated subprotocol is
       mandatory or browsers abort with 1006.

After ``accept()``:

    8. Concurrency caps (per graph / per principal) are applied before the
       streamer/CDP session is started.
    9. ``SESSION_READY`` is sent, then four cooperating tasks run: stream
       runner, frame pump, a *single* serialised outbound writer and the
       inbound receiver, plus a watchdog (idle / lifetime / token expiry /
       takeover-lease expiry).

Authorization matrix
--------------------
========================  ==================  ==============================
Message                   Minimum role        Extra gate
========================  ==================  ==============================
``PING``                  any                 ``ping`` bucket
``AUTH``                  any                 ``auth`` bucket, same ``sub``
``SCREEN_FRAME`` (out)    ``VIEWER``          outbound policy filter
``SET_TAKEOVER``          ``OPERATOR``        ``control`` bucket + lease
``MOUSE_EVENT``           ``OPERATOR``        takeover lease + input buckets
``KEYBOARD_EVENT``        ``OPERATOR``        takeover lease + input buckets
========================  ==================  ==============================

A ``VIEWER`` therefore *only* receives the video stream: every state-changing
message is rejected with ``ERROR{code: 40300}`` and, after repeated attempts,
the socket is closed with ``4403``.

DoS protection for the CDP input path (three layers)
----------------------------------------------------
* ``mouseMoved`` coalescing — one move per frame interval (~16 ms) per
  connection; intermediate positions are worthless to the remote browser.
* Per-connection token buckets — separate budgets for ``message`` (any frame),
  ``input``, ``control``, ``ping`` and ``auth``.
* One shared per-graph ``graph_input`` bucket — N operators on the same
  sandbox cannot multiply CDP pressure.

Rejections produce ``ERROR{code: 42901, retry_after_ms}``; accumulating
``api_ws_rate_limit_strikes`` of them closes the socket with ``4429``.
Inbound frames larger than ``api_ws_max_message_bytes`` are refused *before*
``json.loads`` (a 100 MB payload is a parse-time DoS, not a protocol message).

Takeover lease
--------------
Only one connection per graph may drive the browser (SPEC §5).  The lease has
a TTL, is renewed by operator activity and auto-expires when the holder goes
silent or disconnects; the change is broadcast to the rest of the graph's room
so every UI stops showing the crosshair.

Integration point: when the lease flips, a full deployment should also
pause/resume the agent's graph execution (publish to the graph supervisor).
That coupling lives outside the sandbox layer; here we log + notify clients.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
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
    AuthMessage,
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
from ..sandboxes.browser.streamer import ScreencastStreamer
from ..security.audit import AuditEvent, audit_event
from ..security.ratelimit import (
    ConnectionRateLimiter,
    RateLimitDecision,
    MouseMoveCoalescer,
    ThrottleStats,
    get_graph_input_registry,
)
from ..security.roles import Permission, Principal, Role
from ..security.tokens import TokenError, TokenService, client_fingerprint, get_token_service
from ..security.ws_auth import (
    WsAuthError,
    WsCredentials,
    authenticate_message_token,
    check_origin,
    client_ip,
    extract_credentials,
    record_handshake_attempt,
    resolve_principal,
)
from .connection_registry import (
    ConnectionRegistry,
    WsConnection,
    get_connection_registry,
    new_connection_id,
    takeover_state_envelope,
)
from .graph_access import (
    GraphAccessError,
    GraphContext,
    get_graph_authorizer,
    validate_graph_id,
)

logger = logging.getLogger(__name__)

router = APIRouter()

_TASK_STREAM_RUNNER: Final = "graph-stream-runner"
_TASK_FRAME_PUMP: Final = "graph-frame-pump"
_TASK_WS_WRITER: Final = "graph-ws-writer"
_TASK_WS_RECEIVER: Final = "graph-ws-receiver"
_TASK_WATCHDOG: Final = "graph-watchdog"

_OUT_QUEUE_FACTOR: Final = 2
_WATCHDOG_PERIOD_S: Final = 2.0
_TOKEN_EXPIRY_WARNING_S: Final = 60.0

#: Outbound envelope policy.  A ``VIEWER`` receives the video stream and the
#: protocol frames it needs to stay alive — nothing about *who* is driving.
_VIEWER_OUTBOUND: Final[frozenset[str]] = frozenset(
    {
        ServerMessageType.SCREEN_FRAME.value,
        ServerMessageType.STREAM_READY.value,
        ServerMessageType.STREAM_RECONNECTING.value,
        ServerMessageType.STREAM_ERROR.value,
        ServerMessageType.SESSION_READY.value,
        ServerMessageType.AUTH_REQUIRED.value,
        ServerMessageType.PONG.value,
        ServerMessageType.ERROR.value,
        ServerMessageType.RATE_LIMITED.value,
    }
)
_OPERATOR_OUTBOUND: Final[frozenset[str]] = _VIEWER_OUTBOUND | {
    ServerMessageType.TAKEOVER_STATE.value
}


class _AuthError(Exception):
    """WebSocket authentication failed (close with 4401/4403)."""


class _ProtocolError(Exception):
    """WebSocket-level protocol violation (close the connection)."""


class _CloseRequest(Exception):
    """Deliberate close from a worker task, carrying code + reason."""

    def __init__(self, code: int, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(reason)


@dataclass
class _ConnectionState:
    """Per-connection mutable state."""

    graph_id: str
    connection_id: str
    principal: Principal
    client_label: str = "unknown"
    takeover_active: bool = False
    started_at: float = field(default_factory=time.time)
    last_activity_at: float = field(default_factory=time.time)
    frames_sent: int = 0
    messages_in: int = 0
    inputs_dispatched: int = 0
    inputs_suppressed: int = 0
    permission_denials: int = 0
    reauth_requested_at: float | None = None
    reauth_deadline: float | None = None

    def touch(self) -> None:
        self.last_activity_at = time.time()


@dataclass
class _Session:
    """Everything the worker tasks share (keeps signatures readable)."""

    websocket: WebSocket
    settings: Settings
    state: _ConnectionState
    streamer: ScreencastStreamer
    out_queue: asyncio.Queue[dict[str, Any] | None]
    connection: WsConnection
    limiter: ConnectionRateLimiter
    graph_limiter: ConnectionRateLimiter
    move_coalescer: MouseMoveCoalescer
    token_service: TokenService
    registry: ConnectionRegistry
    graph: GraphContext
    fingerprint: str | None
    credentials: WsCredentials | None
    stats: ThrottleStats = field(default_factory=ThrottleStats)
    lease_ttl_s: float = 120.0

    @property
    def graph_id(self) -> str:
        return self.state.graph_id

    @property
    def principal(self) -> Principal:
        return self.state.principal

    def push(self, envelope: dict[str, Any] | None) -> None:
        """Queue an outbound envelope (drop-oldest under backpressure)."""
        while True:
            try:
                self.out_queue.put_nowait(envelope)
                return
            except asyncio.QueueFull:
                with contextlib.suppress(asyncio.QueueEmpty):
                    self.out_queue.get_nowait()

    def push_error(self, code: int, message: str, **fields: Any) -> None:
        self.push(error_envelope(code, message, **fields))


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.websocket("/ws/graph/{graph_id}")
async def graph_browser_stream(websocket: WebSocket, graph_id: str) -> None:
    """Stream a graph's browser sandbox and relay authorized takeover input."""
    settings = get_settings()
    token_service = get_token_service(settings)
    registry = get_connection_registry()
    ip_address = client_ip(websocket, settings)
    client = _describe_client(websocket, settings)

    # -- 1. Pre-accept gauntlet (no resources allocated on failure) -------
    subprotocol: str | None = None
    credentials: WsCredentials | None = None
    try:
        check_origin(websocket, settings)
        record_handshake_attempt(websocket, settings)
        validate_graph_id(graph_id, settings)
        credentials, subprotocol = extract_credentials(websocket, settings)
        _require_credential_present(credentials, settings)
    except (WsAuthError, GraphAccessError) as exc:
        close_code, app_code, message = _normalize_handshake_error(exc)
        audit_event(
            AuditEvent.WS_HANDSHAKE_REJECTED,
            graph_id=graph_id,
            ip=ip_address,
            close_code=close_code,
            app_code=app_code,
            reason=message,
            level=logging.WARNING,
        )
        logger.warning(
            "[%s] handshake refused for %s: %s (close=%d app=%d)",
            graph_id,
            client,
            message,
            close_code,
            app_code,
        )
        await _refuse_handshake(websocket, settings)
        return

    # -- 2. Verify credential + authorize graph BEFORE HTTP 101 ---------
    # A WebSocket handshake is not accepted merely because a credential is
    # present: validate signature/type/expiry/replay, graph scope, and the
    # screen:view permission before allocating an accepted socket.
    fingerprint = (
        client_fingerprint(ip_address, websocket.headers.get("user-agent"))
        if settings.jwt_ticket_bind_client
        else None
    )
    try:
        auth = resolve_principal(
            credentials,
            settings=settings,
            graph_id=graph_id,
            token_service=token_service,
            fingerprint=fingerprint,
        )
        principal = auth.principal
        graph_ctx = await get_graph_authorizer(settings).authorize(
            principal, graph_id, permission=Permission.SCREEN_VIEW
        )
    except (WsAuthError, GraphAccessError, TokenError) as exc:
        close_code, app_code, message = _normalize_handshake_error(exc)
        audit_event(
            AuditEvent.WS_AUTH_FAILED,
            graph_id=graph_id,
            ip=ip_address,
            close_code=close_code,
            app_code=app_code,
            reason=message,
            token=credentials.token if credentials else None,
            level=logging.WARNING,
        )
        logger.warning("[%s] refusing handshake for %s: %s", graph_id, client, message)
        await _refuse_handshake(websocket, settings)
        return

    # Only an authenticated, graph-authorized principal receives HTTP 101.
    await websocket.accept(subprotocol=subprotocol)

    # -- 3. Concurrency caps ---------------------------------------------
    connection_id = new_connection_id()
    out_queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(
        maxsize=settings.browser_frame_queue_size * _OUT_QUEUE_FACTOR
    )
    connection = WsConnection(
        id=connection_id,
        graph_id=graph_id,
        principal=principal,
        out_queue=out_queue,
        client_label=client,
    )
    registration = registry.register(
        connection,
        max_per_graph=settings.api_ws_max_connections_per_graph,
        max_per_principal=settings.api_ws_max_connections_per_principal,
    )
    if not registration.ok:
        audit_event(
            AuditEvent.WS_HANDSHAKE_REJECTED,
            graph_id=graph_id,
            subject=principal.subject,
            role=principal.role.value,
            connection_id=connection_id,
            ip=ip_address,
            reason=registration.reason,
            level=logging.WARNING,
        )
        await _reject(
            websocket,
            WsCloseCode.TOO_MANY_REQUESTS,
            AppErrorCode.CONNECTION_LIMIT,
            "connection limit reached for this graph",
        )
        return

    graph_limiter = get_graph_input_registry().acquire(graph_id)
    state = _ConnectionState(
        graph_id=graph_id,
        connection_id=connection_id,
        principal=principal,
        client_label=client,
    )
    session = _Session(
        websocket=websocket,
        settings=settings,
        state=state,
        streamer=ScreencastStreamer(
            graph_id=graph_id,
            settings=settings,
            cdp_url=graph_ctx.cdp_url,
            cdp_headers=graph_ctx.cdp_headers,
        ),
        out_queue=out_queue,
        connection=connection,
        limiter=ConnectionRateLimiter(
            settings.ws_rate_limit_policies(),
            max_strikes=settings.api_ws_rate_limit_strikes,
        ),
        graph_limiter=graph_limiter,
        move_coalescer=MouseMoveCoalescer(settings.ratelimit_mouse_move_interval_ms / 1000.0),
        token_service=token_service,
        registry=registry,
        graph=graph_ctx,
        fingerprint=fingerprint,
        credentials=credentials,
        lease_ttl_s=min(settings.takeover_lease_ttl_s, settings.takeover_max_lease_s),
    )

    logger.info(
        "[%s] websocket connected (%s) conn=%s %s source=%s ticket=%s sandbox=%s",
        graph_id,
        client,
        connection_id,
        principal.describe(),
        auth.source.value,
        auth.used_ticket,
        graph_ctx.cdp_url or "<local-fallback>",
    )
    audit_event(
        AuditEvent.WS_CONNECTED,
        graph_id=graph_id,
        subject=principal.subject,
        role=principal.role.value,
        connection_id=connection_id,
        ip=ip_address,
        credential_source=auth.source.value,
        used_ticket=auth.used_ticket,
        connections_in_graph=registration.graph_connections,
    )

    session.push(_session_ready_envelope(session))

    tasks = {
        asyncio.create_task(session.streamer.run(), name=_TASK_STREAM_RUNNER),
        asyncio.create_task(_pump_stream_events(session), name=_TASK_FRAME_PUMP),
        asyncio.create_task(_writer_loop(session), name=_TASK_WS_WRITER),
        asyncio.create_task(_receive_loop(session), name=_TASK_WS_RECEIVER),
        asyncio.create_task(_watchdog(session), name=_TASK_WATCHDOG),
    }

    close_code = WsCloseCode.NORMAL
    close_reason = "connection closed"
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        close_code, close_reason = _classify_completion(graph_id, done)
    finally:
        _release_takeover(session, reason="connection closed")
        registry.unregister(graph_id, connection_id)
        get_graph_input_registry().release(graph_id)
        session.streamer.stop()
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
                result, (asyncio.CancelledError, WebSocketDisconnect, _CloseRequest)
            ):
                logger.error(
                    "[%s] task %s failed: %r", graph_id, task.get_name(), result
                )
        await _close_socket(websocket, close_code, close_reason)
        logger.info(
            "[%s] websocket closed (%s) conn=%s %s: code=%d reason=%r "
            "frames_sent=%d in=%d inputs=%d suppressed=%d denied=%d duration=%.1fs",
            graph_id,
            client,
            connection_id,
            state.principal.describe(),
            close_code,
            close_reason,
            state.frames_sent,
            state.messages_in,
            state.inputs_dispatched,
            state.inputs_suppressed,
            state.permission_denials,
            time.time() - state.started_at,
        )
        audit_event(
            AuditEvent.WS_DISCONNECTED,
            graph_id=graph_id,
            subject=state.principal.subject,
            role=state.principal.role.value,
            connection_id=connection_id,
            close_code=close_code,
            reason=close_reason,
            frames_sent=state.frames_sent,
            messages_in=state.messages_in,
            inputs_dispatched=state.inputs_dispatched,
            inputs_suppressed=state.inputs_suppressed,
            permission_denials=state.permission_denials,
            throttled=session.stats.as_dict(),
            duration_s=round(time.time() - state.started_at, 3),
        )


# ---------------------------------------------------------------------------
# Task loops
# ---------------------------------------------------------------------------


async def _pump_stream_events(session: _Session) -> None:
    """Move streamer envelopes to the outbound queue; propagate the sentinel."""
    while True:
        envelope = await session.streamer.events.get()
        if envelope is None:
            session.push(None)
            return
        session.push(envelope)


async def _writer_loop(session: _Session) -> None:
    """The ONLY task allowed to send on the socket (serialised writer).

    Also the single place where the role-based outbound policy is applied, so
    neither the streamer nor a broadcast from another connection can leak an
    operator-only envelope to a ``VIEWER``.
    """
    while True:
        envelope = await session.out_queue.get()
        if envelope is None:
            return
        if not _outbound_allowed(session.principal.role, envelope, session.settings):
            continue
        await session.websocket.send_json(envelope)
        if envelope.get("type") == ServerMessageType.SCREEN_FRAME.value:
            session.state.frames_sent += 1


async def _watchdog(session: _Session) -> None:
    """Enforce idle timeout, absolute lifetime, credential and lease expiry."""
    settings = session.settings
    state = session.state
    while True:
        await asyncio.sleep(_WATCHDOG_PERIOD_S)
        now = time.time()

        # (a) Idle socket — a dead client must not keep a CDP session open.
        if now - state.last_activity_at > settings.api_ws_idle_timeout_s:
            audit_event(
                AuditEvent.WS_IDLE_TIMEOUT,
                graph_id=state.graph_id,
                subject=state.principal.subject,
                connection_id=state.connection_id,
                idle_s=round(now - state.last_activity_at, 1),
                level=logging.WARNING,
            )
            session.push_error(
                AppErrorCode.FORBIDDEN, "connection idle for too long", code_hint="idle_timeout"
            )
            raise _CloseRequest(
                WsCloseCode.IDLE_TIMEOUT,
                f"no client activity for {settings.api_ws_idle_timeout_s:.0f}s",
            )

        # (b) Absolute lifetime — bounds the blast radius of a stolen ticket.
        if (
            settings.api_ws_max_lifetime_s > 0
            and now - state.started_at > settings.api_ws_max_lifetime_s
        ):
            audit_event(
                AuditEvent.WS_LIFETIME_EXCEEDED,
                graph_id=state.graph_id,
                subject=state.principal.subject,
                connection_id=state.connection_id,
                lifetime_s=round(now - state.started_at, 1),
            )
            raise _CloseRequest(
                WsCloseCode.GOING_AWAY, "maximum connection lifetime reached; reconnect"
            )

        # (c) Session expiry — warn once, then close after the grace window.
        #     ``effective_expires_at`` is the *session* expiry: a single-use
        #     ws-ticket only lives ~60 s but must not tear down the socket.
        expires_at = state.principal.effective_expires_at
        if expires_at is not None:
            remaining = expires_at - now
            if remaining <= _TOKEN_EXPIRY_WARNING_S and state.reauth_requested_at is None:
                state.reauth_requested_at = now
                state.reauth_deadline = expires_at + settings.api_ws_reauth_grace_s
                session.push(
                    server_envelope(
                        ServerMessageType.AUTH_REQUIRED,
                        reason="credential_expiring"
                        if remaining > 0
                        else "credential_expired",
                        expires_in_s=max(0, int(remaining)),
                        grace_s=settings.api_ws_reauth_grace_s,
                    )
                )
            if remaining <= 0 and (
                state.reauth_deadline is None or now >= state.reauth_deadline
            ):
                audit_event(
                    AuditEvent.WS_SESSION_EXPIRED,
                    graph_id=state.graph_id,
                    subject=state.principal.subject,
                    connection_id=state.connection_id,
                    level=logging.WARNING,
                )
                raise _CloseRequest(
                    WsCloseCode.UNAUTHORIZED,
                    "credential expired; reconnect with a fresh ticket",
                )

        # (d) Takeover lease bookkeeping: expire stale leases fleet-wide and
        #     drop our own local flag when our lease lapsed.
        for expired in session.registry.sweep_expired_leases():
            if expired.graph_id == state.graph_id:
                session.push(
                    takeover_state_envelope(
                        state.graph_id, None, reason="lease_expired", include_subject=False
                    )
                )
            if expired.graph_id == state.graph_id and state.takeover_active:
                state.takeover_active = False


async def _receive_loop(session: _Session) -> None:
    """Read client commands, authorize them and dispatch.

    Returns on clean client disconnect; raises :class:`_ProtocolError` /
    :class:`_CloseRequest` for violations that must terminate the connection.
    """
    settings = session.settings
    state = session.state
    while True:
        message = await session.websocket.receive()
        if message["type"] == "websocket.disconnect":
            logger.info(
                "[%s] client disconnected (code=%s)",
                state.graph_id,
                message.get("code"),
            )
            return

        try:
            raw = _extract_payload(session, message)
        except _OversizedMessage as exc:
            _record_policy_violation(
                session,
                AppErrorCode.MESSAGE_TOO_LARGE,
                str(exc),
                limit="message_size",
                audit=AuditEvent.WS_MESSAGE_TOO_LARGE,
            )
            if session.limiter.must_disconnect:
                raise _CloseRequest(
                    WsCloseCode.PAYLOAD_TOO_LARGE, "oversized message after repeated violations"
                ) from exc
            continue
        if raw is None:
            continue

        # Global inbound budget is charged *before* json.loads(): parsing a
        # flood is itself a CPU DoS.
        decision = session.limiter.check("message")
        if not decision.allowed:
            _emit_rate_limit(session, decision, audit=AuditEvent.WS_RATE_LIMITED)
            if session.limiter.must_disconnect:
                raise _CloseRequest(
                    WsCloseCode.TOO_MANY_REQUESTS, "message rate limit exceeded repeatedly"
                )
            continue

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            session.push_error(AppErrorCode.INVALID_PAYLOAD, f"invalid JSON: {_clip(str(exc))}")
            continue
        if not isinstance(data, dict):
            session.push_error(AppErrorCode.INVALID_PAYLOAD, "message must be a JSON object")
            continue

        state.messages_in += 1
        state.touch()
        session.connection.touch()
        msg_type, payload = parse_client_envelope(data)

        if msg_type == ClientMessageType.PING.value:
            await _handle_ping(session, payload)
        elif msg_type == ClientMessageType.AUTH.value:
            await _handle_auth(session, payload)
        elif msg_type == ClientMessageType.SET_TAKEOVER.value:
            await _handle_set_takeover(session, payload)
        elif msg_type == ClientMessageType.MOUSE_EVENT.value:
            await _handle_mouse_event(session, payload)
        elif msg_type == ClientMessageType.KEYBOARD_EVENT.value:
            await _handle_keyboard_event(session, payload)
        else:
            session.push_error(
                AppErrorCode.UNKNOWN_MESSAGE_TYPE,
                f"unknown message type: {msg_type or '<missing>'!r}",
            )

        if session.limiter.must_disconnect:
            raise _CloseRequest(
                WsCloseCode.TOO_MANY_REQUESTS, "too many throttled messages"
            )


class _OversizedMessage(Exception):
    """An inbound frame exceeded ``api_ws_max_message_bytes``."""


def _extract_payload(session: _Session, message: dict[str, Any]) -> str | None:
    """Return the inbound frame as text, or ``None`` when there is nothing.

    The size guard runs on the **raw bytes before** any decoding or
    ``json.loads`` — parsing a 100 MB frame is itself a CPU DoS, so it must
    never reach the parser.

    Raises:
        _OversizedMessage: when the frame exceeds the configured cap.
    """
    limit = session.settings.api_ws_max_message_bytes
    text = message.get("text")
    if text is None:
        payload_bytes = message.get("bytes")
        if payload_bytes is None:
            return None
        if len(payload_bytes) > limit:
            raise _OversizedMessage(
                f"binary message of {len(payload_bytes)} bytes exceeds the {limit}-byte limit"
            )
        try:
            return payload_bytes.decode("utf-8")
        except UnicodeDecodeError:
            session.push_error(
                AppErrorCode.INVALID_PAYLOAD, "binary payloads must be UTF-8 encoded JSON"
            )
            return None
    if len(text.encode("utf-8")) > limit:
        raise _OversizedMessage(
            f"text message of {len(text.encode('utf-8'))} bytes exceeds the {limit}-byte limit"
        )
    return text


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


async def _handle_ping(session: _Session, payload: dict[str, Any]) -> None:
    decision = session.limiter.check("ping")
    if not decision.allowed:
        _emit_rate_limit(session, decision, audit=AuditEvent.WS_RATE_LIMITED)
        return
    session.push(
        server_envelope(
            ServerMessageType.PONG,
            ts_ms=int(time.time() * 1000),
            echo=payload.get("ts"),
        )
    )


async def _handle_auth(session: _Session, payload: dict[str, Any]) -> None:
    """Mid-connection credential refresh (``AUTH``)."""
    decision = session.limiter.check("auth")
    if not decision.allowed:
        _emit_rate_limit(session, decision, audit=AuditEvent.WS_RATE_LIMITED)
        return
    try:
        message = AuthMessage.model_validate(payload)
    except ValidationError as exc:
        session.push_error(AppErrorCode.VALIDATION_FAILED, _format_validation(exc))
        return

    try:
        result = authenticate_message_token(
            message.token,
            settings=session.settings,
            graph_id=session.graph_id,
            token_service=session.token_service,
            fingerprint=session.fingerprint,
            current=session.principal,
        )
    except (WsAuthError, TokenError) as exc:
        _close_code, app_code, text = _normalize_handshake_error(exc)
        audit_event(
            AuditEvent.WS_AUTH_FAILED,
            graph_id=session.graph_id,
            subject=session.principal.subject,
            connection_id=session.state.connection_id,
            reason=text,
            token=message.token,
            level=logging.WARNING,
        )
        # A failed refresh does not kill an otherwise healthy connection;
        # if the credential really is expired the watchdog closes it.
        session.push_error(app_code, text)
        return

    previous_role = session.principal.role
    session.state.principal = result.principal
    session.connection.principal = result.principal
    session.state.reauth_requested_at = None
    session.state.reauth_deadline = None
    audit_event(
        AuditEvent.WS_AUTH_REFRESHED,
        graph_id=session.graph_id,
        subject=result.principal.subject,
        role=result.principal.role.value,
        connection_id=session.state.connection_id,
        previous_role=previous_role.value,
        token=message.token,
    )
    logger.info(
        "[%s] credential refreshed conn=%s %s (was %s)",
        session.graph_id,
        session.state.connection_id,
        result.principal.describe(),
        previous_role.value,
    )
    session.push(_session_ready_envelope(session, refreshed=True))

    # A downgrade to VIEWER must immediately end any takeover lease.
    if not result.principal.can(Permission.TAKEOVER_CONTROL) and session.state.takeover_active:
        _release_takeover(session, reason="role downgraded")


async def _handle_set_takeover(session: _Session, payload: dict[str, Any]) -> None:
    """Acquire/release the exclusive human-control lease (OPERATOR+)."""
    if not _check_permission(session, Permission.TAKEOVER_CONTROL, ClientMessageType.SET_TAKEOVER):
        return

    decision = session.limiter.check("control")
    if not decision.allowed:
        _emit_rate_limit(session, decision, audit=AuditEvent.WS_RATE_LIMITED)
        return

    try:
        message = SetTakeoverMessage.model_validate(payload)
    except ValidationError as exc:
        session.push_error(AppErrorCode.VALIDATION_FAILED, _format_validation(exc))
        return

    state = session.state
    settings = session.settings

    if not message.enabled:
        released = session.registry.release_takeover(session.graph_id, state.connection_id)
        state.takeover_active = False
        if released is not None:
            audit_event(
                AuditEvent.TAKEOVER_RELEASED,
                graph_id=session.graph_id,
                subject=state.principal.subject,
                role=state.principal.role.value,
                connection_id=state.connection_id,
                held_s=round(time.time() - released.acquired_at, 1),
            )
        logger.info("[%s] human takeover DISABLED by %s", session.graph_id, state.principal.describe())
        _broadcast_takeover(session, None, reason="released")
        return

    ttl = session.lease_ttl_s
    if message.lease_ms:
        ttl = min(message.lease_ms / 1000.0, settings.takeover_max_lease_s)
    result = session.registry.acquire_takeover(
        session.connection,
        ttl_s=ttl,
        max_ttl_s=settings.takeover_max_lease_s,
        single_holder=settings.takeover_single_holder_per_graph,
        reason=message.reason,
    )
    if not result.ok or result.lease is None:
        state.takeover_active = False
        conflict = result.conflict
        audit_event(
            AuditEvent.TAKEOVER_CONFLICT,
            graph_id=session.graph_id,
            subject=state.principal.subject,
            connection_id=state.connection_id,
            holder=conflict.subject if conflict else None,
            reason=result.reason,
            level=logging.WARNING,
        )
        session.push_error(
            AppErrorCode.TAKEOVER_LEASE_CONFLICT,
            result.reason or "takeover lease is held by another operator",
            holder_is_other=True,
            retry_after_ms=int((conflict.ttl_s * 1000) if conflict else 5_000),
        )
        return

    state.takeover_active = True
    # Renew the shared lease view for this connection (idempotent).
    session.connection.principal = state.principal
    audit_event(
        AuditEvent.TAKEOVER_ACQUIRED,
        graph_id=session.graph_id,
        subject=state.principal.subject,
        role=state.principal.role.value,
        connection_id=state.connection_id,
        lease_ms=int(ttl * 1000),
        reason=message.reason,
    )
    logger.info(
        "[%s] human takeover ENABLED by %s (lease %.0fs)",
        session.graph_id,
        state.principal.describe(),
        ttl,
    )
    # Integration point: notify the graph supervisor to pause agent actions on
    # this sandbox so human and agent never drive concurrently.
    _broadcast_takeover(session, result.lease, reason=message.reason or "acquired")


async def _handle_mouse_event(session: _Session, payload: dict[str, Any]) -> None:
    if not _check_permission(session, Permission.INPUT_SEND, ClientMessageType.MOUSE_EVENT):
        return

    try:
        event = MouseEvent.model_validate(payload)
    except ValidationError as exc:
        session.push_error(AppErrorCode.VALIDATION_FAILED, _format_validation(exc))
        return

    # ``mouseMoved`` is state, not an event: coalesce before spending budget.
    if event.action == "move" and not session.move_coalescer.accept():
        session.state.inputs_suppressed += 1
        session.stats.suppressed += 1
        return

    session_obj = _prepare_input_dispatch(session, ClientMessageType.MOUSE_EVENT)
    if isinstance(session_obj, dict):
        session.push(session_obj)
        return
    if event.action != "move":
        # A press/wheel resets the coalescing window so the pointer position
        # that follows a click is never delayed by a suppressed move.
        session.move_coalescer.force_next()

    try:
        await dispatch_mouse_event(
            session_obj, event, timeout=session.settings.browser_cdp_command_timeout
        )
    except ValueError as exc:
        session.push_error(AppErrorCode.VALIDATION_FAILED, _clip(str(exc)))
        return
    except asyncio.TimeoutError:
        logger.warning(
            "[%s] mouse dispatch timed out: %s", session.graph_id, event.action
        )
        session.push_error(
            AppErrorCode.CDP_DISPATCH_TIMEOUT, "mouse event dispatch timed out"
        )
        return
    except (TargetClosedError, PlaywrightError) as exc:
        logger.warning(
            "[%s] mouse dispatch failed (%s): %s", session.graph_id, event.action, exc
        )
        session.push_error(
            AppErrorCode.CDP_DISPATCH_FAILED,
            "input dispatch failed",
            action=event.action,
        )
        return
    _record_input(session, event.action)


async def _handle_keyboard_event(session: _Session, payload: dict[str, Any]) -> None:
    if not _check_permission(session, Permission.INPUT_SEND, ClientMessageType.KEYBOARD_EVENT):
        return

    try:
        event = KeyboardEvent.model_validate(payload)
    except ValidationError as exc:
        session.push_error(AppErrorCode.VALIDATION_FAILED, _format_validation(exc))
        return

    session_obj = _prepare_input_dispatch(session, ClientMessageType.KEYBOARD_EVENT)
    if isinstance(session_obj, dict):
        session.push(session_obj)
        return

    try:
        await dispatch_keyboard_event(
            session_obj, event, timeout=session.settings.browser_cdp_command_timeout
        )
    except ValueError as exc:
        session.push_error(AppErrorCode.VALIDATION_FAILED, _clip(str(exc)))
        return
    except asyncio.TimeoutError:
        logger.warning("[%s] key dispatch timed out: %s", session.graph_id, event.action)
        session.push_error(
            AppErrorCode.CDP_DISPATCH_TIMEOUT, "keyboard event dispatch timed out"
        )
        return
    except (TargetClosedError, PlaywrightError) as exc:
        logger.warning(
            "[%s] key dispatch failed (%s): %s", session.graph_id, event.action, exc
        )
        session.push_error(
            AppErrorCode.CDP_DISPATCH_FAILED, "input dispatch failed", action=event.action
        )
        return
    _record_input(session, event.action)


def _record_input(session: _Session, action: str) -> None:
    """Bookkeeping after a successful CDP input dispatch."""
    session.state.inputs_dispatched += 1
    session.stats.forwarded += 1
    # Operator activity keeps the takeover lease alive (SPEC §5 auto-expiry).
    if session.state.takeover_active:
        session.registry.renew_takeover(
            session.graph_id, session.state.connection_id, session.lease_ttl_s
        )
    audit_event(
        AuditEvent.INPUT_DISPATCHED,
        graph_id=session.graph_id,
        subject=session.principal.subject,
        connection_id=session.state.connection_id,
        action=action,
    )


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def _check_permission(
    session: _Session, permission: Permission, message_type: ClientMessageType
) -> bool:
    """RBAC gate. ``True`` = allowed, ``False`` = rejected (+envelope queued)."""
    principal = session.principal
    if principal.can(permission):
        return True

    session.state.permission_denials += 1
    audit_event(
        AuditEvent.WS_PERMISSION_DENIED,
        graph_id=session.graph_id,
        subject=principal.subject,
        role=principal.role.value,
        connection_id=session.state.connection_id,
        message_type=message_type.value,
        required_permission=permission.value,
        level=logging.WARNING,
    )
    logger.warning(
        "[%s] %s denied %s (needs %s, has role %s)",
        session.graph_id,
        principal.describe(),
        message_type.value,
        permission.value,
        principal.role.value,
    )
    # Charging the control bucket too makes a permission-probing loop expensive.
    session.limiter.check("control")
    session.push_error(
        AppErrorCode.FORBIDDEN,
        f"role {principal.role.value} is not allowed to send {message_type.value}",
        required_permission=permission.value,
        required_role=_MINIMUM_ROLE_LABELS[permission],
    )
    if session.state.permission_denials >= session.settings.api_ws_rate_limit_strikes:
        raise _CloseRequest(
            WsCloseCode.FORBIDDEN,
            f"role {principal.role.value} repeatedly attempted unauthorized commands",
        )
    return False


_MINIMUM_ROLE_LABELS: Final[dict[Permission, str]] = {
    Permission.INPUT_SEND: Role.OPERATOR.value,
    Permission.TAKEOVER_CONTROL: Role.OPERATOR.value,
    Permission.SCREEN_VIEW: Role.VIEWER.value,
    Permission.GRAPH_MANAGE: Role.ADMIN.value,
    Permission.AUDIT_READ: Role.ADMIN.value,
}


def _prepare_input_dispatch(
    session: _Session, message_type: ClientMessageType
) -> Any:
    """Gate check for input events.

    Returns the live ``CDPSession`` when input may be dispatched, otherwise an
    ``ERROR`` envelope to send back to the client.
    """
    settings = session.settings
    state = session.state

    if settings.browser_input_requires_takeover and not state.takeover_active:
        return error_envelope(
            AppErrorCode.TAKEOVER_NOT_ACTIVE,
            "human takeover is not active; send SET_TAKEOVER {enabled: true} first",
        )

    # The lease must still be ours: it may have expired or been force-released.
    lease = session.registry.lease(session.graph_id)
    if (
        settings.takeover_single_holder_per_graph
        and lease is not None
        and lease.connection_id != state.connection_id
    ):
        state.takeover_active = False
        audit_event(
            AuditEvent.INPUT_BLOCKED,
            graph_id=session.graph_id,
            subject=state.principal.subject,
            connection_id=state.connection_id,
            reason="lease_held_by_other",
            holder=lease.subject,
            level=logging.WARNING,
        )
        return error_envelope(
            AppErrorCode.TAKEOVER_LEASE_CONFLICT,
            "another operator holds the takeover lease",
            retry_after_ms=int(lease.ttl_s * 1000),
        )
    if lease is None and settings.takeover_single_holder_per_graph and state.takeover_active:
        state.takeover_active = False
        return error_envelope(
            AppErrorCode.TAKEOVER_NOT_ACTIVE,
            "your takeover lease expired; re-enable takeover to continue",
        )

    decision = session.limiter.check("input")
    if not decision.allowed:
        _emit_rate_limit(session, decision, audit=AuditEvent.WS_RATE_LIMITED)
        return error_envelope(
            AppErrorCode.RATE_LIMITED,
            "input rate limit exceeded; slow down",
            limit=decision.limit,
            retry_after_ms=decision.retry_after_ms,
        )
    graph_decision = session.graph_limiter.check("graph_input")
    if not graph_decision.allowed:
        session.stats.record_rejection("graph_input")
        audit_event(
            AuditEvent.WS_RATE_LIMITED,
            graph_id=session.graph_id,
            subject=state.principal.subject,
            connection_id=state.connection_id,
            limit="graph_input",
            scope="graph",
            retry_after_ms=graph_decision.retry_after_ms,
            level=logging.WARNING,
        )
        return error_envelope(
            AppErrorCode.RATE_LIMITED,
            "this sandbox is receiving too much input from all operators",
            limit="graph_input",
            scope="graph",
            retry_after_ms=graph_decision.retry_after_ms,
        )

    cdp_session = session.streamer.active_session
    if cdp_session is None:
        return error_envelope(
            AppErrorCode.SESSION_NOT_READY,
            "screencast session is not attached yet; wait for STREAM_READY",
        )
    return cdp_session


def _emit_rate_limit(
    session: _Session, decision: RateLimitDecision, *, audit: str
) -> None:
    """Notify the client about a throttle decision (once per event)."""
    session.stats.record_rejection(decision.limit)
    session.stats.suppressed += 1
    audit_event(
        audit,
        graph_id=session.graph_id,
        subject=session.principal.subject,
        connection_id=session.state.connection_id,
        limit=decision.limit,
        retry_after_ms=decision.retry_after_ms,
        strikes=decision.strikes,
        level=logging.WARNING,
    )
    session.push(
        server_envelope(
            ServerMessageType.RATE_LIMITED,
            limit=decision.limit,
            retry_after_ms=decision.retry_after_ms,
            strikes=decision.strikes,
        )
    )
    session.push_error(
        AppErrorCode.RATE_LIMITED,
        "rate limit exceeded; slow down",
        limit=decision.limit,
        retry_after_ms=decision.retry_after_ms,
    )


def _record_policy_violation(
    session: _Session,
    app_code: int,
    message: str,
    *,
    limit: str,
    audit: str,
    retry_after_ms: int = 0,
) -> None:
    """Charge a strike for a policy breach and notify the client."""
    strikes = session.limiter.record_strike(limit)
    session.stats.record_rejection(limit)
    audit_event(
        audit,
        graph_id=session.graph_id,
        subject=session.principal.subject,
        connection_id=session.state.connection_id,
        limit=limit,
        reason=_clip(message),
        strikes=strikes,
        level=logging.WARNING,
    )
    session.push_error(app_code, message, limit=limit, retry_after_ms=retry_after_ms)


def _broadcast_takeover(session: _Session, lease: Any, *, reason: str) -> None:
    """Send ``TAKEOVER_STATE`` to this connection and the rest of the room."""
    # Subjects are only disclosed to operators/admins (least privilege).
    include_subject = session.principal.has_role_at_least(Role.OPERATOR)
    envelope = takeover_state_envelope(
        session.graph_id, lease, reason=reason, include_subject=include_subject
    )
    session.push(envelope)
    if session.settings.takeover_broadcast_state:
        session.registry.broadcast(
            session.graph_id,
            takeover_state_envelope(
                session.graph_id, lease, reason=reason, include_subject=False
            ),
            exclude=session.state.connection_id,
        )


def _release_takeover(session: _Session, *, reason: str) -> None:
    """Drop our lease on teardown and tell the room."""
    if not session.state.takeover_active:
        return
    session.state.takeover_active = False
    released = session.registry.release_takeover(session.graph_id, session.state.connection_id)
    audit_event(
        AuditEvent.TAKEOVER_RELEASED,
        graph_id=session.graph_id,
        subject=session.principal.subject,
        connection_id=session.state.connection_id,
        reason=reason,
        released=released is not None,
    )
    if released is not None and session.settings.takeover_broadcast_state:
        session.registry.broadcast(
            session.graph_id,
            takeover_state_envelope(
                session.graph_id, None, reason="holder_disconnected", include_subject=False
            ),
            exclude=session.state.connection_id,
        )


def _session_ready_envelope(session: _Session, *, refreshed: bool = False) -> dict[str, Any]:
    """First (and post-refresh) envelope: who you are and what you may do."""
    settings = session.settings
    principal = session.principal
    return server_envelope(
        ServerMessageType.SESSION_READY,
        graph_id=session.graph_id,
        connection_id=session.state.connection_id,
        subject=principal.subject,
        role=principal.role.value,
        permissions=sorted(p.value for p in principal.permissions),
        credential_expires_at=principal.effective_expires_at,
        refreshed=refreshed,
        rate_limits={
            "input": {
                "capacity": settings.ratelimit_input_capacity,
                "per_second": settings.ratelimit_input_rate,
            },
            "control": {
                "capacity": settings.ratelimit_control_capacity,
                "per_second": settings.ratelimit_control_rate,
            },
            "message": {
                "capacity": settings.ratelimit_message_capacity,
                "per_second": settings.ratelimit_message_rate,
            },
            "mouse_move_coalesce_ms": settings.ratelimit_mouse_move_interval_ms,
        },
        takeover={
            "requires_role": Role.OPERATOR.value,
            "input_requires_takeover": settings.browser_input_requires_takeover,
            "single_holder": settings.takeover_single_holder_per_graph,
            "lease_ttl_s": session.lease_ttl_s,
            "max_lease_s": settings.takeover_max_lease_s,
        },
        limits={
            "idle_timeout_s": settings.api_ws_idle_timeout_s,
            "max_lifetime_s": settings.api_ws_max_lifetime_s,
            "max_message_bytes": settings.api_ws_max_message_bytes,
        },
    )


def _outbound_allowed(role: Role, envelope: dict[str, Any], settings: Settings) -> bool:
    """Role-based outbound filter (single choke point in the writer task)."""
    msg_type = str(envelope.get("type") or "")
    if role is Role.VIEWER:
        return msg_type in _VIEWER_OUTBOUND
    if role is Role.OPERATOR:
        return msg_type in _OPERATOR_OUTBOUND or msg_type == ServerMessageType.ERROR.value
    return True  # ADMIN sees everything


# ---------------------------------------------------------------------------
# Auth / validation / shutdown helpers
# ---------------------------------------------------------------------------


def _require_credential_present(
    credentials: WsCredentials | None, settings: Settings
) -> None:
    """Pre-accept presence check so anonymous sockets never get accepted."""
    if not settings.auth_enabled:
        return
    if credentials is not None:
        return
    if settings.auth_allow_legacy_static_token and settings.api_ws_auth_token:
        return
    raise WsAuthError("missing authentication credential")


def _normalize_handshake_error(exc: Exception) -> tuple[int, int, str]:
    """Map auth/graph errors onto ``(close_code, app_code, public_message)``."""
    if isinstance(exc, WsAuthError):
        return exc.close_code, exc.app_code, exc.message
    if isinstance(exc, GraphAccessError):
        return exc.close_code, exc.app_code, exc.message
    if isinstance(exc, TokenError):
        mapped = WsAuthError.from_token_error(exc)
        return mapped.close_code, mapped.app_code, mapped.message
    logger.exception("unexpected handshake error")
    return (
        WsCloseCode.INTERNAL_ERROR,
        AppErrorCode.INTERNAL,
        "internal error during handshake",
    )


async def _refuse_handshake(websocket: WebSocket, settings: Settings) -> None:
    """Refuse *before* ``accept()`` — the client sees a plain HTTP 403.

    Closing an unaccepted Starlette WebSocket makes the ASGI server answer the
    upgrade with ``403 Forbidden`` instead of ``101 Switching Protocols``: no
    streamer, no queue, no CDP session is ever allocated for the attacker.
    ``settings`` is accepted for symmetry/logging policy.
    """
    _ = settings
    with contextlib.suppress(Exception):
        await websocket.close(code=WsCloseCode.POLICY_VIOLATION)


def _describe_client(websocket: WebSocket, settings: Settings) -> str:
    """Log-safe client label (never includes query parameters)."""
    client = websocket.client
    ip = client_ip(websocket, settings)
    if client:
        return f"{ip}:{client.port}"
    return ip


def _format_validation(exc: ValidationError) -> str:
    details = "; ".join(
        f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}"
        for err in exc.errors()
    )
    return _clip(f"payload validation failed: {details}", 400)


def _clip(text: str, limit: int = 200) -> str:
    """Truncate untrusted strings before echoing them back to a client."""
    text = text.replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


async def _reject(
    websocket: WebSocket,
    close_code: int,
    app_code: int,
    message: str,
) -> None:
    """Send a final ERROR envelope and close a freshly accepted socket."""
    with contextlib.suppress(Exception):
        await websocket.send_json(error_envelope(app_code, message))
    await _close_socket(websocket, close_code, message)


async def _close_socket(websocket: WebSocket, code: int, reason: str) -> None:
    """Close the socket exactly once, tolerating already-closed states."""
    if (
        websocket.client_state is WebSocketState.CONNECTED
        and websocket.application_state is not WebSocketState.DISCONNECTED
    ):
        with contextlib.suppress(Exception):
            await websocket.close(code=code, reason=_clip(reason, 120))


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
            if isinstance(exc, _CloseRequest):
                return exc.code, exc.reason
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
