"""Wire protocol models for the browser-sandbox WebSocket endpoints.

Server -> client envelopes (``type`` discriminator):

``SCREEN_FRAME``
    ``{type, seq, format, width, height, data_b64, device_width,
    device_height, page_scale_factor}`` — one screencast frame. ``width`` /
    ``height`` are the pixel dimensions of ``data_b64``; ``device_*`` are the
    CSS-pixel viewport dimensions of the page (use them to map pointer
    coordinates back onto the frame if the client letterboxes the image).
``STREAM_READY``      screencast attached; streaming begins.
``STREAM_RECONNECTING`` transient CDP failure; ``{attempt, delay_s, reason}``.
``STREAM_ERROR``      terminal stream failure; ``{message}``.
``TAKEOVER_STATE``    ``{enabled, holder, lease_expires_at, reason}`` — the
                    human-takeover lease changed (broadcast to every
                    connection of the graph).
``SESSION_READY``     handshake succeeded; ``{subject, role, permissions,
                    graph_id, rate_limits, idle_timeout_s, max_lifetime_s}``.
``AUTH_REQUIRED``     credential is expiring/expired; ``{reason, grace_s}``.
``RATE_LIMITED``      a throttle tripped; ``{limit, retry_after_ms}``.
``PONG``              heartbeat reply.
``ERROR``             ``{code, message}`` — rejected client command.

Client -> server envelopes:

``MOUSE_EVENT``     ``{action: move|down|up|click|double_click|wheel, x, y,
                    button, clickCount, deltaX, deltaY, buttons, modifiers}``
``KEYBOARD_EVENT``  ``{action: keydown|keyup|keypress|insert_text, key, code,
                    text, autoRepeat, location, modifiers}``
``SET_TAKEOVER``    ``{enabled: bool, lease_ms?: int, reason?: str}``
``PING``            ``{ts?}``
``AUTH``            ``{token: str}`` — refresh the credential mid-connection.

Both flat (``{"type": "MOUSE_EVENT", "x": 1, ...}``) and nested
(``{"type": "MOUSE_EVENT", "payload": {"x": 1, ...}}``) forms are accepted;
camelCase and snake_case field names are both understood.
"""

from __future__ import annotations

import re
from enum import IntEnum, StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------

MouseAction = Literal["move", "down", "up", "click", "double_click", "wheel"]
MouseButton = Literal["left", "right", "middle", "none"]
KeyAction = Literal["keydown", "keyup", "keypress", "insert_text"]
ModifierKey = Literal["alt", "ctrl", "control", "meta", "command", "shift"]


class ClientMessageType(StrEnum):
    MOUSE_EVENT = "MOUSE_EVENT"
    KEYBOARD_EVENT = "KEYBOARD_EVENT"
    SET_TAKEOVER = "SET_TAKEOVER"
    PING = "PING"
    #: Mid-connection credential refresh: ``{"type": "AUTH",
    #: "payload": {"token": "<ws-ticket|access jwt>"}}``.  Required before
    #: :data:`ServerMessageType.AUTH_REQUIRED` turns into a close.
    AUTH = "AUTH"


class ServerMessageType(StrEnum):
    SCREEN_FRAME = "SCREEN_FRAME"
    STREAM_READY = "STREAM_READY"
    STREAM_RECONNECTING = "STREAM_RECONNECTING"
    STREAM_ERROR = "STREAM_ERROR"
    TAKEOVER_STATE = "TAKEOVER_STATE"
    PONG = "PONG"
    ERROR = "ERROR"
    #: First envelope after a successful handshake: identity, role,
    #: effective permissions, rate-limit budgets and lease policy.
    SESSION_READY = "SESSION_READY"
    #: The credential is about to expire (or expired): the client has
    #: ``reauth_grace_s`` to send :data:`ClientMessageType.AUTH`.
    AUTH_REQUIRED = "AUTH_REQUIRED"
    #: Explicit throttle notification (also mirrored as an ``ERROR``).
    RATE_LIMITED = "RATE_LIMITED"


class WsCloseCode(IntEnum):
    """WebSocket close codes (RFC 6455 registered + 4000-4999 application)."""

    NORMAL = 1000
    GOING_AWAY = 1001
    #: Handshake refused *before* ``accept()`` (the browser sees HTTP 403).
    POLICY_VIOLATION = 1008
    BAD_REQUEST = 4400
    UNAUTHORIZED = 4401
    FORBIDDEN = 4403
    IDLE_TIMEOUT = 4408
    PAYLOAD_TOO_LARGE = 4413
    TOO_MANY_REQUESTS = 4429
    INTERNAL_ERROR = 4500
    STREAM_ENDED = 4501
    #: Sandbox/connection pool exhausted.
    SERVICE_UNAVAILABLE = 4503


class AppErrorCode(IntEnum):
    """Application-level error codes carried inside ``ERROR`` envelopes."""

    INVALID_PAYLOAD = 40001
    VALIDATION_FAILED = 40002
    UNKNOWN_MESSAGE_TYPE = 40003
    #: Authentication (401-family).
    UNAUTHENTICATED = 40100
    TOKEN_EXPIRED = 40101
    TOKEN_INVALID = 40102
    TOKEN_REPLAYED = 40103
    #: Authorization (403-family).
    FORBIDDEN = 40300
    TAKEOVER_NOT_ACTIVE = 40301
    GRAPH_FORBIDDEN = 40302
    TAKEOVER_LEASE_CONFLICT = 40303
    SESSION_NOT_READY = 40901
    #: Payload / policy (413 + 429 family).
    MESSAGE_TOO_LARGE = 41301
    RATE_LIMITED = 42901
    CONNECTION_LIMIT = 42902
    #: Upstream / internal (5xx-family).
    INTERNAL = 50000
    CDP_DISPATCH_FAILED = 50201
    CDP_DISPATCH_TIMEOUT = 50401


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CAMEL_FIXUPS: dict[str, str] = {
    "inserttext": "insert_text",
    "doubleclick": "double_click",
    "keydown": "keydown",
    "keyup": "keyup",
    "keypress": "keypress",
}


def _normalize_action(value: Any) -> Any:
    """Accept ``keyDown`` / ``KEYDOWN`` / ``double-click`` / ``insertText``."""
    if not isinstance(value, str):
        return value
    compact = re.sub(r"[\s_-]", "", value).lower()
    return _CAMEL_FIXUPS.get(compact, compact.replace(" ", "_"))


# ---------------------------------------------------------------------------
# Client -> server payloads
# ---------------------------------------------------------------------------


class _CamelModel(BaseModel):
    """Base model tolerating camelCase aliases and unknown extra fields."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class MouseEvent(_CamelModel):
    """A single pointer event produced by the human operator."""

    action: MouseAction
    #: Coordinates in CSS pixels of the screencast frame the client renders.
    x: float = 0.0
    y: float = 0.0
    button: MouseButton = "left"
    click_count: int = Field(1, ge=1, le=10, alias="clickCount")
    #: Optional explicit CDP ``buttons`` bitmask (left=1, right=2, middle=4).
    buttons: int | None = Field(None, ge=0, le=31)
    delta_x: float = Field(0.0, alias="deltaX")
    delta_y: float = Field(0.0, alias="deltaY")
    modifiers: list[ModifierKey] = Field(default_factory=list)

    @field_validator("action", mode="before")
    @classmethod
    def _norm_action(cls, value: Any) -> Any:
        return _normalize_action(value)

    @field_validator("button", mode="before")
    @classmethod
    def _norm_button(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("modifiers", mode="before")
    @classmethod
    def _norm_modifiers(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [v.strip().lower() if isinstance(v, str) else v for v in value]
        return value


class KeyboardEvent(_CamelModel):
    """A single keyboard event produced by the human operator."""

    action: KeyAction
    #: DOM ``KeyboardEvent.key`` (e.g. ``"a"``, ``"Enter"``, ``"Shift"``).
    key: str | None = Field(None, max_length=64)
    #: DOM ``KeyboardEvent.code`` (e.g. ``"KeyA"``, ``"Digit1"``).
    code: str | None = Field(None, max_length=64)
    #: Text produced by the key. For ``insert_text`` this is the full string
    #: (IME-safe path — preferred for Vietnamese/CJK input).
    text: str | None = Field(None, max_length=4096)
    auto_repeat: bool = Field(False, alias="autoRepeat")
    #: 0 = default, 1 = left, 2 = right, 3 = numpad.
    location: int = Field(0, ge=0, le=3)
    modifiers: list[ModifierKey] = Field(default_factory=list)

    @field_validator("action", mode="before")
    @classmethod
    def _norm_action(cls, value: Any) -> Any:
        return _normalize_action(value)

    @field_validator("modifiers", mode="before")
    @classmethod
    def _norm_modifiers(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [v.strip().lower() if isinstance(v, str) else v for v in value]
        return value


class SetTakeoverMessage(_CamelModel):
    """Toggles the human-takeover lease for this connection.

    ``lease_ms`` caps how long the operator keeps exclusive control; the
    server clamps it to ``takeover_max_lease_s`` and auto-expires the lease
    when the holder goes silent (SPEC §5 "auto-expire via server timer").
    """

    enabled: bool
    lease_ms: int | None = Field(None, ge=1_000, le=86_400_000, alias="leaseMs")
    reason: str | None = Field(None, max_length=64)


class AuthMessage(_CamelModel):
    """Mid-connection credential refresh (``AUTH``)."""

    token: str = Field(min_length=8, max_length=65_536)


# ---------------------------------------------------------------------------
# Envelope construction / parsing
# ---------------------------------------------------------------------------


def server_envelope(msg_type: ServerMessageType, **fields: Any) -> dict[str, Any]:
    """Build a server -> client envelope."""
    return {"type": msg_type.value, **fields}


def error_envelope(
    code: int | AppErrorCode, message: str, **fields: Any
) -> dict[str, Any]:
    """Build a server -> client ``ERROR`` envelope."""
    return {
        "type": ServerMessageType.ERROR.value,
        "code": int(code),
        "message": message,
        **fields,
    }


def parse_client_envelope(data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Split a raw client message into ``(TYPE, payload)``.

    Accepts both the flat form (fields next to ``type``) and the nested form
    (fields under ``payload``); nested fields win on conflict.
    """
    msg_type = str(data.get("type") or "").strip().upper()
    payload: dict[str, Any] = dict(data)
    nested = data.get("payload")
    if isinstance(nested, dict):
        payload.update(nested)
    return msg_type, payload
