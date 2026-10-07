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
``TAKEOVER_STATE``    ``{enabled}`` — human-takeover mode changed.
``PONG``              heartbeat reply.
``ERROR``             ``{code, message, reason?}`` — rejected client command.
                      Notable codes: ``40301`` takeover forbidden
                      (``reason=role_forbidden`` for VIEWER,
                      ``reason=takeover_not_active`` before SET_TAKEOVER),
                      ``42901`` rate limited (``{retry_after, strikes}``).

Client -> server envelopes:

``MOUSE_EVENT``     ``{action: move|down|up|click|double_click|wheel, x, y,
                    button, clickCount, deltaX, deltaY, buttons, modifiers}``
                    — requires role OPERATOR/ADMIN + active takeover.
``KEYBOARD_EVENT``  ``{action: keydown|keyup|keypress|insert_text, key, code,
                    text, autoRepeat, location, modifiers}`` — same gating.
``SET_TAKEOVER``    ``{enabled: bool}`` — requires role OPERATOR/ADMIN.
``PING``            ``{ts?}``

Authentication happens at handshake (before the socket is accepted):
JWT via ``Authorization: Bearer``, ``?token=``/``?access_token=`` or a
``bearer.<jwt>`` ``Sec-WebSocket-Protocol`` entry (browser clients);
failures close the handshake with code 4401 (HTTP 403). Rate-limit
strike-out closes with 4429. See :mod:`omniagent.security.auth`.

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


class ServerMessageType(StrEnum):
    SCREEN_FRAME = "SCREEN_FRAME"
    STREAM_READY = "STREAM_READY"
    STREAM_RECONNECTING = "STREAM_RECONNECTING"
    STREAM_ERROR = "STREAM_ERROR"
    TAKEOVER_STATE = "TAKEOVER_STATE"
    PONG = "PONG"
    ERROR = "ERROR"


class WsCloseCode(IntEnum):
    """Application-defined WebSocket close codes (4000-4999 range)."""

    NORMAL = 1000
    BAD_REQUEST = 4400
    UNAUTHORIZED = 4401
    RATE_LIMITED = 4429
    INTERNAL_ERROR = 4500
    STREAM_ENDED = 4501


class AppErrorCode(IntEnum):
    """Application-level error codes carried inside ``ERROR`` envelopes."""

    INVALID_PAYLOAD = 40001
    VALIDATION_FAILED = 40002
    UNKNOWN_MESSAGE_TYPE = 40003
    #: Human takeover forbidden or not active. The ``reason`` field
    #: distinguishes ``role_forbidden`` (VIEWER) from
    #: ``takeover_not_active`` (OPERATOR/ADMIN before SET_TAKEOVER).
    TAKEOVER_NOT_ACTIVE = 40301
    SESSION_NOT_READY = 40901
    RATE_LIMITED = 42901
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
    """Toggles human-takeover mode for this connection."""

    enabled: bool


# ---------------------------------------------------------------------------
# Envelope construction / parsing
# ---------------------------------------------------------------------------


def server_envelope(msg_type: ServerMessageType, **fields: Any) -> dict[str, Any]:
    """Build a server -> client envelope."""
    return {"type": msg_type.value, **fields}


def error_envelope(
    code: int | AppErrorCode,
    message: str,
    *,
    reason: str | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """Build a server -> client ``ERROR`` envelope.

    ``reason`` is an optional machine-readable qualifier (e.g.
    ``role_forbidden`` vs ``takeover_not_active`` under code 40301).
    """
    envelope: dict[str, Any] = {
        "type": ServerMessageType.ERROR.value,
        "code": int(code),
        "message": message,
        **fields,
    }
    if reason is not None:
        envelope["reason"] = reason
    return envelope


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
