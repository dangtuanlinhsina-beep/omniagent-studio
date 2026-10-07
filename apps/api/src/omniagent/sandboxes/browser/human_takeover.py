"""Human takeover: translate client input events into raw CDP input calls.

The functions here receive validated :class:`~...models.MouseEvent` /
:class:`~...models.KeyboardEvent` payloads from the WebSocket layer and
dispatch them onto a live :class:`playwright.async_api.CDPSession` via
``Input.dispatchMouseEvent`` / ``Input.dispatchKeyEvent`` /
``Input.insertText``.

Design notes
------------
* Coordinates are CSS pixels of the screencast frame. If the client renders
  the frame scaled, pass ``coordinate_scale = frame_css_width / rendered_width``
  so events land on the right element.
* ``keydown`` with printable ``text`` dispatches a CDP ``keyDown`` carrying
  ``text`` — Blink inserts the characters directly from that event (an extra
  ``char`` event would double-type; ``keypress`` is the explicit ``char``
  path). ``Enter`` is normalised to ``"\\r"`` per CDP convention.
* For IME-style text (Vietnamese diacritics typed via TELEX/VNI, CJK, emoji)
  clients should prefer ``action="insert_text"`` which maps to
  ``Input.insertText`` — the only fully reliable path for composed text.
* Virtual key codes are derived from ``code`` (preferred) or ``key`` so
  non-text keys (arrows, function keys, modifiers) behave correctly.
* Failures (``TargetClosedError``, ``playwright.async_api.Error``,
  ``asyncio.TimeoutError``) propagate to the caller, which converts them
  into ``ERROR`` envelopes for the client.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Final

from playwright.async_api import CDPSession

from .models import KeyboardEvent, MouseEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CDP constant tables
# ---------------------------------------------------------------------------

#: CDP ``Input.dispatchMouseEvent`` button bitmask values.
_BUTTON_MASKS: Final[dict[str, int]] = {
    "none": 0,
    "left": 1,
    "right": 2,
    "middle": 4,
}

#: CDP modifier bitmask values.
_MODIFIER_MASKS: Final[dict[str, int]] = {
    "alt": 1,
    "ctrl": 2,
    "control": 2,
    "meta": 4,
    "command": 4,
    "shift": 8,
}

#: ``KeyboardEvent.code`` -> Windows virtual key code for non-derivable keys.
_SPECIAL_VIRTUAL_KEY_CODES: Final[dict[str, int]] = {
    "Backquote": 192,
    "Minus": 189,
    "Equal": 187,
    "BracketLeft": 219,
    "BracketRight": 221,
    "Backslash": 220,
    "IntlBackslash": 226,
    "Semicolon": 186,
    "Quote": 222,
    "Comma": 188,
    "Period": 190,
    "Slash": 191,
    "Backspace": 8,
    "Tab": 9,
    "Enter": 13,
    "NumpadEnter": 13,
    "ShiftLeft": 16,
    "ShiftRight": 16,
    "ControlLeft": 17,
    "ControlRight": 17,
    "AltLeft": 18,
    "AltRight": 18,
    "MetaLeft": 91,
    "MetaRight": 92,
    "CapsLock": 20,
    "Escape": 27,
    "Space": 32,
    "PageUp": 33,
    "PageDown": 34,
    "End": 35,
    "Home": 36,
    "ArrowLeft": 37,
    "ArrowUp": 38,
    "ArrowRight": 39,
    "ArrowDown": 40,
    "Insert": 45,
    "Delete": 46,
    "NumLock": 144,
    "ScrollLock": 145,
    "NumpadAdd": 107,
    "NumpadSubtract": 109,
    "NumpadMultiply": 106,
    "NumpadDivide": 111,
    "NumpadDecimal": 110,
    "ContextMenu": 93,
}

#: Fallback lookup by ``KeyboardEvent.key`` (lowercased) when ``code`` is absent.
_NAMED_KEY_VIRTUAL_CODES: Final[dict[str, int]] = {
    "backspace": 8,
    "tab": 9,
    "enter": 13,
    "shift": 16,
    "control": 17,
    "alt": 18,
    "pause": 19,
    "capslock": 20,
    "escape": 27,
    " ": 32,
    "spacebar": 32,
    "pageup": 33,
    "pagedown": 34,
    "end": 35,
    "home": 36,
    "arrowleft": 37,
    "arrowup": 38,
    "arrowright": 39,
    "arrowdown": 40,
    "insert": 45,
    "delete": 46,
    "meta": 91,
    "contextmenu": 93,
    "numlock": 144,
    "scrolllock": 145,
}


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


async def dispatch_mouse_event(
    session: CDPSession,
    event: MouseEvent,
    *,
    coordinate_scale: float = 1.0,
    timeout: float | None = None,
) -> None:
    """Translate one ``MOUSE_EVENT`` into CDP ``Input.dispatchMouseEvent``.

    Args:
        session: Live CDP session of the streamed page.
        event: Validated client event.
        coordinate_scale: Multiplier applied to ``x``/``y`` when the client
            renders the screencast frame at a different size than the page's
            CSS viewport.
        timeout: Optional hard timeout (seconds) per CDP command.

    Raises:
        ValueError: For inconsistent payloads (e.g. wheel without deltas,
            ``button="none"`` on a press action).
        playwright.async_api.Error / TargetClosedError / asyncio.TimeoutError:
            Propagated from the CDP transport.
    """
    if coordinate_scale <= 0:
        raise ValueError(f"coordinate_scale must be > 0, got {coordinate_scale}")

    x = event.x * coordinate_scale
    y = event.y * coordinate_scale
    modifiers = _modifiers_to_mask(event.modifiers)

    async def send(params: dict[str, Any]) -> None:
        await _cdp_send(session, "Input.dispatchMouseEvent", params, timeout)

    match event.action:
        case "move":
            params: dict[str, Any] = {
                "type": "mouseMoved",
                "x": x,
                "y": y,
                "modifiers": modifiers,
            }
            if event.buttons is not None:
                params["buttons"] = event.buttons
            await send(params)

        case "down":
            _ensure_pressable_button(event)
            await send(
                {
                    "type": "mousePressed",
                    "x": x,
                    "y": y,
                    "button": event.button,
                    "buttons": (
                        event.buttons
                        if event.buttons is not None
                        else _BUTTON_MASKS[event.button]
                    ),
                    "clickCount": event.click_count,
                    "modifiers": modifiers,
                }
            )

        case "up":
            await send(
                {
                    "type": "mouseReleased",
                    "x": x,
                    "y": y,
                    "button": event.button,
                    "buttons": event.buttons if event.buttons is not None else 0,
                    "clickCount": event.click_count,
                    "modifiers": modifiers,
                }
            )

        case "click":
            _ensure_pressable_button(event)
            pressed = {
                "type": "mousePressed",
                "x": x,
                "y": y,
                "button": event.button,
                "buttons": (
                    event.buttons
                    if event.buttons is not None
                    else _BUTTON_MASKS[event.button]
                ),
                "clickCount": event.click_count,
                "modifiers": modifiers,
            }
            released = {**pressed, "type": "mouseReleased", "buttons": 0}
            await send(pressed)
            await send(released)

        case "double_click":
            _ensure_pressable_button(event)
            for click_count in (1, 2):
                await send(
                    {
                        "type": "mousePressed",
                        "x": x,
                        "y": y,
                        "button": event.button,
                        "buttons": _BUTTON_MASKS[event.button],
                        "clickCount": click_count,
                        "modifiers": modifiers,
                    }
                )
                await send(
                    {
                        "type": "mouseReleased",
                        "x": x,
                        "y": y,
                        "button": event.button,
                        "buttons": 0,
                        "clickCount": click_count,
                        "modifiers": modifiers,
                    }
                )

        case "wheel":
            if event.delta_x == 0 and event.delta_y == 0:
                raise ValueError("wheel event requires non-zero deltaX/deltaY")
            await send(
                {
                    "type": "mouseWheel",
                    "x": x,
                    "y": y,
                    "deltaX": event.delta_x,
                    "deltaY": event.delta_y,
                    "modifiers": modifiers,
                }
            )

        case _:  # pragma: no cover - Literal type guards this
            raise ValueError(f"unsupported mouse action: {event.action!r}")


async def dispatch_keyboard_event(
    session: CDPSession,
    event: KeyboardEvent,
    *,
    timeout: float | None = None,
) -> None:
    """Translate one ``KEYBOARD_EVENT`` into CDP key/input commands.

    ``keydown`` -> ``Input.dispatchKeyEvent`` ``keyDown`` (text-bearing
    keyDowns insert characters directly); ``keyup`` -> ``keyUp``;
    ``keypress`` -> ``char``; ``insert_text`` -> ``Input.insertText``
    (IME-safe).

    Raises:
        ValueError: Missing required fields (e.g. no ``text`` for
            ``insert_text``).
        playwright.async_api.Error / TargetClosedError / asyncio.TimeoutError:
            Propagated from the CDP transport.
    """
    modifiers = _modifiers_to_mask(event.modifiers)
    virtual_key = _virtual_key_code(event.code, event.key)

    async def send_key(params: dict[str, Any]) -> None:
        await _cdp_send(session, "Input.dispatchKeyEvent", params, timeout)

    def _common_params() -> dict[str, Any]:
        params: dict[str, Any] = {"modifiers": modifiers}
        if event.key:
            params["key"] = event.key
        if event.code:
            params["code"] = event.code
        if virtual_key is not None:
            params["windowsVirtualKeyCode"] = virtual_key
            params["nativeVirtualKeyCode"] = virtual_key
        if event.location:
            params["location"] = event.location
        if event.auto_repeat:
            params["autoRepeat"] = True
        return params

    match event.action:
        case "insert_text":
            if not event.text:
                raise ValueError("insert_text requires a non-empty 'text'")
            await _cdp_send(
                session, "Input.insertText", {"text": event.text}, timeout
            )

        case "keydown":
            text = event.text
            if text is None and event.key == "Enter":
                # CDP convention: Enter must carry "\r" to activate inputs.
                text = "\r"
            params = _common_params() | {"type": "keyDown"}
            if text:
                params["text"] = text
                params["unmodifiedText"] = text
            # NOTE: a "keyDown" carrying text already inserts it in Blink.
            # Dispatching an extra "char" event here would double-type
            # (the historical Puppeteer bug); "char" is reserved for the
            # explicit "keypress" action below. This matches the behaviour
            # of both Playwright and modern Puppeteer.
            await send_key(params)

        case "keypress":
            if not event.text:
                raise ValueError("keypress requires a non-empty 'text'")
            await send_key(
                _common_params() | {"type": "char", "text": event.text}
            )

        case "keyup":
            await send_key(_common_params() | {"type": "keyUp"})

        case _:  # pragma: no cover - Literal type guards this
            raise ValueError(f"unsupported keyboard action: {event.action!r}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _cdp_send(
    session: CDPSession,
    method: str,
    params: dict[str, Any],
    timeout: float | None,
) -> Any:
    """``session.send`` with an optional hard timeout."""
    if timeout is None:
        return await session.send(method, params)
    return await asyncio.wait_for(session.send(method, params), timeout=timeout)


def _modifiers_to_mask(modifiers: list[str]) -> int:
    mask = 0
    for modifier in modifiers:
        mask |= _MODIFIER_MASKS.get(modifier.lower(), 0)
    return mask


def _ensure_pressable_button(event: MouseEvent) -> None:
    if event.button == "none":
        raise ValueError(
            f"mouse action {event.action!r} requires a concrete button "
            "(left/right/middle), got 'none'"
        )


def _virtual_key_code(code: str | None, key: str | None) -> int | None:
    """Derive the Windows virtual key code from DOM ``code``/``key``.

    Returns ``None`` when it cannot be determined; CDP treats the field as
    optional, and text-bearing events still insert correctly via ``text``.
    """
    if code:
        special = _SPECIAL_VIRTUAL_KEY_CODES.get(code)
        if special is not None:
            return special
        # KeyA..KeyZ -> 65..90
        if len(code) == 4 and code.startswith("Key") and code[3].isalpha():
            return ord(code[3].upper())
        # Digit0..Digit9 -> 48..57
        if len(code) == 6 and code.startswith("Digit") and code[5].isdigit():
            return ord(code[5])
        # Numpad0..Numpad9 -> 96..105
        if len(code) == 7 and code.startswith("Numpad") and code[6].isdigit():
            return 96 + int(code[6])
        # F1..F24 -> 112..135
        if code.startswith("F") and code[1:].isdigit():
            number = int(code[1:])
            if 1 <= number <= 24:
                return 111 + number

    if key:
        if len(key) == 1:
            upper = key.upper()
            if upper.isalnum() and upper.isascii():
                return ord(upper)
        named = _NAMED_KEY_VIRTUAL_CODES.get(key.lower())
        if named is not None:
            return named
        # F1..F24 given via key ("F5")
        if key.startswith("F") and key[1:].isdigit():
            number = int(key[1:])
            if 1 <= number <= 24:
                return 111 + number

    return None
