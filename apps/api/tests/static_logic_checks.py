"""Static logic checks for the browser-sandbox subsystem.

Runnable both as a plain script (``python static_logic_checks.py``) and via
pytest (``pytest apps/api/tests``). These cover the pure-logic layers:
protocol models, virtual-key mapping, envelope parsing, sandbox registry and
the streamer's queue/geometry helpers. The full stack (real Chromium +
WebSocket) is exercised by ``e2e_stream_test.py``.
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from omniagent.main import create_app
from omniagent.sandboxes.browser.config import Settings
from omniagent.sandboxes.browser.human_takeover import (
    _modifiers_to_mask,
    _virtual_key_code,
)
from omniagent.sandboxes.browser.models import (
    KeyboardEvent,
    MouseEvent,
    ServerMessageType,
    parse_client_envelope,
    server_envelope,
)
from omniagent.sandboxes.browser.registry import SandboxRegistry
from omniagent.sandboxes.browser.streamer import ScreencastStreamer

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if not cond else ""))
    if not cond:
        _failures.append(name)


def _collect_ws_paths(routes: object) -> list[str]:
    """Recursively collect /ws/* paths across FastAPI versions.

    FastAPI >= 0.142 wraps ``include_router`` targets in a lazy
    ``_IncludedRouter`` (exposing ``original_router``) instead of flattening
    routes into ``app.routes``.
    """
    paths: list[str] = []
    for r in getattr(routes, "__iter__", lambda: [])():
        path = getattr(r, "path", None)
        if isinstance(path, str) and path.startswith("/ws/"):
            paths.append(path)
        sub = getattr(r, "original_router", None) or getattr(r, "router", None)
        if sub is not None and hasattr(sub, "routes"):
            paths.extend(_collect_ws_paths(sub.routes))
    return paths


def test_all_static_logic() -> None:
    # 1. FastAPI app builds; WS route registered.
    app = create_app()
    ws_routes = _collect_ws_paths(app.routes)
    check("route /ws/graph/{graph_id} registered", "/ws/graph/{graph_id}" in ws_routes, str(ws_routes))

    # 2. Mouse event parsing (flat / camelCase / nested payload / normalization).
    m1 = MouseEvent.model_validate({"action": "move", "x": 10.5, "y": 20, "modifiers": ["Shift"]})
    check("mouse move flat", m1.action == "move" and m1.x == 10.5 and m1.modifiers == ["shift"])

    m2 = MouseEvent.model_validate({"action": "click", "x": 1, "y": 2, "button": "RIGHT", "clickCount": 2})
    check("mouse click camelCase", m2.button == "right" and m2.click_count == 2)

    m3 = MouseEvent.model_validate({"action": "doubleClick", "x": 0, "y": 0})
    check("mouse doubleClick normalization", m3.action == "double_click")

    m4 = MouseEvent.model_validate({"action": "wheel", "x": 5, "y": 5, "deltaX": 0, "deltaY": -120})
    check("mouse wheel deltas", m4.delta_y == -120)

    try:
        MouseEvent.model_validate({"action": "teleport", "x": 0, "y": 0})
        check("invalid action rejected", False)
    except Exception:
        check("invalid action rejected", True)

    # 3. Keyboard event parsing.
    k1 = KeyboardEvent.model_validate({"action": "keyDown", "key": "a", "code": "KeyA", "text": "a"})
    check("keyboard keyDown normalization", k1.action == "keydown" and k1.code == "KeyA")

    k2 = KeyboardEvent.model_validate({"action": "insertText", "text": "Tiếng Việt 🎉"})
    check("keyboard insertText + unicode", k2.action == "insert_text" and "Việt" in (k2.text or ""))

    k3 = KeyboardEvent.model_validate({"action": "keyup", "key": "Enter", "code": "Enter"})
    check("keyboard keyup", k3.action == "keyup")

    # 4. Virtual key codes.
    vk_cases = [
        (("KeyA", None), 65), (("Digit7", None), 55), (("F5", None), 116),
        (("Enter", None), 13), (("ArrowUp", None), 38), (("Numpad3", None), 99),
        (("Space", None), 32), (("Escape", None), 27), (("ShiftLeft", None), 16),
        ((None, "a"), 65), ((None, "Enter"), 13), ((None, "ArrowLeft"), 37),
        (("Minus", None), 189), (("F24", None), 135), (("KeyZ", None), 90),
    ]
    bad_vk = [(i, o, _virtual_key_code(*i)) for i, o in vk_cases if _virtual_key_code(*i) != o]
    check("virtual key codes (15 cases)", not bad_vk, str(bad_vk))
    check("unknown key -> None", _virtual_key_code("WeirdCode", "🦄") is None)

    # 5. Modifier mask.
    check("modifier mask ctrl+shift", _modifiers_to_mask(["ctrl", "shift"]) == 2 | 8)
    check("modifier mask command->meta", _modifiers_to_mask(["command"]) == 4)

    # 6. Envelope parse/build.
    t, p = parse_client_envelope({"type": "mouse_event", "payload": {"action": "down", "x": 1}, "y": 9})
    check("parse nested payload wins", t == "MOUSE_EVENT" and p["x"] == 1 and p["y"] == 9)

    env = server_envelope(
        ServerMessageType.SCREEN_FRAME, seq=1, format="jpeg", width=10, height=5, data_b64="AAA"
    )
    check(
        "SCREEN_FRAME envelope fields",
        env["type"] == "SCREEN_FRAME"
        and env["seq"] == 1
        and set(env) == {"type", "seq", "format", "width", "height", "data_b64"},
    )

    # 7. Registry resolution order.
    s = Settings(
        browser_sandbox_cdp_url=None,
        browser_sandbox_cdp_url_template="http://{graph_id}-browser:9222",
    )
    check("registry template", asyncio.run(SandboxRegistry(s).resolve_cdp_url("g1")) == "http://g1-browser:9222")

    s2 = Settings(browser_sandbox_cdp_url="http://fixed:9222", browser_sandbox_cdp_url_template="http://{graph_id}:1")
    check("registry static wins", asyncio.run(SandboxRegistry(s2).resolve_cdp_url("g")) == "http://fixed:9222")

    s3 = Settings(browser_sandbox_cdp_url=None, browser_sandbox_cdp_url_template=None)
    check("registry none", asyncio.run(SandboxRegistry(s3).resolve_cdp_url("g")) is None)

    # 8. Streamer queue drop-oldest backpressure.
    async def queue_test() -> bool:
        st = Settings(browser_frame_queue_size=3)
        streamer = ScreencastStreamer(graph_id="t", settings=st, cdp_url=None)
        for i in range(10):
            streamer._push({"seq": i})
        got = []
        while not streamer.events.empty():
            got.append(streamer.events.get_nowait())
        return [g["seq"] for g in got] == [7, 8, 9]

    check("streamer drop-oldest backpressure", asyncio.run(queue_test()))

    # 9. Frame geometry computation.
    st = Settings(browser_screencast_max_width=1280, browser_screencast_max_height=720)
    streamer = ScreencastStreamer(graph_id="t", settings=st, cdp_url=None)
    w, h, dw, dh, _ps = streamer._compute_frame_size(
        {"deviceWidth": 1920, "deviceHeight": 1080, "pageScaleFactor": 1.0}
    )
    check("frame downscale 1920x1080 -> 1280x720", (w, h, dw, dh) == (1280, 720, 1920, 1080), f"{w}x{h}")
    w2, h2, *_ = streamer._compute_frame_size({"deviceWidth": 800, "deviceHeight": 600})
    check("frame no upscale 800x600", (w2, h2) == (800, 600), f"{w2}x{h2}")
    w3, h3, *_ = streamer._compute_frame_size({})
    check("frame metadata fallback cached", (w3, h3) == (800, 600), f"{w3}x{h3}")

    assert not _failures, f"{len(_failures)} failures: {_failures}"
    print("\nALL STATIC TESTS PASSED")


if __name__ == "__main__":
    test_all_static_logic()
    sys.exit(1 if _failures else 0)
