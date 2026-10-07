"""End-to-end verification of the browser sandbox stack (NO mocks).

What this exercises, with a real Chromium build:

1. ``ScreencastStreamer`` over ``connect_over_cdp`` against a Chromium
   process launched with the exact flags from
   ``infra/sandbox-browser/sandbox-entrypoint.sh`` (the sandbox container
   equivalent), verifying:
     * STREAM_READY / SCREEN_FRAME envelopes,
     * frames are real JPEGs (magic bytes) with sane geometry and seq,
     * tab-switch re-attach,
     * graceful stop + sentinel.
2. ``human_takeover`` dispatchers against a live page, verifying the input
   REALLY reaches the renderer (mousemove listener coordinates, <input>
   value after keydown/insert_text with Vietnamese diacritics).
3. The FastAPI WebSocket route ``/ws/graph/{graph_id}`` through
   ``starlette.testclient``, verifying the full protocol: takeover gating,
   SET_TAKEOVER, MOUSE_EVENT/KEYBOARD_EVENT dispatch, PING/PONG, error
   envelopes (40001/40002/40003/40301) and token auth (4401).

Requires: ``playwright install chromium`` (deps installed) in this
environment. Run: ``python3 apps/api/tests/e2e_stream_test.py``
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

JPEG_MAGIC = b"\xff\xd8\xff"
CDP_PORT = 9333
CDP_URL = f"http://127.0.0.1:{CDP_PORT}"

TEST_PAGE = (
    "data:text/html,"
    "%3Cinput%20id%3D'i'%20style%3D'width:300px;height:40px'%3E"
    "%3Cscript%3E"
    "window.__mm=null;window.__clicks=0;"
    "document.addEventListener('mousemove',e=%3E{window.__mm=[e.clientX,e.clientY]});"
    "document.addEventListener('mousedown',e=%3E{window.__clicks+=1});"
    "%3C/script%3E"
)

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if not cond else ""), flush=True)
    if not cond:
        _failures.append(name)


def chromium_executable_path() -> str:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        return p.chromium.executable_path


def launch_sandbox_chrome(extra_url: str | None = None) -> subprocess.Popen[bytes]:
    """Launch Chromium exactly like infra/sandbox-browser/sandbox-entrypoint.sh."""
    chrome = chromium_executable_path()
    profile = tempfile.mkdtemp(prefix="e2e-chrome-")
    args = [
        chrome,
        "--headless=new",
        f"--remote-debugging-port={CDP_PORT}",
        "--remote-debugging-address=127.0.0.1",
        "--remote-allow-origins=*",
        f"--user-data-dir={profile}",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-renderer-backgrounding",
        "--mute-audio",
        extra_url or TEST_PAGE,
    ]
    chrome_log = open('/tmp/chrome_e2e.log', 'wb')  # noqa: SIM115 - lives as long as chrome
    proc = subprocess.Popen(args, stdout=chrome_log, stderr=chrome_log)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"chrome exited early with code {proc.returncode}")
        try:
            with urllib.request.urlopen(f"{CDP_URL}/json/version", timeout=2) as resp:
                if resp.status == 200:
                    return proc
        except OSError:
            time.sleep(0.25)
    proc.terminate()
    raise RuntimeError("chrome CDP endpoint did not come up in time")


_SKIP_TYPES = ("SCREEN_FRAME", "STREAM_READY", "STREAM_RECONNECTING", "PONG")


def recv_type(ws, want: str, limit: int = 500) -> dict:
    """Receive until an envelope of type `want` arrives.

    Streaming envelopes (frames, lifecycle) legitimately interleave with
    command responses on the single writer queue; skip them. Any other
    unexpected envelope is returned so the check fails visibly.
    """
    for _ in range(limit):
        m = ws.receive_json()
        if m.get("type") == want or m.get("type") not in _SKIP_TYPES:
            return m
    return {"type": "<recv-limit-exhausted>"}


async def goto_resilient(page, url: str, *, timeout: int = 20_000) -> None:
    """Navigate, surviving the headless-Chromium data:-URL lifecycle quirk.

    Chromium (headless=new) intermittently fails to emit navigation
    lifecycle events when navigating repeatedly to the SAME data: URL
    (opaque origins make every navigation cross-origin). This reproduces
    with plain Playwright and NO screencast attached, so it is an engine
    quirk, not a sandbox bug. reload()/two-step navigation recover.
    """
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        return
    except Exception:
        pass
    try:
        await page.reload(wait_until="domcontentloaded", timeout=timeout)
        return
    except Exception:
        pass
    await page.goto("about:blank", wait_until="domcontentloaded", timeout=timeout)
    await page.goto(url, wait_until="domcontentloaded", timeout=timeout)


async def next_envelope(
    streamer, wanted: str, timeout: float = 30
) -> dict:
    """Drain streamer.events until an envelope of `wanted` type arrives."""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for {wanted}")
        try:
            env = await asyncio.wait_for(streamer.events.get(), timeout=remaining)
        except TimeoutError as exc:
            raise TimeoutError(f"timed out waiting for {wanted}") from exc
        if env is None:
            raise AssertionError(f"stream ended while waiting for {wanted}")
        if env.get("type") == "STREAM_ERROR":
            raise AssertionError(f"STREAM_ERROR: {env}")
        if env.get("type") == wanted:
            return env


async def test_streamer_over_cdp(proc: subprocess.Popen[bytes]) -> None:
    """Streamer attaches over CDP, streams real JPEG frames, re-attaches on new tab."""
    from omniagent.sandboxes.browser.config import Settings
    from omniagent.sandboxes.browser.streamer import ScreencastStreamer

    settings = Settings(
        browser_sandbox_cdp_url=CDP_URL,
        browser_sandbox_launch_local_fallback=False,
        browser_frame_queue_size=64,
        browser_connect_timeout_ms=20_000,
        browser_max_reconnect_attempts=3,
        browser_reconnect_base_delay=0.2,
    )
    streamer = ScreencastStreamer(graph_id="e2e-cdp", settings=settings, cdp_url=CDP_URL)
    runner = asyncio.create_task(streamer.run(), name="runner")
    try:
        ready = await next_envelope(streamer, "STREAM_READY", timeout=45)
        check("cdp: STREAM_READY", ready.get("format") == "jpeg" and ready.get("quality") == 70, str(ready))

        frame = await next_envelope(streamer, "SCREEN_FRAME", timeout=20)
        raw = base64.b64decode(frame["data_b64"], validate=True)
        check(
            "cdp: SCREEN_FRAME is real JPEG with spec fields",
            raw[:3] == JPEG_MAGIC
            and isinstance(frame["seq"], int)
            and frame["seq"] >= 1
            and frame["format"] == "jpeg"
            and frame["width"] > 0
            and frame["height"] > 0
            and frame["width"] <= 1280
            and frame["height"] <= 720,
            f"seq={frame.get('seq')} {frame.get('width')}x{frame.get('height')} magic={raw[:3].hex()}",
        )

        # New visual change must produce a NEW frame with a higher seq.
        page = streamer.active_page
        assert page is not None
        await page.evaluate("document.body.style.background = 'linear-gradient(red, blue)'")
        frame2 = await next_envelope(streamer, "SCREEN_FRAME", timeout=20)
        check("cdp: adaptive frames on visual change (seq increments)", frame2["seq"] > frame["seq"], f"{frame['seq']} -> {frame2['seq']}")

        # Open a new tab -> streamer must re-attach (second STREAM_READY).
        new_page = await page.context.new_page()
        await goto_resilient(new_page, "data:text/html,%3Ch1%3Esecond%20tab%3C/h1%3E")
        ready2 = await next_envelope(streamer, "STREAM_READY", timeout=30)
        check("cdp: re-attaches to new tab", "second%20tab" in ready2.get("page_url", "") or ready2.get("page_url", "").startswith("data:"), str(ready2.get("page_url"))[:80])
        frame3 = await next_envelope(streamer, "SCREEN_FRAME", timeout=20)
        check("cdp: frames resume after re-attach", frame3["seq"] > frame2["seq"])
        await new_page.close()
        await asyncio.sleep(0.5)
        # streamer should re-attach back to the surviving tab
        ready3 = await next_envelope(streamer, "STREAM_READY", timeout=30)
        check("cdp: re-attaches back after tab close", ready3.get("page_url", "").startswith("data:"), str(ready3.get("page_url"))[:80])

        # Graceful stop -> sentinel.
        streamer.stop()
        await asyncio.wait_for(runner, timeout=30)
        sentinel_seen = False
        while not streamer.events.empty():
            if streamer.events.get_nowait() is None:
                sentinel_seen = True
        check("cdp: graceful stop pushes sentinel", sentinel_seen)
    finally:
        streamer.stop()
        runner.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await runner


async def test_human_takeover_real_input(proc: subprocess.Popen[bytes]) -> None:
    """Mouse/keyboard dispatch must REALLY affect the live page."""
    from omniagent.sandboxes.browser.config import Settings
    from omniagent.sandboxes.browser.human_takeover import (
        dispatch_keyboard_event,
        dispatch_mouse_event,
    )
    from omniagent.sandboxes.browser.models import KeyboardEvent, MouseEvent
    from omniagent.sandboxes.browser.streamer import ScreencastStreamer

    settings = Settings(
        browser_sandbox_launch_local_fallback=False,
        browser_frame_queue_size=64,
        browser_connect_timeout_ms=20_000,
        browser_max_reconnect_attempts=3,
        browser_reconnect_base_delay=0.2,
    )
    streamer = ScreencastStreamer(graph_id="e2e-input", settings=settings, cdp_url=CDP_URL)
    runner = asyncio.create_task(streamer.run())
    try:
        await next_envelope(streamer, "STREAM_READY", timeout=45)
        session = streamer.active_session
        page = streamer.active_page
        assert session is not None and page is not None
        await goto_resilient(page, TEST_PAGE)
        await page.wait_for_selector("#i", timeout=30_000)

        # --- Mouse move really moves the (virtual) pointer ---
        await dispatch_mouse_event(session, MouseEvent.model_validate({"action": "move", "x": 120, "y": 80}), timeout=10)
        mm = await page.evaluate("window.__mm")
        check("takeover: mousemove reaches renderer", mm == [120, 80], f"got {mm}")

        # --- Down/up/click ---
        for action in ("down", "up", "click"):
            await dispatch_mouse_event(
                session,
                MouseEvent.model_validate({"action": action, "x": 120, "y": 80, "button": "left"}),
                timeout=10,
            )
        clicks = await page.evaluate("window.__clicks")
        check("takeover: mousedown/click reach renderer", clicks == 2, f"got {clicks}")  # down + click

        # --- Wheel (must not raise) ---
        await dispatch_mouse_event(
            session, MouseEvent.model_validate({"action": "wheel", "x": 120, "y": 80, "deltaY": 100}), timeout=10
        )
        check("takeover: wheel dispatch ok", True)

        # --- Keyboard: raw key events type into the focused input ---
        await page.evaluate("document.getElementById('i').focus()")
        for ch, code in (("O", "KeyO"), ("m", "KeyM"), ("n", "KeyN"), ("i", "KeyI")):
            await dispatch_keyboard_event(
                session,
                KeyboardEvent.model_validate({"action": "keydown", "key": ch, "code": code, "text": ch}),
                timeout=10,
            )
            await dispatch_keyboard_event(
                session, KeyboardEvent.model_validate({"action": "keyup", "key": ch, "code": code}), timeout=10
            )
        value = await page.input_value("#i")
        check("takeover: keydown/keyup type text", value == "Omni", f"got {value!r}")

        # --- insert_text path (IME-safe, Vietnamese diacritics) ---
        await dispatch_keyboard_event(
            session, KeyboardEvent.model_validate({"action": "insert_text", "text": "Agent-Tiếng-Việt"}), timeout=10
        )
        value = await page.input_value("#i")
        check("takeover: insert_text with diacritics", value == "OmniAgent-Tiếng-Việt", f"got {value!r}")

        # --- Enter normalization ---
        await dispatch_keyboard_event(
            session, KeyboardEvent.model_validate({"action": "keydown", "key": "Enter", "code": "Enter"}), timeout=10
        )
        check("takeover: Enter dispatch ok (no text required)", True)

        # --- Validation errors surface as ValueError ---
        try:
            await dispatch_mouse_event(
                session, MouseEvent.model_validate({"action": "wheel", "x": 0, "y": 0, "deltaX": 0, "deltaY": 0}), timeout=10
            )
            check("takeover: zero-delta wheel rejected", False)
        except ValueError:
            check("takeover: zero-delta wheel rejected", True)
    finally:
        streamer.stop()
        runner.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await runner


def test_websocket_route(proc: subprocess.Popen[bytes]) -> None:
    """Full protocol test of /ws/graph/{graph_id} via starlette TestClient."""
    os.environ["OMNIAGENT_BROWSER_SANDBOX_CDP_URL"] = CDP_URL
    os.environ["OMNIAGENT_BROWSER_SANDBOX_LAUNCH_LOCAL_FALLBACK"] = "false"
    os.environ.pop("OMNIAGENT_API_WS_AUTH_TOKEN", None)

    from omniagent.sandboxes.browser.config import get_settings
    from omniagent.sandboxes.browser.registry import get_sandbox_registry

    get_settings.cache_clear()
    get_sandbox_registry.cache_clear()

    from starlette.testclient import TestClient

    from omniagent.main import create_app

    with TestClient(create_app()) as client:
        with client.websocket_connect("/ws/graph/e2e-graph-1") as ws:
            # Wait for STREAM_READY then a real frame.
            msg = None
            for _ in range(20):
                msg = ws.receive_json()
                if msg["type"] == "STREAM_READY":
                    break
            check("ws: STREAM_READY received", msg is not None and msg["type"] == "STREAM_READY", str(msg)[:120])

            frame = None
            for _ in range(50):
                candidate = ws.receive_json()
                if candidate["type"] == "SCREEN_FRAME":
                    frame = candidate
                    break
            ok_frame = (
                frame is not None
                and base64.b64decode(frame["data_b64"], validate=True)[:3] == JPEG_MAGIC
                and frame["width"] > 0
            )
            check("ws: SCREEN_FRAME carries real JPEG", ok_frame, str(frame)[:120] if frame else "no frame")

            # --- Takeover gating ---
            ws.send_json({"type": "MOUSE_EVENT", "action": "move", "x": 5, "y": 5})
            err = recv_type(ws, "ERROR")
            check(
                "ws: input rejected before takeover (40301)",
                err["type"] == "ERROR" and err["code"] == 40301,
                str(err)[:120],
            )

            ws.send_json({"type": "SET_TAKEOVER", "enabled": True})
            st = recv_type(ws, "TAKEOVER_STATE")
            check("ws: SET_TAKEOVER -> TAKEOVER_STATE", st["type"] == "TAKEOVER_STATE" and st["enabled"] is True, str(st)[:120])

            # --- Real input through the socket; PONG confirms clean processing ---
            ws.send_json({"type": "MOUSE_EVENT", "action": "move", "x": 10, "y": 10})
            ws.send_json({"type": "MOUSE_EVENT", "action": "click", "x": 10, "y": 10, "button": "left"})
            ws.send_json({"type": "MOUSE_EVENT", "action": "wheel", "x": 10, "y": 10, "deltaY": 60})
            ws.send_json({"type": "KEYBOARD_EVENT", "action": "keydown", "key": "a", "code": "KeyA", "text": "a"})
            ws.send_json({"type": "KEYBOARD_EVENT", "action": "keyup", "key": "a", "code": "KeyA"})
            ws.send_json({"type": "PING", "ts": 42})
            errors = []
            pong = None
            for _ in range(100):
                m = ws.receive_json()
                if m["type"] == "ERROR":
                    errors.append(m)
                elif m["type"] == "PONG":
                    pong = m
                    break
            check("ws: mouse+keyboard accepted after takeover", not errors and pong is not None and pong.get("echo") == 42, str(errors)[:200])

            # --- Protocol error envelopes ---
            ws.send_text("{not json")
            m = recv_type(ws, "ERROR")
            check("ws: invalid JSON -> 40001", m["type"] == "ERROR" and m["code"] == 40001, str(m)[:120])

            ws.send_json({"type": "BOGUS_COMMAND"})
            m = recv_type(ws, "ERROR")
            check("ws: unknown type -> 40003", m["type"] == "ERROR" and m["code"] == 40003, str(m)[:120])

            ws.send_json({"type": "KEYBOARD_EVENT", "action": "selfdestruct"})
            m = recv_type(ws, "ERROR")
            check("ws: bad payload -> 40002", m["type"] == "ERROR" and m["code"] == 40002, str(m)[:120])

            # --- Frames keep flowing (stream still healthy after all that) ---
            got_frame = False
            for _ in range(60):
                m = ws.receive_json()
                if m["type"] == "SCREEN_FRAME":
                    got_frame = True
                    break
            check("ws: stream still alive after commands", got_frame)

        # --- Bad graph_id is rejected at handshake ---
        try:
            with client.websocket_connect("/ws/graph/bad..id!") as ws2:
                ws2.receive_json()
            check("ws: bad graph_id rejected 4400", False, "connect succeeded")
        except BaseException as exc:
            code = getattr(exc, "code", None)
            check(
                "ws: bad graph_id rejected 4400",
                code == 4400,
                f"code={code!r} exc={exc!r}",
            )

    # --- Auth token enforcement ---
    os.environ["OMNIAGENT_API_WS_AUTH_TOKEN"] = "s3cret"
    get_settings.cache_clear()
    get_sandbox_registry.cache_clear()
    from starlette.testclient import TestClient as TC2

    from omniagent.main import create_app as create_app2

    with TC2(create_app2()) as client:
        # Handshake is now rejected BEFORE accept => connect raises with 4401.
        try:
            with client.websocket_connect("/ws/graph/e2e-graph-2") as ws:
                ws.receive_json()
            check("ws: missing token -> handshake rejected 4401", False, "connect succeeded")
        except BaseException as exc:
            code = getattr(exc, "code", None)
            check(
                "ws: missing token -> handshake rejected 4401",
                code == 4401,
                f"code={code!r} exc={exc!r}",
            )

        with client.websocket_connect("/ws/graph/e2e-graph-3?token=s3cret") as ws:
            m = None
            for _ in range(20):
                m = ws.receive_json()
                if m["type"] in ("STREAM_READY", "STREAM_RECONNECTING"):
                    break
            check("ws: valid token accepted", m is not None and m["type"] == "STREAM_READY", str(m)[:120])

    os.environ.pop("OMNIAGENT_API_WS_AUTH_TOKEN", None)
    get_settings.cache_clear()
    get_sandbox_registry.cache_clear()


async def async_main(proc: subprocess.Popen[bytes]) -> None:
    await asyncio.wait_for(test_streamer_over_cdp(proc), timeout=150)
    await asyncio.sleep(1.0)  # let teardown settle on small CI boxes
    if proc.poll() is not None:
        raise RuntimeError(f"chrome died (rc={proc.returncode}) before takeover test")
    await asyncio.wait_for(test_human_takeover_real_input(proc), timeout=150)
    if proc.poll() is not None:
        raise RuntimeError(f"chrome died (rc={proc.returncode}) before ws test")


def main() -> int:
    proc = launch_sandbox_chrome()
    print(f"[info] sandbox chromium up (pid={proc.pid}, cdp={CDP_URL})", flush=True)

    import signal

    def _kill_chrome(signum: int, _frame: object) -> None:
        proc.terminate()
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _kill_chrome)
    signal.signal(signal.SIGINT, _kill_chrome)

    try:
        asyncio.run(async_main(proc))
        test_websocket_route(proc)
    finally:
        rc = proc.poll()
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=10)
        if proc.poll() is None:
            proc.kill()
        if _failures or rc is not None:
            print(f"\n[diag] chrome exit code before terminate: {rc}")
            with contextlib.suppress(OSError):
                from pathlib import Path

                data = Path("/tmp/chrome_e2e.log").read_bytes()[-2000:]
                print(f"[diag] chrome log tail:\n{data.decode(errors='replace')}")

    print()
    if _failures:
        print(f"{len(_failures)} E2E FAILURES: {_failures}")
        return 1
    print("ALL E2E TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
