"""End-to-end Security & Auth verification (real Chromium, real tokens).

Phases:
  1. HS256 JWT mode — handshake rejection (missing / bad-signature /
     expired => WebSocketDisconnect 4401 before accept), VIEWER read-only
     enforcement (40301 + reason=role_forbidden for MOUSE_EVENT,
     KEYBOARD_EVENT, SET_TAKEOVER; frames + PING still work), OPERATOR
     control path with *independent* verification that the dispatched input
     really reached the page (second CDP connection reads window.__mm and
     the <input> value), takeover-not-active reason, ADMIN parity,
     bearer.<jwt> subprotocol auth for browser clients.
  2. Rate limiting — tuned buckets via env; flooding MOUSE_EVENTs yields
     42901 envelopes (with retry_after) and finally close code 4429.
  3. RS256 via a REAL local JWKS HTTP server (Clerk-style claims: sub,
     org_id, custom role) — OPERATOR controls, VIEWER blocked.
  4. Legacy static-token mode regression — full control without roles.

Run: ``python3 apps/api/tests/e2e_auth_test.py`` (requires chromium installed)
"""

from __future__ import annotations

import base64
import contextlib
import os
import signal
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

import jwt
from auth_security_checks import (  # real key/JWKS helpers (no mocks)
    HS_SECRET,
    generate_rsa_jwks,
    start_jwks_server,
)
from e2e_stream_test import CDP_URL, launch_sandbox_chrome, recv_type

from omniagent.sandboxes.browser.config import get_settings
from omniagent.sandboxes.browser.registry import get_sandbox_registry

JPEG_MAGIC = b"\xff\xd8\xff"
_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if not cond else ""), flush=True)
    if not cond:
        _failures.append(name)


def hs_token(role: str, *, secret: str = HS_SECRET, exp_offset: int = 3600, user: str = "user_e2e") -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "user_id": user,
            "workspace_id": "ws_e2e",
            "role": role,
            "iat": now,
            "exp": now + exp_offset,
            "iss": "https://auth.omniagent.dev",
        },
        secret,
        algorithm="HS256",
    )


BASE_ENV = {
    "OMNIAGENT_BROWSER_SANDBOX_CDP_URL": CDP_URL,
    "OMNIAGENT_BROWSER_SANDBOX_LAUNCH_LOCAL_FALLBACK": "false",
}


def phase_client(extra_env: dict[str, str]):
    """Fresh TestClient with an isolated OMNIAGENT_* environment."""
    for key in [k for k in os.environ if k.startswith("OMNIAGENT_")]:
        os.environ.pop(key)
    os.environ.update(BASE_ENV)
    os.environ.update(extra_env)
    get_settings.cache_clear()
    get_sandbox_registry.cache_clear()
    from starlette.testclient import TestClient

    from omniagent.main import create_app

    return TestClient(create_app())


def expect_handshake_reject(client, url: str, code: int, label: str) -> None:
    try:
        with client.websocket_connect(url) as ws:
            ws.receive_json()
        check(label, False, "connect unexpectedly succeeded")
    except BaseException as exc:
        got = getattr(exc, "code", None)
        check(label, got == code, f"code={got!r} exc={exc!r}")


def read_page_state() -> tuple[object, str]:
    """Independent CDP connection to verify dispatched input really landed."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP_URL)
        try:
            page = browser.contexts[0].pages[0]
            mm = page.evaluate("window.__mm")
            value = page.input_value("#i") if page.evaluate(
                "!!document.getElementById('i')"
            ) else ""
            return mm, value
        finally:
            browser.close()


def phase_hs256() -> None:
    client = phase_client({"OMNIAGENT_SECURITY_JWT_SECRET": HS_SECRET})
    with client:
        # --- Handshake rejections (before accept) ---
        expect_handshake_reject(client, "/ws/graph/auth-1", 4401, "auth: missing token -> 4401")
        expect_handshake_reject(
            client, f"/ws/graph/auth-1?token={hs_token('ADMIN', secret='wrong-secret')}",
            4401, "auth: bad signature -> 4401",
        )
        expect_handshake_reject(
            client, f"/ws/graph/auth-1?token={hs_token('ADMIN', exp_offset=-300)}",
            4401, "auth: expired token -> 4401",
        )

        # --- VIEWER: frames OK, control forbidden ---
        with client.websocket_connect(f"/ws/graph/auth-viewer?token={hs_token('viewer')}") as ws:
            ready = recv_type(ws, "STREAM_READY")
            check("viewer: STREAM_READY received", ready.get("type") == "STREAM_READY", str(ready)[:100])
            frame = recv_type(ws, "SCREEN_FRAME")
            ok_frame = (
                frame.get("type") == "SCREEN_FRAME"
                and base64.b64decode(frame["data_b64"], validate=True)[:3] == JPEG_MAGIC
            )
            check("viewer: still receives real JPEG frames", ok_frame, str(frame)[:100])

            ws.send_json({"type": "MOUSE_EVENT", "action": "move", "x": 3, "y": 4})
            m = recv_type(ws, "ERROR")
            check(
                "viewer: MOUSE_EVENT -> 40301 role_forbidden",
                m.get("code") == 40301 and m.get("reason") == "role_forbidden",
                str(m)[:140],
            )
            ws.send_json({"type": "KEYBOARD_EVENT", "action": "keydown", "key": "a", "text": "a"})
            m = recv_type(ws, "ERROR")
            check("viewer: KEYBOARD_EVENT -> 40301", m.get("code") == 40301 and m.get("reason") == "role_forbidden", str(m)[:140])
            ws.send_json({"type": "SET_TAKEOVER", "enabled": True})
            m = recv_type(ws, "ERROR")
            check("viewer: SET_TAKEOVER -> 40301", m.get("code") == 40301 and m.get("reason") == "role_forbidden", str(m)[:140])

            ws.send_json({"type": "PING", "ts": 9})
            m = recv_type(ws, "PONG")
            check("viewer: PING still answered", m.get("type") == "PONG" and m.get("echo") == 9, str(m)[:100])

        # --- OPERATOR: takeover + control, verified on the page ---
        with client.websocket_connect(f"/ws/graph/auth-operator?token={hs_token('OPERATOR')}") as ws:
            recv_type(ws, "STREAM_READY")

            # Input before SET_TAKEOVER -> takeover_not_active reason.
            ws.send_json({"type": "MOUSE_EVENT", "action": "move", "x": 77, "y": 33})
            m = recv_type(ws, "ERROR")
            check(
                "operator: input pre-takeover -> 40301 takeover_not_active",
                m.get("code") == 40301 and m.get("reason") == "takeover_not_active",
                str(m)[:140],
            )

            ws.send_json({"type": "SET_TAKEOVER", "enabled": True})
            m = recv_type(ws, "TAKEOVER_STATE")
            check("operator: SET_TAKEOVER accepted", m.get("type") == "TAKEOVER_STATE" and m.get("enabled") is True, str(m)[:100])

            ws.send_json({"type": "MOUSE_EVENT", "action": "move", "x": 77, "y": 33})
            # Click lands inside the <input id="i"> (300x40 at page origin),
            # focusing it so insert_text has a target.
            ws.send_json({"type": "MOUSE_EVENT", "action": "click", "x": 77, "y": 33, "button": "left"})
            ws.send_json({"type": "KEYBOARD_EVENT", "action": "insert_text", "text": "xin-chào-ễ"})
            ws.send_json({"type": "PING", "ts": 11})
            errors = []
            pong = None
            for _ in range(200):
                m = ws.receive_json()
                if m.get("type") == "ERROR":
                    errors.append(m)
                elif m.get("type") == "PONG":
                    pong = m
                    break
            check("operator: control commands accepted (no errors)", not errors and pong is not None and pong.get("echo") == 11, str(errors)[:200])

        # Independent verification that the input REALLY reached the page.
        mm, value = read_page_state()
        check("operator: mouse move landed on page", mm == [77, 33], f"__mm={mm}")
        check("operator: typed text landed in <input>", value == "xin-chào-ễ", f"value={value!r}")

        # --- ADMIN parity ---
        with client.websocket_connect(f"/ws/graph/auth-admin?token={hs_token('ADMIN')}") as ws:
            recv_type(ws, "STREAM_READY")
            ws.send_json({"type": "SET_TAKEOVER", "enabled": True})
            m = recv_type(ws, "TAKEOVER_STATE")
            check("admin: SET_TAKEOVER accepted", m.get("type") == "TAKEOVER_STATE", str(m)[:100])

        # --- Browser-style subprotocol auth ---
        tok = hs_token("OPERATOR", user="user_proto")
        with client.websocket_connect(
            "/ws/graph/auth-proto", subprotocols=["omniagent.v1", f"bearer.{tok}"]
        ) as ws:
            check("subprotocol: accepted protocol echoed", ws.accepted_subprotocol == f"bearer.{tok}", str(ws.accepted_subprotocol)[:80])
            m = recv_type(ws, "STREAM_READY")
            check("subprotocol: stream starts", m.get("type") == "STREAM_READY", str(m)[:100])


def phase_rate_limit() -> None:
    client = phase_client(
        {
            "OMNIAGENT_SECURITY_JWT_SECRET": HS_SECRET,
            "OMNIAGENT_SECURITY_RATE_LIMIT_INPUT_PER_SECOND": "10",
            "OMNIAGENT_SECURITY_RATE_LIMIT_INPUT_BURST": "5",
            "OMNIAGENT_SECURITY_RATE_LIMIT_MESSAGES_PER_SECOND": "200",
            "OMNIAGENT_SECURITY_RATE_LIMIT_MAX_STRIKES": "10",
        }
    )
    with client, client.websocket_connect(f"/ws/graph/auth-flood?token={hs_token('OPERATOR')}") as ws:
        recv_type(ws, "STREAM_READY")
        ws.send_json({"type": "SET_TAKEOVER", "enabled": True})
        recv_type(ws, "TAKEOVER_STATE")

        # Flood: far beyond 10/s sustained; server must throttle and then close 4429.
        with contextlib.suppress(Exception):
            for i in range(400):
                ws.send_json({"type": "MOUSE_EVENT", "action": "move", "x": i % 200, "y": 5})

        rate_limited = 0
        closed_code = None
        retry_after_ok = True
        try:
            while True:
                m = ws.receive_json()
                if m.get("type") == "ERROR" and m.get("code") == 42901:
                    rate_limited += 1
                    if not isinstance(m.get("retry_after"), (int, float)):
                        retry_after_ok = False
        except BaseException as exc:
            closed_code = getattr(exc, "code", None)
        check("rate-limit: 42901 envelopes emitted", rate_limited >= 5, f"count={rate_limited}")
        check("rate-limit: retry_after present", retry_after_ok)
        check("rate-limit: socket closed 4429 after strikes", closed_code == 4429, f"code={closed_code!r}")


def phase_rs256_jwks() -> None:
    rsa_key, jwks_doc = generate_rsa_jwks("e2e-clerk-key")
    server, thread, jwks_url = start_jwks_server(jwks_doc)
    issuer = "https://e2e.clerk.accounts.dev"
    try:
        # clerk_style_token embeds iss=example.clerk.accounts.dev; issue our
        # own tokens with the configured issuer instead.
        def rs_token(role: str) -> str:
            now = int(time.time())
            return jwt.encode(
                {
                    "sub": "user_2clerk99",
                    "org_id": "org_e2e_workspace",
                    "role": role,
                    "iss": issuer,
                    "iat": now,
                    "exp": now + 600,
                },
                rsa_key,
                algorithm="RS256",
                headers={"kid": "e2e-clerk-key"},
            )

        client = phase_client(
            {
                "OMNIAGENT_SECURITY_JWKS_URL": jwks_url,
                "OMNIAGENT_SECURITY_JWT_ISSUER": issuer,
            }
        )
        with client:
            with client.websocket_connect(f"/ws/graph/auth-clerk-op?token={rs_token('OPERATOR')}") as ws:
                m = recv_type(ws, "STREAM_READY")
                check("rs256/jwks: clerk-style OPERATOR accepted", m.get("type") == "STREAM_READY", str(m)[:100])
                ws.send_json({"type": "SET_TAKEOVER", "enabled": True})
                m = recv_type(ws, "TAKEOVER_STATE")
                check("rs256/jwks: OPERATOR can control", m.get("type") == "TAKEOVER_STATE", str(m)[:100])

            with client.websocket_connect(f"/ws/graph/auth-clerk-view?token={rs_token('VIEWER')}") as ws:
                recv_type(ws, "STREAM_READY")
                ws.send_json({"type": "MOUSE_EVENT", "action": "move", "x": 1, "y": 1})
                m = recv_type(ws, "ERROR")
                check("rs256/jwks: VIEWER blocked 40301", m.get("code") == 40301 and m.get("reason") == "role_forbidden", str(m)[:140])

            # JWKS hits happened over real HTTP (server-side observable).
            check("rs256/jwks: JWKS fetched over HTTP", server.RequestHandlerClass.hits >= 1, f"hits={server.RequestHandlerClass.hits}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def phase_legacy_static_token() -> None:
    client = phase_client({"OMNIAGENT_API_WS_AUTH_TOKEN": "legacy-secret"})
    with client:
        expect_handshake_reject(client, "/ws/graph/auth-legacy-bad", 4401, "legacy: wrong token -> 4401")
        with client.websocket_connect("/ws/graph/auth-legacy?token=legacy-secret") as ws:
            m = recv_type(ws, "STREAM_READY")
            check("legacy: valid static token accepted", m.get("type") == "STREAM_READY", str(m)[:100])
            ws.send_json({"type": "SET_TAKEOVER", "enabled": True})
            m = recv_type(ws, "TAKEOVER_STATE")
            check("legacy: full control without roles", m.get("type") == "TAKEOVER_STATE", str(m)[:100])


def main() -> int:
    proc = launch_sandbox_chrome()
    print(f"[info] sandbox chromium up (pid={proc.pid})", flush=True)

    def _kill(signum: int, _frame: object) -> None:
        proc.terminate()
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _kill)
    signal.signal(signal.SIGINT, _kill)

    try:
        phase_hs256()
        phase_rate_limit()
        phase_rs256_jwks()
        phase_legacy_static_token()
    finally:
        rc = proc.poll()
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=10)
        if proc.poll() is None:
            proc.kill()
        if _failures or rc is not None:
            print(f"\n[diag] chrome exit code before terminate: {rc}")

    print()
    if _failures:
        print(f"{len(_failures)} AUTH E2E FAILURES: {_failures}")
        return 1
    print("ALL AUTH E2E TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
