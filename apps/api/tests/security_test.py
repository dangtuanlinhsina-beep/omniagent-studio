"""Security test-suite: RBAC, JWT, throttling, WS handshake, takeover leases.

Run::

    pytest apps/api/tests/security_test.py -q
    python apps/api/tests/security_test.py          # same, via pytest.main

The WebSocket cases drive the real endpoint through Starlette's test client
with a stubbed :class:`ScreencastStreamer` (no Chromium needed): the stub
exposes a fake ``CDPSession`` that records every ``Input.dispatch*`` call, so
the tests assert both *what is refused* and *what actually reaches CDP*.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

from omniagent.api import routes_stream  # noqa: E402
from omniagent.api.connection_registry import (  # noqa: E402
    WsConnection,
    get_connection_registry,
    takeover_state_envelope,
)
from omniagent.api.graph_access import (  # noqa: E402
    GraphAccessError,
    get_graph_authorizer,
    set_graph_authorizer,
    validate_cdp_url,
    validate_graph_id,
)
from omniagent.main import create_app  # noqa: E402
from omniagent.sandboxes.browser.config import Settings, get_settings  # noqa: E402
from omniagent.sandboxes.browser.models import (  # noqa: E402
    AppErrorCode,
    ServerMessageType,
    WsCloseCode,
)
from omniagent.security.audit import redact_email  # noqa: E402
from omniagent.security.ratelimit import (  # noqa: E402
    ConnectionRateLimiter,
    MouseMoveCoalescer,
    RateLimitPolicy,
    SlidingWindowCounter,
    TokenBucket,
    get_graph_input_registry,
)
from omniagent.security.roles import (  # noqa: E402
    Permission,
    Principal,
    Role,
    build_anonymous_principal,
    coerce_role,
    normalize_graph_ids,
)
from omniagent.security.tokens import (  # noqa: E402
    SecurityConfigError,
    TokenError,
    TokenErrorCode,
    TokenService,
    TokenType,
    client_fingerprint,
    get_token_service,
    reset_token_service,
    token_fingerprint,
)
from omniagent.security.user_store import (  # noqa: E402
    LoginThrottle,
    PasswordPolicyError,
    UserConflictError,
    get_login_throttle,
    get_user_store,
    hash_password,
    reset_user_store,
    verify_password,
)
from omniagent.security.ws_auth import (  # noqa: E402
    WsAuthError,
    negotiate_subprotocol,
    redact_url,
    reset_handshake_limiter,
    required_role_for,
)

TEST_SECRET = "unit-test-secret-value-with-enough-entropy-0123456789"
OPERATOR_EMAIL = "operator@omniagent.test"
VIEWER_EMAIL = "viewer@omniagent.test"
PASSWORD = "Sup3r-secret-password!"
GRAPH_A = "graph-alpha"
GRAPH_B = "graph-beta"


# ---------------------------------------------------------------------------
# Fixtures / stubs
# ---------------------------------------------------------------------------


class FakeCDPSession:
    """Records every CDP command the route dispatches."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.detached = False

    async def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append((method, params or {}))
        return {}

    async def detach(self) -> None:
        self.detached = True

    def methods(self) -> list[str]:
        return [method for method, _ in self.calls]


class FakeStreamer:
    """Drop-in replacement for :class:`ScreencastStreamer`."""

    instances: list[FakeStreamer] = []

    def __init__(
        self,
        *,
        graph_id: str,
        settings: Settings | None = None,
        cdp_url: str | None = None,
        cdp_headers: dict[str, str] | None = None,
    ) -> None:
        self.graph_id = graph_id
        self.settings = settings
        self.cdp_url = cdp_url
        self.cdp_headers = cdp_headers
        self.events: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=8)
        self.session = FakeCDPSession()
        self._stop = asyncio.Event()
        self.ran = False
        FakeStreamer.instances.append(self)

    @property
    def active_session(self) -> FakeCDPSession:
        return self.session

    @property
    def active_page(self) -> None:
        return None

    def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        self.ran = True
        # Block until the route tears us down, then emit the terminal sentinel
        # exactly like the real streamer does.
        await self._stop.wait()
        self.events.put_nowait(None)


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Reset every process-wide cache so tests cannot leak into each other."""
    monkeypatch.setenv("OMNIAGENT_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("OMNIAGENT_AUTH_ENABLED", "true")
    monkeypatch.setenv("OMNIAGENT_BROWSER_SANDBOX_LAUNCH_LOCAL_FALLBACK", "false")
    monkeypatch.setenv("OMNIAGENT_BROWSER_SANDBOX_REQUIRE_REMOTE", "true")
    monkeypatch.setenv("OMNIAGENT_API_WS_ALLOWED_ORIGINS", json.dumps(["https://studio.test"]))
    monkeypatch.setenv("OMNIAGENT_API_WS_HANDSHAKE_RATE_LIMIT", "200")
    monkeypatch.setenv("OMNIAGENT_AUTH_LOGIN_ATTEMPTS", "50")
    monkeypatch.setenv("OMNIAGENT_TAKEOVER_LEASE_TTL_S", "30")
    monkeypatch.setenv("OMNIAGENT_API_WS_MAX_LIFETIME_S", "600")
    monkeypatch.setenv("OMNIAGENT_API_WS_IDLE_TIMEOUT_S", "60")
    monkeypatch.setenv("OMNIAGENT_RATELIMIT_MOUSE_MOVE_INTERVAL_MS", "0")

    get_settings.cache_clear()
    reset_token_service()
    reset_user_store()
    reset_handshake_limiter()
    set_graph_authorizer(None)
    get_connection_registry().clear()
    get_graph_input_registry().clear()
    FakeStreamer.instances.clear()
    monkeypatch.setattr(routes_stream, "ScreencastStreamer", FakeStreamer)

    yield get_settings()

    get_settings.cache_clear()
    reset_token_service()
    reset_user_store()
    reset_handshake_limiter()
    set_graph_authorizer(None)
    get_connection_registry().clear()
    get_graph_input_registry().clear()


@pytest.fixture()
def store(isolated_state: Settings) -> Any:
    user_store = get_user_store(isolated_state)
    user_store.create_sync(  # type: ignore[attr-defined]
        email=OPERATOR_EMAIL, password=PASSWORD, role=Role.OPERATOR, graph_ids=(GRAPH_A,)
    )
    user_store.create_sync(  # type: ignore[attr-defined]
        email=VIEWER_EMAIL, password=PASSWORD, role=Role.VIEWER, graph_ids=(GRAPH_A,)
    )
    return user_store


@pytest.fixture()
def app(isolated_state: Settings, store: Any) -> Any:
    return create_app()


@pytest.fixture()
def client(app: Any) -> Any:
    with TestClient(app) as test_client:
        yield test_client


def login(client: Any, email: str = OPERATOR_EMAIL, password: str = PASSWORD) -> dict[str, Any]:
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def ticket_for(
    client: Any, graph_id: str, access_token: str | None = None, email: str = OPERATOR_EMAIL
) -> str:
    token = access_token or login(client, email)["access_token"]
    response = client.post(
        "/api/auth/ws-ticket",
        json={"graph_id": graph_id},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    return response.json()["ticket"]


def connect(
    client: Any,
    graph_id: str,
    ticket: str,
    *,
    origin: str = "https://studio.test",
    headers: dict[str, str] | None = None,
) -> Any:
    """Open the WS offering ``["omniagent.v1", ticket]`` like the browser does."""
    request_headers = {"Origin": origin}
    if headers:
        request_headers.update(headers)
    return client.websocket_connect(
        f"/ws/graph/{graph_id}",
        subprotocols=["omniagent.v1", ticket],
        headers=request_headers,
    )


def drain(session: Any, count: int = 1, timeout: float = 2.0) -> list[dict[str, Any]]:
    """Receive ``count`` JSON envelopes."""
    return [session.receive_json() for _ in range(count)]


def expect_error(session: Any, app_code: int) -> dict[str, Any]:
    """Assert the next envelope is ``ERROR{code}`` and return it."""
    envelope = session.receive_json()
    assert envelope["type"] == ServerMessageType.ERROR.value, envelope
    assert envelope["code"] == app_code, envelope
    return envelope


def expect_close(session: Any, close_code: int) -> None:
    """Assert the socket closes with ``close_code`` on the next read."""
    with pytest.raises(WebSocketDisconnect) as excinfo:
        session.receive_json()
    assert excinfo.value.code == close_code


# ===========================================================================
# 1. Roles & permissions
# ===========================================================================


def test_role_coercion_fails_safe() -> None:
    assert coerce_role("operator") is Role.OPERATOR
    assert coerce_role("ADMIN") is Role.ADMIN
    assert coerce_role("superuser") is Role.VIEWER  # unknown -> least privilege
    assert coerce_role(None) is Role.VIEWER
    assert coerce_role(42) is Role.VIEWER
    assert coerce_role(["OPERATOR"]) is Role.OPERATOR


def test_permission_matrix() -> None:
    viewer = Principal(subject="v", role=Role.VIEWER)
    operator = Principal(subject="o", role=Role.OPERATOR)
    admin = Principal(subject="a", role=Role.ADMIN)

    assert viewer.can(Permission.SCREEN_VIEW)
    assert not viewer.can(Permission.INPUT_SEND)
    assert not viewer.can(Permission.TAKEOVER_CONTROL)

    assert operator.can(Permission.INPUT_SEND)
    assert operator.can(Permission.TAKEOVER_CONTROL)
    assert not operator.can(Permission.GRAPH_MANAGE)

    assert admin.can(Permission.GRAPH_MANAGE)
    assert admin.has_role_at_least(Role.OPERATOR)
    assert not operator.has_role_at_least(Role.ADMIN)
    # Unknown permissions are denied, not raised.
    assert not admin.can("not-a-permission")


def test_graph_scope_checks() -> None:
    scoped = Principal(subject="u", role=Role.OPERATOR, graph_ids=(GRAPH_A,))
    assert scoped.can_access_graph(GRAPH_A)
    assert not scoped.can_access_graph(GRAPH_B)
    assert not scoped.can_access_graph("")

    wildcard = Principal(subject="svc", role=Role.ADMIN, graph_ids=("*",), is_service=True)
    assert wildcard.can_access_graph(GRAPH_B)

    unbound = Principal(subject="n", role=Role.VIEWER)
    assert not unbound.can_access_graph(GRAPH_A)

    assert normalize_graph_ids(["g1", " g1 ", "", "*"]) == ("*",)
    assert normalize_graph_ids(None) == ()
    assert normalize_graph_ids("g2") == ("g2",)


def test_anonymous_principal_is_viewer_by_default() -> None:
    assert build_anonymous_principal().role is Role.VIEWER
    assert build_anonymous_principal(Role.OPERATOR).role is Role.OPERATOR


def test_message_role_requirements() -> None:
    assert required_role_for("mouse_event") is Role.OPERATOR
    assert required_role_for("SET_TAKEOVER") is Role.OPERATOR
    assert required_role_for("KEYBOARD_EVENT") is Role.OPERATOR
    assert required_role_for("PING") is Role.VIEWER
    assert required_role_for("SOMETHING") is None


# ===========================================================================
# 2. JWT token service
# ===========================================================================


def test_access_token_roundtrip(isolated_state: Settings) -> None:
    service = get_token_service(isolated_state)
    issued = service.issue_access_token(
        subject="user-1", role="operator", graph_ids=[GRAPH_A], display_name="Op"
    )
    principal = service.verify(issued.token, expected_type=TokenType.ACCESS)
    assert principal.subject == "user-1"
    assert principal.role is Role.OPERATOR
    assert principal.can_access_graph(GRAPH_A)
    assert not principal.can_access_graph(GRAPH_B)
    assert principal.effective_expires_at == pytest.approx(issued.expires_at, abs=1)


def test_verify_rejects_wrong_graph(isolated_state: Settings) -> None:
    service = get_token_service(isolated_state)
    issued = service.issue_access_token(subject="u", role=Role.OPERATOR, graph_ids=[GRAPH_A])
    with pytest.raises(TokenError) as excinfo:
        service.verify(issued.token, expected_type=TokenType.ACCESS, graph_id=GRAPH_B)
    assert excinfo.value.code is TokenErrorCode.GRAPH


def test_verify_rejects_tampered_token(isolated_state: Settings) -> None:
    service = get_token_service(isolated_state)
    token = service.issue_access_token(subject="u", role=Role.VIEWER, graph_ids=[GRAPH_A]).token
    header, payload, signature = token.split(".")
    forged_role = base64.urlsafe_b64encode(
        json.dumps({"role": "ADMIN", "sub": "u", "gph": ["*"]}).encode()
    ).rstrip(b"=").decode()
    with pytest.raises(TokenError) as excinfo:
        service.verify(f"{header}.{forged_role}.{signature}", expected_type=TokenType.ACCESS)
    assert excinfo.value.code in (TokenErrorCode.SIGNATURE, TokenErrorCode.MALFORMED, TokenErrorCode.CLAIM)


def test_verify_rejects_alg_none(isolated_state: Settings) -> None:
    """The classic ``alg: none`` downgrade must never verify."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "iss": isolated_state.jwt_issuer,
                "aud": isolated_state.jwt_audience,
                "sub": "attacker",
                "role": "ADMIN",
                "gph": ["*"],
                "typ": "access",
                "jti": "x",
                "iat": int(time.time()),
                "exp": int(time.time()) + 60,
            }
        ).encode()
    ).rstrip(b"=")
    with pytest.raises(TokenError):
        get_token_service(isolated_state).verify(
            f"{header.decode()}.{payload.decode()}.", expected_type=TokenType.ACCESS
        )


def test_verify_rejects_wrong_audience_and_issuer(isolated_state: Settings) -> None:
    service = get_token_service(isolated_state)
    token = service.issue_access_token(subject="u", role=Role.VIEWER, graph_ids=[GRAPH_A]).token
    other = Settings(
        jwt_secret=TEST_SECRET, jwt_audience="someone-else", jwt_issuer=isolated_state.jwt_issuer
    )
    with pytest.raises(TokenError) as excinfo:
        TokenService(other).verify(token, expected_type=TokenType.ACCESS)
    assert excinfo.value.code is TokenErrorCode.AUDIENCE

    foreign_issuer = Settings(
        jwt_secret=TEST_SECRET,
        jwt_audience=isolated_state.jwt_audience,
        jwt_issuer="evil-corp",
    )
    with pytest.raises(TokenError) as excinfo:
        TokenService(foreign_issuer).verify(token, expected_type=TokenType.ACCESS)
    assert excinfo.value.code is TokenErrorCode.ISSUER


def test_expired_token_rejected(isolated_state: Settings) -> None:
    # ``jwt_clock_skew_s`` (default 5 s) is legitimate leeway for NTP drift,
    # so this case pins it to 0 to observe the expiry itself.
    strict = Settings(jwt_secret=TEST_SECRET, jwt_clock_skew_s=0)
    service = TokenService(strict)
    issued = service.issue_access_token(
        subject="u", role=Role.VIEWER, graph_ids=[GRAPH_A], ttl_s=1
    )
    time.sleep(1.4)
    with pytest.raises(TokenError) as excinfo:
        service.verify(issued.token, expected_type=TokenType.ACCESS)
    assert excinfo.value.code is TokenErrorCode.EXPIRED
    # Within leeway the same token is still accepted (clock-skew tolerance).
    lenient = TokenService(Settings(jwt_secret=TEST_SECRET, jwt_clock_skew_s=30))
    assert lenient.verify(issued.token, expected_type=TokenType.ACCESS).subject == "u"


def test_ws_ticket_is_single_use_and_graph_bound(isolated_state: Settings) -> None:
    service = get_token_service(isolated_state)
    access = service.issue_access_token(subject="u", role=Role.OPERATOR, graph_ids=[GRAPH_A])
    principal = service.verify(access.token, expected_type=TokenType.ACCESS)
    ticket = service.issue_ws_ticket(principal=principal, graph_id=GRAPH_A)

    used = service.verify(ticket.token, expected_type=TokenType.WS_TICKET, graph_id=GRAPH_A)
    assert used.subject == "u"
    assert used.role is Role.OPERATOR
    assert used.graph_ids == (GRAPH_A,)
    # The ticket outlives itself without killing the socket: session expiry is carried.
    assert used.effective_expires_at == pytest.approx(principal.expires_at, abs=1)

    with pytest.raises(TokenError) as excinfo:
        service.verify(ticket.token, expected_type=TokenType.WS_TICKET, graph_id=GRAPH_A)
    assert excinfo.value.code is TokenErrorCode.REPLAYED


def test_ws_ticket_cannot_be_minted_for_foreign_graph(isolated_state: Settings) -> None:
    service = get_token_service(isolated_state)
    principal = service.verify(
        service.issue_access_token(subject="u", role=Role.OPERATOR, graph_ids=[GRAPH_A]).token,
        expected_type=TokenType.ACCESS,
    )
    with pytest.raises(TokenError) as excinfo:
        service.issue_ws_ticket(principal=principal, graph_id=GRAPH_B)
    assert excinfo.value.code is TokenErrorCode.GRAPH


def test_token_type_confusion_rejected(isolated_state: Settings) -> None:
    service = get_token_service(isolated_state)
    access = service.issue_access_token(subject="u", role=Role.OPERATOR, graph_ids=[GRAPH_A])
    with pytest.raises(TokenError) as excinfo:
        service.verify(access.token, expected_type=TokenType.WS_TICKET)
    assert excinfo.value.code is TokenErrorCode.TYPE

    refresh = service.issue_refresh_token(subject="u", role=Role.OPERATOR, graph_ids=[GRAPH_A])
    with pytest.raises(TokenError):
        service.verify(refresh.token, expected_type=TokenType.ACCESS)


def test_revocation_of_token_and_session(isolated_state: Settings) -> None:
    service = get_token_service(isolated_state)
    issued = service.issue_access_token(subject="u", role=Role.OPERATOR, graph_ids=[GRAPH_A])
    principal = service.verify(issued.token, expected_type=TokenType.ACCESS)

    service.revoke_token(principal.token_id, 60)
    with pytest.raises(TokenError) as excinfo:
        service.verify(issued.token, expected_type=TokenType.ACCESS)
    assert excinfo.value.code is TokenErrorCode.REVOKED

    second = service.issue_access_token(
        subject="u", role=Role.OPERATOR, graph_ids=[GRAPH_A], session_id=principal.session_id
    )
    service.revoke_session(principal.session_id, 60)
    with pytest.raises(TokenError):
        service.verify(second.token, expected_type=TokenType.ACCESS)


def test_sender_binding(isolated_state: Settings) -> None:
    service = get_token_service(isolated_state)
    principal = service.verify(
        service.issue_access_token(subject="u", role=Role.OPERATOR, graph_ids=[GRAPH_A]).token,
        expected_type=TokenType.ACCESS,
    )
    fingerprint = client_fingerprint("203.0.113.7", "Mozilla/5.0")
    ticket = service.issue_ws_ticket(
        principal=principal, graph_id=GRAPH_A, fingerprint=fingerprint
    )
    service.verify(
        ticket.token, expected_type=TokenType.WS_TICKET, graph_id=GRAPH_A, fingerprint=fingerprint
    )
    other = service.issue_ws_ticket(
        principal=principal, graph_id=GRAPH_A, fingerprint=fingerprint
    )
    with pytest.raises(TokenError) as excinfo:
        service.verify(
            other.token,
            expected_type=TokenType.WS_TICKET,
            graph_id=GRAPH_A,
            fingerprint=client_fingerprint("198.51.100.9", "curl/8"),
        )
    assert excinfo.value.code is TokenErrorCode.BINDING


def test_weak_secret_is_refused() -> None:
    weak = Settings(jwt_secret="changeme", auth_enabled=True)
    with pytest.raises(SecurityConfigError):
        TokenService(weak)._signing_key()  # noqa: SLF001
    problems = TokenService(weak).validate_configuration()
    assert any("placeholder" in problem or "43" in problem for problem in problems)

    missing = Settings(jwt_secret=None, auth_enabled=True)
    assert any("JWT_SECRET" in problem for problem in missing.__class__ and TokenService(missing).validate_configuration())


def test_oversized_token_rejected(isolated_state: Settings) -> None:
    service = get_token_service(isolated_state)
    with pytest.raises(TokenError) as excinfo:
        service.verify("a" * (isolated_state.jwt_max_token_chars + 1), expected_type=TokenType.ACCESS)
    assert excinfo.value.code is TokenErrorCode.TOO_LARGE


def test_token_fingerprint_never_contains_the_token() -> None:
    token = "header.payload.signature"
    fingerprint = token_fingerprint(token)
    assert token not in fingerprint
    assert fingerprint.endswith("…")
    assert token_fingerprint("") == "<empty>"


# ===========================================================================
# 3. Rate limiting primitives
# ===========================================================================


def test_token_bucket_burst_and_refill() -> None:
    bucket = TokenBucket(RateLimitPolicy("t", capacity=3, refill_per_second=10), now=0.0)
    assert all(bucket.consume(now=0.0)[0] for _ in range(3))
    allowed, retry_after = bucket.consume(now=0.0)
    assert not allowed and retry_after == pytest.approx(0.1, abs=0.01)
    allowed, _ = bucket.consume(now=0.2)
    assert allowed


def test_connection_limiter_categories_and_rollback() -> None:
    limiter = ConnectionRateLimiter(
        {
            "message": RateLimitPolicy("message", capacity=100, refill_per_second=1),
            "input": RateLimitPolicy("input", capacity=2, refill_per_second=0.001),
        },
        max_strikes=3,
    )
    assert limiter.check("message", "input").allowed
    assert limiter.check("message", "input").allowed
    denied = limiter.check("message", "input")
    assert not denied.allowed and denied.limit == "input"
    assert limiter.strikes == 1
    # The rejected call must not have drained the message budget.
    assert limiter.snapshot()["message"] > 95
    assert not limiter.must_disconnect
    limiter.check("message", "input")
    limiter.check("message", "input")
    assert limiter.must_disconnect


def test_limiter_fails_closed_on_unknown_category() -> None:
    limiter = ConnectionRateLimiter()
    decision = limiter.check("nope")
    assert not decision.allowed


def test_mouse_move_coalescer() -> None:
    coalescer = MouseMoveCoalescer(0.016)
    assert coalescer.accept(now=0.0)
    assert not coalescer.accept(now=0.005)
    assert not coalescer.accept(now=0.010)
    assert coalescer.accept(now=0.020)
    assert coalescer.suppressed == 2 and coalescer.forwarded == 2
    coalescer.force_next()
    assert coalescer.accept(now=0.021)

    disabled = MouseMoveCoalescer(0)
    assert all(disabled.accept(now=i * 0.001) for i in range(10))


def test_sliding_window_counter() -> None:
    counter = SlidingWindowCounter(limit=3, window_s=1.0)
    results = [counter.hit("ip", now=0.0 + i * 0.1)[0] for i in range(5)]
    assert results == [True, True, True, False, False]
    assert counter.hit("ip", now=1.5)[0]
    assert counter.peek("ip", now=1.6) == 1
    assert counter.peek("other", now=1.6) == 0


# ===========================================================================
# 4. Subprotocol negotiation / origin policy / log hygiene
# ===========================================================================


class _FakeHeaders(dict[str, str]):
    def get(self, key: str, default: str | None = None) -> str | None:  # type: ignore[override]
        return super().get(key.lower(), default)


@dataclass
class _FakeWebSocket:
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.headers = {k.lower(): v for k, v in self.headers.items()}
        object.__setattr__(self, "headers", _FakeHeaders(self.headers))


def _negotiate(header: str, settings: Settings) -> tuple[str | None, str | None]:
    return negotiate_subprotocol(_FakeWebSocket({"sec-websocket-protocol": header}), settings)  # type: ignore[arg-type]


def test_subprotocol_negotiation_two_entry_form(isolated_state: Settings) -> None:
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.c2lnbmF0dXJlLXBhcnQ"
    token, echo = _negotiate(f"omniagent.v1, {fake_jwt}", isolated_state)
    assert token == fake_jwt
    assert echo == "omniagent.v1"  # token is NOT echoed back


def test_subprotocol_negotiation_single_entry_form(isolated_state: Settings) -> None:
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.c2lnbmF0dXJlLXBhcnQ"
    token, echo = _negotiate(f"omniagent.v1.jwt.{fake_jwt}", isolated_state)
    assert token == fake_jwt
    # RFC 6455: the server must echo one of the offered values verbatim,
    # otherwise the browser aborts the connection with 1006.
    assert echo == f"omniagent.v1.jwt.{fake_jwt}"


def test_subprotocol_without_token(isolated_state: Settings) -> None:
    token, echo = _negotiate("omniagent.v1", isolated_state)
    assert token is None and echo == "omniagent.v1"
    token, echo = _negotiate("", isolated_state)
    assert token is None and echo is None
    token, echo = _negotiate("unknown.protocol", isolated_state)
    assert token is None and echo is None


def test_redact_url_strips_credentials() -> None:
    assert "secret" not in redact_url("/ws/graph/g1?token=secret&debug=1")
    assert "debug=1" in redact_url("/ws/graph/g1?token=secret&debug=1")
    assert redact_url("/ws/graph/g1") == "/ws/graph/g1"


def test_redact_email_is_one_way() -> None:
    hashed = redact_email(OPERATOR_EMAIL)
    assert hashed and OPERATOR_EMAIL not in hashed and hashed.startswith("sha256:")
    assert redact_email(OPERATOR_EMAIL) == hashed
    assert redact_email(None) is None


# ===========================================================================
# 5. Graph-level authorization (IDOR defence)
# ===========================================================================


def test_graph_id_shape_validation(isolated_state: Settings) -> None:
    assert validate_graph_id("graph-42_ok", isolated_state) == "graph-42_ok"
    for bad in ("../etc/passwd", "a" * 65, "has space", "", "semi;colon"):
        with pytest.raises(GraphAccessError):
            validate_graph_id(bad, isolated_state)


def test_cdp_url_validation(isolated_state: Settings) -> None:
    assert validate_cdp_url("http://browser-g1:9222", isolated_state)
    for bad in (
        "file:///etc/passwd",
        "gopher://browser:9222",
        "http://user:pass@browser:9222",
        "http://:9222",
    ):
        with pytest.raises(GraphAccessError):
            validate_cdp_url(bad, isolated_state)

    strict = Settings(browser_sandbox_cdp_reject_loopback=True)
    with pytest.raises(GraphAccessError):
        validate_cdp_url("http://127.0.0.1:9222", strict)


@pytest.mark.asyncio
async def test_authorizer_denies_foreign_graph(isolated_state: Settings) -> None:
    authorizer = get_graph_authorizer(isolated_state)
    principal = Principal(subject="u", role=Role.OPERATOR, graph_ids=(GRAPH_A,))
    context = await authorizer.authorize(principal, GRAPH_A, permission=Permission.SCREEN_VIEW)
    assert context.graph_id == GRAPH_A

    with pytest.raises(GraphAccessError):
        await authorizer.authorize(principal, GRAPH_B, permission=Permission.SCREEN_VIEW)

    viewer = Principal(subject="v", role=Role.VIEWER, graph_ids=(GRAPH_A,))
    with pytest.raises(GraphAccessError):
        await authorizer.authorize(viewer, GRAPH_A, permission=Permission.TAKEOVER_CONTROL)


@pytest.mark.asyncio
async def test_authorizer_attaches_cdp_token(isolated_state: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OMNIAGENT_BROWSER_SANDBOX_CDP_URL", "http://browser:9222")
    monkeypatch.setenv("OMNIAGENT_BROWSER_SANDBOX_CDP_AUTH_TOKEN", "sandbox-secret")
    get_settings.cache_clear()
    set_graph_authorizer(None)
    authorizer = get_graph_authorizer(get_settings())
    context = await authorizer.authorize(
        Principal(subject="u", role=Role.OPERATOR, graph_ids=("*",)), GRAPH_A
    )
    assert context.cdp_headers == {"Authorization": "Bearer sandbox-secret"}


# ===========================================================================
# 6. Connection registry & takeover lease
# ===========================================================================


def _connection(graph_id: str, subject: str, role: Role, conn_id: str) -> WsConnection:
    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=4)
    return WsConnection(
        id=conn_id,
        graph_id=graph_id,
        principal=Principal(subject=subject, role=role, graph_ids=(graph_id,)),
        out_queue=queue,
    )


@pytest.mark.asyncio
async def test_connection_caps() -> None:
    registry = get_connection_registry()
    for index in range(2):
        result = registry.register(
            _connection(GRAPH_A, "u", Role.VIEWER, f"c{index}"), max_per_graph=2, max_per_principal=5
        )
        assert result.ok
    refused = registry.register(
        _connection(GRAPH_A, "u2", Role.VIEWER, "c2"), max_per_graph=2, max_per_principal=5
    )
    assert not refused.ok and "limit" in refused.reason

    for index in range(3):
        registry.register(
            _connection(GRAPH_B, "greedy", Role.VIEWER, f"b{index}"),
            max_per_graph=10,
            max_per_principal=2,
        )
    third = registry.register(
        _connection(GRAPH_B, "greedy", Role.VIEWER, "b3"), max_per_graph=10, max_per_principal=2
    )
    assert not third.ok and "greedy" in third.reason


@pytest.mark.asyncio
async def test_takeover_lease_is_exclusive_and_expires() -> None:
    registry = get_connection_registry()
    first = _connection(GRAPH_A, "op1", Role.OPERATOR, "c1")
    second = _connection(GRAPH_A, "op2", Role.OPERATOR, "c2")
    registry.register(first, max_per_graph=5, max_per_principal=5)
    registry.register(second, max_per_graph=5, max_per_principal=5)

    granted = registry.acquire_takeover(first, ttl_s=30, max_ttl_s=60)
    assert granted.ok and granted.lease is not None
    assert granted.lease.subject == "op1"

    conflict = registry.acquire_takeover(second, ttl_s=30, max_ttl_s=60)
    assert not conflict.ok and conflict.conflict is not None
    assert conflict.conflict.subject == "op1"

    # TTL is clamped to the server maximum, never to the client's wish.
    clamped = registry.acquire_takeover(first, ttl_s=9999, max_ttl_s=60)
    assert clamped.lease is not None
    assert clamped.lease.expires_at - clamped.lease.acquired_at <= 61

    # Admins may force-release somebody else's lease.
    admin = Principal(subject="root", role=Role.ADMIN, graph_ids=("*",))
    assert registry.force_release_takeover(GRAPH_A, by=admin) is not None
    assert registry.lease(GRAPH_A) is None

    # Second operator can now take over.
    assert registry.acquire_takeover(second, ttl_s=30, max_ttl_s=60).ok

    # Expiry: backdate and sweep.
    lease = registry.lease(GRAPH_A)
    assert lease is not None
    object.__setattr__(lease, "expires_at", time.time() - 1)
    expired = registry.sweep_expired_leases()
    assert any(item.graph_id == GRAPH_A for item in expired)
    assert registry.lease(GRAPH_A) is None


@pytest.mark.asyncio
async def test_broadcast_is_queued_and_drop_oldest() -> None:
    registry = get_connection_registry()
    slow = _connection(GRAPH_A, "slow", Role.VIEWER, "c-slow")
    registry.register(slow, max_per_graph=5, max_per_principal=5)
    for index in range(10):  # queue maxsize is 4
        registry.broadcast(GRAPH_A, takeover_state_envelope(GRAPH_A, None, reason=f"r{index}"))
    collected: list[dict[str, Any]] = []
    while not slow.out_queue.empty():
        collected.append(slow.out_queue.get_nowait())
    assert len(collected) == 4
    assert collected[-1]["reason"] == "r9"  # newest wins


def test_unregister_releases_lease() -> None:
    registry = get_connection_registry()
    conn = _connection(GRAPH_A, "op", Role.OPERATOR, "c1")
    registry.register(conn, max_per_graph=5, max_per_principal=5)
    registry.acquire_takeover(conn, ttl_s=30, max_ttl_s=60)
    assert registry.lease(GRAPH_A) is not None
    registry.unregister(GRAPH_A, "c1")
    assert registry.lease(GRAPH_A) is None
    assert registry.connections(GRAPH_A) == ()


# ===========================================================================
# 7. Password hashing / user store
# ===========================================================================


def test_password_hashing() -> None:
    stored = hash_password("correct horse battery staple")
    assert stored.startswith("pbkdf2_sha256$")
    assert verify_password("correct horse battery staple", stored)
    assert not verify_password("wrong", stored)
    assert not verify_password("correct horse battery staple", "garbage")
    assert not verify_password("anything", "")
    # Two hashes of the same password differ (per-password salt).
    assert hash_password("same") != hash_password("same")


def test_password_policy() -> None:
    store = get_user_store()
    with pytest.raises(PasswordPolicyError):
        store.create_sync(email="x@y.test", password="short")  # type: ignore[attr-defined]
    with pytest.raises(PasswordPolicyError):
        # Password containing the e-mail local part is guessable.
        store.create_sync(email="alice@y.test", password="alice-Str0ng-pw")  # type: ignore[attr-defined]
    with pytest.raises(PasswordPolicyError):
        store.create_sync(email="x@y.test", password="password")  # type: ignore[attr-defined]


def test_duplicate_registration_conflicts() -> None:
    store = get_user_store()
    store.create_sync(email="dup@y.test", password="Str0ng-passw0rd!")  # type: ignore[attr-defined]
    with pytest.raises(UserConflictError):
        store.create_sync(email="DUP@y.test", password="An0ther-passw0rd!")  # type: ignore[attr-defined]


def test_login_throttle_dual_key() -> None:
    throttle = LoginThrottle(limit=3, window_s=60.0)
    for _ in range(4):
        throttle.check("10.0.0.1", "victim@y.test")
    # A different IP hammering the SAME account is still blocked (email key).
    allowed, retry_after = throttle.check("10.0.0.2", "victim@y.test")
    assert not allowed and retry_after > 0
    # A different account is unaffected.
    assert throttle.check("10.0.0.3", "someone-else@y.test")[0]
    # One IP spraying many accounts is blocked by the (4x) IP key.
    spray = LoginThrottle(limit=2, window_s=60.0)
    for index in range(9):
        spray.check("10.9.9.9", f"user{index}@y.test")
    assert not spray.check("10.9.9.9", "user99@y.test")[0]
    assert get_login_throttle() is get_login_throttle()  # process-wide singleton


# ===========================================================================
# 8. REST auth endpoints
# ===========================================================================


def test_login_and_me(client: Any) -> None:
    body = login(client)
    assert body["role"] == "OPERATOR"
    assert "input:send" in body["permissions"]
    assert body["expires_in"] <= 900
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["role"] == "OPERATOR"
    assert me.json()["graph_ids"] == [GRAPH_A]


def test_login_rejects_bad_credentials_without_enumeration(client: Any) -> None:
    wrong_password = client.post(
        "/api/auth/login", json={"email": OPERATOR_EMAIL, "password": "nope"}
    )
    unknown_user = client.post(
        "/api/auth/login", json={"email": "ghost@omniagent.test", "password": "nope"}
    )
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["detail"] == unknown_user.json()["detail"] == "invalid credentials"


def test_login_is_throttled(client: Any, isolated_state: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OMNIAGENT_AUTH_LOGIN_ATTEMPTS", "3")
    get_settings.cache_clear()
    import omniagent.security.user_store as user_store_module

    user_store_module._login_throttle = None  # noqa: SLF001 - rebuild from settings
    try:
        codes = [
            client.post(
                "/api/auth/login", json={"email": OPERATOR_EMAIL, "password": "wrong"}
            ).status_code
            for _ in range(6)
        ]
        assert 429 in codes
        assert codes.count(401) <= 4
    finally:
        user_store_module._login_throttle = None  # noqa: SLF001


def test_refresh_rotates_and_logout_revokes(client: Any) -> None:
    body = login(client)
    refreshed = client.post(
        "/api/auth/refresh", json={"refresh_token": body["refresh_token"]}
    )
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["access_token"] != body["access_token"]

    # The consumed refresh token cannot be replayed.
    replay = client.post("/api/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert replay.status_code == 401

    headers = {"Authorization": f"Bearer {refreshed.json()['access_token']}"}
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_registration_disabled_by_default(client: Any) -> None:
    response = client.post(
        "/api/auth/register",
        json={"email": "new@omniagent.test", "password": "Str0ng-passw0rd!", "role": "ADMIN"},
    )
    assert response.status_code == 403


def test_registration_never_escalates_role(isolated_state: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OMNIAGENT_AUTH_ALLOW_SELF_REGISTRATION", "true")
    monkeypatch.setenv("OMNIAGENT_AUTH_DEFAULT_REGISTRATION_ROLE", "VIEWER")
    get_settings.cache_clear()
    reset_user_store()
    with TestClient(create_app()) as test_client:
        response = test_client.post(
            "/api/auth/register",
            json={"email": "new@omniagent.test", "password": "Str0ng-passw0rd!", "role": "ADMIN"},
        )
        assert response.status_code == 201, response.text
        assert response.json()["role"] == "VIEWER"
        assert "input:send" not in response.json()["permissions"]


def test_ws_ticket_requires_auth_and_rejects_foreign_graph(client: Any) -> None:
    assert client.post("/api/auth/ws-ticket", json={"graph_id": GRAPH_A}).status_code in (401, 403)

    viewer_token = login(client, VIEWER_EMAIL)["access_token"]
    denied = client.post(
        "/api/auth/ws-ticket",
        json={"graph_id": GRAPH_B},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert denied.status_code == 403

    ok = client.post(
        "/api/auth/ws-ticket",
        json={"graph_id": GRAPH_A},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert ok.status_code == 200
    assert ok.json()["expires_in"] <= 60
    assert ok.json()["subprotocols"] == ["omniagent.v1", "omniagent.v1.jwt"]


def test_stream_stats_requires_admin(client: Any) -> None:
    operator = login(client)["access_token"]
    assert (
        client.get(
            f"/api/auth/graphs/{GRAPH_A}/stream-stats",
            headers={"Authorization": f"Bearer {operator}"},
        ).status_code
        == 403
    )


def test_docs_are_hidden_by_default(client: Any) -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_security_headers_present(client: Any) -> None:
    response = client.get("/healthz")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in response.headers["content-security-policy"]


# ===========================================================================
# 9. WebSocket endpoint — end to end
# ===========================================================================


def test_ws_requires_credential(client: Any) -> None:
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(
            f"/ws/graph/{GRAPH_A}",
            subprotocols=["omniagent.v1"],
            headers={"Origin": "https://studio.test"},
        ) as session:
            session.receive_json()
    # Refused before accept(): the client never sees a 101.
    assert excinfo.value.code in (WsCloseCode.POLICY_VIOLATION, 1006, 403)


def test_ws_rejects_invalid_token(client: Any) -> None:
    # A structurally plausible but unsigned/forged JWT never receives HTTP 101.
    forged = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiJ9.bogus"
    with pytest.raises(WebSocketDisconnect):
        with connect(client, GRAPH_A, forged) as session:
            session.receive_json()


def test_ws_rejects_credential_shaped_garbage(client: Any) -> None:
    with pytest.raises(WebSocketDisconnect):
        with connect(client, GRAPH_A, "definitely-not-a-valid-jwt-token-value") as session:
            session.receive_json()


def test_ws_rejects_foreign_origin(client: Any) -> None:
    ticket = ticket_for(client, GRAPH_A)
    with pytest.raises(WebSocketDisconnect):
        with connect(client, GRAPH_A, ticket, origin="https://evil.example") as session:
            session.receive_json()


def test_ws_rejects_malformed_graph_id(client: Any) -> None:
    ticket = ticket_for(client, GRAPH_A)
    with pytest.raises(WebSocketDisconnect):
        with connect(client, "..%2Fetc", ticket) as session:
            session.receive_json()


def test_ws_rejects_ticket_for_another_graph(client: Any) -> None:
    """IDOR defence: a ticket minted for graph A never receives HTTP 101 on B."""
    ticket = ticket_for(client, GRAPH_A)
    with pytest.raises(WebSocketDisconnect):
        with connect(client, GRAPH_B, ticket) as session:
            session.receive_json()


def test_ws_ticket_replay_is_rejected(client: Any) -> None:
    ticket = ticket_for(client, GRAPH_A)
    with connect(client, GRAPH_A, ticket) as session:
        ready = session.receive_json()
        assert ready["type"] == ServerMessageType.SESSION_READY.value
    # Same ticket again -> replay is refused before HTTP 101 (single-use JTI).
    with pytest.raises(WebSocketDisconnect):
        with connect(client, GRAPH_A, ticket) as session:
            session.receive_json()


def test_session_ready_describes_capabilities(client: Any) -> None:
    ticket = ticket_for(client, GRAPH_A)
    with connect(client, GRAPH_A, ticket) as session:
        ready = session.receive_json()
    assert ready["type"] == "SESSION_READY"
    assert ready["role"] == "OPERATOR"
    assert ready["graph_id"] == GRAPH_A
    assert set(ready["permissions"]) == {"screen:view", "input:send", "takeover:control"}
    assert ready["takeover"]["input_requires_takeover"] is True
    assert ready["rate_limits"]["input"]["per_second"] > 0
    assert ready["limits"]["max_message_bytes"] > 0
    # The 60-second ticket is single-use; the connection expiry is the parent
    # access/session expiry, otherwise long-lived WS streams reauth every ticket TTL.
    assert ready["credential_expires_at"] > time.time() + 60


def test_viewer_cannot_send_input_or_takeover(client: Any) -> None:
    ticket = ticket_for(client, GRAPH_A, email=VIEWER_EMAIL)
    with connect(client, GRAPH_A, ticket) as session:
        ready = session.receive_json()
        assert ready["role"] == "VIEWER"

        session.send_json({"type": "SET_TAKEOVER", "payload": {"enabled": True}})
        denied = session.receive_json()
        assert denied["type"] == "ERROR"
        assert denied["code"] == AppErrorCode.FORBIDDEN
        assert denied["required_role"] == "OPERATOR"

        session.send_json({"type": "MOUSE_EVENT", "payload": {"action": "click", "x": 1, "y": 2}})
        denied = session.receive_json()
        assert denied["code"] == AppErrorCode.FORBIDDEN

        session.send_json({"type": "KEYBOARD_EVENT", "payload": {"action": "keydown", "key": "a"}})
        denied = session.receive_json()
        assert denied["code"] == AppErrorCode.FORBIDDEN

        # Viewers keep working heartbeat support.
        session.send_json({"type": "PING", "payload": {"ts": 42}})
        pong = session.receive_json()
        assert pong["type"] == "PONG" and pong["echo"] == 42

        # ...and a viewer that keeps probing gets disconnected with 4403.
        for _ in range(10):
            session.send_json({"type": "MOUSE_EVENT", "payload": {"action": "move", "x": 1, "y": 1}})
        with pytest.raises(WebSocketDisconnect) as excinfo:
            while True:
                envelope = session.receive_json()
                if envelope.get("code") == AppErrorCode.FORBIDDEN:
                    continue
        assert excinfo.value.code == WsCloseCode.FORBIDDEN

    # Nothing ever reached the fake CDP session.
    streamer = FakeStreamer.instances[-1]
    assert streamer.session.calls == []


def test_viewer_does_not_receive_takeover_state(client: Any) -> None:
    """Outbound policy: the video stream is all a VIEWER gets.

    The operator's ``SET_TAKEOVER`` broadcasts ``TAKEOVER_STATE`` to the whole
    graph room, but the single serialised writer filters envelopes by role —
    so the viewer's socket never sees it (it only sees its own PONG).
    """
    viewer_ticket = ticket_for(client, GRAPH_A, email=VIEWER_EMAIL)
    operator_ticket = ticket_for(client, GRAPH_A)

    with connect(client, GRAPH_A, viewer_ticket) as viewer_ws:
        assert viewer_ws.receive_json()["role"] == "VIEWER"
        with connect(client, GRAPH_A, operator_ticket) as operator_ws:
            assert operator_ws.receive_json()["role"] == "OPERATOR"
            operator_ws.send_json({"type": "SET_TAKEOVER", "payload": {"enabled": True}})
            state = operator_ws.receive_json()
            assert state["type"] == "TAKEOVER_STATE" and state["enabled"] is True
            assert state["holder"]  # operators learn *who* holds the lease

            viewer_ws.send_json({"type": "PING", "payload": {"ts": 7}})
            pong = viewer_ws.receive_json()
            assert pong["type"] == "PONG" and pong["echo"] == 7


def test_outbound_policy_matrix(isolated_state: Settings) -> None:
    """Unit-level check of the writer's role filter."""
    from omniagent.api.routes_stream import _outbound_allowed

    frames = {"type": ServerMessageType.SCREEN_FRAME.value}
    takeover = {"type": ServerMessageType.TAKEOVER_STATE.value}
    error = {"type": ServerMessageType.ERROR.value}

    assert _outbound_allowed(Role.VIEWER, frames, isolated_state)
    assert not _outbound_allowed(Role.VIEWER, takeover, isolated_state)
    assert _outbound_allowed(Role.VIEWER, error, isolated_state)
    assert _outbound_allowed(Role.OPERATOR, takeover, isolated_state)
    assert _outbound_allowed(Role.ADMIN, {"type": "ANYTHING"}, isolated_state)


def test_operator_input_requires_takeover_then_reaches_cdp(client: Any) -> None:
    ticket = ticket_for(client, GRAPH_A)
    with connect(client, GRAPH_A, ticket) as session:
        session.receive_json()  # SESSION_READY

        session.send_json({"type": "MOUSE_EVENT", "payload": {"action": "click", "x": 5, "y": 6}})
        blocked = session.receive_json()
        assert blocked["code"] == AppErrorCode.TAKEOVER_NOT_ACTIVE

        session.send_json(
            {"type": "SET_TAKEOVER", "payload": {"enabled": True, "leaseMs": 20000}}
        )
        state = session.receive_json()
        assert state["type"] == "TAKEOVER_STATE" and state["enabled"] is True
        assert state["lease_ms"] == 20000

        session.send_json({"type": "MOUSE_EVENT", "payload": {"action": "click", "x": 5, "y": 6}})
        session.send_json(
            {"type": "KEYBOARD_EVENT", "payload": {"action": "insert_text", "text": "Tiếng Việt"}}
        )
        session.send_json({"type": "PING"})
        pong = session.receive_json()
        assert pong["type"] == "PONG"

    streamer = FakeStreamer.instances[-1]
    methods = streamer.session.methods()
    assert methods.count("Input.dispatchMouseEvent") == 2  # click = press + release
    assert "Input.insertText" in methods


def test_second_operator_loses_the_lease_conflict(client: Any) -> None:
    first_ticket = ticket_for(client, GRAPH_A)
    second_token = login(client)["access_token"]

    with connect(client, GRAPH_A, first_ticket) as first:
        first.receive_json()
        first.send_json({"type": "SET_TAKEOVER", "payload": {"enabled": True}})
        assert first.receive_json()["enabled"] is True

        second_ticket = ticket_for(client, GRAPH_A, access_token=second_token)
        with connect(client, GRAPH_A, second_ticket) as second:
            second.receive_json()
            second.send_json({"type": "SET_TAKEOVER", "payload": {"enabled": True}})
            conflict = second.receive_json()
            assert conflict["type"] == "ERROR"
            assert conflict["code"] == AppErrorCode.TAKEOVER_LEASE_CONFLICT
            assert conflict["holder_is_other"] is True

            # Input is refused too: the lease belongs to somebody else.
            second.send_json(
                {"type": "MOUSE_EVENT", "payload": {"action": "move", "x": 1, "y": 1}}
            )
            blocked = second.receive_json()
            assert blocked["code"] in (
                AppErrorCode.TAKEOVER_NOT_ACTIVE,
                AppErrorCode.TAKEOVER_LEASE_CONFLICT,
            )

        # When the holder leaves, the lease is released for the next operator.
    assert get_connection_registry().lease(GRAPH_A) is None


def test_oversized_message_is_refused(client: Any) -> None:
    ticket = ticket_for(client, GRAPH_A)
    with connect(client, GRAPH_A, ticket) as session:
        session.receive_json()
        session.send_text(json.dumps({"type": "PING", "blob": "x" * 200_000}))
        error = session.receive_json()
        assert error["type"] == "ERROR"
        assert error["code"] == AppErrorCode.MESSAGE_TOO_LARGE


def test_input_rate_limit_kicks_in(client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OMNIAGENT_RATELIMIT_INPUT_CAPACITY", "5")
    monkeypatch.setenv("OMNIAGENT_RATELIMIT_INPUT_RATE", "0.001")
    monkeypatch.setenv("OMNIAGENT_RATELIMIT_MESSAGE_CAPACITY", "10000")
    monkeypatch.setenv("OMNIAGENT_RATELIMIT_MESSAGE_RATE", "10000")
    monkeypatch.setenv("OMNIAGENT_API_WS_RATE_LIMIT_STRIKES", "4")
    get_settings.cache_clear()
    get_graph_input_registry().clear()

    ticket = ticket_for(client, GRAPH_A)
    with connect(client, GRAPH_A, ticket) as session:
        session.receive_json()
        session.send_json({"type": "SET_TAKEOVER", "payload": {"enabled": True}})
        assert session.receive_json()["type"] == "TAKEOVER_STATE"

        for index in range(40):
            session.send_json(
                {"type": "KEYBOARD_EVENT", "payload": {"action": "keydown", "key": "a", "code": "KeyA"}}
            )

        throttled = 0
        closed_with = None
        try:
            while True:
                envelope = session.receive_json()
                if envelope.get("type") == "RATE_LIMITED":
                    throttled += 1
                if envelope.get("code") == AppErrorCode.RATE_LIMITED:
                    throttled += 1
        except WebSocketDisconnect as exc:
            closed_with = exc.code
    assert throttled > 0
    assert closed_with == WsCloseCode.TOO_MANY_REQUESTS


def test_mouse_move_coalescing_reduces_cdp_calls(
    client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OMNIAGENT_RATELIMIT_MOUSE_MOVE_INTERVAL_MS", "25")
    monkeypatch.setenv("OMNIAGENT_RATELIMIT_INPUT_CAPACITY", "10000")
    monkeypatch.setenv("OMNIAGENT_RATELIMIT_INPUT_RATE", "10000")
    get_settings.cache_clear()

    ticket = ticket_for(client, GRAPH_A)
    with connect(client, GRAPH_A, ticket) as session:
        session.receive_json()
        session.send_json({"type": "SET_TAKEOVER", "payload": {"enabled": True}})
        session.receive_json()
        # 20 moves fired back-to-back inside one coalescing window.
        for index in range(20):
            session.send_json(
                {"type": "MOUSE_EVENT", "payload": {"action": "move", "x": index, "y": index}}
            )
        session.send_json({"type": "PING"})
        while session.receive_json()["type"] != "PONG":
            pass

    streamer = FakeStreamer.instances[-1]
    moves = [call for call in streamer.session.methods() if call == "Input.dispatchMouseEvent"]
    assert len(moves) < 20
    assert streamer.cdp_url is None  # require_remote=true -> no local fallback


def test_auth_message_refreshes_credential(client: Any) -> None:
    ticket = ticket_for(client, GRAPH_A)
    with connect(client, GRAPH_A, ticket) as session:
        session.receive_json()
        fresh_ticket = ticket_for(client, GRAPH_A)
        session.send_json({"type": "AUTH", "payload": {"token": fresh_ticket}})
        refreshed = session.receive_json()
        assert refreshed["type"] == "SESSION_READY"
        assert refreshed["refreshed"] is True

        session.send_json({"type": "AUTH", "payload": {"token": "garbage.token.value"}})
        error = session.receive_json()
        assert error["type"] == "ERROR"


def test_header_bearer_transport_works(client: Any) -> None:
    """Non-browser clients may use ``Authorization: Bearer`` instead."""
    ticket = ticket_for(client, GRAPH_A)
    with client.websocket_connect(
        f"/ws/graph/{GRAPH_A}",
        headers={"Origin": "https://studio.test", "Authorization": f"Bearer {ticket}"},
    ) as session:
        ready = session.receive_json()
        assert ready["type"] == "SESSION_READY"


def test_query_token_can_be_disabled(client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OMNIAGENT_API_WS_TOKEN_IN_QUERY", "false")
    get_settings.cache_clear()
    ticket = ticket_for(client, GRAPH_A)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            f"/ws/graph/{GRAPH_A}?token={ticket}", headers={"Origin": "https://studio.test"}
        ) as session:
            session.receive_json()


def test_connection_cap_per_graph(client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OMNIAGENT_API_WS_MAX_CONNECTIONS_PER_GRAPH", "1")
    get_settings.cache_clear()
    token = login(client)["access_token"]
    first_ticket = ticket_for(client, GRAPH_A, access_token=token)
    with connect(client, GRAPH_A, first_ticket) as first:
        first.receive_json()
        second_ticket = ticket_for(client, GRAPH_A, access_token=token)
        with connect(client, GRAPH_A, second_ticket) as second:
            expect_error(second, AppErrorCode.CONNECTION_LIMIT)
            expect_close(second, WsCloseCode.TOO_MANY_REQUESTS)


def test_legacy_static_token_is_opt_in(client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OMNIAGENT_API_WS_AUTH_TOKEN", "shared-dev-secret")
    monkeypatch.setenv("OMNIAGENT_AUTH_ALLOW_LEGACY_STATIC_TOKEN", "true")
    monkeypatch.setenv("OMNIAGENT_API_WS_STATIC_TOKEN_ROLE", "VIEWER")
    get_settings.cache_clear()
    reset_token_service()
    with client.websocket_connect(
        f"/ws/graph/{GRAPH_A}",
        headers={"Origin": "https://studio.test", "Authorization": "Bearer shared-dev-secret"},
    ) as session:
        ready = session.receive_json()
        assert ready["role"] == "VIEWER"
        session.send_json({"type": "SET_TAKEOVER", "payload": {"enabled": True}})
        assert session.receive_json()["code"] == AppErrorCode.FORBIDDEN


def test_auth_disabled_falls_back_to_configured_role(
    monkeypatch: pytest.MonkeyPatch, isolated_state: Settings
) -> None:
    monkeypatch.setenv("OMNIAGENT_AUTH_ENABLED", "false")
    monkeypatch.setenv("OMNIAGENT_AUTH_ANONYMOUS_ROLE", "VIEWER")
    get_settings.cache_clear()
    reset_token_service()
    with TestClient(create_app()) as test_client:
        with test_client.websocket_connect(f"/ws/graph/{GRAPH_A}") as session:
            ready = session.receive_json()
            assert ready["role"] == "VIEWER"
            session.send_json({"type": "MOUSE_EVENT", "payload": {"action": "move"}})
            assert session.receive_json()["code"] == AppErrorCode.FORBIDDEN


def test_handshake_flood_is_throttled(client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OMNIAGENT_API_WS_HANDSHAKE_RATE_LIMIT", "3")
    monkeypatch.setenv("OMNIAGENT_API_WS_HANDSHAKE_WINDOW_S", "60")
    get_settings.cache_clear()
    reset_handshake_limiter()
    token = login(client)["access_token"]
    refused = 0
    for _ in range(8):
        ticket = ticket_for(client, GRAPH_A, access_token=token)
        try:
            with connect(client, GRAPH_A, ticket) as session:
                session.receive_json()
        except WebSocketDisconnect:
            refused += 1
    assert refused >= 5


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
