"""Security layer checks — real crypto, real JWKS HTTP server, no mocks.

Covers:
  * HS256 verification (OmniAgent-minted + Supabase legacy shapes),
  * RS256 verification through a REAL local JWKS endpoint (Clerk-style
    claims), including kid lookup, caching and unknown-kid rejection,
  * algorithm-confusion and alg=none attacks,
  * exp/iss/aud enforcement + leeway,
  * claim mapping (user_id / workspace_id / role) incl. dot-paths and
    Supabase transport-role skipping, deny-by-default role fallback,
  * token-bucket rate limiting (deterministic via injected clock) and
    strike accounting,
  * handshake token extraction (header / query / subprotocol).

Run: ``python3 apps/api/tests/auth_security_checks.py``
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from starlette.websockets import WebSocket

from omniagent.sandboxes.browser.config import Settings
from omniagent.security.auth import (
    AuthContext,
    Authenticator,
    AuthError,
    ConnectionRateLimiter,
    JwksError,
    Role,
    TokenBucket,
    TokenClaimsError,
    TokenExpiredError,
    TokenInvalidError,
    build_rate_limiter,
    extract_ws_token,
)

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if not cond else ""), flush=True)
    if not cond:
        _failures.append(name)


def settings_with(**overrides: object) -> Settings:
    """Settings isolated from ambient env/.env noise."""
    base: dict[str, object] = {
        "security_jwt_secret": None,
        "security_jwt_issuer": None,
        "security_jwt_audience": None,
        "security_jwks_url": None,
        "security_require_workspace_id": True,
        "security_default_role": "VIEWER",
        "security_jwt_leeway_seconds": 10,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


HS_SECRET = "unit-test-shared-secret-0xDEADBEEF"


def hs_token(
    *,
    role: str = "OPERATOR",
    user: str = "user_123",
    workspace: str | None = "ws_42",
    exp_offset: int = 3600,
    secret: str = HS_SECRET,
    issuer: str | None = None,
    audience: str | None = None,
    drop_exp: bool = False,
    extra: dict | None = None,
) -> str:
    now = int(time.time())
    claims: dict = {"user_id": user, "role": role, "iat": now}
    if workspace is not None:
        claims["workspace_id"] = workspace
    if not drop_exp:
        claims["exp"] = now + exp_offset
    if issuer:
        claims["iss"] = issuer
    if audience:
        claims["aud"] = audience
    if extra:
        claims.update(extra)
    return jwt.encode(claims, secret, algorithm="HS256")


# ---------------------------------------------------------------------------
# Real local JWKS server (Clerk/Supabase asymmetric verification)
# ---------------------------------------------------------------------------


class _JwksHandler(BaseHTTPRequestHandler):
    document: bytes = b'{"keys": []}'
    hits: int = 0

    def do_GET(self) -> None:
        type(self).hits += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(type(self).document)))
        self.end_headers()
        self.wfile.write(type(self).document)

    def log_message(self, *args: object) -> None:  # silence stderr
        pass


def start_jwks_server(document: dict) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    handler = type("Handler", (_JwksHandler,), {"document": json.dumps(document).encode(), "hits": 0})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/.well-known/jwks.json"
    return server, thread, url


def generate_rsa_jwks(kid: str = "clerk-key-1") -> tuple[object, dict]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # JWKS publishes PUBLIC material only.
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return key, {"keys": [jwk]}


def generate_es256_jwks(kid: str = "sb-key-1") -> tuple[object, dict]:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "alg": "ES256", "use": "sig"})
    return key, {"keys": [jwk]}


def clerk_style_token(key: object, kid: str, *, role: str = "ADMIN", exp_offset: int = 3600) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": "user_2abc1337",          # Clerk user id
            "org_id": "org_workspacex",       # Clerk organisation -> workspace
            "ses": "sess_999",
            "role": role,                     # custom session-template claim
            "iss": "https://example.clerk.accounts.dev",
            "iat": now,
            "nbf": now,
            "exp": now + exp_offset,
        },
        key,
        algorithm="RS256",
        headers={"kid": kid},
    )


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


async def hs256_checks() -> None:
    auth = Authenticator(settings_with(security_jwt_secret=HS_SECRET))
    check("hs256: is_configured", auth.is_configured)

    ctx = await auth.authenticate(hs_token(role="operator"))
    check(
        "hs256: valid token -> AuthContext",
        isinstance(ctx, AuthContext)
        and ctx.user_id == "user_123"
        and ctx.workspace_id == "ws_42"
        and ctx.role is Role.OPERATOR
        and ctx.can_control
        and ctx.expires_at is not None,
        repr(ctx),
    )

    ctx_admin = await auth.authenticate(hs_token(role="ADMIN"))
    ctx_viewer = await auth.authenticate(hs_token(role="viewer"))
    check("roles: ADMIN can_control, VIEWER cannot", ctx_admin.can_control and not ctx_viewer.can_control)

    # Supabase legacy shape: sub + role="authenticated" (transport role!) +
    # app role in app_metadata.
    now = int(time.time())
    supabase_tok = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "aud": "authenticated",
            "role": "authenticated",
            "app_metadata": {"role": "OPERATOR", "workspace_id": "ws_77"},
            "iss": "https://abcdef.supabase.co/auth/v1",
            "exp": now + 600,
        },
        HS_SECRET,
        algorithm="HS256",
    )
    ctx_sb = await auth.authenticate(supabase_tok)
    check(
        "supabase legacy: transport role skipped, app_metadata used",
        ctx_sb.role is Role.OPERATOR and ctx_sb.workspace_id == "ws_77" and ctx_sb.user_id,
        repr(ctx_sb),
    )

    # Supabase token WITHOUT an app role -> deny-by-default VIEWER.
    plain_sb = jwt.encode(
        {"sub": str(uuid.uuid4()), "role": "authenticated", "workspace_id": "ws_x", "exp": now + 600},
        HS_SECRET,
        algorithm="HS256",
    )
    ctx_plain = await auth.authenticate(plain_sb)
    check("role fallback: unknown/absent app role -> VIEWER", ctx_plain.role is Role.VIEWER)

    # Expired.
    try:
        await auth.authenticate(hs_token(exp_offset=-120))
        check("hs256: expired rejected", False)
    except TokenExpiredError:
        check("hs256: expired rejected", True)

    # Expired within leeway is accepted.
    ctx_leeway = await auth.authenticate(hs_token(exp_offset=-5))
    check("hs256: exp within leeway accepted", ctx_leeway.role is Role.OPERATOR)

    # Wrong signature.
    try:
        await auth.authenticate(hs_token(secret="wrong-secret"))
        check("hs256: bad signature rejected", False)
    except TokenInvalidError:
        check("hs256: bad signature rejected", True)

    # Missing exp.
    try:
        await auth.authenticate(hs_token(drop_exp=True))
        check("hs256: missing exp rejected", False)
    except TokenClaimsError:
        check("hs256: missing exp rejected", True)

    # Missing user id.
    tok_no_user = jwt.encode({"exp": now + 60, "workspace_id": "w"}, HS_SECRET, algorithm="HS256")
    try:
        await auth.authenticate(tok_no_user)
        check("hs256: missing user_id rejected", False)
    except TokenClaimsError:
        check("hs256: missing user_id rejected", True)

    # `sub` fallback for user_id.
    tok_sub = jwt.encode({"sub": "user_sub", "exp": now + 60, "workspace_id": "w"}, HS_SECRET, algorithm="HS256")
    ctx_sub = await auth.authenticate(tok_sub)
    check("hs256: sub used as user_id fallback", ctx_sub.user_id == "user_sub")

    # Workspace requirement toggle.
    tok_no_ws = jwt.encode({"sub": "u", "exp": now + 60}, HS_SECRET, algorithm="HS256")
    try:
        await auth.authenticate(tok_no_ws)
        check("hs256: missing workspace rejected (required)", False)
    except TokenClaimsError:
        check("hs256: missing workspace rejected (required)", True)

    lenient = Authenticator(settings_with(security_jwt_secret=HS_SECRET, security_require_workspace_id=False))
    ctx_l = await lenient.authenticate(tok_no_ws)
    check("hs256: workspace optional when configured", ctx_l.workspace_id is None)

    # Issuer / audience enforcement.
    strict = Authenticator(
        settings_with(
            security_jwt_secret=HS_SECRET,
            security_jwt_issuer="https://auth.omniagent.dev",
            security_jwt_audience="omniagent-api",
        )
    )
    good = hs_token(issuer="https://auth.omniagent.dev", audience="omniagent-api")
    ctx_ok = await strict.authenticate(good)
    check("hs256: iss+aud enforced (accept)", ctx_ok.issuer == "https://auth.omniagent.dev")
    for label, tok in (
        ("wrong issuer", hs_token(issuer="https://evil.example", audience="omniagent-api")),
        ("wrong audience", hs_token(issuer="https://auth.omniagent.dev", audience="other")),
    ):
        try:
            await strict.authenticate(tok)
            check(f"hs256: {label} rejected", False)
        except TokenInvalidError:
            check(f"hs256: {label} rejected", True)

    # alg=none attack.
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"user_id": "admin", "role": "ADMIN", "exp": now + 600}).encode()
    ).rstrip(b"=")
    none_token = f"{header.decode()}.{payload.decode()}."
    try:
        await auth.authenticate(none_token)
        check("attack: alg=none rejected", False)
    except TokenInvalidError:
        check("attack: alg=none rejected", True)

    # Algorithm confusion: RS256-signed token presented to secret-only verifier.
    rsa_key, _ = generate_rsa_jwks()
    rs_tok = clerk_style_token(rsa_key, "k1")
    try:
        await auth.authenticate(rs_tok)
        check("attack: RS256 token vs secret-only config rejected", False)
    except TokenInvalidError:
        check("attack: RS256 token vs secret-only config rejected", True)

    # Garbage token.
    try:
        await auth.authenticate("not-a-jwt")
        check("hs256: garbage token rejected", False)
    except TokenInvalidError:
        check("hs256: garbage token rejected", True)

    # Unconfigured authenticator.
    unconfigured = Authenticator(settings_with())
    check("unconfigured: is_configured False", not unconfigured.is_configured)
    try:
        await unconfigured.authenticate(hs_token())
        check("unconfigured: authenticate raises", False)
    except AuthError:
        check("unconfigured: authenticate raises", True)


async def jwks_checks() -> None:
    rsa_key, rsa_doc = generate_rsa_jwks("clerk-key-1")
    ec_key, ec_doc = generate_es256_jwks("sb-key-1")
    combined = {"keys": [*rsa_doc["keys"], *ec_doc["keys"]]}
    server, thread, url = start_jwks_server(combined)
    handler = server.RequestHandlerClass
    try:
        auth = Authenticator(
            settings_with(
                security_jwks_url=url,
                security_jwt_issuer="https://example.clerk.accounts.dev",
            )
        )
        check("jwks: is_configured", auth.is_configured)

        tok = clerk_style_token(rsa_key, "clerk-key-1", role="ADMIN")
        ctx = await auth.authenticate(tok)
        check(
            "jwks/RS256: clerk-style token verified",
            ctx.user_id == "user_2abc1337"
            and ctx.workspace_id == "org_workspacex"
            and ctx.role is Role.ADMIN
            and ctx.can_control,
            repr(ctx),
        )

        # Second auth uses the cache (no extra HTTP hit).
        hits_after_first = handler.hits
        await auth.authenticate(clerk_style_token(rsa_key, "clerk-key-1", role="VIEWER"))
        check("jwks: cache hit (no refetch)", handler.hits == hits_after_first, f"hits={handler.hits}")

        # ES256 (Supabase asymmetric shape) through the same JWKS.
        now = int(time.time())
        es_tok = jwt.encode(
            {
                "sub": "11111111-2222-3333-4444-555555555555",
                "iss": "https://example.clerk.accounts.dev",
                "role": "authenticated",
                "app_metadata": {"role": "OPERATOR", "workspace_id": "ws_sb"},
                "exp": now + 600,
            },
            ec_key,
            algorithm="ES256",
            headers={"kid": "sb-key-1"},
        )
        ctx_es = await auth.authenticate(es_tok)
        check("jwks/ES256: verified with app_metadata role", ctx_es.role is Role.OPERATOR)

        # Unknown kid -> rejected (and no hammering: single extra fetch max).
        forged = jwt.encode(
            {"sub": "u", "exp": now + 60, "workspace_id": "w", "role": "ADMIN"},
            rsa_key,
            algorithm="RS256",
            headers={"kid": "unknown-kid"},
        )
        try:
            await auth.authenticate(forged)
            check("jwks: unknown kid rejected", False)
        except TokenInvalidError:
            check("jwks: unknown kid rejected", True)

        # HS256 token presented to JWKS-only verifier -> rejected (confusion).
        try:
            await auth.authenticate(hs_token())
            check("attack: HS256 token vs JWKS-only config rejected", False)
        except TokenInvalidError:
            check("attack: HS256 token vs JWKS-only config rejected", True)

        # Missing kid header on RS256.
        no_kid = jwt.encode({"sub": "u", "exp": now + 60, "workspace_id": "w"}, rsa_key, algorithm="RS256")
        try:
            await auth.authenticate(no_kid)
            check("jwks: RS256 without kid rejected", False)
        except TokenInvalidError:
            check("jwks: RS256 without kid rejected", True)

        await auth.aclose()

        # JWKS endpoint down -> JwksError (surfaces as AuthError).
        dead = Authenticator(settings_with(security_jwks_url="http://127.0.0.1:1/jwks.json",
                                           security_jwks_fetch_timeout_seconds=2.0))
        try:
            await dead.authenticate(clerk_style_token(rsa_key, "clerk-key-1"))
            check("jwks: unreachable endpoint -> AuthError", False)
        except JwksError:
            check("jwks: unreachable endpoint -> AuthError", True)
        await dead.aclose()

        # Issuer-derived JWKS URL (no explicit jwks url): serve at issuer path.
        derived_auth = Authenticator(
            settings_with(security_jwt_issuer=f"http://127.0.0.1:{server.server_address[1]}")
        )
        # Server answers any path with the same doc, so derivation must build
        # {issuer}/.well-known/jwks.json and succeed.
        ctx_derived = await derived_auth.authenticate(
            jwt.encode(
                {
                    "sub": "u9",
                    "exp": now + 600,
                    "workspace_id": "w9",
                    "role": "OPERATOR",
                    "iss": f"http://127.0.0.1:{server.server_address[1]}",
                },
                rsa_key,
                algorithm="RS256",
                headers={"kid": "clerk-key-1"},
            )
        )
        check("jwks: URL derived from issuer works", ctx_derived.user_id == "u9")
        await derived_auth.aclose()

        # Hardening: a misconfigured IdP publishing PRIVATE key material in
        # the JWKS must still yield a working public-key verifier.
        priv_jwk = json.loads(RSAAlgorithm.to_jwk(rsa_key))  # includes d/p/q!
        priv_jwk.update({"kid": "priv-leak", "alg": "RS256", "use": "sig"})
        priv_server, priv_thread, priv_url = start_jwks_server({"keys": [priv_jwk]})
        try:
            hardened = Authenticator(settings_with(security_jwks_url=priv_url))
            ctx_hard = await hardened.authenticate(
                clerk_style_token(rsa_key, "priv-leak", role="OPERATOR")
            )
            check("jwks: private material stripped -> verify still works", ctx_hard.can_control)
            await hardened.aclose()
        finally:
            priv_server.shutdown()
            priv_server.server_close()
            priv_thread.join(timeout=5)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def rate_limit_checks() -> None:
    # Deterministic token bucket via injected clock.
    bucket = TokenBucket(rate=60.0)  # capacity defaults to rate => 60 burst
    t0 = 1000.0
    allowed = sum(1 for i in range(75) if bucket.allow(now=t0 + i * 1e-9))
    check("bucket: 60/s allows exactly 60 burst", allowed == 60, f"allowed={allowed}")
    check("bucket: 61st within same instant denied", not bucket.allow(now=t0))

    moved = sum(1 for i in range(40) if bucket.allow(now=t0 + 0.5))  # +30 tokens refilled
    check("bucket: refill 30 tokens after 0.5s", moved == 30, f"moved={moved}")
    check("bucket: retry_after positive when empty", bucket.retry_after > 0.0)

    limiter = ConnectionRateLimiter(
        input_rate=60.0, message_rate=240.0, max_strikes=3
    )
    check("limiter: strike 1/3 not exceeded", not limiter.register_strike())
    check("limiter: strike 2/3 not exceeded", not limiter.register_strike())
    check("limiter: strike 3/3 exceeded", limiter.register_strike())

    settings = settings_with(
        security_rate_limit_input_per_second=60.0,
        security_rate_limit_messages_per_second=240.0,
        security_rate_limit_max_strikes=7,
    )
    from_settings = build_rate_limiter(settings)
    check(
        "limiter: built from settings",
        from_settings.input.rate == 60.0
        and from_settings.messages.rate == 240.0
        and from_settings.max_strikes == 7
        and from_settings.input.capacity == 60.0,
    )

    custom_burst = settings_with(
        security_rate_limit_input_per_second=60.0, security_rate_limit_input_burst=5.0
    )
    check("limiter: custom burst honoured", build_rate_limiter(custom_burst).input.capacity == 5.0)


def token_extraction_checks() -> None:
    async def _channel_never_used(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("extraction must not touch the socket channels")

    def make_ws(headers: list[tuple[bytes, bytes]] | None = None,
                query: bytes = b"",
                subprotocols: list[str] | None = None) -> WebSocket:
        scope = {
            "type": "websocket",
            "scheme": "ws",
            "path": "/ws/graph/g1",
            "raw_path": b"/ws/graph/g1",
            "headers": headers or [],
            "query_string": query,
            "subprotocols": subprotocols or [],
            "server": ("testserver", 80),
            "client": ("testclient", 50000),
        }
        return WebSocket(scope, _channel_never_used, _channel_never_used)

    tok, proto = extract_ws_token(make_ws(headers=[(b"authorization", b"Bearer abc.def.ghi")]))
    check("extract: Authorization Bearer header", (tok, proto) == ("abc.def.ghi", None))

    tok, proto = extract_ws_token(make_ws(query=b"token=q.tok&x=1"))
    check("extract: ?token= query", (tok, proto) == ("q.tok", None))

    tok, proto = extract_ws_token(make_ws(query=b"access_token=sup.tok"))
    check("extract: ?access_token= query", (tok, proto) == ("sup.tok", None))

    tok, proto = extract_ws_token(
        make_ws(subprotocols=["omniagent.v1", "bearer.proto.tok"])
    )
    check(
        "extract: bearer.<jwt> subprotocol + echo",
        (tok, proto) == ("proto.tok", "bearer.proto.tok"),
    )

    tok, proto = extract_ws_token(
        make_ws(headers=[(b"sec-websocket-protocol", b"omniagent.v1, bearer.hdr.tok")])
    )
    check(
        "extract: subprotocol via raw header fallback",
        tok == "hdr.tok" and proto == "bearer.hdr.tok",
        f"tok={tok!r} proto={proto!r}",
    )

    tok, proto = extract_ws_token(make_ws())
    check("extract: nothing -> (None, None)", (tok, proto) == (None, None))

    # Header wins over query.
    tok, _ = extract_ws_token(
        make_ws(headers=[(b"authorization", b"Bearer hdr-wins")], query=b"token=query-loses")
    )
    check("extract: header precedence over query", tok == "hdr-wins")


def custom_claim_path_checks() -> None:
    async def run() -> None:
        now = int(time.time())
        namespaced = jwt.encode(
            {
                "sub": "user_ns",
                "exp": now + 600,
                "https://omniagent.io/claims": {"role": "ADMIN", "workspace_id": "ws_ns"},
            },
            HS_SECRET,
            algorithm="HS256",
        )
        auth = Authenticator(
            settings_with(
                security_jwt_secret=HS_SECRET,
                security_role_claim="https://omniagent.io/claims.role",
                security_workspace_id_claim="https://omniagent.io/claims.workspace_id",
            )
        )
        ctx = await auth.authenticate(namespaced)
        check(
            "claims: namespaced dot-path extraction",
            ctx.role is Role.ADMIN and ctx.workspace_id == "ws_ns",
            repr(ctx),
        )

    asyncio.run(run())


def main() -> int:
    asyncio.run(hs256_checks())
    asyncio.run(jwks_checks())
    rate_limit_checks()
    token_extraction_checks()
    custom_claim_path_checks()

    print()
    if _failures:
        print(f"{len(_failures)} FAILURES: {_failures}")
        return 1
    print("ALL AUTH CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
