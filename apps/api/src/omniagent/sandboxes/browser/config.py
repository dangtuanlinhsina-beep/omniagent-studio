"""Central configuration for the browser-sandbox subsystem and its security.

All values are overridable through environment variables prefixed with
``OMNIAGENT_`` (e.g. ``OMNIAGENT_BROWSER_SANDBOX_CDP_URL``) or a local
``.env`` file.  List/dict values are parsed as JSON, e.g.::

    OMNIAGENT_API_WS_ALLOWED_ORIGINS='["https://studio.example.com"]'

Security-relevant defaults are chosen *fail-closed* wherever possible: auth on,
graph binding required, single-use WS tickets, input requires an explicit
takeover lease, inbound payloads capped, rate limits on every message class.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

if TYPE_CHECKING:  # pragma: no cover - typing only (avoids an import cycle)
    from ...security.ratelimit import RateLimitPolicy

#: String form of :class:`omniagent.security.roles.Role` (kept as a Literal so
#: configuration never depends on the security package).
RoleName = Literal["VIEWER", "OPERATOR", "ADMIN"]


class Settings(BaseSettings):
    """Runtime settings for sandbox discovery, screencast and WS security."""

    model_config = SettingsConfigDict(
        env_prefix="OMNIAGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Sandbox discovery
    # ------------------------------------------------------------------
    #: Static CDP endpoint shared by every graph (single-sandbox dev mode).
    browser_sandbox_cdp_url: str | None = None
    #: Per-graph endpoint template, e.g.
    #: ``http://browser-{graph_id}.sandbox.svc.cluster.local:9222`` or
    #: ``http://{graph_id}-browser:9222`` for docker-compose networks.
    browser_sandbox_cdp_url_template: str | None = None
    #: If no endpoint can be resolved, launch a local Playwright Chromium
    #: (development fallback — disable in production).
    browser_sandbox_launch_local_fallback: bool = True
    browser_sandbox_local_headless: bool = True

    # ------------------------------------------------------------------
    # Screencast (Page.startScreencast)
    # ------------------------------------------------------------------
    browser_screencast_format: Literal["jpeg", "png"] = "jpeg"
    #: JPEG quality 0-100. Ignored when format is "png".
    browser_screencast_quality: int = Field(70, ge=0, le=100)
    browser_screencast_max_width: int = Field(1280, ge=320, le=3840)
    browser_screencast_max_height: int = Field(720, ge=240, le=2160)
    browser_screencast_every_nth_frame: int = Field(1, ge=1, le=10)

    # ------------------------------------------------------------------
    # Streaming robustness / CDP
    # ------------------------------------------------------------------
    #: Bounded frame queue; oldest frames are dropped when the WebSocket
    #: consumer falls behind (low-latency policy for live video).
    browser_frame_queue_size: int = Field(32, ge=1, le=1024)
    #: Hard timeout (seconds) for every ``CDPSession.send`` call.
    browser_cdp_command_timeout: float = Field(10.0, gt=0.0)
    #: Playwright connect timeout in milliseconds.
    browser_connect_timeout_ms: float = Field(15_000.0, gt=0.0)
    browser_reconnect_base_delay: float = Field(0.5, gt=0.0)
    browser_reconnect_max_delay: float = Field(10.0, gt=0.0)
    #: ``None`` = retry forever (with capped exponential backoff + jitter).
    browser_max_reconnect_attempts: int | None = Field(None, ge=1)

    # ------------------------------------------------------------------
    # Viewport used when the API launches its own fallback browser
    # ------------------------------------------------------------------
    browser_viewport_width: int = Field(1280, ge=320, le=3840)
    browser_viewport_height: int = Field(720, ge=240, le=2160)

    # ------------------------------------------------------------------
    # WebSocket API security / behaviour
    # ------------------------------------------------------------------
    #: Master switch. ``False`` is development-only: every caller becomes an
    #: anonymous principal with :data:`auth_anonymous_role`.
    auth_enabled: bool = True
    #: Role handed to unauthenticated callers when ``auth_enabled=False``.
    auth_anonymous_role: RoleName = "VIEWER"

    #: Legacy shared static token (``?token=`` / ``Authorization: Bearer``).
    #: Kept for single-tenant/dev deployments and only honoured when
    #: :data:`auth_allow_legacy_static_token` is true.
    api_ws_auth_token: str | None = None
    #: Role granted to holders of the legacy static token.
    api_ws_static_token_role: RoleName = "OPERATOR"
    #: Accept the legacy static token *in addition* to JWTs. Off by default:
    #: a shared secret has no identity, no expiry and cannot be revoked.
    auth_allow_legacy_static_token: bool = False

    #: graph_id must match this pattern before being interpolated anywhere.
    api_graph_id_pattern: str = r"^[A-Za-z0-9_-]{1,64}$"
    #: When true, MOUSE_EVENT/KEYBOARD_EVENT are rejected until the client
    #: explicitly enables human takeover via SET_TAKEOVER.
    browser_input_requires_takeover: bool = True

    # ------------------------------------------------------------------
    # JWT (HS* shared secret or RS*/ES* key pair)
    # ------------------------------------------------------------------
    #: HMAC secret; must be >= 43 chars (256 bits). `openssl rand -base64 48`.
    jwt_secret: str | None = None
    #: PEM private key (RS256/ES256 issuers) — or a path when prefixed ``file:``.
    jwt_private_key: str | None = None
    #: PEM public key (RS256/ES256 verifiers) — or ``file:`` path.
    jwt_public_key: str | None = None
    #: Only algorithms in ``security.tokens.ALLOWED_ALGORITHMS`` are accepted.
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "omniagent-studio"
    jwt_audience: str = "omniagent-api"
    #: Accepted clock skew (seconds) for ``exp``/``nbf``.
    jwt_clock_skew_s: int = Field(5, ge=0, le=120)
    #: Hard cap on token length before parsing (DoS guard).
    jwt_max_token_chars: int = Field(8192, ge=256, le=65_536)
    #: Require the token's ``gph`` claim to cover the requested graph_id.
    #: Turning this off reintroduces IDOR — do not disable in production.
    jwt_require_graph_binding: bool = True

    #: Access-token lifetime. Short on purpose; refresh via ``/auth/refresh``.
    auth_access_token_ttl_s: int = Field(900, ge=30, le=86_400)
    auth_refresh_token_ttl_s: int = Field(43_200, ge=300, le=2_592_000)

    # ------------------------------------------------------------------
    # WebSocket handshake tickets (single-use, graph-bound)
    # ------------------------------------------------------------------
    jwt_ws_ticket_ttl_s: int = Field(60, ge=5, le=600)
    jwt_tickets_single_use: bool = True
    #: Bind a ticket to the IP+User-Agent that requested it. Only enable when
    #: the API sees real client IPs (``--proxy-headers`` + trusted proxy).
    jwt_ticket_bind_client: bool = False
    jwt_ticket_cache_size: int = Field(16_384, ge=256)
    jwt_revoked_cache_size: int = Field(16_384, ge=256)

    # ------------------------------------------------------------------
    # WebSocket transport hardening
    # ------------------------------------------------------------------
    #: Allowed ``Origin`` headers. Empty = no restriction (a warning is logged
    #: at startup). Cross-site WebSocket hijaging is otherwise possible for
    #: any cookie-based deployment.
    api_ws_allowed_origins: list[str] = Field(default_factory=list)
    #: Optional regex escape hatch for preview/staging hostnames.
    api_ws_allowed_origin_regex: str | None = None
    #: Subprotocols the server is willing to speak. The browser carries the
    #: token in ``Sec-WebSocket-Protocol`` because ``WebSocket`` cannot set
    #: custom headers.
    api_ws_subprotocols: list[str] = Field(
        default_factory=lambda: ["omniagent.v1", "omniagent.v1.jwt"]
    )
    #: Accept ``?token=`` as a credential source. Convenient, but query
    #: strings leak into proxy/access logs — disable in production.
    api_ws_token_in_query: bool = True
    #: Maximum size of one inbound text/binary frame (bytes).
    api_ws_max_message_bytes: int = Field(65_536, ge=1_024, le=4_194_304)
    #: Close a connection that sent nothing for this long (seconds).
    api_ws_idle_timeout_s: float = Field(120.0, gt=0.0)
    #: Absolute connection lifetime; the client must reconnect and re-auth
    #: (bounds the blast radius of a stolen ticket). ``0`` disables.
    api_ws_max_lifetime_s: float = Field(3_600.0, ge=0.0)
    #: Grace period to answer ``AUTH_REQUIRED`` with a fresh ticket before the
    #: socket is closed.
    api_ws_reauth_grace_s: float = Field(30.0, ge=0.0, le=300.0)
    #: Fail the HTTP 101 handshake (403) *before* ``accept()`` when the
    #: credentials are obviously bad — cheaper than accept-then-close and it
    #: never allocates a CDP session for an attacker.
    api_ws_reject_before_accept: bool = True
    #: Per-IP handshake attempts allowed within the window below.
    api_ws_handshake_rate_limit: int = Field(12, ge=1, le=10_000)
    api_ws_handshake_window_s: float = Field(60.0, gt=0.0)
    #: Concurrent sockets per graph / per principal (resource-exhaustion cap).
    api_ws_max_connections_per_graph: int = Field(8, ge=1, le=1_000)
    api_ws_max_connections_per_principal: int = Field(3, ge=1, le=100)
    #: Throttle strikes tolerated before the socket is closed with 4429.
    api_ws_rate_limit_strikes: int = Field(5, ge=1, le=1_000)

    # ------------------------------------------------------------------
    # Rate limiting (protects the CDP input path)
    # ------------------------------------------------------------------
    ratelimit_message_capacity: int = Field(200, ge=1)
    ratelimit_message_rate: float = Field(120.0, gt=0.0)
    ratelimit_input_capacity: int = Field(120, ge=1)
    ratelimit_input_rate: float = Field(90.0, gt=0.0)
    ratelimit_control_capacity: int = Field(8, ge=1)
    ratelimit_control_rate: float = Field(1.0, gt=0.0)
    ratelimit_ping_capacity: int = Field(6, ge=1)
    ratelimit_ping_rate: float = Field(0.5, gt=0.0)
    ratelimit_auth_capacity: int = Field(5, ge=1)
    ratelimit_auth_rate: float = Field(0.2, gt=0.0)
    #: Aggregate ceiling shared by every connection attached to one graph.
    ratelimit_graph_input_capacity: int = Field(160, ge=1)
    ratelimit_graph_input_rate: float = Field(120.0, gt=0.0)
    #: ``mouseMoved`` coalescing window; ``0`` disables. 16 ms ≈ one frame.
    ratelimit_mouse_move_interval_ms: int = Field(16, ge=0, le=1_000)

    # ------------------------------------------------------------------
    # Human-takeover lease (SPEC §5: "auto-expire via server timer")
    # ------------------------------------------------------------------
    #: Only one connection may drive the browser per graph at a time.
    takeover_single_holder_per_graph: bool = True
    takeover_lease_ttl_s: float = Field(120.0, gt=0.0, le=3_600.0)
    #: Hard ceiling for a requested lease (client may ask for less).
    takeover_max_lease_s: float = Field(900.0, gt=0.0, le=86_400.0)
    #: Broadcast takeover changes to the other connections of the graph.
    takeover_broadcast_state: bool = True

    # ------------------------------------------------------------------
    # Sandbox CDP transport authentication (see infra/sandbox-browser)
    # ------------------------------------------------------------------
    #: Shared secret for the in-container CDP guard. Playwright sends it as
    #: ``Authorization: Bearer`` on both the ``/json/version`` probe and the
    #: DevTools WebSocket upgrade.
    browser_sandbox_cdp_auth_token: str | None = None
    #: Preferred: per-sandbox token template, e.g. ``"{graph_id}-cdp-secret"``
    #: (or a Vault-injected value per pod). One leaked token then compromises
    #: a single session instead of the whole fleet.
    browser_sandbox_cdp_auth_token_template: str | None = None
    #: Refuse CDP endpoints that resolve to loopback (production guard against
    #: a template that silently points back at the API container).
    browser_sandbox_cdp_reject_loopback: bool = False
    #: Refuse to launch a local Chromium fallback when a sandbox was expected.
    #: ``True`` in production: a fallback browser shares the API's filesystem
    #: and network namespace with everything else.
    browser_sandbox_require_remote: bool = False

    # ------------------------------------------------------------------
    # Audit trail (see omniagent.security.audit)
    # ------------------------------------------------------------------
    #: Log every dispatched input event (very chatty; incident forensics only).
    audit_input_events: bool = False
    #: Include client IPs in audit records (disable for GDPR-strict setups).
    audit_ip_addresses: bool = True

    # ------------------------------------------------------------------
    # HTTP surface (auth routes, CORS, security headers)
    # ------------------------------------------------------------------
    #: Serve /docs + /openapi.json. Off by default: the schema is a gift to
    #: an attacker and contains every internal endpoint.
    api_docs_enabled: bool = False
    api_cors_allow_origins: list[str] = Field(default_factory=list)
    api_cors_allow_credentials: bool = True
    api_security_headers_enabled: bool = True
    auth_allow_self_registration: bool = False
    auth_default_registration_role: RoleName = "VIEWER"
    #: Graph scope granted to self-registered accounts (``|``-separated,
    #: ``"*"`` = every graph).  Production should assign graphs per tenant
    #: instead of wildcarding.
    auth_registration_graph_ids: str = "*"
    #: Login throttling: attempts per window, per IP and per e-mail.
    auth_login_attempts: int = Field(5, ge=1, le=1_000)
    auth_login_window_s: float = Field(300.0, gt=0.0)
    auth_password_min_length: int = Field(10, ge=8, le=128)
    auth_pbkdf2_iterations: int = Field(210_000, ge=100_000, le=2_000_000)
    #: Optional seed accounts: ``email:password:ROLE[,email:password:ROLE]``.
    #: Development/demo convenience — leave unset in production.
    auth_bootstrap_users: str | None = None
    #: Persist the demo user directory here (JSON). ``None`` = memory only.
    auth_user_store_path: str | None = None
    #: uvicorn sets this from ``--proxy-headers``; used for the real client IP.
    api_trust_proxy_headers: bool = False

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------

    def ws_rate_limit_policies(self) -> dict[str, "RateLimitPolicy"]:
        """Build the per-connection rate-limit policy table."""
        # Imported lazily: the security package imports this module.
        from ...security.ratelimit import RateLimitPolicy

        return {
            "message": RateLimitPolicy(
                "message_rate", self.ratelimit_message_capacity, self.ratelimit_message_rate
            ),
            "input": RateLimitPolicy(
                "input_rate", self.ratelimit_input_capacity, self.ratelimit_input_rate
            ),
            "control": RateLimitPolicy(
                "control_rate", self.ratelimit_control_capacity, self.ratelimit_control_rate
            ),
            "ping": RateLimitPolicy(
                "ping_rate", self.ratelimit_ping_capacity, self.ratelimit_ping_rate
            ),
            "auth": RateLimitPolicy(
                "auth_rate", self.ratelimit_auth_capacity, self.ratelimit_auth_rate
            ),
        }

    def graph_input_policies(self) -> dict[str, "RateLimitPolicy"]:
        """Build the per-graph (shared) rate-limit policy table."""
        from ...security.ratelimit import RateLimitPolicy

        return {
            "graph_input": RateLimitPolicy(
                "graph_input_rate",
                self.ratelimit_graph_input_capacity,
                self.ratelimit_graph_input_rate,
            )
        }

    @field_validator(
        "api_ws_allowed_origins", "api_ws_subprotocols", "api_cors_allow_origins"
    )
    @classmethod
    def _strip_string_lists(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if isinstance(item, str) and item.strip()]
        # Preserve order but drop duplicates.
        return list(dict.fromkeys(cleaned))

    @field_validator("jwt_algorithm")
    @classmethod
    def _upper_algorithm(cls, value: str) -> str:
        return value.strip().upper()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide cached settings instance."""
    return Settings()
