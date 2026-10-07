#!/usr/bin/env python3
"""Token-authenticating CDP guard for the OmniAgent browser sandbox.

Why this exists
---------------
The Chrome DevTools Protocol has **no authentication of any kind**.  Anyone
who can open a TCP connection to ``:9222`` owns that browser: they can read
every cookie and credential in the profile, navigate to internal hosts, dump
the DOM, execute arbitrary JavaScript and exfiltrate whatever the agent (or a
human operator) logged into.  Publishing that port — even inside a "trusted"
cluster network — is how a single compromised pod becomes a session-theft
pivot into your users' accounts.

This guard is a tiny, dependency-free (stdlib ``asyncio``) reverse proxy that
sits in front of Chromium inside the sandbox container:

    ┌────────────────────────── sandbox container ─────────────────────────┐
    │  API ──▶ 0.0.0.0:9222 (cdp_guard)  ──▶ 127.0.0.1:9223 (chromium)     │
    │            │ Bearer token required          │ loopback only          │
    │            │ path allow-list                │ unreachable from       │
    │            │ Host/URL rewriting             │ outside the container  │
    │            │ origin check, client cap       │                        │
    └──────────────────────────────────────────────────────────────────────┘

Behaviour
---------
* Every new TCP connection must present ``Authorization: Bearer $CDP_GUARD_TOKEN``
  (constant-time comparison) **before** a single byte reaches Chromium.
  Without a configured token the guard refuses to start (fail closed) unless
  ``CDP_GUARD_ALLOW_ANONYMOUS=1`` is set explicitly for local development.
* Chromium is launched with ``--remote-debugging-address=127.0.0.1`` so the
  raw CDP port is never reachable from outside the container.
* DevTools HTTP endpoints are allow-listed.  ``/json/new``, ``/json/close``
  and ``/json/activate`` (target management) are denied unless
  ``CDP_GUARD_ALLOW_TARGET_MANAGEMENT=1``: a screencast/automation client does
  not need to spawn or kill tabs through the HTTP surface.
* ``webSocketDebuggerUrl`` is rewritten to point back at the guard, so
  Playwright's ``connect_over_cdp()`` transparently tunnels through it (the
  ``Host`` header is rewritten to the loopback form Chromium expects, because
  DevTools rejects non-IP/non-localhost ``Host`` values).
* WebSocket upgrades are piped byte-for-byte after authentication; the guard
  never parses CDP frames (no protocol-version coupling with Chromium).
* ``/healthz`` and ``/readyz`` are answered locally, without a token, but only
  from loopback by default (that is where the container HEALTHCHECK runs).
* Concurrency is capped (``CDP_GUARD_MAX_CLIENTS``) and every decision is
  logged as a single audit line — tokens are never logged, only a SHA-256
  prefix.

Environment
-----------
``CDP_PORT``                 public port of the guard (default 9222)
``CDP_INTERNAL_PORT``        Chromium's loopback port (default 9223)
``CDP_GUARD_TOKEN``          required bearer token (fail closed if unset)
``CDP_GUARD_ALLOW_ANONYMOUS``  ``1`` = dev escape hatch (logged loudly)
``CDP_GUARD_ADVERTISED_HOST``  host used when rewriting WS URLs (default: the
                             ``Host`` header the client sent)
``CDP_GUARD_ALLOWED_ORIGINS``  comma-separated Origin allow-list (default: any)
``CDP_GUARD_ALLOW_TARGET_MANAGEMENT`` ``1`` = allow /json/new|close|activate
``CDP_GUARD_MAX_CLIENTS``    concurrent proxied connections (default 8)
``CDP_GUARD_HEALTH_LOCALHOST_ONLY`` ``0`` = expose /healthz publicly
``CDP_GUARD_IDLE_TIMEOUT``   seconds of silence before a pipe is closed (0=off)
``CDP_GUARD_BIND``           bind address (default 0.0.0.0)
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Final

logging.basicConfig(
    level=os.environ.get("CDP_GUARD_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s cdp-guard %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("cdp-guard")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        logger.error("%s is not an integer; using %d", name, default)
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        logger.error("%s is not a number; using %s", name, default)
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    bind: str = field(default_factory=lambda: os.environ.get("CDP_GUARD_BIND", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("CDP_PORT", 9222))
    upstream_host: str = "127.0.0.1"
    upstream_port: int = field(default_factory=lambda: _env_int("CDP_INTERNAL_PORT", 9223))
    token: str | None = field(default_factory=lambda: os.environ.get("CDP_GUARD_TOKEN") or None)
    allow_anonymous: bool = field(default_factory=lambda: _env_bool("CDP_GUARD_ALLOW_ANONYMOUS"))
    advertised_host: str | None = field(
        default_factory=lambda: os.environ.get("CDP_GUARD_ADVERTISED_HOST") or None
    )
    allowed_origins: tuple[str, ...] = field(default_factory=lambda: _parse_origins())
    allow_target_management: bool = field(
        default_factory=lambda: _env_bool("CDP_GUARD_ALLOW_TARGET_MANAGEMENT")
    )
    max_clients: int = field(default_factory=lambda: _env_int("CDP_GUARD_MAX_CLIENTS", 8))
    health_localhost_only: bool = field(
        default_factory=lambda: _env_bool("CDP_GUARD_HEALTH_LOCALHOST_ONLY", True)
    )
    idle_timeout_s: float = field(default_factory=lambda: _env_float("CDP_GUARD_IDLE_TIMEOUT", 0.0))
    max_request_bytes: int = field(default_factory=lambda: _env_int("CDP_GUARD_MAX_HEADER_BYTES", 16384))
    max_json_bytes: int = field(default_factory=lambda: _env_int("CDP_GUARD_MAX_JSON_BYTES", 1048576))


def _parse_origins() -> tuple[str, ...]:
    raw = os.environ.get("CDP_GUARD_ALLOWED_ORIGINS", "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


#: DevTools HTTP endpoints a screencast/automation client legitimately needs.
_ALLOWED_PATHS: Final[frozenset[str]] = frozenset(
    {"/json", "/json/version", "/json/list", "/json/protocol"}
)
#: Target-management endpoints — denied unless explicitly enabled.
_TARGET_PATHS: Final[frozenset[str]] = frozenset(
    {"/json/new", "/json/close", "/json/activate"}
)
#: Guard-local endpoints (never proxied).
_LOCAL_PATHS: Final[frozenset[str]] = frozenset({"/healthz", "/readyz", "/metrics"})

_HEADER_TIMEOUT_S: Final = 10.0
_CONNECT_TIMEOUT_S: Final = 5.0


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass
class Metrics:
    started_at: float = field(default_factory=time.time)
    connections: int = 0
    auth_failures: int = 0
    denied_paths: int = 0
    rejected_origins: int = 0
    refused_capacity: int = 0
    proxied: int = 0
    websockets: int = 0
    active: int = 0
    bytes_upstream: int = 0
    bytes_downstream: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "uptime_s": round(time.time() - self.started_at, 1),
            "connections": self.connections,
            "auth_failures": self.auth_failures,
            "denied_paths": self.denied_paths,
            "rejected_origins": self.rejected_origins,
            "refused_capacity": self.refused_capacity,
            "proxied": self.proxied,
            "websockets": self.websockets,
            "active": self.active,
            "bytes_upstream": self.bytes_upstream,
            "bytes_downstream": self.bytes_downstream,
        }


METRICS = Metrics()


def token_fingerprint(token: str) -> str:
    """Non-reversible token id for audit lines (never the token itself)."""
    if not token:
        return "<empty>"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# HTTP parsing helpers (deliberately minimal — we are a tunnel, not a server)
# ---------------------------------------------------------------------------


@dataclass
class HttpRequest:
    method: str
    path: str
    version: str
    headers: dict[str, str]
    raw_head: bytes

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    @property
    def is_websocket(self) -> bool:
        return (self.header("upgrade") or "").lower() == "websocket"


def parse_request(head: bytes) -> HttpRequest | None:
    try:
        text = head.decode("iso-8859-1")
    except UnicodeDecodeError:  # pragma: no cover - iso-8859-1 never fails
        return None
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return None
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    method, path = parts[0].upper(), parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    return HttpRequest(method=method, path=path, version=version, headers=headers, raw_head=head)


def rebuild_request(request: HttpRequest, *, host: str) -> bytes:
    """Re-serialize the request with a rewritten ``Host`` header.

    Chromium's DevTools HTTP handler rejects any ``Host`` that is not
    ``localhost`` or an IP literal ("Host header is specified and is not an IP
    address or localhost"), so the guard always talks to it as loopback while
    preserving the client's original host for URL rewriting.
    """
    lines = [f"{request.method} {request.path} {request.version}"]
    written_host = False
    for key, value in request.headers.items():
        if key == "host":
            lines.append(f"Host: {host}")
            written_host = True
        elif key == "authorization":
            # The guard consumed the credential; do not forward it upstream.
            continue
        else:
            lines.append(f"{_canonical(key)}: {value}")
    if not written_host:
        lines.append(f"Host: {host}")
    lines.extend(["", ""])
    return "\r\n".join(lines).encode("iso-8859-1")


def _canonical(header: str) -> str:
    return "-".join(part.capitalize() for part in header.split("-"))


def _respond(status: int, reason: str, body: str = "", extra_headers: dict[str, str] | None = None) -> bytes:
    payload = body.encode("utf-8")
    headers = {
        "Content-Length": str(len(payload)),
        "Content-Type": "application/json; charset=UTF-8" if payload else "text/plain",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    if extra_headers:
        headers.update(extra_headers)
    head = [f"HTTP/1.1 {status} {reason}"]
    head.extend(f"{key}: {value}" for key, value in headers.items())
    head.extend(["", ""])
    return "\r\n".join(head).encode("iso-8859-1") + payload


def _json_response(status: int, reason: str, payload: dict[str, object]) -> bytes:
    return _respond(status, reason, json.dumps(payload))


def _parse_response_head(head: bytes) -> tuple[int, dict[str, str]]:
    text = head.decode("iso-8859-1")
    lines = text.split("\r\n")
    status = 0
    if lines and lines[0].startswith("HTTP/"):
        tokens = lines[0].split(" ")
        if len(tokens) > 1 and tokens[1].isdigit():
            status = int(tokens[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    return status, headers


def _rewrite_devtools_urls(body: bytes, config: Config, host_header: str) -> bytes:
    """Point ``webSocketDebuggerUrl`` back at the guard.

    Chromium advertises ``ws://127.0.0.1:<internal-port>/devtools/…``; a client
    outside the container cannot use that (and must not bypass the guard), so
    every occurrence of the internal endpoint is replaced with the address the
    client actually reached us on.
    """
    advertised = config.advertised_host or host_header
    if not advertised:
        return body
    replacements = (
        f"127.0.0.1:{config.upstream_port}".encode(),
        f"localhost:{config.upstream_port}".encode(),
    )
    target = advertised.encode()
    out = body
    for needle in replacements:
        if needle in out and needle != target:
            out = out.replace(needle, target)
    return out


# ---------------------------------------------------------------------------
# Connection handling
# ---------------------------------------------------------------------------


def _client_host(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if not peer:
        return "unknown"
    return f"{peer[0]}:{peer[1]}"


def _is_loopback(writer: asyncio.StreamWriter) -> bool:
    peer = writer.get_extra_info("peername")
    return bool(peer) and str(peer[0]) in {"127.0.0.1", "::1", "localhost"}


def _authorized(request: HttpRequest, config: Config) -> bool:
    if config.allow_anonymous:
        return True
    header = request.header("authorization") or ""
    provided = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not provided:
        provided = (request.header("x-cdp-token") or "").strip()
    if not provided or not config.token:
        return False
    # Constant-time comparison: the guard is an oracle otherwise.
    return _constant_time_equals(provided, config.token)


def _constant_time_equals(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _origin_allowed(request: HttpRequest, config: Config) -> bool:
    if not config.allowed_origins:
        return True
    origin = request.header("origin")
    if not origin:
        # Non-browser clients (Playwright) send no Origin; the bearer token is
        # the real gate for them.
        return True
    return origin.rstrip("/").lower() in {o.rstrip("/").lower() for o in config.allowed_origins}


def _path_allowed(request: HttpRequest, config: Config) -> bool:
    path = request.path.split("?", 1)[0]
    if path.startswith("/devtools/"):  # WebSocket endpoints
        return True
    if path in _ALLOWED_PATHS:
        return True
    if path in _TARGET_PATHS:
        return config.allow_target_management
    # Anything else on the DevTools HTTP surface is refused by default.
    return False


async def _pipe(
    source: asyncio.StreamReader,
    sink: asyncio.StreamWriter,
    *,
    counter: str,
    idle_timeout_s: float,
) -> None:
    """Copy bytes until EOF; updates a metric counter."""
    try:
        while True:
            if idle_timeout_s > 0:
                chunk = await asyncio.wait_for(source.read(65536), timeout=idle_timeout_s)
            else:
                chunk = await source.read(65536)
            if not chunk:
                break
            setattr(METRICS, counter, getattr(METRICS, counter) + len(chunk))
            sink.write(chunk)
            await sink.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        with contextlib.suppress(OSError):
            if sink.can_write_eof():
                sink.write_eof()


async def handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: Config
) -> None:
    peer = _client_host(writer)
    METRICS.connections += 1
    try:
        head = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), timeout=_HEADER_TIMEOUT_S
        )
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionResetError, OSError, ValueError):
        with contextlib.suppress(OSError):
            writer.close()
        return

    if len(head) > config.max_request_bytes:
        logger.warning("refusing oversized request head from %s (%d bytes)", peer, len(head))
        writer.write(_respond(431, "Request Header Fields Too Large"))
        await writer.drain()
        writer.close()
        return

    request = parse_request(head)
    if request is None:
        writer.write(_respond(400, "Bad Request"))
        await writer.drain()
        writer.close()
        return

    path = request.path.split("?", 1)[0]

    # --- guard-local endpoints -----------------------------------------
    if path in _LOCAL_PATHS:
        if config.health_localhost_only and not _is_loopback(writer):
            logger.warning("refusing %s from non-loopback client %s", path, peer)
            writer.write(_respond(404, "Not Found"))
        elif path == "/metrics":
            writer.write(_json_response(200, "OK", METRICS.as_dict()))
        else:
            writer.write(_json_response(200, "OK", {"status": "ok", "port": config.port}))
        await writer.drain()
        writer.close()
        return

    # --- authentication -------------------------------------------------
    if not _authorized(request, config):
        METRICS.auth_failures += 1
        logger.warning(
            "audit auth_failure peer=%s path=%s token_fp=%s",
            peer,
            path,
            token_fingerprint(request.header("authorization") or ""),
        )
        writer.write(
            _respond(
                401,
                "Unauthorized",
                extra_headers={"WWW-Authenticate": 'Bearer realm="cdp-guard"'},
            )
        )
        await writer.drain()
        writer.close()
        return

    # --- origin policy (WebSocket upgrades) -----------------------------
    if not _origin_allowed(request, config):
        METRICS.rejected_origins += 1
        logger.warning("audit origin_rejected peer=%s origin=%s", peer, request.header("origin"))
        writer.write(_respond(403, "Forbidden"))
        await writer.drain()
        writer.close()
        return

    # --- path allow-list ------------------------------------------------
    if not _path_allowed(request, config):
        METRICS.denied_paths += 1
        logger.warning("audit path_denied peer=%s path=%s method=%s", peer, path, request.method)
        writer.write(
            _json_response(
                403,
                "Forbidden",
                {"error": "endpoint not permitted by the sandbox CDP guard"},
            )
        )
        await writer.drain()
        writer.close()
        return

    # --- capacity -------------------------------------------------------
    if METRICS.active >= config.max_clients:
        METRICS.refused_capacity += 1
        logger.warning("audit capacity_refused peer=%s active=%d", peer, METRICS.active)
        writer.write(
            _json_response(
                503, "Service Unavailable", {"error": "too many concurrent CDP clients"}
            )
        )
        await writer.drain()
        writer.close()
        return

    # --- connect upstream ----------------------------------------------
    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(config.upstream_host, config.upstream_port),
            timeout=_CONNECT_TIMEOUT_S,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        logger.error("upstream CDP unavailable (%s:%d): %s", config.upstream_host, config.upstream_port, exc)
        writer.write(_json_response(502, "Bad Gateway", {"error": "browser not reachable"}))
        await writer.drain()
        writer.close()
        return

    METRICS.active += 1
    METRICS.proxied += 1
    host_header = request.header("host") or f"{config.advertised_host}:{config.port}"
    logger.info(
        "audit proxy peer=%s path=%s websocket=%s host=%s",
        peer,
        path,
        request.is_websocket,
        host_header,
    )
    try:
        upstream_writer.write(
            rebuild_request(request, host=f"{config.upstream_host}:{config.upstream_port}")
        )
        await upstream_writer.drain()

        if request.is_websocket:
            METRICS.websockets += 1
            # 101 response has no body: pipe both directions verbatim.
            await asyncio.gather(
                _pipe(reader, upstream_writer, counter="bytes_upstream", idle_timeout_s=config.idle_timeout_s),
                _pipe(upstream_reader, writer, counter="bytes_downstream", idle_timeout_s=config.idle_timeout_s),
            )
        else:
            await _proxy_http_response(
                upstream_reader, upstream_writer, reader, writer, config, host_header
            )
    finally:
        METRICS.active -= 1
        for stream in (writer, upstream_writer):
            with contextlib.suppress(OSError):
                stream.close()


async def _proxy_http_response(
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    config: Config,
    host_header: str,
) -> None:
    """Forward a DevTools HTTP response, rewriting URLs and Content-Length."""
    try:
        head = await asyncio.wait_for(upstream_reader.readuntil(b"\r\n\r\n"), timeout=_HEADER_TIMEOUT_S)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError, ValueError):
        client_writer.write(_json_response(502, "Bad Gateway", {"error": "bad upstream response"}))
        await client_writer.drain()
        return

    status, headers = _parse_response_head(head)
    content_type = headers.get("content-type", "")
    length = headers.get("content-length")
    chunked = headers.get("transfer-encoding", "").lower() == "chunked"

    if status == 101 or "json" not in content_type:
        # Not JSON (or a protocol switch): forward untouched, then pipe.
        client_writer.write(head)
        await client_writer.drain()
        await asyncio.gather(
            _pipe(client_reader, upstream_writer, counter="bytes_upstream", idle_timeout_s=config.idle_timeout_s),
            _pipe(upstream_reader, client_writer, counter="bytes_downstream", idle_timeout_s=config.idle_timeout_s),
        )
        return

    body = await _read_body(upstream_reader, length, chunked, config.max_json_bytes)
    if body is None:
        client_writer.write(_json_response(502, "Bad Gateway", {"error": "upstream body too large"}))
        await client_writer.drain()
        return

    body = _rewrite_devtools_urls(body, config, host_header)
    lines = head.decode("iso-8859-1").split("\r\n")
    out = [lines[0]]
    for line in lines[1:]:
        if not line:
            continue
        key = line.split(":", 1)[0].strip().lower()
        if key in {"content-length", "transfer-encoding"}:
            continue
        out.append(line)
    out.append(f"Content-Length: {len(body)}")
    out.extend(["", ""])
    client_writer.write("\r\n".join(out).encode("iso-8859-1") + body)
    await client_writer.drain()


async def _read_body(
    reader: asyncio.StreamReader, length: str | None, chunked: bool, max_bytes: int
) -> bytes | None:
    """Read a bounded response body (Content-Length or chunked)."""
    if chunked:
        buffer = bytearray()
        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                size = int(line.strip().split(b";")[0], 16)
            except ValueError:
                return None
            if size == 0:
                await reader.read(2)  # trailing CRLF
                break
            if len(buffer) + size > max_bytes:
                return None
            buffer.extend(await reader.readexactly(size))
            await reader.read(2)  # chunk CRLF
        return bytes(buffer)

    if length is None:
        return b""
    try:
        size = int(length)
    except ValueError:
        return None
    if size > max_bytes:
        return None
    return await reader.readexactly(size) if size else b""


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


async def _serve(config: Config) -> None:
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, config),
        host=config.bind,
        port=config.port,
        limit=config.max_request_bytes,
    )
    logger.info(
        "cdp-guard listening on %s:%d -> chromium %s:%d (auth=%s, max_clients=%d, "
        "target_management=%s, origins=%s)",
        config.bind,
        config.port,
        config.upstream_host,
        config.upstream_port,
        "anonymous!" if config.allow_anonymous else f"bearer:{token_fingerprint(config.token or '')}",
        config.max_clients,
        config.allow_target_management,
        ",".join(config.allowed_origins) or "<any>",
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    async with server:
        await stop.wait()
    logger.info("cdp-guard shutting down (metrics=%s)", METRICS.as_dict())


def main() -> int:
    config = Config()
    if not config.token and not config.allow_anonymous:
        logger.critical(
            "CDP_GUARD_TOKEN is not set. Refusing to expose an unauthenticated "
            "DevTools endpoint — set the token (the API sends it as "
            "OMNIAGENT_BROWSER_SANDBOX_CDP_AUTH_TOKEN) or, for local "
            "development only, CDP_GUARD_ALLOW_ANONYMOUS=1."
        )
        return 2
    if config.allow_anonymous:
        logger.warning(
            "CDP_GUARD_ALLOW_ANONYMOUS=1 — the DevTools endpoint is OPEN. "
            "Anyone able to reach port %d fully controls this browser.",
            config.port,
        )
    if config.port == config.upstream_port:
        logger.critical(
            "CDP_PORT and CDP_INTERNAL_PORT must differ (got %d)", config.port
        )
        return 2
    try:
        asyncio.run(_serve(config))
    except KeyboardInterrupt:  # pragma: no cover
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
