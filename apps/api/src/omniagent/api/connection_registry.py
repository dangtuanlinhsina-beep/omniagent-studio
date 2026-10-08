"""Per-graph connection bookkeeping: caps, takeover leases and broadcasts.

The WebSocket route owns exactly one socket, but several security decisions
are *graph-wide*:

* **Connection caps** — one client (or one compromised principal) must not be
  able to open hundreds of sockets against the same sandbox and exhaust the
  API's file descriptors / CDP bandwidth.
* **Takeover lease** — only one human may drive the browser at a time.  Two
  operators sending ``MOUSE_EVENT`` simultaneously corrupt each other's input
  and fight the agent.  The lease has a TTL and is renewed by activity, so a
  crashed tab cannot lock the graph forever (SPEC §5: "Takeover lease —
  auto-expire via server timer").
* **Broadcasts** — when the lease changes hands every other connection of the
  graph should learn about it (their UI must stop showing the crosshair).

Broadcasts are *queued*, never sent directly: the route serialises all socket
writes through a single writer task, so this module only pushes envelopes onto
each connection's outbound queue.  Queues are bounded and drop-oldest, which
means a stalled client can never block the coordinator (or another client).

The registry is process-local.  In a multi-replica deployment back it with
Redis (``SET graph:{id}:takeover … NX PX ttl`` + pub/sub for broadcasts) by
subclassing :class:`ConnectionRegistry`; the route only uses the methods here.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Final

from ..sandboxes.browser.models import ServerMessageType, server_envelope
from ..security.roles import Principal, Role

logger = logging.getLogger(__name__)

__all__ = [
    "AcquireResult",
    "ConnectionRegistry",
    "GraphStats",
    "RegisterResult",
    "TakeoverLease",
    "WsConnection",
    "get_connection_registry",
    "new_connection_id",
]


def new_connection_id() -> str:
    """Opaque, unguessable id for one WebSocket connection."""
    return secrets.token_urlsafe(12)


@dataclass(slots=True)
class WsConnection:
    """One live socket attached to a graph.

    ``out_queue`` is the *only* channel this class writes to; the route's
    writer task drains it.  ``principal`` may be replaced in place when the
    client refreshes its credential mid-connection (``AUTH`` message).
    """

    id: str
    graph_id: str
    principal: Principal
    out_queue: asyncio.Queue[dict[str, Any] | None]
    client_label: str = "unknown"
    started_at: float = field(default_factory=time.time)
    #: Last time an inbound message was accepted (idle-timeout watchdog).
    last_activity_at: float = field(default_factory=time.time)
    role_at_connect: Role = Role.VIEWER

    def __post_init__(self) -> None:
        self.role_at_connect = self.principal.role

    @property
    def subject(self) -> str:
        return self.principal.subject

    def touch(self, *, now: float | None = None) -> None:
        self.last_activity_at = time.time() if now is None else now

    def push(self, envelope: dict[str, Any] | None) -> bool:
        """Non-blocking enqueue; drops the oldest item when the queue is full."""
        while True:
            try:
                self.out_queue.put_nowait(envelope)
                return True
            except asyncio.QueueFull:
                with contextlib.suppress(asyncio.QueueEmpty):
                    try:
                        self.out_queue.get_nowait()
                    except Exception:  # pragma: no cover - defensive
                        return False


@dataclass(frozen=True, slots=True)
class RegisterResult:
    """Outcome of :meth:`ConnectionRegistry.register`."""

    ok: bool
    reason: str = ""
    graph_connections: int = 0
    principal_connections: int = 0


@dataclass(frozen=True, slots=True)
class TakeoverLease:
    """Exclusive human-control lease over one graph's browser."""

    graph_id: str
    connection_id: str
    subject: str
    role: Role
    acquired_at: float
    expires_at: float
    reason: str | None = None

    @property
    def ttl_s(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def is_expired(self, *, now: float | None = None) -> bool:
        moment = time.time() if now is None else now
        return moment >= self.expires_at

    def public_dict(self, *, include_subject: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "graph_id": self.graph_id,
            "connection_id": self.connection_id,
            "acquired_at": round(self.acquired_at, 3),
            "expires_at": round(self.expires_at, 3),
            "lease_ms": max(0, int((self.expires_at - self.acquired_at) * 1000)),
        }
        if include_subject:
            payload["holder"] = self.subject
            payload["role"] = self.role.value
        if self.reason:
            payload["reason"] = self.reason
        return payload


@dataclass(frozen=True, slots=True)
class AcquireResult:
    """Outcome of a takeover lease request."""

    ok: bool
    lease: TakeoverLease | None = None
    #: The lease that blocked us (already expired leases are never returned).
    conflict: TakeoverLease | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class GraphStats:
    """Point-in-time view of one graph's room (metrics / admin API)."""

    graph_id: str
    connections: int
    viewers: int
    operators: int
    takeover: TakeoverLease | None


class ConnectionRegistry:
    """Rooms of live connections, keyed by ``graph_id``."""

    def __init__(self) -> None:
        self._rooms: dict[str, dict[str, WsConnection]] = {}
        self._leases: dict[str, TakeoverLease] = {}
        self._by_subject: dict[str, set[str]] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def register(
        self,
        connection: WsConnection,
        *,
        max_per_graph: int,
        max_per_principal: int,
    ) -> RegisterResult:
        """Add a connection, enforcing both concurrency caps."""
        with self._lock:
            room = self._rooms.setdefault(connection.graph_id, {})
            subject_conns = self._by_subject.setdefault(connection.principal.subject, set())
            # Ignore caps for service accounts (agents, recorders).
            if not connection.principal.is_service:
                if len(room) >= max_per_graph:
                    return RegisterResult(
                        ok=False,
                        reason=(
                            f"graph {connection.graph_id!r} already has "
                            f"{len(room)} connection(s) (limit {max_per_graph})"
                        ),
                        graph_connections=len(room),
                        principal_connections=len(subject_conns),
                    )
                if len(subject_conns) >= max_per_principal:
                    return RegisterResult(
                        ok=False,
                        reason=(
                            f"{connection.principal.describe()} already holds "
                            f"{len(subject_conns)} connection(s) (limit {max_per_principal})"
                        ),
                        graph_connections=len(room),
                        principal_connections=len(subject_conns),
                    )
            room[connection.id] = connection
            subject_conns.add(connection.id)
            return RegisterResult(
                ok=True,
                graph_connections=len(room),
                principal_connections=len(subject_conns),
            )

    def unregister(self, graph_id: str, connection_id: str, *, subject: str | None = None) -> None:
        """Remove a connection and release any lease it held."""
        with self._lock:
            room = self._rooms.get(graph_id)
            if room is not None:
                connection = room.pop(connection_id, None)
                if connection is not None:
                    subject = subject or connection.principal.subject
                if not room:
                    self._rooms.pop(graph_id, None)
            if subject:
                held = self._by_subject.get(subject)
                if held is not None:
                    held.discard(connection_id)
                    if not held:
                        self._by_subject.pop(subject, None)
            self._release_lease_locked(graph_id, connection_id)

    def get(self, graph_id: str, connection_id: str) -> WsConnection | None:
        with self._lock:
            return self._rooms.get(graph_id, {}).get(connection_id)

    def connections(self, graph_id: str) -> tuple[WsConnection, ...]:
        with self._lock:
            return tuple(self._rooms.get(graph_id, {}).values())

    def stats(self, graph_id: str) -> GraphStats:
        with self._lock:
            room = self._rooms.get(graph_id, {})
            lease = self._leases.get(graph_id)
            if lease is not None and lease.is_expired():
                lease = None
            operators = sum(
                1 for c in room.values() if c.principal.has_role_at_least(Role.OPERATOR)
            )
            return GraphStats(
                graph_id=graph_id,
                connections=len(room),
                viewers=len(room) - operators,
                operators=operators,
                takeover=lease,
            )

    def total_connections(self) -> int:
        with self._lock:
            return sum(len(room) for room in self._rooms.values())

    # ------------------------------------------------------------------
    # Broadcasting
    # ------------------------------------------------------------------

    def broadcast(
        self,
        graph_id: str,
        envelope: dict[str, Any],
        *,
        exclude: str | None = None,
        min_role: Role | None = None,
    ) -> int:
        """Queue ``envelope`` for every connection of ``graph_id``.

        Returns the number of connections reached.  Never blocks: full queues
        drop their oldest envelope instead.
        """
        with self._lock:
            targets = [
                conn
                for conn in self._rooms.get(graph_id, {}).values()
                if conn.id != exclude
                and (min_role is None or conn.principal.has_role_at_least(min_role))
            ]
        delivered = 0
        for conn in targets:
            if conn.push(dict(envelope)):
                delivered += 1
        return delivered

    # ------------------------------------------------------------------
    # Takeover lease
    # ------------------------------------------------------------------

    def lease(self, graph_id: str) -> TakeoverLease | None:
        """Current live lease for ``graph_id`` (expired leases are dropped)."""
        with self._lock:
            lease = self._leases.get(graph_id)
            if lease is None:
                return None
            if lease.is_expired():
                del self._leases[graph_id]
                logger.info(
                    "[%s] takeover lease of %s expired", graph_id, lease.subject
                )
                return None
            return lease

    def acquire_takeover(
        self,
        connection: WsConnection,
        *,
        ttl_s: float,
        max_ttl_s: float,
        single_holder: bool = True,
        reason: str | None = None,
        force: bool = False,
    ) -> AcquireResult:
        """Grant (or renew) the exclusive human-control lease."""
        ttl = min(max(1.0, ttl_s), max(1.0, max_ttl_s))
        now = time.time()
        with self._lock:
            existing = self._leases.get(connection.graph_id)
            if existing is not None and existing.is_expired(now=now):
                logger.info(
                    "[%s] expiring stale takeover lease held by %s",
                    connection.graph_id,
                    existing.subject,
                )
                self._leases.pop(connection.graph_id, None)
                existing = None

            if (
                existing is not None
                and single_holder
                and existing.connection_id != connection.id
                and not (force and connection.principal.role is Role.ADMIN)
            ):
                return AcquireResult(
                    ok=False,
                    conflict=existing,
                    reason=(
                        "another operator holds the takeover lease "
                        f"({existing.subject}, {existing.ttl_s:.0f}s remaining)"
                    ),
                )

            lease = TakeoverLease(
                graph_id=connection.graph_id,
                connection_id=connection.id,
                subject=connection.principal.subject,
                role=connection.principal.role,
                acquired_at=now if existing is None else existing.acquired_at,
                expires_at=now + ttl,
                reason=reason or (existing.reason if existing else None),
            )
            self._leases[connection.graph_id] = lease
            return AcquireResult(ok=True, lease=lease)

    def renew_takeover(self, graph_id: str, connection_id: str, ttl_s: float) -> TakeoverLease | None:
        """Extend the lease of the current holder (activity-driven keepalive)."""
        now = time.time()
        with self._lock:
            lease = self._leases.get(graph_id)
            if lease is None or lease.connection_id != connection_id or lease.is_expired(now=now):
                return None
            renewed = TakeoverLease(
                graph_id=lease.graph_id,
                connection_id=lease.connection_id,
                subject=lease.subject,
                role=lease.role,
                acquired_at=lease.acquired_at,
                expires_at=max(lease.expires_at, now + max(1.0, ttl_s)),
                reason=lease.reason,
            )
            self._leases[graph_id] = renewed
            return renewed

    def release_takeover(self, graph_id: str, connection_id: str) -> TakeoverLease | None:
        """Drop the lease if (and only if) ``connection_id`` holds it."""
        with self._lock:
            lease = self._leases.get(graph_id)
            if lease is None or lease.connection_id != connection_id:
                return None
            del self._leases[graph_id]
            logger.info(
                "[%s] takeover lease released by %s", graph_id, lease.subject
            )
            return lease

    def force_release_takeover(self, graph_id: str, *, by: Principal) -> TakeoverLease | None:
        """Admin-only: kick the current holder (audited)."""
        with self._lock:
            lease = self._leases.pop(graph_id, None)
        if lease is not None:
            logger.warning(
                "[%s] takeover lease force-released by %s (holder was %s)",
                graph_id,
                by.describe(),
                lease.subject,
            )
        return lease

    def sweep_expired_leases(self) -> tuple[TakeoverLease, ...]:
        """Drop every expired lease; returns them for broadcast/audit."""
        now = time.time()
        expired: list[TakeoverLease] = []
        with self._lock:
            for graph_id, lease in list(self._leases.items()):
                if lease.is_expired(now=now):
                    del self._leases[graph_id]
                    expired.append(lease)
        for lease in expired:
            logger.info(
                "[%s] takeover lease of %s expired (sweep)", lease.graph_id, lease.subject
            )
        return tuple(expired)

    def _release_lease_locked(self, graph_id: str, connection_id: str) -> None:
        lease = self._leases.get(graph_id)
        if lease is not None and lease.connection_id == connection_id:
            del self._leases[graph_id]
            logger.info(
                "[%s] takeover lease dropped: holder %s disconnected",
                graph_id,
                lease.subject,
            )

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def clear(self) -> None:
        with self._lock:
            self._rooms.clear()
            self._leases.clear()
            self._by_subject.clear()


def takeover_state_envelope(
    graph_id: str,
    lease: TakeoverLease | None,
    *,
    reason: str = "updated",
    include_subject: bool = True,
) -> dict[str, Any]:
    """Build the ``TAKEOVER_STATE`` envelope broadcast to a graph's room."""
    payload: dict[str, Any] = {
        "graph_id": graph_id,
        "enabled": lease is not None,
        "reason": reason,
    }
    if lease is not None:
        payload.update(lease.public_dict(include_subject=include_subject))
    else:
        payload.update({"holder": None, "lease_expires_at": None})
    return server_envelope(ServerMessageType.TAKEOVER_STATE, **payload)


_registry: Final = ConnectionRegistry()


def get_connection_registry() -> ConnectionRegistry:
    """Return the process-wide connection registry."""
    return _registry
