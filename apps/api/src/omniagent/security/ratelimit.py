"""Rate limiting / throttling primitives (anti-DoS for the CDP input path).

Why this module exists
----------------------
Every ``MOUSE_EVENT`` / ``KEYBOARD_EVENT`` becomes one or two
``Input.dispatch*Event`` round-trips into the sandbox browser.  A single
malicious (or simply buggy — e.g. a ``mousemove`` listener with no
throttling) client can therefore push tens of thousands of CDP commands per
second, which:

* saturates the sandbox's CDP pipe and starves the screencast (frame stalls),
* burns CPU in the renderer, i.e. a cheap amplification DoS,
* can wedge the browser so the *agent* can no longer drive the page.

Three independent layers are applied, cheapest first:

1. **Client-side coalescing** (:class:`MouseMoveCoalescer`) — ``mouseMoved``
   is a *state*, not an event: only the newest position per frame interval is
   worth forwarding.  This alone removes ~90% of the traffic of a naive
   client.
2. **Per-connection token buckets** (:class:`ConnectionRateLimiter`) — one
   bucket per message category so a keyboard flood cannot hide behind a
   generous mouse budget, plus a global "any message" bucket.
3. **Per-graph shared bucket** (:class:`SharedLimiterRegistry`) — protects the
   *browser* (the real shared resource) when several operators/watchers are
   attached to the same ``graph_id``.

Buckets are monotonic-clock based, allocation-free and ``O(1)``; there is no
background task to reap them (the registry drops entries when the last
connection for a graph disconnects).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Final

__all__ = [
    "ConnectionRateLimiter",
    "MouseMoveCoalescer",
    "RateLimitDecision",
    "RateLimitPolicy",
    "SharedLimiterRegistry",
    "SlidingWindowCounter",
    "TokenBucket",
]


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """Bucket configuration for one category of traffic."""

    #: Human-readable limiter name, echoed back to the client on 429.
    name: str
    #: Burst allowance (bucket size).
    capacity: float
    #: Sustained refill rate, events per second.
    refill_per_second: float

    def __post_init__(self) -> None:
        if self.capacity <= 0 or self.refill_per_second <= 0:
            raise ValueError(
                f"rate limit policy {self.name!r} needs capacity>0 and "
                f"refill_per_second>0 (got {self.capacity}/{self.refill_per_second})"
            )


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Outcome of :meth:`ConnectionRateLimiter.check`."""

    allowed: bool
    limit: str
    #: Seconds the caller should wait before retrying (0.0 when allowed).
    retry_after_s: float = 0.0
    #: Remaining burst budget of the bucket that decided (informational).
    remaining: float = 0.0
    #: Total number of times this connection has been throttled.
    strikes: int = 0

    @property
    def retry_after_ms(self) -> int:
        return max(0, round(self.retry_after_s * 1000))


class TokenBucket:
    """Classic token bucket with lazy (on-demand) refill.

    ``consume()`` never blocks and never allocates, so it is safe to call from
    the hot receive loop.  Not thread-safe by itself — asyncio handlers are
    single-threaded, and :class:`SharedLimiterRegistry` adds a lock for the
    cross-connection case.
    """

    __slots__ = ("_capacity", "_refill", "_tokens", "_updated")

    def __init__(self, policy: RateLimitPolicy, *, now: float | None = None) -> None:
        self._capacity = float(policy.capacity)
        self._refill = float(policy.refill_per_second)
        self._tokens = float(policy.capacity)
        self._updated = time.monotonic() if now is None else now

    @property
    def capacity(self) -> float:
        return self._capacity

    @property
    def refill_per_second(self) -> float:
        return self._refill

    def _refill_to(self, now: float) -> None:
        elapsed = now - self._updated
        if elapsed <= 0:
            return
        self._updated = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill)

    def peek(self, now: float | None = None) -> float:
        """Current (fractional) token count without consuming anything."""
        moment = time.monotonic() if now is None else now
        elapsed = max(0.0, moment - self._updated)
        return min(self._capacity, self._tokens + elapsed * self._refill)

    def consume(self, amount: float = 1.0, *, now: float | None = None) -> tuple[bool, float]:
        """Try to consume ``amount`` tokens.

        Returns ``(allowed, retry_after_seconds)``.  On success the tokens are
        removed; on failure the bucket is left untouched.
        """
        moment = time.monotonic() if now is None else now
        self._refill_to(moment)
        if self._tokens >= amount:
            self._tokens -= amount
            return True, 0.0
        deficit = amount - self._tokens
        return False, deficit / self._refill


#: Default per-connection policies.  Values are generous enough for a real
#: human operator (mouse move streams top out around 60-125 Hz) while making
#: an input flood economically pointless.
DEFAULT_POLICIES: Final[dict[str, RateLimitPolicy]] = {
    # Any inbound frame at all — stops parse-floods before json.loads().
    "message": RateLimitPolicy("message_rate", capacity=200, refill_per_second=120),
    # MOUSE_EVENT / KEYBOARD_EVENT (post-coalescing).
    "input": RateLimitPolicy("input_rate", capacity=120, refill_per_second=90),
    # SET_TAKEOVER and other state-changing control messages.
    "control": RateLimitPolicy("control_rate", capacity=8, refill_per_second=1),
    # PING/PONG heartbeats.
    "ping": RateLimitPolicy("ping_rate", capacity=6, refill_per_second=0.5),
    # Mid-connection AUTH (token refresh) attempts — brute-force guard.
    "auth": RateLimitPolicy("auth_rate", capacity=5, refill_per_second=0.2),
}


class ConnectionRateLimiter:
    """Per-connection bundle of token buckets + strike accounting.

    A *strike* is recorded every time a bucket rejects a message.  The caller
    (WebSocket receive loop) closes the socket once ``max_strikes`` is
    reached, which turns "endless 429 chatter" into a single decisive
    disconnect.
    """

    __slots__ = ("_buckets", "_max_strikes", "_names", "_suppressed", "_strikes")

    def __init__(
        self,
        policies: dict[str, RateLimitPolicy] | None = None,
        *,
        max_strikes: int = 5,
    ) -> None:
        resolved = dict(DEFAULT_POLICIES)
        if policies:
            resolved.update(policies)
        self._names = tuple(resolved)
        self._buckets: dict[str, TokenBucket] = {
            name: TokenBucket(policy) for name, policy in resolved.items()
        }
        self._max_strikes = max(1, max_strikes)
        self._strikes = 0
        self._suppressed = 0

    @property
    def categories(self) -> tuple[str, ...]:
        return self._names

    @property
    def strikes(self) -> int:
        return self._strikes

    @property
    def suppressed_messages(self) -> int:
        """Messages dropped by any bucket on this connection (audit metric)."""
        return self._suppressed

    @property
    def must_disconnect(self) -> bool:
        return self._strikes >= self._max_strikes

    def check(self, *categories: str, amount: float = 1.0) -> RateLimitDecision:
        """Consume from every listed bucket; all-or-nothing semantics.

        ``check("message", "input")`` charges both the global message bucket
        and the input bucket.  If *any* bucket is empty the decision is a
        rejection — but tokens are only removed from the buckets that were
        evaluated before the failure, so a rejected call cannot slowly drain
        an unrelated bucket.
        """
        worst: RateLimitDecision | None = None
        charged: list[str] = []
        for category in categories:
            bucket = self._buckets.get(category)
            if bucket is None:  # unknown category -> fail closed
                return RateLimitDecision(
                    allowed=False,
                    limit=f"unknown_limit:{category}",
                    retry_after_s=1.0,
                    strikes=self._strikes,
                )
            allowed, retry_after = bucket.consume(amount)
            if not allowed:
                worst = RateLimitDecision(
                    allowed=False,
                    limit=category,
                    retry_after_s=retry_after,
                    remaining=bucket.peek(),
                    strikes=self._strikes,
                )
                break
            charged.append(category)

        if worst is None:
            first = self._buckets[categories[0]]
            return RateLimitDecision(
                allowed=True,
                limit=categories[0],
                remaining=first.peek(),
                strikes=self._strikes,
            )

        # Roll back the buckets we already charged so the client is not
        # double-punished for a single rejected message.
        for category in charged:
            bucket = self._buckets[category]
            bucket._tokens = min(bucket._capacity, bucket._tokens + amount)  # noqa: SLF001
        self._strikes += 1
        self._suppressed += 1
        return RateLimitDecision(
            allowed=False,
            limit=worst.limit,
            retry_after_s=worst.retry_after_s,
            remaining=worst.remaining,
            strikes=self._strikes,
        )

    def record_strike(self, limit: str) -> int:
        """Charge a violation that was not detected by a bucket.

        Used for policy breaches (oversized frame, permission probe) so they
        count towards :attr:`must_disconnect` exactly like a throttle hit.
        """
        self._strikes += 1
        self._suppressed += 1
        return self._strikes

    def snapshot(self) -> dict[str, float]:
        """Remaining budget per category (sent to the client on connect)."""
        return {name: round(bucket.peek(), 2) for name, bucket in self._buckets.items()}


class MouseMoveCoalescer:
    """Emit at most one ``mouseMoved`` per ``interval_s`` window.

    ``mousemove`` is pure state: intermediate positions are worthless to the
    remote browser.  Dropping them is lossless from the user's point of view
    (the local cursor is still drawn by the browser) and removes the single
    biggest amplifier in the protocol.

    Set ``interval_s <= 0`` to disable coalescing.
    """

    __slots__ = ("_interval", "_last_emit", "suppressed", "forwarded")

    def __init__(self, interval_s: float) -> None:
        self._interval = max(0.0, interval_s)
        self._last_emit = float("-inf")
        self.suppressed = 0
        self.forwarded = 0

    @property
    def interval_s(self) -> float:
        return self._interval

    def accept(self, *, now: float | None = None) -> bool:
        """Return ``True`` when this move should be forwarded to CDP."""
        if self._interval <= 0:
            self.forwarded += 1
            return True
        moment = time.monotonic() if now is None else now
        if moment - self._last_emit >= self._interval:
            self._last_emit = moment
            self.forwarded += 1
            return True
        self.suppressed += 1
        return False

    def force_next(self) -> None:
        """Reset the window (used after a click so the next move is instant)."""
        self._last_emit = float("-inf")


class SlidingWindowCounter:
    """Sliding-window hit counter used for handshake / login throttling.

    Keyed by an arbitrary string (IP address, e-mail, ``ip|email`` …) with an
    automatic sweep of stale keys so a flood of distinct keys cannot exhaust
    memory.
    """

    __slots__ = ("_events", "_limit", "_window", "_lock", "_max_keys", "_last_sweep")

    def __init__(
        self,
        *,
        limit: int,
        window_s: float,
        max_keys: int = 10_000,
    ) -> None:
        self._events: dict[str, deque[float]] = {}
        self._limit = max(1, limit)
        self._window = max(0.1, window_s)
        self._max_keys = max(64, max_keys)
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def window_s(self) -> float:
        return self._window

    def hit(self, key: str, *, now: float | None = None) -> tuple[bool, float, int]:
        """Record an attempt for ``key``.

        Returns ``(allowed, retry_after_seconds, hits_in_window)``.  The hit
        is recorded even when the limit is exceeded, so a client that keeps
        hammering never gets a shorter wait.
        """
        moment = time.monotonic() if now is None else now
        with self._lock:
            self._sweep(moment)
            events = self._events.get(key)
            if events is None:
                events = deque()
                self._events[key] = events
            cutoff = moment - self._window
            while events and events[0] <= cutoff:
                events.popleft()
            events.append(moment)
            hits = len(events)
            if hits <= self._limit:
                return True, 0.0, hits
            retry_after = max(0.0, events[0] + self._window - moment)
            return False, retry_after, hits

    def peek(self, key: str, *, now: float | None = None) -> int:
        moment = time.monotonic() if now is None else now
        cutoff = moment - self._window
        with self._lock:
            events = self._events.get(key)
            if not events:
                return 0
            return sum(1 for ts in events if ts > cutoff)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)

    def _sweep(self, now: float) -> None:
        """Drop empty keys; hard-cap the key count (oldest keys evicted)."""
        if now - self._last_sweep < 5.0 and len(self._events) < self._max_keys:
            return
        self._last_sweep = now
        cutoff = now - self._window
        empty = [key for key, events in self._events.items() if not events or events[-1] <= cutoff]
        for key in empty:
            del self._events[key]
        if len(self._events) > self._max_keys:
            # deque insertion order approximates age; evict the oldest keys.
            for key in list(self._events)[: len(self._events) - self._max_keys]:
                del self._events[key]


@dataclass(slots=True)
class _SharedEntry:
    limiter: ConnectionRateLimiter
    refcount: int = 0


class SharedLimiterRegistry:
    """Refcounted :class:`ConnectionRateLimiter` instances keyed by graph id.

    Gives the *sandbox* (not the client) a hard ceiling: N operators on the
    same graph share one input budget, so adding connections no longer
    multiplies CDP pressure.
    """

    __slots__ = ("_entries", "_lock", "_policies", "_max_strikes")

    def __init__(
        self,
        policies: dict[str, RateLimitPolicy] | None = None,
        *,
        max_strikes: int = 10**9,
    ) -> None:
        self._entries: dict[str, _SharedEntry] = {}
        self._lock = threading.Lock()
        self._policies = policies
        # Shared buckets report, they never disconnect: strikes are the
        # per-connection limiter's business.
        self._max_strikes = max_strikes

    def acquire(self, key: str) -> ConnectionRateLimiter:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = _SharedEntry(
                    limiter=ConnectionRateLimiter(self._policies, max_strikes=self._max_strikes)
                )
                self._entries[key] = entry
            entry.refcount += 1
            return entry.limiter

    def release(self, key: str) -> None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return
            entry.refcount -= 1
            if entry.refcount <= 0:
                del self._entries[key]

    def active_keys(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


#: Process-wide registry of per-graph input buckets.
_graph_input_limiters: Final = SharedLimiterRegistry(
    {
        # Aggregate ceiling for one sandbox browser: even 8 operators cannot
        # push more than ~120 CDP input commands/s (burst 160).
        "graph_input": RateLimitPolicy("graph_input_rate", capacity=160, refill_per_second=120),
    }
)


def get_graph_input_registry() -> SharedLimiterRegistry:
    """Return the process-wide per-graph input limiter registry."""
    return _graph_input_limiters


@dataclass(slots=True)
class ThrottleStats:
    """Counters exported in the closing log line / ``/metrics``."""

    forwarded: int = 0
    suppressed: int = 0
    rejected: dict[str, int] = field(default_factory=dict)

    def record_rejection(self, limit: str) -> None:
        self.rejected[limit] = self.rejected.get(limit, 0) + 1

    def as_dict(self) -> dict[str, object]:
        return {
            "forwarded": self.forwarded,
            "suppressed": self.suppressed,
            "rejected": dict(self.rejected),
        }
