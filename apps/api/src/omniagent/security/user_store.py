"""Password hashing + user directory for the reference auth provider.

This module is deliberately dependency-free (stdlib ``hashlib`` only) so the
API image stays small, while implementing the parts that are easy to get
wrong:

* PBKDF2-HMAC-SHA256 with a per-password 128-bit salt and a configurable,
  OWASP-aligned iteration count (210 000 by default).
* Self-describing hash strings (``pbkdf2_sha256$<iters>$<salt>$<hash>``) so
  the work factor can be raised later and re-hashed lazily on next login
  (:meth:`InMemoryUserStore.needs_rehash`).
* Constant-time comparison (:func:`hmac.compare_digest`) — including for
  unknown users, where we still run one hash to avoid a user-enumeration
  timing oracle.
* Login throttling hooks (see :class:`LoginThrottle`).

**Production note.**  Swap :class:`InMemoryUserStore` for a database-backed
implementation (Postgres/Prisma) or, better, delegate to an identity provider
(Keycloak/Auth0/Cognito/Authentik) and keep only :mod:`omniagent.security.tokens`
in this codebase.  The REST routes depend on the :class:`UserStore` protocol,
not on this class, so that swap touches one factory function.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Final, Protocol

from ..sandboxes.browser.config import Settings, get_settings
from .ratelimit import SlidingWindowCounter
from .roles import Role, WILDCARD_GRAPH, coerce_role, normalize_graph_ids

logger = logging.getLogger(__name__)

__all__ = [
    "InMemoryUserStore",
    "LoginThrottle",
    "PasswordPolicyError",
    "UnknownUserError",
    "UserConflictError",
    "UserRecord",
    "UserStore",
    "get_user_store",
    "hash_password",
    "verify_password",
]

_HASH_SCHEME: Final = "pbkdf2_sha256"
_SALT_BYTES: Final = 16
_KEY_BYTES: Final = 32
#: Cost of the "unknown user" dummy hash — keeps login latency flat.
_DUMMY_HASH: Final = "pbkdf2_sha256$210000$AAAAAAAAAAAAAAAAAAAAAA$" + "A" * 44


class PasswordPolicyError(ValueError):
    """Raised when a password violates the configured policy."""


class UnknownUserError(LookupError):
    """No such user (mapped to a generic 401 by the caller)."""


class UserConflictError(ValueError):
    """E-mail already registered."""


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def hash_password(
    password: str,
    *,
    iterations: int = 210_000,
    salt: bytes | None = None,
) -> str:
    """Return a self-describing PBKDF2-HMAC-SHA256 hash string."""
    if not password:
        raise PasswordPolicyError("password must not be empty")
    if iterations < 100_000:
        raise PasswordPolicyError("PBKDF2 iterations must be >= 100000")
    raw_salt = salt or secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), raw_salt, iterations, dklen=_KEY_BYTES
    )
    import base64  # local import: keeps module import cost flat

    salt_b64 = base64.b64encode(raw_salt).decode("ascii")
    hash_b64 = base64.b64encode(digest).decode("ascii")
    return f"{_HASH_SCHEME}${iterations}${salt_b64}${hash_b64}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification of ``password`` against a stored hash.

    Returns ``False`` for malformed/unknown schemes instead of raising — a
    broken row must never become a 500 (nor an auth bypass).
    """
    if not stored:
        # Still spend comparable time so "no password set" is not detectable.
        verify_password(password or "x", _DUMMY_HASH)
        return False
    try:
        scheme, iterations_s, salt_b64, hash_b64 = stored.split("$")
        if scheme != _HASH_SCHEME:
            logger.error("unsupported password hash scheme %r", scheme)
            return False
        iterations = int(iterations_s)
        import base64

        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(hash_b64.encode("ascii"))
    except (ValueError, TypeError) as exc:
        logger.error("malformed password hash: %s", exc)
        return False

    candidate = hashlib.pbkdf2_hmac(
        "sha256", (password or "").encode("utf-8"), salt, iterations, dklen=len(expected)
    )
    return hmac.compare_digest(candidate, expected)


def check_password_policy(
    password: str, *, min_length: int, email: str | None = None
) -> None:
    """Enforce a minimum password policy; raise :class:`PasswordPolicyError`."""
    if len(password) < min_length:
        raise PasswordPolicyError(f"password must be at least {min_length} characters")
    if len(password) > 512:
        raise PasswordPolicyError("password must be at most 512 characters")
    if password.strip() != password:
        raise PasswordPolicyError("password must not start or end with whitespace")
    if email:
        lowered = password.lower()
        local_part = email.split("@")[0].strip().lower()
        # Both directions: "alice@corp" + "alice123!" and "alice@corp" +
        # "alice@corp" are equally guessable.
        # A >= 3 char local part avoids silly false positives ("li" in "…light").
        if lowered in email.lower() or (len(local_part) >= 3 and local_part in lowered):
            raise PasswordPolicyError("password must not contain the account e-mail")
    if password.lower() in {"password", "changeme", "12345678", "qwertyuiop"}:
        raise PasswordPolicyError("password is too common")


# ---------------------------------------------------------------------------
# User directory
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UserRecord:
    """One account in the directory."""

    id: str
    email: str
    password_hash: str
    role: Role = Role.VIEWER
    #: Graphs the account may access; ``(WILDCARD_GRAPH,)`` for admins/services.
    graph_ids: tuple[str, ...] = ()
    display_name: str | None = None
    created_at: float = field(default_factory=time.time)
    disabled: bool = False
    last_login_at: float | None = None

    def public_dict(self) -> dict[str, Any]:
        """Serialisable, secret-free view for API responses."""
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role.value,
            "graph_ids": list(self.graph_ids),
            "display_name": self.display_name,
            "disabled": self.disabled,
            "created_at": self.created_at,
            "last_login_at": self.last_login_at,
        }


class UserStore(Protocol):
    """Storage contract used by the auth routes."""

    async def get_by_email(self, email: str) -> UserRecord | None: ...

    async def get_by_id(self, user_id: str) -> UserRecord | None: ...

    async def create(
        self,
        *,
        email: str,
        password: str,
        role: Role = Role.VIEWER,
        graph_ids: tuple[str, ...] = (),
        display_name: str | None = None,
    ) -> UserRecord: ...

    async def touch_login(self, user: UserRecord) -> None: ...

    async def set_disabled(self, user_id: str, disabled: bool) -> None: ...

    async def count(self) -> int: ...


class InMemoryUserStore:
    """Thread-safe in-memory directory with optional JSON persistence.

    Suitable for development, demos and single-node deployments.  Every
    mutation is synchronous under a lock and (optionally) flushed to
    ``auth_user_store_path`` so restarts keep the accounts.
    """

    def __init__(
        self,
        *,
        iterations: int = 210_000,
        min_password_length: int = 10,
        persist_path: str | None = None,
    ) -> None:
        self._users: dict[str, UserRecord] = {}
        self._by_email: dict[str, str] = {}
        self._lock = threading.RLock()
        self._iterations = iterations
        self._min_password_length = min_password_length
        self._persist_path = persist_path
        if persist_path:
            self._load()

    # -- UserStore protocol --------------------------------------------

    async def get_by_email(self, email: str) -> UserRecord | None:
        key = _normalize_email(email)
        with self._lock:
            user_id = self._by_email.get(key)
            return self._users.get(user_id) if user_id else None

    async def get_by_id(self, user_id: str) -> UserRecord | None:
        with self._lock:
            return self._users.get(user_id)

    async def create(
        self,
        *,
        email: str,
        password: str,
        role: Role = Role.VIEWER,
        graph_ids: tuple[str, ...] = (),
        display_name: str | None = None,
    ) -> UserRecord:
        return self.create_sync(
            email=email,
            password=password,
            role=role,
            graph_ids=graph_ids,
            display_name=display_name,
        )

    def create_sync(
        self,
        *,
        email: str,
        password: str,
        role: Role = Role.VIEWER,
        graph_ids: tuple[str, ...] = (),
        display_name: str | None = None,
    ) -> UserRecord:
        """Synchronous variant of :meth:`create` (used at startup/seed time)."""
        key = _normalize_email(email)
        check_password_policy(
            password, min_length=self._min_password_length, email=key
        )
        with self._lock:
            if key in self._by_email:
                raise UserConflictError("an account with this e-mail already exists")
            record = UserRecord(
                id=secrets.token_urlsafe(12),
                email=key,
                password_hash=hash_password(password, iterations=self._iterations),
                role=coerce_role(role),
                graph_ids=normalize_graph_ids(graph_ids) or (WILDCARD_GRAPH,),
                display_name=display_name or key.split("@")[0],
            )
            self._users[record.id] = record
            self._by_email[key] = record.id
            self._flush_locked()
            return record

    async def touch_login(self, user: UserRecord) -> None:
        with self._lock:
            current = self._users.get(user.id)
            if current is None:
                return
            self._users[user.id] = replace(current, last_login_at=time.time())
            self._flush_locked()

    async def set_disabled(self, user_id: str, disabled: bool) -> None:
        with self._lock:
            current = self._users.get(user_id)
            if current is None:
                raise UnknownUserError(user_id)
            self._users[user_id] = replace(current, disabled=disabled)
            self._flush_locked()

    async def count(self) -> int:
        with self._lock:
            return len(self._users)

    # -- extras ---------------------------------------------------------

    def needs_rehash(self, user: UserRecord) -> bool:
        """``True`` when the stored hash uses an older work factor."""
        try:
            iterations = int(user.password_hash.split("$")[1])
        except (IndexError, ValueError):
            return True
        return iterations < self._iterations

    async def rehash(self, user: UserRecord, password: str) -> None:
        """Upgrade the work factor after a successful login."""
        with self._lock:
            current = self._users.get(user.id)
            if current is None:
                return
            self._users[user.id] = replace(
                current, password_hash=hash_password(password, iterations=self._iterations)
            )
            self._flush_locked()
            logger.info("rehashed password for user=%s", current.id)

    def _flush_locked(self) -> None:
        if not self._persist_path:
            return
        try:
            payload = [asdict(user) | {"role": user.role.value} for user in self._users.values()]
            tmp = f"{self._persist_path}.tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
            # 0600: the file contains password hashes.
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._persist_path)
        except OSError as exc:
            logger.error("failed to persist user store to %s: %s", self._persist_path, exc)

    def _load(self) -> None:
        assert self._persist_path is not None
        try:
            with open(self._persist_path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("ignoring unreadable user store %s: %s", self._persist_path, exc)
            return
        if not isinstance(payload, list):
            logger.error("user store %s must contain a list", self._persist_path)
            return
        with self._lock:
            for entry in payload:
                if not isinstance(entry, dict):
                    continue
                try:
                    record = UserRecord(
                        id=str(entry["id"]),
                        email=_normalize_email(str(entry["email"])),
                        password_hash=str(entry["password_hash"]),
                        role=coerce_role(entry.get("role", Role.VIEWER)),
                        graph_ids=normalize_graph_ids(entry.get("graph_ids")),
                        display_name=entry.get("display_name"),
                        created_at=float(entry.get("created_at") or time.time()),
                        disabled=bool(entry.get("disabled", False)),
                        last_login_at=entry.get("last_login_at"),
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    logger.error("skipping invalid user record: %s", exc)
                    continue
                self._users[record.id] = record
                self._by_email[record.email] = record.id
            logger.info("loaded %d user(s) from %s", len(self._users), self._persist_path)


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


# ---------------------------------------------------------------------------
# Login throttling
# ---------------------------------------------------------------------------


class LoginThrottle:
    """Dual-key (IP and e-mail) sliding window for credential stuffing.

    Both keys are charged on *every* attempt and both must allow it, so an
    attacker rotating e-mails from one host, or one e-mail from a botnet,
    hits a wall either way.
    """

    def __init__(self, *, limit: int = 5, window_s: float = 300.0) -> None:
        self._ip = SlidingWindowCounter(limit=limit * 4, window_s=window_s, max_keys=20_000)
        self._email = SlidingWindowCounter(limit=limit, window_s=window_s, max_keys=20_000)

    def check(self, ip: str, email: str) -> tuple[bool, float]:
        ip_ok, ip_wait, _ = self._ip.hit(f"login-ip:{ip}")
        mail_ok, mail_wait, _ = self._email.hit(f"login-mail:{_normalize_email(email)}")
        if ip_ok and mail_ok:
            return True, 0.0
        return False, max(ip_wait, mail_wait)


_login_throttle: LoginThrottle | None = None
_throttle_lock = threading.Lock()


def get_login_throttle(settings: Settings | None = None) -> LoginThrottle:
    """Process-wide :class:`LoginThrottle` configured from settings."""
    global _login_throttle
    with _throttle_lock:
        if _login_throttle is None:
            cfg = settings or get_settings()
            _login_throttle = LoginThrottle(
                limit=cfg.auth_login_attempts, window_s=cfg.auth_login_window_s
            )
        return _login_throttle


# ---------------------------------------------------------------------------
# Factory / bootstrap
# ---------------------------------------------------------------------------

_store: UserStore | None = None
_store_lock = threading.Lock()


def get_user_store(settings: Settings | None = None) -> UserStore:
    """Return the process-wide user store, seeding bootstrap users on demand.

    ``OMNIAGENT_AUTH_BOOTSTRAP_USERS`` accepts a comma-separated list of
    ``email:password:ROLE`` (optionally ``email:password:ROLE:graph1|graph2``)
    entries — handy for demos and CI, dangerous in production (the passwords
    live in the environment), so a warning is logged whenever it is used.
    """
    global _store
    cfg = settings or get_settings()
    with _store_lock:
        if _store is None:
            _store = InMemoryUserStore(
                iterations=cfg.auth_pbkdf2_iterations,
                min_password_length=cfg.auth_password_min_length,
                persist_path=cfg.auth_user_store_path,
            )
            _seed_bootstrap_users(_store, cfg)
        return _store


def reset_user_store() -> None:
    """Drop the cached store (tests)."""
    global _store
    with _store_lock:
        _store = None


def _seed_bootstrap_users(store: UserStore, settings: Settings) -> None:
    """Create the accounts listed in ``OMNIAGENT_AUTH_BOOTSTRAP_USERS``.

    Format: ``email:password:ROLE[:graph1|graph2]``, comma-separated.  Handy
    for demos/CI; the passwords live in the environment, so production should
    use a real identity provider instead.
    """
    raw = settings.auth_bootstrap_users
    if not raw:
        return
    logger.warning(
        "OMNIAGENT_AUTH_BOOTSTRAP_USERS is set — seeded accounts carry "
        "environment-provided passwords; remove it in production"
    )
    for chunk in raw.split(","):
        entry = chunk.strip()
        if not entry:
            continue
        parts = entry.split(":")
        if len(parts) < 3:
            logger.error(
                "ignoring malformed bootstrap user %r (want email:password:ROLE)", entry
            )
            continue
        email, password, role = parts[0], parts[1], parts[2]
        graphs = parts[3].split("|") if len(parts) > 3 else [WILDCARD_GRAPH]
        try:
            create_sync = getattr(store, "create_sync", None)
            if callable(create_sync):
                create_sync(
                    email=email,
                    password=password,
                    role=coerce_role(role),
                    graph_ids=normalize_graph_ids(graphs),
                )
            else:  # database-backed store: drive the coroutine on a private loop
                import asyncio

                asyncio.run(
                    store.create(  # type: ignore[call-arg]
                        email=email,
                        password=password,
                        role=coerce_role(role),
                        graph_ids=normalize_graph_ids(graphs),
                    )
                )
        except (PasswordPolicyError, UserConflictError) as exc:
            logger.error("bootstrap user %s not created: %s", email, exc)
