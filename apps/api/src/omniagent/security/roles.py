"""Role-based access control (RBAC) primitives.

OmniAgent Studio separates *who you are* (authentication, see
:mod:`omniagent.security.tokens`) from *what you may do* (authorization, this
module).  Three roles exist:

``VIEWER``
    Read-only.  May receive ``SCREEN_FRAME`` / lifecycle envelopes but can
    never influence the browser: ``SET_TAKEOVER``, ``MOUSE_EVENT`` and
    ``KEYBOARD_EVENT`` are rejected with ``PERMISSION_DENIED``.
``OPERATOR``
    Human-in-the-loop driver.  Everything a viewer can do plus takeover
    control and raw input dispatch (the CAPTCHA-solving path).
``ADMIN``
    Superset of ``OPERATOR``; additionally allowed to manage graphs, force
    release somebody else's takeover lease and read audit data.

Design rules
------------
* **Fail safe.**  An unknown/missing role string always collapses to
  :attr:`Role.VIEWER` (least privilege) — never to OPERATOR.
* **Graph scoped.**  A principal is only valid for the graphs listed in its
  ``gph`` claim; ``"*"`` means "any graph" and is reserved for service
  accounts and admins.  This closes the IDOR hole where any authenticated
  client could stream *any* ``graph_id``.
* **Deny by default.**  :meth:`Principal.can` returns ``False`` for anything
  not explicitly listed in :data:`ROLE_PERMISSIONS`.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

logger = logging.getLogger(__name__)

__all__ = [
    "WILDCARD_GRAPH",
    "Permission",
    "Principal",
    "Role",
    "coerce_role",
    "normalize_graph_ids",
    "permissions_for",
    "role_level",
]


class Role(StrEnum):
    """Account roles, ordered from least to most privileged."""

    VIEWER = "VIEWER"
    OPERATOR = "OPERATOR"
    ADMIN = "ADMIN"


class Permission(StrEnum):
    """Fine-grained capabilities mapped onto :class:`Role`."""

    #: Receive ``SCREEN_FRAME`` and stream lifecycle envelopes.
    SCREEN_VIEW = "screen:view"
    #: Send ``MOUSE_EVENT`` / ``KEYBOARD_EVENT`` (dispatched to CDP).
    INPUT_SEND = "input:send"
    #: Send ``SET_TAKEOVER`` (acquire/release the human-takeover lease).
    TAKEOVER_CONTROL = "takeover:control"
    #: Manage graph lifecycle (start/stop/delete) — HTTP surface.
    GRAPH_MANAGE = "graph:manage"
    #: Read audit/telemetry data — HTTP surface.
    AUDIT_READ = "audit:read"


#: Explicit role -> permission table.  Anything not listed is denied.
ROLE_PERMISSIONS: Final[dict[Role, frozenset[Permission]]] = {
    Role.VIEWER: frozenset({Permission.SCREEN_VIEW}),
    Role.OPERATOR: frozenset(
        {
            Permission.SCREEN_VIEW,
            Permission.INPUT_SEND,
            Permission.TAKEOVER_CONTROL,
        }
    ),
    Role.ADMIN: frozenset(
        {
            Permission.SCREEN_VIEW,
            Permission.INPUT_SEND,
            Permission.TAKEOVER_CONTROL,
            Permission.GRAPH_MANAGE,
            Permission.AUDIT_READ,
        }
    ),
}

#: Numeric rank used for "at least this role" comparisons.
_ROLE_RANK: Final[dict[Role, int]] = {
    Role.VIEWER: 0,
    Role.OPERATOR: 1,
    Role.ADMIN: 2,
}

#: Claim value meaning "this principal may access every graph".
WILDCARD_GRAPH: Final = "*"


def role_level(role: Role) -> int:
    """Return the hierarchy rank of ``role`` (VIEWER=0 … ADMIN=2)."""
    return _ROLE_RANK[role]


def permissions_for(role: Role) -> frozenset[Permission]:
    """Return the permission set granted to ``role``."""
    return ROLE_PERMISSIONS.get(role, frozenset())


def coerce_role(raw: object) -> Role:
    """Best-effort, fail-safe conversion of a claim value into a :class:`Role`.

    Accepts ``Role`` members, case-insensitive strings (``"operator"``,
    ``"Operator"``) and single-element sequences.  Anything unrecognised is
    downgraded to :attr:`Role.VIEWER` and logged — an authorization layer
    must never *escalate* on bad input.
    """
    if isinstance(raw, Role):
        return raw
    if isinstance(raw, (list, tuple)) and len(raw) == 1:
        raw = raw[0]
    if isinstance(raw, str):
        candidate = raw.strip().upper().replace("-", "_")
        try:
            return Role(candidate)
        except ValueError:
            logger.warning("unknown role claim %r; falling back to VIEWER", raw)
            return Role.VIEWER
    logger.warning("non-string role claim %r; falling back to VIEWER", raw)
    return Role.VIEWER


def normalize_graph_ids(raw: Iterable[object] | object | None) -> tuple[str, ...]:
    """Normalize the ``gph`` claim into a de-duplicated tuple of graph ids.

    ``None``/empty -> ``()`` (no graph access).  A bare string is accepted for
    convenience (``"graph-42"`` == ``["graph-42"]``).  Entries are stripped
    and empty ones dropped; ``"*"`` short-circuits to wildcard-only.
    """
    if raw is None:
        return ()
    if isinstance(raw, str):
        items: Iterable[object] = [raw]
    elif isinstance(raw, Iterable):
        items = raw
    else:
        items = [raw]

    result: list[str] = []
    for item in items:
        if not isinstance(item, str):
            continue
        value = item.strip()
        if not value:
            continue
        if value == WILDCARD_GRAPH:
            return (WILDCARD_GRAPH,)
        if value not in result:
            result.append(value)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller.

    Immutable and cheap to copy; one instance is attached to every WebSocket
    connection (see :class:`omniagent.api.routes_stream._ConnectionState`) and
    to every authenticated HTTP request.
    """

    #: Stable user/service id (JWT ``sub``).
    subject: str
    #: Effective role after fail-safe coercion.
    role: Role
    #: Graph ids this principal may access (``("*",)`` = all graphs).
    graph_ids: tuple[str, ...] = ()
    #: Auth session id — shared by all tokens of one login (revocation unit).
    session_id: str | None = None
    #: JWT id (``jti``) — revocation/single-use unit for one token.
    token_id: str | None = None
    #: ``access`` | ``ws-ticket`` | ``refresh``.
    token_type: str = "access"
    display_name: str | None = None
    #: Unix seconds; ``None`` for tokens without ``exp`` (discouraged).
    expires_at: float | None = None
    #: Expiry of the *login session* behind this token.  A single-use
    #: ``ws-ticket`` lives ~60 s but must not tear the connection down with
    #: it — the ticket carries the session's ``exp`` in its ``sexp`` claim.
    session_expires_at: float | None = None
    issued_at: float | None = None
    #: Machine-to-machine principal (no interactive user behind it).
    is_service: bool = False
    #: Free-form OAuth-style scopes, kept for forward compatibility.
    scopes: frozenset[str] = frozenset()

    # ------------------------------------------------------------------
    # Authorization helpers
    # ------------------------------------------------------------------

    def can(self, permission: Permission | str) -> bool:
        """Return ``True`` when the principal's role grants ``permission``."""
        try:
            perm = Permission(permission)
        except ValueError:
            logger.warning("unknown permission %r requested; denying", permission)
            return False
        return perm in permissions_for(self.role)

    def has_role_at_least(self, minimum: Role) -> bool:
        """Return ``True`` when this principal's rank >= ``minimum``."""
        return role_level(self.role) >= role_level(minimum)

    def can_access_graph(self, graph_id: str) -> bool:
        """Return ``True`` when this principal is scoped to ``graph_id``.

        Wildcard principals (service accounts / admins) match every graph.
        An empty ``graph_ids`` tuple means "unbound token" and is only ever
        produced when server-side graph binding is disabled — the token
        service upgrades those to a wildcard so this method stays total.
        """
        if not graph_id:
            return False
        if WILDCARD_GRAPH in self.graph_ids:
            return True
        return graph_id in self.graph_ids

    @property
    def effective_expires_at(self) -> float | None:
        """When this *connection* must be re-authenticated.

        For a short-lived ``ws-ticket`` that is the underlying session's
        expiry (``sexp``), otherwise the token's own ``exp``.
        """
        candidates = [value for value in (self.session_expires_at, self.expires_at) if value]
        return max(candidates) if candidates else None

    @property
    def permissions(self) -> frozenset[Permission]:
        """Permission set of the effective role (echoed to clients)."""
        return permissions_for(self.role)

    def describe(self) -> str:
        """Stable, secret-free description used in log lines and audit rows."""
        return f"sub={self.subject or '<anon>'}:role={self.role.value}"


#: Subject recorded for unauthenticated (development) connections.
ANONYMOUS_SUBJECT: Final = "<anonymous>"


def build_anonymous_principal(role: Role = Role.VIEWER) -> Principal:
    """Build the principal used when authentication is *explicitly* disabled.

    Only reachable with ``OMNIAGENT_AUTH_ENABLED=false`` (local development).
    The role is configurable so a developer can exercise the OPERATOR path,
    but it deliberately defaults to :attr:`Role.VIEWER`: an accidental
    production deploy with auth off must not hand out input control.
    """
    return Principal(
        subject=ANONYMOUS_SUBJECT,
        role=coerce_role(role),
        graph_ids=(WILDCARD_GRAPH,),
        token_type="none",
    )
