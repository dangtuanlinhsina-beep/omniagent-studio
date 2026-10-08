"""Structured security audit trail.

Every authorization decision, credential event and takeover transition is
emitted as a single JSON line on the ``omniagent.audit`` logger so it can be
shipped to Loki/CloudWatch/ELK independently of the application logs and
alerted on (``auth_failed`` bursts, ``lease_conflict`` storms, …).

Rules
-----
* **Never** log a token, password or e-mail in clear.  Tokens are reduced to
  :func:`~omniagent.security.tokens.token_fingerprint`; e-mails are hashed.
* High-frequency events (input dispatch) are *not* audited by default —
  set ``audit_input_events=True`` only when investigating an incident.
* Audit failures must never break a request: everything is wrapped in
  ``contextlib.suppress``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import time
from typing import Any

from ..security.tokens import token_fingerprint

logger = logging.getLogger("omniagent.audit")

__all__ = ["AuditEvent", "audit_event", "configure_audit_logging", "redact_email", "set_audit_config"]


class AuditEvent:
    """Stable event names (kept as constants so dashboards don't drift)."""

    WS_HANDSHAKE_REJECTED = "ws.handshake_rejected"
    WS_CONNECTED = "ws.connected"
    WS_DISCONNECTED = "ws.disconnected"
    WS_AUTH_FAILED = "ws.auth_failed"
    WS_AUTH_REFRESHED = "ws.auth_refreshed"
    WS_PERMISSION_DENIED = "ws.permission_denied"
    WS_RATE_LIMITED = "ws.rate_limited"
    WS_MESSAGE_TOO_LARGE = "ws.message_too_large"
    WS_IDLE_TIMEOUT = "ws.idle_timeout"
    WS_LIFETIME_EXCEEDED = "ws.lifetime_exceeded"
    WS_SESSION_EXPIRED = "ws.session_expired"
    TAKEOVER_ACQUIRED = "takeover.acquired"
    TAKEOVER_RELEASED = "takeover.released"
    TAKEOVER_RENEWED = "takeover.renewed"
    TAKEOVER_CONFLICT = "takeover.conflict"
    TAKEOVER_EXPIRED = "takeover.expired"
    TAKEOVER_FORCED = "takeover.forced"
    INPUT_DISPATCHED = "input.dispatched"
    INPUT_BLOCKED = "input.blocked"
    AUTH_LOGIN = "auth.login"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_REGISTER = "auth.register"
    AUTH_TICKET_ISSUED = "auth.ticket_issued"
    AUTH_LOGOUT = "auth.logout"
    CONFIG_INSECURE = "config.insecure"


_audit_input_events = False
_audit_ip_addresses = True


def set_audit_config(*, input_events: bool | None = None, ip_addresses: bool | None = None) -> None:
    """Tune verbosity at startup (see ``OMNIAGENT_AUDIT_*`` settings)."""
    global _audit_input_events, _audit_ip_addresses
    if input_events is not None:
        _audit_input_events = bool(input_events)
    if ip_addresses is not None:
        _audit_ip_addresses = bool(ip_addresses)


def configure_audit_logging(level: int = logging.INFO) -> None:
    """Attach a JSON-ish formatter to the audit logger if it has no handler."""
    if logger.handlers:
        return
    logger.setLevel(level)
    logger.propagate = False


def redact_email(email: str | None) -> str | None:
    """One-way hash of an e-mail so audit rows stay correlatable but private."""
    if not email:
        return None
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def audit_event(
    event: str,
    *,
    graph_id: str | None = None,
    subject: str | None = None,
    role: str | None = None,
    connection_id: str | None = None,
    ip: str | None = None,
    token: str | None = None,
    level: int = logging.INFO,
    **fields: Any,
) -> None:
    """Emit one audit record.

    Unknown/None fields are dropped so the JSON stays compact and greppable.
    """
    payload: dict[str, Any] = {
        "ts": round(time.time(), 3),
        "event": event,
    }
    if graph_id is not None:
        payload["graph_id"] = graph_id
    if subject is not None:
        payload["subject"] = subject
    if role is not None:
        payload["role"] = role
    if connection_id is not None:
        payload["connection_id"] = connection_id
    if ip is not None and _audit_ip_addresses:
        payload["ip"] = ip
    if token is not None:
        payload["token_fp"] = token_fingerprint(token)
    for key, value in fields.items():
        if value is not None:
            payload[key] = value

    if event == AuditEvent.INPUT_DISPATCHED and not _audit_input_events:
        return

    with contextlib.suppress(Exception):
        logger.log(level, json.dumps(payload, default=str, ensure_ascii=False, separators=(",", ":")))
