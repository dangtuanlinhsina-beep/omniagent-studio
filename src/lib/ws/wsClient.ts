'use client';

/**
 * OmniAgent WebSocket client.
 *
 * Security properties (mirrors `apps/api/src/omniagent/security/ws_auth.py`):
 *
 * - The credential is a **single-use, 60-second, graph-bound JWT ticket**
 *   fetched from the Next.js BFF (`/api/auth/ticket`) — never the user's
 *   access token, and never stored in `localStorage`/`sessionStorage`.
 * - It travels in `Sec-WebSocket-Protocol` (`["omniagent.v1", ticket]`)
 *   because browsers cannot set headers on a WS upgrade. That keeps it out of
 *   URLs, access logs, `Referer` and browser history.
 * - On `AUTH_REQUIRED` (or before the credential expires) a *fresh* ticket is
 *   fetched and sent as an in-band `AUTH` message, so long sessions survive
 *   without reconnecting.
 * - Client-side throttling (token bucket + `mousemove` coalescing) mirrors the
 *   server's limits, so a busy pointer never burns the server-side budget and
 *   never trips the 4429 disconnect.
 * - Close codes 4403/4413 are terminal (re-authenticating cannot help);
 *   4401/4408/4429/1006 trigger a bounded reconnect with jittered backoff.
 */

import {
  AppErrorCode,
  ClientMessageType,
  ServerMessageType,
  TERMINAL_CLOSE_CODES,
  WsCloseCode,
  type ClientEnvelope,
  type KeyboardPayload,
  type MousePayload,
  type Permission,
  type Role,
  type ServerEnvelope,
  type SessionReady,
  type TakeoverState,
} from './protocol';

/* -------------------------------------------------------------------------- */
/* Types                                                                       */
/* -------------------------------------------------------------------------- */

export type WsTicket = {
  ticket: string;
  expires_in: number;
  graph_id: string;
  subprotocols?: string[];
};

export type SocketPhase =
  | 'idle'
  | 'fetching-ticket'
  | 'connecting'
  | 'open'
  | 'reconnecting'
  | 'closed'
  | 'failed';

export type SocketSnapshot = {
  phase: SocketPhase;
  role: Role | null;
  permissions: Permission[];
  subject: string | null;
  connectionId: string | null;
  takeoverActive: boolean;
  takeoverHolder: string | null;
  takeoverConnectionId: string | null;
  lastError: string | null;
  lastErrorCode: number | null;
  attempt: number;
  frames: number;
  throttled: number;
  suppressedMoves: number;
  rttMs: number | null;
};

export type OmniAgentSocketOptions = {
  graphId: string;
  /** Fetch a fresh single-use ticket (BFF call). Called on every (re)connect. */
  getTicket: (graphId: string) => Promise<WsTicket>;
  /** Rotate the BFF access/refresh cookie pair before in-band re-auth. */
  refreshSession?: () => Promise<boolean>;
  /** WS base URL; defaults to the current origin (reverse-proxy setup). */
  baseUrl?: string;
  /** URL builder; defaults to `/ws/graph/{graphId}`. */
  buildUrl?: (baseUrl: string, graphId: string) => string;
  /** Application heartbeat (server closes idle sockets after 120 s). */
  heartbeatMs?: number;
  /** Client-side `mousemove` coalescing window (server default: 16 ms). */
  mouseMoveIntervalMs?: number;
  /** Client-side sustained input rate (kept below the server's 90/s). */
  inputPerSecond?: number;
  inputBurst?: number;
  maxReconnectAttempts?: number;
  reconnectBaseMs?: number;
  reconnectMaxMs?: number;
  onSnapshot?: (snapshot: SocketSnapshot) => void;
  /** Every parsed server envelope (including the typed callbacks below). */
  onEnvelope?: (envelope: ServerEnvelope) => void;
  onFrame?: (frame: Extract<ServerEnvelope, { type: typeof ServerMessageType.SCREEN_FRAME }>) => void;
  onSessionReady?: (session: SessionReady) => void;
  onTakeoverState?: (state: TakeoverState) => void;
  onError?: (code: number, message: string) => void;
  onRateLimited?: (limit: string, retryAfterMs: number) => void;
  onClosed?: (code: number, reason: string) => void;
};

/* -------------------------------------------------------------------------- */
/* Token bucket (client-side mirror of the server limiter)                     */
/* -------------------------------------------------------------------------- */

class TokenBucket {
  private tokens: number;
  private updated: number;

  constructor(
    private readonly capacity: number,
    private readonly refillPerSecond: number,
  ) {
    this.tokens = capacity;
    this.updated = performance.now();
  }

  consume(amount = 1): boolean {
    const now = performance.now();
    const elapsed = Math.max(0, (now - this.updated) / 1000);
    this.updated = now;
    this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refillPerSecond);
    if (this.tokens >= amount) {
      this.tokens -= amount;
      return true;
    }
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Socket                                                                      */
/* -------------------------------------------------------------------------- */

export class OmniAgentSocket {
  private readonly options: Required<
    Pick<
      OmniAgentSocketOptions,
      | 'graphId'
      | 'heartbeatMs'
      | 'mouseMoveIntervalMs'
      | 'inputPerSecond'
      | 'inputBurst'
      | 'maxReconnectAttempts'
      | 'reconnectBaseMs'
      | 'reconnectMaxMs'
    >
  > &
    OmniAgentSocketOptions;

  private socket: WebSocket | null = null;
  private inputBucket: TokenBucket;
  private lastMoveAt = 0;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private pendingPingTs: number | null = null;
  private closedByUser = false;
  private refreshing = false;

  private snapshot: SocketSnapshot = {
    phase: 'idle',
    role: null,
    permissions: [],
    subject: null,
    connectionId: null,
    takeoverActive: false,
    takeoverHolder: null,
    takeoverConnectionId: null,
    lastError: null,
    lastErrorCode: null,
    attempt: 0,
    frames: 0,
    throttled: 0,
    suppressedMoves: 0,
    rttMs: null,
  };

  constructor(options: OmniAgentSocketOptions) {
    this.options = {
      heartbeatMs: 20_000,
      mouseMoveIntervalMs: 16,
      inputPerSecond: 60,
      inputBurst: 90,
      maxReconnectAttempts: 8,
      reconnectBaseMs: 500,
      reconnectMaxMs: 15_000,
      ...options,
    };
    this.inputBucket = new TokenBucket(this.options.inputBurst, this.options.inputPerSecond);
  }

  /* ---------------------------------------------------------------- public */

  get state(): SocketSnapshot {
    return { ...this.snapshot };
  }

  get isOpen(): boolean {
    return this.socket?.readyState === WebSocket.OPEN;
  }

  get role(): Role | null {
    return this.snapshot.role;
  }

  can(permission: Permission): boolean {
    return this.snapshot.permissions.includes(permission);
  }

  connect(): void {
    this.closedByUser = false;
    void this.open();
  }

  close(code: number = WsCloseCode.NORMAL, reason = 'client closing'): void {
    this.closedByUser = true;
    this.clearTimers();
    const socket = this.socket;
    this.socket = null;
    if (socket && socket.readyState <= WebSocket.OPEN) {
      try {
        socket.close(code, reason.slice(0, 120));
      } catch {
        /* the browser rejects some codes/reasons — ignore */
      }
    }
    this.update({ phase: 'closed' });
  }

  /** Enable/disable the human-takeover lease (OPERATOR only). */
  setTakeover(enabled: boolean, leaseMs?: number, reason?: string): boolean {
    return this.send({
      type: ClientMessageType.SET_TAKEOVER,
      payload: { enabled, leaseMs, reason },
    });
  }

  sendMouse(payload: MousePayload): boolean {
    if (payload.action === 'move') {
      const now = performance.now();
      if (now - this.lastMoveAt < this.options.mouseMoveIntervalMs) {
        this.update({ suppressedMoves: this.snapshot.suppressedMoves + 1 });
        return false;
      }
      this.lastMoveAt = now;
    }
    return this.sendInput({ type: ClientMessageType.MOUSE_EVENT, payload });
  }

  sendKeyboard(payload: KeyboardPayload): boolean {
    return this.sendInput({ type: ClientMessageType.KEYBOARD_EVENT, payload });
  }

  ping(): boolean {
    this.pendingPingTs = Date.now();
    return this.send({ type: ClientMessageType.PING, payload: { ts: this.pendingPingTs } });
  }

  /** Send an arbitrary envelope (subject to the client-side message budget). */
  send(envelope: ClientEnvelope): boolean {
    const socket = this.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) return false;
    try {
      socket.send(JSON.stringify(envelope));
      return true;
    } catch {
      return false;
    }
  }

  /* --------------------------------------------------------------- private */

  private sendInput(envelope: ClientEnvelope): boolean {
    if (!this.inputBucket.consume()) {
      this.update({ throttled: this.snapshot.throttled + 1 });
      return false;
    }
    return this.send(envelope);
  }

  private update(patch: Partial<SocketSnapshot>): void {
    this.snapshot = { ...this.snapshot, ...patch };
    this.options.onSnapshot?.(this.snapshot);
  }

  private url(): string {
    const base =
      this.options.baseUrl ??
      (typeof window === 'undefined'
        ? ''
        : `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`);
    const build =
      this.options.buildUrl ??
      ((origin: string, graphId: string) => `${origin}/ws/graph/${encodeURIComponent(graphId)}`);
    return build(base, this.options.graphId);
  }

  private async open(): Promise<void> {
    if (this.closedByUser) return;
    this.update({ phase: 'fetching-ticket', attempt: this.snapshot.attempt + 1 });

    let ticket: WsTicket;
    try {
      ticket = await this.options.getTicket(this.options.graphId);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'failed to obtain a WS ticket';
      const status =
        error && typeof error === 'object' && 'status' in error
          ? Number((error as { status?: unknown }).status)
          : 0;
      const terminalAuthFailure = status === 401 || status === 403;
      const code =
        status === 401
          ? AppErrorCode.UNAUTHENTICATED
          : status === 403
            ? AppErrorCode.FORBIDDEN
            : status === 429
              ? AppErrorCode.RATE_LIMITED
              : AppErrorCode.INTERNAL;
      this.update({ phase: terminalAuthFailure ? 'failed' : 'reconnecting', lastError: message, lastErrorCode: code });
      this.options.onError?.(code, message);
      if (!terminalAuthFailure) this.scheduleReconnect();
      return;
    }

    // The ticket is single-use: create the socket immediately.
    const protocols = ticket.subprotocols?.length
      ? [ticket.subprotocols[0], ticket.ticket]
      : ['omniagent.v1', ticket.ticket];

    this.update({ phase: 'connecting' });
    let socket: WebSocket;
    try {
      socket = new WebSocket(this.url(), protocols);
    } catch (error) {
      this.update({
        phase: 'failed',
        lastError: error instanceof Error ? error.message : 'WebSocket constructor failed',
      });
      this.scheduleReconnect();
      return;
    }
    this.socket = socket;

    socket.onopen = () => {
      // A stable connection resets the consecutive-reconnect budget.
      this.update({ phase: 'open', attempt: 0, lastError: null, lastErrorCode: null });
      this.startHeartbeat();
    };
    socket.onmessage = (event) => this.handleMessage(event);
    socket.onerror = () => {
      // Details are not exposed to JS by design; `onclose` carries the code.
      this.update({ lastError: 'websocket error' });
    };
    socket.onclose = (event) => {
      this.clearTimers();
      this.socket = null;
      this.update({
        phase: this.closedByUser ? 'closed' : 'reconnecting',
        takeoverActive: false,
      });
      this.options.onClosed?.(event.code, event.reason);
      if (this.closedByUser) return;
      if (TERMINAL_CLOSE_CODES.includes(event.code)) {
        this.update({
          phase: 'failed',
          lastError: event.reason || `closed with code ${event.code}`,
          lastErrorCode: event.code,
        });
        return;
      }
      this.scheduleReconnect();
    };
  }

  private handleMessage(event: MessageEvent<string | ArrayBuffer | Blob>): void {
    if (typeof event.data !== 'string') return; // the API only sends JSON text
    let envelope: ServerEnvelope;
    try {
      envelope = JSON.parse(event.data) as ServerEnvelope;
    } catch {
      return;
    }

    this.options.onEnvelope?.(envelope);

    switch (envelope.type) {
      case ServerMessageType.SESSION_READY: {
        const session = envelope as SessionReady;
        this.update({
          role: session.role,
          permissions: session.permissions ?? [],
          subject: session.subject,
          connectionId: session.connection_id,
        });
        this.scheduleAuthRefresh(session.credential_expires_at);
        this.options.onSessionReady?.(session);
        break;
      }
      case ServerMessageType.SCREEN_FRAME:
        // Count frames without notifying React on every video packet; the
        // canvas paints via its image ref and status snapshots stay low-rate.
        this.snapshot = { ...this.snapshot, frames: this.snapshot.frames + 1 };
        this.options.onFrame?.(
          envelope as Extract<
            ServerEnvelope,
            { type: typeof ServerMessageType.SCREEN_FRAME }
          >,
        );
        break;
      case ServerMessageType.TAKEOVER_STATE: {
        const state = envelope as TakeoverState;
        this.update({
          takeoverActive: state.enabled,
          takeoverHolder: state.holder ?? null,
          takeoverConnectionId: state.connection_id ?? null,
        });
        this.options.onTakeoverState?.(state);
        break;
      }
      case ServerMessageType.AUTH_REQUIRED:
        void this.refreshCredential();
        break;
      case ServerMessageType.RATE_LIMITED: {
        const limited = envelope as { limit: string; retry_after_ms: number };
        this.update({ throttled: this.snapshot.throttled + 1 });
        this.options.onRateLimited?.(limited.limit, limited.retry_after_ms);
        break;
      }
      case ServerMessageType.PONG: {
        const pong = envelope as { ts_ms: number; echo?: unknown };
        if (typeof pong.echo === 'number' && this.pendingPingTs === pong.echo) {
          this.update({ rttMs: Date.now() - pong.echo });
        }
        break;
      }
      case ServerMessageType.ERROR: {
        const error = envelope as {
          code: number;
          message: string;
          holder_is_other?: boolean;
        };
        this.update({
          lastError: error.message,
          lastErrorCode: error.code,
          ...(error.code === AppErrorCode.TAKEOVER_LEASE_CONFLICT && error.holder_is_other
            ? { takeoverActive: true, takeoverConnectionId: '__other__' }
            : {}),
        });
        this.options.onError?.(error.code, error.message);
        break;
      }
      default:
        break;
    }
  }

  /** In-band credential refresh: new ticket, sent as an `AUTH` message. */
  async refreshCredential(): Promise<boolean> {
    if (this.refreshing || !this.isOpen) return false;
    this.refreshing = true;
    try {
      // A fresh ticket alone inherits the old access-token expiry. Rotate the
      // parent session first; the BFF coalesces simultaneous socket refreshes.
      if (this.options.refreshSession && !(await this.options.refreshSession())) return false;
      const ticket = await this.options.getTicket(this.options.graphId);
      const sent = this.send({
        type: ClientMessageType.AUTH,
        payload: { token: ticket.ticket },
      });
      // The server sends a fresh SESSION_READY after accepting AUTH; that
      // envelope carries the effective session expiry and arms the next timer.
      return sent;
    } catch {
      return false;
    } finally {
      this.refreshing = false;
    }
  }

  private scheduleAuthRefresh(sessionExpiresAt: number | null): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    if (sessionExpiresAt === null || !Number.isFinite(sessionExpiresAt)) return;
    // A WS ticket expires after ~60 s, but the socket is bound to the parent
    // session (`sexp`). Refresh 90 s before that session expiry, not on ticket
    // expiry (or 10% for unusually short sessions); the server also sends
    // AUTH_REQUIRED as a watchdog fallback.
    const untilExpiryMs = sessionExpiresAt * 1000 - Date.now();
    const leadMs = Math.min(90_000, Math.max(5_000, untilExpiryMs * 0.1));
    const delayMs = Math.max(1_000, untilExpiryMs - leadMs);
    this.refreshTimer = setTimeout(() => void this.refreshCredential(), delayMs);
  }

  private startHeartbeat(): void {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = setInterval(() => {
      if (this.isOpen) this.ping();
    }, this.options.heartbeatMs);
  }

  private scheduleReconnect(): void {
    if (this.closedByUser) return;
    if (this.snapshot.attempt >= this.options.maxReconnectAttempts) {
      this.update({ phase: 'failed', lastError: 'gave up reconnecting' });
      return;
    }
    const attempt = this.snapshot.attempt;
    const base = Math.min(
      this.options.reconnectMaxMs,
      this.options.reconnectBaseMs * 2 ** Math.max(0, attempt - 1),
    );
    const delay = Math.round(base * (0.85 + Math.random() * 0.3)); // +-15% jitter
    this.update({ phase: 'reconnecting' });
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => void this.open(), delay);
  }

  private clearTimers(): void {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    this.heartbeatTimer = null;
    this.reconnectTimer = null;
    this.refreshTimer = null;
  }
}

export type ScreenFrameEnvelope = Extract<
  ServerEnvelope,
  { type: typeof ServerMessageType.SCREEN_FRAME }
>;

/** Convenience factory for React code. */
export function createOmniAgentSocket(options: OmniAgentSocketOptions): OmniAgentSocket {
  return new OmniAgentSocket(options);
}
