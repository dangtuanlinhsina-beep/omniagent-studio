'use client';

/**
 * Browser-side auth helpers.
 *
 * All calls go to the same-origin Next.js BFF (`/api/auth/*`), never directly
 * to FastAPI. Access/refresh tokens remain in httpOnly cookies. The only token
 * that client code receives is the graph-bound, single-use WebSocket ticket.
 */

import type { Role } from '@/lib/ws/protocol';

export type SessionUser = {
  id?: string;
  email?: string;
  role?: Role;
  graph_ids?: string[];
  display_name?: string | null;
  disabled?: boolean;
};

export type SessionInfo = {
  authenticated: boolean;
  subject?: string;
  role?: Role;
  permissions?: string[];
  graph_ids?: string[];
  expires_in?: number;
  expires_at?: number | null;
  token_type?: string;
  user?: SessionUser | null;
};

export type LoginResponse = {
  subject: string;
  role: Role;
  permissions: string[];
  expires_in: number;
  user: SessionUser | null;
};

export type WsTicketResponse = {
  ticket: string;
  token_type: 'ws-ticket';
  expires_in: number;
  graph_id: string;
  subprotocols: string[];
  ws_url_template: string;
};

export type AuthConfig = {
  auth_enabled: boolean;
  registration_enabled: boolean;
  access_token_ttl_s: number;
  refresh_token_ttl_s: number;
  ws_ticket_ttl_s: number;
  ws_subprotocols: string[];
  ws_url_template: string;
  password_min_length: number;
  roles: string[];
};

export class AuthError extends Error {
  constructor(message: string, readonly status: number, readonly detail?: unknown) {
    super(message);
    this.name = 'AuthError';
  }
}

async function parse<T>(response: Response): Promise<T> {
  const text = await response.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!response.ok) {
    const message = (data as { detail?: unknown } | null)?.detail ??
      `request failed (${response.status})`;
    throw new AuthError(
      typeof message === 'string' ? message : JSON.stringify(message),
      response.status,
      data,
    );
  }
  return data as T;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    credentials: 'same-origin',
    cache: 'no-store',
    body: JSON.stringify(body),
  });
  return parse<T>(response);
}

export async function login(email: string, password: string): Promise<LoginResponse> {
  return postJson<LoginResponse>('/api/auth/login', { email, password });
}

export async function register(
  email: string,
  password: string,
  displayName?: string,
): Promise<LoginResponse> {
  return postJson<LoginResponse>('/api/auth/register', {
    email,
    password,
    display_name: displayName ?? null,
  });
}

export async function logout(): Promise<void> {
  try {
    await postJson<{ ok: boolean }>('/api/auth/logout', {});
  } catch {
    // The BFF clears cookies regardless; ignore transport failures here.
  }
}

/** One rotation for all nodes in the same browser tab when access expires. */
let refreshInFlight: Promise<boolean> | null = null;

export async function refreshSession(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;
  const pending = (async () => {
    try {
      await postJson<{ ok: boolean }>('/api/auth/refresh', {});
      return true;
    } catch {
      return false;
    }
  })();
  refreshInFlight = pending;
  try {
    return await pending;
  } finally {
    if (refreshInFlight === pending) refreshInFlight = null;
  }
}

async function requestMe(): Promise<Response> {
  return fetch('/api/auth/me', {
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { accept: 'application/json' },
  });
}

export async function fetchSession(): Promise<SessionInfo> {
  try {
    let response = await requestMe();
    if (response.status === 401 && await refreshSession()) {
      response = await requestMe();
    }
    if (response.status === 401) return { authenticated: false };
    return await parse<SessionInfo>(response);
  } catch {
    return { authenticated: false };
  }
}

export async function fetchAuthConfig(): Promise<AuthConfig | null> {
  try {
    const response = await fetch('/api/auth/config', {
      credentials: 'same-origin',
      cache: 'no-store',
    });
    if (!response.ok) return null;
    return (await response.json()) as AuthConfig;
  } catch {
    return null;
  }
}

/**
 * Mint a single-use, short-lived WS ticket. When the access cookie has expired,
 * rotate it once through the BFF then retry. The shared promise coalesces this
 * refresh across multiple graph nodes mounting at once.
 */
export async function requestWsTicket(
  graphId: string,
  ttlS?: number,
): Promise<WsTicketResponse> {
  const issue = () => postJson<WsTicketResponse>(
    '/api/auth/ticket',
    ttlS ? { graphId, ttl_s: ttlS } : { graphId },
  );
  try {
    return await issue();
  } catch (error) {
    if (!(error instanceof AuthError) || error.status !== 401 || !(await refreshSession())) {
      throw error;
    }
    return issue();
  }
}
