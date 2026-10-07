import 'server-only';

import { cookies } from 'next/headers';

/**
 * Server-only session helpers (Next.js BFF pattern). Never import from a
 * client component; `client.ts` is the browser-safe counterpart.
 *
 * The browser never sees FastAPI access/refresh JWTs. They are stored in
 * httpOnly, SameSite=Lax cookies and are read only by these route handlers.
 * Client code receives a graph-bound, single-use WebSocket ticket when it
 * needs to open a stream.
 */

export const ACCESS_COOKIE = 'omniagent_at';
export const REFRESH_COOKIE = 'omniagent_rt';

export type SessionTokens = {
  accessToken: string;
  refreshToken: string | null;
  expiresIn: number;
};

export type ApiUser = {
  id: string;
  email: string;
  role: 'VIEWER' | 'OPERATOR' | 'ADMIN';
  graph_ids: string[];
  display_name?: string | null;
};

export type LoginResult = {
  access_token: string;
  refresh_token?: string | null;
  token_type?: string;
  expires_in: number;
  role: ApiUser['role'];
  subject: string;
  permissions: string[];
  user?: ApiUser | null;
};

/** Backend origin; server-side only, never `NEXT_PUBLIC_*`. */
export function apiBaseUrl(): string {
  const value = process.env.OMNIAGENT_API_URL ?? 'http://127.0.0.1:8000';
  return value.replace(/\/+$/, '');
}

function cookieOptions(maxAgeSeconds: number) {
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: Math.max(0, Math.floor(maxAgeSeconds)),
  };
}

/** Origin + Fetch Metadata check for state-changing BFF endpoints. */
export function isSameOriginRequest(request: Request): boolean {
  const fetchSite = request.headers.get('sec-fetch-site');
  if (fetchSite === 'cross-site') return false;

  const origin = request.headers.get('origin');
  if (!origin) {
    // Non-browser clients may omit Origin. Browsers submit Origin for unsafe
    // fetch/form methods; `SameSite=Lax` is the additional cookie boundary.
    return true;
  }
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

/** Rejects non-JSON POSTs before route handlers attempt to read credentials. */
export function isJsonRequest(request: Request): boolean {
  return request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() ===
    'application/json';
}

export async function readSession(): Promise<SessionTokens | null> {
  const store = await cookies();
  const accessToken = store.get(ACCESS_COOKIE)?.value;
  if (!accessToken) return null;
  return {
    accessToken,
    refreshToken: store.get(REFRESH_COOKIE)?.value ?? null,
    expiresIn: 0,
  };
}

/** The refresh cookie may outlive the access cookie; read it independently. */
export async function readRefreshToken(): Promise<string | null> {
  const store = await cookies();
  return store.get(REFRESH_COOKIE)?.value ?? null;
}

export async function writeSession(
  accessToken: string,
  refreshToken: string | null | undefined,
  expiresIn: number,
  refreshExpiresIn = 43_200,
): Promise<void> {
  const store = await cookies();
  store.set(ACCESS_COOKIE, accessToken, cookieOptions(expiresIn));
  if (refreshToken) {
    store.set(REFRESH_COOKIE, refreshToken, cookieOptions(refreshExpiresIn));
  } else {
    store.delete(REFRESH_COOKIE);
  }
}

export async function clearSession(): Promise<void> {
  const store = await cookies();
  store.delete(ACCESS_COOKIE);
  store.delete(REFRESH_COOKIE);
}

/**
 * Make a server-to-server request to FastAPI. `path` is intentionally limited
 * to a relative `/api/...` path so caller-controlled input can never become an
 * SSRF target. Responses are uncached and time-bounded.
 */
export async function apiFetch(
  path: string,
  init: RequestInit = {},
  options: { auth?: boolean; timeoutMs?: number } = {},
): Promise<Response> {
  const { auth = true, timeoutMs = 10_000 } = options;
  if (!path.startsWith('/api/') || path.startsWith('//')) {
    throw new Error('apiFetch accepts only relative /api/ paths');
  }
  const headers = new Headers(init.headers);
  headers.set('accept', 'application/json');
  if (init.body && !headers.has('content-type')) {
    headers.set('content-type', 'application/json');
  }
  if (auth) {
    const session = await readSession();
    if (session) headers.set('authorization', `Bearer ${session.accessToken}`);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(`${apiBaseUrl()}${path}`, {
      ...init,
      headers,
      signal: controller.signal,
      cache: 'no-store',
      redirect: 'manual',
    });
  } finally {
    clearTimeout(timer);
  }
}

/** Only the public identity fields are allowed back to the browser. */
export function publicSessionPayload(result: LoginResult) {
  return {
    subject: result.subject,
    role: result.role,
    permissions: result.permissions,
    expires_in: result.expires_in,
    user: result.user ?? null,
  };
}
