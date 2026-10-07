import { NextResponse } from 'next/server';

import {
  apiFetch,
  clearSession,
  isJsonRequest,
  isSameOriginRequest,
  readRefreshToken,
  readSession,
  writeSession,
  type LoginResult,
} from '@/lib/auth/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** POST /api/auth/logout — revoke server-side and clear both cookies. */
export async function POST(request: Request): Promise<NextResponse> {
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ detail: 'cross-origin request rejected' }, { status: 403 });
  }
  if (!isJsonRequest(request)) {
    return NextResponse.json({ detail: 'application/json required' }, { status: 415 });
  }

  const session = await readSession();
  const refreshToken = await readRefreshToken();
  let accessToken = session?.accessToken ?? null;
  let accessWasRejected = !accessToken;

  if (accessToken) {
    try {
      const revoked = await apiFetch('/api/auth/logout', { method: 'POST' }, { timeoutMs: 8_000 });
      accessWasRejected = revoked.status === 401;
    } catch {
      // Clear browser credentials even if FastAPI is temporarily unreachable.
    }
  }

  // If the access cookie expired first, rotate the still-live refresh token
  // server-side and revoke the same session with the fresh access token.
  if (accessWasRejected && refreshToken) {
    try {
      const rotated = await apiFetch(
        '/api/auth/refresh',
        { method: 'POST', body: JSON.stringify({ refresh_token: refreshToken }) },
        { auth: false, timeoutMs: 8_000 },
      );
      if (rotated.ok) {
        const credentials = (await rotated.json()) as LoginResult;
        accessToken = credentials.access_token;
        await writeSession(credentials.access_token, credentials.refresh_token, credentials.expires_in);
      }
    } catch {
      accessToken = null;
    }
    if (accessToken) {
      try {
        await apiFetch(
          '/api/auth/logout',
          { method: 'POST', headers: { authorization: `Bearer ${accessToken}` } },
          { auth: false, timeoutMs: 8_000 },
        );
      } catch {
        // Cookies are still cleared below; this remains best effort on outages.
      }
    }
  }

  await clearSession();
  return NextResponse.json({ ok: true }, { headers: { 'cache-control': 'no-store' } });
}
