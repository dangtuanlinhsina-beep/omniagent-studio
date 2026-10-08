import { NextResponse } from 'next/server';

import {
  apiFetch,
  isJsonRequest,
  isSameOriginRequest,
  clearSession,
  readRefreshToken,
  writeSession,
  type LoginResult,
} from '@/lib/auth/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * POST /api/auth/refresh — rotates the cookie pair.
 *
 * The backend revokes the presented refresh token (jti) and returns a new
 * pair; a replayed token therefore fails, which is why the cookies are only
 * rewritten on success.
 */
export async function POST(request: Request): Promise<NextResponse> {
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ detail: 'cross-origin request rejected' }, { status: 403 });
  }
  if (!isJsonRequest(request)) {
    return NextResponse.json({ detail: 'application/json required' }, { status: 415 });
  }
  const refreshToken = await readRefreshToken();
  if (!refreshToken) {
    return NextResponse.json({ detail: 'no refresh token' }, { status: 401 });
  }
  const upstream = await apiFetch(
    '/api/auth/refresh',
    { method: 'POST', body: JSON.stringify({ refresh_token: refreshToken }) },
    { auth: false, timeoutMs: 10_000 },
  );
  if (!upstream.ok) {
    await clearSession();
    return NextResponse.json({ detail: 'refresh rejected' }, { status: upstream.status });
  }
  const result = (await upstream.json()) as LoginResult;
  await writeSession(result.access_token, result.refresh_token, result.expires_in);
  return NextResponse.json({ ok: true, expires_in: result.expires_in });
}
