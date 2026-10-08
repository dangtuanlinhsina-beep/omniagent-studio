import { NextResponse } from 'next/server';

import {
  apiFetch,
  isJsonRequest,
  isSameOriginRequest,
  clearSession,
  publicSessionPayload,
  writeSession,
  type LoginResult,
} from '@/lib/auth/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * POST /api/auth/login  →  FastAPI POST /api/auth/login
 *
 * The backend's tokens are stored in httpOnly cookies; the browser only ever
 * sees `{ subject, role, permissions, expires_in, user }`.
 */
export async function POST(request: Request): Promise<NextResponse> {
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ detail: 'cross-origin request rejected' }, { status: 403 });
  }
  if (!isJsonRequest(request)) {
    return NextResponse.json({ detail: 'application/json required' }, { status: 415 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: 'invalid JSON body' }, { status: 400 });
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return NextResponse.json({ detail: 'JSON object required' }, { status: 400 });
  }
  const { email, password } = body as Record<string, unknown>;
  if (typeof email !== 'string' || typeof password !== 'string' || !password) {
    return NextResponse.json({ detail: 'email and password are required' }, { status: 400 });
  }

  const upstream = await apiFetch(
    '/api/auth/login',
    { method: 'POST', body: JSON.stringify({ email, password }) },
    { auth: false, timeoutMs: 15_000 },
  );

  if (!upstream.ok) {
    // Forward the backend's generic error verbatim (it never reveals whether
    // the account exists), and drop any stale session.
    await clearSession();
    const detail = await upstream.text();
    return new NextResponse(detail, {
      status: upstream.status,
      headers: { 'content-type': upstream.headers.get('content-type') ?? 'application/json' },
    });
  }

  const result = (await upstream.json()) as LoginResult;
  await writeSession(result.access_token, result.refresh_token, result.expires_in);
  return NextResponse.json(publicSessionPayload(result));
}
