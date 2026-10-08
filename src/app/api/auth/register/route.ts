import { NextResponse } from 'next/server';

import { apiFetch, isJsonRequest, isSameOriginRequest, writeSession, publicSessionPayload, type LoginResult } from '@/lib/auth/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * POST /api/auth/register — self-service sign-up (disabled by default on the
 * backend). The role is always decided server-side; anything the client sends
 * as `role` is ignored.
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
  const fields = body as Record<string, unknown>;
  const upstream = await apiFetch(
    '/api/auth/register',
    {
      method: 'POST',
      body: JSON.stringify({
        email: fields.email,
        password: fields.password,
        display_name: fields.display_name ?? fields.displayName ?? null,
      }),
    },
    { auth: false, timeoutMs: 15_000 },
  );
  if (!upstream.ok) {
    const detail = await upstream.text();
    return new NextResponse(detail, {
      status: upstream.status,
      headers: { 'content-type': upstream.headers.get('content-type') ?? 'application/json' },
    });
  }
  const result = (await upstream.json()) as LoginResult;
  await writeSession(result.access_token, result.refresh_token, result.expires_in);
  return NextResponse.json(publicSessionPayload(result), { status: 201 });
}
