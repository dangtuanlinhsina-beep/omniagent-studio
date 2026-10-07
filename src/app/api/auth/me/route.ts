import { NextResponse } from 'next/server';

import { apiFetch, readSession } from '@/lib/auth/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** GET /api/auth/me — current identity (no tokens). */
export async function GET(): Promise<NextResponse> {
  const session = await readSession();
  if (!session) {
    return NextResponse.json({ authenticated: false }, { status: 401 });
  }
  const upstream = await apiFetch('/api/auth/me');
  if (upstream.status === 401) {
    // Leave refresh cookie intact; the browser's shared refresh flow rotates it
    // and retries /me. The /refresh route clears cookies only on refresh failure.
    return NextResponse.json({ authenticated: false }, { status: 401 });
  }
  if (!upstream.ok) {
    return NextResponse.json({ authenticated: false, detail: 'upstream error' }, { status: 502 });
  }
  const body = (await upstream.json()) as Record<string, unknown>;
  return NextResponse.json({ authenticated: true, ...body });
}
