import { NextResponse } from 'next/server';

import { apiFetch } from '@/lib/auth/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** GET /api/auth/config — public auth policy (TTLs, subprotocols, roles). */
export async function GET(): Promise<NextResponse> {
  const upstream = await apiFetch('/api/auth/config', {}, { auth: false });
  if (!upstream.ok) {
    return NextResponse.json({ detail: 'upstream error' }, { status: 502 });
  }
  return NextResponse.json(await upstream.json(), {
    headers: { 'cache-control': 'no-store' },
  });
}
