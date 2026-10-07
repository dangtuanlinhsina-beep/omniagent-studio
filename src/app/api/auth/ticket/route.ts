import { NextResponse } from 'next/server';

import { apiFetch, isJsonRequest, isSameOriginRequest, readSession } from '@/lib/auth/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const GRAPH_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * POST /api/auth/ticket  { graphId }  →  FastAPI POST /api/auth/ws-ticket
 *
 * Issues the **single-use, short-lived, graph-bound** JWT that the browser
 * presents during the WebSocket handshake (via `Sec-WebSocket-Protocol`).
 * This is the only token that ever reaches client-side JavaScript, and it is
 * worthless outside this graph, this session and this 60-second window.
 */
export async function POST(request: Request): Promise<NextResponse> {
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ detail: 'cross-origin request rejected' }, { status: 403 });
  }
  if (!isJsonRequest(request)) {
    return NextResponse.json({ detail: 'application/json required' }, { status: 415 });
  }
  const session = await readSession();
  if (!session) {
    return NextResponse.json({ detail: 'authentication required' }, { status: 401 });
  }

  let requestBody: unknown;
  try {
    requestBody = await request.json();
  } catch {
    return NextResponse.json({ detail: 'invalid JSON body' }, { status: 400 });
  }
  if (!requestBody || typeof requestBody !== 'object' || Array.isArray(requestBody)) {
    return NextResponse.json({ detail: 'JSON object required' }, { status: 400 });
  }
  const fields = requestBody as Record<string, unknown>;
  const graphId = fields.graphId ?? fields.graph_id;
  const ttl = fields.ttl_s ?? fields.ttl;
  if (typeof graphId !== 'string' || !GRAPH_ID_PATTERN.test(graphId)) {
    return NextResponse.json({ detail: 'invalid graphId' }, { status: 400 });
  }

  const upstream = await apiFetch(
    '/api/auth/ws-ticket',
    {
      method: 'POST',
      body: JSON.stringify(
        typeof ttl === 'number' ? { graph_id: graphId, ttl_s: ttl } : { graph_id: graphId },
      ),
    },
    { timeoutMs: 8_000 },
  );
  if (!upstream.ok) {
    const detail = await upstream.text();
    return new NextResponse(detail, {
      status: upstream.status,
      headers: { 'content-type': upstream.headers.get('content-type') ?? 'application/json' },
    });
  }
  const ticketResponse = await upstream.json();
  return NextResponse.json(ticketResponse, {
    headers: { 'cache-control': 'no-store' },
  });
}
