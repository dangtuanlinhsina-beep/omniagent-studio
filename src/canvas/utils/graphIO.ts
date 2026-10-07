'use client';

import type { Edge } from '@xyflow/react';
import type { OmniNode } from '@/canvas/types';

/* -------------------------------------------------------------------------- */
/* Workspace payload schema                                                    */
/* -------------------------------------------------------------------------- */

export const WORKSPACE_KEY = 'omniagent:workspace:v1';

export interface WorkspacePayload {
  version: 1;
  savedAt: string;
  nodes: OmniNode[];
  edges: Edge[];
}

const VALID_TYPES = new Set(['browser', 'analyst', 'dashboard']);

/* -------------------------------------------------------------------------- */
/* Sanitisers — coerce arbitrary JSON back into well-formed node data          */
/* -------------------------------------------------------------------------- */

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function sanitizeBrowserData(raw: unknown): Record<string, unknown> {
  const d = asRecord(raw);
  return {
    url: typeof d.url === 'string' ? d.url : 'https://example.com/landing',
    title: typeof d.title === 'string' ? d.title : 'Example — Landing',
    status: ['Browsing', 'CaptchaDetected', 'Paused'].includes(d.status as string)
      ? d.status
      : 'Browsing',
    takeover: Boolean(d.takeover),
    navCount: typeof d.navCount === 'number' ? d.navCount : 0,
  };
}

function sanitizeAnalystData(raw: unknown): Record<string, unknown> {
  const d = asRecord(raw);
  const thoughts = Array.isArray(d.thoughts)
    ? d.thoughts
        .filter((t) => t && typeof (t as Record<string, unknown>).text === 'string')
        .map((t) => {
          const th = t as Record<string, unknown>;
          return {
            id: typeof th.id === 'string' ? th.id : `t-${Math.random().toString(36).slice(2)}`,
            ts: typeof th.ts === 'number' ? th.ts : 0,
            kind: ['thought', 'tool', 'result', 'warning'].includes(th.kind as string)
              ? th.kind
              : 'thought',
            text: th.text,
          };
        })
        .slice(-42)
    : [];
  return {
    status: ['Reasoning', 'ToolCall', 'Idle', 'Done'].includes(d.status as string)
      ? d.status
      : 'Idle',
    thoughts,
    tokens: typeof d.tokens === 'number' ? d.tokens : 0,
    model: typeof d.model === 'string' ? d.model : 'omni-core-70b',
  };
}

function sanitizeDashboardData(raw: unknown): Record<string, unknown> {
  const d = asRecord(raw);
  const schema = asRecord(d.schema);
  const charts = Array.isArray(schema.charts) ? schema.charts : [];
  const kpis = Array.isArray(schema.kpis) ? schema.kpis : [];
  return {
    events: typeof d.events === 'number' ? d.events : 0,
    schema: {
      title: typeof schema.title === 'string' ? schema.title : 'Imported Board',
      kpis: kpis.filter((k) => k && typeof (k as Record<string, unknown>).label === 'string'),
      charts: charts
        .filter(
          (c) =>
            c &&
            typeof (c as Record<string, unknown>).id === 'string' &&
            ['line', 'bar'].includes((c as Record<string, unknown>).type as string),
        )
        .map((c) => {
          const chart = c as Record<string, unknown>;
          return {
            ...chart,
            xLabels: Array.isArray(chart.xLabels) ? chart.xLabels.map(String) : [],
            series: Array.isArray(chart.series)
              ? chart.series.map((s) => {
                  const series = asRecord(s);
                  return {
                    ...series,
                    name: typeof series.name === 'string' ? series.name : 'series',
                    color: typeof series.color === 'string' ? series.color : '#22d3ee',
                    data: Array.isArray(series.data) ? series.data.map(Number) : [],
                  };
                })
              : [],
          };
        }),
    },
  };
}

/* -------------------------------------------------------------------------- */
/* Validate + normalize an untrusted workspace payload                         */
/* -------------------------------------------------------------------------- */

export function validateWorkspace(raw: unknown): { nodes: OmniNode[]; edges: Edge[] } | null {
  if (!raw || typeof raw !== 'object') return null;
  const payload = raw as Record<string, unknown>;
  if (payload.version !== 1 || !Array.isArray(payload.nodes) || !Array.isArray(payload.edges)) {
    return null;
  }

  const nodes: OmniNode[] = [];
  for (const item of payload.nodes) {
    const n = asRecord(item);
    if (typeof n.id !== 'string' || !VALID_TYPES.has(n.type as string)) continue;
    const pos = asRecord(n.position);
    const position = {
      x: typeof pos.x === 'number' ? pos.x : 0,
      y: typeof pos.y === 'number' ? pos.y : 0,
    };
    const data =
      n.type === 'browser'
        ? sanitizeBrowserData(n.data)
        : n.type === 'analyst'
          ? sanitizeAnalystData(n.data)
          : sanitizeDashboardData(n.data);
    nodes.push({ id: n.id, type: n.type as OmniNode['type'], position, data } as OmniNode);
  }

  if (nodes.length === 0) return null;
  const nodeIds = new Set(nodes.map((n) => n.id));

  const edges: Edge[] = [];
  for (const item of payload.edges) {
    const e = asRecord(item);
    if (
      typeof e.id !== 'string' ||
      typeof e.source !== 'string' ||
      typeof e.target !== 'string' ||
      !nodeIds.has(e.source) ||
      !nodeIds.has(e.target)
    ) {
      continue;
    }
    edges.push({
      id: e.id,
      source: e.source,
      target: e.target,
      sourceHandle: typeof e.sourceHandle === 'string' ? e.sourceHandle : null,
      targetHandle: typeof e.targetHandle === 'string' ? e.targetHandle : null,
    });
  }

  return { nodes, edges };
}

/* -------------------------------------------------------------------------- */
/* Export / Import helpers                                                     */
/* -------------------------------------------------------------------------- */

export function serializeWorkspace(nodes: OmniNode[], edges: Edge[]): WorkspacePayload {
  return {
    version: 1,
    savedAt: new Date().toISOString(),
    nodes: JSON.parse(JSON.stringify(nodes)) as OmniNode[],
    edges: JSON.parse(JSON.stringify(edges)) as Edge[],
  };
}

export function downloadWorkspace(nodes: OmniNode[], edges: Edge[]) {
  const payload = serializeWorkspace(nodes, edges);
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `omniagent-workspace-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '')}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/* -------------------------------------------------------------------------- */
/* localStorage persistence                                                    */
/* -------------------------------------------------------------------------- */

export function saveWorkspaceLocal(nodes: OmniNode[], edges: Edge[]) {
  try {
    localStorage.setItem(WORKSPACE_KEY, JSON.stringify(serializeWorkspace(nodes, edges)));
  } catch {
    /* quota / private mode — silently skip */
  }
}

export function loadWorkspaceLocal(): { nodes: OmniNode[]; edges: Edge[] } | null {
  try {
    const raw = localStorage.getItem(WORKSPACE_KEY);
    if (!raw) return null;
    return validateWorkspace(JSON.parse(raw));
  } catch {
    return null;
  }
}

export function clearWorkspaceLocal() {
  try {
    localStorage.removeItem(WORKSPACE_KEY);
  } catch {
    /* noop */
  }
}
