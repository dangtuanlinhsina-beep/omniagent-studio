'use client';

import {
  addEdge,
  applyEdgeChanges,
  applyNodeChanges,
  MarkerType,
  type Connection,
  type Edge,
  type EdgeChange,
  type NodeChange,
} from '@xyflow/react';
import { create } from 'zustand';
import { buildInitialFlow, NAV_URLS } from '@/canvas/data/mockFlow';
import { clearWorkspaceLocal } from '@/canvas/utils/graphIO';
import type {
  AnalystNodeData,
  BrowserNodeData,
  BrowserStatus,
  DashboardNodeData,
  InsertableNodeKind,
  OmniNode,
  Thought,
  ThoughtKind,
} from '@/canvas/types';

/* -------------------------------------------------------------------------- */
/* Store shape                                                                 */
/* -------------------------------------------------------------------------- */

export interface GraphState {
  nodes: OmniNode[];
  edges: Edge[];
  running: boolean;
  /** monotonic simulation tick counter (shown in the status bar) */
  ticks: number;

  /* react-flow wiring */
  onNodesChange: (changes: NodeChange<OmniNode>[]) => void;
  onEdgesChange: (changes: EdgeChange[]) => void;
  onConnect: (connection: Connection) => void;

  /* lifecycle */
  setRunning: (running: boolean) => void;
  toggleRunning: () => void;
  resetFlow: () => void;
  addNode: (kind: InsertableNodeKind) => void;
  removeNode: (id: string) => void;
  duplicateNode: (id: string) => void;
  importGraph: (nodes: OmniNode[], edges: Edge[]) => void;

  /* ui state */
  inspectorOpen: boolean;
  toggleInspector: () => void;

  /* simulation mutations (invoked by useAgentRuntime) */
  bumpTick: () => void;
  toggleTakeover: (id: string) => void;
  setBrowserStatus: (id: string, status: BrowserStatus) => void;
  navigateBrowser: (id: string, url: string, title: string) => void;
  pushThought: (id: string, kind: ThoughtKind, text: string) => void;
  tickDashboard: (id: string) => void;
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

let uid = 0;
const nextId = (prefix: string) => `${prefix}-${Date.now().toString(36)}-${uid++}`;

function patchNodeData(nodes: OmniNode[], id: string, patch: Record<string, unknown>): OmniNode[] {
  return nodes.map((n) =>
    n.id === id ? ({ ...n, data: { ...n.data, ...patch } } as OmniNode) : n,
  );
}

const readBrowserData = (nodes: OmniNode[], id: string) =>
  nodes.find((n) => n.id === id)?.data as BrowserNodeData | undefined;

/* -------------------------------------------------------------------------- */
/* Store                                                                       */
/* -------------------------------------------------------------------------- */

export const useGraphStore = create<GraphState>()((set, get) => {
  const initial = buildInitialFlow();

  return {
    nodes: initial.nodes,
    edges: initial.edges,
    running: true,
    ticks: 0,

    /* ---------------- react-flow wiring ---------------- */
    onNodesChange: (changes) => set({ nodes: applyNodeChanges(changes, get().nodes) }),

    onEdgesChange: (changes) => set({ edges: applyEdgeChanges(changes, get().edges) }),

    onConnect: (connection) =>
      set({
        edges: addEdge(
          {
            ...connection,
            animated: true,
            style: { stroke: '#22d3ee', strokeWidth: 1.8 },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#22d3ee', width: 14, height: 14 },
          },
          get().edges,
        ),
      }),

    /* ---------------- lifecycle ---------------- */
    setRunning: (running) => set({ running }),
    toggleRunning: () => set({ running: !get().running }),

    resetFlow: () => {
      const fresh = buildInitialFlow();
      set({ nodes: fresh.nodes, edges: fresh.edges, ticks: 0, running: true });
      if (typeof window !== 'undefined') clearWorkspaceLocal();
    },

    addNode: (kind) => {
      const id = nextId(kind);
      const jitter = () => Math.round((Math.random() - 0.5) * 220);
      const position = { x: 260 + jitter(), y: 140 + jitter() };

      let node: OmniNode;
      switch (kind) {
        case 'browser':
          node = {
            id,
            type: 'browser',
            position,
            data: {
              url: 'https://example.com/landing',
              title: 'Example — Landing',
              status: 'Browsing',
              takeover: false,
              navCount: 0,
            } satisfies BrowserNodeData,
          };
          break;
        case 'analyst':
          node = {
            id,
            type: 'analyst',
            position,
            data: {
              status: 'Idle',
              thoughts: [
                { id: nextId('t'), ts: 0, kind: 'result', text: 'Analyst online. Awaiting objective assignment…' },
              ],
              tokens: 0,
              model: 'omni-core-70b',
            } satisfies AnalystNodeData,
          };
          break;
        case 'dashboard':
          node = {
            id,
            type: 'dashboard',
            position,
            data: {
              events: 0,
              schema: {
                title: 'Blank Metrics Board',
                kpis: [
                  { id: nextId('k'), label: 'Events', value: '0', delta: '+0%', good: true },
                  { id: nextId('k'), label: 'Errors', value: '0', delta: '+0%', good: true },
                ],
                charts: [
                  {
                    id: nextId('c'),
                    type: 'line',
                    title: 'Awaiting upstream signal…',
                    xLabels: Array.from({ length: 26 }, (_, i) => `T-${25 - i}`),
                    series: [{ name: 'signal', color: '#fbbf24', data: Array(26).fill(0) }],
                  },
                ],
              },
            } satisfies DashboardNodeData,
          };
          break;
      }

      set({ nodes: [...get().nodes, node] });
    },

    removeNode: (id) =>
      set({
        nodes: get().nodes.filter((n) => n.id !== id),
        edges: get().edges.filter((e) => e.source !== id && e.target !== id),
      }),

    duplicateNode: (id) => {
      const source = get().nodes.find((n) => n.id === id);
      if (!source) return;
      const clone = {
        ...source,
        id: nextId(source.type ?? 'node'),
        position: { x: source.position.x + 36, y: source.position.y + 36 },
        selected: false,
        // deep-clone data so mutations on the copy never touch the original
        data: JSON.parse(JSON.stringify(source.data)) as Record<string, unknown>,
      } as OmniNode;
      set({ nodes: [...get().nodes, clone] });
    },

    importGraph: (nodes, edges) => set({ nodes, edges }),

    /* ---------------- ui state ---------------- */
    inspectorOpen: false,
    toggleInspector: () => set({ inspectorOpen: !get().inspectorOpen }),

    /* ---------------- simulation mutations ---------------- */
    bumpTick: () => set({ ticks: get().ticks + 1 }),

    toggleTakeover: (id) => {
      const current = readBrowserData(get().nodes, id)?.takeover ?? false;
      set({ nodes: patchNodeData(get().nodes, id, { takeover: !current }) });
    },

    setBrowserStatus: (id, status) =>
      set({ nodes: patchNodeData(get().nodes, id, { status }) }),

    navigateBrowser: (id, url, title) => {
      const navCount = (readBrowserData(get().nodes, id)?.navCount ?? 0) + 1;
      set({ nodes: patchNodeData(get().nodes, id, { url, title, status: 'Browsing', navCount }) });
    },

    pushThought: (id, kind, text) =>
      set({
        nodes: get().nodes.map((n) => {
          if (n.id !== id || n.type !== 'analyst') return n;
          const data = n.data as AnalystNodeData;
          const thought: Thought = { id: nextId('t'), ts: Date.now(), kind, text };
          const thoughts = [...data.thoughts, thought].slice(-42);
          const status = kind === 'tool' ? 'ToolCall' : 'Reasoning';
          return {
            ...n,
            data: {
              ...data,
              thoughts,
              status,
              tokens: data.tokens + Math.max(12, Math.round(text.length * 2.4)),
            } satisfies AnalystNodeData,
          };
        }),
      }),

    tickDashboard: (id) =>
      set({
        nodes: get().nodes.map((n) => {
          if (n.id !== id || n.type !== 'dashboard') return n;
          const data = n.data as DashboardNodeData;
          const schema = {
            ...data.schema,
            charts: data.schema.charts.map((chart) => ({ ...chart })),
          };

          for (const chart of schema.charts) {
            if (chart.type !== 'line') continue;
            for (const series of chart.series) {
              const last = series.data[series.data.length - 1] ?? 50;
              const drift = series.name === 'errors' ? 5 : 13;
              const next = Math.min(96, Math.max(4, last + (Math.random() - 0.5) * drift * 2));
              series.data = [...series.data.slice(1), Math.round(next)];
            }
            const step = parseInt(chart.xLabels[chart.xLabels.length - 1].replace('T', ''), 10) || 0;
            chart.xLabels = [...chart.xLabels.slice(1), `T+${step + 1}`];
          }

          return {
            ...n,
            data: { ...data, events: data.events + 1 + Math.round(Math.random() * 3), schema },
          };
        }),
      }),
  };
});

/** Convenience helper — next URL entry for the browser navigation cycle */
export function nextNavEntry(currentUrl: string) {
  const idx = NAV_URLS.findIndex((n) => n.url === currentUrl);
  return NAV_URLS[(idx + 1 + NAV_URLS.length) % NAV_URLS.length];
}
