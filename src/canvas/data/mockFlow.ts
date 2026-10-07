import { MarkerType } from '@xyflow/react';
import type { Edge } from '@xyflow/react';
import type {
  AnalystNodeData,
  BrowserNodeData,
  DashboardNodeData,
  OmniNode,
  Thought,
} from '@/canvas/types';

/* -------------------------------------------------------------------------- */
/* Node ids — shared with the simulation runtime                               */
/* -------------------------------------------------------------------------- */

export const BROWSER_NODE_ID = 'browser-1';
export const ANALYST_NODE_ID = 'analyst-1';
export const DASHBOARD_NODE_ID = 'dashboard-1';

/* -------------------------------------------------------------------------- */
/* Simulation assets                                                           */
/* -------------------------------------------------------------------------- */

/** Deterministic PRNG (mulberry32) — keeps SSR output stable, no hydration diff */
function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** URLs the simulated agent rotates through while navigating */
export const NAV_URLS: { url: string; title: string }[] = [
  { url: 'https://shop.orbital.io/checkout/cart', title: 'Orbital Shop — Cart' },
  { url: 'https://shop.orbital.io/checkout/shipping', title: 'Orbital Shop — Shipping' },
  { url: 'https://analytics.orbital.io/funnel/q3', title: 'Orbital Analytics — Funnel Q3' },
  { url: 'https://status.orbital.io/edge-metrics', title: 'Orbital Status — Edge Metrics' },
];

/** Script of LLM thoughts / tool calls, cycled by the runtime */
export const THOUGHT_SCRIPT: { kind: Thought['kind']; text: string }[] = [
  { kind: 'thought', text: 'Parsing objective → "audit Q3 checkout funnel & summarise KPIs".' },
  { kind: 'tool', text: 'dom.queryAll("button[data-testid=add-to-cart]") → 14 matches' },
  { kind: 'result', text: 'Selector coverage OK. Proceeding to scroll-depth sampling.' },
  { kind: 'thought', text: 'p95 latency anomalous on /checkout/shipping — hypothesis: un-bundled polyfill.' },
  { kind: 'tool', text: 'net.har.capture({ duration: 12s }) → 214 requests, 3.2 MB' },
  { kind: 'result', text: 'HAR archived → s3://omni-traces/q3/checkout.har' },
  { kind: 'thought', text: 'Funnel drop-off concentrated at payment step (-38%). Correlating with edge logs.' },
  { kind: 'tool', text: 'vision.analyze(screencast) → layout-shift score 0.31 (threshold 0.1)' },
  { kind: 'result', text: 'Root cause candidate: late-loading payment iframe pushing CTA below fold.' },
  { kind: 'thought', text: 'Drafting remediation: preconnect + skeleton placeholder for iframe host.' },
  { kind: 'tool', text: 'kb.search("iframe layout shift") → 3 playbooks, top match confidence 0.92' },
  { kind: 'result', text: 'Playbook PB-118 attached to report draft. Scheduling verification pass.' },
];

/* -------------------------------------------------------------------------- */
/* Initial node data factories                                                 */
/* -------------------------------------------------------------------------- */

function initialBrowserData(): BrowserNodeData {
  return {
    url: NAV_URLS[0].url,
    title: NAV_URLS[0].title,
    status: 'Browsing',
    takeover: false,
    navCount: 0,
  };
}

function initialAnalystData(): AnalystNodeData {
  const seed: Thought[] = [
    { id: 'seed-1', ts: 0, kind: 'thought', text: 'Booting analyst runtime · attaching CDP listener to browser-1…' },
    { id: 'seed-2', ts: 0, kind: 'result', text: 'Attached. Objective queue: 1 task — audit Q3 checkout funnel.' },
  ];
  return { status: 'Reasoning', thoughts: seed, tokens: 12840, model: 'omni-core-70b' };
}

function initialDashboardData(): DashboardNodeData {
  const rng = mulberry32(1337);
  const N = 26;
  const sessions: number[] = [];
  const errors: number[] = [];
  let s = 58;
  let e = 14;
  for (let i = 0; i < N; i++) {
    s = Math.min(94, Math.max(22, s + (rng() - 0.46) * 14));
    e = Math.min(40, Math.max(4, e + (rng() - 0.52) * 7));
    sessions.push(Math.round(s));
    errors.push(Math.round(e));
  }
  const xLabels = Array.from({ length: N }, (_, i) => `T-${N - 1 - i}`);

  return {
    events: 0,
    schema: {
      title: 'Q3 Checkout Funnel',
      kpis: [
        { id: 'k1', label: 'Sessions', value: '48.2K', delta: '+12.4%', good: true },
        { id: 'k2', label: 'Conv. Rate', value: '3.68%', delta: '+0.8pt', good: true },
        { id: 'k3', label: 'p95 Latency', value: '812ms', delta: '-62ms', good: true },
        { id: 'k4', label: 'Captcha Hits', value: '126', delta: '+9', good: false },
      ],
      charts: [
        {
          id: 'c1',
          type: 'line',
          title: 'Live Sessions vs Errors — 30s window',
          xLabels,
          series: [
            { name: 'sessions', color: '#22d3ee', data: sessions },
            { name: 'errors', color: '#fb7185', data: errors },
          ],
        },
        {
          id: 'c2',
          type: 'bar',
          title: 'Task Success by Channel (%)',
          xLabels: ['organic', 'ads', 'social', 'email', 'direct'],
          series: [{ name: 'success', color: '#34d399', data: [82, 74, 68, 91, 77] }],
        },
      ],
    },
  };
}

/* -------------------------------------------------------------------------- */
/* Initial graph                                                               */
/* -------------------------------------------------------------------------- */

function edgeStyle(color: string) {
  return {
    style: { stroke: color, strokeWidth: 1.8 },
    markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
    labelStyle: {
      fill: color,
      fontFamily: 'monospace',
      fontSize: 9,
      letterSpacing: '0.08em',
    },
    labelBgStyle: {
      fill: 'rgba(7, 11, 21, 0.92)',
      stroke: color,
      strokeWidth: 0.75,
      strokeOpacity: 0.4,
    },
    labelBgPadding: [7, 3] as [number, number],
    labelBgBorderRadius: 4,
  };
}

/** Builds a pristine copy of the mock Browser → Analyst → Dashboard flow */
export function buildInitialFlow(): { nodes: OmniNode[]; edges: Edge[] } {
  const nodes: OmniNode[] = [
    {
      id: BROWSER_NODE_ID,
      type: 'browser',
      position: { x: 0, y: 90 },
      data: initialBrowserData(),
    },
    {
      id: ANALYST_NODE_ID,
      type: 'analyst',
      position: { x: 430, y: 40 },
      data: initialAnalystData(),
    },
    {
      id: DASHBOARD_NODE_ID,
      type: 'dashboard',
      position: { x: 850, y: 0 },
      data: initialDashboardData(),
    },
  ];

  const edges: Edge[] = [
    {
      id: 'e-browser-analyst',
      source: BROWSER_NODE_ID,
      target: ANALYST_NODE_ID,
      animated: true,
      label: 'cdp screencast',
      ...edgeStyle('#22d3ee'),
    },
    {
      id: 'e-analyst-dashboard',
      source: ANALYST_NODE_ID,
      target: DASHBOARD_NODE_ID,
      animated: true,
      label: 'structured insights',
      ...edgeStyle('#e879f9'),
    },
  ];

  return { nodes, edges };
}
