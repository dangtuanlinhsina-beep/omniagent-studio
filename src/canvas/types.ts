import type { Node } from '@xyflow/react';

/* -------------------------------------------------------------------------- */
/* Browser node                                                                */
/* -------------------------------------------------------------------------- */

export type BrowserStatus = 'Browsing' | 'CaptchaDetected' | 'Paused';

export type BrowserNodeData = {
  /** Target URL currently loaded in the simulated browser */
  url: string;
  /** Human friendly page title */
  title: string;
  status: BrowserStatus;
  /** Whether a human operator has taken over control of the session */
  takeover: boolean;
  /** Monotonic counter of navigations performed (drives screencast hue) */
  navCount: number;
} & Record<string, unknown>;

export type BrowserNodeType = Node<BrowserNodeData, 'browser'>;

/* -------------------------------------------------------------------------- */
/* Analyst node                                                                */
/* -------------------------------------------------------------------------- */

export type AnalystStatus = 'Reasoning' | 'ToolCall' | 'Idle' | 'Done';

export type ThoughtKind = 'thought' | 'tool' | 'result' | 'warning';

export type Thought = {
  id: string;
  /** epoch ms — 0 for seeded mock entries (time chip hidden) */
  ts: number;
  kind: ThoughtKind;
  text: string;
};

export type AnalystNodeData = {
  status: AnalystStatus;
  thoughts: Thought[];
  /** fake token budget consumed — incremented by the runtime */
  tokens: number;
  model: string;
} & Record<string, unknown>;

export type AnalystNodeType = Node<AnalystNodeData, 'analyst'>;

/* -------------------------------------------------------------------------- */
/* Dashboard node                                                              */
/* -------------------------------------------------------------------------- */

export type KpiCard = {
  id: string;
  label: string;
  value: string;
  delta: string;
  /** true → render delta in emerald, false → rose */
  good: boolean;
};

export type ChartSeries = {
  name: string;
  color: string;
  data: number[];
};

export type ChartSpec = {
  id: string;
  type: 'line' | 'bar';
  title: string;
  xLabels: string[];
  series: ChartSeries[];
};

/**
 * Schema JSON — DashboardNode auto-renders whatever it receives here:
 * KPI cards first, then one ECharts instance per ChartSpec.
 */
export type DashboardSchema = {
  title: string;
  kpis: KpiCard[];
  charts: ChartSpec[];
};

export type DashboardNodeData = {
  schema: DashboardSchema;
  /** live "events/min" counter shown in the node header */
  events: number;
} & Record<string, unknown>;

export type DashboardNodeType = Node<DashboardNodeData, 'dashboard'>;

/* -------------------------------------------------------------------------- */
/* Unions                                                                      */
/* -------------------------------------------------------------------------- */

export type OmniNode = BrowserNodeType | AnalystNodeType | DashboardNodeType;

export type InsertableNodeKind = 'browser' | 'analyst' | 'dashboard';
