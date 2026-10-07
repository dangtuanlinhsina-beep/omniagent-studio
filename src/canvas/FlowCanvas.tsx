'use client';

import '@xyflow/react/dist/style.css';

import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Panel,
  ReactFlow,
  type EdgeTypes,
  type NodeTypes,
} from '@xyflow/react';
import { AlertCircle, MousePointer2 } from 'lucide-react';
import { AnalystNode } from '@/canvas/nodes/AnalystNode';
import { BrowserNode } from '@/canvas/nodes/BrowserNode';
import { DashboardNode } from '@/canvas/nodes/DashboardNode';
import { useAgentRuntime } from '@/canvas/hooks/useAgentRuntime';
import { useGraphStore } from '@/canvas/store/graphStore';
import type { OmniNode } from '@/canvas/types';

/* -------------------------------------------------------------------------- */
/* Static config (module scope → stable identity across renders)               */
/* -------------------------------------------------------------------------- */

const nodeTypes: NodeTypes = {
  browser: BrowserNode,
  analyst: AnalystNode,
  dashboard: DashboardNode,
} as NodeTypes;

const edgeTypes: EdgeTypes = {};

function miniMapColor(node: OmniNode) {
  switch (node.type) {
    case 'browser':
      return '#22d3ee';
    case 'analyst':
      return '#e879f9';
    default:
      return '#34d399';
  }
}

const LEGEND: { type: OmniNode['type']; label: string; color: string }[] = [
  { type: 'browser', label: 'browser', color: 'bg-cyan-400' },
  { type: 'analyst', label: 'analyst', color: 'bg-fuchsia-400' },
  { type: 'dashboard', label: 'dashboard', color: 'bg-emerald-400' },
];

/* -------------------------------------------------------------------------- */
/* FlowCanvas                                                                  */
/* -------------------------------------------------------------------------- */

export function FlowCanvas() {
  const nodes = useGraphStore((s) => s.nodes);
  const edges = useGraphStore((s) => s.edges);
  const onNodesChange = useGraphStore((s) => s.onNodesChange);
  const onEdgesChange = useGraphStore((s) => s.onEdgesChange);
  const onConnect = useGraphStore((s) => s.onConnect);

  /* drives the live simulation (thoughts / navigations / captcha / charts) */
  useAgentRuntime();

  return (
    <div className="cyber-grid vignette scanlines absolute inset-0">
      <ReactFlow
        className="omni-flow"
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        fitView
        fitViewOptions={{ padding: 0.22, maxZoom: 0.95 }}
        minZoom={0.15}
        maxZoom={2.2}
        defaultEdgeOptions={{
          animated: true,
          style: { stroke: '#22d3ee', strokeWidth: 1.8 },
        }}
        connectionLineStyle={{ stroke: '#e879f9', strokeWidth: 2 }}
        proOptions={{ hideAttribution: false }}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} color="#20304a" />

        {/* workspace breadcrumb + legend */}
        <Panel position="top-left">
          <div className="omni-panel flex flex-col gap-1.5 px-3 py-2.5">
            <div className="flex items-center gap-1.5 font-mono text-[10px] tracking-wider text-slate-400">
              <span className="text-slate-600">workspace</span>
              <span className="text-slate-700">/</span>
              <span className="text-cyan-300">q3-funnel-audit</span>
            </div>
            <div className="flex items-center gap-3 border-t border-white/5 pt-1.5">
              {LEGEND.map((l) => {
                const count = nodes.filter((n) => n.type === l.type).length;
                return (
                  <span key={l.type} className="flex items-center gap-1.5 font-mono text-[9px] text-slate-500">
                    <span className={`h-1.5 w-1.5 rounded-full ${l.color}`} />
                    {l.label}
                    <span className="text-slate-300 tabular-nums">×{count}</span>
                  </span>
                );
              })}
            </div>
          </div>
        </Panel>

        {/* interaction hints */}
        <Panel position="top-right">
          <div className="omni-panel hidden flex-col gap-1 px-3 py-2 font-mono text-[9px] tracking-wider text-slate-500 md:flex">
            <span className="flex items-center gap-1.5">
              <MousePointer2 size={9} className="text-cyan-400/80" />
              drag nodes · connect ports
            </span>
            <span className="flex items-center gap-1.5">
              <AlertCircle size={9} className="text-fuchsia-400/80" />
              scroll = zoom · del = remove
            </span>
          </div>
        </Panel>

        <Controls position="bottom-left" showInteractive={false} />
        <MiniMap
          position="bottom-right"
          pannable
          zoomable
          nodeColor={miniMapColor}
          nodeStrokeWidth={3}
          maskColor="rgba(4,7,14,0.82)"
          style={{ width: 168, height: 108 }}
        />
      </ReactFlow>
    </div>
  );
}
