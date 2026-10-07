'use client';

import { Handle, Position, type NodeProps } from '@xyflow/react';
import * as echarts from 'echarts';
import { ArrowDownRight, ArrowUpRight, BarChart3, LayoutDashboard } from 'lucide-react';
import { useMemo } from 'react';
import { EChart } from '@/canvas/components/EChart';
import { NodeShell } from '@/canvas/components/NodeShell';
import type { ChartSpec, DashboardNodeData, DashboardNodeType, KpiCard } from '@/canvas/types';
import { cn } from '@/lib/utils';

/* -------------------------------------------------------------------------- */
/* ECharts option builders                                                     */
/* -------------------------------------------------------------------------- */

const AXIS_LABEL = { color: '#64748b', fontSize: 9, fontFamily: 'monospace' };
const TOOLTIP_STYLE = {
  backgroundColor: 'rgba(8,12,22,0.94)',
  borderColor: 'rgba(148,163,184,0.25)',
  borderWidth: 1,
  textStyle: { color: '#e2e8f0', fontSize: 10, fontFamily: 'monospace' },
};

function rgba(hex: string, alpha: number) {
  const v = hex.replace('#', '');
  const r = parseInt(v.slice(0, 2), 16);
  const g = parseInt(v.slice(2, 4), 16);
  const b = parseInt(v.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

function buildLineOption(chart: ChartSpec): echarts.EChartsOption {
  return {
    backgroundColor: 'transparent',
    animationDuration: 300,
    animationDurationUpdate: 350,
    grid: { left: 6, right: 10, top: 12, bottom: 2, containLabel: true },
    tooltip: { trigger: 'axis', ...TOOLTIP_STYLE },
    legend: {
      show: chart.series.length > 1,
      top: 0,
      right: 0,
      icon: 'roundRect',
      itemWidth: 8,
      itemHeight: 3,
      textStyle: { color: '#94a3b8', fontSize: 9, fontFamily: 'monospace' },
    },
    xAxis: {
      type: 'category',
      data: chart.xLabels,
      axisLine: { lineStyle: { color: 'rgba(148,163,184,0.22)' } },
      axisTick: { show: false },
      axisLabel: AXIS_LABEL,
      boundaryGap: false,
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: 'rgba(148,163,184,0.08)' } },
      axisLabel: AXIS_LABEL,
    },
    series: chart.series.map((s) => ({
      name: s.name,
      type: 'line' as const,
      data: s.data,
      smooth: true,
      symbol: 'none',
      lineStyle: { width: 2, color: s.color, shadowColor: rgba(s.color, 0.5), shadowBlur: 8 },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: rgba(s.color, 0.28) },
          { offset: 1, color: rgba(s.color, 0) },
        ]),
      },
    })),
  };
}

function buildBarOption(chart: ChartSpec): echarts.EChartsOption {
  return {
    backgroundColor: 'transparent',
    animationDuration: 500,
    grid: { left: 6, right: 10, top: 14, bottom: 2, containLabel: true },
    tooltip: { trigger: 'axis', ...TOOLTIP_STYLE },
    xAxis: {
      type: 'category',
      data: chart.xLabels,
      axisLine: { lineStyle: { color: 'rgba(148,163,184,0.22)' } },
      axisTick: { show: false },
      axisLabel: AXIS_LABEL,
    },
    yAxis: {
      type: 'value',
      max: 100,
      splitLine: { lineStyle: { color: 'rgba(148,163,184,0.08)' } },
      axisLabel: AXIS_LABEL,
    },
    series: chart.series.map((s) => ({
      name: s.name,
      type: 'bar' as const,
      data: s.data,
      barWidth: '46%',
      itemStyle: {
        borderRadius: [4, 4, 0, 0],
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: s.color },
          { offset: 1, color: rgba(s.color, 0.25) },
        ]),
      },
      emphasis: { itemStyle: { shadowBlur: 12, shadowColor: rgba(s.color, 0.6) } },
    })),
  };
}

/* -------------------------------------------------------------------------- */
/* KPI card                                                                    */
/* -------------------------------------------------------------------------- */

function Kpi({ kpi }: { kpi: KpiCard }) {
  return (
    <div className="rounded-lg border border-slate-700/50 bg-[#0a101f]/70 px-2.5 py-2 transition-colors hover:border-emerald-400/30">
      <div className="truncate font-mono text-[8.5px] uppercase tracking-[0.18em] text-slate-500">
        {kpi.label}
      </div>
      <div className="mt-1 flex items-baseline justify-between gap-1">
        <span className="text-[15px] font-semibold tabular-nums text-slate-100">{kpi.value}</span>
        <span
          className={cn(
            'flex items-center gap-0.5 font-mono text-[9px] tabular-nums',
            kpi.good ? 'text-emerald-400' : 'text-rose-400',
          )}
        >
          {kpi.good ? <ArrowUpRight size={9} /> : <ArrowDownRight size={9} />}
          {kpi.delta}
        </span>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* DashboardNode                                                               */
/* -------------------------------------------------------------------------- */

export function DashboardNode({ data }: NodeProps<DashboardNodeType>) {
  const d = data as DashboardNodeData;
  const { schema, events } = d;

  const chartOptions = useMemo(
    () =>
      schema.charts.map((chart) => ({
        chart,
        option: chart.type === 'line' ? buildLineOption(chart) : buildBarOption(chart),
      })),
    [schema],
  );

  return (
    <NodeShell
      accent="emerald"
      icon={LayoutDashboard}
      title="Dashboard Renderer"
      subtitle={`auto-layout · ${schema.title}`}
      width={520}
      badge={
        <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-emerald-400/35 bg-emerald-400/10 px-2 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-[0.14em] text-emerald-300">
          <BarChart3 size={10} />
          {events}/min
        </span>
      }
    >
      <Handle type="target" position={Position.Left} className="!border-emerald-300 !bg-emerald-900" />

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {schema.kpis.map((kpi) => (
          <Kpi key={kpi.id} kpi={kpi} />
        ))}
      </div>

      {/* Auto-rendered charts */}
      <div className="mt-3 space-y-3">
        {chartOptions.map(({ chart, option }) => (
          <section
            key={chart.id}
            className="overflow-hidden rounded-lg border border-slate-700/50 bg-[#0a101f]/70"
          >
            <header className="flex items-center justify-between border-b border-white/5 px-2.5 py-1.5">
              <h4 className="font-mono text-[9px] uppercase tracking-[0.18em] text-slate-400">
                {chart.title}
              </h4>
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{ backgroundColor: chart.series[0]?.color ?? '#34d399' }}
              />
            </header>
            <EChart
              option={option}
              className={cn('w-full', chart.type === 'line' ? 'h-44' : 'h-40')}
            />
          </section>
        ))}
      </div>
    </NodeShell>
  );
}

export type { DashboardNodeType };
