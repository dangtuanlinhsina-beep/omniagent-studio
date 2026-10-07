'use client';

import * as echarts from 'echarts';
import { useEffect, useRef } from 'react';

/**
 * Minimal ECharts wrapper:
 * - init/dispose lifecycle tied to the container div
 * - auto-resize via ResizeObserver
 * - setOption (notMerge) on every option identity change
 */
export function EChart({
  option,
  className,
  style,
}: {
  option: echarts.EChartsOption;
  className?: string;
  style?: React.CSSProperties;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const chartRef = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const chart = echarts.init(el);
    chartRef.current = chart;

    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(el);

    return () => {
      observer.disconnect();
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  useEffect(() => {
    chartRef.current?.setOption(option, { notMerge: true });
  }, [option]);

  return <div ref={containerRef} className={className} style={style} />;
}
