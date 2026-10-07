'use client';

import { Cpu, GitBranch, Network, Timer, Zap } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useGraphStore } from '@/canvas/store/graphStore';

export function StatusBar() {
  const nodes = useGraphStore((s) => s.nodes.length);
  const edges = useGraphStore((s) => s.edges.length);
  const ticks = useGraphStore((s) => s.ticks);
  const running = useGraphStore((s) => s.running);

  const [clock, setClock] = useState('--:--:--');
  const [latency, setLatency] = useState(24);

  useEffect(() => {
    const clockIv = setInterval(() => setClock(new Date().toLocaleTimeString('en-GB')), 1000);
    const latencyIv = setInterval(() => setLatency(16 + Math.round(Math.random() * 26)), 2000);
    return () => {
      clearInterval(clockIv);
      clearInterval(latencyIv);
    };
  }, []);

  return (
    <footer
      role="contentinfo"
      className="mt-auto flex h-8 shrink-0 items-center justify-between gap-3 border-t border-cyan-400/15 bg-[#05070d]/95 px-3 font-mono text-[10px] tracking-wider text-slate-500 sm:px-4"
    >
      <div className="flex min-w-0 items-center gap-2">
        <span
          className={`h-1.5 w-1.5 shrink-0 rounded-full ${
            running
              ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.9)]'
              : 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.9)]'
          }`}
        />
        <span className={running ? 'text-emerald-400' : 'text-amber-400'}>
          RUNTIME {running ? 'ACTIVE' : 'HALTED'}
        </span>
        <span className="hidden text-slate-700 md:inline">│</span>
        <span className="hidden items-center gap-1 md:flex">
          <Cpu size={10} className="text-slate-600" /> sim-agent v0.3.0
        </span>
        <span className="hidden text-slate-700 lg:inline">│</span>
        <span className="hidden items-center gap-1 text-cyan-500/80 lg:flex">
          <Network size={10} /> CDP bridge OK
        </span>
      </div>

      <div className="flex items-center gap-2 sm:gap-3">
        <span className="flex items-center gap-1">
          <GitBranch size={10} className="text-slate-600" />
          {nodes} nodes · {edges} edges
        </span>
        <span className="hidden text-slate-700 sm:inline">│</span>
        <span className="hidden items-center gap-1 sm:flex">
          <Zap size={10} className="text-slate-600" /> {ticks} ticks
        </span>
        <span className="text-slate-700">│</span>
        <span className="flex items-center gap-1 text-slate-400">
          <Timer size={10} className="text-slate-600" /> {latency}ms
        </span>
        <span className="text-slate-400">{clock}</span>
      </div>
    </footer>
  );
}
