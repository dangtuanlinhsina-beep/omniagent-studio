'use client';

import { BarChart3, BrainCircuit, Globe, Hexagon, LogOut, Pause, Play, Plus, RotateCcw } from 'lucide-react';
import { useGraphStore } from '@/canvas/store/graphStore';
import type { InsertableNodeKind } from '@/canvas/types';
import type { Role } from '@/lib/ws/protocol';
import { cn } from '@/lib/utils';

const INSERTABLE: { kind: InsertableNodeKind; icon: typeof Globe; label: string }[] = [
  { kind: 'browser', icon: Globe, label: 'Browser' },
  { kind: 'analyst', icon: BrainCircuit, label: 'Analyst' },
  { kind: 'dashboard', icon: BarChart3, label: 'Dashboard' },
];

type TopBarProps = {
  role: Role | null;
  onLogout: () => void;
};

export function TopBar({ role, onLogout }: TopBarProps) {
  const running = useGraphStore((s) => s.running);
  const toggleRunning = useGraphStore((s) => s.toggleRunning);
  const resetFlow = useGraphStore((s) => s.resetFlow);
  const addNode = useGraphStore((s) => s.addNode);

  return (
    <header className="relative z-20 flex h-14 shrink-0 items-center gap-3 border-b border-cyan-400/15 bg-[#070b14]/92 px-3 backdrop-blur-md sm:px-4">
      {/* Brand */}
      <div className="flex items-center gap-2.5">
        <div className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-300/30 bg-gradient-to-br from-cyan-400/20 via-slate-900 to-fuchsia-500/20 text-cyan-300 shadow-[0_0_18px_rgba(34,211,238,0.18)]">
          <Hexagon size={18} strokeWidth={2.2} />
          <span className="absolute inset-0 rounded-lg border border-white/5" />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-bold tracking-wide text-slate-100">
            OmniAgent <span className="text-cyan-300">Studio</span>
          </div>
          <div className="hidden font-mono text-[8.5px] uppercase tracking-[0.32em] text-slate-500 sm:block">
            visual agent runtime
          </div>
        </div>
      </div>

      <div className="mx-1 hidden h-7 w-px bg-slate-700/50 md:block" />

      {/* Session pill */}
      <div className="hidden items-center gap-2 rounded-full border border-slate-700/60 bg-slate-900/60 px-3 py-1.5 md:flex">
        <span className="glow-breathe h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.9)]" />
        <span className="font-mono text-[10px] tracking-wider text-slate-400">
          session <span className="text-slate-200">authenticated</span>
        </span>
      </div>

      <div className="ml-auto flex items-center gap-1.5 sm:gap-2">
        {/* Insert node group */}
        <div className="hidden items-center gap-1 rounded-lg border border-slate-700/60 bg-slate-900/50 p-1 lg:flex">
          <Plus size={12} className="mx-1 text-slate-500" />
          {INSERTABLE.map(({ kind, icon: Icon, label }) => (
            <button
              key={kind}
              type="button"
              title={`Insert ${label} node`}
              aria-label={`Insert ${label} node`}
              onClick={() => addNode(kind)}
              className="flex h-7 items-center gap-1.5 rounded-md px-2 text-[10px] font-medium text-slate-400 transition-colors hover:bg-cyan-400/10 hover:text-cyan-300"
            >
              <Icon size={12} />
              <span className="hidden xl:inline">{label}</span>
            </button>
          ))}
        </div>

        {/* Reset */}
        <button
          type="button"
          title="Reset workspace"
          aria-label="Reset workspace"
          onClick={resetFlow}
          className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-700/60 bg-slate-900/50 text-slate-400 transition-colors hover:border-rose-400/40 hover:text-rose-300"
        >
          <RotateCcw size={13} />
        </button>

        {/* Authenticated identity and logout */}
        <span className="hidden rounded-md border border-emerald-400/20 bg-emerald-400/5 px-2 py-1 font-mono text-[9px] uppercase tracking-wider text-emerald-300 sm:inline">
          {role ?? 'SESSION'}
        </span>
        <button
          type="button"
          title="Sign out"
          aria-label="Sign out"
          onClick={onLogout}
          className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-700/60 bg-slate-900/50 text-slate-400 transition-colors hover:border-rose-400/40 hover:text-rose-300"
        >
          <LogOut size={13} />
        </button>

        {/* Run / Pause */}
        <button
          type="button"
          onClick={toggleRunning}
          className={cn(
            'flex h-8 items-center gap-2 rounded-lg border px-3 font-mono text-[10px] font-bold uppercase tracking-[0.18em] transition-all',
            running
              ? 'border-fuchsia-400/40 bg-fuchsia-400/10 text-fuchsia-300 hover:bg-fuchsia-400/20'
              : 'border-cyan-400/40 bg-cyan-400/10 text-cyan-300 hover:bg-cyan-400/20',
          )}
        >
          {running ? <Pause size={12} /> : <Play size={12} />}
          <span className="hidden sm:inline">{running ? 'Pause' : 'Resume'}</span>
        </button>
      </div>
    </header>
  );
}
