'use client';

import { Handle, Position, type NodeProps } from '@xyflow/react';
import {
  AlertTriangle,
  BrainCircuit,
  Brain,
  CheckCircle2,
  CircleDashed,
  Wrench,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { NodeShell, StatusBadge } from '@/canvas/components/NodeShell';
import type { AnalystNodeData, AnalystNodeType, Thought, ThoughtKind } from '@/canvas/types';
import { cn } from '@/lib/utils';

/* -------------------------------------------------------------------------- */
/* Status → badge mapping                                                      */
/* -------------------------------------------------------------------------- */

const STATUS_META = {
  Reasoning: { tone: 'fuchsia' as const, pulse: true, icon: Brain },
  ToolCall: { tone: 'amber' as const, pulse: true, icon: Wrench },
  Done: { tone: 'emerald' as const, pulse: false, icon: CheckCircle2 },
  Idle: { tone: 'slate' as const, pulse: false, icon: CircleDashed },
} as const;

const KIND_META: Record<ThoughtKind, { icon: typeof Brain; className: string; prefix: string }> = {
  thought: { icon: Brain, className: 'text-fuchsia-300/90', prefix: '◆ think' },
  tool: { icon: Wrench, className: 'text-amber-300/90', prefix: '▸ tool ' },
  result: { icon: CheckCircle2, className: 'text-emerald-300/90', prefix: '✓ result' },
  warning: { icon: AlertTriangle, className: 'text-rose-300/90', prefix: '⚠ alert ' },
};

/* -------------------------------------------------------------------------- */
/* Thought line — typed rendering for the newest line, instant for the rest    */
/* -------------------------------------------------------------------------- */

function formatTime(ts: number) {
  if (!ts) return null;
  return new Date(ts).toLocaleTimeString('en-GB', { hour12: false });
}

function ThoughtLine({
  thought,
  typedChars,
  typing,
}: {
  thought: Thought;
  typedChars: number;
  typing: boolean;
}) {
  const meta = KIND_META[thought.kind];
  const Icon = meta.icon;
  const time = formatTime(thought.ts);
  const text = typing ? thought.text.slice(0, typedChars) : thought.text;

  return (
    <div className="group flex gap-2">
      <span className={cn('mt-[1px] shrink-0 font-mono text-[9px] uppercase tracking-wider opacity-80', meta.className)}>
        {meta.prefix}
      </span>
      <span className="min-w-0 flex-1 break-words leading-relaxed">
        <Icon size={10} className={cn('mr-1 inline-block align-[-1px]', meta.className)} />
        <span className={cn('font-mono text-[10.5px]', typing ? meta.className : 'text-slate-300/85')}>
          {text}
        </span>
        {typing && <span className="type-caret" aria-hidden />}
        {time ? (
          <span className="ml-1.5 font-mono text-[8.5px] text-slate-600 opacity-0 transition-opacity group-hover:opacity-100">
            [{time}]
          </span>
        ) : null}
      </span>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* AnalystNode                                                                 */
/* -------------------------------------------------------------------------- */

export function AnalystNode({ data }: NodeProps<AnalystNodeType>) {
  const d = data as AnalystNodeData;
  const thoughts = d.thoughts;
  const lastThought = thoughts[thoughts.length - 1];

  /*
   * Typing effect — the newest thought line animates character-by-character.
   * Progress resets via the React-endorsed "adjust state during render"
   * pattern (no setState inside effect bodies), then a low-frequency
   * interval drives the caret forward through functional updates.
   */
  const [typing, setTyping] = useState<{ id: string; chars: number; done: boolean } | null>(() =>
    lastThought
      ? { id: lastThought.id, chars: lastThought.text.length, done: true }
      : null,
  );
  const [renderedId, setRenderedId] = useState<string | null>(lastThought?.id ?? null);
  if (lastThought && lastThought.id !== renderedId) {
    setRenderedId(lastThought.id);
    setTyping({ id: lastThought.id, chars: 0, done: false });
  }

  useEffect(() => {
    if (!typing || typing.done) return;
    const target = lastThought?.text.length ?? 0;
    if (target === 0) return;
    const step = Math.max(1, Math.round(target / 48));
    const iv = setInterval(() => {
      setTyping((prev) => {
        if (!prev || prev.done || prev.id !== (lastThought?.id ?? '')) return prev;
        const chars = Math.min(prev.chars + step, target);
        return { id: prev.id, chars, done: chars >= target };
      });
    }, 16);
    return () => clearInterval(iv);
  }, [typing, lastThought]);

  /* autoscroll stream to bottom */
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [typing, thoughts.length]);

  const meta = STATUS_META[d.status];
  const tokensLabel = useMemo(() => `${(d.tokens / 1000).toFixed(1)}K`, [d.tokens]);

  return (
    <NodeShell
      accent="fuchsia"
      icon={BrainCircuit}
      title="Analyst Agent"
      subtitle={`llm · ${d.model}`}
      width={360}
      badge={<StatusBadge tone={meta.tone} label={d.status} pulse={meta.pulse} icon={meta.icon} />}
    >
      <Handle type="target" position={Position.Left} className="!border-fuchsia-300 !bg-fuchsia-900" />

      {/* LLM thought stream */}
      <div className="mb-1 flex items-center justify-between">
        <span className="font-mono text-[9px] uppercase tracking-[0.22em] text-fuchsia-200/50">
          llm thought stream
        </span>
        <span className="flex items-center gap-1 font-mono text-[8.5px] text-slate-500">
          <span className="h-1 w-1 animate-pulse rounded-full bg-fuchsia-400" />
          streaming
        </span>
      </div>

      <div
        ref={scrollRef}
        className="scrollbar-thin h-60 space-y-2 overflow-y-auto rounded-lg border border-fuchsia-400/15 bg-[#0a0612]/80 p-2.5 shadow-[inset_0_0_24px_rgba(0,0,0,0.45)]"
      >
        {thoughts.map((t, i) => {
          const isLast = i === thoughts.length - 1;
          const isActive = isLast && typing?.id === t.id && !typing.done;
          return (
            <ThoughtLine
              key={t.id}
              thought={t}
              typedChars={isActive ? (typing?.chars ?? t.text.length) : t.text.length}
              typing={Boolean(isActive)}
            />
          );
        })}
        {d.status === 'Idle' && thoughts.length === 0 && (
          <div className="font-mono text-[10px] text-slate-600">— stream idle —</div>
        )}
      </div>

      {/* footer telemetry */}
      <div className="mt-2.5 flex items-center justify-between font-mono text-[9px] text-slate-500">
        <span>
          tokens <span className="text-fuchsia-300/90 tabular-nums">{tokensLabel}</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-1 w-1 rounded-full bg-emerald-400/80" />
          ctx 32K
        </span>
        <span className="text-slate-600">temp 0.2</span>
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!border-fuchsia-300 !bg-fuchsia-900"
      />
    </NodeShell>
  );
}

export type { AnalystNodeType };
