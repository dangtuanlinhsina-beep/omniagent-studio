'use client';

import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

/* -------------------------------------------------------------------------- */
/* Accent tokens — static class strings so Tailwind can statically extract     */
/* -------------------------------------------------------------------------- */

export type AccentKey = 'cyan' | 'fuchsia' | 'emerald';

export const ACCENTS: Record<
  AccentKey,
  {
    chip: string;
    corner: string;
    text: string;
    titleBar: string;
    subText: string;
  }
> = {
  cyan: {
    chip: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300',
    corner: 'border-cyan-300/50',
    text: 'text-cyan-300',
    titleBar: 'from-cyan-400/15',
    subText: 'text-cyan-100/60',
  },
  fuchsia: {
    chip: 'border-fuchsia-400/30 bg-fuchsia-400/10 text-fuchsia-300',
    corner: 'border-fuchsia-300/50',
    text: 'text-fuchsia-300',
    titleBar: 'from-fuchsia-400/15',
    subText: 'text-fuchsia-100/60',
  },
  emerald: {
    chip: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
    corner: 'border-emerald-300/50',
    text: 'text-emerald-300',
    titleBar: 'from-emerald-400/15',
    subText: 'text-emerald-100/60',
  },
};

/* -------------------------------------------------------------------------- */
/* CornerBrackets — sci-fi targeting brackets on the 4 node corners            */
/* -------------------------------------------------------------------------- */

export function CornerBrackets({ className }: { className?: string }) {
  return (
    <>
      <span
        aria-hidden
        className={cn('pointer-events-none absolute left-0 top-0 h-3 w-3 rounded-tl-[11px] border-l-2 border-t-2', className)}
      />
      <span
        aria-hidden
        className={cn('pointer-events-none absolute right-0 top-0 h-3 w-3 rounded-tr-[11px] border-r-2 border-t-2', className)}
      />
      <span
        aria-hidden
        className={cn('pointer-events-none absolute bottom-0 left-0 h-3 w-3 rounded-bl-[11px] border-b-2 border-l-2', className)}
      />
      <span
        aria-hidden
        className={cn('pointer-events-none absolute bottom-0 right-0 h-3 w-3 rounded-br-[11px] border-b-2 border-r-2', className)}
      />
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* StatusBadge — pill with pulsing dot, used by every node header              */
/* -------------------------------------------------------------------------- */

type BadgeTone = 'cyan' | 'fuchsia' | 'emerald' | 'amber' | 'rose' | 'slate';

export const BADGE_TONES: Record<BadgeTone, string> = {
  cyan: 'border-cyan-400/35 bg-cyan-400/10 text-cyan-300',
  fuchsia: 'border-fuchsia-400/35 bg-fuchsia-400/10 text-fuchsia-300',
  emerald: 'border-emerald-400/35 bg-emerald-400/10 text-emerald-300',
  amber: 'border-amber-400/35 bg-amber-400/10 text-amber-300',
  rose: 'border-rose-400/35 bg-rose-400/10 text-rose-300',
  slate: 'border-slate-500/35 bg-slate-500/10 text-slate-400',
};

export function StatusBadge({
  tone,
  label,
  pulse = false,
  icon: Icon,
}: {
  tone: BadgeTone;
  label: string;
  pulse?: boolean;
  icon?: LucideIcon;
}) {
  return (
    <span
      className={cn(
        'inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-[0.14em]',
        BADGE_TONES[tone],
      )}
    >
      <span className="relative flex h-1.5 w-1.5">
        {pulse && (
          <span
            className={cn(
              'absolute inline-flex h-full w-full animate-ping rounded-full opacity-60',
              tone === 'cyan' && 'bg-cyan-400',
              tone === 'fuchsia' && 'bg-fuchsia-400',
              tone === 'emerald' && 'bg-emerald-400',
              tone === 'amber' && 'bg-amber-400',
              tone === 'rose' && 'bg-rose-400',
              tone === 'slate' && 'bg-slate-400',
            )}
          />
        )}
        <span
          className={cn(
            'relative inline-flex h-1.5 w-1.5 rounded-full',
            tone === 'cyan' && 'bg-cyan-400',
            tone === 'fuchsia' && 'bg-fuchsia-400',
            tone === 'emerald' && 'bg-emerald-400',
            tone === 'amber' && 'bg-amber-400',
            tone === 'rose' && 'bg-rose-400',
            tone === 'slate' && 'bg-slate-400',
          )}
        />
      </span>
      {Icon ? <Icon size={10} strokeWidth={2.5} /> : null}
      {label}
    </span>
  );
}

/* -------------------------------------------------------------------------- */
/* NodeShell — shared chrome: header (icon / title / badge) + body             */
/* -------------------------------------------------------------------------- */

export function NodeShell({
  accent,
  icon: Icon,
  title,
  subtitle,
  badge,
  width,
  alert = false,
  children,
}: {
  accent: AccentKey;
  icon: LucideIcon;
  title: string;
  subtitle?: string;
  badge?: ReactNode;
  width?: number;
  /** adds a pulsing red alert border (e.g. CaptchaDetected) */
  alert?: boolean;
  children: ReactNode;
}) {
  const a = ACCENTS[accent];
  return (
    <div
      className={cn('node-shell nodrag nopan nowheel', alert && 'node-alert')}
      style={width ? { width } : undefined}
    >
      <CornerBrackets className={a.corner} />
      <header
        className={cn(
          'flex items-center gap-2.5 rounded-t-[12px] border-b border-white/5 bg-gradient-to-r to-transparent px-3.5 py-2.5',
          a.titleBar,
        )}
      >
        <div
          className={cn(
            'flex h-7 w-7 shrink-0 items-center justify-center rounded-md border shadow-[0_0_12px_rgba(34,211,238,0.12)]',
            a.chip,
          )}
        >
          <Icon size={15} strokeWidth={2.2} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[13px] font-semibold leading-none tracking-wide text-slate-100">
            {title}
          </div>
          {subtitle ? (
            <div className={cn('mt-1 truncate font-mono text-[9px] uppercase tracking-[0.2em]', a.subText)}>
              {subtitle}
            </div>
          ) : null}
        </div>
        {badge}
      </header>
      <div className="p-3.5">{children}</div>
    </div>
  );
}
