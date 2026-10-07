'use client';

import { Handle, Position, type NodeProps } from '@xyflow/react';
import {
  Globe,
  Hand,
  Lock,
  MonitorPlay,
  MousePointerClick,
  Pause,
  ShieldAlert,
  Signal,
  Unplug,
} from 'lucide-react';
import { useEffect, useRef } from 'react';
import { NodeShell, StatusBadge } from '@/canvas/components/NodeShell';
import { useGraphStore } from '@/canvas/store/graphStore';
import { useBrowserStream } from '@/canvas/hooks/useBrowserStream';
import { EMPTY_GRAPH_STREAM, useStreamStore } from '@/canvas/store/streamStore';
import type { BrowserNodeData, BrowserNodeType, BrowserStatus } from '@/canvas/types';
import { cn } from '@/lib/utils';

/* -------------------------------------------------------------------------- */
/* Status → badge mapping                                                      */
/* -------------------------------------------------------------------------- */

const STATUS_META: Record<
  BrowserStatus,
  { tone: 'emerald' | 'amber' | 'slate'; label: string; pulse: boolean }
> = {
  Browsing: { tone: 'emerald', label: 'Browsing', pulse: true },
  CaptchaDetected: { tone: 'amber', label: 'CaptchaDetected', pulse: true },
  Paused: { tone: 'slate', label: 'Paused', pulse: false },
};

/* -------------------------------------------------------------------------- */
/* Screencast painter — draws a fake web page onto the <canvas> each frame     */
/* -------------------------------------------------------------------------- */

function hashString(s: string) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

function rr(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  ctx.beginPath();
  if (typeof ctx.roundRect === 'function') {
    ctx.roundRect(x, y, w, h, r);
  } else {
    ctx.rect(x, y, w, h);
  }
}

function drawFakePage(ctx: CanvasRenderingContext2D, w: number, h: number, seedHue: number) {
  // page background
  ctx.fillStyle = '#0c1424';
  ctx.fillRect(0, 26, w, h - 26);

  // browser chrome bar
  ctx.fillStyle = '#0a101f';
  ctx.fillRect(0, 0, w, 26);
  const dots = ['#fb7185', '#fbbf24', '#34d399'];
  dots.forEach((c, i) => {
    ctx.fillStyle = c;
    ctx.beginPath();
    ctx.arc(13 + i * 13, 13, 3.5, 0, Math.PI * 2);
    ctx.fill();
  });
  ctx.fillStyle = 'rgba(148,163,184,0.1)';
  rr(ctx, 58, 7, w - 90, 12, 6);
  ctx.fill();
  ctx.fillStyle = 'rgba(148,163,184,0.45)';
  ctx.fillRect(64, 12, 44, 2);

  // hero band
  const grad = ctx.createLinearGradient(10, 36, w - 10, 92);
  grad.addColorStop(0, `hsla(${seedHue}, 85%, 58%, 0.4)`);
  grad.addColorStop(1, `hsla(${(seedHue + 70) % 360}, 85%, 58%, 0.06)`);
  ctx.fillStyle = grad;
  rr(ctx, 10, 36, w - 20, 52, 8);
  ctx.fill();

  // hero heading + sub
  ctx.fillStyle = 'rgba(226,232,240,0.9)';
  rr(ctx, 22, 48, 118, 9, 4);
  ctx.fill();
  ctx.fillStyle = 'rgba(148,163,184,0.45)';
  rr(ctx, 22, 64, 172, 5, 2.5);
  ctx.fill();
  ctx.fillStyle = `hsla(${seedHue}, 90%, 65%, 0.85)`;
  rr(ctx, 22, 74, 64, 8, 4);
  ctx.fill();

  // two product cards
  for (let i = 0; i < 2; i++) {
    const cx = 10 + i * ((w - 26) / 2 + 6);
    const cw = (w - 26) / 2;
    ctx.fillStyle = 'rgba(148,163,184,0.08)';
    rr(ctx, cx, 98, cw, 64, 7);
    ctx.fill();
    ctx.fillStyle = `hsla(${(seedHue + i * 40) % 360}, 70%, 55%, 0.35)`;
    rr(ctx, cx + 8, 106, cw - 16, 28, 5);
    ctx.fill();
    ctx.fillStyle = 'rgba(203,213,225,0.5)';
    rr(ctx, cx + 8, 140, (cw - 16) * 0.62, 5, 2.5);
    ctx.fill();
    ctx.fillStyle = 'rgba(148,163,184,0.28)';
    rr(ctx, cx + 8, 150, (cw - 16) * 0.4, 5, 2.5);
    ctx.fill();
  }

  // list rows
  for (let i = 0; i < 2; i++) {
    const ly = 172 + i * 13;
    ctx.fillStyle = 'rgba(148,163,184,0.18)';
    rr(ctx, 10, ly, w - 20, 8, 4);
    ctx.fill();
    ctx.fillStyle = `hsla(${seedHue}, 80%, 60%, 0.5)`;
    rr(ctx, 14, ly + 2.5, 3.5, 3.5, 2);
    ctx.fill();
  }
}

function drawScanline(ctx: CanvasRenderingContext2D, w: number, h: number, t: number) {
  const sy = ((t / 14) % (h + 60)) - 30;
  const grad = ctx.createLinearGradient(0, sy - 18, 0, sy + 18);
  grad.addColorStop(0, 'rgba(34,211,238,0)');
  grad.addColorStop(0.5, 'rgba(34,211,238,0.09)');
  grad.addColorStop(1, 'rgba(34,211,238,0)');
  ctx.fillStyle = grad;
  ctx.fillRect(0, sy - 18, w, 36);
}

function drawCaptcha(ctx: CanvasRenderingContext2D, w: number, h: number, t: number) {
  ctx.fillStyle = 'rgba(2, 6, 12, 0.62)';
  ctx.fillRect(0, 0, w, h);

  const cw = 132;
  const ch = 128;
  const cx = (w - cw) / 2;
  const cy = (h - ch) / 2;

  ctx.fillStyle = '#0d1526';
  ctx.strokeStyle = 'rgba(251,113,133,0.75)';
  ctx.lineWidth = 1;
  rr(ctx, cx, cy, cw, ch, 8);
  ctx.fill();
  ctx.stroke();

  ctx.fillStyle = 'rgba(251,113,133,0.95)';
  ctx.font = 'bold 9px monospace';
  ctx.textAlign = 'center';
  ctx.fillText('VERIFY — HUMAN?', w / 2, cy + 16);

  const tile = 26;
  const gap = 4;
  const gx0 = (w - (tile * 3 + gap * 2)) / 2;
  const gy0 = cy + 26;
  const phase = Math.floor(t / 40) % 9;
  for (let i = 0; i < 9; i++) {
    const tx = gx0 + (i % 3) * (tile + gap);
    const ty = gy0 + Math.floor(i / 3) * (tile + gap);
    const active = i === phase || i === (phase + 4) % 9;
    ctx.fillStyle = active ? 'rgba(251,113,133,0.55)' : 'rgba(148,163,184,0.14)';
    rr(ctx, tx, ty, tile, tile, 4);
    ctx.fill();
  }
  ctx.fillStyle = 'rgba(148,163,184,0.5)';
  ctx.font = '7px monospace';
  ctx.fillText('solving via vision-agent…', w / 2, cy + ch - 8);
  ctx.textAlign = 'left';
}

function drawTakeoverCursor(
  ctx: CanvasRenderingContext2D,
  w: number,
  h: number,
  t: number,
  mouse: { x: number; y: number } | null,
) {
  const p = mouse ?? {
    x: w / 2 + Math.sin(t / 40) * w * 0.28,
    y: h / 2 + Math.cos(t / 55) * h * 0.24,
  };
  ctx.strokeStyle = 'rgba(232,121,249,0.85)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(p.x - 12, p.y);
  ctx.lineTo(p.x + 12, p.y);
  ctx.moveTo(p.x, p.y - 12);
  ctx.lineTo(p.x, p.y + 12);
  ctx.stroke();
  ctx.beginPath();
  ctx.arc(p.x, p.y, 7 + Math.sin(t / 18) * 1.5, 0, Math.PI * 2);
  ctx.stroke();
  ctx.fillStyle = 'rgba(232,121,249,0.95)';
  ctx.beginPath();
  ctx.arc(p.x, p.y, 1.6, 0, Math.PI * 2);
  ctx.fill();
}

function drawPausedOverlay(ctx: CanvasRenderingContext2D, w: number, h: number) {
  ctx.fillStyle = 'rgba(2, 6, 12, 0.58)';
  ctx.fillRect(0, 0, w, h);
  ctx.fillStyle = 'rgba(203,213,225,0.85)';
  ctx.font = 'bold 11px monospace';
  ctx.textAlign = 'center';
  ctx.fillText('⏸ PAUSED', w / 2, h / 2 + 4);
  ctx.textAlign = 'left';
}

/* -------------------------------------------------------------------------- */
/* BrowserNode                                                                 */
/* -------------------------------------------------------------------------- */

export function BrowserNode({ id, data }: NodeProps<BrowserNodeType>) {
  const d = data as BrowserNodeData;
  const toggleTakeover = useGraphStore((s) => s.toggleTakeover);
  const graphId = typeof d.graphId === 'string' ? d.graphId : id;
  const streamingEnabled = process.env.NEXT_PUBLIC_OMNIAGENT_STREAMING === 'true';
  const stream = useBrowserStream({
    graphId,
    enabled: streamingEnabled,
    baseUrl: process.env.NEXT_PUBLIC_OMNIAGENT_WS_BASE_URL || undefined,
  });
  const streamMeta = useStreamStore(
    (state) => (state.streams[graphId] ?? EMPTY_GRAPH_STREAM).streamMeta,
  );
  const streamHealth = useStreamStore(
    (state) => (state.streams[graphId] ?? EMPTY_GRAPH_STREAM).streamHealth,
  );
  const streamFps = useStreamStore(
    (state) => (state.streams[graphId] ?? EMPTY_GRAPH_STREAM).fps,
  );
  const liveUrl = streamMeta?.pageUrl;
  const isLive = Boolean(streamingEnabled && stream.connected && streamHealth === 'ready');
  const takeover = streamingEnabled ? stream.takeoverActive : d.takeover;
  const canTakeover = !streamingEnabled || (
    stream.connected &&
    stream.canOperate('takeover:control') &&
    !stream.takeoverBusy
  );
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const liveImageRef = useRef<HTMLImageElement | null>(null);
  const takeoverRef = useRef(false);
  const mouseRef = useRef<{ x: number; y: number } | null>(null);
  const stateRef = useRef(d);
  useEffect(() => {
    stateRef.current = d;
  }, [d]);
  useEffect(() => {
    const syncImage = (state: ReturnType<typeof useStreamStore.getState>) => {
      liveImageRef.current = state.streams[graphId]?.liveImage ?? null;
    };
    syncImage(useStreamStore.getState());
    return useStreamStore.subscribe((state) => syncImage(state));
  }, [graphId]);
  useEffect(() => {
    takeoverRef.current = takeover;
  }, [takeover]);

  // Input listeners are attached only when the server has granted both the
  // operator permission and the active single-holder takeover lease.
  useEffect(() => {
    if (
      !stream.connected ||
      !stream.takeoverActive ||
      !stream.canOperate('input:send')
    ) return;
    return stream.attachCanvas(canvasRef.current);
  }, [stream.attachCanvas, stream.canOperate, stream.connected, stream.takeoverActive]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let raf = 0;
    const render = (t: number) => {
      const s = stateRef.current;
      const w = canvas.width;
      const h = canvas.height;

      ctx.save();
      ctx.scale(2, 2); // internal resolution @2x — CSS scales down
      const W = w / 2;
      const H = h / 2;

      const frame = liveImageRef.current;
      if (frame) {
        ctx.fillStyle = '#0c1424';
        ctx.fillRect(0, 0, W, H);
        ctx.drawImage(frame, 0, 0, W, H);
      } else {
        const seedHue = hashString(s.url) % 360;
        drawFakePage(ctx, W, H, seedHue + s.navCount * 47);
        drawScanline(ctx, W, H, t);

        if (s.status === 'CaptchaDetected') drawCaptcha(ctx, W, H, t);
        else if (s.status === 'Paused') drawPausedOverlay(ctx, W, H);
        if (takeoverRef.current) drawTakeoverCursor(ctx, W, H, t, mouseRef.current);
      }

      ctx.restore();
      raf = requestAnimationFrame(render);
    };

    raf = requestAnimationFrame(render);
    return () => cancelAnimationFrame(raf);
  }, []);

  const meta = STATUS_META[d.status];
  const isAlert = d.status === 'CaptchaDetected';

  return (
    <NodeShell
      accent="cyan"
      icon={Globe}
      title={d.title}
      subtitle="remote browser session"
      width={370}
      alert={isAlert}
      badge={
        <StatusBadge
          tone={meta.tone}
          label={meta.label}
          pulse={meta.pulse}
          icon={d.status === 'CaptchaDetected' ? ShieldAlert : d.status === 'Paused' ? Pause : undefined}
        />
      }
    >
      <Handle type="source" position={Position.Right} className="!border-cyan-300 !bg-cyan-900" />

      {/* URL bar */}
      <div className="mb-2.5 flex items-center gap-2 rounded-lg border border-cyan-400/20 bg-[#0a101f]/80 px-2.5 py-1.5">
        <Lock size={10} className="shrink-0 text-emerald-400/80" />
        <span className="truncate font-mono text-[10.5px] text-cyan-200/90">{liveUrl || d.url}</span>
        <span className="ml-auto flex shrink-0 items-center gap-1 font-mono text-[9px] text-slate-500">
          <Signal size={9} className={cn(streamHealth === 'ready' ? 'text-emerald-400/70' : 'text-slate-500')} />
          {isLive ? `${streamFps} fps` : 'mock feed'}
        </span>
      </div>
      {d.status === 'Browsing' && !takeover && (
        <div className="relative -mt-2.5 mb-2 h-[2px] overflow-hidden rounded-full bg-slate-800/50">
          <div className="url-progress h-full rounded-full bg-gradient-to-r from-cyan-400 to-fuchsia-400" />
        </div>
      )}

      {/* Screencast canvas */}
      <div className="relative overflow-hidden rounded-lg border border-slate-700/60 bg-[#0a101f] shadow-[inset_0_0_24px_rgba(0,0,0,0.5)]">
        <canvas
          ref={canvasRef}
          width={680}
          height={400}
          className={cn('nodrag nopan block h-[186px] w-full touch-none outline-none', takeover ? 'cursor-none' : 'cursor-crosshair')}
          onMouseMove={(e) => {
            const rect = e.currentTarget.getBoundingClientRect();
            const scaleX = e.currentTarget.width / 2 / rect.width;
            const scaleY = e.currentTarget.height / 2 / rect.height;
            mouseRef.current = {
              x: (e.clientX - rect.left) * scaleX,
              y: (e.clientY - rect.top) * scaleY,
            };
          }}
          onMouseLeave={() => {
            mouseRef.current = null;
          }}
          aria-label="Browser screencast stream"
          role="img"
        />
        {/* stream chrome */}
        <div className="pointer-events-none absolute left-2 top-2 flex items-center gap-1.5 rounded bg-black/55 px-1.5 py-0.5 font-mono text-[8.5px] uppercase tracking-[0.16em] text-slate-300 backdrop-blur-sm">
          <MonitorPlay size={9} className="text-cyan-300" />
          {takeover ? 'human takeover' : isLive ? 'live browser' : 'agent feed'}
        </div>
        <div className="pointer-events-none absolute right-2 top-2 rounded bg-black/55 px-1.5 py-0.5 font-mono text-[8.5px] text-rose-300 backdrop-blur-sm">
          <span className={cn('mr-1 inline-block h-1.5 w-1.5 rounded-full align-middle', isLive ? 'animate-pulse bg-rose-400' : 'bg-slate-500')} />
          {streamingEnabled ? streamHealth.toUpperCase() : 'MOCK'}
        </div>
      </div>

      {/* Takeover toggle */}
      <button
        type="button"
        onClick={() => {
          if (!canTakeover) return;
          if (streamingEnabled) {
            if (stream.connected) stream.setTakeover(!stream.takeoverActive);
          } else {
            toggleTakeover(id);
          }
        }}
        disabled={!canTakeover}
        title={
          stream.takeoverBusy
            ? `Control is held by ${stream.takeoverHolder ?? 'another operator'}`
            : !canTakeover
              ? 'Operator permission and an open stream are required'
              : undefined
        }
        aria-pressed={takeover}
        className={cn(
          'mt-3 flex h-9 w-full items-center justify-center gap-2 rounded-lg border font-mono text-[10px] font-bold uppercase tracking-[0.2em] transition-all active:scale-[0.98]',
          takeover
            ? 'border-fuchsia-400/50 bg-fuchsia-400/15 text-fuchsia-200 shadow-[0_0_20px_rgba(232,121,249,0.18)] hover:bg-fuchsia-400/25'
            : 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200 hover:bg-cyan-400/20',
          !canTakeover && 'cursor-not-allowed opacity-50',
        )}
      >
        {takeover ? <Unplug size={13} /> : <MousePointerClick size={13} />}
        {streamingEnabled && stream.takeoverBusy
          ? 'Control in use'
          : takeover
            ? 'Release control'
            : 'Takeover control'}
        <Hand size={12} className={cn('opacity-60', takeover && 'hidden')} />
      </button>
    </NodeShell>
  );
}

export type { BrowserNodeType };
