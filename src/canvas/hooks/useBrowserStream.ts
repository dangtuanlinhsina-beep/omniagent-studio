'use client';

/**
 * Wires the authenticated WebSocket stream to the canvas.
 *
 * Lifecycle: mount → `requestWsTicket(graphId)` (BFF) → `new WebSocket(url,
 * ["omniagent.v1", ticket])` → `SESSION_READY` (role/permissions) → frames.
 * The hook owns throttling, heartbeat, credential refresh and reconnects; the
 * UI only consumes the derived snapshot from `useStreamStore`.
 *
 * `enabled: false` (or no `graphId`) keeps the app in mock mode: nothing is
 * opened and the store stays empty, so the simulated canvas keeps running.
 */

import { useCallback, useEffect, useMemo, useRef } from 'react';

import { EMPTY_GRAPH_STREAM, useStreamStore } from '@/canvas/store/streamStore';
import { requestWsTicket, refreshSession } from '@/lib/auth/client';
import {
  can,
  ServerMessageType,
  type KeyboardPayload,
  type MouseButton,
  type Permission,
  type Role,
  type ScreenFrame,
  type ServerEnvelope,
} from '@/lib/ws/protocol';
import { OmniAgentSocket, type SocketPhase, type WsTicket } from '@/lib/ws/wsClient';

export type UseBrowserStreamOptions = {
  /** Graph id the ticket is bound to. `null` disables the stream. */
  graphId: string | null;
  /** Kill switch (e.g. only stream for the focused node). */
  enabled?: boolean;
  /** WS origin override; defaults to the current origin (reverse proxy). */
  baseUrl?: string;
};

export type UseBrowserStreamResult = {
  connected: boolean;
  phase: SocketPhase;
  role: Role | null;
  canOperate: (permission: Permission) => boolean;
  /** True only when this connection (not merely someone in the graph) holds the lease. */
  takeoverActive: boolean;
  takeoverHolder: string | null;
  takeoverBusy: boolean;
  setTakeover: (enabled: boolean, leaseMs?: number) => boolean;
  sendMouse: (payload: Parameters<OmniAgentSocket['sendMouse']>[0]) => boolean;
  sendKeyboard: (payload: KeyboardPayload) => boolean;
  /** Attach pointer/keyboard listeners that map DOM coords → page CSS px. */
  attachCanvas: (canvas: HTMLCanvasElement | null) => () => void;
};

/** base64 → Blob URL without pulling in a polyfill. */
function base64ToObjectUrl(dataB64: string, format: 'jpeg' | 'png'): string {
  const binary = atob(dataB64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  const blob = new Blob([bytes], { type: `image/${format}` });
  return URL.createObjectURL(blob);
}

export function useBrowserStream(options: UseBrowserStreamOptions): UseBrowserStreamResult {
  const { graphId, enabled = true, baseUrl } = options;
  const socketRef = useRef<OmniAgentSocket | null>(null);
  const objectUrlRef = useRef<string | null>(null);
  const frameMetaRef = useRef<{ cssWidth: number; cssHeight: number } | null>(null);
  const fpsWindowRef = useRef<number[]>([]);
  const detachedRef = useRef<(() => void) | null>(null);

  const setSocket = useStreamStore((s) => s.setSocket);
  const setLiveImage = useStreamStore((s) => s.setLiveImage);
  const setFps = useStreamStore((s) => s.setFps);
  const setStreamMeta = useStreamStore((s) => s.setStreamMeta);
  const setStreamHealth = useStreamStore((s) => s.setStreamHealth);
  const reset = useStreamStore((s) => s.reset);

  useEffect(() => {
    if (!enabled || !graphId) {
      if (graphId) reset(graphId);
      return undefined;
    }

    setStreamHealth(graphId, 'idle');

    let active = true;
    let newestFrameToken = 0;
    let lastFpsPublishAt = 0;
    const handleFrame = (frame: ScreenFrame) => {
      // Frames are ~10-40/s: decode, publish, and release the previous URL so
      // a long session cannot accumulate blob memory. Use a local arrival token
      // instead of server seq because seq may restart after WS reconnect.
      const frameToken = ++newestFrameToken;
      let url: string;
      try {
        url = base64ToObjectUrl(frame.data_b64, frame.format);
      } catch {
        return;
      }
      const image = new Image();
      image.onload = () => {
        if (!active || frameToken !== newestFrameToken) {
          URL.revokeObjectURL(url);
          return;
        }
        if (objectUrlRef.current) URL.revokeObjectURL(objectUrlRef.current);
        objectUrlRef.current = url;
        setLiveImage(graphId, image, frame.seq, frame.data_b64.length);

        const scale = frame.page_scale_factor && frame.page_scale_factor > 0
          ? frame.page_scale_factor
          : 1;
        frameMetaRef.current = {
          cssWidth: (frame.device_width || frame.width) / scale,
          cssHeight: (frame.device_height || frame.height) / scale,
        };

        const now = performance.now();
        const window = fpsWindowRef.current;
        window.push(now);
        while (window.length && now - window[0] > 1000) window.shift();
        if (now - lastFpsPublishAt >= 500) {
          lastFpsPublishAt = now;
          setFps(graphId, window.length);
        }
      };
      image.onerror = () => URL.revokeObjectURL(url);
      image.src = url;
    };

    /** STREAM_READY / STREAM_RECONNECTING / STREAM_ERROR drive the health chip. */
    const handleEnvelope = (envelope: ServerEnvelope) => {
      if (envelope.type === ServerMessageType.STREAM_READY) {
        setStreamHealth(graphId, 'ready');
        setStreamMeta(graphId, {
          pageUrl: envelope.page_url,
          format: envelope.format,
          width: envelope.max_width,
          height: envelope.max_height,
        });
      } else if (envelope.type === ServerMessageType.STREAM_RECONNECTING) {
        setStreamHealth(graphId, 'reconnecting');
      } else if (envelope.type === ServerMessageType.STREAM_ERROR) {
        setStreamHealth(graphId, envelope.fatal ? 'error' : 'reconnecting');
      }
    };

    const socket = new OmniAgentSocket({
      graphId,
      baseUrl,
      refreshSession,
      getTicket: async (id: string): Promise<WsTicket> => {
        const ticket = await requestWsTicket(id);
        return {
          ticket: ticket.ticket,
          expires_in: ticket.expires_in,
          graph_id: ticket.graph_id,
          subprotocols: ticket.subprotocols,
        };
      },
      onSnapshot: (snapshot) => setSocket(graphId, snapshot),
      onFrame: handleFrame,
      onEnvelope: handleEnvelope,
      onError: (code) => {
        setStreamHealth(graphId, 'error');
        if (code === 40100 && typeof window !== 'undefined') {
          window.location.assign('/login?next=%2F');
        }
      },
      onClosed: () => setStreamHealth(graphId, 'reconnecting'),
    });
    socketRef.current = socket;
    socket.connect();

    return () => {
      active = false;
      socket.close();
      socketRef.current = null;
      detachedRef.current?.();
      detachedRef.current = null;
      if (objectUrlRef.current) {
        URL.revokeObjectURL(objectUrlRef.current);
        objectUrlRef.current = null;
      }
      fpsWindowRef.current = [];
      reset(graphId);
    };
  }, [
    baseUrl,
    enabled,
    graphId,
    reset,
    setFps,
    setLiveImage,
    setSocket,
    setStreamHealth,
    setStreamMeta,
  ]);

  const setTakeover = useCallback((value: boolean, leaseMs?: number) => {
    const socket = socketRef.current;
    if (!socket) return false;
    return socket.setTakeover(value, leaseMs, value ? 'operator takeover from canvas' : undefined);
  }, []);

  const sendMouse = useCallback((payload: Parameters<OmniAgentSocket['sendMouse']>[0]) => {
    const socket = socketRef.current;
    if (!socket) return false;
    return socket.sendMouse(payload);
  }, []);

  const sendKeyboard = useCallback((payload: KeyboardPayload) => {
    const socket = socketRef.current;
    if (!socket) return false;
    return socket.sendKeyboard(payload);
  }, []);

  const attachCanvas = useCallback(
    (canvasElement: HTMLCanvasElement | null) => {
      detachedRef.current?.();
      detachedRef.current = null;
      if (!canvasElement) return () => undefined;

      const toPageCoords = (event: PointerEvent | MouseEvent) => {
        const rect = canvasElement.getBoundingClientRect();
        const meta = frameMetaRef.current;
        const cssWidth = meta?.cssWidth ?? rect.width;
        const cssHeight = meta?.cssHeight ?? rect.height;
        const x = rect.width > 0 ? ((event.clientX - rect.left) / rect.width) * cssWidth : 0;
        const y = rect.height > 0 ? ((event.clientY - rect.top) / rect.height) * cssHeight : 0;
        return { x: Math.round(x), y: Math.round(y) };
      };

      const buttonName = (button: number): MouseButton =>
        button === 2 ? 'right' : button === 1 ? 'middle' : 'left';

      const onPointerMove = (event: PointerEvent) => {
        event.stopPropagation();
        sendMouse({ action: 'move', ...toPageCoords(event), buttons: event.buttons });
      };
      const onPointerDown = (event: PointerEvent) => {
        event.preventDefault();
        event.stopPropagation();
        canvasElement.focus();
        sendMouse({
          action: 'down',
          ...toPageCoords(event),
          button: buttonName(event.button),
          clickCount: event.detail || 1,
        });
      };
      const onPointerUp = (event: PointerEvent) => {
        event.preventDefault();
        event.stopPropagation();
        sendMouse({
          action: 'up',
          ...toPageCoords(event),
          button: buttonName(event.button),
          clickCount: event.detail || 1,
        });
      };
      const onWheel = (event: WheelEvent) => {
        event.preventDefault();
        event.stopPropagation();
        sendMouse({
          action: 'wheel',
          ...toPageCoords(event),
          deltaX: event.deltaX,
          deltaY: event.deltaY,
        });
      };
      const onContextMenu = (event: Event) => {
        event.preventDefault();
        event.stopPropagation();
      };
      const onKeyDown = (event: KeyboardEvent) => {
        event.preventDefault();
        event.stopPropagation();
        sendKeyboard({ action: 'keydown', key: event.key, code: event.code, autoRepeat: event.repeat });
      };
      const onKeyUp = (event: KeyboardEvent) => {
        event.preventDefault();
        event.stopPropagation();
        sendKeyboard({ action: 'keyup', key: event.key, code: event.code });
      };

      canvasElement.addEventListener('pointermove', onPointerMove);
      canvasElement.addEventListener('pointerdown', onPointerDown);
      canvasElement.addEventListener('pointerup', onPointerUp);
      canvasElement.addEventListener('wheel', onWheel, { passive: false });
      canvasElement.addEventListener('contextmenu', onContextMenu);
      canvasElement.addEventListener('keydown', onKeyDown);
      canvasElement.addEventListener('keyup', onKeyUp);
      if (!canvasElement.hasAttribute('tabindex')) canvasElement.tabIndex = 0;

      const detach = () => {
        canvasElement.removeEventListener('pointermove', onPointerMove);
        canvasElement.removeEventListener('pointerdown', onPointerDown);
        canvasElement.removeEventListener('pointerup', onPointerUp);
        canvasElement.removeEventListener('wheel', onWheel);
        canvasElement.removeEventListener('contextmenu', onContextMenu);
        canvasElement.removeEventListener('keydown', onKeyDown);
        canvasElement.removeEventListener('keyup', onKeyUp);
      };
      detachedRef.current = detach;
      return detach;
    },
    [sendKeyboard, sendMouse],
  );

  const snapshot = useStreamStore((s) =>
    graphId ? (s.streams[graphId] ?? EMPTY_GRAPH_STREAM).socket : null,
  );
  const connected = snapshot?.phase === 'open';
  const permissions = snapshot?.permissions ?? [];
  const takeoverActive = Boolean(
    snapshot?.takeoverActive &&
    snapshot.connectionId &&
    snapshot.takeoverConnectionId === snapshot.connectionId,
  );
  const takeoverBusy = Boolean(snapshot?.takeoverActive && !takeoverActive);
  const takeoverHolder = snapshot?.takeoverHolder ?? null;

  const canOperate = useCallback(
    (permission: Permission) => {
      // Mock mode (no socket yet): let the existing simulated UI keep working.
      if (!snapshot || snapshot.phase !== 'open') return true;
      return can(permissions, permission);
    },
    [permissions, snapshot],
  );

  return useMemo(
    () => ({
      connected,
      phase: snapshot?.phase ?? 'idle',
      role: snapshot?.role ?? null,
      canOperate,
      takeoverActive,
      takeoverHolder,
      takeoverBusy,
      setTakeover,
      sendMouse,
      sendKeyboard,
      attachCanvas,
    }),
    [attachCanvas, canOperate, connected, sendKeyboard, sendMouse, setTakeover, snapshot, takeoverActive, takeoverBusy, takeoverHolder],
  );
}
