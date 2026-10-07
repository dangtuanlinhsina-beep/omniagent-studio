'use client';

/**
 * Per-graph live stream state shared between WebSocket clients and canvas nodes.
 *
 * A map is intentional: a flow may contain several browser sessions, and one
 * node must never display another graph's screenshot or takeover state.
 */

import { create } from 'zustand';

import type { SocketSnapshot } from '@/lib/ws/wsClient';
import type { Permission, Role } from '@/lib/ws/protocol';

export type GraphStreamState = {
  socket: SocketSnapshot | null;
  liveImage: HTMLImageElement | null;
  liveSeq: number;
  frameBytes: number;
  fps: number;
  streamMeta: { pageUrl: string; format: string; width: number; height: number } | null;
  streamHealth: 'ready' | 'reconnecting' | 'error' | 'idle';
};

export const EMPTY_GRAPH_STREAM: GraphStreamState = {
  socket: null,
  liveImage: null,
  liveSeq: 0,
  frameBytes: 0,
  fps: 0,
  streamMeta: null,
  streamHealth: 'idle',
};

export type StreamStoreState = {
  streams: Record<string, GraphStreamState>;
  setSocket: (graphId: string, snapshot: SocketSnapshot | null) => void;
  setLiveImage: (graphId: string, image: HTMLImageElement | null, seq: number, bytes: number) => void;
  setFps: (graphId: string, fps: number) => void;
  setStreamMeta: (
    graphId: string,
    meta: GraphStreamState['streamMeta'],
  ) => void;
  setStreamHealth: (graphId: string, health: GraphStreamState['streamHealth']) => void;
  reset: (graphId: string) => void;
};

function updateGraph(
  streams: Record<string, GraphStreamState>,
  graphId: string,
  patch: Partial<GraphStreamState>,
): Record<string, GraphStreamState> {
  return {
    ...streams,
    [graphId]: { ...(streams[graphId] ?? EMPTY_GRAPH_STREAM), ...patch },
  };
}

export const useStreamStore = create<StreamStoreState>((set) => ({
  streams: {},
  setSocket: (graphId, socket) =>
    set((state) => ({ streams: updateGraph(state.streams, graphId, { socket }) })),
  setLiveImage: (graphId, liveImage, liveSeq, frameBytes) =>
    set((state) => ({
      streams: updateGraph(state.streams, graphId, { liveImage, liveSeq, frameBytes }),
    })),
  setFps: (graphId, fps) =>
    set((state) => ({ streams: updateGraph(state.streams, graphId, { fps }) })),
  setStreamMeta: (graphId, streamMeta) =>
    set((state) => ({ streams: updateGraph(state.streams, graphId, { streamMeta }) })),
  setStreamHealth: (graphId, streamHealth) =>
    set((state) => ({ streams: updateGraph(state.streams, graphId, { streamHealth }) })),
  reset: (graphId) =>
    set((state) => {
      const streams = { ...state.streams };
      delete streams[graphId];
      return { streams };
    }),
}));

/** No live connection means the existing simulated canvas remains enabled. */
export function selectRole(state: GraphStreamState): Role | null {
  return state.socket?.role ?? null;
}

/**
 * UI-side capability hint only. The API independently checks the permission
 * and takeover lease on every control message.
 */
export function canOperate(state: GraphStreamState, permission: Permission): boolean {
  const socket = state.socket;
  if (!socket || socket.phase !== 'open') return true;
  return socket.permissions.includes(permission);
}
