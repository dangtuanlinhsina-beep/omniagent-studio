'use client';

import { useEffect } from 'react';
import {
  ANALYST_NODE_ID,
  BROWSER_NODE_ID,
  DASHBOARD_NODE_ID,
  THOUGHT_SCRIPT,
} from '@/canvas/data/mockFlow';
import { nextNavEntry, useGraphStore } from '@/canvas/store/graphStore';
import type { BrowserNodeData } from '@/canvas/types';

/**
 * useAgentRuntime
 * ---------------
 * Client-side simulation engine that drives the whole mock data flow:
 *
 *  - pushes LLM thoughts into the AnalystNode (typing stream)
 *  - rotates browser URLs (navigation events)
 *  - triggers CaptchaDetected windows every ~11 ticks (auto-solved)
 *  - feeds the DashboardNode live line-chart data every tick
 *
 * Paused instantly when store.running === false. All randomness happens
 * inside timers (client-only) so SSR output stays deterministic.
 */
const TICK_MS = 1500;

export function useAgentRuntime() {
  useEffect(() => {
    let tick = 0;
    let captchaCountdown = -1;

    const iv = setInterval(() => {
      const s = useGraphStore.getState();
      if (!s.running) return;

      tick += 1;
      s.bumpTick();

      /* --- captcha auto-resolution lifecycle --- */
      if (captchaCountdown > 0) {
        captchaCountdown -= 1;
        if (captchaCountdown === 0) {
          s.setBrowserStatus(BROWSER_NODE_ID, 'Browsing');
          s.pushThought(
            ANALYST_NODE_ID,
            'result',
            'Captcha challenge solved by vision-solver (confidence 0.97). Session resumed.',
          );
        }
      }

      /* --- navigation events --- */
      if (tick % 7 === 0) {
        const browser = s.nodes.find((n) => n.id === BROWSER_NODE_ID);
        const currentUrl = (browser?.data as BrowserNodeData | undefined)?.url;
        const entry = nextNavEntry(currentUrl ?? '');
        s.navigateBrowser(BROWSER_NODE_ID, entry.url, entry.title);
        s.pushThought(
          ANALYST_NODE_ID,
          'tool',
          `page.goto("${entry.url}") → 200 OK (${(0.6 + Math.random() * 1.6).toFixed(2)}s)`,
        );
      }

      /* --- captcha trigger window --- */
      if (tick % 11 === 0 && captchaCountdown < 0) {
        captchaCountdown = 4;
        s.setBrowserStatus(BROWSER_NODE_ID, 'CaptchaDetected');
        s.pushThought(
          ANALYST_NODE_ID,
          'warning',
          'CaptchaDetected on edge-node → delegating to vision solver.',
        );
      }

      /* --- LLM thought script --- */
      if (tick % 2 === 0) {
        const line = THOUGHT_SCRIPT[Math.floor(tick / 2 - 1) % THOUGHT_SCRIPT.length];
        s.pushThought(ANALYST_NODE_ID, line.kind, line.text);
      }

      /* --- live dashboard data --- */
      s.tickDashboard(DASHBOARD_NODE_ID);
    }, TICK_MS);

    return () => clearInterval(iv);
  }, []);
}
