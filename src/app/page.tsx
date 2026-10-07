'use client';

import { FlowCanvas } from '@/canvas/FlowCanvas';
import { StatusBar } from '@/canvas/components/StatusBar';
import { TopBar } from '@/canvas/components/TopBar';

export default function Home() {
  return (
    <div className="flex h-screen min-h-screen flex-col overflow-hidden bg-background">
      <TopBar />
      <main aria-label="OmniAgent flow canvas" className="relative min-h-0 flex-1">
        <FlowCanvas />
      </main>
      <StatusBar />
    </div>
  );
}
