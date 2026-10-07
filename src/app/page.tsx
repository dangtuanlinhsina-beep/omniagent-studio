'use client';

import { useRouter } from 'next/navigation';
import { useEffect } from 'react';

import { FlowCanvas } from '@/canvas/FlowCanvas';
import { StatusBar } from '@/canvas/components/StatusBar';
import { TopBar } from '@/canvas/components/TopBar';
import { useAuth } from '@/lib/auth/useAuth';

/** Client-side route gate; every API and WebSocket authorization is still
 * independently verified by FastAPI. This is UX, not a security boundary. */
export default function Home() {
  const router = useRouter();
  const { loading, authenticated, logout, role } = useAuth();

  useEffect(() => {
    if (!loading && !authenticated) {
      router.replace('/login?next=%2F');
    }
  }, [authenticated, loading, router]);

  if (loading || !authenticated) {
    return (
      <main className="cyber-grid flex h-screen items-center justify-center bg-background">
        <div
          role="status"
          className="omni-panel rounded-lg px-5 py-4 font-mono text-[11px] text-cyan-200"
        >
          {loading ? 'Verifying session…' : 'Redirecting to sign in…'}
        </div>
      </main>
    );
  }

  return (
    <div className="flex h-screen min-h-screen flex-col overflow-hidden bg-background">
      <TopBar
        role={role}
        onLogout={async () => {
          await logout();
          router.replace('/login');
        }}
      />
      <main aria-label="OmniAgent flow canvas" className="relative min-h-0 flex-1">
        <FlowCanvas />
      </main>
      <StatusBar />
    </div>
  );
}
