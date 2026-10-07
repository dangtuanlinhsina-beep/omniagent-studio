'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useEffect, useState } from 'react';
import { ShieldCheck } from 'lucide-react';

import { useAuth } from '@/lib/auth/useAuth';

/**
 * Login screen for the OmniAgent console.
 *
 * It posts to the Next.js BFF (`/api/auth/login`), which forwards the
 * credentials to FastAPI and stores the returned tokens in httpOnly cookies.
 * No JWT is ever exposed to page JavaScript here — the only client-visible
 * credential is the single-use WebSocket ticket minted per graph later on.
 */

/** Allow only same-origin relative targets (blocks `//evil.test` redirects). */
function safeNext(value: string | null): string {
  if (!value) return '/';
  if (!value.startsWith('/') || value.startsWith('//')) return '/';
  if (value.includes('\\')) return '/';
  return value;
}

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const { login, authenticated, error: authError } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const next = safeNext(params.get('next'));

  useEffect(() => {
    if (authenticated) router.replace(next);
  }, [authenticated, next, router]);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const result = await login(email.trim(), password);
    setPassword('');
    setBusy(false);
    if (result.ok) {
      router.replace(next);
      return;
    }
    setError(result.message);
  }

  const message = error ?? authError;

  return (
    <form onSubmit={onSubmit} className="omni-panel w-full max-w-sm space-y-4 p-6">
      <div className="flex items-center gap-2 text-[13px] font-semibold tracking-wide text-foreground">
        <ShieldCheck size={16} className="text-cyan-400" />
        Operator sign-in
      </div>

      <label className="block space-y-1">
        <span className="text-[10.5px] uppercase tracking-widest text-muted-foreground">
          Email
        </span>
        <input
          type="email"
          name="email"
          value={email}
          autoComplete="username"
          required
          maxLength={254}
          onChange={(event) => setEmail(event.target.value)}
          className="w-full rounded-md border border-border bg-black/40 px-3 py-2 font-mono text-[12px] text-foreground outline-none focus:border-cyan-400/60 focus:ring-1 focus:ring-cyan-400/30"
          placeholder="operator@omniagent.test"
        />
      </label>

      <label className="block space-y-1">
        <span className="text-[10.5px] uppercase tracking-widest text-muted-foreground">
          Password
        </span>
        <input
          type="password"
          name="password"
          value={password}
          autoComplete="current-password"
          required
          minLength={1}
          maxLength={512}
          onChange={(event) => setPassword(event.target.value)}
          className="w-full rounded-md border border-border bg-black/40 px-3 py-2 font-mono text-[12px] text-foreground outline-none focus:border-cyan-400/60 focus:ring-1 focus:ring-cyan-400/30"
          placeholder="••••••••••••"
        />
      </label>

      {message ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-[11px] text-destructive"
        >
          {message}
        </p>
      ) : null}

      <button
        type="submit"
        disabled={busy || !email || !password}
        className="w-full rounded-md border border-cyan-400/40 bg-cyan-500/15 px-3 py-2 text-[12px] font-semibold tracking-wide text-cyan-200 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {busy ? 'Authenticating…' : 'Sign in'}
      </button>

      <p className="text-[10px] leading-relaxed text-muted-foreground">
        Sessions are short-lived and bound to this browser (httpOnly cookie, 15-minute access
        token). <span className="text-foreground/80">OPERATOR</span> may take over the browser;{' '}
        <span className="text-foreground/80">VIEWER</span> receives the screencast only. Repeated
        failures are throttled and audited.
      </p>
    </form>
  );
}

export default function LoginPage() {
  return (
    <div className="cyber-grid flex min-h-screen items-center justify-center bg-background p-6">
      <Suspense fallback={<div className="omni-panel h-56 w-full max-w-sm animate-pulse" />}>
        <LoginForm />
      </Suspense>
    </div>
  );
}
