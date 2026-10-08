'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

import {
  fetchSession,
  login as apiLogin,
  logout as apiLogout,
  type SessionInfo,
} from '@/lib/auth/client';
import type { Permission, Role } from '@/lib/ws/protocol';

/**
 * Session state for client components.
 *
 * The identity is fetched from the BFF (`/api/auth/me`) — the access token is
 * never readable from JS, so the only thing stored here is the *public* view
 * of the session (role, permissions, graph ids).
 */
export type AuthState = {
  loading: boolean;
  authenticated: boolean;
  session: SessionInfo | null;
  role: Role | null;
  permissions: Permission[];
  graphIds: string[];
  error: string | null;
};

const EMPTY: AuthState = {
  loading: true,
  authenticated: false,
  session: null,
  role: null,
  permissions: [],
  graphIds: [],
  error: null,
};

export function useAuth() {
  const [state, setState] = useState<AuthState>(EMPTY);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true }));
    const session = await fetchSession();
    if (!mounted.current) return;
    setState({
      loading: false,
      authenticated: session.authenticated,
      session,
      role: (session.role as Role | undefined) ?? null,
      permissions: (session.permissions as Permission[] | undefined) ?? [],
      graphIds: session.graph_ids ?? session.user?.graph_ids ?? [],
      error: null,
    });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const login = useCallback(async (email: string, password: string) => {
    try {
      const result = await apiLogin(email, password);
      if (mounted.current) {
        setState({
          loading: false,
          authenticated: true,
          session: {
            authenticated: true,
            subject: result.subject,
            role: result.role,
            permissions: result.permissions,
            expires_in: result.expires_in,
            user: result.user,
          },
          role: result.role,
          permissions: result.permissions as Permission[],
          graphIds: result.user?.graph_ids ?? [],
          error: null,
        });
      }
      return { ok: true as const };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'login failed';
      if (mounted.current) setState((prev) => ({ ...prev, loading: false, error: message }));
      return { ok: false as const, message };
    }
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    if (mounted.current) setState({ ...EMPTY, loading: false });
  }, []);

  const can = useCallback(
    (permission: Permission) => state.permissions.includes(permission),
    [state.permissions],
  );

  return { ...state, login, logout, reload: load, can };
}
