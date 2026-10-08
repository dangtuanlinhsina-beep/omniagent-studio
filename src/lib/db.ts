/**
 * Prisma access for the Next.js app.
 *
 * The previous version had two problems:
 *
 * 1. `import { PrismaClient } from '@prisma/client'` breaks `tsc`/`next build`
 *    on a fresh clone, because the generated client only exists after
 *    `npm run db:generate` (see `prisma/schema.prisma`).
 * 2. `new PrismaClient(...)` at module scope opens a connection pool as soon as
 *    anything imports the file — including during static rendering — and
 *    `log: ['query']` prints every query *with its parameters* (emails,
 *    session ids, token digests) in **all** environments.
 *
 * So: lazy construction, structural typing (no dependency on generated types)
 * and query logging only in development.
 */

import 'server-only';

type DbClient = {
  $connect(): Promise<void>;
  $disconnect(): Promise<void>;
  [model: string]: unknown;
};

type DbModule = {
  PrismaClient?: new (options?: Record<string, unknown>) => DbClient;
};

const globalForPrisma = globalThis as unknown as { prisma?: DbClient };

let cached: Promise<DbClient> | null = null;

/** Resolve (and memoize) the Prisma client. */
export function getDb(): Promise<DbClient> {
  if (globalForPrisma.prisma) return Promise.resolve(globalForPrisma.prisma);
  if (!cached) {
    cached = (async () => {
      // Dynamic import + structural cast: works before `prisma generate` has
      // produced typed models, and never puts PII-bearing types in the bundle.
      const mod = (await import('@prisma/client')) as unknown as DbModule;
      if (!mod.PrismaClient) {
        throw new Error(
          'PrismaClient is unavailable — run `npm run db:generate` (prisma/schema.prisma).',
        );
      }
      const client = new mod.PrismaClient({
        // Query logging leaks parameters into logs; dev only, overridable.
        log:
          process.env.NODE_ENV === 'development'
            ? (process.env.DATABASE_LOG_LEVEL?.split(',').filter(Boolean) ?? ['warn', 'error'])
            : ['error'],
      });
      globalForPrisma.prisma = client;
      return client;
    })();
    cached.catch(() => {
      cached = null;
    });
  }
  return cached;
}

/** Run a callback with a resolved client (preferred ergonomics). */
export async function withDb<T>(fn: (db: DbClient) => Promise<T> | T): Promise<T> {
  return fn(await getDb());
}

/** Close the pooled connection (used by scripts and test teardown). */
export async function disconnectDb(): Promise<void> {
  const client = globalForPrisma.prisma;
  globalForPrisma.prisma = undefined;
  cached = null;
  if (client) await client.$disconnect();
}
