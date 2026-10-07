import type { NextConfig } from 'next';

/**
 * Browser-facing security headers for the OmniAgent console and auth BFF.
 *
 * CSP is intentionally compatible with the current Next.js/React Flow client
 * build (`unsafe-inline`/`unsafe-eval` are needed by the existing runtime).
 * Production deployments should set `OMNIAGENT_CSP` to a nonce-based policy
 * after validating it in report-only mode. In production, only `wss:` is
 * permitted; local dev keeps `ws:` for the Next dev server. When WebSocket
 * traffic is reverse-proxied through this same origin, prefer that layout and
 * override CSP to pin `connect-src` to the exact host.
 */

const wsScheme = process.env.NODE_ENV === 'production' ? 'wss:' : 'ws:';
const DEFAULT_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  `connect-src 'self' ${wsScheme}`,
  "media-src 'self'",
  "object-src 'none'",
  "child-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  ...(process.env.NODE_ENV === 'production' ? ['upgrade-insecure-requests'] : []),
].join('; ');

const securityHeaders = [
  { key: 'Content-Security-Policy', value: process.env.OMNIAGENT_CSP ?? DEFAULT_CSP },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), browsing-topics=(), interest-cohort=()',
  },
  { key: 'X-DNS-Prefetch-Control', value: 'off' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
];

/** Authentication/API results must never be cached or stored on disk. */
const apiCacheHeaders = [{ key: 'Cache-Control', value: 'no-store, max-age=0' }];

if (process.env.NODE_ENV === 'production') {
  securityHeaders.push({
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000',
  });
}

const nextConfig: NextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [
      { source: '/:path*', headers: securityHeaders },
      { source: '/api/:path*', headers: apiCacheHeaders },
    ];
  },
};

export default nextConfig;
