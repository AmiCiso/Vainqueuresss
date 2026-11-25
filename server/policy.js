// Pure security-policy helpers (no Express import so they are unit-testable anywhere).

export function buildCsp(config) {
  const connect = ["'self'", ...config.cspConnectExtra].join(' ');
  const parts = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' https://fonts.googleapis.com",
    'font-src https://fonts.gstatic.com',
    "img-src 'self' data:",
    `connect-src ${connect}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ];
  if (config.hsts) parts.push('upgrade-insecure-requests');
  return parts.join('; ');
}

/** CORS is a browser-side policy. It is NOT authentication and does nothing against curl/scripts. */
export function corsDecision(origin, requestHost, allowedOrigins) {
  if (!origin) return { allowed: true, origin: null };
  if (allowedOrigins.includes(origin)) return { allowed: true, origin };
  try { if (new URL(origin).host === requestHost) return { allowed: true, origin }; } catch { /* malformed Origin */ }
  return { allowed: false, origin };
}
