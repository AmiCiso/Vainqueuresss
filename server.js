// Entry point: `npm start`. All behaviour is configured via environment variables (see .env.example).
import { loadEnvFileIfPresent, buildConfig } from './server/config.js';
import { createApp } from './server/app.js';

loadEnvFileIfPresent();
const config = buildConfig();
const { app } = await createApp(config);

const server = app.listen(config.port, config.host, () => {
  const addr = server.address();
  console.log(`[VAINQUEURES] gateway listening on http://${config.host}:${addr.port} (${config.production ? 'production' : 'development'})`);
  console.log(`[VAINQUEURES] Google Safe Browsing key configured: ${Boolean(config.providers.gsbKey)} (not verified)`);
  console.log(`[VAINQUEURES] URLhaus Auth-Key configured: ${Boolean(config.providers.urlhausKey)} (not verified)`);
  if (config.production && config.rateLimit.store === 'memory') {
    console.warn('[VAINQUEURES] Rate limits are per-instance (memory store). Use RATE_LIMIT_STORE=redis when running multiple instances.');
  }
  if (config.production && config.trustProxy === false) {
    console.warn('[VAINQUEURES] TRUST_PROXY is unset. Behind a reverse proxy every client will share the proxy IP; set it to your real hop count.');
  }
});
server.requestTimeout = 15000;
server.headersTimeout = 10000;
server.keepAliveTimeout = 5000;

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => server.close(() => process.exit(0)));
}
