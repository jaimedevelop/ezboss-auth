import { securityRoutes } from './routes/security.js';
import express from 'express';
import { toNodeHandler } from 'better-auth/node';
import type { Pool } from 'pg';
import type { Auth } from './auth.js';
import type { Environment } from './env.js';
import { internalVerification } from './routes/internalVerification.js';

export function createApp(auth: Auth, env: Environment, database: Pool) {
  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' }); next();
  });
  app.get('/health/live', (_req, res) => { res.json({ ok: true }); });
  app.get('/health/ready', async (_req, res) => {
    try { await database.query('SELECT "acceptedTermsVersion","termsAcceptedAt" FROM "user",session,totp_replay,admin_challenges,admin_assurance LIMIT 0'); res.json({ ok: true }); }
    catch { res.status(503).json({ ok: false }); }
  });
  app.use('/api/auth', (req, _res, next) => {
    // Direct service origin is deliberately conservative until ingress trust is proved.
    delete req.headers['x-forwarded-for']; delete req.headers['x-forwarded-host']; delete req.headers['x-forwarded-proto'];
    req.headers['x-ezboss-peer-ip'] = req.socket.remoteAddress || 'unknown'; next();
  });
  app.use('/api/auth/ezboss',express.json({limit:'16kb'}),securityRoutes(auth,env,database));
  app.all('/api/auth/*splat', toNodeHandler(auth));
  app.post('/internal/verify-session', express.json({ limit: '12kb' }), internalVerification(auth, env, database));
  app.use((_error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(503).json({ error: 'Authentication unavailable' });
  });
  return app;
}
