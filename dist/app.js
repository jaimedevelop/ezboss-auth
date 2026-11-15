import { securityRoutes } from './routes/security.js';
import express from 'express';
import { randomUUID } from 'node:crypto';
import { toNodeHandler } from 'better-auth/node';
import { createMailDelivery } from './services/email.js';
import { internalVerification } from './routes/internalVerification.js';
export function createApp(auth, env, database, deliver = createMailDelivery(env)) {
    const app = express();
    app.disable('x-powered-by');
    app.use((req, res, next) => {
        const requestId = randomUUID();
        const started = Date.now();
        res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
            'X-Content-Type-Options': 'nosniff', 'X-EzBoss-Request-Id': requestId });
        res.once('finish', () => {
            if (res.statusCode !== 429 && res.statusCode < 500)
                return;
            const path = req.originalUrl.split('?')[0];
            const area = path === '/api/auth/get-session' ? 'browser-session'
                : path === '/internal/verify-session' ? 'api-session'
                    : path === '/health/ready' ? 'readiness'
                        : path.startsWith('/api/auth/ezboss/admin/') ? 'administrator-verification'
                            : 'auth';
            console.warn('Authentication request failed', {
                requestId, area, status: res.statusCode, durationMs: Date.now() - started,
            });
        });
        next();
    });
    app.get('/health/live', (_req, res) => { res.json({ ok: true }); });
    app.get('/health/ready', async (_req, res) => {
        try {
            await database.query(`SELECT u."acceptedTermsVersion", u."termsAcceptedAt", a."accountId", p."credentialID"
        FROM "user" u, session, account a, passkey p, "rateLimit", totp_replay, admin_challenges, admin_assurance
        LIMIT 0`);
            res.json({ ok: true });
        }
        catch {
            res.status(503).json({ ok: false });
        }
    });
    app.use('/api/auth', (req, _res, next) => {
        // Direct service origin is deliberately conservative until ingress trust is proved.
        delete req.headers['x-forwarded-for'];
        delete req.headers['x-forwarded-host'];
        delete req.headers['x-forwarded-proto'];
        req.headers['x-ezboss-peer-ip'] = req.socket.remoteAddress || 'unknown';
        next();
    });
    app.use('/api/auth/ezboss', express.json({ limit: '16kb' }), securityRoutes(auth, env, database, deliver));
    app.all('/api/auth/*splat', toNodeHandler(auth));
    app.post('/internal/verify-session', express.json({ limit: '12kb' }), internalVerification(auth, env, database));
    app.use((_error, _req, res, _next) => {
        res.status(503).json({ error: 'Authentication unavailable' });
    });
    return app;
}
