import { Router } from 'express';
import { fromNodeHeaders } from 'better-auth/node';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { AdminStepUp, AssuranceDenied } from '../services/adminStepUp.js';
export function securityRoutes(auth, env, database) {
    const router = Router();
    router.get('/config', (_req, res) => res.json({ appOrigin: env.appOrigin, providers: env.GOOGLE_CLIENT_ID ? ['google'] : [],
        termsVersion: env.AUTH_TERMS_VERSION || null, privacyVersion: env.AUTH_PRIVACY_VERSION || null,
        termsURL: env.AUTH_TERMS_URL || null, privacyURL: env.AUTH_PRIVACY_URL || null }));
    router.use(async (req, res, next) => {
        if (req.method !== 'POST')
            return res.sendStatus(405);
        if (req.get('Origin') !== env.appOrigin || req.get('X-EzBoss-CSRF') !== '1')
            return res.status(403).json({ error: 'Request origin rejected' });
        try {
            const session = await auth.api.getSession({ headers: fromNodeHeaders(req.headers), query: { disableCookieCache: true, disableRefresh: true } });
            if (!session)
                return res.status(401).json({ error: 'Sign in required' });
            // These wrappers bypass Better Auth's HTTP limiter: count attempts atomically in shared SQL.
            const key = `ezboss-security:${session.user.id}:${Math.floor(Date.now() / 60000)}`;
            const limited = await database.query(`INSERT INTO "rateLimit"(id,key,count,"lastRequest") VALUES($1,$2,1,$3)
        ON CONFLICT(key) DO UPDATE SET count="rateLimit".count+1 WHERE "rateLimit".count<10 RETURNING id`, [randomUUID(), key, Date.now()]);
            if (!limited.rowCount)
                return res.status(429).json({ error: 'Please wait before trying again' });
            res.locals.session = session;
            next();
        }
        catch {
            res.status(503).json({ error: 'Authentication unavailable' });
        }
    });
    router.post('/status', async (_req, res) => {
        try {
            const consent = (await database.query('SELECT "acceptedTermsVersion","acceptedPrivacyVersion","termsAcceptedAt" FROM "user" WHERE id=$1', [res.locals.session.user.id])).rows[0];
            res.json({ legalAccepted: Boolean(env.AUTH_TERMS_VERSION && consent?.termsAcceptedAt && consent.acceptedTermsVersion === env.AUTH_TERMS_VERSION && consent.acceptedPrivacyVersion === env.AUTH_PRIVACY_VERSION) });
        }
        catch {
            res.status(503).json({ error: 'Authentication unavailable' });
        }
    });
    router.post('/consent', async (req, res) => {
        const parsed = z.object({ termsVersion: z.string(), privacyVersion: z.string() }).strict().safeParse(req.body);
        if (!parsed.success || !env.AUTH_TERMS_VERSION || parsed.data.termsVersion !== env.AUTH_TERMS_VERSION || parsed.data.privacyVersion !== env.AUTH_PRIVACY_VERSION)
            return res.status(400).json({ error: 'Review the current legal documents' });
        try {
            await database.query(`UPDATE "user" SET "acceptedTermsVersion"=$2,"acceptedPrivacyVersion"=$3,"termsAcceptedAt"=now() WHERE id=$1`, [res.locals.session.user.id, env.AUTH_TERMS_VERSION, env.AUTH_PRIVACY_VERSION]);
            res.json({ ok: true });
        }
        catch {
            res.status(503).json({ error: 'Authentication unavailable' });
        }
    });
    const admin = new AdminStepUp(database, env);
    router.post('/admin/challenge', async (_req, res) => {
        try {
            res.json(await admin.challenge(res.locals.session.user.id, res.locals.session.session.id));
        }
        catch (error) {
            res.status(error instanceof AssuranceDenied ? 403 : 503).json({ error: 'Security verification unavailable. Enroll a passkey in account security.' });
        }
    });
    router.post('/admin/verify', async (req, res) => {
        const parsed = z.object({ transactionId: z.uuid(), response: z.object({ id: z.string(), rawId: z.string(), type: z.literal('public-key'), clientExtensionResults: z.record(z.string(), z.unknown()), response: z.object({ clientDataJSON: z.string(), authenticatorData: z.string(), signature: z.string(), userHandle: z.string().optional() }) }) }).strict().safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json({ error: 'Invalid verification request' });
        try {
            await admin.verify(res.locals.session.user.id, res.locals.session.session.id, parsed.data.transactionId, parsed.data.response);
            res.json({ ok: true });
        }
        catch (error) {
            res.status(error instanceof AssuranceDenied ? 403 : 503).json({ error: 'Security verification failed' });
        }
    });
    return router;
}
