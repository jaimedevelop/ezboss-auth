import { AdminStepUp } from '../services/adminStepUp.js';
import { timingSafeEqual } from 'node:crypto';
export function internalVerification(auth, env, database) {
    return async (req, res) => {
        res.set('Cache-Control', 'no-store');
        const supplied = Buffer.from(req.get('X-EzBoss-Service-Key') || '');
        const expected = Buffer.from(env.AUTH_INTERNAL_SECRET);
        if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }
        const body = req.body;
        if (!body || !['cookie', 'bearer'].includes(body.transport) || typeof body.credential !== 'string' ||
            !body.credential || body.credential.length > 8192 || /[\r\n]/.test(body.credential)) {
            res.status(400).json({ error: 'Invalid verification request' });
            return;
        }
        // Forward only the selected credential; never combine competing sources.
        const headers = new Headers(body.transport === 'cookie'
            ? { cookie: body.credential } : { authorization: `Bearer ${body.credential}` });
        try {
            const result = await auth.api.getSession({ headers, query: { disableCookieCache: true, disableRefresh: true } });
            if (!result || result.session.expiresAt.getTime() <= Date.now()) {
                res.status(401).json({ error: 'Invalid session' });
                return;
            }
            const adminVerifiedAt = await new AdminStepUp(database, env).recent(result.user.id, result.session.id);
            const consent = (await database.query('SELECT "acceptedTermsVersion","acceptedPrivacyVersion","termsAcceptedAt" FROM "user" WHERE id=$1', [result.user.id])).rows[0];
            const legalAccepted = Boolean(env.AUTH_TERMS_VERSION && consent?.termsAcceptedAt && consent.acceptedTermsVersion === env.AUTH_TERMS_VERSION && consent.acceptedPrivacyVersion === env.AUTH_PRIVACY_VERSION);
            res.json({ legalAccepted, ...(adminVerifiedAt ? { adminVerifiedAt } : {}), provider: 'better-auth', credentialKind: 'session', issuer: `${env.baseURL}/api/auth`,
                subject: result.user.id, sessionId: result.session.id, expiresAt: result.session.expiresAt.toISOString(),
                email: result.user.email, emailVerified: result.user.emailVerified });
        }
        catch {
            res.status(503).json({ error: 'Authentication unavailable' });
        }
    };
}
