import { AdminStepUp } from '../services/adminStepUp.js';
import type { Pool } from 'pg';
import { timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import type { Auth } from '../auth.js';
import type { Environment } from '../env.js';

export function internalVerification(auth: Auth, env: Environment, database: Pool) {
  return async (req: Request, res: Response) => {
    res.set('Cache-Control', 'no-store');
    const supplied = Buffer.from(req.get('X-EzBoss-Service-Key') || '');
    const expected = Buffer.from(env.AUTH_INTERNAL_SECRET);
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
      res.status(401).json({ error: 'Unauthorized' }); return;
    }
    const body = req.body;
    if (!body || !['cookie', 'bearer'].includes(body.transport) || typeof body.credential !== 'string' ||
      !body.credential || body.credential.length > 8192 || /[\r\n]/.test(body.credential)) {
      res.status(400).json({ error: 'Invalid verification request' }); return;
    }
    // Forward only the selected credential; never combine competing sources.
    const headers = new Headers(body.transport === 'cookie'
      ? { cookie: body.credential } : { authorization: `Bearer ${body.credential}` });
    try {
      const result = await auth.api.getSession({ headers, query: { disableCookieCache: true, disableRefresh: true } });
      if (!result || result.session.expiresAt.getTime() <= Date.now()) {
        res.status(401).json({ error: 'Invalid session' }); return;
      }
      const adminVerifiedAt = await new AdminStepUp(database,env).verifiedAt(result.user.id,result.session.id);
      const consent=(await database.query('SELECT "acceptedTermsVersion","acceptedPrivacyVersion","termsAcceptedAt" FROM "user" WHERE id=$1',[result.user.id])).rows[0];
      const legalAccepted=Boolean(env.AUTH_TERMS_VERSION && consent?.termsAcceptedAt && consent.acceptedTermsVersion===env.AUTH_TERMS_VERSION && consent.acceptedPrivacyVersion===env.AUTH_PRIVACY_VERSION);
      let migrationGoogleSubject: string | undefined;
      if (env.googleMigrationSubjects.size && body.transport === 'cookie') {
        const accounts = await database.query(`SELECT a."accountId" FROM account a
          JOIN verification v ON v.id=$3 AND v.identifier='ezboss-google-migration'
            AND v.value=a."userId" AND v."expiresAt">now()
          WHERE a."providerId"=$1 AND a."userId"=$2 LIMIT 2`,
          ['google', result.user.id, `google-migration:${result.session.id}`]);
        const subject = accounts.rows[0]?.accountId;
        if (accounts.rowCount === 1 && env.googleMigrationSubjects.has(subject)) migrationGoogleSubject = subject;
      }
      res.json({ legalAccepted, ...(migrationGoogleSubject ? {migrationGoogleSubject}:{}), ...(adminVerifiedAt ? {adminVerifiedAt}:{}), provider: 'better-auth', credentialKind: 'session', issuer: `${env.baseURL}/api/auth`,
        subject: result.user.id, sessionId: result.session.id, expiresAt: result.session.expiresAt.toISOString(),
        email: result.user.email, emailVerified: result.user.emailVerified });
    } catch {
      res.status(503).json({ error: 'Authentication unavailable' });
    }
  };
}
