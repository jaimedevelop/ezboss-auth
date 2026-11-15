import { createHmac, randomInt, randomUUID } from 'node:crypto';
import { Router } from 'express';
import { symmetricDecrypt } from 'better-auth/crypto';
import { fromNodeHeaders } from 'better-auth/node';
import { z } from 'zod';
import { claimTotpStep, decodeSecret, matchingTotpStep } from '../services/totpReplay.js';
const kindSchema = z.enum(['google', 'password']);
const password = z.string().min(12).max(128);
export function accountMergeRoutes(auth, env, db, deliver) {
    const router = Router();
    async function status({ user, session }) {
        const { rows: [row] } = await db.query(`SELECT u.email,u."emailVerified",u."twoFactorEnabled" IS TRUE AS totp,
        EXISTS(SELECT 1 FROM account WHERE "userId"=u.id AND "providerId"='google') AS google,
        EXISTS(SELECT 1 FROM account WHERE "userId"=u.id AND "providerId"='credential' AND password IS NOT NULL) AS credential,
        EXISTS(SELECT 1 FROM verification WHERE id=$2 AND value=u.id AND "expiresAt">now()) AS "googleProof"
      FROM "user" u WHERE u.id=$1`, [user.id, `merge-google:${session.id}`]);
        return row;
    }
    function eligible(row, kind) {
        return row?.emailVerified && (kind === 'google'
            ? Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET && row.credential && !row.google)
            : row.google && !row.credential && row.googleProof);
    }
    const identifier = (identity, kind) => `ezboss-merge:${identity.session.id}:${kind}`;
    const totpValue = (id, email) => JSON.stringify(['totp', id, email]);
    const digest = (key, id, code) => createHmac('sha256', env.BETTER_AUTH_SECRET).update(JSON.stringify([key, id, code])).digest('hex');
    const start = z.object({ kind: kindSchema, currentPassword: z.string().min(1).max(128).optional() }).strict();
    const confirm = z.object({ kind: kindSchema, id: z.uuid(), code: z.string().regex(/^\d{6}$/), newPassword: password.optional(), hosted: z.boolean().optional(), returnTo: z.string().max(2048).optional() }).strict();
    router.post('/status', async (_req, res) => {
        const row = await status(res.locals.session);
        res.json({ canLinkGoogle: eligible(row, 'google'), canAddPassword: eligible(row, 'password'), googleConnected: row.google, hasPassword: row.credential, email: row.email });
    });
    router.post('/start', async (req, res) => {
        const data = start.safeParse(req.body);
        if (!data.success)
            return res.status(400).json({ code: 'MERGE_UNAVAILABLE' });
        const identity = res.locals.session;
        const { kind, currentPassword } = data.data;
        const row = await status(identity);
        if (!eligible(row, kind))
            return res.status(409).json({ code: 'MERGE_UNAVAILABLE' });
        if (kind === 'google') {
            if (!currentPassword)
                return res.status(400).json({ code: 'MERGE_PASSWORD_INVALID' });
            try {
                await auth.api.verifyPassword({ headers: fromNodeHeaders(req.headers), body: { password: currentPassword } });
            }
            catch {
                return res.status(400).json({ code: 'MERGE_PASSWORD_INVALID' });
            }
        }
        const key = identifier(identity, kind);
        const id = randomUUID();
        const code = randomInt(1000000).toString().padStart(6, '0');
        // A new request replaces this session's previous challenge. The security router limits
        // attempts across the user's sessions. Store only a keyed digest, never the email code.
        const proof = row.totp ? totpValue(id, row.email) : digest(key, id, code + row.email);
        const value = id + ':' + proof;
        await db.query(`INSERT INTO verification(id,identifier,value,"expiresAt")
      VALUES($1,$1,$2,now()+interval '5 minutes') ON CONFLICT(id) DO UPDATE
      SET value=EXCLUDED.value,"expiresAt"=EXCLUDED."expiresAt"`, [key, value]);
        if (!row.totp) {
            try {
                await deliver({ to: row.email, code, kind: 'merge' });
            }
            catch (error) {
                await db.query('DELETE FROM verification WHERE id=$1 AND value=$2', [key, value]);
                throw error;
            }
        }
        res.json({ id, factor: row.totp ? 'totp' : 'email' });
    });
    router.post('/confirm', async (req, res) => {
        const data = confirm.safeParse(req.body);
        if (!data.success || (data.data.kind === 'password') !== (data.data.newPassword !== undefined)) {
            return res.status(400).json({ code: 'MERGE_UNAVAILABLE' });
        }
        const identity = res.locals.session;
        const { kind, id, code, newPassword, hosted, returnTo } = data.data;
        const row = await status(identity);
        if (!eligible(row, kind))
            return res.status(409).json({ code: 'MERGE_UNAVAILABLE' });
        const key = identifier(identity, kind);
        if (!(await db.query(`SELECT 1 FROM verification WHERE id=$1 AND left(value,37)=$2 AND "expiresAt">now()`, [key, id + ':'])).rowCount) {
            return res.status(400).json({ code: 'MERGE_CODE_INVALID' });
        }
        const attempts = await db.query(`INSERT INTO "rateLimit"(id,key,count,"lastRequest") VALUES($1,$2,1,$3)
      ON CONFLICT(key) DO UPDATE SET count="rateLimit".count+1 WHERE "rateLimit".count<5 RETURNING id`, [randomUUID(), `merge-attempt:${key}:${id}`, Date.now()]);
        if (!attempts.rowCount)
            return res.status(400).json({ code: 'MERGE_CODE_INVALID' });
        const proof = row.totp ? totpValue(id, row.email) : digest(key, id, code + row.email);
        const value = id + ':' + proof;
        if (row.totp) {
            const { rows } = await db.query(`SELECT id,secret FROM "twoFactor" WHERE "userId"=$1 AND verified IS DISTINCT FROM false`, [identity.user.id]);
            const factor = rows.length === 1 ? rows[0] : undefined;
            const context = await auth.$context;
            const step = factor && matchingTotpStep(decodeSecret(await symmetricDecrypt({ key: context.secretConfig, data: factor.secret })), code);
            if (!factor || step === undefined || !await claimTotpStep(db, factor.id, step)) {
                return res.status(400).json({ code: 'MERGE_CODE_INVALID' });
            }
        }
        const consumed = await db.query(`DELETE FROM verification WHERE id=$1 AND value=$2 AND "expiresAt">now()`, [key, value]);
        if (!consumed.rowCount)
            return res.status(400).json({ code: 'MERGE_CODE_INVALID' });
        const headers = fromNodeHeaders(req.headers);
        if (kind === 'password') {
            await auth.api.setPassword({ headers, body: { newPassword: newPassword } });
            return res.json({ ok: true });
        }
        const callback = new URL('/auth/merge?kind=google', env.appOrigin);
        if (hosted)
            callback.searchParams.set('hosted', '1');
        if (returnTo?.startsWith('/') && !returnTo.startsWith('//') && !returnTo.includes('\\') &&
            new URL(returnTo, env.appOrigin).origin === env.appOrigin)
            callback.searchParams.set('returnTo', returnTo);
        const grant = randomUUID();
        await db.query(`INSERT INTO verification(id,identifier,value,"expiresAt")
      VALUES($1,'ezboss-merge-link-grant',$2,now()+interval '5 minutes')`, [`merge-link:${grant}`, identity.user.id]);
        const result = await auth.api.linkSocialAccount({ headers, returnHeaders: true, body: {
                provider: 'google', callbackURL: callback + '&linked=1', errorCallbackURL: callback + '&linkError=1',
                disableRedirect: true, loginHint: row.email, additionalData: { ezbossMergeGrant: grant },
            } });
        for (const cookie of result.headers.getSetCookie())
            res.append('Set-Cookie', cookie);
        res.json({ url: result.response.url });
    });
    return router;
}
