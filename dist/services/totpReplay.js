import { createHmac, timingSafeEqual } from 'node:crypto';
import { APIError, createAuthMiddleware } from 'better-auth/api';
import { symmetricDecrypt } from 'better-auth/crypto';
/** Same six-digit SHA-1/30s/±1 policy as the pinned twoFactor configuration. */
export function matchingTotpStep(secret, code, now = Date.now()) {
    if (!/^\d{6}$/.test(code))
        return undefined;
    const current = Math.floor(now / 30000);
    let matched;
    for (let step = Math.max(0, current - 1); step <= current + 1; step++) {
        const counter = Buffer.alloc(8);
        counter.writeBigUInt64BE(BigInt(step));
        const digest = createHmac('sha1', secret).update(counter).digest();
        const offset = digest[digest.length - 1] & 15;
        const expected = ((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
        if (timingSafeEqual(Buffer.from(expected), Buffer.from(code)))
            matched = step;
    }
    return matched;
}
function decodeSecret(value) {
    // Match Better Auth's documented Auth0 import representation as well as generated UTF-8 secrets.
    if (!value.startsWith('base32:'))
        return Buffer.from(value, 'utf8');
    let bits = '';
    for (const char of value.slice(7).toUpperCase().replace(/=+$/, '')) {
        const index = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
        if (index < 0)
            throw new Error('Invalid factor secret');
        bits += index.toString(2).padStart(5, '0');
    }
    return Buffer.from((bits.match(/.{8}/g) || []).map(byte => parseInt(byte, 2)));
}
export async function claimTotpStep(db, factorId, step) {
    const result = await db.query(`INSERT INTO totp_replay("factorId","lastStep") VALUES($1,$2)
    ON CONFLICT("factorId") DO UPDATE SET "lastStep"=EXCLUDED."lastStep"
    WHERE totp_replay."lastStep"<EXCLUDED."lastStep" RETURNING "factorId"`, [factorId, step]);
    return result.rowCount === 1;
}
/** Runs after bearer translation, BEFORE any MFA endpoint can create a session. */
export function totpReplayGuard(db) {
    return {
        id: 'ezboss-totp-replay',
        hooks: { before: [{
                    matcher: ctx => ctx.path === '/two-factor/verify-totp' || ctx.path === '/two-factor/verify-backup-code',
                    handler: createAuthMiddleware(async (ctx) => {
                        if (ctx.body?.trustDevice === true)
                            throw new APIError('BAD_REQUEST', { code: 'TRUSTED_DEVICE_DISABLED', message: 'Trusted devices are not enabled for this deployment.' });
                        if (ctx.path !== '/two-factor/verify-totp')
                            return;
                        const code = ctx.body?.code;
                        if (typeof code !== 'string' || !/^\d{6}$/.test(code))
                            return; // Preserve provider validation/attempt counters.
                        try {
                            // Read authoritative sessions directly. The pinned before-hook cookie helper
                            // is bound before bearer translation; relying on its cached session here skips native enrollment.
                            let token = await ctx.getSignedCookie(ctx.context.authCookies.sessionToken.name, ctx.context.secret);
                            const authorization = ctx.headers?.get('authorization') || ctx.request?.headers.get('authorization');
                            if (authorization?.startsWith('Bearer ')) {
                                const signed = decodeURIComponent(authorization.slice(7));
                                const parts = signed.split('.');
                                token = false;
                                if (parts.length === 2) {
                                    const expected = createHmac('sha256', ctx.context.secret).update(parts[0]).digest();
                                    const actual = Buffer.from(parts[1], 'base64url');
                                    if (actual.length === expected.length && timingSafeEqual(actual, expected))
                                        token = parts[0];
                                }
                            }
                            let userId;
                            if (token) {
                                const active = await db.query('SELECT "userId" FROM session WHERE token=$1 AND "expiresAt">now()', [token]);
                                userId = active.rows[0]?.userId;
                            }
                            if (!userId) {
                                // Pinned plugin contract: intermediate cookie contains a signed opaque verification key.
                                // Its value and expiry are resolved on the server, never from client identity fields.
                                const cookie = ctx.context.createAuthCookie('two_factor');
                                const key = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
                                if (!key)
                                    return;
                                const pending = await ctx.context.internalAdapter.findVerificationValue(key);
                                if (!pending || pending.expiresAt.getTime() <= Date.now())
                                    return;
                                userId = pending.value;
                            }
                            const factor = await db.query('SELECT id,secret FROM "twoFactor" WHERE "userId"=$1', [userId]);
                            if (factor.rows.length > 1)
                                throw new APIError('UNAUTHORIZED', { code: 'INVALID_FACTOR', message: 'Authentication factor unavailable' });
                            if (!factor.rows.length)
                                return; // Provider rejects absent factor state.
                            const row = factor.rows[0];
                            const plaintext = await symmetricDecrypt({ key: ctx.context.secretConfig, data: row.secret });
                            const step = matchingTotpStep(decodeSecret(plaintext), code);
                            if (step === undefined)
                                return; // Invalid codes still run through provider lockout bookkeeping.
                            // A consumed valid step remains consumed even if later work fails. Retry with the next code.
                            if (!await claimTotpStep(db, row.id, step))
                                throw new APIError('UNAUTHORIZED', {
                                    code: 'TOTP_REPLAYED', message: 'Wait for a new authenticator code and try again.',
                                });
                        }
                        catch (error) {
                            if (error instanceof APIError)
                                throw error;
                            throw new APIError('SERVICE_UNAVAILABLE', { code: 'AUTH_UNAVAILABLE', message: 'Authentication unavailable. Try again later.' });
                        }
                    }),
                }] },
    };
}
