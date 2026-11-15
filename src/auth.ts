import { randomUUID } from 'node:crypto';
import { totpReplayGuard } from './services/totpReplay.js';
import { APIError, createAuthMiddleware, getOAuthState } from 'better-auth/api';
import { betterAuth } from 'better-auth';
import { bearer, twoFactor, jwt } from 'better-auth/plugins';
import { passkey } from '@better-auth/passkey';
import { oauthProvider } from '@better-auth/oauth-provider';
import type { Pool } from 'pg';
import type { Environment } from './env.js';
import type { DeliverMail } from './services/email.js';

export function createAuth(env: Environment, database: Pool, deliver: DeliverMail) {
  return betterAuth({
    appName: 'EzBoss', baseURL: env.baseURL, basePath: '/api/auth', secret: env.BETTER_AUTH_SECRET,
    database, trustedOrigins: [env.appOrigin],
    // OAuth linking remains available to the server wrapper after merge verification.
    disabledPaths: ['/link-social'],
    hooks: { before: createAuthMiddleware(async ctx => {
      if (ctx.path === '/sign-up/email') {
        const password = ctx.body?.password;
        if (typeof password === 'string' && (!/\p{Lu}/u.test(password) || !/[\p{P}\p{S}]/u.test(password) || !/\p{Nd}/u.test(password))) {
          throw new APIError('BAD_REQUEST', { code: 'PASSWORD_REQUIREMENTS_NOT_MET', message: 'Use at least 8 characters, one uppercase letter, one symbol, and one number.' });
        }
        return;
      }
      // Better Auth shares its minimum between signup and other password flows.
      if ((ctx.path === '/reset-password' || ctx.path === '/change-password') &&
          typeof ctx.body?.newPassword === 'string' && ctx.body.newPassword.length < 12) {
        throw new APIError('BAD_REQUEST', { code: 'PASSWORD_TOO_SHORT', message: 'Password must be at least 12 characters.' });
      }
      if (ctx.path !== '/reset-password') return;
      const token = ctx.body?.token || ctx.query?.token;
      if (typeof token !== 'string') return;
      const verification = await ctx.context.internalAdapter.findVerificationValue(`reset-password:${token}`);
      if (!verification || !(await ctx.context.internalAdapter.findCredentialAccount(verification.value))?.password) {
        throw new APIError('BAD_REQUEST', {code:'INVALID_TOKEN', message:'Invalid or expired recovery link.'});
      }
    }), after: createAuthMiddleware(async ctx => {
      const failure = ctx.context.returned;
      const email = ctx.body?.email;
      if (ctx.path !== '/sign-in/email' || !(failure instanceof APIError) ||
          failure.body?.code !== 'INVALID_EMAIL_OR_PASSWORD' || typeof email !== 'string' ||
          !env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) return;

      // Keep the sign-in response identical for unknown addresses and both account types.
      // This service runs as a persistent Express process, so mail can follow the response.
      void (async () => {
        const {rows:[user]} = await database.query<{id:string;email:string}>(`
          SELECT u.id,u.email FROM "user" u WHERE u.email=$1 AND u."emailVerified"
          AND u."twoFactorEnabled" IS DISTINCT FROM true
          AND EXISTS (SELECT 1 FROM account WHERE "userId"=u.id AND "providerId"='google')
          AND NOT EXISTS (SELECT 1 FROM account WHERE "userId"=u.id AND "providerId"='credential' AND password IS NOT NULL)
        `,[email.toLowerCase()]);
        if (!user) return;

        const now = Date.now();
        const allowed = await database.query(`
          INSERT INTO "rateLimit"(id,key,count,"lastRequest") VALUES($1,$2,1,$3)
          ON CONFLICT(key) DO UPDATE SET "lastRequest"=EXCLUDED."lastRequest"
          WHERE "rateLimit"."lastRequest"<=$4 RETURNING id
        `,[randomUUID(),`first-password-mail:${user.id}`,now,now-15*60_000]);
        if (allowed.rowCount) await deliver({
          to:user.email, kind:'first-password', url:env.appOrigin+'/auth/merge?kind=password',
        });
      })().catch(() => console.warn('First-password email could not be delivered'));
    }) },
    emailAndPassword: {
      enabled: true, requireEmailVerification: true, minPasswordLength: 8, maxPasswordLength: 128,
      revokeSessionsOnPasswordReset: true,
      sendResetPassword: async ({ user, url }) => {
        if ((await database.query(`SELECT 1 FROM account WHERE "userId"=$1 AND "providerId"='credential' AND password IS NOT NULL`, [user.id])).rowCount) {
          await deliver({ to: user.email, url, kind: 'reset' });
        }
      },
    },
    emailVerification: {
      sendOnSignUp: true, sendOnSignIn: true, autoSignInAfterVerification: false, expiresIn: 3600,
      sendVerificationEmail: async ({ user, url }) => deliver({ to: user.email, url, kind: 'verification' }),
    },
    socialProviders: env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET ? {
      google: {
        clientId: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        prompt: 'select_account',
        disableImplicitSignUp: true,
      },
    } : {},
    user: {
      async validateUserInfo({user, source}, context) {
        if (source.action === 'link-account' && source.oauth?.providerId === 'google') {
          const local = (await database.query('SELECT email,"emailVerified" FROM "user" WHERE id=$1',[user.id])).rows[0];
          if ((!context.path?.startsWith('/callback/') || context.params?.id !== 'google') || user.emailVerified !== true || !local?.emailVerified ||
              local.email.toLowerCase() !== user.email?.toLowerCase()) return {error:'google_merge_email_mismatch'};
          // OAuth additionalData is client-writable. Only a live, server-minted grant
          // for this user can authorize the callback; the string in state is not proof.
          const grant = (await getOAuthState())?.ezbossMergeGrant;
          if (typeof grant !== 'string' || !(await database.query(`DELETE FROM verification
            WHERE id=$1 AND identifier='ezboss-merge-link-grant' AND value=$2 AND "expiresAt">now()`,
            [`merge-link:${grant}`,user.id])).rowCount) return {error:'google_merge_verification_required'};
        }
        if (source.action !== 'create-user' || source.oauth?.providerId !== 'google') return;
        const profile = source.oauth.profile as {sub?: unknown} | undefined;
        if (!context.path?.startsWith('/callback/') || user.emailVerified !== true ||
            typeof profile?.sub !== 'string' || !env.googleMigrationSubjects.has(profile.sub)) {
          return {error:'google_migration_not_allowed'};
        }
      },
      additionalFields:{
      acceptedTermsVersion:{type:'string',required:false,input:true,returned:false},
      acceptedPrivacyVersion:{type:'string',required:false,input:true,returned:false},
      termsAcceptedAt:{type:'date',required:false,input:false,returned:false},
    }},
    databaseHooks:{session:{create:{before:async(session,ctx)=>{
      // The pinned TOTP plugin does not challenge social callbacks. Never silently
      // bypass an enrolled factor while that separate continuation flow is pending.
      if(ctx?.path?.startsWith('/callback/') || ctx?.path==='/sign-in/social') {
        const user=(await database.query('SELECT "twoFactorEnabled" FROM "user" WHERE id=$1',[session.userId])).rows[0];
        if(user?.twoFactorEnabled===true)throw new APIError('FORBIDDEN',{code:'SOCIAL_MFA_CONTINUATION_REQUIRED',message:'Use your password and authenticator or an enrolled passkey to sign in.'});
      }
    },after:async(session,ctx)=>{
      if (ctx?.path?.startsWith('/callback/') && ctx.params?.id === 'google') {
        await database.query(`INSERT INTO verification(id,identifier,value,"expiresAt")
          VALUES($1,$2,$3,LEAST($4,now()+interval '10 minutes'))`,
          [`merge-google:${session.id}`,'ezboss-merge-google',session.userId,session.expiresAt]);
      }
      if (!env.googleMigrationSubjects.size || !ctx?.path?.startsWith('/callback/')) return;
      await database.query(`INSERT INTO verification(id,identifier,value,"expiresAt")
        VALUES($1,$2,$3,LEAST($4,now()+interval '15 minutes'))`,
        [`google-migration:${session.id}`,'ezboss-google-migration',session.userId,session.expiresAt]);
    }}},user:{create:{before:async(user,ctx)=>{
      if(ctx?.path==='/sign-up/email') {
        const values=user as typeof user & {acceptedTermsVersion?:string;acceptedPrivacyVersion?:string};
        if(!env.AUTH_TERMS_VERSION || !env.AUTH_PRIVACY_VERSION)throw new APIError('SERVICE_UNAVAILABLE',{code:'SIGNUP_UNAVAILABLE',message:'Account creation is not available yet.'});
        if(values.acceptedTermsVersion!==env.AUTH_TERMS_VERSION || values.acceptedPrivacyVersion!==env.AUTH_PRIVACY_VERSION)throw new APIError('BAD_REQUEST',{code:'LEGAL_ACCEPTANCE_REQUIRED',message:'Review and accept the current terms and privacy policy.'});
        return {data:{...user,termsAcceptedAt:new Date()}};
      }
    }}}},
    account: { accountLinking: { disableImplicitLinking: true, allowDifferentEmails: false } },
    session: { expiresIn: 60 * 60 * 24 * 7, updateAge: 60 * 60 * 24, freshAge: 300,
      cookieCache: { enabled: false } },
    rateLimit: { enabled: true, storage: 'database', window: 60, max: 60,
      customRules: { '/sign-in/email': { window: 60, max: 5 }, '/sign-up/email': { window: 60, max: 3 },
        '/request-password-reset': { window: 60, max: 3 }, '/send-verification-email': { window: 60, max: 3 },
        '/two-factor/*': { window: 60, max: 5 } } },
    advanced: {
      useSecureCookies: env.secureCookies,
      defaultCookieAttributes: { httpOnly: true, secure: env.secureCookies, sameSite: 'lax', path: '/' },
      // The app sets this from the transport peer; never trust caller-supplied forwarding headers.
      ipAddress: { ipAddressHeaders: ['x-ezboss-peer-ip'] },
    },
    plugins: [
      twoFactor({ issuer: 'EzBoss', totpOptions: { digits: 6, period: 30 }, backupCodeOptions: { storeBackupCodes: 'encrypted' } }),
      passkey({ rpID: new URL(env.appOrigin).hostname, rpName: 'EzBoss', origin: env.appOrigin,
        authenticatorSelection: { userVerification: 'required' } }),
      jwt({ disableSettingJwtHeader: true }),
      oauthProvider({ loginPage: `${env.appOrigin}/login`, consentPage: `${env.appOrigin}/oauth/consent`,
        allowDynamicClientRegistration: false, scopes: ['openid', 'profile', 'email', 'offline_access', 'ezboss:api'] }),
      // Run after the MFA hook has removed intermediate session cookies.
      bearer({ requireSignature: true }),
      totpReplayGuard(database),
    ],
    logger: { disabled: true },
  });
}
export type Auth = ReturnType<typeof createAuth>;
