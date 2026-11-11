import { totpReplayGuard } from './services/totpReplay.js';
import { APIError } from 'better-auth/api';
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
    emailAndPassword: {
      enabled: true, requireEmailVerification: true, minPasswordLength: 12, maxPasswordLength: 128,
      revokeSessionsOnPasswordReset: true,
      sendResetPassword: async ({ user, url }) => deliver({ to: user.email, url, kind: 'reset' }),
    },
    emailVerification: {
      sendOnSignUp: true, sendOnSignIn: true, autoSignInAfterVerification: false, expiresIn: 3600,
      sendVerificationEmail: async ({ user, url }) => deliver({ to: user.email, url, kind: 'verification' }),
    },
    socialProviders: env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET ? {google:{clientId:env.GOOGLE_CLIENT_ID,clientSecret:env.GOOGLE_CLIENT_SECRET}} : {},
    user: {additionalFields:{
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
    }}},user:{create:{before:async(user,ctx)=>{
      if(ctx?.path==='/sign-up/email') {
        const values=user as typeof user & {acceptedTermsVersion?:string;acceptedPrivacyVersion?:string};
        if(!env.AUTH_TERMS_VERSION || !env.AUTH_PRIVACY_VERSION)throw new APIError('SERVICE_UNAVAILABLE',{code:'SIGNUP_UNAVAILABLE',message:'Account creation is not available yet.'});
        if(values.acceptedTermsVersion!==env.AUTH_TERMS_VERSION || values.acceptedPrivacyVersion!==env.AUTH_PRIVACY_VERSION)throw new APIError('BAD_REQUEST',{code:'LEGAL_ACCEPTANCE_REQUIRED',message:'Review and accept the current terms and privacy policy.'});
        return {data:{...user,termsAcceptedAt:new Date()}};
      }
    }}}},
    account: { accountLinking: { enabled: false } },
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
