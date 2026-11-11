import { z } from 'zod';

const secret = z.string().min(32);
function origin(value: string, local: boolean): string {
  const url = new URL(value);
  if (url.hostname.includes('*') || url.username || url.password || url.pathname !== '/' || url.search || url.hash ||
      (url.protocol !== 'https:' && !(local && url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)))) {
    throw new Error('Auth URLs must be exact HTTPS origins (loopback HTTP is development-only)');
  }
  return url.origin;
}
export function readEnvironment(input: NodeJS.ProcessEnv = process.env) {
  const parsed = z.object({
    DEPLOYMENT_ENV: z.enum(['development', 'staging', 'production']),
    BETTER_AUTH_URL: z.string(), APP_ORIGIN: z.string(), DATABASE_URL: z.string().url(),
    BETTER_AUTH_SECRET: secret, AUTH_INTERNAL_SECRET: secret,
    MAIL_API_KEY: z.string().min(1), MAIL_FROM: z.email(),
    GOOGLE_CLIENT_ID: z.string().optional(), GOOGLE_CLIENT_SECRET: z.string().optional(),
    AUTH_TERMS_VERSION: z.string().optional(), AUTH_PRIVACY_VERSION: z.string().optional(),
    AUTH_TERMS_URL: z.string().url().optional(), AUTH_PRIVACY_URL: z.string().url().optional(),
    PORT: z.coerce.number().int().min(1).max(65535).default(3005),
  }).safeParse(input);
  // Never include Zod input values in configuration failures.
  if (!parsed.success) throw new Error(`Invalid auth configuration: ${parsed.error.issues.map(i => i.path.join('.')).join(', ')}`);
  const env = parsed.data;
  if(Boolean(env.GOOGLE_CLIENT_ID)!==Boolean(env.GOOGLE_CLIENT_SECRET))throw new Error('Google requires both server-side OAuth settings');
  const consent=[env.AUTH_TERMS_VERSION,env.AUTH_PRIVACY_VERSION,env.AUTH_TERMS_URL,env.AUTH_PRIVACY_URL];
  if(consent.some(Boolean) && !consent.every(Boolean))throw new Error('Legal publication requires both approved versions and URLs');
  const local = env.DEPLOYMENT_ENV === 'development';
  const baseURL = origin(env.BETTER_AUTH_URL, local);
  const appOrigin = origin(env.APP_ORIGIN, local);
  if (env.BETTER_AUTH_SECRET === env.AUTH_INTERNAL_SECRET) throw new Error('Auth secrets must be independent');
  for(const link of [env.AUTH_TERMS_URL,env.AUTH_PRIVACY_URL])if(link){
    const target=new URL(link);
    if(target.origin!==appOrigin || target.username || target.password || target.search || target.hash)throw new Error('Legal documents must use the exact public app origin');
  }
  const db = new URL(env.DATABASE_URL);
  if (!['postgres:', 'postgresql:'].includes(db.protocol)) throw new Error('PostgreSQL is required');
  return { ...env, baseURL, appOrigin, secureCookies: new URL(baseURL).protocol === 'https:' };
}
export type Environment = ReturnType<typeof readEnvironment>;
