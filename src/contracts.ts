import { z } from 'zod';
export const sessionIdentity = z.object({
  provider: z.literal('better-auth'), credentialKind: z.literal('session'),
  issuer: z.string().url(), subject: z.string().min(1).max(256), sessionId: z.string().min(1).max(256),
  expiresAt: z.iso.datetime(), adminVerifiedAt:z.iso.datetime().optional(), legalAccepted:z.boolean().optional(), email: z.email(), emailVerified: z.boolean(),
}).strict();
export type SessionIdentity = z.infer<typeof sessionIdentity>;
