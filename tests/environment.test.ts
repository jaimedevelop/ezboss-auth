import test from 'node:test';
import assert from 'node:assert/strict';
import { readEnvironment } from '../src/env.js';
export const proofEnvironment = {
 DEPLOYMENT_ENV: 'development', BETTER_AUTH_URL: 'http://localhost:3005', APP_ORIGIN: 'http://localhost:5173',
 DATABASE_URL: 'postgresql://ezboss_proof@127.0.0.1:55439/ezboss_auth_test',
 BETTER_AUTH_SECRET: 'local-test-only-000000000000000001', AUTH_INTERNAL_SECRET: 'local-test-only-000000000000000002',
 MAILGUN_API_KEY: 'test', MAILGUN_DOMAIN: 'example.test', MAILGUN_FROM: 'noreply@example.test',
};
test('configuration rejects unsafe origins, shared secrets and malformed database URLs without echoing inputs', () => {
 assert.equal(readEnvironment(proofEnvironment).secureCookies, false);
 for (const change of [ { DEPLOYMENT_ENV:'production' }, {APP_ORIGIN:'https://example.com/path'},
  {BETTER_AUTH_URL:'https://user:password@example.com'}, {APP_ORIGIN:'https://*.example.com'},
  {DATABASE_URL:'https://example.com'}, {AUTH_INTERNAL_SECRET:proofEnvironment.BETTER_AUTH_SECRET} ]) {
   assert.throws(() => readEnvironment({...proofEnvironment,...change}));
 }
 assert.throws(() => readEnvironment({...proofEnvironment, BETTER_AUTH_SECRET:'sensitive'}), e => !String(e).includes('sensitive'));
});

test('Google migration accepts spaced subject lists and identifies configuration errors', () => {
 const oauth = {...proofEnvironment, GOOGLE_CLIENT_ID:'client', GOOGLE_CLIENT_SECRET:'secret'};
 assert.deepEqual([...readEnvironment({...oauth, GOOGLE_MIGRATION_SUBJECTS:' 001, 234 '}).googleMigrationSubjects], ['001','234']);
 assert.throws(() => readEnvironment({...oauth, GOOGLE_MIGRATION_SUBJECTS:'001,email@example.com'}), /comma-separated numeric Google subject IDs/);
 assert.throws(() => readEnvironment({...proofEnvironment, GOOGLE_MIGRATION_SUBJECTS:'001'}), /requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET/);
});
