import test from 'node:test';
import assert from 'node:assert/strict';
import { readEnvironment } from '../src/env.js';
export const proofEnvironment = {
 DEPLOYMENT_ENV: 'development', BETTER_AUTH_URL: 'http://localhost:3005', APP_ORIGIN: 'http://localhost:5173',
 DATABASE_URL: 'postgresql://ezboss_proof@127.0.0.1:55439/ezboss_auth_test',
 BETTER_AUTH_SECRET: 'local-test-only-000000000000000001', AUTH_INTERNAL_SECRET: 'local-test-only-000000000000000002',
 MAIL_API_KEY: 'test', MAIL_FROM: 'noreply@example.test',
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
