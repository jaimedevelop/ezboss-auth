import test from 'node:test';
import assert from 'node:assert/strict';
import { createMailDelivery } from '../src/services/email.js';
import { readEnvironment } from '../src/env.js';
const env=readEnvironment({DEPLOYMENT_ENV:'development',BETTER_AUTH_URL:'http://localhost:3005',APP_ORIGIN:'http://localhost:5173',DATABASE_URL:'postgresql://localhost/proof',BETTER_AUTH_SECRET:'proof-only-000000000000000000000001',AUTH_INTERNAL_SECRET:'proof-only-000000000000000000000002',MAIL_API_KEY:'sensitive-private-key',MAIL_FROM:'noreply@example.test'});
test('email uses fixed HTTPS endpoint, bounded timeout and generic failures',async()=>{
 let calls=0;
 const deliver=createMailDelivery(env,async(url,init)=>{
  calls++;assert.equal(url,'https://api.resend.com/emails');assert.equal(init?.redirect,'error');assert.ok(init?.signal);
  return new Response('sensitive provider response',{status:503});
 });
 await assert.rejects(deliver({to:'private@example.test',url:'http://localhost:3005/api/auth/verify-email?token=private-token',kind:'verification'}),error=>!String(error).includes('sensitive')&&!String(error).includes('private'));
 await assert.rejects(deliver({to:'private@example.test',url:'https://attacker.test/link',kind:'reset'}));
 assert.equal(calls,1);
});
