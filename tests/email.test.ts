import test from 'node:test';
import assert from 'node:assert/strict';
import { createMailDelivery } from '../src/services/email.js';
import { readEnvironment } from '../src/env.js';
const env=readEnvironment({DEPLOYMENT_ENV:'development',BETTER_AUTH_URL:'http://localhost:3005',APP_ORIGIN:'http://localhost:5173',DATABASE_URL:'postgresql://localhost/proof',BETTER_AUTH_SECRET:'proof-only-000000000000000000000001',AUTH_INTERNAL_SECRET:'proof-only-000000000000000000000002',MAILGUN_API_KEY:'sensitive-private-key',MAILGUN_DOMAIN: 'example.test', MAILGUN_FROM:'noreply@example.test'});
test('email uses fixed HTTPS endpoint, bounded timeout and generic failures',async()=>{
 const requests: Array<{ url: unknown; init?: RequestInit }> = [];
 const deliver=createMailDelivery(env,async(url,init)=>{
  requests.push({url,init});
  return new Response('sensitive provider response',{status:503});
 });
 await assert.rejects(deliver({to:'private@example.test',url:'http://localhost:3005/api/auth/verify-email?token=private-token',kind:'verification'}),{message:'Authentication email delivery unavailable'});
 await assert.rejects(deliver({to:'private@example.test',url:'https://attacker.test/link',kind:'reset'}));
 assert.equal(requests.length,1);
 const [{url,init}]=requests;
 assert.equal(url,'https://api.mailgun.net/v3/example.test/messages');
 assert.equal(init?.redirect,'error');
 assert.ok(init?.signal);
 assert.equal(new Headers(init?.headers).get('Authorization'),'Basic '+Buffer.from('api:sensitive-private-key').toString('base64'));
 assert.ok(init?.body instanceof FormData);
 assert.equal(init.body.get('from'),'noreply@example.test');
 assert.equal(init.body.get('to'),'private@example.test');
 assert.equal(init.body.get('o:tracking-clicks'),'no');
 assert.match(String(init.body.get('text')),/token=private-token/);
});
