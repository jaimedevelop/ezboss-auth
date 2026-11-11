import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Pool } from 'pg';
import { createAuth } from '../src/auth.js';
import { readEnvironment } from '../src/env.js';
import { createApp } from '../src/app.js';
import { claimTotpStep } from '../src/services/totpReplay.js';
import { AdminStepUp } from '../src/services/adminStepUp.js';
import type { Mail } from '../src/services/email.js';

const dbUrl = process.env.AUTH_TEST_DATABASE_URL;
test('real PostgreSQL protocol: verification, signed native bearer, MFA intermediate, revocation and internal boundary', async () => {
 assert.ok(dbUrl, 'AUTH_TEST_DATABASE_URL must name a disposable loopback ezboss_auth_test database');
 const url = new URL(dbUrl);
 assert.ok(['127.0.0.1','localhost'].includes(url.hostname) && url.pathname === '/ezboss_auth_test', 'Refusing non-disposable database');
 const env = readEnvironment({DEPLOYMENT_ENV:'development', BETTER_AUTH_URL:'http://localhost:3005', APP_ORIGIN:'http://localhost:5173',
 DATABASE_URL:dbUrl,AUTH_TERMS_VERSION:'proof-1',AUTH_PRIVACY_VERSION:'proof-1',AUTH_TERMS_URL:'http://localhost:5173/proof-terms',AUTH_PRIVACY_URL:'http://localhost:5173/proof-privacy', BETTER_AUTH_SECRET:'local-test-only-000000000000000001', AUTH_INTERNAL_SECRET:'local-test-only-000000000000000002', MAIL_API_KEY:'test', MAIL_FROM:'noreply@example.test'});
 const pool = new Pool({connectionString:dbUrl, options:'-c search_path=ezboss_auth', statement_timeout:5000});
 const messages: Mail[] = [];

 let server: ReturnType<ReturnType<typeof createApp>['listen']> | undefined;
 try {
  await pool.query('DROP SCHEMA IF EXISTS ezboss_auth CASCADE');
  await pool.query(await readFile(new URL('../schema/001_better_auth.sql',import.meta.url),'utf8'));
  await pool.query(await readFile(new URL('../schema/002_admin_assurance.sql',import.meta.url),'utf8'));
  await pool.query(await readFile(new URL('../schema/003_totp_replay.sql',import.meta.url),'utf8'));
  await pool.query(await readFile(new URL('../schema/004_identity_consent.sql',import.meta.url),'utf8'));
  const auth = createAuth(env,pool, async mail => {messages.push(mail);});
  const call = (path:string, body?:object, cookie?:string, bearer?:string) => auth.handler(new Request(`${env.baseURL}/api/auth${path}`,{
    method:body?'POST':'GET',headers:{origin:env.appOrigin,'x-ezboss-peer-ip':'127.0.0.1',...(body?{'Content-Type':'application/json'}:{}),...(cookie?{cookie}:{}),...(bearer?{authorization:`Bearer ${bearer}`}:{})},body:body?JSON.stringify(body):undefined}));
  const cookies = (response:Response) => response.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');
  const password = 'local proof password 12345';
  const email = 'proof@example.test';
  const signup = await call('/sign-up/email',{name:'Proof',email,password,acceptedTermsVersion:'proof-1',acceptedPrivacyVersion:'proof-1'});
  assert.equal(signup.status,200);
  assert.equal(signup.headers.get('set-auth-token'),null,'unverified signup must not issue a credential');
  assert.equal(messages.length,1);
  const verification = await auth.handler(new Request(messages[0].url));
  assert.ok([200,302].includes(verification.status));
  const login = await call('/sign-in/email',{email,password});
  assert.equal(login.status,200);
  const signedToken = login.headers.get('set-auth-token'); assert.ok(signedToken?.includes('.'));
  const cookie = cookies(login);
  const session = await call('/get-session',undefined,undefined,signedToken!);
  const identity = await session.json(); assert.ok(identity?.session?.id);
  assert.equal((await (await call('/get-session',undefined,undefined,signedToken!.split('.')[0])).json()),null,'unsigned database token is not a native credential');
  assert.equal((await (await call('/get-session',undefined,undefined,`${signedToken}bad`)).json()),null);
  assert.equal(await (await call('/get-session',undefined,undefined,'ezboss:cookie-session')).json(),null,'browser transport handles are never credentials');
  assert.ok((await (await call('/get-session',undefined,cookie)).json()).session);
  const enrollment = await call('/two-factor/enable',{password},undefined,signedToken!);
  assert.equal(enrollment.status,200);
  const setup = await enrollment.json(); assert.ok(setup.totpURI && setup.backupCodes.length);
  // Complete TOTP enrollment using the documented algorithm, no bypass of verification.
  const { createHmac } = await import('node:crypto');
  const secret = new URL(setup.totpURI).searchParams.get('secret')!;
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits='';
  for(const c of secret.toUpperCase().replace(/=+$/,'')) bits+=alphabet.indexOf(c).toString(2).padStart(5,'0');
  const bytes=Buffer.from((bits.match(/.{8}/g)||[]).map(s=>parseInt(s,2)));
  const counter=Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
  const hash=createHmac('sha1',bytes).update(counter).digest(); const offset=hash[19]&15;
  const code=((hash.readUInt32BE(offset)&0x7fffffff)%1000000).toString().padStart(6,'0');
  const badCode = code === '000000' ? '000001' : '000000';
  assert.ok((await call('/two-factor/verify-totp',{code:badCode},undefined,signedToken!)).status>=400);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM totp_replay')).rows[0].n,0,'bad codes never consume valid steps');
  assert.equal((await call('/two-factor/verify-totp',{code},undefined,signedToken!)).status,200);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM totp_replay')).rows[0].n,1,'enrollment must consume the valid TOTP step');
  const factorId=(await pool.query('SELECT id FROM "twoFactor" WHERE "userId"=$1',[identity.user.id])).rows[0].id;
  const nextStep=Math.floor(Date.now()/30000)+2;
  const claims=await Promise.all(Array.from({length:24},()=>claimTotpStep(pool,factorId,nextStep)));
  assert.equal(claims.filter(Boolean).length,1,'concurrent replicas admit only one claim');
  assert.equal(await claimTotpStep(pool,factorId,nextStep-1),false,'older steps remain rejected');
  await assert.rejects(claimTotpStep({query:async()=>{throw new Error('database offline');}} as any,factorId,nextStep+1));
  // Enrollment consumes the time step across all sessions/replicas.
  const replayProbe = await call('/sign-in/email',{email,password});
  const replayResult = await call('/two-factor/verify-totp',{code},cookies(replayProbe));
  assert.equal(replayResult.status,401,'enrollment code cannot be replayed in a fresh sign-in');
  assert.equal(replayResult.headers.get('set-auth-token'),null);
  assert.equal(await (await call('/get-session',undefined,cookies(replayProbe))).json(),null);
  const challenge = await call('/sign-in/email',{email,password});
  assert.equal(challenge.status,200);
  assert.equal((await challenge.clone().json()).twoFactorRedirect,true);
  assert.equal(challenge.headers.get('set-auth-token'),null,'MFA intermediate must not issue a native session');
  const intermediate = cookies(challenge);
  assert.equal(await (await call('/get-session',undefined,intermediate)).json(),null);
  const completed = await call('/two-factor/verify-backup-code',{code:setup.backupCodes[0]},intermediate);
  assert.equal(completed.status,200);
  const completeToken=completed.headers.get('set-auth-token'); assert.ok(completeToken);
  const socialHook=auth.options.databaseHooks?.session?.create?.before;
  assert.ok(socialHook);
  await assert.rejects(socialHook!({userId:identity.user.id} as any,{path:'/callback/google'} as any),'enrolled factors cannot be bypassed by a social callback');
  const trustedDevice=await call('/two-factor/verify-backup-code',{code:setup.backupCodes[1],trustDevice:true},intermediate);
  assert.equal(trustedDevice.status,400,'unreviewed trusted-device bypass is disabled');
  const again=await call('/sign-in/email',{email,password});
  assert.ok((await call('/two-factor/verify-backup-code',{code:setup.backupCodes[0]},cookies(again))).status>=400,'backup code reuse rejected');
  // A fixed first-party public client; never enable open dynamic registration.
  await pool.query(`INSERT INTO "oauthClient" (id,"clientId","redirectUris","tokenEndpointAuthMethod","grantTypes","responseTypes",scopes,"requirePKCE","skipConsent")
    VALUES ('proof-client','proof-native','["http://localhost:4000/callback"]','none','["authorization_code","refresh_token"]','["code"]','["openid","email","offline_access","ezboss:api"]',true,true)`);
  const { createHash, randomBytes } = await import('node:crypto');
  const verifier=randomBytes(32).toString('base64url');
  const challengeValue=createHash('sha256').update(verifier).digest('base64url');
  const params=new URLSearchParams({client_id:'proof-native',redirect_uri:'http://localhost:4000/callback',response_type:'code',scope:'openid email offline_access ezboss:api',state:'unpredictable-proof-state',code_challenge:challengeValue,code_challenge_method:'S256'});
  const authorize=async(query:URLSearchParams)=>auth.handler(new Request(`${env.baseURL}/api/auth/oauth2/authorize?${query}`,{headers:{authorization:`Bearer ${completeToken}`}}));
  const missingPkce=new URLSearchParams(params);missingPkce.delete('code_challenge');missingPkce.delete('code_challenge_method');
  const rejectedPkce=await authorize(missingPkce);
  const rejectedLocation=rejectedPkce.headers.get('location')||'';
  assert.ok(rejectedPkce.status>=400 || rejectedLocation.includes('error='),'public client requires PKCE');
  const authorized=await authorize(params);
  const location=authorized.headers.get('location');
  assert.ok(location,`OAuth authorization must redirect: ${authorized.status}`);
  const callback=new URL(location!);assert.equal(callback.origin,'http://localhost:4000');
  assert.equal(callback.searchParams.get('state'),'unpredictable-proof-state');
  const authCode=callback.searchParams.get('code');assert.ok(authCode,'authorization code issued');
  const tokenRequest=async(code:string,codeVerifier:string)=>auth.handler(new Request(`${env.baseURL}/api/auth/oauth2/token`,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','x-ezboss-peer-ip':'127.0.0.1'},body:new URLSearchParams({grant_type:'authorization_code',client_id:'proof-native',redirect_uri:'http://localhost:4000/callback',code,code_verifier:codeVerifier})}));
  const wrongVerifier=await tokenRequest(authCode!,randomBytes(32).toString('base64url'));
  assert.ok(wrongVerifier.status>=400,'wrong PKCE verifier rejected');
  const fresh=await authorize(params);const freshCode=new URL(fresh.headers.get('location')!).searchParams.get('code')!;
  const tokens=await tokenRequest(freshCode,verifier);assert.equal(tokens.status,200);
  const oauth=await tokens.json();assert.ok(oauth.access_token && oauth.refresh_token);
  assert.ok((await tokenRequest(freshCode,verifier)).status>=400,'authorization code replay rejected');
  assert.equal(await (await call('/get-session',undefined,undefined,oauth.access_token)).json(),null,'OAuth access token is not a session bearer');
  // Cryptographic WebAuthn fixture: signs real assertions, not a client MFA flag.
  const {generateKeyPairSync,sign}=await import('node:crypto');
  const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const jwk=pair.publicKey.export({format:'jwk'});
  const cose=Buffer.concat([Buffer.from([0xa5,0x01,0x02,0x03,0x26,0x20,0x01,0x21,0x58,0x20]),Buffer.from(jwk.x!,'base64url'),Buffer.from([0x22,0x58,0x20]),Buffer.from(jwk.y!,'base64url')]);
  const credentialId=randomBytes(32).toString('base64url');
  const active=await (await call('/get-session',undefined,undefined,completeToken!)).json();
  await pool.query(`INSERT INTO passkey(id,"publicKey","userId","credentialID",counter,"deviceType","backedUp") VALUES('proof-key',$1,$2,$3,0,'singleDevice',false)`,[cose.toString('base64url'),active.user.id,credentialId]);
  const stepUp=new AdminStepUp(pool,env);
  const assertion=(challenge:string,origin=env.appOrigin,uv=true,rp='localhost')=>{
   const clientDataJSON=Buffer.from(JSON.stringify({type:'webauthn.get',challenge,origin}));
   const authData=Buffer.concat([createHash('sha256').update(rp).digest(),Buffer.from([uv?5:1]),Buffer.from([0,0,0,1])]);
   const signature=sign('sha256',Buffer.concat([authData,createHash('sha256').update(clientDataJSON).digest()]),pair.privateKey);
   return {id:credentialId,rawId:credentialId,type:'public-key' as const,clientExtensionResults:{},response:{clientDataJSON:clientDataJSON.toString('base64url'),authenticatorData:authData.toString('base64url'),signature:signature.toString('base64url')}};
  };
  assert.equal(await stepUp.recent(active.user.id,active.session.id),undefined,'TOTP/backup-code login confers no admin assurance');
  for(const change of ['origin','uv','rp','challenge']){
   const transaction=await stepUp.challenge(active.user.id,active.session.id);
   const response=assertion(change==='challenge'?'wrong':transaction.options.challenge,change==='origin'?'https://attacker.test':env.appOrigin,change!=='uv',change==='rp'?'attacker.test':'localhost');
   await assert.rejects(stepUp.verify(active.user.id,active.session.id,transaction.transactionId,response));
  }
  const proof=await stepUp.challenge(active.user.id,active.session.id);
  const response=assertion(proof.options.challenge);
  await assert.rejects(stepUp.verify(active.user.id,'wrong-session',proof.transactionId,response));
  await assert.rejects(stepUp.verify('wrong-user',active.session.id,proof.transactionId,response));
  await stepUp.verify(active.user.id,active.session.id,proof.transactionId,response);
  assert.ok(await stepUp.recent(active.user.id,active.session.id));
  await assert.rejects(stepUp.verify(active.user.id,active.session.id,proof.transactionId,response),'challenge replay rejected');
  await pool.query(`UPDATE admin_assurance SET "verifiedAt"=now()-interval '301 seconds'`);
  assert.equal(await stepUp.recent(active.user.id,active.session.id),undefined);
  await pool.query(`UPDATE admin_assurance SET "verifiedAt"=now()+interval '1 minute'`);
  assert.equal(await stepUp.recent(active.user.id,active.session.id),undefined,'future proof rejected');
  server=createApp(auth,env,pool).listen(0,'127.0.0.1');
  await new Promise<void>(resolve=>server!.once('listening',resolve));
  const address=server.address(); assert.ok(address && typeof address!=='string');
  const verify = (key:string, credential=completeToken!)=>fetch(`http://127.0.0.1:${address.port}/internal/verify-session`,{method:'POST',headers:{'Content-Type':'application/json','X-EzBoss-Service-Key':key},body:JSON.stringify({transport:'bearer',credential})});
  assert.equal((await verify('wrong')).status,401);
  const verified=await verify(env.AUTH_INTERNAL_SECRET); assert.equal(verified.status,200);
  const principal=await verified.json(); assert.equal(principal.subject,identity.user.id); assert.equal(principal.credentialKind,'session');
  assert.equal(JSON.stringify(principal).includes(completeToken!),false);
  const publicOrigin=`http://127.0.0.1:${address.port}`;
  const publicConfig=await (await fetch(publicOrigin+'/api/auth/ezboss/config')).json();
  assert.equal(publicConfig.termsVersion,'proof-1');assert.equal(JSON.stringify(publicConfig).includes(env.AUTH_INTERNAL_SECRET),false);
  const securityRequest=(path:string,body:object,origin=env.appOrigin)=>fetch(publicOrigin+'/api/auth/ezboss'+path,{method:'POST',headers:{'Content-Type':'application/json',Origin:origin,'X-EzBoss-CSRF':'1',Authorization:`Bearer ${completeToken}`},body:JSON.stringify(body)});
  assert.equal((await securityRequest('/status',{},'https://attacker.test')).status,403);
  const consentStatus=await securityRequest('/status',{});assert.equal(consentStatus.status,200);assert.equal((await consentStatus.json()).legalAccepted,true);
  assert.equal((await securityRequest('/consent',{termsVersion:'wrong',privacyVersion:'wrong'})).status,400);
  assert.equal((await securityRequest('/consent',{termsVersion:'proof-1',privacyVersion:'proof-1'})).status,200);
  const limits=await Promise.all(Array.from({length:12},()=>securityRequest('/status',{})));
  assert.ok(limits.some(result=>result.status===429),'custom auth.api wrappers enforce a shared atomic limit');
  await pool.query('ALTER TABLE totp_replay RENAME TO totp_replay_outage_fixture');
  try{
    const unavailable=await call('/two-factor/verify-totp',{code},undefined,completeToken!);
    assert.equal(unavailable.status,503,'mandatory replay-store outage fails unavailable');
    assert.equal(unavailable.headers.get('set-auth-token'),null,'outage never issues a new credential');
  }finally{await pool.query('ALTER TABLE totp_replay_outage_fixture RENAME TO totp_replay');}
  assert.equal((await call('/sign-out',{},undefined,completeToken!)).status,200);
  assert.equal((await verify(env.AUTH_INTERNAL_SECRET)).status,401,'revoked session rejected immediately');
 } finally {
  if(server) await new Promise<void>((resolve,reject)=>server!.close(error=>error?reject(error):resolve()));
  await pool.end();
 }
});
