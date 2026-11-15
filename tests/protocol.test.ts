import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
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
 DATABASE_URL:dbUrl,AUTH_TERMS_VERSION:'proof-1',AUTH_PRIVACY_VERSION:'proof-1',AUTH_TERMS_URL:'http://localhost:5173/proof-terms',AUTH_PRIVACY_URL:'http://localhost:5173/proof-privacy', BETTER_AUTH_SECRET:'local-test-only-000000000000000001', AUTH_INTERNAL_SECRET:'local-test-only-000000000000000002', GOOGLE_CLIENT_ID:'fixture-google-client',GOOGLE_CLIENT_SECRET:'fixture-google-secret',MAILGUN_API_KEY:'test', MAILGUN_DOMAIN: 'example.test', MAILGUN_FROM:'noreply@example.test'});
 const pool = new Pool({connectionString:dbUrl, options:'-c search_path=ezboss_auth', statement_timeout:5000});
 const messages: Mail[] = [];

 let server: ReturnType<ReturnType<typeof createApp>['listen']> | undefined;
 try {
  await pool.query('DROP SCHEMA IF EXISTS ezboss_auth CASCADE');
  await pool.query(await readFile(new URL('../schema/001_better_auth.sql',import.meta.url),'utf8'));
  await pool.query(await readFile(new URL('../schema/002_admin_assurance.sql',import.meta.url),'utf8'));
  await pool.query(await readFile(new URL('../schema/003_totp_replay.sql',import.meta.url),'utf8'));
  await pool.query(await readFile(new URL('../schema/004_identity_consent.sql',import.meta.url),'utf8'));
  await pool.query(await readFile(new URL('../schema/005_google_account_identity.sql',import.meta.url),'utf8'));
  await pool.query(await readFile(new URL('../schema/006_credential_account_identity.sql',import.meta.url),'utf8'));
  const deliver = async (mail:Mail) => {messages.push(mail);};
  const auth = createAuth(env,pool,deliver);
  let peer='127.0.0.1';
  const call = (path:string, body?:object, cookie?:string, bearer?:string) => auth.handler(new Request(`${env.baseURL}/api/auth${path}`,{
    method:body?'POST':'GET',headers:{origin:env.appOrigin,'x-ezboss-peer-ip':peer,...(body?{'Content-Type':'application/json'}:{}),...(cookie?{cookie}:{}),...(bearer?{authorization:`Bearer ${bearer}`}:{})},body:body?JSON.stringify(body):undefined}));
  const cookies = (response:Response) => response.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');
  const password = 'Boss1!xy';
  for (const [index, candidate] of ['Boss1!x', 'boss1!xy', 'Boss1 xy', 'Boss!!xy'].entries()) {
    peer = `127.0.0.${20 + index}`;
    const invalidSignup = await call('/sign-up/email',{name:'Proof',email:'invalid@example.test',password:candidate,acceptedTermsVersion:'proof-1',acceptedPrivacyVersion:'proof-1'});
    assert.equal(invalidSignup.status,400);
    assert.equal((await invalidSignup.json()).code,index===0?'PASSWORD_TOO_SHORT':'PASSWORD_REQUIREMENTS_NOT_MET');
  }
  peer = '127.0.0.1';
  const email = 'proof@example.test';
  const signup = await call('/sign-up/email',{name:'Proof',email,password,acceptedTermsVersion:'proof-1',acceptedPrivacyVersion:'proof-1'});
  assert.equal(signup.status,200);
  assert.equal(signup.headers.get('set-auth-token'),null,'unverified signup must not issue a credential');
  assert.equal(messages.length,1);
  assert.equal(messages[0].kind,'verification');
  if (messages[0].kind==='merge') throw new Error('Expected a verification link');
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
  const tokenRequest=async(code:string,codeVerifier:string)=>auth.handler(new Request(`${env.baseURL}/api/auth/oauth2/token`,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','x-ezboss-peer-ip':peer},body:new URLSearchParams({grant_type:'authorization_code',client_id:'proof-native',redirect_uri:'http://localhost:4000/callback',code,code_verifier:codeVerifier})}));
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
  assert.equal(await stepUp.verifiedAt(active.user.id,active.session.id),undefined,'TOTP/backup-code login confers no admin assurance');
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
  assert.ok(await stepUp.verifiedAt(active.user.id,active.session.id));
  await assert.rejects(stepUp.verify(active.user.id,active.session.id,proof.transactionId,response),'challenge replay rejected');
  assert.notEqual(identity.session.id,active.session.id);
  assert.equal(await stepUp.verifiedAt(active.user.id,identity.session.id),undefined,'another session for the same user has no proof');
  await pool.query(`UPDATE admin_assurance SET "verifiedAt"=now()+interval '1 minute'`);
  assert.equal(await stepUp.verifiedAt(active.user.id,active.session.id),undefined,'future proof rejected');
  await pool.query(`UPDATE admin_assurance SET "verifiedAt"=now()-interval '1 day'`);
  const adminVerifiedAt = await stepUp.verifiedAt(active.user.id,active.session.id);
  assert.ok(adminVerifiedAt,'older proof lasts for the session');
  server=createApp(auth,env,pool,deliver).listen(0,'127.0.0.1');
  await new Promise<void>(resolve=>server!.once('listening',resolve));
  const address=server.address(); assert.ok(address && typeof address!=='string');
  const verify = (key:string, credential=completeToken!)=>fetch(`http://127.0.0.1:${address.port}/internal/verify-session`,{method:'POST',headers:{'Content-Type':'application/json','X-EzBoss-Service-Key':key},body:JSON.stringify({transport:'bearer',credential})});
  assert.equal((await verify('wrong')).status,401);
  const verified=await verify(env.AUTH_INTERNAL_SECRET); assert.equal(verified.status,200);
  const principal=await verified.json(); assert.equal(principal.subject,identity.user.id); assert.equal(principal.credentialKind,'session');
  assert.equal(JSON.stringify(principal).includes(completeToken!),false);
  assert.equal(principal.adminVerifiedAt,adminVerifiedAt);
  assert.ok(completed.headers.getSetCookie().some(cookie=>cookie.includes('session_token=') && /Max-Age=[1-9]/i.test(cookie)),
    'the browser sign-in cookie survives closing the browser');
  const restored = await fetch(`http://127.0.0.1:${address.port}/internal/verify-session`,{
    method:'POST',headers:{'Content-Type':'application/json','X-EzBoss-Service-Key':env.AUTH_INTERNAL_SECRET},
    body:JSON.stringify({transport:'cookie',credential:cookies(completed)}),
  });
  assert.equal(restored.status,200);
  const restoredPrincipal = await restored.json();
  assert.equal(restoredPrincipal.sessionId,active.session.id);
  assert.equal(restoredPrincipal.adminVerifiedAt,adminVerifiedAt);
  await pool.query(`UPDATE session SET "expiresAt"=now()-interval '1 second' WHERE id=$1`,[active.session.id]);
  assert.equal(await stepUp.verifiedAt(active.user.id,active.session.id),undefined,'expired session has no usable proof');
  await pool.query('UPDATE session SET "expiresAt"=$2 WHERE id=$1',[active.session.id,active.session.expiresAt]);
  const publicOrigin=`http://127.0.0.1:${address.port}`;
  const publicConfig=await (await fetch(publicOrigin+'/api/auth/ezboss/config')).json();
  assert.equal(publicConfig.termsVersion,'proof-1');assert.equal(JSON.stringify(publicConfig).includes(env.AUTH_INTERNAL_SECRET),false);
  const securityRequest=(path:string,body:object,origin=env.appOrigin)=>fetch(publicOrigin+'/api/auth/ezboss'+path,{method:'POST',headers:{'Content-Type':'application/json',Origin:origin,'X-EzBoss-CSRF':'1',Authorization:`Bearer ${completeToken}`},body:JSON.stringify(body)});
  assert.equal((await securityRequest('/status',{},'https://attacker.test')).status,403);
  const consentStatus=await securityRequest('/status',{});assert.equal(consentStatus.status,200);assert.equal((await consentStatus.json()).legalAccepted,true);
  assert.equal((await securityRequest('/consent',{termsVersion:'wrong',privacyVersion:'wrong'})).status,400);
  assert.equal((await securityRequest('/consent',{termsVersion:'proof-1',privacyVersion:'proof-1'})).status,200);
  const mailBeforeMfaMerge=messages.length;
  const authenticatorMerge=await securityRequest('/merge/start',{kind:'google',currentPassword:password});
  assert.equal(authenticatorMerge.status,200);
  const authenticatorProof=await authenticatorMerge.json();
  assert.equal(authenticatorProof.factor,'totp');
  assert.equal(messages.length,mailBeforeMfaMerge,'an enrolled authenticator cannot be replaced by email verification');
  assert.equal((await securityRequest('/merge/confirm',{kind:'google',id:authenticatorProof.id,code})).status,400,'a spent TOTP code cannot authorize a merge');
  const limits=await Promise.all(Array.from({length:12},()=>securityRequest('/status',{})));
  assert.ok(limits.some(result=>result.status===429),'custom auth.api wrappers enforce a shared atomic limit');
  await pool.query('ALTER TABLE totp_replay RENAME TO totp_replay_outage_fixture');
  try{
    const unavailable=await call('/two-factor/verify-totp',{code},undefined,completeToken!);
    assert.equal(unavailable.status,503,'mandatory replay-store outage fails unavailable');
    assert.equal(unavailable.headers.get('set-auth-token'),null,'outage never issues a new credential');
  }finally{await pool.query('ALTER TABLE totp_replay_outage_fixture RENAME TO totp_replay');}
  const redirectTo = env.appOrigin + '/reset-password';
  const mailCount = messages.length;
  assert.equal((await call('/request-password-reset',{email:'unknown@example.test',redirectTo})).status,200);
  assert.equal(messages.length,mailCount);
  assert.equal((await call('/request-password-reset',{email,redirectTo})).status,200);
  const resetMail = messages.at(-1)!;
  assert.equal(resetMail.kind,'reset');
  const resetRedirect = await auth.handler(new Request(resetMail.url));
  const resetURL = new URL(resetRedirect.headers.get('Location')!);
  assert.equal(resetURL.origin + resetURL.pathname,redirectTo);
  const token = resetURL.searchParams.get('token');
  assert.ok(token);
  const newPassword = 'different local proof password 67890';
  const shortReset = await call('/reset-password',{token,newPassword:password});
  assert.equal(shortReset.status,400);
  assert.equal((await shortReset.json()).code,'PASSWORD_TOO_SHORT');
  assert.equal((await call('/reset-password',{token,newPassword})).status,200);
  assert.equal((await verify(env.AUTH_INTERNAL_SECRET)).status,401,'password reset immediately revokes the previous session');
  assert.equal((await call('/reset-password',{token,newPassword})).ok,false,'a consumed reset link cannot be reused');
  const afterReset = await call('/sign-in/email',{email,password:newPassword});
  assert.equal(afterReset.status,200);
  assert.equal((await afterReset.json()).twoFactorRedirect,true,'password reset preserves the enrolled authenticator');
  peer='192.0.2.10'; // Independent rate-limit bucket for the two new fixture users.
  const merge = (path:string, body:object, cookie:string) => fetch(publicOrigin+'/api/auth/ezboss/merge'+path,{
   method:'POST',headers:{'Content-Type':'application/json',Origin:env.appOrigin,'X-EzBoss-CSRF':'1',Cookie:cookie},body:JSON.stringify(body)});
  const emailFirst = 'email-first@example.test';
  const googleFirst = 'google-first@example.test';
  const signupEmail = await call('/sign-up/email',{name:'Email first',email:emailFirst,password,acceptedTermsVersion:'proof-1',acceptedPrivacyVersion:'proof-1'});
  assert.equal(signupEmail.status,200);
  const verificationMail = messages.at(-1)!;
  assert.equal(verificationMail.kind,'verification');
  await auth.handler(new Request(verificationMail.url));
  const emailLogin = await call('/sign-in/email',{email:emailFirst,password});
  assert.equal(emailLogin.status,200);
  const emailCookie = cookies(emailLogin);
  const emailIdentity = await (await call('/get-session',undefined,emailCookie)).json();
  assert.ok(emailIdentity.user.id);
  assert.equal((await call('/link-social',{provider:'google'},emailCookie)).status,404);
  assert.equal((await merge('/start',{kind:'google',currentPassword:'wrong'},emailCookie)).status,400);
  assert.equal((await merge('/start',{kind:'google',currentPassword:password},'')).status,401);
  const initial = await merge('/start',{kind:'google',currentPassword:password},emailCookie);
  assert.equal(initial.status,200);
  const firstProof = await initial.json();
  assert.equal(firstProof.factor,'email');
  const mergeMail = messages.at(-1)!;
  assert.equal(mergeMail.kind,'merge');
  assert.equal((await merge('/confirm',{kind:'google',id:firstProof.id,code:mergeMail.code==='000000'?'000001':'000000'},emailCookie)).status,400);
  const differentSession = cookies(await call('/sign-in/email',{email:emailFirst,password}));
  const confirmGoogle = {kind:'google',id:firstProof.id,code:mergeMail.code};
  assert.equal((await merge('/confirm',confirmGoogle,differentSession)).status,400);
  const authorizedLink = await merge('/confirm',confirmGoogle,emailCookie);
  assert.equal(authorizedLink.status,200);
  const linkURL = new URL((await authorizedLink.json()).url);
  assert.equal(linkURL.hostname,'accounts.google.com');
  assert.equal(linkURL.searchParams.get('login_hint'),emailFirst);
  assert.equal((await merge('/confirm',confirmGoogle,emailCookie)).status,400);

  const {privateKey,publicKey} = generateKeyPairSync('rsa',{modulusLength:2048});
  const signingKey = {...publicKey.export({format:'jwk'}),kid:'fixture-key',alg:'RS256'};
  async function oauthCallback(authorization:URL, oauthCookies:string, emailAddress:string, sub:string, emailVerified=true) {
   const encode = (value:unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
   const now = Math.floor(Date.now()/1000);
   const unsigned = encode({alg:'RS256',kid:signingKey.kid})+'.'+encode({
    iss:'https://accounts.google.com',aud:'fixture-google-client',iat:now,exp:now+300,sub,name:'Google fixture',
    email:emailAddress,email_verified:emailVerified,nonce:authorization.searchParams.get('nonce')||undefined,
   });
   const idToken = unsigned+'.'+sign('RSA-SHA256',Buffer.from(unsigned),privateKey).toString('base64url');
   const originalFetch = globalThis.fetch;
   globalThis.fetch = async (input,init) => {
    const href = input instanceof Request ? input.url : String(input);
    if (href === 'https://oauth2.googleapis.com/token') return Response.json({id_token:idToken,access_token:'fixture-token',token_type:'Bearer'});
    if (href === 'https://www.googleapis.com/oauth2/v3/certs') return Response.json({keys:[signingKey]});
    return originalFetch(input,init);
   };
   try {
    const query = new URLSearchParams({code:'fixture-authorization-code',state:authorization.searchParams.get('state')!});
    return await call('/callback/google?'+query,undefined,oauthCookies);
   } finally {globalThis.fetch = originalFetch;}
  }
  const socialSignIn = () => call('/sign-in/social',{provider:'google',callbackURL:env.appOrigin+'/auth/merge?kind=password',errorCallbackURL:env.appOrigin+'/login'});
  const beforeLink = await socialSignIn();
  const collision = await oauthCallback(new URL((await beforeLink.json()).url),cookies(beforeLink),emailFirst,'fixture-email-first');
  assert.equal(new URL(collision.headers.get('Location')!).searchParams.get('error'),'account_not_linked');
  const wrongGoogle = await oauthCallback(linkURL,[emailCookie,cookies(authorizedLink)].filter(Boolean).join('; '),'different@example.test','fixture-different-user');
  assert.equal(new URL(wrongGoogle.headers.get('Location')!).searchParams.get('error'),'google_merge_email_mismatch');
  assert.equal((await pool.query('SELECT 1 FROM account WHERE "providerId"=$1',['google'])).rowCount,0);

  const linkRetry = await merge('/start',{kind:'google',currentPassword:password},emailCookie);
  assert.equal(linkRetry.status,200);
  const linkRetryProof = await linkRetry.json();
  const retryMail = messages.at(-1)!;
  assert.equal(retryMail.kind,'merge');
  const linkRetryConfirm = await merge('/confirm',{kind:'google',id:linkRetryProof.id,code:retryMail.code},emailCookie);
  assert.equal(linkRetryConfirm.status,200);
  const linked = await oauthCallback(new URL((await linkRetryConfirm.json()).url),[emailCookie,cookies(linkRetryConfirm)].filter(Boolean).join('; '),emailFirst,'fixture-email-first');
  assert.equal(new URL(linked.headers.get('Location')!).searchParams.get('linked'),'1',linked.headers.get('Location')||'missing redirect');
  assert.equal((await pool.query('SELECT "userId" FROM account WHERE "providerId"=$1 AND "accountId"=$2',['google','fixture-email-first'])).rows[0].userId,emailIdentity.user.id);
  const linkedLogin = await socialSignIn();
  const linkedSession = await oauthCallback(new URL((await linkedLogin.json()).url),cookies(linkedLogin),emailFirst,'fixture-email-first');
  assert.equal((await (await call('/get-session',undefined,cookies(linkedSession))).json()).user.id,emailIdentity.user.id);

  await pool.query('INSERT INTO "user"(id,name,email,"emailVerified") VALUES($1,$2,$3,true)',['fixture-google-user','Google first',googleFirst]);
  await pool.query(`INSERT INTO account(id,"userId","accountId","providerId","updatedAt") VALUES($1,$2,$3,'google',now())`,
   ['fixture-google-account','fixture-google-user','fixture-google-first']);
  const emailAttempt = await call('/sign-in/email',{email:googleFirst,password});
  assert.equal(emailAttempt.status,401);
  const unavailable = await call('/sign-in/email',{email:'unknown-google@example.test',password});
  assert.deepEqual(await emailAttempt.json(),await unavailable.json(),'sign-in failure does not disclose account type');
  for (let attempt=0; attempt<50 && !messages.some(mail=>mail.kind==='first-password'); attempt++) {
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  const setupLink = messages.find(mail=>mail.kind==='first-password');
  assert.equal(setupLink?.to,googleFirst);
  assert.equal(setupLink?.url,env.appOrigin+'/auth/merge?kind=password');
  const beforeRecovery = messages.length;
  assert.equal((await call('/request-password-reset',{email:googleFirst,redirectTo})).status,200);
  assert.equal(messages.length,beforeRecovery,'password recovery cannot add the first password');
  const firstLogin = await socialSignIn();
  const googleSession = await oauthCallback(new URL((await firstLogin.json()).url),cookies(firstLogin),googleFirst,'fixture-google-first');
  const googleCookie = cookies(googleSession);
  const mergeStatus = await merge('/status',{},googleCookie);
  assert.equal((await mergeStatus.json()).canAddPassword,true);
  const second = await merge('/start',{kind:'password'},googleCookie);
  assert.equal(second.status,200);
  const secondProof = await second.json();
  const secondMail = messages.at(-1)!;
  assert.equal(secondMail.kind,'merge');
  await pool.query(`UPDATE verification SET "expiresAt"=now()-interval '1 second' WHERE left(value,37)=$1`,[secondProof.id+':']);
  const firstPassword = 'Local proof! 12345';
  const confirmPassword = {kind:'password',id:secondProof.id,code:secondMail.code,newPassword:firstPassword};
  assert.equal((await merge('/confirm',confirmPassword,googleCookie)).status,400);
  const retryProof = await (await merge('/start',{kind:'password'},googleCookie)).json();
  const freshMail = messages.at(-1)!;
  assert.equal(freshMail.kind,'merge');
  assert.equal((await merge('/confirm',{...confirmPassword,id:retryProof.id,code:freshMail.code},googleCookie)).status,200);
  assert.equal((await merge('/confirm',{...confirmPassword,id:retryProof.id,code:freshMail.code},googleCookie)).status,409);
  const passwordSession = await call('/sign-in/email',{email:googleFirst,password:firstPassword});
  assert.equal((await (await call('/get-session',undefined,cookies(passwordSession))).json()).user.id,'fixture-google-user');

 } finally {
  if(server) await new Promise<void>((resolve,reject)=>server!.close(error=>error?reject(error):resolve()));
  await pool.end();
 }
});
