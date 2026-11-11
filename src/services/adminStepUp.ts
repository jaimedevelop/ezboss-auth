import { generateAuthenticationOptions, verifyAuthenticationResponse, type AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { Pool } from 'pg';
import type { Environment } from '../env.js';

export class AssuranceDenied extends Error { constructor(){super('Security verification failed');} }
export class AdminStepUp {
 constructor(private readonly db:Pool,private readonly env:Environment){}
 async challenge(userId:string,sessionId:string) {
  const keys=await this.db.query('SELECT "credentialID",transports FROM passkey WHERE "userId"=$1',[userId]);
  if(!keys.rowCount) throw new AssuranceDenied();
  const options=await generateAuthenticationOptions({rpID:new URL(this.env.appOrigin).hostname,userVerification:'required',
   allowCredentials:keys.rows.map(key=>({id:key.credentialID}))});
  const result=await this.db.query(`INSERT INTO admin_challenges("userId","sessionId",challenge)
    SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM session WHERE id=$2 AND "userId"=$1 AND "expiresAt">now()) RETURNING id`,[userId,sessionId,options.challenge]);
  if(!result.rowCount) throw new AssuranceDenied();
  return {transactionId:result.rows[0].id,options};
 }
 async verify(userId:string,sessionId:string,transactionId:string,response:AuthenticationResponseJSON) {
  // Atomic consumption commits before cryptographic verification: every attempt is one use.
  const challenge=await this.db.query(`DELETE FROM admin_challenges WHERE id=$1 AND "userId"=$2 AND "sessionId"=$3
   AND "expiresAt">now() RETURNING challenge`,[transactionId,userId,sessionId]);
  if(!challenge.rowCount) throw new AssuranceDenied();
  const client=await this.db.connect();
  try {
   await client.query('BEGIN');
   const session=await client.query(`SELECT id FROM session WHERE id=$1 AND "userId"=$2 AND "expiresAt">now() FOR UPDATE`,[sessionId,userId]);
   if(!session.rowCount) throw new AssuranceDenied();
   const keys=await client.query('SELECT id,"publicKey",counter FROM passkey WHERE "credentialID"=$1 AND "userId"=$2 FOR UPDATE',[response.id,userId]);
   const key=keys.rows[0];if(!key)throw new AssuranceDenied();
   let result;
   try {
    result=await verifyAuthenticationResponse({response,expectedChallenge:challenge.rows[0].challenge,
     expectedOrigin:this.env.appOrigin,expectedRPID:new URL(this.env.appOrigin).hostname,requireUserVerification:true,
     credential:{id:response.id,publicKey:new Uint8Array(Buffer.from(key.publicKey,'base64url')),counter:key.counter}});
   }catch{throw new AssuranceDenied();}
   if(!result.verified || !result.authenticationInfo.userVerified)throw new AssuranceDenied();
   await client.query('UPDATE passkey SET counter=$1 WHERE id=$2',[result.authenticationInfo.newCounter,key.id]);
   await client.query(`INSERT INTO admin_assurance("sessionId","userId",method) VALUES($1,$2,'webauthn-uv')
    ON CONFLICT("sessionId") DO UPDATE SET "verifiedAt"=now(),"userId"=EXCLUDED."userId",method='webauthn-uv'`,[sessionId,userId]);
   await client.query('COMMIT');
  }catch(error){await client.query('ROLLBACK');throw error;}
  finally{client.release();}
 }
 async recent(userId:string,sessionId:string){
  const proof=await this.db.query(`SELECT a."verifiedAt" FROM admin_assurance a JOIN session s ON s.id=a."sessionId" AND s."userId"=a."userId"
   WHERE a."userId"=$1 AND a."sessionId"=$2 AND a.method='webauthn-uv' AND a."verifiedAt"<=now()
    AND a."verifiedAt">=now()-interval '5 minutes' AND s."expiresAt">now()`,[userId,sessionId]);
  return proof.rows[0]?.verifiedAt?.toISOString() as string|undefined;
 }
}
