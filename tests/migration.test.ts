import { provisionBetterAuthUser } from '../../ezboss-api/src/services/provisionIdentity.js';
import { resolveBetterAuthMarketplaceClient } from '../../ezboss-api/src/middleware/marketplaceClient.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Pool } from 'pg';
import { mapIdentity } from '../../ezboss-api/scripts/auth-migration/identity-mapping.js';

test('additive migration preserves IDs, rejects mapping collisions and erases across providers without resurrection',async()=>{
 const connectionString=process.env.AUTH_TEST_DATABASE_URL; assert.ok(connectionString,'Disposable AUTH_TEST_DATABASE_URL required');
 const url=new URL(connectionString);assert.ok(['localhost','127.0.0.1'].includes(url.hostname)&&url.pathname==='/ezboss_auth_test');
 const pool=new Pool({connectionString}); const client=await pool.connect();
 try {
  await client.query('BEGIN');
  // A separate fixture schema models the deployed legacy contract, never the production database.
  await client.query(`CREATE SCHEMA migration_fixture; SET LOCAL search_path=migration_fixture;
    CREATE TABLE roles(id serial PRIMARY KEY,name text); INSERT INTO roles(name) VALUES('User');
    CREATE TABLE users(id serial PRIMARY KEY,"auth0Id" text NOT NULL UNIQUE,email text UNIQUE,"authProvider" text,roles text[] NOT NULL DEFAULT '{}',"roleId" integer REFERENCES roles(id),status text NOT NULL DEFAULT 'active',"deletedAt" timestamptz);
    CREATE TABLE marketplace_clients(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),"auth0Subject" text NOT NULL UNIQUE,status text NOT NULL DEFAULT 'active',name text,email text,"updatedAt" timestamptz);
    CREATE FUNCTION revoke_erased_marketplace_identity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END $$;
    CREATE TRIGGER marketplace_identity_erasure BEFORE DELETE ON users FOR EACH ROW EXECUTE FUNCTION revoke_erased_marketplace_identity();
    INSERT INTO users("auth0Id",email) VALUES ('auth0|one','one@example.test'),('auth0|two','two@example.test');
    INSERT INTO marketplace_clients("auth0Subject",name,email) VALUES('auth0|one','Test','test@example.test');`);
  await client.query(await readFile(new URL('../../ezboss-api/src/db/schema/120_auth_identity_mappings.sql',import.meta.url),'utf8'));
  assert.deepEqual((await client.query('SELECT id,"auth0Id" FROM users ORDER BY id')).rows,[{id:1,auth0Id:'auth0|one'},{id:2,auth0Id:'auth0|two'}]);
  const marketplaceId=(await client.query('SELECT id FROM marketplace_clients')).rows[0].id;
  const mapping={provider:'better-auth' as const,issuer:'https://alpha.ezboss.pro/api/auth',subject:'new-trusted-id',userId:1,marketplaceClientId:marketplaceId};
  const id=await mapIdentity(client,mapping);assert.equal(await mapIdentity(client,mapping),id);
  await assert.rejects(mapIdentity(client,{...mapping,userId:2}),/collision/);
  assert.equal((await client.query('SELECT count(*)::int AS n FROM auth_identities')).rows[0].n,1);
  assert.equal((await client.query('SELECT count(*)::int AS n FROM auth_migration_ledger')).rows[0].n,1);
  await client.query("UPDATE users SET status='disabled' WHERE id=1");
  await assert.rejects(mapIdentity(client,mapping),/disabled/);
  await client.query('DELETE FROM users WHERE id=1');
  const erased=(await client.query('SELECT status,"userId" FROM auth_identities WHERE id=$1',[id])).rows[0];
  assert.deepEqual(erased,{status:'revoked',userId:null});
  assert.equal((await client.query('SELECT status FROM marketplace_clients')).rows[0].status,'inactive');
  assert.equal((await client.query("SELECT operation FROM auth_lifecycle_outbox")).rows[0].operation,'erase');
  await assert.rejects(mapIdentity(client,{...mapping,userId:2,marketplaceClientId:null}),/collision/);
  const identity={provider:'better-auth' as const,issuer:mapping.issuer,subject:'new-identity',credentialKind:'session' as const,email:'new@example.test',emailVerified:true,legalAccepted:true};
  const provisioned=await provisionBetterAuthUser(client,identity,identity.email,true);
  assert.equal(provisioned.auth0Id,null,'new users never receive fabricated legacy subjects');
  assert.equal((await provisionBetterAuthUser(client,identity,identity.email,true)).id,provisioned.id,'signup resume keeps one stable ID');
  await assert.rejects(provisionBetterAuthUser(client,{...identity,subject:'different-identity'},identity.email,true),/existing account/);
  await assert.rejects(provisionBetterAuthUser(client,{...identity,subject:'no-consent',legalAccepted:false,email:'other@example.test'},'other@example.test',true));
  await client.query("UPDATE users SET status='disabled' WHERE id=$1",[provisioned.id]);
  await assert.rejects(provisionBetterAuthUser(client,identity,identity.email,true),/unavailable/);
  // Exercise the real marketplace SQL using savepoints within this rollback-only fixture.
  const nestedPool={connect:async()=>({query:async(sql:string,values?:any[])=>{
    if(sql==='BEGIN')return client.query('SAVEPOINT marketplace_test');
    if(sql==='COMMIT')return client.query('RELEASE SAVEPOINT marketplace_test');
    if(sql==='ROLLBACK')return client.query('ROLLBACK TO SAVEPOINT marketplace_test');
    return client.query(sql,values);
  },release(){}})} as any;
  const marketplaceIdentity={...identity,subject:'marketplace-only',email:'client-only@example.test'};
  const customer=await resolveBetterAuthMarketplaceClient(marketplaceIdentity,nestedPool);
  assert.equal((await resolveBetterAuthMarketplaceClient(marketplaceIdentity,nestedPool)).id,customer.id);
  assert.equal((await client.query('SELECT "userId" FROM auth_identities WHERE subject=$1',[marketplaceIdentity.subject])).rows[0].userId,null,'marketplace creation does not create a contractor user');
  await client.query("UPDATE marketplace_clients SET status='inactive' WHERE id=$1",[customer.id]);
  await assert.rejects(resolveBetterAuthMarketplaceClient(marketplaceIdentity,nestedPool),/unavailable/);
  await client.query("INSERT INTO users(\"auth0Id\") VALUES (NULL),(NULL)");
  await client.query('ROLLBACK');
 } finally { await client.query('ROLLBACK');client.release();await pool.end(); }
});
