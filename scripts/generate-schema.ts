// Read-only generation. Never executes migrations. Use a disposable EMPTY schema.
import path from 'node:path';
import os from 'node:os';
import { writeFile } from 'node:fs/promises';
import { Pool } from 'pg';
import { getMigrations } from 'better-auth/db/migration';
import { createAuth } from '../src/auth.js';
import { readEnvironment } from '../src/env.js';
const env = readEnvironment();
if (env.DEPLOYMENT_ENV !== 'development') throw new Error('Generate against a disposable development database only');
const pool = new Pool({ connectionString: env.DATABASE_URL, options: '-c search_path=ezboss_auth' });
try {
  const existing=await pool.query("SELECT count(*)::int AS count FROM information_schema.tables WHERE table_schema='ezboss_auth'");
  if(existing.rows[0].count!==0)throw new Error('Schema generation requires an empty disposable auth schema');
  const auth = createAuth(env, pool, async () => { throw new Error('Schema generator cannot send email'); });
  const migrations = await getMigrations(auth.options);
  if (migrations.toBeAdded.length || migrations.schemaProblems.length || migrations.unsafeChanges.length) throw new Error('Expected an empty valid schema');
  const sql = await migrations.compileMigrations();
  const output=process.argv[2];
  if(!output || !path.resolve(output).startsWith(path.resolve(os.tmpdir())+path.sep))throw new Error('Supply an explicit output file in the temporary directory; numbered migrations are immutable');
  await writeFile(output,
    '-- Generated with Better Auth/passkey/oauth-provider 1.7.17. Review before controlled application.\nBEGIN;\nCREATE SCHEMA IF NOT EXISTS ezboss_auth;\nSET LOCAL search_path = ezboss_auth;\n' + sql + '\nCOMMIT;\n');
} finally { await pool.end(); }
