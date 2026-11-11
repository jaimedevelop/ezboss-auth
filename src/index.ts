import { Pool } from 'pg';
import { readEnvironment } from './env.js';
import { createAuth } from './auth.js';
import { createApp } from './app.js';
import { createMailDelivery } from './services/email.js';
const env = readEnvironment();
const database = new Pool({ connectionString: env.DATABASE_URL, options: '-c search_path=ezboss_auth',
  max: 10, connectionTimeoutMillis: 3000, statement_timeout: 5000, query_timeout: 6000 });
const auth = createAuth(env, database, createMailDelivery(env));
const server = createApp(auth, env, database).listen(env.PORT, '0.0.0.0');
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => {
  const deadline = setTimeout(() => process.exit(1), 10_000).unref();
  server.close(() => { void database.end().then(() => { clearTimeout(deadline); process.exit(0); }); });
});
