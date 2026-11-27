/**
 * Prepares the isolated database the backend suite runs against, then exits.
 *
 * The suite never touches the dev database. It uses `siot_test` on the same
 * Postgres (created here on first run) and Redis logical database 15, and both
 * are wiped before every run so a test can rely on starting from nothing. The
 * schema comes from the real migrations, applied with the real migrator, so the
 * suite is testing the tables production gets and not a hand-written copy.
 *
 * Connection settings come from `TEST_DATABASE_URL` / `TEST_REDIS_URL`, falling
 * back to the docker-compose defaults. They are deliberately not read from
 * `.env`: a `.env` pointed at a real database is exactly the file this must
 * never be able to truncate.
 */

const { execFileSync } = require('node:child_process');
const path = require('node:path');
const { Client } = require('pg');
const Redis = require('ioredis');

const DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://siot:siot@localhost:5433/siot_test';
const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://localhost:6379/15';

/** Refuses anything that does not look like a throwaway target. */
function assertDisposable() {
  const db = new URL(DATABASE_URL).pathname.slice(1);
  if (!db.endsWith('_test')) {
    throw new Error(`refusing to wipe ${db}: the test database name must end in _test`);
  }
  const redisDb = new URL(REDIS_URL).pathname.slice(1);
  if (redisDb === '' || redisDb === '0') {
    throw new Error('refusing to flush Redis database 0: point TEST_REDIS_URL at a numbered database');
  }
  return db;
}

async function ensureDatabase(name) {
  const admin = new URL(DATABASE_URL);
  admin.pathname = '/postgres';
  const client = new Client({ connectionString: admin.toString() });
  await client.connect();
  try {
    const found = await client.query('select 1 from pg_database where datname = $1', [name]);
    // The name passed the `_test` check above and is an identifier we built, not
    // user input, but quote it anyway: create database takes no parameters.
    if (found.rowCount === 0) await client.query(`create database "${name.replaceAll('"', '""')}"`);
  } finally {
    await client.end();
  }
}

function migrate() {
  const bin = path.join(__dirname, '..', 'node_modules', 'node-pg-migrate', 'bin', 'node-pg-migrate.js');
  execFileSync(process.execPath, [bin, '-j', 'js', '-m', 'migrations', 'up'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, DATABASE_URL },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
}

async function wipe() {
  const client = new Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    const { rows } = await client.query(
      `select tablename from pg_tables
        where schemaname = 'public' and tablename <> 'pgmigrations'`,
    );
    if (rows.length > 0) {
      const tables = rows.map(({ tablename }) => `"${tablename}"`).join(', ');
      await client.query(`truncate ${tables} restart identity cascade`);
    }
  } finally {
    await client.end();
  }

  const redis = new Redis(REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
  await redis.connect();
  try {
    await redis.flushdb();
  } finally {
    redis.disconnect();
  }
}

(async () => {
  const name = assertDisposable();
  await ensureDatabase(name);
  migrate();
  await wipe();
})().catch((err) => {
  console.error(`test database setup failed: ${err.message}`);
  process.exit(1);
});
