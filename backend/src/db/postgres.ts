import fp from 'fastify-plugin';
import { Pool } from 'pg';
import type { PoolClient, QueryResultRow } from 'pg';
import { config } from '../config.js';

declare module 'fastify' {
  interface FastifyInstance {
    pg: Postgres;
  }
}

export class Postgres {
  constructor(private readonly pool: Pool) {}

  query<T extends QueryResultRow = QueryResultRow>(text: string, params?: unknown[]) {
    return this.pool.query<T>(text, params as never[]);
  }

  /** First row or undefined. The common shape for lookups by id/username. */
  async queryOne<T extends QueryResultRow = QueryResultRow>(text: string, params?: unknown[]) {
    const result = await this.query<T>(text, params);
    return result.rows[0];
  }

  /** Runs fn inside a transaction, rolling back on any throw. */
  async transaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async ping(): Promise<void> {
    await this.pool.query('SELECT 1');
  }

  close() {
    return this.pool.end();
  }
}

export const postgresPlugin = fp(async (app) => {
  const pool = new Pool({ connectionString: config.databaseUrl, max: 10 });
  const pg = new Postgres(pool);

  // Fail fast at boot rather than on the first request.
  await pg.ping();
  app.log.info('postgres connected');

  app.decorate('pg', pg);
  app.addHook('onClose', async () => {
    await pg.close();
  });
});
