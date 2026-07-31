import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';

const DependencyStatus = Type.Union([Type.Literal('up'), Type.Literal('down')]);

const HealthResponse = Type.Object({
  status: Type.Union([Type.Literal('ok'), Type.Literal('degraded')]),
  uptimeSeconds: Type.Number(),
  dependencies: Type.Object({
    postgres: DependencyStatus,
    redis: DependencyStatus,
  }),
});

/** Probe a dependency without letting its failure bubble up as a 500. */
async function probe(check: () => Promise<unknown>): Promise<'up' | 'down'> {
  try {
    await check();
    return 'up';
  } catch {
    return 'down';
  }
}

export const healthRoutes: FastifyPluginAsyncTypebox = async (app) => {
  app.get(
    '/health',
    {
      schema: {
        response: { 200: HealthResponse, 503: HealthResponse },
      },
    },
    async (_req, reply) => {
      const [postgres, redis] = await Promise.all([
        probe(() => app.pg.ping()),
        probe(() => app.redis.ping()),
      ]);

      const healthy = postgres === 'up' && redis === 'up';
      return reply.code(healthy ? 200 : 503).send({
        status: healthy ? 'ok' : 'degraded',
        uptimeSeconds: Math.round(process.uptime()),
        dependencies: { postgres, redis },
      });
    },
  );
};
