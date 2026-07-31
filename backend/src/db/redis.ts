import fp from 'fastify-plugin';
import { Redis } from 'ioredis';
import { config } from '../config.js';

declare module 'fastify' {
  interface FastifyInstance {
    redis: Redis;
  }
}

export const redisPlugin = fp(async (app) => {
  const redis = new Redis(config.redisUrl, {
    // Boot should fail loudly if Redis is down, not queue commands forever.
    lazyConnect: true,
    maxRetriesPerRequest: 3,
  });

  await redis.connect();
  await redis.ping();
  app.log.info('redis connected');

  app.decorate('redis', redis);
  app.addHook('onClose', async () => {
    await redis.quit();
  });
});
