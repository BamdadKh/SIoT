import path from 'node:path';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import { config, isDev } from './config.js';
import { postgresPlugin } from './db/postgres.js';
import { redisPlugin } from './db/redis.js';
import { healthRoutes } from './routes/health.js';

export async function buildApp() {
  const app = Fastify({
    logger: {
      level: config.logLevel,
      transport: isDev ? { target: 'pino-pretty', options: { translateTime: 'HH:MM:ss' } } : undefined,
    },
    // The wire protocol carries base64 blobs; keep a sane ceiling on record size.
    bodyLimit: 1024 * 1024,
  }).withTypeProvider<TypeBoxTypeProvider>();

  await app.register(postgresPlugin);
  await app.register(redisPlugin);

  await app.register(healthRoutes);

  // Dev-only convenience: serve the plain-HTML test console from the API origin
  // so there is no CORS setup and session cookies will just work. The real
  // client will be a separate Vite app; this goes away then.
  if (config.serveTestFrontend) {
    const root = path.resolve(__dirname, '../../frontend');
    await app.register(fastifyStatic, { root });
    app.log.warn(`serving test frontend from ${root}`);
  }

  return app;
}

export type App = Awaited<ReturnType<typeof buildApp>>;
