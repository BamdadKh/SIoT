import fs from 'node:fs';
import path from 'node:path';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import { config, isDev } from './config.js';
import { postgresPlugin } from './db/postgres.js';
import { redisPlugin } from './db/redis.js';
import { healthRoutes } from './routes/health.js';

/**
 * Reads the TLS key pair, failing with an actionable message rather than a bare
 * ENOENT. Refusing to start is deliberate: silently downgrading to HTTP would
 * defeat the point (design Section 4).
 */
function loadTlsCredentials() {
  const certPath = path.resolve(process.cwd(), config.tlsCertPath);
  const keyPath = path.resolve(process.cwd(), config.tlsKeyPath);

  for (const [label, file] of [
    ['certificate', certPath],
    ['private key', keyPath],
  ]) {
    if (!fs.existsSync(file)) {
      throw new Error(
        `TLS ${label} not found at ${file}\n` +
          'Run `npm run gen-cert` to create a development certificate, ' +
          'or set TLS_ENABLED=false if you genuinely need plaintext.',
      );
    }
  }

  return { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) };
}

export async function buildApp() {
  const app = Fastify({
    logger: {
      level: config.logLevel,
      transport: isDev
        ? { target: 'pino-pretty', options: { translateTime: 'HH:MM:ss' } }
        : undefined,
    },
    // The wire protocol carries base64 blobs; keep a sane ceiling on record size.
    bodyLimit: 1024 * 1024,
    ...(config.tlsEnabled ? { https: loadTlsCredentials() } : {}),
  }).withTypeProvider<TypeBoxTypeProvider>();

  if (!config.tlsEnabled) {
    app.log.warn('TLS IS DISABLED — plaintext HTTP. Never do this outside local debugging.');
  }

  // HSTS, but not in dev: the header is host-scoped and ignores the port, so
  // pinning `localhost` to HTTPS would force it on every other project served
  // from localhost on this machine, with a 1-year memory and no easy undo.
  if (!isDev) {
    app.addHook('onSend', async (_req, reply) => {
      reply.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    });
  }

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
