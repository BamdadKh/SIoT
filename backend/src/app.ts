import fs from 'node:fs';
import path from 'node:path';
import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import { config, isDev } from './config.js';
import { postgresPlugin } from './db/postgres.js';
import { redisPlugin } from './db/redis.js';
import { requireSession, sessionPlugin } from './lib/require-session.js';
import { authRoutes } from './routes/auth.js';
import { changePasswordRoutes } from './routes/change-password.js';
import { deviceRoutes } from './routes/devices.js';
import { deviceGrantRoutes, grantRoutes } from './routes/grants.js';
import { healthRoutes } from './routes/health.js';
import { recordRoutes } from './routes/records.js';
import { sessionRoutes } from './routes/session.js';
import { vaultRoutes } from './routes/vault.js';

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

    // Fastify's Ajv defaults to `removeAdditional: true`, which silently strips properties
    // an `additionalProperties: false` schema doesn't name. For this server that's the
    // wrong default - if a request carries a field we never asked for, the client is out of
    // spec, and the field it sent might be key material. We reject it visibly instead of
    // quietly dropping it and returning 201.
    ajv: { customOptions: { removeAdditional: false } },
    ...(config.tlsEnabled ? { https: loadTlsCredentials() } : {}),
  }).withTypeProvider<TypeBoxTypeProvider>();

  if (!config.tlsEnabled) {
    app.log.warn('TLS IS DISABLED: plaintext HTTP. Never do this outside local debugging.');
  }

  // HSTS is disabled in dev because the header is host-scoped and ignores the port.
  // Pinning localhost to HTTPS would force it on every other project served from
  // localhost on this machine for a year with no easy undo.
  if (!isDev) {
    app.addHook('onSend', async (_req, reply) => {
      reply.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    });
  }

  // Cookie parsing/serialisation only. No `secret`, deliberately: the session
  // cookie carries a 256-bit random id whose only copy on the server is a hash,
  // so there is nothing for a signature to add — it would just be a second
  // secret to leak.
  await app.register(fastifyCookie);

  await app.register(postgresPlugin);
  await app.register(redisPlugin);

  await app.register(sessionPlugin);

  // Public: reachable without a session, by necessity. `/signup` and `/login`
  // are how you get one, and `/salt` has to answer before authentication is
  // even possible — its own anti-enumeration design is what covers that.
  await app.register(healthRoutes);
  await app.register(authRoutes);

  // Also public, but for a different reason: a device never holds a session,
  // it signs (design Section 7.4). `requireSession` would just reject every
  // request with a 401 before the signature — the real authentication — is
  // ever checked.
  await app.register(recordRoutes);

  // Public for the same reason: Device A's own firmware polls this for grants
  // naming it as recipient (design 9.3), and it has no session either. The
  // response is opaque ciphertext scoped by a 128-bit device_id, and design
  // 13.1 already lists which devices hold grants on which others as metadata
  // the server sees, so this adds no new leak.
  await app.register(deviceGrantRoutes);

  // Authenticated: the hook belongs to this scope, so anything registered here
  // is protected by construction. New routes go inside unless there is a reason
  // they cannot — that way the easy mistake is a 401, not an open endpoint.
  await app.register(async (scope) => {
    scope.addHook('onRequest', requireSession);
    await scope.register(sessionRoutes);
    await scope.register(vaultRoutes);
    await scope.register(changePasswordRoutes);
    await scope.register(deviceRoutes);
    await scope.register(grantRoutes);
  });

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
