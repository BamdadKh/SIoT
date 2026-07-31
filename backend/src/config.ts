import 'dotenv/config';

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`missing required env var ${name} (copy .env.example to .env)`);
  }
  return value;
}

function optional(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function bool(name: string, fallback: boolean): boolean {
  const value = process.env[name];
  if (value === undefined) return fallback;
  return value === 'true' || value === '1';
}

/**
 * A base64url secret, decoded and floor-checked for entropy. Refusing a short
 * value at boot matters: the decoy-salt HMAC is only indistinguishable from a
 * real salt for as long as the key behind it is unguessable, and a placeholder
 * like `changeme` would silently produce forgeable decoys.
 */
function requiredSecret(name: string, minBytes: number): Buffer {
  const bytes = Buffer.from(required(name), 'base64url');
  if (bytes.length < minBytes) {
    throw new Error(
      `${name} must decode to at least ${minBytes} bytes of base64url, got ${bytes.length}\n` +
        `generate one with: node -e "console.log(require('crypto').randomBytes(${minBytes}).toString('base64url'))"`,
    );
  }
  return bytes;
}

export const config = {
  nodeEnv: optional('NODE_ENV', 'development'),
  logLevel: optional('LOG_LEVEL', 'info'),
  host: optional('HOST', '0.0.0.0'),
  port: Number(optional('PORT', '3030')),
  databaseUrl: required('DATABASE_URL'),
  redisUrl: required('REDIS_URL'),
  serveTestFrontend: bool('SERVE_TEST_FRONTEND', false),

  // Keys the decoy salts that make `GET /salt` refuse to confirm whether an
  // account exists (design Section 3). Rotating it changes every decoy, which is
  // harmless — decoys only have to be stable, not permanent.
  serverSecret: requiredSecret('SERVER_SECRET', 32),

  // TLS is mandatory by design (Section 4) — including on the LAN. The toggle
  // exists only so a misconfigured cert produces an obvious, loud failure
  // instead of a silent fallback to plaintext.
  tlsEnabled: bool('TLS_ENABLED', true),
  tlsCertPath: optional('TLS_CERT_PATH', 'certs/dev-cert.pem'),
  tlsKeyPath: optional('TLS_KEY_PATH', 'certs/dev-key.pem'),
} as const;

export const isDev = config.nodeEnv !== 'production';
