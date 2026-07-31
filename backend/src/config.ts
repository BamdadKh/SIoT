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

export const config = {
  nodeEnv: optional('NODE_ENV', 'development'),
  logLevel: optional('LOG_LEVEL', 'info'),
  host: optional('HOST', '0.0.0.0'),
  port: Number(optional('PORT', '3030')),
  databaseUrl: required('DATABASE_URL'),
  redisUrl: required('REDIS_URL'),
  serveTestFrontend: bool('SERVE_TEST_FRONTEND', false),

  // TLS is mandatory by design (Section 4) — including on the LAN. The toggle
  // exists only so a misconfigured cert produces an obvious, loud failure
  // instead of a silent fallback to plaintext.
  tlsEnabled: bool('TLS_ENABLED', true),
  tlsCertPath: optional('TLS_CERT_PATH', 'certs/dev-cert.pem'),
  tlsKeyPath: optional('TLS_KEY_PATH', 'certs/dev-key.pem'),
} as const;

export const isDev = config.nodeEnv !== 'production';
