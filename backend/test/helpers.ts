/**
 * The backend suite's harness: the real app, the real database, no mocks.
 *
 * `buildApp()` is driven through Fastify's `inject`, which never opens a socket,
 * so TLS stays enabled exactly as in dev and there is no plaintext mode to add
 * for testing (CLAUDE.md, rule 4). Postgres and Redis are the docker-compose
 * ones, pointed at the disposable `siot_test` database and Redis database 15
 * that `scripts/test-db.js` creates, migrates and wipes before each run.
 *
 * Every value a client would derive (salts, `login_key`, wrapped keys, vault
 * blobs, ciphertext) is random bytes of the right length here. That is not a
 * shortcut: the server cannot tell the difference, which is the property the
 * whole design rests on. The one thing the server does check cryptographically
 * is a device's Ed25519 signature, so devices get real keypairs from Node's own
 * `crypto`, and the signing input is built here from the published layout
 * (`docs/protocol.md`), independently of `src/lib/seq.ts`, so a bug there is a
 * failing test rather than a matching one. Nothing here imports
 * `frontend/lib/crypto/`: the backend has no business reaching for client keys,
 * even in a test.
 */

import crypto from 'node:crypto';

process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent';
process.env.DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://siot:siot@localhost:5433/siot_test';
process.env.REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://localhost:6379/15';
process.env.SERVER_SECRET = crypto.randomBytes(32).toString('base64url');
process.env.TLS_ENABLED = 'true';

type App = Awaited<ReturnType<typeof import('../src/app.js').buildApp>>;

/** A fresh app per test file; close it in `after`. */
export async function startApp(): Promise<App> {
  const { buildApp } = await import('../src/app.js');
  const app = await buildApp();
  await app.ready();
  return app;
}

export const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
export const random = (length: number) => b64(crypto.randomBytes(length));

/** A username that cannot collide with another test's. */
export function uniqueName(prefix = 'user') {
  return `${prefix}_${crypto.randomBytes(6).toString('hex')}`;
}

export type Account = { username: string; loginKey: string; salt: string; cookie: string };

/** Signs up and logs in, returning the session cookie as a `cookie` header value. */
export async function newAccount(app: App): Promise<Account> {
  const username = uniqueName();
  const salt = random(16);
  const loginKey = random(32);
  const signup = await app.inject({
    method: 'POST',
    url: '/siot/signup',
    payload: { username, salt, login_key: loginKey, wrapped_vault_key: random(60) },
  });
  if (signup.statusCode !== 201) throw new Error(`signup failed: ${signup.body}`);

  const login = await app.inject({
    method: 'POST',
    url: '/siot/login',
    payload: { username, login_key: loginKey },
  });
  if (login.statusCode !== 200) throw new Error(`login failed: ${login.body}`);
  const session = login.cookies.find((cookie) => cookie.name === 'siot_session');
  if (!session) throw new Error('login set no session cookie');
  return { username, loginKey, salt, cookie: `siot_session=${session.value}` };
}

export type Device = {
  id: string;
  idBytes: Buffer;
  privateKey: crypto.KeyObject;
  signPub: string;
};

export function newDeviceKeys(): Device {
  const idBytes = crypto.randomBytes(16);
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  return { id: b64(idBytes), idBytes, privateKey, signPub: jwk.x as string };
}

/** Mints device keys and registers them under the account. */
export async function newDevice(app: App, account: Account): Promise<Device> {
  const device = newDeviceKeys();
  const response = await app.inject({
    method: 'POST',
    url: '/siot/devices/register',
    headers: { cookie: account.cookie },
    payload: { device_id: device.id, sign_pub: device.signPub },
  });
  if (response.statusCode !== 201) throw new Error(`register failed: ${response.body}`);
  return device;
}

/** `(boot_epoch << 32) | msg_counter` as the wire's decimal string. */
export function seqOf(bootEpoch: number | bigint, msgCounter: number | bigint): string {
  return ((BigInt(bootEpoch) << 32n) | BigInt(msgCounter)).toString();
}

function u64(value: string) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

/**
 * A `POST /records` body, signed the way `docs/protocol.md` sections 4, 5 and 7
 * describe: nonce `0x00000000 || seq`, AAD `0x01 || DEVICE_ID || 0x00 || seq`,
 * signature over `AAD || nonce || ciphertext`. The ciphertext is random: the
 * server never opens it.
 */
export function signedRecord(
  device: Device,
  seq: string,
  options: { nonceSeq?: string; signer?: crypto.KeyObject } = {},
) {
  const nonce = Buffer.concat([Buffer.alloc(4), u64(options.nonceSeq ?? seq)]);
  const aad = Buffer.concat([Buffer.from([1]), device.idBytes, Buffer.from([0]), u64(seq)]);
  const ciphertext = crypto.randomBytes(40);
  const sig = crypto.sign(
    null,
    Buffer.concat([aad, nonce, ciphertext]),
    options.signer ?? device.privateKey,
  );
  return {
    device_id: device.id,
    seq,
    nonce: b64(nonce),
    ciphertext: b64(ciphertext),
    sig: b64(sig),
  };
}

export async function upload(app: App, body: ReturnType<typeof signedRecord>) {
  return app.inject({ method: 'POST', url: '/siot/records', payload: body });
}
