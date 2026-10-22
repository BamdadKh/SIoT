/**
 * Device identity routes (design Section 5, roadmap 4.2, 4.8 and 4.9).
 *
 * Everything here is a value the design document explicitly permits the server
 * to see in plaintext (Section 5.2): `DEVICE_ID`, `device_sign_pub`, and timing
 * metadata. `DEVICE_SECRET` and the device's name never appear on this path —
 * the name lives in the vault (design 5.5) and is joined against this list
 * client-side, not looked up here.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import {
  Base64UrlBytes,
  Base64UrlVariableBytes,
  decodeBase64Url,
  encodeBase64Url,
} from '../lib/base64url.js';
import { httpError, isUniqueViolation } from '../lib/http-error.js';
import { verifyLoginKey } from '../lib/login-key.js';
import {
  addressThrottle,
  changePasswordThrottle,
  checkThrottles,
  clearThrottle,
  registerFailure,
} from '../lib/rate-limit.js';
import { parseSeq, SeqString } from '../lib/seq.js';
import {
  DEVICE_ID_BYTES,
  LOGIN_KEY_BYTES,
  NONCE_BYTES,
  RECORD_CIPHERTEXT_MAX_BYTES,
  RECORD_CIPHERTEXT_MIN_BYTES,
  SIGN_PUB_BYTES,
} from '../lib/wire-format.js';

const DeviceId = Base64UrlBytes(DEVICE_ID_BYTES, '128-bit device identifier');

/** Page size bounds for `GET /devices/:device_id/records` (roadmap 6.2). */
const RECORDS_PAGE_DEFAULT = 100;
const RECORDS_PAGE_MAX = 500;

const RegisterDeviceBody = Type.Object(
  {
    device_id: DeviceId,
    sign_pub: Base64UrlBytes(SIGN_PUB_BYTES, 'Ed25519 device_sign_pub'),
  },
  { additionalProperties: false },
);

const RegisterDeviceResponse = Type.Object({
  device_id: DeviceId,
});

const RotateDeviceBody = Type.Object(
  {
    sign_pub: Base64UrlBytes(SIGN_PUB_BYTES, 'Ed25519 device_sign_pub derived from the new secret'),
    current_login_key: Base64UrlBytes(
      LOGIN_KEY_BYTES,
      'HKDF(current master_key, "siot/auth/v1")',
    ),
  },
  { additionalProperties: false },
);

const RotateDeviceResponse = Type.Object({ through_seq: SeqString });

const DeviceListResponse = Type.Object({
  devices: Type.Array(
    Type.Object({
      device_id: DeviceId,
      last_seq: SeqString,
      /** `null` until the device's first record lands (Phase 6). */
      last_seen_at: Type.Union([Type.String({ format: 'date-time' }), Type.Null()]),
    }),
  ),
});

const RecordsParams = Type.Object({ device_id: DeviceId });

/**
 * Cursor is `seq`, not time (roadmap 6.2's "by seq or time"): `seq` is the
 * authoritative order (Section 7.1), the device's own clock is not trusted for
 * anything, and it is already the index's sort key (`devices_seq_unique`'s
 * partner index, `device_id, seq desc`).
 *
 * **Both directions, because the two readers of this route want opposite ends.**
 * An export (roadmap 6.4) walks the whole history forwards from the beginning,
 * which is what `after_seq` with the default ascending order is for. A device
 * page (6.3) wants the newest page first and then older ones on demand, and
 * with an ascending cursor the only way to reach the newest record is to page
 * through every record before it. `order: 'desc'` with `before_seq` is that walk
 * run the other way. The index is already `(device_id, seq desc)`, so the
 * direction this was missing is the one the index was built for.
 */
const RecordsQuery = Type.Object({
  /** Exclusive lower bound; omit for the oldest record. */
  after_seq: Type.Optional(SeqString),
  /** Exclusive upper bound; omit for the newest record. */
  before_seq: Type.Optional(SeqString),
  order: Type.Optional(
    Type.Union([Type.Literal('asc'), Type.Literal('desc')], { default: 'asc' }),
  ),
  limit: Type.Optional(Type.Integer({ minimum: 1, maximum: RECORDS_PAGE_MAX })),
});

const RecordsListResponse = Type.Object({
  records: Type.Array(
    Type.Object({
      seq: SeqString,
      nonce: Base64UrlBytes(NONCE_BYTES, '0x00000000 || seq'),
      ciphertext: Base64UrlVariableBytes(
        RECORD_CIPHERTEXT_MIN_BYTES,
        RECORD_CIPHERTEXT_MAX_BYTES,
        'AES-256-GCM(device_data_key, nonce, CBOR{t,r}, AAD)',
      ),
      created_at: Type.String({ format: 'date-time' }),
    }),
  ),
});

export const deviceRoutes: FastifyPluginAsyncTypebox = async (app) => {
  /**
   * Registers the public half of a device's identity, generated in the browser
   * (design 5.1, 5.3 step 2). `DEVICE_SECRET` and everything derived from it
   * never reach this route — the client uploads the encrypted device record to
   * the vault separately (roadmap 4.3), which is the only place the secret and
   * its name are stored.
   */
  app.post(
    '/devices/register',
    { schema: { body: RegisterDeviceBody, response: { 201: RegisterDeviceResponse } } },
    async (req, reply) => {
      const deviceId = decodeBase64Url(req.body.device_id, DEVICE_ID_BYTES);
      const signPub = decodeBase64Url(req.body.sign_pub, SIGN_PUB_BYTES);

      try {
        await app.pg.query(
          `insert into devices (device_id, owner_user_id, sign_pub)
           values ($1, $2, $3)`,
          [deviceId, req.session!.userId, signPub],
        );
      } catch (err) {
        // device_id is the primary key, so the index itself is the uniqueness
        // check — same reasoning as the username check-then-insert race in
        // /signup: a pre-SELECT would let two concurrent registrations of the
        // same freshly-generated id both pass.
        if (isUniqueViolation(err)) {
          throw httpError(409, 'that device_id is already registered');
        }
        throw err;
      }

      return reply.code(201).send({ device_id: req.body.device_id });
    },
  );

  /**
   * The metadata the server legitimately holds per device (design 5.2): the id,
   * how far it has counted, and when its newest record arrived. No names — it
   * has none (design 5.5). The client joins this against the vault's device
   * records by `DEVICE_ID` to get names and to notice the two mismatch cases
   * (roadmap 4.8): a vault entry the server has never heard of, and a device
   * the server reports that the vault has no record for.
   */
  app.get(
    '/devices',
    { schema: { response: { 200: DeviceListResponse } } },
    async (req, reply) => {
      const rows = await app.pg.query<{
        device_id: Buffer;
        last_seq: string;
        last_seen_at: Date | null;
      }>(
        `select device_id, last_seq, last_seen_at
           from devices
          where owner_user_id = $1
          order by created_at asc`,
        [req.session!.userId],
      );

      reply.header('cache-control', 'no-store');
      return {
        devices: rows.rows.map((row) => ({
          device_id: encodeBase64Url(row.device_id),
          last_seq: row.last_seq,
          last_seen_at: row.last_seen_at ? row.last_seen_at.toISOString() : null,
        })),
      };
    },
  );

  /**
   * Deletes a device and everything the server holds for it (roadmap 4.9).
   *
   * A hard delete, with no soft-delete flag and no tombstone. A tombstone would
   * be a retained record of a device someone asked to erase, and it would hold
   * the `device_id` primary key occupied forever — so the id could never be
   * re-registered and the board never cleanly reused, which is the exit this
   * route exists to provide.
   *
   * `records` and `grants` go with it by construction rather than by a cleanup
   * path someone has to remember to write: all three foreign keys are already
   * `ON DELETE CASCADE` (`1785456000000_initial-schema.js`,
   * `1785650000000_grants.js`). Grants cascade in *both* directions and that is
   * correct rather than collateral damage — a grant naming this device as the
   * source wraps a key whose records no longer exist, and one naming it as the
   * recipient is addressed to a device whose `device_data_key` died with its
   * vault entry. Neither is openable by anyone afterwards, so keeping the row
   * would preserve only its metadata (design 13.1 already counts grant edges as
   * server-visible).
   *
   * One statement, with the ownership check in the `where` clause rather than a
   * preceding `select`: same shape as the `last_seq` and `vault_version`
   * compare-and-swaps, and for the same reason — a device that changes hands
   * between a check and a write must not be deleted on the strength of the
   * check.
   *
   * Note this is only half of a delete. The device's `DEVICE_SECRET` and name
   * live in the vault, which the server cannot touch; the client removes that
   * entry with a separate `PUT /vault`. The two cannot be one transaction, so
   * the client does this half *first* — a failed vault write then leaves the
   * device reading as `UNREGISTERED` (roadmap 4.8), which is recoverable, where
   * the other order leaves an `ORPHAN`, which is not.
   */
  app.delete(
    '/devices/:device_id',
    { schema: { params: RecordsParams, response: { 204: Type.Null() } } },
    async (req, reply) => {
      const deviceId = decodeBase64Url(req.params.device_id, DEVICE_ID_BYTES);

      const deleted = await app.pg.query(
        'delete from devices where device_id = $1 and owner_user_id = $2',
        [deviceId, req.session!.userId],
      );

      // 404 for "not yours" and "does not exist" alike, matching every other
      // cross-owner lookup in this file. Answering 204 for an id that was never
      // here would make a stranger's live device (404) distinguishable from a
      // made-up one, which is the distinction the shared message exists to
      // deny. The client covers idempotency instead: retrying a delete that
      // already landed gets a 404, and the goal state is "not there", so it
      // treats that as success.
      if (deleted.rowCount === 0) throw httpError(404, 'unknown device_id');

      return reply.code(204).send(null);
    },
  );

  /**
   * Rebinds a device to a new `sign_pub` after its `DEVICE_SECRET` is rotated
   * (design 9.3, roadmap 8.4). The device keeps its `DEVICE_ID`; a new secret
   * yields a new signing key; this route is where the server learns it.
   *
   * **Why the password is required on top of the session.** A session alone
   * would let a cookie thief who also controls a device holding a read grant on
   * this one (it has the data key but never the signing key, design 9.1) rebind
   * `sign_pub` to a key they hold and then forge records that decrypt
   * correctly. Keeping the signing key out of every reader's hands is exactly
   * what the 5.1 key split is for, and an unauthenticated rebind would undo it.
   * So the check is the one `POST /change-password` makes: the same Argon2id
   * verify of `current_login_key`, the same 403, and the same per-user
   * throttle bucket. Sharing the bucket is deliberate: both routes are
   * "prove the password with a live session in hand", so guesses against either
   * must spend one budget, or the second route would double an attacker's tries.
   *
   * **`through_seq`** is the `last_seq` the row held at the instant of the
   * rebind: every record accepted under the old key has `seq <= through_seq`,
   * and none can land above it afterwards because `POST /records` makes its
   * `last_seq` swap conditional on `sign_pub` too (see records.ts). For a device
   * that never uploaded it is "0": `last_seq` defaults to 0 and a record needs
   * `seq > last_seq`, so "0" means nothing was accepted under the old key.
   *
   * Idempotent: repeating with the same `sign_pub` rewrites the same value and
   * returns the current `last_seq`, which is the same boundary unless a record
   * under the new key has landed since. A client retrying after a lost response
   * is therefore safe.
   *
   * One statement with the owner check in the `where` clause, as in DELETE.
   * 404 for "not yours" and "does not exist" alike.
   */
  app.post(
    '/devices/:device_id/rotate',
    {
      schema: {
        params: RecordsParams,
        body: RotateDeviceBody,
        response: { 200: RotateDeviceResponse },
      },
    },
    async (req) => {
      const userId = req.session!.userId;

      const throttles = [changePasswordThrottle(userId), addressThrottle(req.ip)];
      const throttle = await checkThrottles(app.redis, throttles);
      if (!throttle.allowed) {
        throw httpError(429, `too many attempts, try again in ${throttle.retryAfterSeconds}s`);
      }

      const user = await app.pg.queryOne<{ login_key_hash: string }>(
        'select login_key_hash from users where id = $1',
        [userId],
      );
      if (!user) throw httpError(401, 'authentication required');

      const currentLoginKey = decodeBase64Url(req.body.current_login_key, LOGIN_KEY_BYTES);
      let verified: boolean;
      try {
        verified = await verifyLoginKey(user.login_key_hash, currentLoginKey);
      } finally {
        currentLoginKey.fill(0);
      }
      if (!verified) {
        await registerFailure(app.redis, throttles);
        throw httpError(403, 'current password is incorrect');
      }
      await clearThrottle(app.redis, throttles[0]);

      const deviceId = decodeBase64Url(req.params.device_id, DEVICE_ID_BYTES);
      const signPub = decodeBase64Url(req.body.sign_pub, SIGN_PUB_BYTES);

      const rebound = await app.pg.queryOne<{ last_seq: string }>(
        `update devices
            set sign_pub = $1
          where device_id = $2 and owner_user_id = $3
      returning last_seq`,
        [signPub, deviceId, userId],
      );
      if (!rebound) throw httpError(404, 'unknown device_id');

      return { through_seq: rebound.last_seq };
    },
  );

  /**
   * Raw record blobs for client-side decryption (roadmap 6.2, design Section 6.3).
   * Owner-only for now — the design's grant mechanism (Section 9) is Phase 8,
   * so a device visible only through a grant is out of scope until then, per
   * the roadmap item's own "stub owner-only check for now".
   *
   * The server never decrypts; it hands back exactly the columns it stored in
   * `POST /records` (Section 7.4) plus when it received them, in `seq` order so
   * gaps within a `boot_epoch` are as easy to see as the design's client-side
   * gap detection (6.3) needs them to be. A page is contiguous in `seq` between
   * its bounds in either direction, which is what lets the client claim a gap
   * between two rows it holds and never claim one at the edge of a page.
   */
  app.get(
    '/devices/:device_id/records',
    {
      schema: {
        params: RecordsParams,
        querystring: RecordsQuery,
        response: { 200: RecordsListResponse },
      },
    },
    async (req, reply) => {
      const deviceId = decodeBase64Url(req.params.device_id, DEVICE_ID_BYTES);

      const owned = await app.pg.queryOne(
        'select 1 from devices where device_id = $1 and owner_user_id = $2',
        [deviceId, req.session!.userId],
      );
      // One message for "not yours" and "does not exist" — same reasoning as
      // every other cross-owner lookup in this file: a stranger's device_id
      // should not be distinguishable from a made-up one.
      if (!owned) throw httpError(404, 'unknown device_id');

      const bound = (value: string | undefined) => {
        if (value === undefined) return undefined;
        try {
          return parseSeq(value).toString();
        } catch (err) {
          throw httpError(400, (err as Error).message);
        }
      };
      const afterSeq = bound(req.query.after_seq);
      const beforeSeq = bound(req.query.before_seq);
      const limit = req.query.limit ?? RECORDS_PAGE_DEFAULT;
      // Not interpolated from the query value: an enum the schema already
      // narrowed to two literals, mapped through this table rather than
      // concatenated, so the SQL string stays a constant either way.
      const direction = req.query.order === 'desc' ? 'desc' : 'asc';

      // Built rather than fixed, because a sentinel upper bound would have to be
      // a literal above the uint64 range and that is a number to get wrong once.
      const params: unknown[] = [deviceId];
      const conditions = ['device_id = $1'];
      if (afterSeq !== undefined) conditions.push(`seq > $${params.push(afterSeq)}`);
      if (beforeSeq !== undefined) conditions.push(`seq < $${params.push(beforeSeq)}`);

      const rows = await app.pg.query<{
        seq: string;
        nonce: Buffer;
        ciphertext: Buffer;
        created_at: Date;
      }>(
        `select seq, nonce, ciphertext, created_at
           from records
          where ${conditions.join(' and ')}
          order by seq ${direction}
          limit $${params.push(limit)}`,
        params,
      );

      reply.header('cache-control', 'no-store');
      return {
        records: rows.rows.map((row) => ({
          seq: row.seq,
          nonce: encodeBase64Url(row.nonce),
          ciphertext: encodeBase64Url(row.ciphertext),
          created_at: row.created_at.toISOString(),
        })),
      };
    },
  );
};
