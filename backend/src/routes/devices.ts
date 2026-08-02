/**
 * Device identity routes (design Section 5, roadmap 4.2 and 4.8).
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
import { parseSeq, SeqString } from '../lib/seq.js';
import {
  DEVICE_ID_BYTES,
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
 */
const RecordsQuery = Type.Object({
  /** Exclusive lower bound; omit for the oldest page. */
  after_seq: Type.Optional(SeqString),
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
   * Raw record blobs for client-side decryption (roadmap 6.2, design Section 6.3).
   * Owner-only for now — the design's grant mechanism (Section 9) is Phase 8,
   * so a device visible only through a grant is out of scope until then, per
   * the roadmap item's own "stub owner-only check for now".
   *
   * The server never decrypts; it hands back exactly the columns it stored in
   * `POST /records` (Section 7.4) plus when it received them, in ascending
   * `seq` order so gaps within a `boot_epoch` are as easy to see as the design's
   * client-side gap detection (6.3) needs them to be.
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

      let afterSeq = 0n;
      if (req.query.after_seq !== undefined) {
        try {
          afterSeq = parseSeq(req.query.after_seq);
        } catch (err) {
          throw httpError(400, (err as Error).message);
        }
      }
      const limit = req.query.limit ?? RECORDS_PAGE_DEFAULT;

      const rows = await app.pg.query<{
        seq: string;
        nonce: Buffer;
        ciphertext: Buffer;
        created_at: Date;
      }>(
        `select seq, nonce, ciphertext, created_at
           from records
          where device_id = $1 and seq > $2
          order by seq asc
          limit $3`,
        [deviceId, afterSeq.toString(), limit],
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
