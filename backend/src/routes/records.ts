/**
 * `POST /records` (design Section 7, roadmap 6.1) — the one route authenticated
 * by a device signature rather than a session cookie, so it is registered
 * outside `requireSession`'s scope entirely (see the note on that scope in
 * `require-session.ts` and roadmap 2.6). A device has no session to hold: it
 * never logs in, it signs.
 *
 * The three checks below are exactly Section 7.4's three, in that order, and
 * none of them touch `ciphertext`'s contents — the server stores an opaque blob
 * it has verified came from a device that owns `sign_pub`, at a sequence
 * position it has not seen before, and stops there.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import {
  Base64UrlBytes,
  Base64UrlVariableBytes,
  decodeBase64Url,
  decodeBase64UrlRange,
} from '../lib/base64url.js';
import { verifyEd25519 } from '../lib/ed25519.js';
import { httpError, isUniqueViolation } from '../lib/http-error.js';
import { buildAad, buildNonce, parseSeq, SeqString } from '../lib/seq.js';
import {
  DEVICE_ID_BYTES,
  NONCE_BYTES,
  RECORD_CIPHERTEXT_MAX_BYTES,
  RECORD_CIPHERTEXT_MIN_BYTES,
  SIG_BYTES,
} from '../lib/wire-format.js';

const RecordBody = Type.Object(
  {
    device_id: Base64UrlBytes(DEVICE_ID_BYTES, '128-bit device identifier'),
    seq: SeqString,
    nonce: Base64UrlBytes(NONCE_BYTES, '0x00000000 || seq'),
    ciphertext: Base64UrlVariableBytes(
      RECORD_CIPHERTEXT_MIN_BYTES,
      RECORD_CIPHERTEXT_MAX_BYTES,
      'AES-256-GCM(device_data_key, nonce, CBOR{t,r}, AAD)',
    ),
    sig: Base64UrlBytes(SIG_BYTES, 'Ed25519(device_sign_priv, AAD||nonce||ciphertext)'),
  },
  { additionalProperties: false },
);

export const recordRoutes: FastifyPluginAsyncTypebox = async (app) => {
  app.post(
    '/records',
    { schema: { body: RecordBody, response: { 201: Type.Object({}) } } },
    async (req, reply) => {
      const deviceId = decodeBase64Url(req.body.device_id, DEVICE_ID_BYTES);
      const nonce = decodeBase64Url(req.body.nonce, NONCE_BYTES);
      const sig = decodeBase64Url(req.body.sig, SIG_BYTES);
      const ciphertext = decodeBase64UrlRange(
        req.body.ciphertext,
        RECORD_CIPHERTEXT_MIN_BYTES,
        RECORD_CIPHERTEXT_MAX_BYTES,
      );

      let seq: bigint;
      try {
        seq = parseSeq(req.body.seq);
      } catch (err) {
        throw httpError(400, (err as Error).message);
      }

      // Not an anti-enumeration concern the way /salt is: device_id is not a
      // credential, it is a value the design document already lists as
      // something the server legitimately knows (Section 5.2).
      const device = await app.pg.queryOne<{ sign_pub: Buffer }>(
        'select sign_pub from devices where device_id = $1',
        [deviceId],
      );
      if (!device) throw httpError(404, 'unknown device_id');

      const aad = buildAad(deviceId, seq);
      const message = Buffer.concat([aad, nonce, ciphertext]);

      // Check 1: is this really from that device? Verified against the
      // wire-supplied nonce, since that is what the device actually signed —
      // check 3 below confirms that nonce was also the *correct* one for this
      // seq, which is a separate question from whether the device signed it.
      if (!verifyEd25519(device.sign_pub, message, sig)) {
        throw httpError(401, 'signature does not verify against the registered sign_pub');
      }

      // Check 3: nonce well-formed and consistent with the claimed seq.
      if (!nonce.equals(buildNonce(seq))) {
        throw httpError(400, 'nonce does not match 0x00000000 || seq for the claimed seq');
      }

      await app.pg.transaction(async (tx) => {
        // Check 2: seq > last_seq[device_id], as a single-statement
        // compare-and-swap rather than a read-then-write — same reasoning as
        // the vault_version CAS in `vault.ts`. Two uploads racing for the same
        // device must not both pass a separate read.
        const bumped = await tx.query<{ last_seq: string }>(
          `update devices
              set last_seq = $2, last_seen_at = now()
            where device_id = $1 and last_seq < $2
        returning last_seq`,
          [deviceId, seq.toString()],
        );

        if (bumped.rowCount === 0) {
          throw httpError(409, `seq ${seq} is not greater than this device's last recorded seq`);
        }

        try {
          await tx.query(
            `insert into records (device_id, seq, nonce, ciphertext, sig)
             values ($1, $2, $3, $4, $5)`,
            [deviceId, seq.toString(), nonce, ciphertext, sig],
          );
        } catch (err) {
          // Belt-and-braces against the unique constraint in the initial
          // migration; the CAS above should already make this unreachable.
          if (isUniqueViolation(err)) {
            throw httpError(409, 'seq already recorded for this device');
          }
          throw err;
        }
      });

      return reply.code(201).send({});
    },
  );
};
