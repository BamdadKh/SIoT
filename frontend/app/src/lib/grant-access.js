/**
 * The browser's half of a grant (roadmap 8.1), between `GrantAccess.jsx` and
 * `sealGrant`.
 *
 * Both data keys are derived here from the `DEVICE_SECRET`s the vault holds and
 * zeroed as soon as the blob is sealed, the same lifetime rule
 * `use-device-records.js` follows: a key that outlives the one operation it was
 * derived for is a key sitting in memory for no reason. The server receives the
 * sealed 60 bytes and the two identifiers, which it already knows.
 *
 * Untested here, like the other hooks and adapters: the crypto it composes is
 * covered by `test/grant.test.js`, including that the key a grant carries opens
 * the source device's records.
 */

import {
  deriveDeviceDataKey,
  deviceIdBytes,
  deviceSecretBytes,
  sealGrant,
  toBase64Url,
} from '@siot/crypto';
import { createGrant, fetchDeviceGrants } from './api.js';

/**
 * Seals `source`'s data key under `recipient`'s and stores it.
 *
 * @param {{ source: { id: string, secret: string }, recipient: { id: string, secret: string } }} pair
 *        vault entries: `source` is device B, the one being read; `recipient` is A.
 */
export async function grantReadAccess({ source, recipient }) {
  const sourceKey = await deriveDeviceDataKey(deviceSecretBytes(source));
  const recipientKey = await deriveDeviceDataKey(deviceSecretBytes(recipient));
  let blob;
  try {
    blob = await sealGrant({
      deviceAId: deviceIdBytes(recipient),
      deviceBId: deviceIdBytes(source),
      deviceADataKey: recipientKey,
      deviceBDataKey: sourceKey,
    });
  } finally {
    sourceKey.fill(0);
    recipientKey.fill(0);
  }

  await createGrant({
    deviceAId: recipient.id,
    deviceBId: source.id,
    ciphertext: toBase64Url(blob),
  });
}

/**
 * Which of `candidates` hold a grant on `sourceId`, each with the date of its
 * earliest grant. A pair can hold several rows (a grant made again after the
 * source rotates its secret adds one rather than replacing one, design 9.3), and
 * the earliest is when the recipient first could read.
 *
 * @param {string} sourceId
 * @param {string[]} candidates device ids to ask about.
 * @returns {Promise<Array<{ id: string, since: string }>>}
 */
export async function findReaders(sourceId, candidates) {
  const answers = await Promise.all(
    candidates.map(async (id) => {
      const { grants } = await fetchDeviceGrants(id);
      const dates = grants
        .filter((grant) => grant.device_b_id === sourceId)
        .map((grant) => grant.created_at)
        .sort();
      return dates.length > 0 ? { id, since: dates[0] } : null;
    }),
  );
  return answers.filter(Boolean);
}
