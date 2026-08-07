import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';

import {
  buildNonce,
  buildRecordAad,
  composeSeq,
  decryptRecord,
  encryptRecord,
  recordSigningInput,
} from '../lib/crypto/record.js';
import { encodeCbor } from '../lib/crypto/cbor.js';
import { deriveDeviceDataKey, deriveDeviceSignSeed } from '../lib/crypto/device.js';
import { ed25519PublicKeyFromSeed, ed25519Sign } from '../lib/crypto/ed25519.js';
import { toBase64Url } from '../lib/crypto/encoding.js';

/**
 * The published vectors (`docs/vectors/records-v1.json`, roadmap 4.7) re-derived
 * from scratch.
 *
 * This is what stops the document being a description of what the code used to
 * do. `scripts/generate-vectors.js` writes the file; this reads it back and
 * recomputes every field, so a change to the HKDF labels, the AAD layout, the
 * nonce construction, the CBOR encoding or the signature input fails here rather
 * than in somebody else's firmware six months later.
 */
const VECTORS = JSON.parse(
  readFileSync(new URL('../../docs/vectors/records-v1.json', import.meta.url), 'utf8'),
);

const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (value) => Buffer.from(value).toString('hex');

test('the published device keys derive from the published DEVICE_SECRET', async () => {
  const secret = bytes(VECTORS.device.device_secret_hex);

  const dataKey = await deriveDeviceDataKey(secret);
  assert.equal(hex(dataKey), VECTORS.device.device_data_key_hex);

  const signSeed = await deriveDeviceSignSeed(secret);
  assert.equal(hex(signSeed), VECTORS.device.ed25519_seed_hex);

  const signPub = await ed25519PublicKeyFromSeed(signSeed);
  assert.equal(hex(signPub), VECTORS.device.sign_pub_hex);
  assert.equal(toBase64Url(signPub), VECTORS.device.sign_pub_b64url);

  // The two labels are a wire format shared with every port, so they are pinned
  // by value here and not only by the derivation above.
  assert.equal(VECTORS.device.hkdf.data_key_info, 'siot/device/data/v1');
  assert.equal(VECTORS.device.hkdf.sign_seed_info, 'siot/device/sign/v1');
});

test('every published record reproduces byte for byte', async () => {
  const secret = bytes(VECTORS.device.device_secret_hex);
  const deviceId = bytes(VECTORS.device.device_id_hex);
  const dataKey = await deriveDeviceDataKey(secret);
  const signSeed = await deriveDeviceSignSeed(secret);

  assert.ok(VECTORS.records.length >= 2, 'the vectors should cover more than one boot');

  for (const record of VECTORS.records) {
    const where = `record ${record.seq} (${record.label})`;

    const seq = composeSeq(record.boot_epoch, record.msg_counter);
    assert.equal(seq.toString(), record.seq, `${where}: seq composition`);

    assert.equal(hex(encodeCbor(record.payload)), record.payload_cbor_hex, `${where}: CBOR`);
    assert.equal(hex(buildNonce(seq)), record.nonce_hex, `${where}: nonce`);
    assert.equal(hex(buildRecordAad(deviceId, seq)), record.aad_hex, `${where}: AAD`);

    const { nonce, ciphertext, aad } = await encryptRecord({
      dataKey,
      deviceId,
      seq,
      payload: record.payload,
    });
    assert.equal(hex(ciphertext), record.ciphertext_hex, `${where}: ciphertext`);

    const signature = await ed25519Sign(signSeed, recordSigningInput(aad, nonce, ciphertext));
    assert.equal(hex(signature), record.sig_hex, `${where}: signature`);

    // And the body a port actually posts, so a mismatch shows up as a diff of
    // the request rather than as a 400 with a field name in it.
    assert.deepEqual(
      record.post_records_body,
      {
        device_id: VECTORS.device.device_id_b64url,
        seq: record.seq,
        nonce: toBase64Url(nonce),
        ciphertext: toBase64Url(ciphertext),
        sig: toBase64Url(signature),
      },
      `${where}: POST /records body`,
    );
  }
});

test('the published records verify and decrypt the way the server and the client do', async () => {
  const secret = bytes(VECTORS.device.device_secret_hex);
  const deviceId = bytes(VECTORS.device.device_id_hex);
  const dataKey = await deriveDeviceDataKey(secret);

  const publicKey = createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: VECTORS.device.sign_pub_b64url },
    format: 'jwk',
  });

  for (const record of VECTORS.records) {
    const seq = BigInt(record.seq);
    const nonce = bytes(record.nonce_hex);
    const ciphertext = bytes(record.ciphertext_hex);

    // The server's check 1, against nothing but the published public key.
    const message = recordSigningInput(bytes(record.aad_hex), nonce, ciphertext);
    assert.equal(
      nodeVerify(null, message, publicKey, bytes(record.sig_hex)),
      true,
      `record ${record.seq}: signature verifies`,
    );

    // The client's side of it: the payload comes back out.
    const payload = await decryptRecord({ dataKey, deviceId, seq, nonce, ciphertext });
    assert.deepEqual(payload, record.payload, `record ${record.seq}: payload`);
  }
});
