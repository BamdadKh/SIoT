/**
 * Sending one command to a device the account owns (roadmap 11.2 and 11.5).
 *
 * The order is the whole of the safety argument, and it is fixed by ROADMAP 11.0:
 *
 *   1. Re-read the vault and check the command against the device's schema as
 *      it is *now*. A command is sent only if the schema declares its type, with
 *      exactly the arguments it declares (`buildCommandArgs`). A screen can hand
 *      this values, never shape.
 *   2. Reserve the next `command_seq` and write the vault *before* anything is
 *      posted. Two tabs racing collide on the `vault_version` compare-and-swap and
 *      one gets the ordinary 409; neither can send a number the other also sends,
 *      which the device would run only once.
 *   3. Derive `device_command_key` from the current `DEVICE_SECRET`, encrypt with
 *      a random nonce (`encryptCommand`), post, zero the key.
 *
 * A number reserved and then never posted (the post failed) is harmless: the
 * device only needs `command_seq` to increase. Retrying reserves a fresh one
 * rather than re-sending the old ciphertext, so a retry is never two commands
 * that the device would both run.
 *
 * The server sees that a command was queued for this device and when. It cannot
 * see the type, the arguments or the sequence number, and it cannot forge one,
 * since it holds no `DEVICE_SECRET`.
 */

import {
  buildCommandArgs,
  deriveDeviceCommandKey,
  deviceIdBytes,
  deviceSecretBytes,
  encryptCommand,
  findDevice,
  findSchemaCommand,
  reserveCommandSeq,
  toBase64Url,
} from '@siot/crypto';
import { postCommand } from './api.js';
import { loadVault, storeVault } from './vault-store.js';

/**
 * @param {string} username
 * @param {string} deviceId base64url
 * @param {string} type a command type the device's schema declares.
 * @param {Record<string, unknown>} values its arguments.
 * @returns {Promise<{ commandSeq: number, cursor: string|null }>}
 */
export async function sendCommand(username, deviceId, type, values) {
  const { version, document } = await loadVault(username);
  const entry = findDevice(document, deviceId);
  if (!entry) throw new Error('This device is no longer in your vault.');

  const command = findSchemaCommand(entry.schema ?? null, type);
  if (!command) throw new Error(`This device's fields no longer declare the command ${type}.`);
  // Throws with a message fit to show, before anything is reserved.
  const args = buildCommandArgs(command, values);

  const { document: reserved, commandSeq } = reserveCommandSeq(document, deviceId);
  await storeVault(username, version, reserved);

  const commandKey = await deriveDeviceCommandKey(deviceSecretBytes({ secret: entry.secret }));
  try {
    const { nonce, ciphertext } = await encryptCommand({
      deviceId: deviceIdBytes({ id: deviceId }),
      commandKey,
      commandSeq,
      type,
      args,
    });
    const response = await postCommand(deviceId, {
      nonce: toBase64Url(nonce),
      ciphertext: toBase64Url(ciphertext),
    });
    return { commandSeq, cursor: response?.cursor ?? null };
  } finally {
    commandKey.fill(0);
  }
}
