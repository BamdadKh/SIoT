/**
 * Decoy salts for unknown usernames (design Section 3).
 *
 * The salt has to be fetched by username *before* authentication, so an unknown
 * username still has to return something. Returning an error — or a random value
 * — would answer the question the endpoint exists to refuse: 404 says the
 * account is free, and a value that changes between two requests for the same
 * name says it was never real.
 *
 * `HMAC(server_secret, username)` gives a value that is deterministic (stable
 * across retries, like a stored salt), unguessable without the server secret,
 * and uniformly distributed, so it is indistinguishable from a CSPRNG salt.
 *
 * It is not a *secret* — it goes on the wire to anyone who asks. The secret only
 * has to stop an attacker from computing decoys offline and diffing them against
 * live responses to sort real accounts from fake ones.
 */

import { createHmac } from 'node:crypto';
import { config } from '../config.js';

export function decoySalt(username: string, byteLength: number): Buffer {
  // Truncating SHA-256 is fine — every byte of an HMAC tag is equally uniform,
  // and 128 bits is the length a real salt has.
  return createHmac('sha256', config.serverSecret)
    .update(username, 'utf8')
    .digest()
    .subarray(0, byteLength);
}
