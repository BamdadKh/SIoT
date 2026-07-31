#!/usr/bin/env node
/**
 * Generates a self-signed cert for local development.
 *
 * Dev-only scaffolding. Production terminates TLS with a real certificate; this
 * exists so the plaintext HTTP path can be retired now rather than "later",
 * because a codebase that works over HTTP in dev grows assumptions that only
 * hold over HTTP (design Section 4 — "it's just my LAN" is exactly how the
 * device-registration attack succeeds).
 *
 * SANs cover localhost plus every detected LAN address, so an ESP32 on the same
 * network can reach the dev server by IP and still validate the certificate.
 *
 * Uses the `selfsigned` package rather than shelling out to openssl, which is
 * not reliably on PATH on Windows.
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const selfsigned = require('selfsigned');

const CERT_DIR = path.resolve(__dirname, '../certs');
const CERT_PATH = path.join(CERT_DIR, 'dev-cert.pem');
const KEY_PATH = path.join(CERT_DIR, 'dev-key.pem');
const VALID_DAYS = 825; // browsers reject longer-lived leaf certs

function localAddresses() {
  const addresses = new Set(['127.0.0.1', '::1']);
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) addresses.add(entry.address);
    }
  }
  return [...addresses];
}

/**
 * SHA-256 of the SubjectPublicKeyInfo, base64. This is the value devices pin
 * (design Section 4 — SPKI, not the leaf cert, so renewals that reuse the key
 * pair don't brick the fleet).
 */
function spkiPin(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('base64');
}

async function main() {
  const force = process.argv.includes('--force');
  if (fs.existsSync(CERT_PATH) && !force) {
    console.log(`cert already exists at ${CERT_PATH}\nre-run with --force to replace it`);
    return;
  }

  const ips = localAddresses();
  const altNames = [
    { type: 2, value: 'localhost' }, // 2 = DNS
    ...ips.map((ip) => ({ type: 7, ip })), // 7 = IP
  ];

  const notBeforeDate = new Date();
  const notAfterDate = new Date(notBeforeDate.getTime() + VALID_DAYS * 86_400_000);

  // selfsigned v5 is async-only and takes explicit date bounds, not `days`.
  const pems = await selfsigned.generate([{ name: 'commonName', value: 'localhost' }], {
    keyType: 'rsa',
    keySize: 2048,
    algorithm: 'sha256',
    notBeforeDate,
    notAfterDate,
    extensions: [
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames },
    ],
  });

  fs.mkdirSync(CERT_DIR, { recursive: true });
  fs.writeFileSync(CERT_PATH, pems.cert);
  fs.writeFileSync(KEY_PATH, pems.private, { mode: 0o600 });

  console.log(`wrote ${CERT_PATH}`);
  console.log(`wrote ${KEY_PATH}`);
  console.log(`\nvalid for ${VALID_DAYS} days, SANs: localhost, ${ips.join(', ')}`);
  console.log(`SPKI pin (sha256/base64): ${spkiPin(pems.public)}`);
  console.log('\nThis cert is self-signed, so browsers will warn once per host. That is');
  console.log('expected in dev; it is not a reason to fall back to HTTP.');
}

main().catch((err) => {
  console.error('certificate generation failed:', err);
  process.exit(1);
});
