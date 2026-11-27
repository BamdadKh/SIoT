<div align="center">

# SIoT

**The S in IoT stands for security.**

A zero-knowledge IoT platform. ESP32 devices encrypt and sign their readings on the board;
the server is a dumb, fully untrusted blob store that never holds a key or a plaintext byte.

![Backend](https://img.shields.io/badge/backend-Fastify%20%2B%20TypeScript-2b2b2b)
![Frontend](https://img.shields.io/badge/client-React%20%2B%20Web%20Crypto-2b2b2b)
![Firmware](https://img.shields.io/badge/firmware-ESP32%20%2F%20Arduino-2b2b2b)
![Crypto](https://img.shields.io/badge/AEAD-AES--256--GCM-6b7a3a)
![Signatures](https://img.shields.io/badge/signatures-Ed25519-6b7a3a)

</div>

---

## The one rule

Every change to this project is judged against a single question:

> **Does this give the server plaintext access to anything, even indirectly?**

If the answer is yes, the change is wrong, however convenient it is. The server may only ever
see usernames, client salts, device IDs, device public keys, sequence numbers, nonces, opaque
ciphertext and timing metadata. Nothing else.

The guarantee is stated precisely, because cryptography cannot buy more than this:

> **The server can withhold, but it cannot lie undetected.**

It can refuse to serve data, stall, or delete. It cannot read anything, forge a record, move a
valid record into a different slot, or roll the vault back without the client noticing.

## How it works

```
            password (never leaves the browser)
                │
         Argon2id (64 MiB)
                │
            master_key ──HKDF──► login_key ──► server  (hashed again with Argon2id)
                │
                └──────HKDF──► kek ──unwraps──► vault_key ──opens──► vault
                                                                      │
                          device secrets, names, schemas, grants ◄────┘

  ESP32 ── DEVICE_SECRET ──HKDF──► data key  (AES-256-GCM, counter nonces)
                         └─HKDF──► signing key (Ed25519)
                                       │
                          encrypt + sign each reading on the board
                                       │
                                       ▼
          ┌────────────────────────────────────────────────────┐
          │  Server: verify signature, check seq, check nonce. │
          │  Store ciphertext. Decrypt nothing.                │
          └────────────────────────────────────────────────────┘
                                       │
                                       ▼
             browser fetches ciphertext, decrypts with the key
             from its own vault, and draws the dashboard
```

- **One secret to remember.** Everything else is derived or wrapped from the password, in the
  browser. Changing the password re-wraps 32 bytes; the vault itself never moves.
- **Nonces are never random on the device.** They come from a persisted boot epoch plus a
  message counter, so GCM nonce reuse is structurally impossible rather than unlikely.
- **Everything binds its context as AAD.** A record commits to its owner, device and position in
  sequence, so the server cannot splice one device's readings into another's history.
- **Rollback is caught client-side.** The vault version is bound into the ciphertext twice and
  checked against a high-water mark the browser keeps in IndexedDB.
- **Device names live in the vault.** "Bedroom motion sensor" next to upload timestamps would be
  a labelled occupancy log, so the server never sees one.
- **Provisioning goes over USB, not the network.** The browser writes credentials straight into
  a dedicated NVS partition over Web Serial, with a compare-and-swap so a board swapped mid-flow
  is never written against the wrong check.
- **Grants are read-only, and revocation is rotation.** One device can read another's data by
  holding its sealed data key; revoking means rotating the source's secret.

## The hard part: trusting the code in the browser

All of the above assumes the browser is the trust boundary. But the server delivers the
JavaScript that runs in that browser, and a server that swaps it can read the password at the
next sign-in. Cryptography cannot stop the party that ships the crypto code. This is the
standard objection to browser-based end-to-end encryption, and it applies here.

SIoT's answer is a small, deliberately non-updating **client verification extension**:

1. **On install**, you review the client and approve it. That version is pinned locally as your
   trust root.
2. **On every change**, the extension hashes the code your browser actually received (it never
   trusts a hash the server reports), fetches the published source, shows you the diff against
   what you approved, and waits for you to approve it.
3. **The only remaining point of failure is your own judgement**, and the design is built to make
   that judgement usable:
   - a **minimal trusted core** holds every key and almost never changes, so prompts are rare
     and short enough to read, while UI changes cannot touch key material;
   - a **reproducible build**, so the diff you approve is of the source that produced the bundle
     you run;
   - a **public transparency log**, so a version served to one targeted user is detectable, and a
     first install gets the same code everyone else got;
   - **delegated review**, so someone who cannot read a crypto diff can lean on auditors they
     choose.

The extension verifies the client code the browser receives, not what the server runs. The
server is untrusted and holds no plaintext, so what it runs does not matter. The closest prior
work is Meta's [Code Verify](https://engineering.fb.com/2022/03/10/security/code-verify/) for
WhatsApp Web. SIoT differs in using a user-pinned approval rather than a vendor's source of truth,
diff-based review over a minimal core, and applying this to IoT device pairing. The extension is
not built yet; it is [Phase 12](ROADMAP.md) and
[Section 10](SIoT_Design_Document.md#10-client-verification-system) of the design, and it is the
part of the project with a research question in it.

The full architecture, including the threat model and what is deliberately *not* defended
against (metadata leakage, availability, physical access), is in
[`SIoT_Design_Document.md`](SIoT_Design_Document.md).

## What's in the repo

| Path | What it is |
|---|---|
| [`backend/`](backend) | Fastify + TypeScript API. Postgres for blobs and public keys, Redis for sessions and login throttling. Raw SQL, TypeBox schemas, no ORM. |
| [`frontend/app/`](frontend/app) | The React + Vite client: sign up, unlock, devices, provisioning, readings, dashboard, grants, export. |
| [`frontend/lib/crypto/`](frontend/lib/crypto) | All client crypto, as plain ESM modules shared by the browser and the test suite. It lives outside `backend/` on purpose. |
| [`frontend/index.html`](frontend/index.html) | A plain-HTML test console that exercises the crypto directly, with no React in the way. |
| [`firmware/SIoT/`](firmware/SIoT) | The Arduino device library for ESP32: HKDF, hardware AES-GCM, Ed25519, CBOR, pinned TLS. Nothing outside the ESP32 core. |
| [`firmware/esp32-provisioning/`](firmware/esp32-provisioning) | The serial listener the browser provisions a board through. |
| `extension/` | The client verification extension (Phase 12, not started). |
| [`docs/protocol.md`](docs/protocol.md) | The published wire contract for anyone porting to other hardware, with [known-answer vectors](docs/vectors) generated by the shipped code. |
| [`ROADMAP.md`](ROADMAP.md) | The ordered task list, and the record of what is actually done. |

## Running it locally

You need Node.js, Docker, and (for firmware) `arduino-cli` with the ESP32 core.

**1. Databases**

```bash
docker compose up -d          # Postgres on :5433, Redis on :6379
```

**2. Backend**

```bash
cd backend
npm install
cp .env.example .env          # first time only
npm run gen-cert              # first time only: self-signed dev TLS cert
npm run migrate:up
npm run dev                   # https://localhost:3030
```

TLS is on in development too. The browser warns once about the self-signed certificate;
accept it rather than turning TLS off. The session cookie is `Secure; SameSite=Strict`, so a
plaintext setup silently breaks authentication.

**3. Client**

```bash
cd frontend
npm install
npm test                      # node --test over the crypto and client logic
npm run dev                   # https://localhost:5173
```

The Vite dev server reuses the backend's certificate and proxies API calls to `:3030`.

**4. A device (optional)**

```bash
# Flash the provisioning listener, then add the device from the browser (Chromium, Web Serial)
arduino-cli compile --fqbn esp32:esp32:esp32 --port COM6 --upload firmware/esp32-provisioning

# Then flash the application firmware over it; credentials survive in their own partition
arduino-cli compile --fqbn esp32:esp32:esp32 --libraries firmware firmware/SIoT/examples/Temperature
```

See [`firmware/README.md`](firmware/README.md) for details.

## Status

Built and working end to end: accounts, the encrypted vault with rollback detection, device
provisioning over Web Serial, signed and encrypted uploads from real ESP32 hardware, client-side
decryption with gap detection, per-device dashboards from declared schemas, read-only grants
between devices, secret rotation, and lossless export.

| Phase | |
|---|---|
| 0. Project skeleton | ✅ |
| 1. Client-side crypto primitives | ✅ |
| 2. Signup and login | ✅ |
| 3. Vault storage | ✅ |
| 4. Device identity and provisioning | ✅ |
| 5. ESP32 library and wire protocol | ✅ |
| 6. Server-side record validation | ✅ |
| 7. Dashboard and schemas | ✅ (one item open) |
| 8. Inter-device grants | 🚧 device-side consumption pending |
| 9. Hardening (plugin sandbox, cert rotation, flash encryption) | ⏳ not started |
| 10. Device notifications | 🚧 in progress |
| 11. Device commands (dashboard to device) | 🚧 in progress |
| 12. Client verification extension | ⏳ not started |

Known gaps, stated plainly: `backend/` has no automated test suite yet (it has been verified by
hand against a running server), the React screens are not covered by tests, the client
verification extension does not exist yet (so a malicious server could swap the client code),
and there is no
account recovery in v1. Forgetting the password loses the account, by design, until a recovery
mechanism exists that is no weaker than the password itself.

## Contributing

Read [`CLAUDE.md`](CLAUDE.md) for how work is done here and the decisions already made, and
[`ROADMAP.md`](ROADMAP.md) for what comes next. Conventional commits. Comments explain *why*,
especially where the reason is a security property. And the one rule above applies to every
pull request.
