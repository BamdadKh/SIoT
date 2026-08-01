# SIOT — Implementation Roadmap

Granular, ordered task list derived from `SIOT_Design_Document.md`. Check items off as you go. Each phase should leave you with something runnable/testable before moving to the next.

---

## Phase 0 — Project Skeleton

### 0.1 Repo & tooling
- [x] Decide monorepo layout — kept the existing `backend/`, `frontend/`, `firmware/`, `extension/`; provisioning will live under `frontend/`
- [x] Set up root `package.json` workspaces (or separate repos, pick one) — **decided: neither.** One repo, `backend/` is a standalone npm package, frontend has no build step yet
- [ ] Add `.editorconfig`, shared `tsconfig.base.json`, ESLint + Prettier config — `.editorconfig` and `.prettierrc.json` done; ESLint deferred, `tsconfig.base.json` pointless while there's only one TS package
- [x] Set up `.env.example` for server (DB URL, Redis URL, ports)

### 0.2 Backend skeleton
- [x] `npm init` server package, add TypeScript, Fastify
- [x] Add `@fastify/type-provider-typebox` or zod for JSON schema validation — TypeBox
- [x] Create basic `server.ts` entrypoint with health-check route (`GET /health`) — `src/index.ts` + `src/app.ts`; health reports per-dependency status and 503s when degraded
- [x] Add PostgreSQL connection (pg or a lightweight query builder — decide, don't over-engineer with a full ORM yet) — raw `pg` with a thin wrapper
- [x] Add Redis connection (ioredis)
- [x] Write Docker Compose for local Postgres + Redis — Postgres on host port **5433** to avoid a native install already on 5432
- [x] Verify server boots and connects to both

### 0.3 Database schema (empty tables first)
- [x] `users` table: id, username, salt, login_key_hash, wrapped_vault_key, vault_version, created_at
- [x] `devices` table: device_id, owner_user_id, sign_pub, last_seq, created_at
- [x] `records` table: id, device_id, seq, nonce, ciphertext, sig, created_at
- [x] `vault_blobs` table (or column on users) for encrypted vault contents — separate table; `vault_version` stays on `users` only so the two can't drift
- [x] Write a migration tool setup (node-pg-migrate or similar) — first migration creates these tables

### 0.4 Frontend skeleton
> Deferred deliberately: the real client is React, but until there's an API worth calling
> the frontend is a single plain-HTML test console (`frontend/index.html`), served by the
> backend in dev so it's same-origin. Revisit when Phase 2 needs real forms and routing.

- [ ] Scaffold React app (Vite)
- [ ] Add routing (login, signup, dashboard placeholder pages)
- [ ] Add a basic layout shell (nav, empty content area)
- [x] Confirm it can hit `GET /health` on the backend

### 0.5 Local HTTPS
- [x] Generate self-signed cert for local dev — `npm run gen-cert`; SANs cover `localhost` and every LAN IP, so a device can reach it by address and still validate. Also prints the SPKI pin for Phase 5.6
- [x] Configure Fastify to serve HTTPS locally — `TLS_ENABLED` defaults on; missing cert is a hard startup failure, never a silent downgrade
- [x] Confirm frontend dev server proxies to HTTPS backend without cert errors (or accept dev-only self-signed warning) — no proxy needed, the backend serves the test console itself; browsers warn once on the self-signed cert
- [x] Retire the plaintext HTTP spike path once this works — no HTTP listener at all, and `POST /button` is gone. The ESP32 spike sketch is now dead against this server, as intended
- [x] HSTS header, production only (not dev — it is host-scoped and would pin all of `localhost` to HTTPS)

---

## Phase 1 — Client-Side Crypto Primitives

> Lives in `frontend/lib/crypto/` as plain ESM — deliberately *not* in `backend/`, so the
> server cannot import the code that produces `kek`/`vault_key` even by accident. Tested with
> `node --test` from `frontend/` (`npm test`); Node's Web Crypto is the same API the browser
> exposes, so the tests exercise the exact modules the client loads. An import map in
> `index.html` resolves the bare `hash-wasm` specifier in the browser until Vite lands.

### 1.1 Argon2id in the browser
- [x] Pick a vetted Argon2id WASM library (e.g. `hash-wasm` or `argon2-browser`) — **`hash-wasm` 4.12.0**: MIT, reference Argon2 C compiled to WASM, WASM inlined as base64 (no second fetch, no build step), same package works in Node and browser. `argon2-browser` rejected — last release 2022
- [x] Write a thin wrapper function `deriveMasterKey(password, salt) -> 32B key` with the exact params (m=64MiB, t=3, p=1) — `lib/crypto/argon2.js`; params frozen in `ARGON2_PARAMS` and treated as a wire format, since changing one locks every existing user out
- [x] Unit test: same password+salt always produces same output; different salt produces different output — plus a pinned known-answer vector, so a silent param/library drift fails the suite

### 1.2 HKDF derivation
- [x] Implement `hkdfSha256(masterKey, info) -> 32B` using Web Crypto's `HKDF` support — empty HKDF salt, which RFC 5869 allows when the IKM is already uniform (it is: Argon2id output). The per-user randomness lives in the Argon2id salt one step up
- [x] Derive `login_key` with info=`"siot/auth/v1"`
- [x] Derive `kek` with info=`"siot/kek/v1"`
- [x] Unit test: `login_key` and `kek` are different even though derived from the same `master_key`
- [x] Added `deriveAccountKeys(password, salt)` — the whole path in one call, zeroing the master_key after use so no caller has to hold it

### 1.3 vault_key wrapping
- [x] Generate random `vault_key` (32B CSPRNG) at signup time only
- [x] Implement AES-256-GCM wrap/unwrap functions (`wrapKey(vault_key, kek)`, `unwrapKey(wrapped, kek)`) — named `wrapVaultKey`/`unwrapVaultKey`; blob is `iv(12) || ct(32) || tag(16)` = 60B, AAD `"siot/vault-key-wrap/v1"` (not bound to username, which must stay changeable). Random IV is safe here and only here — a `kek` wraps a handful of times ever, unlike a device emitting records forever (Section 7.2)
- [x] Unit test: wrap then unwrap round-trips correctly
- [x] Unit test: unwrap fails loudly with wrong `kek` — also on a tampered blob and on a same-`kek` blob carrying a foreign AAD

### 1.4 Salt & CSPRNG helpers
- [x] Helper to generate 128-bit CSPRNG salt at signup — `generateSalt()`; `lib/crypto/random.js` throws at import time if `getRandomValues` is missing rather than degrading
- [x] Confirm `crypto.getRandomValues` used everywhere random bytes are needed (never `Math.random`) — enforced by a test that greps `lib/` for `Math.random`, not just by review
- [x] `toBase64Url`/`fromBase64Url` in `lib/crypto/encoding.js` — needed before Phase 2 can put any of this on the wire

---

## Phase 2 — Signup & Login Flow

### 2.1 Signup — client
- [x] Signup form UI (username, password, confirm password) — a panel in the plain-HTML test console, not React; 0.4 is still deferred
- [x] On submit: generate salt, derive master_key/login_key/kek, generate vault_key, wrap it
- [x] POST `/signup` with `{ username, salt, login_key, wrapped_vault_key }`
- [x] Clear password from memory/variables as soon as derivation is done (don't hold it longer than needed) — inputs are cleared and every derived key is zeroed once the body is built. The password *string* itself cannot be wiped: JS strings are immutable and interned. That is a platform limit, not something to paper over

### 2.2 Signup — server
- [x] Route `POST /signup`: validate input shape (JSON schema) — fixed-length base64url patterns, so a wrong-sized blob is a 400 before any handler runs. Also flipped Fastify's Ajv to `removeAdditional: false` globally: silently *stripping* an unexpected field is the wrong default when the field might be key material
- [x] Check username uniqueness — via the unique index, not a pre-`SELECT`: a check-then-insert is a race two simultaneous signups both pass
- [x] Server-side Argon2id hash of `login_key` (separate salt, server-generated) — `@node-rs/argon2`, m=19 MiB/t=2/p=1, salt generated internally per hash. Lighter than the client's m=64 MiB deliberately: the input here is already a 256-bit HKDF output, so cost buys nothing against brute force, and this runs on every login attempt
- [x] Insert user row: username, salt, login_key_hash, wrapped_vault_key, vault_version=0 — username normalised to lowercase, ASCII-only charset so homoglyphs can't make two rows that look identical
- [x] Return success (no session yet — require explicit login) — 201 `{ username }`, echoing the normalised form. Duplicate → 409, which does leak that the name exists; unavoidable for any signup form that refuses duplicates, and 2.3 is where the enumeration defence actually lives

### 2.3 Salt lookup with anti-enumeration
- [x] Route `GET /salt?username=` on server — `cache-control: no-store`, since a cached decoy that later disagrees with a real salt leaks the moment the account is created
- [x] Real user → return stored salt
- [x] Unknown user → return `HMAC(server_secret, username)` truncated/formatted to look like a real salt — new required `SERVER_SECRET` env var (base64url, ≥32B, boot fails if short). Both branches run the same lookup *and* the same HMAC in the same order; the decoy is computed even when discarded, so no branch depends on existence
- [ ] Test: response shape/timing is indistinguishable for real vs. fake usernames (at least structurally)

> Verified by hand, not by an automated test, and the checkbox stays open until it is one.
> A throwaway probe over 200 interleaved requests found no difference: identical status,
> body keys, `content-length` (33), `cache-control`, and 16-byte salt, with p50 0.92 ms for
> both real and unknown names. Automating it needs a backend test harness that boots the app
> against a live Postgres — `backend/` has no test setup at all yet, and picking one is a
> decision for its own step rather than something to smuggle in here.

### 2.4 Login — client
- [x] Login form UI — another panel in the test console; 0.4 is still deferred
- [x] Fetch salt via `/salt`, derive login_key locally
- [x] POST `/login` with `{ username, login_key }`
- [x] On success, store session cookie (browser handles automatically via `HttpOnly`), keep `kek`/`vault_key` in memory only (never persisted to localStorage) — `kek` is held in a module-scoped variable for 2.7 to unwrap with, and zeroed if a later login fails. The panel asserts `document.cookie` cannot see the session, so a regression in the cookie flags shows up as a red pill rather than silently

### 2.5 Login — server
- [x] Route `POST /login`: rate limit by account + by source IP (pick a limiter — e.g. `@fastify/rate-limit` or custom Redis counter) — **custom Redis counter** (`src/lib/rate-limit.ts`). `@fastify/rate-limit` budgets *requests*; what is needed here is a failure ladder that only advances on a wrong answer and survives a restart
- [x] Exponential backoff tracking (store attempt count + last attempt time in Redis per account) — counter and lock are separate keys, so serving one wait does not reset the ladder. Account: 5 free, then 2s doubling to a 15 min cap. Address: 30 free, 1s doubling to the same cap, and *not* cleared on success — one account of their own would otherwise let a stuffer reset the sweep limit at will
- [x] Constant-time comparison of `Argon2id(login_key)` against stored hash — Argon2's own `verify`, never `===`
- [x] On match: create session in Redis (256-bit CSPRNG id, store `Argon2id(session_id)` or SHA-256 hash of it, not raw) — SHA-256: the id is already 256 bits of CSPRNG, so a slow hash buys nothing and would be a DoS surface on every authenticated request
- [x] Set cookie `HttpOnly; Secure; SameSite=Strict` with absolute TTL + idle timeout — idle 30 min as the Redis TTL, absolute 12 h stored on the record; `Secure` tracks `TLS_ENABLED` so the unsupported plaintext hatch fails loudly rather than silently dropping the cookie
- [x] On mismatch: generic error, no distinction between "no such user" and "wrong password"
- [x] Added: unknown usernames verify against a decoy hash, so the *timing* does not distinguish them either — measured 22 ms unknown vs 21 ms wrong-password. Without it the two differ by ~20 ms and login becomes the account oracle `GET /salt` was hardened against

> **Deviation worth knowing about.** `@node-rs/argon2` 2.0.2 accepts a `Uint8Array`
> password on `hash` but decodes it as UTF-8 on `verify`, so raw `login_key` bytes hash
> fine and then always fail to verify. Both calls now go through one `argon2Input()`
> helper that base64s the key first — injective over a fixed 32 bytes, so no entropy is
> lost. **Any account created before this change cannot log in**; the stored hash was
> computed over different input. Dev data only, so they were left alone rather than
> migrated.

### 2.6 Session middleware & logout
- [x] Fastify hook: extract session cookie, hash it, look up in Redis, attach `userId` to request — attaches `req.session = { userId, idHash }`; the hook also slides the idle TTL, clamped so it can never push a session past its absolute deadline
- [x] Reject/401 requests with missing or invalid session — one message for absent, forged, idled-out and revoked alike, and a dead cookie is cleared so the browser stops replaying it
- [x] Route `POST /logout`: delete the one Redis session entry
- [x] Route `POST /logout-everywhere`: delete all Redis entries for that user
- [x] Test full loop: signup → login → authenticated request → logout → request now rejected — plus three concurrent sessions killed from one of them, verified down to Redis holding no keys for that user afterwards
- [x] Added `GET /session` → `{ username }`. Not in the plan, but every client needs one call on page load to choose between the dashboard and the login form, and without it 2.6 has nothing to authenticate

> **Deviation: the hook is scoped, not global-with-an-allowlist.** Authenticated routes are
> registered inside a Fastify encapsulation scope that owns the `onRequest` hook, so a route
> is protected by *where it is registered*. An allowlist fails open when someone forgets to
> add a path; this fails closed. Phase 6's `POST /records` is device-authenticated by
> signature rather than by session, so it will need its own scope rather than this one.

### 2.7 vault_key retrieval after login
- [x] Route `GET /vault-key` (authenticated): returns `wrapped_vault_key` — kept separate from the `/login` response on purpose, so a client with a live session but no `kek` (a reload) can tell the two states apart
- [x] Client unwraps it locally with `kek` to get `vault_key`, holds in memory — in the same closure as `kek`, which is why the panel is wired inside the login script rather than its own block
- [x] Test: server response alone is useless without `kek` — the 60-byte blob refuses a stranger's `kek`, the `login_key` the server actually stores, a `kek` with one bit flipped, and the stored salt run against a wrong password guess. Confirmed in the browser too: after a reload `GET /session` still returns 200 while the vault panel has nothing to open the blob with

> Wire-format byte lengths moved to `src/lib/wire-format.ts` — `/signup` and `/vault-key`
> both encode `wrapped_vault_key`, and two copies of "60" drifting apart is how a length
> check ends up validating nothing.

---

## Phase 3 — Vault Storage

### 3.1 Vault write path
- [ ] Decide vault_record granularity for v1 (single blob is simplest — pick it, revisit later per Section 15.6)
- [ ] Client: encrypt vault contents (JSON) under `vault_key` with AES-256-GCM, include `vault_version` in AAD/plaintext
- [ ] Route `PUT /vault` (authenticated): store ciphertext + bump `vault_version`
- [ ] Server rejects write if client-sent version isn't `current+1` (basic conflict guard)

### 3.2 Vault read path
- [ ] Route `GET /vault` (authenticated): return ciphertext + version
- [ ] Client decrypts with in-memory `vault_key`
- [ ] Client caches highest seen `vault_version` in IndexedDB
- [ ] Client refuses/warns if server returns a version lower than cached (rollback detection)
- [ ] Test: manually roll back a vault row in the DB, confirm client surfaces a loud warning instead of silently accepting

### 3.3 Password change flow
- [ ] Client: derive new `master_key`/`kek` from new password, re-wrap existing `vault_key` (not vault contents)
- [ ] Route `POST /change-password`: update salt (if rotated), login_key_hash, wrapped_vault_key
- [ ] Test: old password no longer logs in, new password does, vault contents unchanged/still decryptable

---

## Phase 4 — Device Identity & Provisioning

### 4.1 Device key derivation (browser side)
- [ ] Generate `DEVICE_SECRET` (32B CSPRNG) in browser
- [ ] Derive `device_data_key` via HKDF info=`"siot/device/data/v1"`
- [ ] Derive `ed25519_seed` via HKDF info=`"siot/device/sign/v1"`, derive keypair from it
- [ ] Generate `DEVICE_ID` (128-bit random)
- [ ] Unit test: deterministic derivation from same `DEVICE_SECRET` reproduces same keys

### 4.2 Device registration — server
- [ ] Table already has `devices` (from 0.3) — confirm columns match: device_id, sign_pub, owner_user_id
- [ ] Route `POST /devices/register` (authenticated): `{ device_id, sign_pub }`, enforce `device_id` uniqueness
- [ ] Reject if `device_id` already exists

### 4.3 Device secret storage in vault
- [ ] Client: encrypt `DEVICE_SECRET` under `vault_key`, add entry to vault's device list
- [ ] Re-save vault via existing `PUT /vault` path (bump version)

### 4.4 Web Serial provisioning tool — UI
- [ ] Basic page: "Connect device" button using Web Serial API (`navigator.serial.requestPort`)
- [ ] Handle browser support check (Web Serial is Chromium-only — surface a clear message otherwise)
- [ ] UI flow: select vault device record → connect to board → write

### 4.5 Web Serial provisioning tool — NVS write protocol
- [ ] Define simple serial command protocol for the tool ↔ ESP32 bootstrap sketch (e.g. `READ_ID`, `WRITE_CREDS`)
- [ ] Write a minimal "provisioning listener" Arduino sketch that just handles NVS read/write over serial (separate from application firmware)
- [ ] Implement read-back: tool reads existing `DEVICE_ID` from NVS before writing
- [ ] Implement overwrite protection logic: no ID → proceed; matching ID → proceed; different ID → refuse with warning
- [ ] Implement actual write of `DEVICE_ID` + `DEVICE_SECRET` to dedicated NVS partition
- [ ] Test round-trip on a real ESP32: provision, power cycle, re-read confirms values persisted

---

## Phase 5 — ESP32 Library & Wire Protocol

### 5.1 Library skeleton
- [ ] New Arduino/PlatformIO library project (`SIOT` lib) separate from example sketches
- [ ] NVS read helpers for `DEVICE_ID` / `DEVICE_SECRET` from the dedicated partition
- [ ] Key derivation on-device: HKDF-SHA256 (need a small C++ implementation or existing lib — mbedTLS has primitives)
- [ ] Derive `device_data_key` and `ed25519_seed` on boot

### 5.2 Sequence counters
- [ ] Persist `boot_epoch` in NVS, increment once on boot before any record
- [ ] Track `msg_counter` in RAM, reset to 0 each boot, increment per record
- [ ] Compose `seq = (boot_epoch << 32) | msg_counter`
- [ ] Test: power-cycle device repeatedly, confirm `boot_epoch` strictly increases and never repeats

### 5.3 Nonce & AEAD
- [ ] Build nonce as `0x00000000 || seq` (12 bytes)
- [ ] Implement AES-256-GCM encrypt using ESP32 hardware acceleration (mbedTLS)
- [ ] Build AAD: `version(1B) || DEVICE_ID(16B) || record_type(1B) || seq(8B)`
- [ ] Unit test (on-device or host-side mock): encrypt/decrypt round-trip with known test vectors

### 5.4 Signing
- [ ] Implement Ed25519 signing (mbedTLS or a small Ed25519 lib) over `AAD || nonce || ciphertext`
- [ ] Unit test: signature verifies with the derived public key

### 5.5 CBOR payload
- [ ] Pick a CBOR library for the readings payload (`t`, `r` fields)
- [ ] Define how the device owner's sketch supplies readings (simple API: `siot.addReading(name, value)`)

### 5.6 Upload
- [ ] HTTPS POST client on ESP32 (WiFiClientSecure) with SPKI pin configured
- [ ] Implement `POST /records` body: `{ device_id, seq, nonce, ciphertext, sig }`
- [ ] Handle upload failure/retry (network drop, don't lose readings silently — decide buffering strategy, keep it simple for v1)
- [ ] End-to-end test against local dev server: one real reading, uploaded, verified

### 5.7 Example sketch
- [ ] Minimal example: init library with NVS creds, define one reading (e.g. temperature), loop + upload every N seconds
- [ ] Document in README how a user writes their own sketch against the library

---

## Phase 6 — Server-Side Record Validation

### 6.1 Records endpoint
- [ ] Route `POST /records` (device-authenticated via signature, not session)
- [ ] Look up `device_id` → fetch `sign_pub`
- [ ] Check 1: `Ed25519_verify(sign_pub, AAD||nonce||ciphertext, sig)`
- [ ] Check 2: `seq > last_seq[device_id]`
- [ ] Check 3: nonce matches `0x00000000 || seq`
- [ ] On pass: store blob in `records` table, update `last_seq`
- [ ] On fail: reject with 4xx, no partial writes

### 6.2 Records read endpoint
- [ ] Route `GET /devices/:id/records` (authenticated, owner or grant-holder only — grants come in Phase 8, stub owner-only check for now)
- [ ] Return raw ciphertext blobs + metadata (seq, nonce, timestamp) for client-side decryption
- [ ] Pagination / range query by seq or time

### 6.3 Client-side decrypt & display
- [ ] Fetch device's `device_data_key` from decrypted vault
- [ ] Decrypt records client-side, verify AAD matches expected device/type
- [ ] Detect sequence gaps within a `boot_epoch` and surface as "possible missing data" in UI (not an error, just a signal)

---

## Phase 7 — Dashboard & Schemas

### 7.1 Schema definition
- [ ] Define schema JSON shape (field name, type, widget hint) for a device
- [ ] Client: form/UI for a device owner to declare a schema at pairing time
- [ ] Store schema encrypted in vault alongside device secret

### 7.2 Schema validation (untrusted input)
- [ ] Write strict allowlist validator for schema field types before ever rendering
- [ ] Reject/sanitize anything outside the allowlist
- [ ] Confirm no path renders raw HTML or uses `dangerouslySetInnerHTML` from schema data
- [ ] Test with a deliberately malicious schema payload (script tags, unexpected types) — confirm it's inert

### 7.3 Widget rendering
- [ ] Build `Graph` widget (time series from decrypted records)
- [ ] Build `Gauge` widget
- [ ] Build `Toggle` widget (for actions — decide how write-back to device works, likely out of scope for v1 read path)
- [ ] Auto-render dashboard from schema + decrypted records, no per-device hardcoding

### 7.4 Layout
- [ ] Drag-and-drop layout library integration (e.g. `react-grid-layout`)
- [ ] Persist layout as part of vault data (encrypted)

---

## Phase 8 — Inter-Device Grants

### 8.1 Grant creation — client
- [ ] UI: pick Device A (granted) and Device B (source), with an explicit warning that this grants access to B's full history, past and future, and that revocation only affects future data
- [ ] Decrypt `device_B_data_key` from vault
- [ ] Re-encrypt it under `device_A_data_key` with AAD `"grant/v1" || DEVICE_ID_A || DEVICE_ID_B`
- [ ] Upload grant blob

### 8.2 Grant storage — server
- [ ] `grants` table: id, device_a_id, device_b_id, ciphertext, created_at
- [ ] Route `POST /grants` (authenticated, must own both devices or have rights — decide policy)
- [ ] Route `GET /devices/:id/grants` for a device to fetch grants targeting it

### 8.3 Grant consumption — device
- [ ] Device A firmware: fetch grants where it's the recipient, decrypt with its own `device_data_key`
- [ ] Use resulting `device_B_data_key` to decrypt B's records fetched from server
- [ ] Test: A can read B's historical + live records without any always-on relay

### 8.4 Revocation flow
- [ ] UI messaging: "revoke" = rotate B's `DEVICE_SECRET` via re-provisioning, old data stays readable by A forever
- [ ] Re-provisioning flow reuses Phase 4 tool with a new `DEVICE_SECRET`, updates vault entry, old grants naturally stop covering new data

---

## Phase 9 — Hardening & Extras (post-MVP)

### 9.1 Browser extension
- [ ] Minimal (~100 line) extension skeleton, no build step
- [ ] On-install hash storage flow
- [ ] On-update: fetch from GitHub, hash, diff, require approval
- [ ] Decide distribution: self-hosted vs Web Store (Section 15.3)
- [ ] Investigate CSP + SRI approach to cover MV3's lack of blocking `webRequest`

### 9.2 Widget plugin sandbox
- [ ] Sandboxed iframe/Worker execution model
- [ ] `postMessage`-only communication contract
- [ ] Confirm plugin never receives raw key material, only decrypted display values

### 9.3 Certificate rotation plan
- [ ] Decide: backup pin, intermediate pinning, or accepted re-provisioning (Section 15.1)
- [ ] Implement chosen approach in firmware library

### 9.4 Metadata mitigation (optional per device class)
- [ ] Evaluate fixed-interval + padded dummy records for privacy-sensitive device types
- [ ] Implement opt-in if any device class warrants it

### 9.5 Flash encryption documentation
- [ ] Write hardening guide: enabling ESP32 flash encryption + secure boot fuses
- [ ] Clearly document irreversibility

---

## Suggested Starting Point

Work top-to-bottom through **Phase 0 → Phase 1 → Phase 2**. That gets you: a real backend/frontend skeleton, real client-side crypto, and a working signup/login flow with genuine zero-knowledge properties — testable end-to-end before any device or vault-content work begins.
