# SIoT Implementation Roadmap

Granular, ordered task list derived from `SIoT_Design_Document.md`. Check items off as you go. Each phase should leave you with something runnable/testable before moving to the next.

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
> Deferred through Phases 1 and 2, then picked up once there was an API worth calling.
> The plain-HTML test console (`frontend/index.html`) **stays** — it is how the crypto
> primitives get exercised directly, and the backend still serves it in dev.

- [x] Scaffold React app (Vite) — lives in `frontend/app/`, with `vite.config.js` at
      `frontend/` (`root: 'app'`). One npm package, still no workspaces. The dev server
      runs HTTPS off the backend's own cert and proxies the API paths to `:3030`; that is
      not optional, since the session cookie is `Secure; SameSite=Strict` and a plaintext
      dev server drops it silently
- [x] Add routing (login, signup, dashboard placeholder pages) — a ~40 line
      `lib/router.jsx`, not React Router. Four screens: sign in, sign up, unlock, devices
- [x] Add a basic layout shell (nav, empty content area) — `TopBar` + `.page`; no nav
      links, because there is exactly one page until Phase 4 adds pairing
- [x] Confirm it can hit `GET /health` on the backend

> **The screen the plan did not anticipate: `Unlock`.** Which screen shows is decided by
> two independent facts, not one — is there a session (the cookie, survives a reload) and
> is the vault open (`kek` in memory, does not). Every refresh lands in the pair
> (session, locked), so it gets a real screen rather than a redirect to sign-in. It never
> calls `/login`: the password is checked by whether the derived `kek` opens the 60-byte
> blob, entirely client-side, and a wrong guess is a GCM failure the server never hears
> about.

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
- [x] Decide vault_record granularity for v1 (single blob is simplest — pick it, revisit later per Section 15.6) — **single blob**, one row per user in `vault_blobs`, which is what 0.3 already built for
- [x] Client: encrypt vault contents (JSON) under `vault_key` with AES-256-GCM, include `vault_version` in AAD/plaintext — `frontend/lib/crypto/vault.js`; **both**, not either. AAD `"siot/vault/v1" || version(8B BE)` means a blob served under a version it was not written at cannot be opened at all; the plaintext envelope `{ version, contents }` carries the same number independently, so a disagreement is a named error rather than a bare GCM failure
- [x] Route `PUT /vault` (authenticated): store ciphertext + bump `vault_version`
- [x] Server rejects write if client-sent version isn't `current+1` (basic conflict guard) — as a single-statement compare-and-swap (`where vault_version = $2 - 1`), not a read-then-write: two tabs saving at once must not both pass, and a read-then-write lets them. The 409 names the current version in its message

### 3.2 Vault read path
- [x] Route `GET /vault` (authenticated): return ciphertext + version — `cache-control: no-store`, for freshness rather than confidentiality: the blob is opaque to any cache it passes through, but a *stale* one is exactly the rollback the version counter exists to make loud
- [x] Client decrypts with in-memory `vault_key` — exercised in the test console's vault panel, which lives in the same closure as `kek`/`vault_key`, and now also on `Devices` mount in the real React client
- [x] Client caches highest seen `vault_version` in IndexedDB: `frontend/app/src/lib/vault-version-store.js`, one object store keyed **by username**, not one global number. First shipped keyed globally per origin; caught by hand-testing before this was ticked off, because a second account signed into on the same browser reported the first account's higher version as a rollback of its own, unrelated counter. Re-keyed per-account and reverified
- [x] Client refuses/warns if server returns a version lower than cached (rollback detection): lives in `Devices.jsx` rather than a new screen, since that is the one place unlocked and vault-open overlap. It runs before the empty-devices state renders and shows a rust-styled panel (design tokens: rust is reserved for a vault the client will not open) naming both versions and telling the person not to make changes until it is resolved
- [x] Test: manually roll back a vault row in the DB, confirm client surfaces a loud warning instead of silently accepting. Verified by hand end-to-end: signed up, wrote vault v1 then v2 through the test console (cached high-water mark advances to 2 in the real client), `update users set vault_version = 1` directly in Postgres, reloaded, and got the rust "This vault went backwards" panel citing server version 1 against cached version 2 with nothing decrypted. Restoring the true version 2 by hand cleared the warning on the next reload. No automated test; `backend/` still has no test harness (same gap 2.3 already flagged)

> **A vault that has never been written is `{ vault_version: 0, ciphertext: null }`, not a 404.**
> A 404 is a second shape the client has to branch on, and the branch that skips the
> monotonicity check is precisely the one a hostile server would want to steer it into.
> "No vault here" and "here is last week's vault" have to be compared on the same scale.

Phase 3.2 is done. Phase 3 is not: 3.3 (password change) is next.

### 3.3 Password change flow
- [x] Client: derive new `master_key`/`kek` from new password, re-wrap existing `vault_key` (not vault contents), in `ChangePassword.jsx`, reached from a link on `Devices`. `vault_key` comes straight from the keyring, already unlocked to get here; only its wrapping moves. The screen itself is a `Plate` (matching Sign in and Create account), not the `TopBar` shell, since it is a focused single-purpose action, not the main app view; the first pass used `TopBar` and was corrected after hand-testing showed it off-centre and inconsistent. Later change: the link is no longer loose in the top bar. Change password and sign out are both items in an `AccountMenu` under the username, which is the only control in the bar and is olive to say so
- [x] Route `POST /change-password`: update salt (if rotated), login_key_hash, wrapped_vault_key. Salt always rotates; there is no case where keeping the old one is right. Deviation from the item as written: the body also carries `current_login_key`, checked against the stored hash before anything is written. Without it, a stolen session cookie alone (no `kek`, no XSS) could overwrite `wrapped_vault_key` with garbage and permanently orphan the real `vault_key`, since the server has no way to check that a new wrapped blob still decrypts to the same key. Wrong current password is a 403, throttled by its own Redis bucket (`changePasswordThrottle`, keyed by user id) rather than sharing `/login`'s, since getting to this endpoint at all already requires a live session
- [x] Test: old password no longer logs in, new password does, vault contents unchanged/still decryptable. Verified by hand: signed up, changed password, old password rejected at `/sign-in`, new password logs in and unlocks the same vault with no rollback warning. No automated test; same gap as 2.3 and the rest of `backend/`

> Caught during hand-testing, not code review: the client route and the server route were both
> `/change-password`, so a full page reload on that URL got proxied straight to the backend
> (`GET`, 404) instead of falling through to the SPA shell, the exact collision `/sign-in` vs
> `/login` and `/sign-up` vs `/signup` already avoid elsewhere. The client-visible path is
> `/password`; the server route stays `POST /change-password`. Also needed adding to `API_PATHS`
> in `vite.config.js`, the gotcha the frontend README already names.

---

## Phase 4 — Device Identity & Provisioning

### 4.1 Device key derivation (browser side)
- [x] Generate `DEVICE_SECRET` (32B CSPRNG) in browser — `frontend/lib/crypto/device.js`
- [x] Derive `device_data_key` via HKDF info=`"siot/device/data/v1"` — added to `HKDF_INFO` alongside the two account labels, with a note that these two differ from those in kind: firmware computes them too, so they are a wire format shared with every port rather than an internal name
- [x] Derive `ed25519_seed` via HKDF info=`"siot/device/sign/v1"`, derive keypair from it — `frontend/lib/crypto/ed25519.js`. Web Crypto has no seeded `generateKey`, so the seed goes in through the fixed 16-byte PKCS#8 preamble every Ed25519 private key shares, and the public half comes back out through a JWK export (the only route Web Crypto offers from private key to public bytes). No `@noble/ed25519` or `tweetnacl`, same reasoning as `backend/src/lib/ed25519.ts`: the platform already ships an audited implementation
- [x] Generate `DEVICE_ID` (128-bit random)
- [x] Unit test: deterministic derivation from same `DEVICE_SECRET` reproduces same keys — plus RFC 8032 known-answer vectors pinning both the public key and a signature. The 16 preamble bytes are hand-written, and a wrong one would still import cleanly and produce a confident, useless key; the signature vector separately pins that this is pure Ed25519 rather than a prehashed or context variant, which would derive the identical public key and then fail verification at `POST /records` with nothing to point at. One test signs and verifies through Node's `crypto.verify` with a JWK-reconstructed key, which is byte for byte what the server does, so it asserts the real property: what the browser derives is what the server will accept

> **`deriveDeviceKeys` returns the data key and the public key, and zeroes the signing
> seed.** A provisioning screen has no use for signing authority (design 5.1: that is what
> never leaves the device), and the seed is reproducible from `DEVICE_SECRET` by anyone who
> legitimately holds it. `ed25519Sign` is exported anyway, for `node --test` and for a
> stand-in script impersonating firmware that does not exist yet; nothing in `frontend/app/`
> imports it, and an app screen that did would be the bug.

### 4.2 Device registration — server
- [x] Table already has `devices` (from 0.3) — confirm columns match: device_id, sign_pub, owner_user_id
- [x] Route `POST /devices/register` (authenticated): `{ device_id, sign_pub }`, enforce `device_id` uniqueness — `src/routes/devices.ts`. Uniqueness comes from `device_id` being the primary key, not a pre-`SELECT`, same reasoning as the `/signup` username race
- [x] Reject if `device_id` already exists — 409, and it is a *global* uniqueness check (device_id is the PK across all owners), not per-owner; verified by hand that a second account attempting to register the first account's `device_id` also gets 409

> Done out of order and backend-only: 4.1 (browser-side key derivation) and 4.3 (vault device
> record) live in `frontend/lib/crypto/` and were deliberately skipped in this pass — the
> session's instruction was backend work only, no frontend touches. `POST /devices/register`
> was built and hand-verified with a throwaway script generating random `device_id`/`sign_pub`
> bytes directly, standing in for the client derivation 4.1 will eventually produce. No
> automated test; same gap as the rest of `backend/`.
>
> 4.1 has since landed, so the stand-in is retired: `generateDevice()` produces the real
> `device_id`/`sign_pub` this route accepts, and `test/ed25519.test.js` verifies a browser
> signature through the same JWK path `src/lib/ed25519.ts` verifies with.

### 4.3 Device record in the vault
- [x] Client: encrypt `DEVICE_SECRET` under `vault_key`, add entry to vault's device list — `frontend/lib/crypto/vault-document.js`. **Deviation: there is no second encryption.** The whole document is already sealed under `vault_key` by `encryptVault`, so a nested AES-GCM layer under the identical key would add a nonce to manage and no confidentiality at all. `DEVICE_SECRET` is *encrypted in the vault*, which is what design 5.2's table asks for. A separate per-record wrapping starts earning its keep at per-device granularity (design 15.6), where one record could be handed out without the rest of the document; v1 is one blob per user, so there is nothing to hand out
- [x] Include the user's **name** for the device in that entry (design 5.5) — the name lives in the vault and nowhere else; there is no `name` column on `devices` and adding one would be wrong. A test asserts the name does not appear in the sealed blob's bytes
- [x] Ask for the name during setup, before the device exists, so nothing is ever displayed as a bare `DEVICE_ID` — enforced at the data layer: `addDevice` takes the name as a required argument, so there is no way to write an unnamed entry and label it later
- [x] Rename is just a vault write — same `PUT /vault` path, same version bump, no new endpoint. `renameDevice` touches the name and nothing else, so it survives a re-provisioning (design 8.4) unchanged
- [x] Re-save vault via existing `PUT /vault` path (bump version) — `saveVault` in
      `app/src/lib/api.js`, called through `storeVault` in `app/src/lib/vault-store.js`.
      The read and the write are one module rather than two API calls a screen makes,
      because the rollback check from 3.2 has to sit on the read path and a second caller
      is exactly what forgets it: `loadVault` throws `VaultRollbackError` rather than
      returning a flag, so there is no branch to leave unwritten, only a `catch` to leave
      unhandled, which fails loudly on screen instead of quietly in the data. The
      high-water mark is raised only after the blob has actually opened at the version the
      server claimed; a version that arrived with a blob that will not decrypt is not
      evidence of anything and caching it would poison the cache against the real vault

> Superseded: the note that used to sit here said nothing called `PUT /vault` from the
> React client. `AddDevice` does now, which is what closed the item.

> Two design decisions this pass made that the item did not anticipate. **Every function
> returns a new document rather than mutating one**, because `PUT /vault` can lose its
> compare-and-swap and 409, and the caller then has to refetch and re-apply against the
> server's newer document; an in-place edit would have already corrupted the copy it is
> retrying from. And **reading drops entries it cannot parse instead of throwing**: the blob
> is authenticated, so a malformed record means a bug in some version of this client rather
> than tampering, and one bad entry must not make the other devices unreachable. The count
> comes back so a caller can say so rather than swallowing it.
>
> Device names are stripped of C0/C1 controls, the bidi overrides and the zero-width
> characters. Not an XSS defence (React escapes, and the vault is authenticated) but a
> display-integrity one: a right-to-left override can make one device's name render as
> another's, and a device list is exactly where "this is the sensor you think it is" has to
> hold.

### 4.4 Web Serial provisioning tool — UI
> **The supported path, and the only one the app walks a user through.** Chromium + ESP32 is a
> deliberate narrowing (design 5.3, 6.1): it is what keeps the secret out of the clipboard and
> out of source control, and it is the only way the overwrite check in 4.5 can exist at all.
> Other hardware is served by the published protocol plus 4.6, not by a second guided flow.

- [x] Basic page: "Connect device" button using Web Serial API (`navigator.serial.requestPort`) — `app/src/screens/AddDevice.jsx` at `/add-device`. The chooser is deliberately **not** filtered by USB vendor id: the filter would have to enumerate every bridge an ESP32 board might carry (CP2102, CH340, FTDI, the S-series' native USB) and a board missing from that list looks broken rather than unlisted. The `HELLO` handshake is the real check and it tests the thing that matters, which is whether the provisioning sketch is running
- [x] Handle browser support check (Web Serial is Chromium-only — surface a clear message that names the reveal path in 4.6 rather than dead-ending) — names Chromium explicitly rather than saying "unsupported browser". 4.6 does not exist yet, so the copy says the credentials route is coming rather than linking to nothing
- [x] Added: "Add it without one" as a *link* beside the primary button, not a button. It covers **two** cases, and the copy says both: no board to hand right now, and hardware that is not an ESP32 at all. The second is the larger one and is the whole of design 5.3's other half: the guided flow is deliberately one hardware target, and everything else is served by the published protocol (4.7) plus a reveal (4.6). Wording it as only "no board to hand" quietly told every non-ESP32 user this product was not for them. It stays a link rather than a button because it leaves a device half-set-up, so it should not sit where a stray click lands
- [x] UI flow: name the device → connect to board → write — three stages in that order, and **the board is checked before anything is minted**. A board that already belongs to another device therefore costs nothing to discover: no `DEVICE_ID` generated, no vault write, no registration. Doing it the other way round means every refusal burns an identity. One `<form>` dispatching on stage rather than a set of `onClick` buttons, so Enter in the name field does the obvious thing, and a submit fired by Enter still counts as the user gesture `requestPort` requires

> **The write order deviates from design 5.3, and it is about which half-completed state a
> person can be left holding.** 5.3 registers (step 2) before the vault write (step 3).
> Register first and let the vault write fail and the server holds a `DEVICE_ID` and a signing
> key whose `DEVICE_SECRET` only ever existed in that tab's memory: the id is burned and shows
> as an orphan (design 5.4) forever. Vault first and let registration fail and the secret is
> safely stored, the same id can be registered again, and the device list offers exactly that
> button. One order is recoverable and the other is not, so the vault write goes first.
>
> The board write is appended to that same chain, last, for the same reason. The vault is the
> only durable home this secret has: write the board first and lose the tab, and the secret
> exists on a board and nowhere else, happily encrypting records nothing in the world can open.
>
> The screen re-reads the vault immediately before writing rather than trusting what the list
> already had. A write built on a stale version is a 409, and a 409 here costs a freshly minted
> `DEVICE_SECRET` to recover from.
>
> The name is asked for first and is not optional, which is design 5.5 taken literally: there
> is no moment at which a device exists as a bare `DEVICE_ID` waiting to be labelled. `addDevice`
> in the crypto layer already enforces that, so the screen is a friendlier place to say it and
> not the only place it holds. The confirmation echoes the name read back out of the document,
> not the input, since the crypto layer normalises it.

### 4.5 Web Serial provisioning tool — NVS write protocol
- [x] Define simple serial command protocol for the tool ↔ ESP32 bootstrap sketch (e.g. `READ_ID`, `WRITE_CREDS`) — `SIOT HELLO` / `SIOT READ-ID` / `SIOT WRITE`, line-oriented ASCII at 115200, one response line per command. Specified in the sketch header and spoken from the other end by `app/src/lib/provisioning-protocol.js`. Both sides ignore anything not prefixed `SIOT `, because the port also carries ROM bootloader chatter and whatever a serial monitor left behind, and a "first line back" rule would resolve a command with noise
- [x] Write a minimal "provisioning listener" Arduino sketch that just handles NVS read/write over serial (separate from application firmware) — `firmware/esp32-provisioning/`. No WiFi, no network stack, no SIoT wire protocol. base64url hand-rolled rather than taken from the core's libb64, which does padded standard base64; the decoder rejects non-canonical trailing bits, without which several strings decode to the same 16 bytes and `DEVICE_ID` stops being a canonical form of itself
- [x] Implement read-back: tool reads existing `DEVICE_ID` from NVS before writing — and an NVS *error* on that read throws rather than reading as blank, which is the dangerous confusion: a failed read that returned "nothing there" would send the next step straight into overwriting whatever is on the board
- [x] Implement overwrite protection logic: no ID → proceed; matching ID → proceed; different ID → refuse with warning — the decision is in the tool, per design 5.4, because only this side has the vault and can tell whether an id on a board is one of the user's own devices; that difference is the whole content of the warning. **The board enforces it independently as a compare-and-swap**: `WRITE` carries the id the tool believes is there and the board refuses if that is not what it finds. Between the read and the write a user can unplug one board and plug in another, and a check computed for the first would otherwise be applied to the second. **Deviation from this item as written, added after the fact:** there *is* now an override, because "refuse forever" makes a board with a dead device on it permanently unusable, which is a real thing to be stuck with and no vault entry can rescue. It is shaped as an escape hatch and not a path, the same way revealing credentials is (design 5.3.1): the refusal is still the default state and still offers no submit at all; standing it down is a second deliberate click on a link that says what it does; and it does not stay stood down, since reconnecting or disconnecting is a different board and therefore a fresh decision. The compare-and-swap is untouched and still does the work: the override changes which button the *tool* is willing to show, never what the board will accept
- [x] Implement actual write of `DEVICE_ID` + `DEVICE_SECRET` to dedicated NVS partition — `partitions.csv`, a superset of the stock 4MB `default` table with `siot` inserted. A namespace in the stock `nvs` was rejected: the application owns that partition, `nvs_flash_erase()` and a misaimed `Preferences.clear()` wipe all of it, and a factory-reset routine is an ordinary thing for a sketch to have. The write reads both values back and compares in RAM before answering `OK`, so success means the bytes are in flash rather than that an API call returned
- [x] Test round-trip on a real ESP32: provision, power cycle, re-read confirms values persisted — done harder than the item asks. A throwaway PowerShell probe over COM6 covering 18 cases (handshake; blank board reads as `-`; write; read-back; a blank expectation going stale once an id is present; a wrong expectation refused *and storage confirmed unchanged after it*; re-provisioning the same id; rotating to a new one; short, non-alphabet and non-canonical values rejected; missing and extra arguments rejected; unknown command rejected). Then a **full recompile-and-upload followed by a hard reset**, after which `READ-ID` returned the same id: a stronger claim than a power cycle, since it is the one design 5.3 actually rests on

> **The browser transport is verified too.** `provisioning-protocol.js` has 22 `node --test`
> cases and the sketch has the 18-case hardware probe above; `web-serial.js` sits between them
> and can never have either, since `navigator.serial` has no shim worth trusting and the port
> chooser is a native dialog that needs a human. Closed by hand with a throwaway read-only page
> (`serial-check.html`, since deleted): handshake in 26 ms, then `READ-ID` twice returning the
> same id the hardware probe had left on the board. Twice on purpose, because a reader left
> holding a stolen chunk would show up on the second exchange and not the first.
>
> Still unverified: **`AddDevice`'s own write path end to end**, meaning mint, vault, register,
> board, in one run. It needs a signed-in session and an unlocked vault, which neither harness
> could provide, so it is a hand test rather than a gap in the code.
>
> One thing that page existed to catch, because it was a real bug and not a hypothetical: the
> obvious way to write the transport is to race `reader.read()` against a timeout inside each
> exchange, and it is quietly wrong. When the timeout wins the read is still outstanding, and it
> consumes the next chunk off the wire and drops it. That turns the handshake's retry loop, the
> thing that exists to wait out the boot chatter from the DTR/RTS auto-reset, into a way to lose
> the board's answer. It is now a single long-lived pump that owns every read, with callers
> waiting on the buffer it fills.

### 4.6 Reveal credentials — the escape hatch
> Not a second supported path and must not be shaped like one (design 5.3.1). It exists so
> somebody writing their own client for other hardware has something to provision it with;
> without it the published protocol is an invitation with no key attached. Everything below the
> credentials is identical, and the server cannot tell a conforming third-party client from the
> reference library — which is the point.

- [ ] "Reveal credentials" control on an existing device, never a step in setup
- [ ] Decrypt from the vault in the browser and show `DEVICE_ID` + `DEVICE_SECRET` as base64url, with a copy button
- [ ] Reveal on demand, do not stay revealed; never persist the plaintext outside the vault — not localStorage, not a downloaded file
- [ ] State the costs at the moment of revealing, not in docs: it is now in the clipboard and wherever it goes next, there is no overwrite protection (design 5.4), and storage on the target hardware is the porter's problem including surviving a firmware update
- [ ] Link to the protocol documentation (4.7) from here — a revealed secret with no spec beside it is the wrong half of the answer

### 4.7 Protocol documentation for third-party clients
> The other half of "one hardware target done properly". Section 7 of the design document is
> already the byte-level contract; this is packaging it as something someone can build against
> without reading the whole architecture.

- [ ] Write `docs/protocol.md`: HKDF labels, AEAD parameters, nonce construction, AAD layout, CBOR payload shape, signature input, and the three server checks
- [ ] Document the `POST /records` API surface: request shape, every rejection and what it means
- [ ] State the non-negotiables for a port: persisted `boot_epoch`, exact HKDF labels, no invented equivalents
- [ ] Publish known-answer test vectors — a port that cannot reproduce them is broken, and finding that out from a vector beats finding it out from a server rejection

### 4.8 Device list — names and liveness
- [x] Route `GET /devices` (authenticated): the metadata the server legitimately holds per device — `device_id`, `last_seq`, and when its newest record arrived. No names, because it has none — `src/routes/devices.ts`, scoped to `owner_user_id = req.session.userId`
- [x] Decide how last-seen is stored: `max(created_at)` over `records`, or a `last_seen_at` column on `devices` updated alongside `last_seq` in the Phase 6 insert. **Chosen: the column** (migration `1785626993678_devices-last-seen.js`) — `records` has no per-device covering index that makes `max()` cheap once a device has years of history, and `last_seq` already lives on `devices` for the identical reason. Nothing writes it yet; that lands with the Phase 6 insert, so every device currently reads back `last_seen_at: null`, which is correct until then
- [x] Client: join the server's list against the vault's device records by `DEVICE_ID`, so names come from the vault and liveness from the server — `app/src/lib/device-list.js`, called from `Devices.jsx` after one `Promise.all` over `loadVault` and `GET /devices`. The join key is `DEVICE_ID` and nothing else: names are not identifiers, are not unique, and two devices called "sensor" are the user's business rather than a constraint violation. Vault order is kept rather than the server's, since that is the order the person added them in and the server's (creation time) would silently disagree
- [x] Show **when it was last heard from**, not just a dot (design 5.6) — `app/src/lib/last-seen.js`. No threshold anywhere: a sensor that wakes hourly is healthy at 59 minutes and a doorbell is not, so a timestamp lets the person who chose the reporting interval be the one who judges it. Relative phrasing on the row, the exact timestamp in its `title`. A record dated in the future (a server clock running ahead) is named as that rather than rendered as "in 3 minutes", which would read like a schedule
- [x] Never phrase "offline" as a fact about the device: the client knows it has not received a record, not why. A withholding server is indistinguishable from a flat battery — held by a test that asserts the absence rather than by review: every gap from a minute to two and a half years produces a "Last record ..." sentence and none of them matches `offline|dead|down|unreachable|inactive`
- [x] Handle the two mismatch cases visibly: a device in the vault the server does not know, and a device the server reports that the vault has no record for (an orphan — see design 5.4) — three states, `PAIRED`/`UNREGISTERED`/`ORPHAN`, and the two mismatches are worded by what can be done about them rather than by severity. An unregistered device is recoverable (the secret is in the vault, the same id can be registered again) and gets a "Finish registering" button that re-derives `sign_pub` from the stored secret, since the public key always was derived rather than stored. An orphan is not recoverable at all: the `DEVICE_SECRET` is gone, so everything that device has uploaded or will upload is permanently unreadable, and it is styled rust, the token reserved for a vault that will not open, rather than `--alarm`, which is for something the person did or can retry

> `device-list.js` and `last-seen.js` deliberately contain no crypto and no React, so
> `node --test` covers them directly: the three join outcomes are tedious to reproduce by hand
> (an orphan needs a vault entry deleted out from under a registered device) and easy to get
> subtly wrong. 17 new cases, and the suite is 81, up from 65. That is still not a test of the
> screens; `Devices.jsx` itself is uncovered, same gap as the rest of the client.

### 4.9 Device management: rename, delete, and reclaiming the board

> **This is the exit 4.8 shipped without.** That item deliberately renders an orphan as
> permanently unreadable, which is true and honest, and then leaves it sitting in the list
> forever with records nothing can open consuming storage nothing can reclaim. An unregistered
> device has a "Finish registering" button; an orphan has no button at all. Delete is the one
> that belongs there.

> **A delete is two deletes and they cannot be one transaction.** The vault entry goes by
> `PUT /vault` and the server row by `DELETE /devices/:id`, and nothing can make those atomic.
> So the order is chosen the way 4.4 chose the write order: by which half-finished state a
> person can be left holding. **Server row first.** If the vault write then fails, the device
> reads as `UNREGISTERED` (in the vault, unknown to the server), a state 4.8 already renders
> and which costs nothing to retry. Vault entry first, and a failed server delete leaves an
> `ORPHAN`: records that can never be decrypted, storage that can never be reclaimed, and a
> `DEVICE_ID` that can never be registered again because the row still holds the primary key.
> One order is recoverable and the other manufactures exactly the state this item exists to
> provide an exit from.

- [x] Route `DELETE /devices/:device_id` (authenticated, owner-scoped): a hard delete of the
      `devices` row. `records` and `grants` need no second statement, since all three foreign
      keys are already `ON DELETE CASCADE` (`1785456000000_initial-schema.js`,
      `1785650000000_grants.js`), so the blobs go with the device by construction rather than
      by a cleanup path someone has to remember to write — `src/routes/devices.ts`, registered
      inside `requireSession`'s scope like the rest of that file. One statement, with the
      ownership check in the `where` clause rather than a preceding `select`: same shape as the
      `last_seq` and `vault_version` compare-and-swaps, so a device that changes hands between
      a check and a write cannot be deleted on the strength of the check. 204, no body
- [x] 404 for "not yours" and "does not exist" alike, matching every other cross-owner lookup
      in `devices.ts`. The client treats that 404 as success when retrying a delete that
      failed partway: the goal state is "not there", and a delete that already landed is in it
- [x] No soft delete, no tombstone. A tombstone is a retained record of a device someone asked
      to erase, and it would hold the `DEVICE_ID` primary key occupied forever, so the id
      could never be re-registered and the board never cleanly reused
- [x] Grants cascade in both directions and that is correct, not collateral damage: a grant
      naming the deleted device as the source wraps a key whose records no longer exist, and
      one naming it as the recipient is addressed to a device whose `device_data_key` died
      with its vault entry. Neither is openable by anyone afterwards, so keeping the row would
      preserve only its metadata (design 13.1 already counts grant edges as server-visible)
- [ ] Consider batching the record delete ahead of the device row if a long history makes the
      cascade slow enough to hold locks. Batching is safe *here* specifically because the
      target state is total removal, so a pass that dies halfway is resumable rather than
      corrupting. Measure before building it; at v1 record volumes this is very likely a
      non-issue

> **Batching was considered and deliberately not built**, per the item's own "measure first".
> Nothing here has a record volume where it could matter yet. What the consideration *did*
> turn up is a real gap, now closed: Postgres does not index the referencing side of a foreign
> key automatically, and `grants.device_b_id` had no index. `1785650000000_grants.js` indexed
> `device_a_id` only, because until this route existed `grants` was only ever read by "grants
> targeting this device". Both grant columns cascade, so every device delete had to find rows
> naming it on either side, and the `device_b_id` half was a sequential scan of the whole table
> while holding the delete's locks. Migration `1785660000000_grants-device-b-index.js` adds it.
> That is not the batching this item raises; it is the ordinary index a cascading foreign key
> wants, cheap now and expensive to discover once the table is big enough to feel the scan.

- [ ] A per-device surface for the actions, rather than more buttons on the list row. 4.6's
      reveal control needs the same home ("on an existing device, never a step in setup"), and
      three destructive-or-sensitive controls crowded into a row is how a stray click lands on
      the wrong one. Same reasoning that moved sign-out into `AccountMenu`
- [ ] Rename in the UI. `renameDevice` has existed in `vault-document.js` since 4.3 and
      nothing calls it, so the vault holds a name the person can set exactly once, during
      setup, and never correct
- [ ] The delete confirmation names what it destroys, in the moment: the device's name, that
      every record it uploaded is being erased from the only place it exists, and that this
      cannot be undone by anything the person still holds. Shaped like the occupied-board
      override (a second deliberate action, not armed by default, not staying armed), because
      it is the same species of thing
- [ ] Say that the board keeps running. A dashboard delete does not touch NVS: the firmware
      still holds `DEVICE_SECRET` and will keep uploading into 404s until someone reprovisions
      or erases it. A confirmation that implies the hardware was dealt with is lying about
      where the boundary is
- [ ] Offer the export (6.4) from the confirmation. It is the only way the readings survive
      the delete, and the moment someone is about to destroy them is the only moment offering
      it is useful. Ordering note: if 4.9 lands before 6.4, the confirmation ships without the
      offer rather than with a dead link
- [ ] Delete is the only action available on an **orphan**, and it is server-only: there is no
      vault entry to remove, so the two-step order above collapses to one step
- [ ] Delete on an **unregistered** device is the mirror image, a pure vault write with no
      server call, since the server has no row to delete
- [ ] Optional `SIOT ERASE <expected-id>` in the provisioning sketch, carrying the expected id
      as the same compare-and-swap `WRITE` does (4.5), so a board swapped between the read and
      the erase is refused. It adds no exposure `WRITE` does not already have, and it means a
      retired board stops being a live `DEVICE_SECRET` sitting in flash for a device that no
      longer exists. Optional because `WRITE` already reclaims a board for a new device; this
      is for the board going in a drawer
- [ ] Forward note for 5.6: a 404 from `POST /records` means this device has been deleted and
      no amount of retrying will change that, so it must not be handled as the same class of
      failure as a network drop. A deleted device that retries forever is a board flattening
      its battery against a server that will never accept it
- [ ] Test: delete a paired device and confirm the records are gone from Postgres, the vault
      entry is gone, and the `DEVICE_ID` can be registered again; delete an orphan and an
      unregistered device and confirm each takes its one step and no more; kill the vault
      write after the server delete and confirm the device lands in `UNREGISTERED` rather than
      anywhere new; confirm a second account gets 404 deleting the first account's device

> **The server half of that test is done; the halves that need a client are not.** A throwaway
> Node probe (since deleted, same as 4.5's PowerShell one) drove two accounts, two devices,
> five records and two grants — one naming the device as source and one as recipient, so both
> cascade directions were exercised rather than assumed. 20 checks, all passing: records and
> grants both gone from Postgres and the *other* device's untouched; the device dropped out of
> `GET /devices` and its records route 404s; an unauthenticated delete 401s, a second account
> gets 404, a made-up id gets 404, and none of those three deleted anything; a second delete of
> the same id gets 404 (the idempotency the client leans on); and the `DEVICE_ID` re-registers,
> comes back at `last_seq` 0, and accepts a record at the `seq` the deleted rows had used, which
> is the property that makes the id genuinely reusable rather than merely re-insertable.
>
> Still untested, because all three need 4.9's client half: the vault entry going, the orphan
> and unregistered single-step paths, and killing the vault write after the server delete to
> confirm the device lands in `UNREGISTERED`. No automated test either way; `backend/` still has
> no harness, same gap as everything since 2.3.

---

## Phase 5 — ESP32 Library & Wire Protocol

### 5.1 Library skeleton
- [ ] New Arduino/PlatformIO library project (`SIoT` lib) separate from example sketches
- [ ] NVS read helpers for `DEVICE_ID` / `DEVICE_SECRET` from the dedicated partition
- [ ] `SIoT.begin()` takes no credentials — on the supported path the device already has them (design 6)
- [ ] Key derivation on-device: HKDF-SHA256 (need a small C++ implementation or existing lib — mbedTLS has primitives)
- [ ] Derive `device_data_key` and `ed25519_seed` on boot

### 5.2 Sequence counters
- [ ] Persist `boot_epoch` to non-volatile storage (NVS on ESP32), increment once on boot before any record. This one is not optional on any port, unlike credential storage — a device that forgets it repeats a `seq`, and that is nonce reuse
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
- [ ] Minimal example: `SIoT.begin()` reading NVS creds, define one reading (e.g. temperature), loop + upload every N seconds
- [ ] Document in README how a user writes their own sketch against the library

---

## Phase 6 — Server-Side Record Validation

### 6.1 Records endpoint
- [x] Route `POST /records` (device-authenticated via signature, not session) — `src/routes/records.ts`, registered in its own public scope in `app.ts`, alongside (not inside) the `requireSession` scope: a device never holds a session, so that hook would reject every upload with a 401 before the real, signature-based authentication ever ran
- [x] Look up `device_id` → fetch `sign_pub` — 404 on an unknown `device_id`; not an anti-enumeration concern the way `/salt` is, since design 5.2 already lists `device_id` as something the server legitimately knows
- [x] Check 1: `Ed25519_verify(sign_pub, AAD||nonce||ciphertext, sig)` — `src/lib/ed25519.ts`, Node's native `crypto.verify` via a JWK-reconstructed public key (no dependency needed for something the platform already implements: an Ed25519 JWK is just `{kty:'OKP', crv:'Ed25519', x: <the same 32 raw bytes>}`)
- [x] Check 2: `seq > last_seq[device_id]` — a single-statement compare-and-swap (`update devices set last_seq = $2 ... where last_seq < $2`), same reasoning as the `vault_version` CAS in `vault.ts`: two uploads racing for one device must not both pass a separate read
- [x] Check 3: nonce matches `0x00000000 || seq` — `src/lib/seq.ts`
- [x] On pass: store blob in `records` table, update `last_seq` (and `last_seen_at`, closing the gap Phase 4.8 left open) — same transaction as the check 2 CAS
- [x] On fail: reject with 4xx, no partial writes — the CAS and the insert share one transaction, so a failed insert (e.g. the belt-and-braces unique-constraint catch) rolls back the `last_seq` bump too

> **Deviation worth knowing about.** Design 7.3's AAD is `version(1B) || DEVICE_ID(16B) ||
> record_type(1B) || seq(8B)`, but the same section's own `POST /records` example body is
> `{ device_id, seq, nonce, ciphertext, sig }` — no `version` or `record_type` field. Read
> literally, the server cannot reconstruct the AAD it needs to verify without them. Resolved
> by treating `version` and `record_type` as fixed v1 protocol constants (`PROTOCOL_VERSION =
> 1`, `RECORD_TYPE_V1 = 0` in `src/lib/wire-format.ts`), not wire fields — both sides derive
> the same AAD bytes from a constant plus the `device_id`/`seq` already on the wire.
> `record_type` is reserved for Phase 7's per-schema record types; every record is type 0
> until then. Firmware built against `docs/protocol.md` (roadmap 4.7, not yet written) needs
> this stated as a non-negotiable, the same way `boot_epoch` persistence already is.
>
> Verified by hand with a throwaway script standing in for the Phase 5 firmware / Phase 4.1
> browser derivation (neither exists yet): generated an Ed25519 keypair and `device_id`
> directly, registered it, then walked every path — a correctly signed upload (201), a replay
> of the same `seq` (409), a tampered signature (401), a `seq`/nonce pairing that doesn't match
> (400), an unknown `device_id` (404), and a `boot_epoch` jump to confirm the monotonicity
> check holds across the full uint64 range rather than just JS-safe integers. No automated
> test; same gap as the rest of `backend/`.

### 6.2 Records read endpoint
- [x] Route `GET /devices/:id/records` (authenticated, owner or grant-holder only — grants come in Phase 8, stub owner-only check for now) — `src/routes/devices.ts`; 404 for both "not yours" and "does not exist", same anti-enumeration reasoning as the rest of this file
- [x] Return raw ciphertext blobs + metadata (seq, nonce, timestamp) for client-side decryption
- [x] Pagination / range query by seq or time — cursor is `seq` (`after_seq`, exclusive), not time: `seq` is the authoritative order (design 7.1) and the device's own clock is never trusted for anything else either. Ascending order, page size 1-500 (default 100)

> Verified by hand in the same session as 6.1: uploaded five records, paged through them two
> at a time and confirmed the cursor lines up with a single unpaged fetch, confirmed a second
> account gets 404 on the first account's device, confirmed an unauthenticated request gets
> 401, and confirmed a made-up `device_id` gets the same 404 a real-but-foreign one does. No
> automated test.

### 6.3 Client-side decrypt & display
- [ ] Fetch device's `device_data_key` from decrypted vault
- [ ] Decrypt records client-side, verify AAD matches expected device/type
- [ ] Detect sequence gaps within a `boot_epoch` and surface as "possible missing data" in UI (not an error, just a signal)

> Left unticked: `frontend/app/` UI work, same as the four items 4.8 left open, and gated by
> the same CLAUDE.md rule that new UI is Opus-only. `GET /devices/:id/records` (6.2) is done
> and independently testable, so this is a clean stopping point rather than a partial one.

### 6.4 Downloading records

> **There is no server-side export, and the reflex to add one is exactly what the one rule
> exists to catch.** A CSV endpoint has to read the readings to know what the columns are, and
> the server cannot read anything. Export is assembled in the browser out of records 6.3 has
> already fetched and decrypted, and handed to the disk as a `Blob`; no part of it goes back
> over the network, and there is no endpoint to add.

> **A file on disk is outside every guarantee in the design document**, in the same way a
> revealed `DEVICE_SECRET` is (4.6, design 5.3.1). It is plaintext, it is not in the vault, it
> is backed up by whatever the person's machine backs up to, and nothing here can follow it.
> That is a legitimate thing to want and it is not a path to shape apologetically, but the
> cost gets stated at the moment of the export rather than in documentation nobody opens.

- [ ] Walk the whole history rather than exporting the page on screen. `GET /devices/:id/records`
      is cursor paginated at 500 (6.2), so an export is a loop over `after_seq` and needs
      real progress: a device reporting every thirty seconds for a year is thousands of round
      trips, and a silent freeze is indistinguishable from a hang
- [ ] JSON is the lossless format: per record, `seq`, both timestamps, and the decrypted
      payload fields, plus a header naming the device, the `DEVICE_ID`, the export time and
      the `seq` range covered
- [ ] CSV is the format people actually open: one row per record, columns from the union of
      reading keys seen across the whole export, blank where a record did not carry a key.
      Deriving the columns from Phase 7's schema instead becomes possible once schemas exist,
      but the union is what stays correct for a device whose readings changed shape mid-life
- [ ] **Two timestamps, labelled as two different things**, never collapsed into one column.
      The device's own `t` from inside the payload is authenticated but comes from a clock
      nothing verifies; the server's `created_at` is when the upload arrived and is only as
      trustworthy as the server. `seq` is the sole authoritative order (design 7.1), so it is
      what the file is sorted by
- [ ] Carry 6.3's gap detection into the file rather than leaving it on screen. A CSV whose
      rows run continuously across a `seq` gap is a lie about the data, and it is the artifact
      that outlives the UI that told the truth
- [ ] Count records that opened under no key rather than dropping them, the same discipline
      `vault-document.js` applies to entries it cannot parse. After a re-provisioning (8.4)
      the old records are genuinely unopenable, and an export that quietly omitted them would
      report a shorter history than the device has
- [ ] Revoke the object URL after the download and hold no copy of the assembled text. It is
      the same "reveal on demand, do not stay revealed" rule 4.6 states for credentials
- [ ] Not v1, and worth writing down so it is a decision rather than an omission: an
      **encrypted archive** (the raw blobs plus metadata, openable only with `DEVICE_SECRET`)
      is a real backup format and a different feature. It is worthless in the one flow that
      motivated this (exporting before a delete destroys the vault entry and therefore the
      key), so the decrypted export is the one that earns its place first
- [ ] Test: export a device with a deliberate `seq` gap and a record the key will not open,
      and confirm both are visible in the file and not merely in the UI; confirm the row count
      matches an unpaged fetch, so the cursor loop is not dropping a page boundary

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

> Phase 7 has no backend-only slice: a schema is just vault contents (`PUT`/`GET /vault`,
> already done in Phase 3), and validation/rendering are entirely `frontend/app/` concerns.
> Skipped in a backend-only pass for that reason, same as the frontend items in 4.x and 6.3 —
> not because anything here turned out wrong, just nothing left to build without touching
> `frontend/`.

---

## Phase 8 — Inter-Device Grants

### 8.1 Grant creation — client
- [ ] UI: pick Device A (granted) and Device B (source), with an explicit warning that this grants access to B's full history, past and future, and that revocation only affects future data
- [ ] Decrypt `device_B_data_key` from vault
- [ ] Re-encrypt it under `device_A_data_key` with AAD `"grant/v1" || DEVICE_ID_A || DEVICE_ID_B`
- [ ] Upload grant blob

### 8.2 Grant storage — server
- [x] `grants` table: id, device_a_id, device_b_id, ciphertext, created_at — migration `1785650000000_grants.js`. Deliberately **no** uniqueness constraint on `(device_a_id, device_b_id)`: design 9.3 says old data must stay readable by A forever, which depends on A being able to fetch the grant that wrapped the *old* `device_B_data_key` after B rotates; upserting on re-grant would destroy that row. Multiple grants per pair, one per key epoch, newest first
- [x] Route `POST /grants` (authenticated, must own both devices or have rights — decide policy) — `src/routes/grants.ts`. **Policy decided:** must own both. There is no cross-user device-sharing primitive anywhere else in the design or roadmap, so a grant between two different users' devices has no authorization to check yet; this is the policy to revisit if that changes. Ownership of both devices is checked in one query (`select ... where owner_user_id = $1 and device_id in ($2, $3)`, `rowCount !== 2`), not two, so there is no window between checking A and checking B for either to change hands
- [x] Route `GET /devices/:id/grants` for a device to fetch grants targeting it — public, not session-authenticated, registered alongside `POST /records` outside `requireSession`'s scope: Device A's own firmware polls this (design 9.3) and holds no session. Design 13.1 already lists "which devices hold grants on which others" as metadata the server is acknowledged to see, so an unauthenticated read of opaque ciphertext scoped by a 128-bit `device_id` adds no new leak beyond that

> Verified by hand: two accounts, three devices (two owned by account 1, one by account 2).
> Account 1 granting between its own two devices succeeds (201); account 1 naming account 2's
> device as either side is rejected (403); an unauthenticated create is rejected (401); issuing
> a second grant for the same device pair leaves both rows queryable rather than overwriting,
> newest first; and a device with no grants targeting it reads back an empty list rather than
> an error. No automated test; same gap as the rest of `backend/`.

### 8.3 Grant consumption — device
- [ ] Device A firmware: fetch grants where it's the recipient, decrypt with its own `device_data_key`
- [ ] Use resulting `device_B_data_key` to decrypt B's records fetched from server
- [ ] Test: A can read B's historical + live records without any always-on relay

### 8.4 Revocation flow
- [ ] UI messaging: "revoke" = rotate B's `DEVICE_SECRET` via re-provisioning, old data stays readable by A forever
- [ ] Re-provisioning flow reuses the Phase 4 tool with a new `DEVICE_SECRET`, updates vault entry, old grants naturally stop covering new data — the device's name should survive the rotation, since it is the same physical thing in the same place

> 8.1, 8.3, and 8.4 are `frontend/app/` and Phase 5 firmware work (grant creation UI,
> device-side grant consumption, re-provisioning UI) and were left for sessions that touch
> those, same reasoning as everywhere else in this pass. 8.2 is done and independently
> testable via `POST /grants` and `GET /devices/:id/grants`.

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

## Phase 10 — Device Notifications

> **The number is not the order.** This depends on Phase 6 (records) and Phase 7 (dashboard)
> and on nothing in Phases 8 or 9, so it can be built as soon as those two are done. It is
> numbered 10 because renumbering would invalidate every "Phase 9" reference already in
> `CLAUDE.md`, the design document and the code comments.

A device raises an event its owner should see: a door opened, a tank is low, a battery is
about to die. It arrives in the dashboard saying which device it came from, and the server
learns nothing it did not already know.

### 10.0 The three decisions this rests on

Read these before ticking anything below. Each one is a place where the convenient design is
the wrong one, and the reasons are not recoverable from the task list.

**A notification is a record, not a new kind of thing.** It goes up through `POST /records`
with the same Ed25519 signature, the same `seq` monotonicity, the same nonce construction, and
the same three server checks from design 7.4. There is no notification endpoint, no
notifications table, and no server-side schema change. That is not minimalism for its own
sake: a second upload path is a second place for the checks to be subtly weaker, and "the
alert path skipped the signature check because it needed to be fast" is exactly the kind of
mistake this project's one rule exists to catch.

**The record type stays inside the ciphertext, never on the wire.** Design 7.3's AAD carries a
`record_type` byte, and `src/lib/wire-format.ts` currently pins it to the constant
`RECORD_TYPE_V1 = 0` (see the 6.1 note for why it is a constant rather than a field). It is
tempting to give notifications their own value there. **Do not.** The AAD is authenticated, not
encrypted, so a distinct type in it tells the server "this upload is an alert" — and a smoke
alarm, a door sensor or a panic button emitting a *distinguishable* record at a known moment is
a labelled event log, which is precisely what Section 5.5 refuses to let device names become.
The type goes in the encrypted CBOR payload beside the reading fields. The AAD keeps its
constant.

  The cost is real and has to be accepted, not worked around: **the server cannot tell a
  notification from a temperature reading**, so it cannot selectively notify anyone. Delivery
  is 10.4 and it is poll-based for that reason.

**A symmetric key that can write can also read.** "Notification write key" implies a key that
posts alerts without being able to read them back, and AES-GCM cannot do that: one key, both
directions. This does not matter in v1, because the writer is always the device, and the device
already holds `DEVICE_SECRET` and can derive every key in its own hierarchy — a write-only key
would be a lock on a door it already has the key to. It starts to matter the moment the writer
is *not* the device (a script, a webhook, a third-party service posting to someone's
dashboard), and that needs asymmetric encryption to a per-device public key whose private half
lives in the vault. Out of scope here, written down so it is a known boundary rather than a
surprise discovered by someone building it.

### 10.1 The notification key

- [ ] Derive `device_notify_key` via HKDF from `DEVICE_SECRET`, info=`"siot/device/notify/v1"` — the third label alongside `"siot/device/data/v1"` and `"siot/device/sign/v1"` in `HKDF_INFO`, and like those two it is a wire format shared with every firmware port, not an internal name. Unique per device by construction, since `DEVICE_SECRET` is
- [ ] Add it to `deriveDeviceKeys` in `frontend/lib/crypto/device.js` and to the ESP32 library's boot derivation, in the same commit — a label that exists on one side only is a device whose notifications nothing can open
- [ ] Unit test: the notify key differs from the data key derived from the same secret, and both are reproducible

> **Why a separate key at all, when `device_data_key` is right there.** Grants (design 9.3)
> wrap one key to hand one device's data to another. With a single key per device, a grant is
> all-or-nothing: sharing a door sensor's alerts means sharing its full open/close history.
> Two keys make "alerts only" and "readings only" expressible. If Phase 8 is ever cut down to
> a single grantable key, this separation loses its justification and should be revisited
> rather than kept out of habit.

### 10.2 Sending — device side

- [ ] Extend the CBOR payload shape with a notification record: type marker, a short message, a severity from a fixed small set, and the device's own timestamp — all *inside* the encrypted payload
- [ ] `siot.notify(severity, message)` in the ESP32 library, encrypting under `device_notify_key` and signing with the same Ed25519 key ordinary records use
- [ ] Notifications and readings share one `seq` sequence, not two — `seq` feeds the nonce (design 7.2), and two counters over one key is nonce reuse waiting to happen. This is the single most dangerous thing to get wrong in this phase
- [ ] Bound the message length in the library, not just in the UI: a device that can emit an arbitrarily long ciphertext lets its own payload size leak what it is saying
- [ ] Test: a notification and a reading uploaded from one boot are accepted, in order, with no `seq` collision

### 10.3 Reading — client side

- [ ] Decrypt records with both `device_data_key` and `device_notify_key` and sort by the type marker inside the plaintext — a record that opens under neither is surfaced the way 6.3 surfaces a gap, as a signal rather than an error
- [ ] Validate the decrypted notification against a strict allowlist before rendering, the same discipline 7.2 applies to schemas. The vault is authenticated and the record is signed, so this is not about tampering; it is that a device is a program someone wrote, and the dashboard renders whatever it says
- [ ] Show which device each notification came from, by joining `DEVICE_ID` to the vault name through the existing `device-list.js` join — the server never learns the name, and a locked vault shows notifications attributed to a bare `DEVICE_ID`, the same honest degradation design 5.5 already accepts everywhere else
- [ ] Order by `seq` within a device and by arrival time across devices, and say which is which — cross-device ordering uses the server's timestamps and is therefore only as trustworthy as the server

### 10.4 Delivery and read state

- [ ] v1 is **poll on open, and poll while open**. No push, no email, no SMS. Follows directly from 10.0: the server cannot tell a notification from a reading, so it has nothing to trigger on
- [ ] Unread state lives in the **vault**, not the server — a per-device high-water `seq` of "seen up to here", marked read by an ordinary vault write with a version bump, exactly like a rename. "This account read the smoke alarm alert at 03:12" is not metadata to hand over in exchange for saving a round trip
- [ ] Surface the count of unread notifications in the dashboard shell, derived client-side after decryption
- [ ] Never phrase a quiet device as "no alerts": the same rule as liveness in 4.8. A withholding server and a device with nothing to say are indistinguishable from the client

> **The push question, deliberately left open.** Real push is possible without breaking the one
> rule, and it is worth knowing the shape before anyone reaches for the shape that does break
> it. The server sends a **content-free** Web Push on *every* record arrival, for any device the
> account owns; the client wakes, fetches, decrypts, and decides whether anything is worth
> showing. That leaks nothing new, since the server already sees every upload land (design
> 13.1). The cost is that a sensor reporting every thirty seconds wakes the client every thirty
> seconds. The version that *is* forbidden, and that will look reasonable to whoever builds
> this: letting the server push only when a notification arrives, which requires it to be able
> to tell, which requires 10.0's second decision to be reversed.

### 10.5 Sending from the dashboard (not v1)

- [ ] Decide whether a notification can originate anywhere other than a device. If yes it needs the asymmetric scheme from 10.0's third decision, and that is a phase of its own rather than an item here

---

## Suggested Starting Point

Work top-to-bottom through **Phase 0 → Phase 1 → Phase 2**. That gets you: a real backend/frontend skeleton, real client-side crypto, and a working signup/login flow with genuine zero-knowledge properties — testable end-to-end before any device or vault-content work begins.
