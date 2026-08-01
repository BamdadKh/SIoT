# SIoT

Zero-knowledge IoT platform. ESP32 devices encrypt readings client-side; the server is a
dumb, fully untrusted blob store.

## Read these first

- `SIoT_Design_Document.md` — the architecture. Section numbers are referenced throughout
  the code in comments; keep those references accurate if sections move.
- `ROADMAP.md` — ordered task list. Work top-to-bottom, check items off as they land.

## How we work

We work deliberately and verifiably. Four rules:

1. **Follow `ROADMAP.md` in order, and stop at the first point where the work can actually
   be tested.** Not at the end of a phase — at the next checkpoint that produces something
   observable: an endpoint that responds, a test that passes, a board that blinks. Then hand
   back with the exact commands to try it. Don't run three phases together because they're
   individually small.

2. **Tick roadmap items off as they land.** If the real implementation deviated from what the
   item assumed, tick it and append a short note saying what was decided instead. If an item
   was deliberately skipped, leave it unticked and add a `>` note explaining why. The roadmap
   is the record of what is actually done — it is wrong for it to drift.

3. **Backend first.** The server is the substance of this project; the UI is downstream of it.
   Build the API, then build whatever is needed to exercise it. `frontend/` stays a plain-HTML
   test harness until Phase 2 needs real forms and routing.

4. **Throwaway scaffolding is encouraged.** Test consoles, seed scripts, debug endpoints,
   hardcoded fixtures — write them freely to make the current step observable, and delete them
   when they stop earning their place. Mark them clearly (a comment saying what replaces it and
   when) so they don't get mistaken for real design. What is *not* acceptable is throwaway
   work on a security boundary: no "temporary" plaintext paths, skipped signature checks, or
   dev-only auth bypasses. Convenience never gets to weaken the crypto.

When something in the roadmap turns out to be wrong or premature, say so and propose the change
rather than silently working around it.

## The one rule

Every change is evaluated against a single question:
**does this give the server plaintext access to anything, even indirectly?**

If the answer is yes, the change is wrong regardless of how convenient it is. The server may
only ever see: usernames, client salts, `DEVICE_ID`, `device_sign_pub`, sequence numbers,
nonces, opaque ciphertext, and timing metadata. Nothing else.

Corollaries that are easy to violate by accident:

- Never add a server-side endpoint that decrypts, transforms, or validates payload *contents*.
  The server's only record checks are the three in Section 7.4 (signature, `seq` monotonicity,
  nonce well-formedness) — none require decryption.
- Never log a request body containing key material or ciphertext at a level that ships to disk.
- `login_key` is password-equivalent. It is hashed with Argon2id server-side before storage,
  never stored raw.
- Randomness is always `crypto.getRandomValues` / `crypto.randomBytes`. Never `Math.random`.

## Layout

```
backend/     Fastify + TypeScript API (the main focus of development)
frontend/    Plain-HTML test console for now; becomes a React+Vite app later
firmware/    ESP32 sketches — currently a throwaway HTTP button-counter spike
extension/   Client-verification browser extension (Phase 9, empty)
```

## Running it

```bash
docker compose up -d            # Postgres :5433, Redis :6379
cd backend
cp .env.example .env            # first time only
npm run gen-cert                # first time only — self-signed dev TLS cert
npm run migrate:up              # apply migrations
npm run dev                     # https://localhost:3030
```

Client crypto is a separate package with its own tests:

```bash
cd frontend
npm install                     # first time only — hash-wasm
npm test                        # node --test over lib/crypto/
```

Then open <https://localhost:3030/> for the test console, which polls `GET /health`.
The browser will warn once about the self-signed certificate — that is expected; accept it.
Do not "fix" it by turning TLS off.

`npm run typecheck` before considering anything done.

The cert's SANs cover `localhost` plus every LAN address of this machine, so a device on
the same network can reach the dev server by IP and still validate. `npm run gen-cert`
also prints the SPKI pin, which is what Phase 5.6 firmware will pin.

## Decisions already made (don't relitigate)

- **No npm workspaces.** `backend/` is a standalone package. The frontend has no build step
  yet. Revisit when the React client lands.
- **Directory names are `backend/` and `frontend/`**, not the `server/`/`client/` the roadmap
  suggests — the dirs predate the roadmap and renaming buys nothing.
- **`pg` directly, no ORM.** Raw SQL in `backend/src/`, with a thin `Postgres` wrapper
  (`query`, `queryOne`, `transaction`) in `src/db/postgres.ts`.
- **TypeBox, not zod**, for request/response schemas — it compiles to the JSON Schema Fastify
  validates with natively, so there's no double validation pass.
- **CommonJS**, `module: node16`. Imports still carry `.js` extensions so an ESM move is cheap.
- **`seq` is `numeric(20,0)`, not `bigint`.** It is a uint64 (`(boot_epoch << 32) | msg_counter`)
  and overflows a signed bigint. `pg` returns it as a string — parse to `BigInt`, never `Number`.
- **`vault_version` lives on `users` only**, not duplicated onto `vault_blobs`, so the two
  cannot drift. v1 vault granularity is one blob per user.
- **The backend serves `frontend/` statically in dev** (`SERVE_TEST_FRONTEND=true`). This is
  purely so the test console is same-origin — no CORS, and session cookies work unmodified.
  Delete it when the real client exists.
- **TLS is on in dev too**, via a self-signed cert generated by `scripts/gen-dev-cert.js`
  (the `selfsigned` package, not `openssl`, which isn't reliably on PATH on Windows).
  `TLS_ENABLED=false` exists as a debugging escape hatch and logs a loud warning; it is not
  a supported mode. There is no plaintext listener and no HTTP→HTTPS redirect.
- **Client crypto lives in `frontend/lib/crypto/`, never in `backend/`.** Physical separation
  is weaker than a cryptographic guarantee, but it means "just derive the kek server-side"
  cannot be written without an obviously wrong import path. `frontend/` is now its own npm
  package (still no build step) purely so it can have `hash-wasm` and a test runner.
- **Tests are `node --test`, no framework.** Node's Web Crypto is the same API the browser
  exposes, so the tests run the exact ESM modules the client loads — no jsdom, no mocks, no
  transpile. Same reason the browser gets an import map for `hash-wasm` instead of a bundle:
  one copy of the code, tested and shipped.
- **Fastify's Ajv runs with `removeAdditional: false`.** Its default silently strips
  properties an `additionalProperties: false` schema doesn't name, which would turn a client
  that accidentally posts `kek` into a 201. Unknown fields are a 400.
- **`@node-rs/argon2` for the server-side hash of `login_key`**, at m=19 MiB/t=2/p=1 — lighter
  than the client's m=64 MiB on purpose (see `src/lib/login-key.ts` for why that isn't a
  weakening). Never import it into anything that touches `kek`. Its 2.0.2 `verify` decodes the
  password as UTF-8 even though `hash` takes bytes, so both go through `argon2Input()`, which
  base64s the key first. Hashing one encoding and verifying another rejects every correct
  password, so that helper is not optional on either path.
- **Login throttling is a hand-rolled Redis counter**, not `@fastify/rate-limit`. A request
  budget is the wrong shape: the ladder must advance only on a *wrong* answer, survive a
  restart, and key on account and source address independently. See `src/lib/rate-limit.ts`.
- **Unknown usernames still pay for an Argon2 verify**, against a decoy hash of random bytes.
  A fast 401 for "no such account" and a slow one for "wrong password" is a cleaner account
  oracle than anything `GET /salt` defends against.
- **Authenticated routes are protected by their Fastify scope, not by an allowlist.** `app.ts`
  registers them inside a plugin that owns the `requireSession` hook; put a new route there
  and it is protected, put it outside and it is public. The mistake this shape makes easy is
  an unexpected 401, not an open endpoint. Phase 6's `POST /records` authenticates by device
  signature instead and needs its own scope.
- **HSTS is set in production only.** The header is host-scoped and ignores the port, so
  emitting it on `localhost` would force HTTPS on every other project served from localhost
  on this machine, for a year, with no convenient undo.

## Conventions

- Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`.
- Never add a Claude/AI co-author trailer to commits.
- Binary values (keys, salts, ciphertext, `DEVICE_ID`) are `bytea` in Postgres and base64url
  on the wire. Do not mix in hex.
- Comments explain *why*, especially where the reason is a security property. A comment that
  restates the code is noise; one that says "this is what makes nonce reuse structurally
  impossible" is the point.

## Current state

**Phases 0, 1 and 2 complete.** Server boots over HTTPS,
connects to Postgres and Redis, health check reports both and 503s when either is down, schema
is migrated. The full client key hierarchy of Section 2.1 exists in `frontend/lib/crypto/` —
Argon2id → master_key → HKDF → `login_key`/`kek`, plus `vault_key` generation and AES-256-GCM
wrapping — with 28 passing unit tests and a panel in the test console that runs the same
modules in a real browser.

`POST /signup` works end-to-end: the test console derives everything locally and posts only
`{ username, salt, login_key, wrapped_vault_key }`; the server Argon2id-hashes `login_key` and
writes the row. `GET /salt` returns the stored salt for real accounts and an HMAC decoy for
unknown ones, structurally and timing-wise identical.

`POST /login` completes the loop: throttle check, Argon2id verify (against a decoy hash when
the account does not exist), then a session in Redis under `sess:<sha256(id)>` with a 30 min
idle TTL and a 12 h absolute cap, delivered as `HttpOnly; Secure; SameSite=Strict`. The session
lifecycle is closed: `requireSession` resolves the cookie and slides the idle window,
`GET /session` says who you are, and `POST /logout` / `POST /logout-everywhere` revoke one or
all. `GET /vault-key` returns the sealed 60-byte blob, which the client opens with the `kek` it
still holds from login — the first response the server hands back that it cannot read itself.
Routes are `/health`, `/signup`, `/salt`, `/login`, `/session`, `/logout`, `/logout-everywhere`,
`/vault-key`.

**Accounts created before the `argon2Input()` fix cannot log in.** Their `login_key_hash` was
computed over raw bytes rather than the base64 form. Dev data only; sign up again.

`backend/` has no test harness. Everything so far was verified by hand against a running
server; the frontend's `node --test` suite covers `lib/crypto/` only. Phase 2.5 onwards is
where that stops being tenable.

`firmware/esp32/esp32.ino` is the old unencrypted spike and **no longer works against this
server** — its `POST /button` endpoint is gone and the server is HTTPS-only. That is intended;
it gets replaced wholesale by the SIoT library in Phase 5.

Next up is Phase 3 — vault storage: `PUT /vault` / `GET /vault`, version-based conflict and
rollback detection, then the password change flow. The client already holds an unwrapped
`vault_key` after login, so 3.1 has everything it needs.
