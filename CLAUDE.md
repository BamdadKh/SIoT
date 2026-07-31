# SIOT

Zero-knowledge IoT platform. ESP32 devices encrypt readings client-side; the server is a
dumb, fully untrusted blob store.

## Read these first

- `SIOT_Design_Document.md` — the architecture. Section numbers are referenced throughout
  the code in comments; keep those references accurate if sections move.
- `ROADMAP.md` — ordered task list. Work top-to-bottom, check items off as they land.

## How we work

Deliberately slow and verifiable. Four rules:

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
  weakening). Never import it into anything that touches `kek`.
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

**Phases 0 and 1 complete; Phase 2 in progress (2.1–2.2 done).** Server boots over HTTPS,
connects to Postgres and Redis, health check reports both and 503s when either is down, schema
is migrated. The full client key hierarchy of Section 2.1 exists in `frontend/lib/crypto/` —
Argon2id → master_key → HKDF → `login_key`/`kek`, plus `vault_key` generation and AES-256-GCM
wrapping — with 28 passing unit tests and a panel in the test console that runs the same
modules in a real browser.

`POST /signup` works end-to-end: the test console derives everything locally and posts only
`{ username, salt, login_key, wrapped_vault_key }`; the server Argon2id-hashes `login_key` and
writes the row. There are still **no sessions** — nothing is authenticated, and `/health` and
`/signup` are the only routes.

`firmware/esp32/esp32.ino` is the old unencrypted spike and **no longer works against this
server** — its `POST /button` endpoint is gone and the server is HTTPS-only. That is intended;
it gets replaced wholesale by the SIOT library in Phase 5.

Next up is roadmap 2.3 — `GET /salt` with the HMAC decoy for unknown usernames — then login
and sessions (2.4–2.6).
