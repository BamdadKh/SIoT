# SIOT

Zero-knowledge IoT platform. ESP32 devices encrypt readings client-side; the server is a
dumb, fully untrusted blob store.

## Read these first

- `SIOT_Design_Document.md` — the architecture. Section numbers are referenced throughout
  the code in comments; keep those references accurate if sections move.
- `ROADMAP.md` — ordered task list. Work top-to-bottom, check items off as they land.

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
docker compose up -d            # Postgres :5432, Redis :6379
cd backend
cp .env.example .env            # first time only
npm run migrate:up              # apply migrations
npm run dev                     # http://localhost:3030
```

Then open <http://localhost:3030/> for the test console, which polls `GET /health`.

`npm run typecheck` before considering anything done.

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

## Conventions

- Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`.
- Never add a Claude/AI co-author trailer to commits.
- Binary values (keys, salts, ciphertext, `DEVICE_ID`) are `bytea` in Postgres and base64url
  on the wire. Do not mix in hex.
- Comments explain *why*, especially where the reason is a security property. A comment that
  restates the code is noise; one that says "this is what makes nonce reuse structurally
  impossible" is the point.

## Current state

Phase 0 is done through the skeleton: server boots, connects to Postgres and Redis, health
check reports both, schema is migrated, test console renders it. Nothing is authenticated
yet, there is no crypto yet, and `firmware/esp32/esp32.ino` is still the unencrypted spike.

Next up is roadmap Phase 0.5 (local HTTPS) then Phase 1 (client-side crypto primitives).
