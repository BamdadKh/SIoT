# SIoT

Zero-knowledge IoT platform. ESP32 devices encrypt readings client-side; the server is a
dumb, fully untrusted blob store.

## Read these first

- `SIoT_Design_Document.md`: the architecture. Section numbers are referenced throughout
  the code in comments; keep those references accurate if sections move.
- `ROADMAP.md`: an ordered task list. Work top-to-bottom, check items off as they land.

## How we work

We work deliberately and verifiably. Six rules:

1. **Follow `ROADMAP.md` in order, and stop at the first point where the work can actually
   be tested.** Not at the end of a phase, but at the next checkpoint that produces something
   observable: an endpoint that responds, a test that passes, a board that blinks. Then hand
   back with the exact commands to try it. Don't run three phases together because they're
   individually small.

2. **Tick roadmap items off as they land.** If the real implementation deviated from what the
   item assumed, tick it and append a short note saying what was decided instead. If an item
   was deliberately skipped, leave it unticked and add a `>` note explaining why. The roadmap
   is the record of what is actually done, so it is wrong for it to drift.

3. **Backend first.** The server is the substance of this project; the UI is downstream of it.
   Build the API, then build whatever is needed to exercise it. `frontend/` stays a plain-HTML
   test harness until Phase 2 needs real forms and routing.

4. **Throwaway scaffolding is encouraged.** Test consoles, seed scripts, debug endpoints, and
   hardcoded fixtures: write them freely to make the current step observable, and delete them
   when they stop earning their place. Mark them clearly (a comment saying what replaces it and
   when) so they don't get mistaken for real design. What is *not* acceptable is throwaway
   work on a security boundary: no "temporary" plaintext paths, skipped signature checks, or
   dev-only auth bypasses. Convenience never gets to weaken the crypto.

5. **New UI work matches the existing screens, not just the design tokens.** Layout rhythm,
   spacing, copy tone, and how a screen states its state (see the plate-chrome and visual
   language notes below) all carry over from screen to screen. Look at a neighboring screen
   before building a new one. When judgment calls come up, the `frontend-design` skill and the
   `claude-design` MCP tools are available; use them rather than guessing at a one-off style.

6. **New UI is Opus-only.** Sonnet writes backend code, tests, docs, and everything else freely,
   including minor UI edits: copy changes, spacing fixes, wiring an existing component to a new
   endpoint. Building a new screen or component is reserved for Opus. A Sonnet session that hits
   that boundary should say so and stop rather than build it anyway.

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
  nonce well-formedness), and none require decryption.
- Never log a request body containing key material or ciphertext at a level that ships to disk.
- `login_key` is password-equivalent. It is hashed with Argon2id server-side before storage,
  never stored raw.
- Randomness is always `crypto.getRandomValues` / `crypto.randomBytes`. Never `Math.random`.

## Layout

```
backend/       Fastify + TypeScript API (the main focus of development)
frontend/      One npm package, two clients:
  app/           the real React + Vite client (Phase 0.4 onwards)
  index.html     plain-HTML test console, still here, still useful
  lib/crypto/    client crypto, shared by both and by `node --test`
firmware/      ESP32 sketches, currently a throwaway HTTP button-counter spike
extension/     Client-verification browser extension (Phase 9, empty)
```

## Running it

```bash
docker compose up -d            # Postgres :5433, Redis :6379
cd backend
cp .env.example .env            # first time only
npm run gen-cert                # first time only, self-signed dev TLS cert
npm run migrate:up              # apply migrations
npm run dev                     # https://localhost:3030
```

The frontend is one package holding the React client, the test console, and the crypto:

```bash
cd frontend
npm install                     # first time only
npm test                        # node --test over lib/crypto/
npm run dev                     # https://localhost:5173, the real client
```

The Vite dev server runs HTTPS off the backend's own certificate and proxies the API
paths to `:3030`. Both of those are load-bearing, not convenience: the session cookie is
`Secure; SameSite=Strict`, so a plaintext dev server drops it silently and every
authenticated request 401s with nothing to show why. `npm run gen-cert` in `backend/`
has to have run first. Adding a server route means adding it to `API_PATHS` in
`vite.config.js` too; a missing entry shows up as `index.html` arriving where JSON
was expected.

Then open <https://localhost:3030/> for the test console, which polls `GET /health`.
The browser will warn once about the self-signed certificate. That is expected, so accept it.
Do not "fix" it by turning TLS off.

`npm run typecheck` before considering anything done.

The cert's SANs cover `localhost` plus every LAN address of this machine, so a device on
the same network can reach the dev server by IP and still validate. `npm run gen-cert`
also prints the SPKI pin, which is what Phase 5.6 firmware will pin.

## Decisions already made (don't relitigate)

- **No npm workspaces.** `backend/` is a standalone package, `frontend/` is another. The
  React client did land, and it did not need workspaces: `vite.config.js` sits at
  `frontend/` with `root: 'app'`, so one `package.json` covers the app, the test console
  and the crypto tests.
- **The test console stays.** It is not superseded by `frontend/app/`. It exercises
  `lib/crypto/` directly with no React in the way, which is what you want when the
  question is whether a derivation is correct rather than whether a screen renders.
- **Hand-rolled router, ~40 lines** (`app/src/lib/router.jsx`), not React Router. There
  are four screens and no nested routes, params, or loaders to justify the dependency.
- **Fonts are self-hosted** via `@fontsource`, never Google Fonts. A zero-knowledge
  product that phones a third party on every page load is telling on its users for the
  sake of a stylesheet.
- **Design tokens are the whole palette** (`app/src/styles/tokens.css`); screens never
  hardcode a colour. The two accents are not interchangeable: `--olive` is every action the
  user can take, `--rust` is the mark (the wordmark and the registration ticks) plus work
  being waited on or a vault that cannot be opened. A control that comes out rust is a bug,
  and so is a wordmark that comes out olive.
- **The plate chrome never carries state.** The four registration ticks and the wordmark look
  identical on every screen; locked, busy and error are said by the heading and the control,
  where someone is already looking. Markers that change to signal state were explored and
  rejected. A stray `.seal` square survived that rejection on the unlock screen and has been
  removed; anything like it reappearing is the same mistake.
- **Account actions live under the username, not beside it.** The top bar has exactly one
  control, and it is the username: olive with a caret, because olive is the token that says
  "you can press this" and mono is the face that says "this is the name the server stores".
  Change password and sign out are items in a disclosure under it (`AccountMenu.jsx`), not
  loose buttons in the bar, so a rare action and a session-destroying one are not sitting
  where a stray click lands. Hover opens it, but hover is never the only way in: it is a real
  disclosure button, so click, Tab and Escape all work, and it is deliberately not
  `role="menu"` (that pattern owes the reader roving tabindex for what is two controls in a
  box). `.button-quiet`, the pill those two buttons used to wear, was deleted rather than left
  in `base.css` for a later screen to copy because it was there.
- **Directory names are `backend/` and `frontend/`**, not the `server/`/`client/` the roadmap
  suggests. The dirs predate the roadmap, and renaming buys nothing.
- **`pg` directly, no ORM.** Raw SQL in `backend/src/`, with a thin `Postgres` wrapper
  (`query`, `queryOne`, `transaction`) in `src/db/postgres.ts`.
- **TypeBox, not zod**, for request/response schemas. It compiles to the JSON Schema Fastify
  validates with natively, so there's no double validation pass.
- **CommonJS**, `module: node16`. Imports still carry `.js` extensions so an ESM move is cheap.
- **`seq` is `numeric(20,0)`, not `bigint`.** It is a uint64 (`(boot_epoch << 32) | msg_counter`)
  and overflows a signed bigint. `pg` returns it as a string, so parse to `BigInt`, never `Number`.
- **`vault_version` lives on `users` only**, not duplicated onto `vault_blobs`, so the two
  cannot drift. v1 vault granularity is one blob per user.
- **The vault version is bound into the blob twice**, in the AAD *and* in the plaintext
  envelope (`frontend/lib/crypto/vault.js`). The AAD copy means a blob served under a version
  it was not written at will not open; the plaintext copy means a disagreement between the two
  is a named error instead of a bare `OperationError`. Neither catches a *consistent* rollback
  (an old blob, honestly labelled), which is what the client's cached high-water mark is for.
- **`PUT /vault` conflicts are a single-statement compare-and-swap**, not a read-then-write.
  Two tabs saving at once must not both pass; a `select` followed by an `update` lets them.
- **One supported hardware path: ESP32, credentials written to NVS over Web Serial** (design
  5.3). Chromium-only and ESP32-only is a deliberate narrowing, not a gap to fill. Copy-paste
  was tried as the default and reverted: it costs the three properties the guided flow exists
  to provide: no clipboard exposure, no secret in source control, and the overwrite check in
  5.4, which cannot exist without a channel to the board. Other hardware is served by a
  published protocol (`docs/protocol.md`, Phase 4.7) plus a reveal button, not by a second
  guided flow.
- **"Reveal credentials" is an escape hatch and must not be shaped like a path.** Reached by a
  deliberate action on an existing device, never offered during setup; reveals on demand and
  does not stay revealed; states its costs at the moment of revealing. Past that button the
  guarantees in the design document genuinely stop, and a flow that made it look routine would
  be misrepresenting where the boundary is.
- **Device names live in the vault, encrypted.** There is no `name` column on `devices` and
  adding one is the kind of change the one rule exists to catch: "bedroom motion sensor"
  beside the upload timestamps the server already holds is a labelled occupancy log. Renaming
  is an ordinary vault write. A locked vault can show `DEVICE_ID`s and liveness but no names,
  which is the honest rendering of what the client actually knows.
- **Liveness is derived from signed records, and is a lower bound.** The server cannot forge a
  newer record at a higher `seq` (it lacks the signature), so it cannot make a dead device look
  alive; it can withhold and make a live one look dead. Every freshness signal here fails in
  that direction. So the UI shows *when a device was last heard from*, never asserts "offline"
  as a fact about the device, since a withholding server and a flat battery are indistinguishable
  from the client.
- **The backend serves `frontend/` statically in dev** (`SERVE_TEST_FRONTEND=true`). This is
  purely so the test console is same-origin: no CORS, and session cookies work unmodified.
  Delete it when the real client exists.
- **TLS is on in dev too**, via a self-signed cert generated by `scripts/gen-dev-cert.js`
  (the `selfsigned` package, not `openssl`, which isn't reliably on PATH on Windows).
  `TLS_ENABLED=false` exists as a debugging escape hatch and logs a loud warning; it is not
  a supported mode. There is no plaintext listener and no HTTP→HTTPS redirect.
- **Client crypto lives in `frontend/lib/crypto/`, never in `backend/`.** Physical separation
  is weaker than a cryptographic guarantee, but it means "just derive the kek server-side"
  cannot be written without an obviously wrong import path. It stays *outside* `app/` too,
  reached by the single `@siot/crypto` alias in `vite.config.js` rather than copied in, so
  the modules `node --test` covers are byte-identical to the ones the browser loads.
  There is no bundler-only second copy that could drift.
- **Tests are `node --test`, no framework.** Node's Web Crypto is the same API the browser
  exposes, so the tests run the exact ESM modules the client loads: no jsdom, no mocks, no
  transpile. Same reason the browser gets an import map for `hash-wasm` instead of a bundle:
  one copy of the code, tested and shipped.
- **Fastify's Ajv runs with `removeAdditional: false`.** Its default silently strips
  properties an `additionalProperties: false` schema doesn't name, which would turn a client
  that accidentally posts `kek` into a 201. Unknown fields are a 400.
- **`@node-rs/argon2` for the server-side hash of `login_key`**, at m=19 MiB/t=2/p=1, lighter
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
- No em dashes, anywhere: not in code comments, commit messages, roadmap notes, or this file.
  Rephrase with a period, a colon, a semicolon, or parentheses instead of reaching for one.

## Current state

**Phases 0, 1, 2 and the server half of 3 complete.** Server boots over HTTPS,
connects to Postgres and Redis, health check reports both and 503s when either is down, schema
is migrated. The full client key hierarchy of Section 2.1 exists in `frontend/lib/crypto/`:
Argon2id → master_key → HKDF → `login_key`/`kek`, plus `vault_key` generation and AES-256-GCM
wrapping, with 28 passing unit tests and a panel in the test console that runs the same
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
still holds from login, the first response the server hands back that it cannot read itself.

`PUT /vault` and `GET /vault` close Phase 3.1 and the server half of 3.2. The client seals the
whole vault document under `vault_key` with the version bound into both the AAD and the
plaintext envelope; the server compare-and-swaps `vault_version` in one statement, so a write
that does not follow the current version is a 409 and two simultaneous saves cannot both land.
A never-written vault reads as `{ vault_version: 0, ciphertext: null }` rather than a 404, so
the client's rollback check has no branch that skips it. Routes are `/health`, `/signup`,
`/salt`, `/login`, `/session`, `/logout`, `/logout-everywhere`, `/vault-key`, `/vault`.

**Accounts created before the `argon2Input()` fix cannot log in.** Their `login_key_hash` was
computed over raw bytes rather than the base64 form. Dev data only; sign up again.

**Phase 0.4 is now done too, out of order.** `frontend/app/` is a real React + Vite client
with four screens (sign in, sign up, unlock, devices) talking to the seven endpoints
above. Which screen shows is decided by two independent facts rather than one: is there a
session (the cookie, survives a reload) and is the vault open (`kek` in memory, does not).
The pair (session, locked) is where every refresh lands, so `Unlock` is a real screen, not
a redirect. It never calls `/login`: the password is checked by whether the derived `kek`
opens the 60-byte blob, entirely client-side, and a wrong guess is a GCM failure the
server is never told about. The React client does **not** read or write the vault document
yet; that is the rest of Phase 3.2, and it needs the IndexedDB high-water mark and a
rollback warning someone can act on. Until then the vault round-trip lives in the test console.

The visual language is surveyor's field paper: warm ruled ground, one plate shape with
registration ticks at its corners, Archivo for everything with Martian Mono held back for
values the machine owns rather than the person. Argon2id's ~1s gets an honest label and an
indeterminate bar, never a spinner or a fake percentage, since the wait is the security
property working.

`backend/` has no test harness. Everything so far was verified by hand against a running
server; the frontend's `node --test` suite covers `lib/crypto/` only, and nothing covers
the React screens. Phase 2.5 onwards is where that stops being tenable.

`firmware/esp32/esp32.ino` is the old unencrypted spike and **no longer works against this
server**. Its `POST /button` endpoint is gone and the server is HTTPS-only. That is intended;
it gets replaced wholesale by the SIoT library in Phase 5.

**Phase 3.1 and 3.2 are both done now**, server and client halves. `PUT /vault` / `GET /vault`
close the write path and the version-based conflict guard as before, and the client-side
rollback defence described in the design document (Section 8) is now real: `Devices.jsx` fetches
the vault on mount, compares its version against a high-water mark cached in IndexedDB
(`frontend/app/src/lib/vault-version-store.js`, keyed **by username** so switching accounts on
one browser is not mistaken for a rollback of the account it replaced; the first version of
this was keyed globally per origin, and that mistake was caught by hand-testing an account
switch rather than by design), and refuses to trust anything the AAD/envelope checks in
`vault.js` would have let through: a blob that is old but honestly labelled with its own old
version. A caught rollback renders a rust-styled panel (rust, not the generic alarm colour,
since this is "a vault the client will not open", the case tokens.css already reserves rust for)
naming both versions and telling the person not to make vault changes until it is resolved.
Verified by hand against a running server: wrote the vault to v2, rolled `users.vault_version`
back to 1 directly in Postgres, reloaded, and got the warning; restored to the true v2, and the
warning cleared on the next reload. No automated test; `backend/` still has no test harness.

**Phase 3.3 is done**, closing Phase 3. `ChangePassword.jsx`, reached from the account menu on
`Devices`, derives a new `master_key`/`kek` from the new password and re-wraps the existing
`vault_key` from the keyring under it; vault contents never move. The screen itself is a `Plate`,
matching Sign in and Create account, with "Devices" and "Sign out" as footer links the way
`Unlock` already does, not the `TopBar` shell `Devices` uses; a first pass borrowed `TopBar`
instead and read as off-centre and inconsistent once it was actually looked at next to its
neighbours, exactly the mistake rule 5 above exists to catch. `POST /change-password` lands the new
salt/hash/wrapped key in one statement, but only after checking a `current_login_key` the body
also carries against the stored hash, the same Argon2id verify `/login` uses. That check is not
in the roadmap item as written, and it earns its place: without it, a stolen session cookie alone
(no `kek`, no XSS) could overwrite `wrapped_vault_key` with anything at all and permanently orphan
the real `vault_key`, since the server has no plaintext to check a new wrapped blob against.
Wrong current password is a 403, throttled by its own Redis bucket keyed by user id
(`changePasswordThrottle`) rather than sharing `/login`'s username-keyed one, since reaching this
endpoint at all already requires a live session, a materially higher bar than `/login`'s "know a
username". Verified by hand: old password stops working at `/sign-in`, new password logs in and
unlocks the same vault with no rollback warning.

The client-visible route for this screen is `/password`, not `/change-password`, and that
difference is load-bearing rather than cosmetic. The server route is `POST /change-password`;
giving the client screen the identical path meant a full page reload there got proxied straight
to the backend (`GET`, 404) instead of falling through to the SPA shell, the same collision
`/sign-in` vs `/login` and `/sign-up` vs `/signup` already exist to avoid. Adding a route that is
both a server endpoint and something the client needs to reload on needs two names, the way every
other authenticated action already has one name for the API and another for the screen.

`backend/` still has no test harness; this phase adds to that gap rather than closing it.
