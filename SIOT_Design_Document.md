# SIOT — Design Document

*"The S in IoT stands for security"*

Status: Architecture phase. A throwaway spike exists (unencrypted HTTP button counter) to validate the ESP32 → server path; none of the design below is implemented yet.
Last updated: July 31, 2026

---

## 1. Vision & Core Principle

SIOT is a zero-knowledge IoT security platform. The server is **fully untrusted by design** — it functions purely as a dumb encrypted storage layer. At no point does it have access to plaintext device secrets, user data, or decryption keys.

This is treated as a non-negotiable constraint: every architectural decision is evaluated against a single question — *does this give the server plaintext access to anything, even indirectly?*

One clarification on what "untrusted" can and cannot buy us. Cryptography can stop the server from **reading** or **silently altering** anything. It cannot stop the server from **withholding** — refusing to serve data, stalling, or deleting records. The guarantee this design targets is precise:

> **The server can withhold, but it cannot lie undetected.**

Availability is therefore an accepted residual risk (Section 13), not something the design pretends to solve.

---

## 2. Cryptographic Core

### 2.1 Key hierarchy

The user memorizes exactly one thing: their password. Everything below is derived or wrapped automatically, so key handling can be as conservative as we like without adding user burden.

```
password + salt
  └─ Argon2id(m=64 MiB, t=3, p=1) ──> master_key (32B)   [never leaves the device]
       ├─ HKDF-SHA256(info="siot/auth/v1")  ──> login_key (32B)   ──> sent to server
       └─ HKDF-SHA256(info="siot/kek/v1")   ──> kek (32B)         [key-encryption key]

vault_key (random 32B, generated once at signup)
  └─ AES-256-GCM-wrapped by kek ──> wrapped_vault_key   [stored server-side, opaque]

vault_key ──encrypts──> vault records (device secrets, schemas, grants, layout)
```

- The password never leaves the device.
- `login_key` is password-*equivalent* but not password-*revealing*: it authenticates, and it cannot be used to derive `kek`, because HKDF with distinct `info` labels makes the two outputs computationally independent.
- Salt is 128-bit, CSPRNG, unique per user, stored plaintext server-side. Safe because the password itself never travels.

### 2.2 Why the wrapped `vault_key` indirection

The vault is encrypted under a random `vault_key`, not directly under the password-derived key. This costs nothing in user experience and buys two things:

- **Password change re-wraps 32 bytes.** Derive the new `kek`, re-wrap `vault_key`, upload. Vault contents are never touched, never re-uploaded, and never briefly decrypted in bulk.
- **A future recovery path has a clean slot to hook into** — any second wrapping of the same `vault_key` (see Section 12) is an additive change, not a redesign.

Device keys are unaffected by password changes, since they live inside the vault rather than being derived from it.

### 2.3 Symmetric primitives

- **AEAD: AES-256-GCM** everywhere. Chosen because it is the only authenticated cipher available in both Web Crypto and ESP32 hardware acceleration — XChaCha20-Poly1305 would be a better fit for random nonces but has no Web Crypto support, and shipping a JS implementation to handle the user's keys is a worse trade than managing nonces carefully.
- **Nonces are never random on the device.** GCM nonce reuse under a fixed key is catastrophic (it leaks the authentication key, not just the plaintext), and an ESP32 immediately after boot is a bad place to trust an RNG. The counter construction in Section 7.2 makes reuse structurally impossible instead of probabilistically unlikely.
- **All ciphertext binds its context as AAD.** Every record commits to who it belongs to, which device produced it, what kind of record it is, and where it sits in sequence. Without this the server cannot forge a record, but it *can* move a valid one into a different slot — swap a device's readings into another device's history, or replay an old vault record into a newer field. AAD binding closes that.

---

## 3. Authentication & Sessions

- Client submits `login_key` to the server over TLS.
- **The server does not store `login_key`. It stores `Argon2id(login_key, server_salt)`** and compares in constant time.

That second, server-side hash matters: without it a database dump is not just a pile of sealed vaults, it is a working login credential for every account. The vault would stay sealed either way, but the attacker would be authenticated — able to read metadata, delete records, or register devices. The client-side KDF protects the *vault*; the server-side KDF protects *authentication*. They defend different things and you need both.

- On match, the server creates a **server-side session** in Redis and returns a session identifier.
  - Session IDs are 256-bit CSPRNG, **stored hashed** in Redis (a Redis dump shouldn't hand over live sessions), with an absolute TTL and an idle timeout.
  - Delivered as a cookie with `HttpOnly; Secure; SameSite=Strict`.
- Revocation is cheap and immediate — logout, logout-everywhere, or suspected compromise is just deleting the corresponding Redis entry (or all entries tied to a user). No blocklist workaround needed, unlike stateless tokens.
- **Login is rate-limited** per account and per source address, with exponential backoff. Zero-knowledge architecture does nothing to slow down online password guessing; that has to be enforced server-side.
- **Salt lookup must not leak account existence.** The salt is fetched by username before authentication, so an unknown username has to return something. Return a deterministic decoy — `HMAC(server_secret, username)` — so the response is indistinguishable from a real account's and stable across retries.

No zero-knowledge proof is required at the login step itself. A standard hash comparison plus session issuance is sufficient because the password never transmits and the server never learns `kek`.

> **Considered and deferred:** an aPAKE (OPAQUE or SRP) would mean the server never receives a password-equivalent at all, even momentarily. It is the better primitive. It is also unavailable in Web Crypto, so adopting it means shipping unaudited JS crypto on the authentication path to defend against a threat that TLS plus server-side hashing already covers. Revisit for v2 if a well-audited browser implementation lands.

---

## 4. Transport Security

Zero-knowledge does not make the wire safe, and TLS was missing from earlier revisions of this document. It is mandatory:

- **HTTPS everywhere, TLS 1.3, HSTS with preload.** Plain HTTP is disallowed, including on the local network — "it's just my LAN" is exactly how the device-registration attack below succeeds.
- Three things break without it, none of which the crypto core protects:
  - `login_key` is password-equivalent in transit.
  - Session IDs are bearer tokens.
  - **Device public-key registration needs integrity at write time.** An active attacker who can rewrite that request substitutes their own public key and can then forge readings for the device forever. Confidentiality is irrelevant here; this is purely an integrity problem, and TLS is what solves it.
- **Devices pin the server's SPKI** (not the leaf certificate) in the library configuration.

> **Open item — certificate rotation.** Pinned firmware plus an expiring certificate is a fleet-bricking event, and devices may be physically inaccessible. Pinning the SPKI rather than the certificate means routine renewals are safe as long as the key pair is reused, but a key rotation still requires a plan. Options: pin a long-lived intermediate, ship a backup pin alongside the primary, or accept re-provisioning over USB. Not yet decided (Section 15).

---

## 5. Device Identity & Onboarding

Auto-provisioning (an earlier server-assisted handshake mode) has been **removed entirely**. It allowed the server to establish separate shared secrets with both the browser and the device in a DH-style relay, which is a textbook permanent man-in-the-middle position. Rather than patch it, the cleanest fix was to eliminate the mode outright.

**All pairing happens through one path: a browser-based provisioning tool using the Web Serial API.**

### 5.1 Device key material

```
DEVICE_SECRET (random 32B, browser CSPRNG)
  ├─ HKDF-SHA256(info="siot/device/data/v1") ──> device_data_key (32B, AES-256-GCM)
  └─ HKDF-SHA256(info="siot/device/sign/v1") ──> ed25519_seed (32B) ──> device_sign_priv / device_sign_pub
```

The split is what makes read-only grants possible (Section 9). `device_data_key` is shareable and confers **read** access; `device_sign_priv` never leaves the device and confers **write** authority. A single symmetric key could not separate the two.

### 5.2 What the server learns

| Value | Visibility | Purpose |
|---|---|---|
| `DEVICE_ID` (128-bit random) | **Plaintext** | Lookup index; uniqueness enforced at registration |
| `device_sign_pub` | **Plaintext** | Verifying upload signatures — it's a public key, publishing it leaks nothing |
| `DEVICE_SECRET` | Encrypted in vault | Everything else; server never sees it |

`device_sign_pub` in plaintext is what lets an untrusted server authenticate device uploads without holding anything secret. This closes a gap in earlier revisions, where nothing specified how the server distinguished a genuine upload from an attacker POSTing garbage to a known `DEVICE_ID` — and where every obvious answer (device presents `DEVICE_SECRET`) handed the server the secret and collapsed the core guarantee.

`DEVICE_ID` is generated with 128 bits of entropy, so accidental collision is negligible; the server additionally enforces uniqueness as a hard constraint, which it can do trivially without seeing anything sensitive.

### 5.3 Provisioning flow

1. Browser generates `DEVICE_ID` and `DEVICE_SECRET` locally.
2. Browser derives `device_sign_pub` and registers `(DEVICE_ID, device_sign_pub)` with the server.
3. Browser encrypts `DEVICE_SECRET` under `vault_key` and uploads it to the vault.
4. Provisioning tool writes `DEVICE_ID` + `DEVICE_SECRET` into a **dedicated NVS partition** over Web Serial.

The server never sees the plaintext secret at any point.

Physical USB access is treated as an **intentional security property**, not a limitation — it is what makes remote provisioning attacks structurally impossible.

### 5.4 Overwrite protection

Before writing, the tool reads back any `DEVICE_ID` already present in NVS:

- **No ID present** → blank board, provision normally.
- **ID matches the selected vault record** → re-provisioning the same device, proceed.
- **ID present but different** → refuse, and surface a clear warning. Overwriting would orphan the existing vault record — the device would keep reporting under an identity nothing in the vault can decrypt anymore, with no way to recover it.

---

## 6. Firmware & the Device Library

**The provisioning tool does not build, compile, or flash application firmware.** Earlier revisions described the browser decrypting `DEVICE_SECRET`, embedding it into a new firmware build, and reflashing — which is not implementable, because a browser cannot compile C++.

The fix is to stop coupling credentials to firmware images at all:

- **Credentials live in NVS, firmware lives in the app partition.** They are written independently and at different times.
- **The user writes and compiles their own sketch** in Arduino IDE or PlatformIO, exactly as they normally would, including the SIOT library.
- **The library reads `DEVICE_ID` / `DEVICE_SECRET` from NVS** and handles key derivation, AEAD, signing, sequence persistence, and upload internally. The device owner defines readings and actions; they never touch crypto.
- **Firmware updates preserve `DEVICE_SECRET` by construction.** Reflashing the app partition leaves NVS untouched. There is no regeneration step, no decrypt-and-re-embed step, and no per-device firmware blob stored on the server.

### 6.1 Portability

The wire protocol (Section 7) is published as a specification — KDF labels, AEAD parameters, nonce construction, payload layout, signature input. The ESP32 library is the reference implementation, not the only permitted one. Anyone can implement a conforming client for other hardware (Raspberry Pi, nRF, STM32) without server changes, because the server only ever verifies a signature and stores an opaque blob.

### 6.2 Consequences worth stating plainly

- **User-authored firmware cannot be hash-verified.** Section 10's verification therefore covers the web client and official library releases only. The extension can tell you the library you pulled is the published one; it cannot vouch for the sketch you wrote around it.
- **NVS is plaintext flash unless ESP32 flash encryption is fused.** Anyone with physical possession and a USB cable can read `DEVICE_SECRET` out. This sits inside the already-accepted physical-access risk, but deployments that care should burn the flash-encryption and secure-boot fuses. Document it as a recommended hardening step; note that it is irreversible.

---

## 7. Device Wire Protocol

This is the interoperability contract. Byte-level detail is deliberate — it is what makes third-party libraries possible.

### 7.1 Sequence numbers

Each device persists two counters in NVS:

- `boot_epoch` (uint32) — incremented once per boot, before any record is produced.
- `msg_counter` (uint32) — reset to zero each boot, incremented per record.

```
seq (uint64) = (boot_epoch << 32) | msg_counter
```

`seq` is strictly increasing across reboots and power loss without requiring an RTC, network time, or a trustworthy RNG at startup.

Readers verify **strict monotonicity, not contiguity**. A reboot advances the high word and zeroes the low word, producing a large legitimate jump. That jump is distinguishable from tampering: gaps within a single `boot_epoch` indicate dropped or withheld records, whereas a `boot_epoch` increment is a normal restart.

### 7.2 Nonce construction

```
nonce (12B) = 0x00000000 || seq (8B, big-endian)
```

Since `seq` is strictly increasing and `device_data_key` is fixed for the life of the secret, **nonce reuse cannot occur**. No RNG quality assumption, no birthday-bound budgeting, no state to reconcile after an unclean shutdown — the counter is persisted before use, so the worst case after power loss is a skipped `seq`, never a repeated one.

### 7.3 Record format

```
plaintext P   = CBOR { t: <device timestamp>, r: <readings per declared schema> }
AAD           = version (1B) || DEVICE_ID (16B) || record_type (1B) || seq (8B)
ciphertext C  = AES-256-GCM(device_data_key, nonce, P, AAD)
signature S   = Ed25519(device_sign_priv, AAD || nonce || C)

POST /records
{ device_id, seq, nonce, ciphertext: C, sig: S }
```

The signature covers the AAD, the nonce, and the ciphertext — so sequence position, device identity, and record type are all authenticated, not just the payload.

### 7.4 Server-side validation

The server performs exactly three checks, none of which require decryption:

1. `Ed25519_verify(device_sign_pub, AAD || nonce || C, S)` — is this really from that device?
2. `seq > last_seq[device_id]` — is this fresh, not a replay?
3. `nonce == 0x00000000 || seq` — is the nonce well-formed and consistent with the claimed sequence?

Then it stores the blob and updates `last_seq`. It never decrypts, and it cannot produce a record that passes check 1.

---

## 8. Data Integrity & Freshness

Encryption alone does not stop an untrusted server from serving you *stale* or *incomplete* data. Every blob it returns can be perfectly authentic and the overall picture still be a lie — last week's vault, a history with the inconvenient readings removed. Three mechanisms, all cheap:

- **Monotonic `vault_version`.** Every vault write carries a version inside the AEAD-protected plaintext. The client caches the highest version it has seen (IndexedDB) and **refuses anything lower**, surfacing a warning rather than silently accepting. A rollback becomes a visible, loud failure.
- **Strictly increasing `seq` on device records** (Section 7.1). Withheld or reordered readings leave a detectable hole in the sequence.
- **AAD binding on everything** (Section 2.3). The server cannot relocate a valid blob into a different slot, swap records between devices, or replay an old vault record into a newer field.

What remains unfixable: the server can refuse to serve, stall indefinitely, or delete. No cryptographic mechanism recovers data that is simply gone. This is the concrete meaning of *"can withhold, cannot lie undetected"* — and the reason availability is listed as accepted residual risk rather than mitigated.

---

## 9. Inter-Device Automations (Read-Only Key Grants)

- Client decrypts `device_B_data_key` from the vault, re-encrypts it under `device_A_data_key`, and uploads the result as a **key grant**:

```
grant = AES-256-GCM(device_A_data_key, nonce, device_B_data_key,
                    AAD = "grant/v1" || DEVICE_ID_A || DEVICE_ID_B)
```

- Device A fetches the grant, decrypts it locally, and can now read Device B's data autonomously.
- The server sees only encrypted blobs throughout the entire exchange.
- No always-on client is required — the system is fully peer-to-peer once the grant exists.

### 9.1 Grants are read-only

**Only `device_data_key` is shared. `device_sign_priv` never leaves Device B.**

This is why the key split in Section 5.1 exists. Under the earlier single-symmetric-key design, granting A the ability to *read* B necessarily also granted it the ability to *write as* B — anyone holding the key could encrypt convincing readings and attribute them to B. A compromised temperature sensor could have fabricated the smoke detector's output.

Now the capabilities are cleanly separated:

| Capability | Device B | Device A (granted) | Server |
|---|---|---|---|
| Decrypt B's records | ✓ | ✓ | ✗ |
| Verify B's signatures | ✓ | ✓ | ✓ (public key) |
| Produce records signed as B | ✓ | ✗ | ✗ |

A reader can always check authenticity, because `device_sign_pub` is public. A reader can never forge, because the private half stayed on the device.

### 9.2 Scope: historical as well as live

Once Device A holds `device_B_data_key`, it isn't limited to a live feed from B — it can query the server for B's already-uploaded records and decrypt them locally. **A grant extends read access to everything B has stored, past and future.** That is a deliberate capability, but it should be presented to the user as such at grant time, not buried: this is not "let A see what B is doing now."

### 9.3 Revocation is rotation

**Grants cannot be revoked for data already encrypted under the shared key.** A holds the key; that is irreversible. Revocation means rotating B's `DEVICE_SECRET`, which requires **physical re-provisioning over USB** (Section 5.3), and only protects data produced after the rotation. All of B's history remains readable by A forever.

This must be surfaced in the UI before a grant is created. A user who believes "revoke" means "A can no longer read B" will be wrong in a way that matters.

---

## 10. Client Verification System

A minimal, deliberately non-updating browser extension (~100 lines, open source) is the trust anchor for the code the user runs. **The extension is optional.**

- **On install:** no stored hash exists → forced code review → user approves → hash stored locally.
- **On update:** hash mismatch detected → extension fetches raw code from GitHub → computes its own hash (never trusts a claimed hash) → shows a diff → user approves.
- Applies to site code, official library releases, and custom widget plugins (Section 11).

Being optional matters for the threat model: the core zero-knowledge guarantees hold with or without the extension, because they are enforced by cryptography, not by the extension. What it adds is protection against a *separate* threat — a compromised server serving altered JavaScript to the browser, a standard web supply-chain attack. Without it, unverified web client code is part of the residual attack surface (Section 13).

### 10.1 Feasibility constraints

Two things need resolving before this ships, and neither is a detail:

- **Manifest V3 removed blocking `webRequest`.** An extension can no longer reliably intercept and *block* a script before the page executes it. Verification may therefore be after-the-fact — a warning once malicious code has already run, which is a materially weaker guarantee. Likely mitigation: pair the extension with a strict CSP and Subresource Integrity so the *browser* enforces what the extension merely audits, and pin the SRI manifest rather than individual bundles.
- **"No auto-update" conflicts with the Chrome Web Store**, which updates extensions silently. Honoring the no-auto-update property requires self-hosting or unpacked developer-mode installation, both of which hurt adoption enough to affect whether anyone actually runs the extension.

A hash-pinning extension that verifies only the entry HTML while a hashed SPA bundle loads separately would be checking the wrong thing entirely. Whatever ships must cover every executed subresource.

---

## 11. Customizability & Dashboard

- Devices declare a **schema** at pairing time; the schema itself is encrypted into the vault.
- The client auto-renders the dashboard from this schema — no hardcoding per device type.
- Generic widget system: graph, gauge, toggle, with drag-and-drop layout.
- The firmware library handles all crypto and communication internally — the device owner just defines readings and actions.

### 11.1 Schemas are untrusted input

A schema drives UI rendering, and schemas can arrive from granted devices belonging to other users. Treat them as hostile input: **strict validation against an allowlist of field types, no raw HTML rendering, no `dangerouslySetInnerHTML`, no dynamic code paths.** A malicious schema must not be able to reach XSS — decrypting an attacker's blob and injecting it into the DOM would hand them the very keys the whole architecture exists to protect.

### 11.2 Widget plugins need a sandbox

Custom widget plugins are arbitrary third-party JavaScript running inside the client that holds decrypted keys. Hash-pinning tells you *which* code is running; it does not constrain what that code can do once approved, and the extension is optional anyway.

Plugins must run in a **sandboxed iframe or Worker, communicating only over `postMessage`, and must never receive key material or raw vault access.** The host passes in already-decrypted display values and receives back rendering instructions. A plugin should be incapable of exfiltrating a key even if the user approved it while it was malicious.

---

## 12. Account Recovery — Open Question

**There is no account recovery in v1. If you forget your password, the account and all its data are permanently lost.**

This is stated bluntly because it needs to be stated bluntly, in the UI as well as here.

The previously specified mechanism — five security questions, normalized and concatenated into a KDF producing a key that wraps `master_key` — has been removed. Two reasons, and the first is the serious one:

- **The recovery blob was an offline brute-force oracle.** It sits on the server, and security answers carry far less entropy than a password. Anyone who dumped the database could grind the answer space offline and recover the vault key. That reduces every account's security to `min(password strength, answer strength)` — so the recovery path, intended as a safety net, would have quietly become the cheapest way in. Adding a recovery mechanism that is weaker than the primary credential does not add a fallback; it *replaces* the primary credential from the attacker's point of view.
- **Concatenating all five answers made it all-or-nothing.** Forget one of five and recovery fails completely — a high lockout risk for something whose entire purpose is preventing lockout.

Dropping it is a net security improvement, not merely a deferral. The attack surface genuinely shrinks.

If recovery returns, the Section 2.2 indirection is where it attaches: any second wrapping of `vault_key` is additive. Directions worth evaluating, given the constraint that the user must not have to remember anything beyond their password:

- **Shamir k-of-n** over answers (e.g. 3-of-5), fixing the all-or-nothing failure but not the entropy problem.
- **A printed/downloaded recovery code** with real entropy — strong, but it is a physical artifact to store, not something memorized.
- **Social recovery** — shares distributed to trusted contacts' vaults.
- **Rate-limited server-assisted recovery**, which requires giving up some zero-knowledge property and should probably be rejected on those grounds.

Whatever is chosen, the recovery credential must be at least as strong as the password, or it becomes the weakest link by definition.

---

## 13. Threat Model / Attack Surface

| Residual risk | Why it remains |
|---|---|
| Weak passwords | User choice, outside the system's control; mitigated by Argon2id + login rate limiting |
| **Permanent lockout** | No recovery path in v1 — forgetting the password destroys the account (Section 12) |
| Social engineering | Includes a user approving a malicious update without reading the diff |
| Physical device access | Accepted tradeoff — the same USB requirement that kills remote provisioning attacks. NVS is plaintext unless flash encryption is fused |
| Memory scraping | Only relevant if the device is already compromised |
| Unverified web client code | Only a risk if the browser extension isn't installed — optional, not required for the core crypto guarantees |
| **Metadata leakage** | Inherent to the architecture, and significant for IoT — see below |
| **Availability / withholding** | The server can refuse, stall, or delete. Cryptography detects lies; it cannot compel service |
| **Compromised device holding a grant** | Reads everything the grant covers, including full history; revocation requires physical re-provisioning (Section 9.3) |

### 13.1 Metadata leakage

The server cannot read content, but it sees the shape of everything: how many devices exist, when each one uploads, how large each record is, which devices hold grants on which others, and when a client fetches what.

**For IoT this is not a minor leak.** A motion sensor that uploads only on activity leaks occupancy patterns to a fully passive server without a single byte being decrypted. Upload timing alone can reveal when a house is empty. Encrypting the payload does not hide the fact that a payload existed at 3:47am.

Partial mitigations exist and none are free: fixed-interval uploads with padded dummy records, constant-size payloads, batching with jitter. All trade power consumption and latency for privacy, and the tradeoff differs per device class. **Not addressed in v1** — but it must be an explicit, documented limitation rather than an unnoticed one, because users will reasonably assume "zero-knowledge" covers it.

---

Every purely *software-level* trust assumption in the server has been eliminated by design. The remaining risks are physical, human, or metadata — categories cryptography does not reach.

---

## 14. Stack

| Layer | Choice |
|---|---|
| Frontend | React + Web Crypto API |
| Backend | Node.js + TypeScript + Fastify |
| Extension | Vanilla JS, ~100 lines, no build step, no auto-update, optional |
| Firmware | C++ library, Arduino-compatible; published protocol spec for third-party ports |
| Provisioning | Web Serial API (in-browser), writes NVS credentials only |
| Transport | HTTPS / TLS 1.3, HSTS preload, SPKI pinning on devices |
| Password KDF | Argon2id (m=64 MiB, t=3, p=1) client-side; Argon2id again server-side on `login_key` |
| Key derivation | HKDF-SHA256 with domain-separated `info` labels |
| AEAD | AES-256-GCM with counter-derived nonces and AAD context binding |
| Device auth | Ed25519, public key registered plaintext server-side |
| Session | Server-side session store (Redis), hashed 256-bit IDs, TTL |
| Recovery | **None in v1** — open question (Section 12) |
| Database | PostgreSQL (users, salts, device public keys, encrypted blobs) + Redis (sessions) |
| Hardware target | ESP32 + assorted sensors |

*Fastify was chosen over Express for TypeScript-first design, a structured plugin system, and built-in JSON schema validation.*

---

## 15. Open Decisions

The architecture is settled in shape. These remain genuinely open and should be resolved before or during implementation:

1. **Certificate rotation strategy for pinned devices** (Section 4) — backup pins, intermediate pinning, or accepted re-provisioning.
2. **Extension enforcement under Manifest V3** (Section 10.1) — whether CSP + SRI can carry the guarantee that blocking `webRequest` no longer provides.
3. **Extension distribution** (Section 10.1) — self-hosted versus Web Store, trading the no-auto-update property against adoption.
4. **Account recovery** (Section 12) — whether any mechanism can meet the bar of being no weaker than the password.
5. **Metadata mitigation** (Section 13.1) — whether any device class warrants padded fixed-interval uploads in v1.
6. **Vault record granularity** — one blob versus per-record encryption, affecting sync cost and how precisely `vault_version` rollback can be detected.

---

## 16. Changes in This Revision

| Change | Section | Why |
|---|---|---|
| Device Ed25519 keypair; public key registered plaintext | 5 | Upload authentication was unspecified; every obvious alternative leaked `DEVICE_SECRET` to the server |
| `DEVICE_SECRET` split into data key + signing key | 5.1, 9.1 | Grants conveyed forgery capability; read and write are now separable |
| Provisioning writes NVS credentials only; no firmware building | 6 | The previous update flow required the browser to compile C++ |
| Per-device encrypted firmware blob removed | 6 | Obsolete once credentials are decoupled from firmware images |
| Server stores `Argon2id(login_key)`, not `login_key` | 3 | A database dump was a working login credential for every account |
| Wrapped random `vault_key` introduced | 2.2 | Password change re-wraps 32 bytes; clean attachment point for future recovery |
| Transport security section added | 4 | TLS was absent from the document entirely |
| Data integrity & freshness section added | 8 | Encryption addressed confidentiality but not rollback, omission, or reordering |
| AAD context binding on all ciphertext | 2.3 | Server could relocate valid blobs between slots |
| Full wire protocol specified | 7 | Required for third-party library ports; also pins down GCM nonce safety |
| Security-question recovery removed | 12 | Offline brute-force oracle reducing accounts to `min(password, answers)` |
| Metadata leakage added to threat model | 13.1 | Upload timing leaks occupancy regardless of encryption |
| Availability added as accepted risk | 1, 13 | Clarifies the achievable guarantee: withhold yes, lie undetected no |
| Schema validation & plugin sandboxing | 11.1, 11.2 | Decrypted third-party content reached the DOM and key material |
| MV3 / Web Store feasibility flagged | 10.1 | Blocking interception and no-auto-update may not both be achievable |
| "No open decisions remaining" replaced | 15 | Six were outstanding |
